#include "secret_storage.h"
#include <QtCore/qlogging.h>

#include <cassert>
#include <string>

#include "data/data_peer_id.h"

namespace DoubleEncryption {

SecretStorage::SecretStorage(const Path& secret_storage_dir_path, PeerId self_id)
    : db_path_((secret_storage_dir_path / (std::string{"keys"} + std::to_string(self_id.value) + ".db")).lexically_normal()),
      db_(LoadDB(db_path_)),
      currently_encrypted_(LoadCurrentlyEncrypted(db_)) {
}

void SecretStorage::OpenNewInterval(PeerId peer_id, MsgId64 msg_begin_id, EncryptionKeyPtr key) {
    qDebug() << "Opening interval, peerId" << peer_id.value << "msgId" << msg_begin_id;
    const std::string error_message = std::string{"Can't open encryption interval on msgId = "}
                                + std::to_string(msg_begin_id)
                                + " for peer "
                                + std::to_string(peer_id.value);
    if (currently_encrypted_.find(peer_id) != currently_encrypted_.end()) {
        assert(false);
        throw std::runtime_error(error_message + ". Trying to open encryption for already encrypted peer.");
    }

    currently_encrypted_.insert(peer_id);
    sqlite3pp::command cmd(db_,
        "INSERT INTO peer_intervals(peer_id, msg_begin_id, msg_end_id, key_data) "
        "VALUES (?, ?, ?, ?)"
    );
    cmd.bind(1, static_cast<long long>(peer_id.value));
    cmd.bind(2, msg_begin_id);
    cmd.bind(3, kLargestMsgId64);
    cmd.bind(4, key->data().data(), EncryptionKey::kSize, sqlite3pp::copy);

    ExecCmdOrThrow(db_, cmd, error_message);

    // обновляем кеш
    auto& peer_cache = cache_[peer_id];
    auto it = peer_cache.end();
    if (it != peer_cache.begin()) {
        --it;
        if (it->second.msg_end_id == kLargestMsgId64) {
            it->second.msg_end_id = msg_begin_id;
        }
    }
    peer_cache[msg_begin_id] = {key, kLargestMsgId64};
}

void SecretStorage::CloseInterval(PeerId peer_id, MsgId64 msg_end_id) {
    const std::string error_message = std::string{"Can't close encryption interval on msgId = "}
                                    + std::to_string(msg_end_id)
                                    + " for peer "
                                    + std::to_string(peer_id.value);
    qDebug() << "Closing interval, peerId" << peer_id.value << "msgId" << msg_end_id; 
    
    if (currently_encrypted_.find(peer_id) == currently_encrypted_.end()) {
        assert(false);
        throw std::runtime_error(error_message + ". Trying to close encryption for already not encrypted peer.");
    }

    currently_encrypted_.erase(peer_id);

    MsgId64 msg_begin_id = 0;

    sqlite3pp::query q(
        db_,
        "SELECT msg_begin_id FROM peer_intervals "
        "WHERE peer_id = ? AND msg_end_id = ? "
        "LIMIT 1"
    );

    q.bind(1, static_cast<long long>(peer_id.value));
    q.bind(2, static_cast<long long>(kLargestMsgId64));

    if (q.begin() == q.end()) {
        assert(false);
        throw std::runtime_error(error_message + ". Database corruption");
    }

    for (auto row : q) {
        msg_begin_id = row.get<MsgId64>(0);
    }

    if (msg_begin_id > msg_end_id) {
        assert(false);
        throw std::runtime_error(error_message + ". Database corruption");
    }

    // В случае если интервал пустой, удаляем его целиком.
    if (msg_begin_id == msg_end_id) {
        sqlite3pp::command cmd(db_,
            "DELETE FROM peer_intervals "
            "WHERE peer_id = ? AND msg_begin_id = ? AND msg_end_id = ?"
        );

        cmd.bind(1, static_cast<long long>(peer_id.value));
        cmd.bind(2, msg_begin_id);
        cmd.bind(3, static_cast<long long>(kLargestMsgId64));
        cmd.execute();

        // обновляем кеш
        auto peer_cache = cache_.find(peer_id);
        if (peer_cache != cache_.end()) {
            peer_cache->second.erase(msg_begin_id);
        }

        return;
    }

    sqlite3pp::command cmd(db_,
        "UPDATE peer_intervals "
        "SET msg_end_id = ? "
        "WHERE peer_id = ? AND msg_end_id = ?"
    );

    cmd.bind(1, msg_end_id);
    cmd.bind(2, static_cast<long long>(peer_id.value));
    cmd.bind(3, static_cast<long long>(kLargestMsgId64));

    ExecCmdOrThrow(db_, cmd, error_message);

    // обновляем кеш
    auto& peer_cache = cache_[peer_id];
    auto it = peer_cache.end();
    if (it != peer_cache.begin()) {
        --it;
        if (it->second.msg_end_id == kLargestMsgId64) {
            it->second.msg_end_id = msg_end_id;
        }
    }
}

SecretStorage::IntervalEnding SecretStorage::FindKey(PeerId peer_id, int64 msg_id) {
    const std::string error_message = std::string{"Can't read secret for msgId = "}
                                   + std::to_string(msg_id)
                                   + "from database at \""
                                   + db_path_.c_str()
                                   + "\" for peer "
                                   + std::to_string(peer_id.value);

    auto& peer_cache = cache_[peer_id];

    auto it = peer_cache.lower_bound(msg_id);
    // Пытаемся найти подходящий интервал в кеше.
    if (it != peer_cache.begin()) {
        auto prev = std::prev(it);
        if (msg_id < prev->second.msg_end_id) {
            return prev->second;
        }
    }

    if (it != peer_cache.end()) {
        if (msg_id >= it->first && msg_id < it->second.msg_end_id) {
            return it->second;
        }
    }

    // В кеше интервал не нашли -- ищем последний интервал, что начался или в msg_id.
    MsgId64 prev_begin = kSmallestMsgId64;
    MsgId64 prev_end = kSmallestMsgId64;
    EncryptionKeyPtr prev_key;

    sqlite3pp::query q(
        db_,
        "SELECT msg_begin_id, msg_end_id, key_data "
        "FROM peer_intervals "
        "WHERE peer_id = ? AND msg_begin_id <= ? "
        "ORDER BY msg_begin_id DESC "
        "LIMIT 1"
    );

    q.bind(1, static_cast<long long>(peer_id.value));
    q.bind(2, msg_id);

    for (auto row : q) {
        prev_begin = row.get<MsgId64>(0);
        prev_end = row.get<MsgId64>(1);

        const void* blob = row.get<const void*>(2);
        int size = row.column_bytes(2);
        if (size != EncryptionKey::kSize) {
            assert(false);
            throw std::runtime_error(error_message + ". Secret corrupted");
        }

        EncryptionKey::Data data{};
        ::memcpy(data.data(), blob, size);
        prev_key = std::make_shared<EncryptionKey>(data);
    }
    // Если нашли такой интервал, к тому же оказалось, что msg_id попадает в него,
    // заносим его в кеш и возвращаем.
    if (prev_begin != kSmallestMsgId64 && msg_id < prev_end) {
        IntervalEnding interval_end{prev_key, prev_end};
        peer_cache.emplace(prev_begin, interval_end);
        return interval_end;
    }
    // Если оказалось, что такого интервала нет или msg_id в него не попало,
    // ищем интервал, что начался строго после msg_id.
    MsgId64 next_begin = kLargestMsgId64;

    sqlite3pp::query q2(
        db_,
        "SELECT msg_begin_id "
        "FROM peer_intervals "
        "WHERE peer_id = ? AND msg_begin_id > ? "
        "ORDER BY msg_begin_id ASC "
        "LIMIT 1"
    );

    q2.bind(1, static_cast<long long>(peer_id.value));
    q2.bind(2, msg_id);

    for (auto row : q2) {
        next_begin = row.get<MsgId64>(0);
    }
    // вставляем в кеш интервал наибольший интервал с пустым ключом, в который попадает msg_id.
    IntervalEnding hole_end{nullptr, next_begin};
    peer_cache.emplace(prev_end, hole_end);
    // возвращаем этот интервал.
    return hole_end;
}

EncryptionKeyPtr SecretStorage::GetCurrentEncryptionKey(PeerId peer_id) {
    const std::string error_message = std::string{"Can't read current secret from database at \""}
                                    + db_path_.c_str()
                                    + "\" for peer "
                                    + std::to_string(peer_id.value);

    if (currently_encrypted_.find(peer_id) == currently_encrypted_.end()) {
        return nullptr;
    }

    auto& peer_cache = cache_[peer_id];
    auto it = peer_cache.end();
    if (it != peer_cache.begin()) {
        --it;
        if (it->second.msg_end_id == kLargestMsgId64) {
            return it->second.key;
        }
    }

    sqlite3pp::query q(
        db_,
        "SELECT msg_begin_id, key_data FROM peer_intervals "
        "WHERE peer_id = ? AND msg_end_id = ? "
        "LIMIT 1"
    );

    q.bind(1, static_cast<long long>(peer_id.value));
    q.bind(2, static_cast<long long>(kLargestMsgId64));

    for (auto row : q) {
        const MsgId64 msg_begin_id = row.get<MsgId64>(0);
        const void* blob = row.get<const void*>(1);
        int size = row.column_bytes(1);
        if (size != EncryptionKey::kSize) {
            assert(false);
            throw std::runtime_error(error_message + ". Secret corrupted");
        }

        EncryptionKey::Data data{};
        ::memcpy(data.data(), blob, size);
        auto key = std::make_shared<EncryptionKey>(data);
        peer_cache[msg_begin_id] = {key, kLargestMsgId64};

        return key;
    }

    assert(false);
    throw std::runtime_error(error_message + ". Database corrupted");
    return nullptr;
}

bool SecretStorage::IsPeerEncrypted(PeerId peer_id) const {
    return currently_encrypted_.find(peer_id) != currently_encrypted_.end();
}

SecretStorage::DataBase SecretStorage::LoadDB(const Path& db_path) {
    const std::string error_message = std::string{"SQL error while initialising database at "} + db_path.c_str();

    DataBase db(db_path.c_str());

    // Таблица интервалов шифрования.
    ExecOrThrow(db,
        "CREATE TABLE IF NOT EXISTS peer_intervals ( "
            "peer_id INTEGER NOT NULL, "
            "msg_begin_id INTEGER NOT NULL, "
            "msg_end_id INTEGER NOT NULL, "
            "key_data BLOB NOT NULL, "
            "PRIMARY KEY(peer_id, msg_begin_id) "
        ");",
        error_message
    );

    // Индекс для ускорения поиска текущих интервалов шифрования.
    ExecOrThrow(db, (
        "CREATE INDEX IF NOT EXISTS idx_open_intervals "
        "ON peer_intervals(peer_id) "
        "WHERE msg_end_id = " + kLargestMsgId64Str
    ),
        error_message
    );

    return db;
}

std::unordered_set<PeerId, PeerIdHash> SecretStorage::LoadCurrentlyEncrypted(DataBase& db) {

    std::unordered_set<PeerId, PeerIdHash> currently_encrypted;

    // Инициализируем множество чатов с действующим шифрованием.
    sqlite3pp::query q(
        db,
        ("SELECT peer_id FROM peer_intervals "
        "WHERE msg_end_id = " + kLargestMsgId64Str).c_str()
    );

    for (auto row : q) {
        PeerId peer_id(static_cast<uint64>(row.get<long long>(0)));
        currently_encrypted.insert(peer_id);
    }

    return currently_encrypted;
}

void SecretStorage::ExecOrThrow(DataBase& db, const std::string& sql, const std::string& context) {
    if (db.execute(sql.c_str()) != SQLITE_OK) {
        throw std::runtime_error(context + ":\n" + db.error_msg());
    }
};

void SecretStorage::ExecCmdOrThrow(DataBase& db, sqlite3pp::command& cmd, const std::string& context) {
    if (cmd.execute() != SQLITE_OK) {
        throw std::runtime_error(context + ":\n" + db.error_msg());
    }
}

const std::string SecretStorage::kLargestMsgId64Str = std::to_string(kLargestMsgId64);

}  // namespace DoubleEncryption
