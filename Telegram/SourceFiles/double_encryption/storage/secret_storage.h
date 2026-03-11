#pragma once

#include "data/data_peer_id.h"

#include <optional>
#include <limits>
#include <unordered_map>
#include <unordered_set>

#include "double_encryption/encryption_key.h"
#include "double_encryption/common.h"
#include "sqlite3pp.h"

class PeerId;

namespace DoubleEncryption {

struct PeerIdHash {
    size_t operator()(const PeerId &id) const noexcept {
        return std::hash<uint64>{}(id.value);
    }
};

class SecretStorage {
    using DataBase = sqlite3pp::database;

    struct IntervalEnding {
        EncryptionKeyPtr key; // null if message is not encrypted.
        MsgId64 msg_end_id;
    };

public:
    SecretStorage(PeerId self_id);

    void OpenNewInterval(PeerId peer_id, MsgId64 msg_beg_id, EncryptionKeyPtr key);
    void CloseInterval(PeerId peer_id, MsgId64 msg_end_id);

    IntervalEnding FindKey(PeerId peer_id, MsgId64 msg_id);
    EncryptionKeyPtr GetCurrentEncryptionKey(PeerId peer_id); // Доступ к текущему ключу быстрее с этим методом.
    bool IsPeerEncrypted(PeerId peer_id) const;

private:
    DataBase db_;
    // Поддерживаем кеш полуинтервалов [msg_begin_id, msg_end_id), key,
    // Хранятся и интервалы без шифрования с key = nullptr.
    std::unordered_map<PeerId, std::map<MsgId64, IntervalEnding>, PeerIdHash> cache_;
    // Поддерживаем множество чатов, в которых в текущий момент включено шифрование.
    std::unordered_set<PeerId, PeerIdHash> currently_encrypted_;

private:
    // Значения для обозначения "бесконечных" (+inf и -inf) границ интервалов шифрования.
    static constexpr MsgId64 kLargestMsgId64 = std::numeric_limits<MsgId64>::max();
    static constexpr MsgId64 kSmallestMsgId64 = std::numeric_limits<MsgId64>::min();
};

};  // namespace DoubleEncryption
