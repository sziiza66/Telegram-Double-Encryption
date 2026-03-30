#include "gpg_manager.h"

#include <QProcess>
#include <QTextStream>
#include <QDebug>

#include "settings_manager.h"

namespace DoubleEncryption {

GPGManager& GPGManager::Instance() {
    static GPGManager manager(SettingsManager::Instance().GetGPGPath(),
                              SettingsManager::Instance().GetGPGHomedirPath());
    return manager;
}

std::optional<AuthKey> GPGManager::FindPublicKey(const QString& fingerprint) {
    auto output = RunGpg({"--armor", "--export", fingerprint});

    if (output.exit_code != 0 || output.stdout_data.isEmpty()) {
        qCritical() << output.stderr_data;
        return std::nullopt;
    }

    return QString::fromUtf8(output.stdout_data);
}

std::vector<AuthKeyInfo> GPGManager::ListPublicKeys() {
    return ListKeysInternal(false);
}

bool GPGManager::InsertKey(const QString& key) {
    auto res = RunGpg({"--status-fd=2", "--import"}, key.toUtf8());

    if (res.exit_code != 0) {
        qCritical() << "Import failed:" << res.stderr_data;
        return false;
    }

    QTextStream stream(res.stderr_data);
    QString line;

    while (stream.readLineInto(&line)) {
        if (line.startsWith("[GNUPG:] IMPORT_RES")) {
            auto parts = line.split(' ');
            if (parts.size() >= 5) {
                int imported = parts[4].toInt();
                if (imported > 0) {
                    return true;
                }
            }
        }
    }

    return false;
}

void GPGManager::DeletePublicKey(const QString& fingerprint) {
    RunGpg({"--delete-key", fingerprint});
}

std::optional<AuthKey> GPGManager::FindPrivateKey(const QString& fingerprint) {
    auto output = RunGpg({"--armor", "--export-secret-keys", fingerprint});

    if (output.exit_code != 0 || output.stdout_data.isEmpty()) {
        qCritical() << output.stderr_data;
        return std::nullopt;
    }

    return QString::fromUtf8(output.stdout_data);
}

std::vector<AuthKeyInfo> GPGManager::ListPrivateKeys() {
    return ListKeysInternal(true);
}

void GPGManager::DeletePrivateKey(const QString& fingerprint) {
    RunGpg({"--delete-secret-keys", fingerprint});
}

QByteArray GPGManager::EncryptData(const QByteArray& data, const QString& fingerprint) {
    if (data.isEmpty() || fingerprint.isEmpty()) {
        return {};
    }

    auto res = RunGpg({
        "--encrypt",
        "--recipient", fingerprint,
        "--trust-model", "always"
    }, data);

    if (res.exit_code != 0 || res.stdout_data.isEmpty()) {
        qCritical() << "Encrypt failed:" << res.stderr_data;
        return {};
    }

    return res.stdout_data;
}

QByteArray GPGManager::DecryptData(const QByteArray& data) {
    if (data.isEmpty()) {
        return {};
    }

    auto res = RunGpg({
        "--decrypt"
    }, data);

    if (res.exit_code != 0) {
        qCritical() << "Decrypt failed:" << res.stderr_data;
        return {};
    }

    return res.stdout_data;
}

QByteArray GPGManager::SignAndEncryptData(const QByteArray& data,
                                          const QString& signer_fingerprint,
                                          const QString& recipient_fingerprint) {
    if (data.isEmpty() || signer_fingerprint.isEmpty() || recipient_fingerprint.isEmpty()) {
        return {};
    }

    auto res = RunGpg({
        "--encrypt",
        "--sign",
        "--local-user", signer_fingerprint,
        "--recipient", recipient_fingerprint,
        "--trust-model", "always"
    }, data);

    if (res.exit_code != 0 || res.stdout_data.isEmpty()) {
        qCritical() << "Sign+Encrypt failed:" << res.stderr_data;
        return {};
    }

    return res.stdout_data;
}

GPGManager::DecryptVerifyResult GPGManager::DecryptAndVerifyData(const QByteArray& data) {
    if (data.isEmpty()) {
        return {};
    }

    auto res = RunGpg({
        "--status-fd=2",
        "--decrypt"
    }, data);

    DecryptVerifyResult result;
    result.plaintext = res.stdout_data;

    QString encryption_key_id;
    bool saw_bad_signature = false;
    bool saw_good_signature = false;

    QTextStream stream(res.stderr_data);
    QString line;

    while (stream.readLineInto(&line)) {
        if (line.startsWith("[GNUPG:] ENC_TO ")) {
            auto parts = line.split(' ');
            if (parts.size() >= 3) {
                encryption_key_id = parts[2];
            }
        } else if (line.startsWith("[GNUPG:] VALIDSIG ")) {
            auto parts = line.split(' ');
            if (parts.size() >= 3) {
                result.signer_fingerprint = parts[2];
                result.signature_valid = true;
                saw_good_signature = true;
            }
        } else if (line.startsWith("[GNUPG:] GOODSIG ")) {
            saw_good_signature = true;
        } else if (line.startsWith("[GNUPG:] BADSIG ")) {
            saw_bad_signature = true;
            result.signature_valid = false;
        }
    }

    if (saw_bad_signature) {
        result.signature_valid = false;
    } else if (!saw_good_signature) {
        result.signature_valid = false;
    }

    if (!encryption_key_id.isEmpty()) {
        result.encryption_key_fingerprint = FindSecretKeyFingerprintByKeyId(encryption_key_id);
    }

    if (res.exit_code != 0) {
        qCritical() << "Decrypt+Verify returned non-zero:" << res.stderr_data;
    }

    return result;
}

QString GPGManager::GetKeyDescription(const QString& fingerprint, bool secret) {
    auto output = RunGpg({secret ? "--list-secret-keys" : "--list-public-keys"});
    if (output.exit_code == 0) {
        return output.stdout_data;
    }
    return "Error fetching key description";
}

GPGManager::GPGManager(const Path& gpg_path, const Path& homedir)
    : gpg_path_(gpg_path.empty() ? "gpg" : gpg_path.lexically_normal().c_str()), homedir_(homedir.lexically_normal().c_str()) {
    if (!gpg_path.empty() && !QFile::exists(gpg_path_)) {
        qCritical() << "GPG binary not found at" << gpg_path_;
        throw std::runtime_error("GPG binary not found");
    }

    auto output = RunGpg({"--version"});
    if (output.exit_code != 0) {
        qCritical() << "GPG binary not found";
        throw std::runtime_error("GPG binary not found");
    }
    qDebug() << "GPG version:\n" << output.stdout_data;

    if (!homedir_.isEmpty()) {
        QDir dir(homedir_);

        if (!dir.exists()) {
            if (!dir.mkpath(".")) {
                qCritical() << "Failed to create GPG homedir:" << homedir_;
                throw std::runtime_error("Failed to create homedir");
            }
        }

        QFile::setPermissions(homedir_, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);

        QProcess initProc;
        initProc.start(gpg_path_, {"--homedir", homedir_, "--list-keys"});

        if (!initProc.waitForStarted() || !initProc.waitForFinished()) {
            qCritical() << "Failed to initialize GPG homedir:" << homedir_;
            throw std::runtime_error("Failed to init homedir");
        }
    }

    qDebug() << "GPGManager initialized (homedir:" << homedir_ << ")";
}

QString GPGManager::FindSecretKeyFingerprintByKeyId(const QString& key_id) {
    if (key_id.isEmpty()) {
        return {};
    }

    auto res = RunGpg({
        "--list-secret-keys",
        "--with-colons",
        key_id
    });

    if (res.exit_code != 0 || res.stdout_data.isEmpty()) {
        return {};
    }

    QTextStream stream(res.stdout_data);
    QString line;
    bool seen_sec = false;

    while (stream.readLineInto(&line)) {
        const auto parts = line.split(':');
        if (parts.isEmpty()) {
            continue;
        }

        if (parts[0] == "sec") {
            seen_sec = true;
        } else if (seen_sec && parts[0] == "fpr" && parts.size() > 9) {
            return parts[9];
        }
    }

    return {};
}

std::vector<AuthKeyInfo> GPGManager::ListKeysInternal(bool secret) {
    std::vector<AuthKeyInfo> keys;
    auto output = RunGpg({secret ? "--list-secret-keys" : "--list-public-keys", "--with-colons"});

    const QString primary_tag = secret ? "sec" : "pub";
    const QString subkey_tag  = secret ? "ssb" : "sub";

    if (output.exit_code != 0 || output.stdout_data.isEmpty()) {
        return keys;
    }

    QTextStream stream(output.stdout_data);
    QString line;

    AuthKeyInfo current;
    bool has_encrypt_flag = false;
    bool in_key = false;

    enum class LastRecordType {
        None,
        Primary,
        Subkey
    };

    LastRecordType last_record = LastRecordType::None;

    auto FlushCurrent = [&]() {
        if (!current.fingerprint.isEmpty() && has_encrypt_flag) {
            keys.push_back(current);
        }
        current = AuthKeyInfo{};
        has_encrypt_flag = false;
        in_key = false;
        last_record = LastRecordType::None;
    };

    while (stream.readLineInto(&line)) {
        const QStringList parts = line.split(':');
        if (parts.isEmpty()) {
            continue;
        }
        const QString& tag = parts[0];
        if (tag == primary_tag) {
            if (in_key) {
                FlushCurrent();
            }

            in_key = true;
            last_record = LastRecordType::Primary;

            const QString flags = parts.size() > 11 ? parts[11] : "";
            has_encrypt_flag = flags.contains('e', Qt::CaseInsensitive);

            if (parts.size() > 5) {
                bool ok = false;
                const qint64 timestamp = parts[5].toLongLong(&ok);
                if (ok) {
                    current.creation_time = timestamp;
                }
            }

        } else if (tag == subkey_tag) {
            if (!in_key) {
                continue;
            }

            last_record = LastRecordType::Subkey;

            const QString flags = parts.size() > 11 ? parts[11] : "";
            if (flags.contains('e', Qt::CaseInsensitive)) {
                has_encrypt_flag = true;
            }

        } else if (!in_key) {
            continue;

        } else if (tag == "uid") {
            if (current.name.isEmpty() && parts.size() > 9) {
                current.name = parts[9];
            }

        } else if (tag == "fpr") {
            if (parts.size() > 9) {
                if (last_record == LastRecordType::Primary && current.fingerprint.isEmpty()) {
                    current.fingerprint = parts[9];
                }
            }
            last_record = LastRecordType::None;
        }
    }

    if (in_key) {
        FlushCurrent();
    }

    return keys;
}

QStringList GPGManager::GetGpgArgs(const QStringList& extra) const {
    QStringList args;
    if (!homedir_.isEmpty()) {
        args << "--homedir" << homedir_;
    }
    args << "--batch" << "--yes";
    args.append(extra);
    return args;
}

GPGManager::GpgResult GPGManager::RunGpg(const QStringList& args, const QByteArray& input) const {
    QProcess gpg;
    gpg.start(gpg_path_, GetGpgArgs(args));
    if (!gpg.waitForStarted()) {
        qCritical() << gpg.readAllStandardError();
        return {};
    }
    if (!input.isEmpty()) {
        gpg.write(input);
    }
    gpg.closeWriteChannel();

    if (!gpg.waitForFinished()) {
        qCritical() << gpg.readAllStandardError();
        return {};
    }

    return {gpg.exitCode(), gpg.readAllStandardOutput(), gpg.readAllStandardError()};
}

}  // namespace DoubleEncryption
