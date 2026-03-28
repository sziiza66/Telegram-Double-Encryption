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
    auto res = RunGpg({"--status-fd=1", "--import"}, key.toUtf8());

    if (res.exit_code != 0) {
        qCritical() << "Import failed:" << res.stderr_data;
        return false;
    }

    QTextStream stream(res.stdout_data);
    QString line;

    while (stream.readLineInto(&line)) {
        if (line.startsWith("[GNUPG:] IMPORT_RES")) {
            auto parts = line.split(' ');
            if (parts.size() >= 4) {
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

std::vector<AuthKeyInfo> GPGManager::ListKeysInternal(bool secret) {
    std::vector<AuthKeyInfo> keys;
    auto output = RunGpg({secret ? "--list-secret-keys" : "--list-public-keys", "--with-colons"});
    const char* favour = secret ? "sec" : "pub";

    if (output.exit_code != 0 || output.stdout_data.isEmpty()) {
        return keys;
    }

    QTextStream stream(output.stdout_data);
    QString line;
    AuthKeyInfo current;
    bool has_encrypt_flag = false;
    bool is_identity_key = false;

    while (stream.readLineInto(&line)) {
        QStringList parts = line.split(':');
        if (parts.isEmpty()) {
            continue;
        }

        if (parts[0] == favour || parts[0] == "sub") {
            if (!current.fingerprint.isEmpty() && has_encrypt_flag) {
                keys.push_back(current);
            }
            is_identity_key = parts[0] == favour;
            QString flags = parts.size() > 11 ? parts[11] : "";
            has_encrypt_flag = flags.contains("e") || flags.contains("E");
            current = AuthKeyInfo{};
            if (!is_identity_key) {
                continue;
            }

            if (parts.size() > 5) {
                QString date_str = parts[5];
                QDate date = QDate::fromString(date_str, "yyyyMMdd");
                current.creation_time = date.startOfDay().toSecsSinceEpoch();
            }
        } else if (!is_identity_key) {
            continue;
        } else if (parts[0] == "uid") {
            if (parts.size() > 9) {
                current.name = parts[9];
            }
        } else if (parts[0] == "fpr") {
            if (parts.size() > 9) {
                current.fingerprint = parts[9];
            }
        }
    }
    if (!current.fingerprint.isEmpty() && has_encrypt_flag) {
        keys.push_back(current);
    }

    return keys;
}

QByteArray GPGManager::EncryptData(const QByteArray& data, const QString& fingerprint) {
    if (data.isEmpty() || fingerprint.isEmpty()) {
        return {};
    }

    // if (!FindPublicKey(fingerprint).has_value()) {
    //     return {};
    // }

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
