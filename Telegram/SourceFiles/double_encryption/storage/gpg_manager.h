#pragma once

#include <filesystem>
#include <optional>
#include "QtCore/QString"

#include "auth_key.h"

namespace DoubleEncryption {

class GPGManager {
    using Path = std::filesystem::path;

    struct GpgResult {
        int exit_code = -1;
        QByteArray stdout_data;
        QByteArray stderr_data;
    };

    struct DecryptVerifyResult {
        QString signer_fingerprint;
        QString encryption_key_fingerprint;
        bool signature_valid = false;
        QByteArray plaintext;
    };

public:
    static GPGManager& Instance();

    std::optional<AuthKey> FindPublicKey(const QString& fingerprint);
    std::vector<AuthKeyInfo> ListPublicKeys();
    bool InsertKey(const QString& key);
    void DeletePublicKey(const QString& fingerprint);

    std::optional<AuthKey> FindPrivateKey(const QString& fingerprint);
    std::vector<AuthKeyInfo> ListPrivateKeys();
    void DeletePrivateKey(const QString& fingerprint);

    QByteArray EncryptData(const QByteArray& data, const QString& fingerprint);
    QByteArray DecryptData(const QByteArray& data);

    QByteArray SignAndEncryptData(const QByteArray& data,
                              const QString& signer_fingerprint,
                              const QString& recipient_fingerprint);
    DecryptVerifyResult DecryptAndVerifyData(const QByteArray& data);
    
    QString GetKeyDescription(const QString& fingerprint, bool secret);
    
private:
    explicit GPGManager(const Path& gpg_path, const Path& homedir);
    
    QString FindSecretKeyFingerprintByKeyId(const QString& key_id);
    std::vector<AuthKeyInfo> ListKeysInternal(bool secret);
    QStringList GetGpgArgs(const QStringList& extra = {}) const;
    GpgResult RunGpg(const QStringList& args, const QByteArray& input = {}) const;

private:
    QString gpg_path_;
    QString homedir_;
};

}  // namespace DoubleEncryption
