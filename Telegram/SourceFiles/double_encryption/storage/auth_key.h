#pragma once

namespace DoubleEncryption {

using AuthKey = QString;

struct AuthKeyInfo {
    QString fingerprint;
    QString name;
    int64_t creation_time;
};

struct AuthKeyData {
    AuthKeyInfo info;
    AuthKey key;
};

}  // namespace DoubleEncryption
