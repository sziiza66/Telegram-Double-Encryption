#include "base91.h"

#include "base91_c/base91.h"

namespace DoubleEncryption {

QByteArray ToBase91(const QByteArray& data) {
    QByteArray out(data.size() * 2, Qt::Uninitialized);
    out.resize(encodeBase91(data.constData(), data.size(), out.data()));
    return out;
}

QByteArray FromBase91(const QByteArray& data) {
    QByteArray out(data.size(), Qt::Uninitialized);
    out.resize(decodeBase91(data.constData(), data.size(), out.data()));
    return out;
}

}  // namespace DoubleEncryption
