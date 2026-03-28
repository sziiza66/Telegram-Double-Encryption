#pragma once

#include "QtCore/QByteArray"

namespace DoubleEncryption {

QByteArray ToBase91(const QByteArray& data);
QByteArray FromBase91(const QByteArray& data);

}  // namespace DoubleEncryption
