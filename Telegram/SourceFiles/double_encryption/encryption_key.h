/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/

/*
Это модифицированная версия файла mtproto_auth_key.h
Я убрал лишние поля класса и функции, которые я не
использую в проекте.
*/

#pragma once

#include "base/bytes.h"

#include <array>
#include <memory>

namespace DoubleEncryption {

class EncryptionKey {
public:
	static constexpr auto kSize = 256; // 2048 bits.
	using Data = std::array<gsl::byte, kSize>;

	enum class Type {
		Generated,
		Temporary,
		ReadFromFile,
		Local,
	};
	explicit EncryptionKey(const Data &data);

	EncryptionKey(const EncryptionKey &other) = delete;
	EncryptionKey &operator=(const EncryptionKey &other) = delete;

	void prepareAES(const MTPint128 &msgKey, MTPint256 &aesKey, MTPint256 &aesIV) const;

	[[nodiscard]] const void *partForMsgKey() const;

	[[nodiscard]] bytes::const_span data() const;
	[[nodiscard]] bool equals(const std::shared_ptr<EncryptionKey> &other) const;

	[[nodiscard]] crl::time creationTime() const; // > 0 if known.
	[[nodiscard]] TimeId expiresAt() const;
	void setExpiresAt(TimeId expiresAt);

	static void FillData(Data &authKey, bytes::const_span computedAuthKey);

private:
	Data _key = { { gsl::byte{} } };
	crl::time _creationTime = 0;
	TimeId _expiresAt = 0;

};

using EncryptionKeyPtr = std::shared_ptr<EncryptionKey>;

void aesIgeEncryptRaw(const void *src, void *dst, uint32 len, const void *key, const void *iv);
void aesIgeDecryptRaw(const void *src, void *dst, uint32 len, const void *key, const void *iv);

inline void aesIgeEncrypt(const void *src, void *dst, uint32 len, const EncryptionKeyPtr &encryptionKey, const MTPint128 &msgKey) {
	MTPint256 aesKey, aesIV;
	encryptionKey->prepareAES(msgKey, aesKey, aesIV);

	return aesIgeEncryptRaw(src, dst, len, static_cast<const void*>(&aesKey), static_cast<const void*>(&aesIV));
}

inline void aesIgeDecrypt(const void *src, void *dst, uint32 len, const EncryptionKeyPtr &encryptionKey, const MTPint128 &msgKey) {
	MTPint256 aesKey, aesIV;
	encryptionKey->prepareAES(msgKey, aesKey, aesIV);

	return aesIgeDecryptRaw(src, dst, len, static_cast<const void*>(&aesKey), static_cast<const void*>(&aesIV));
}

} // namespace MTP
