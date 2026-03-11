/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/

/*
Это модифицированная версия файла mtproto_auth_key.cpp
Я убрал лишние поля класса и функции, которые я не
использую в проекте.
*/

#include "encryption_key.h"

#include "base/openssl_help.h"

namespace DoubleEncryption {

EncryptionKey::EncryptionKey(const Data &data) : _key(data) {
}

void EncryptionKey::prepareAES(const MTPint128 &msgKey, MTPint256 &aesKey, MTPint256 &aesIV, bool send) const {
	uint32 x = send ? 0 : 8;

	bytes::array<32> sha256_a, sha256_b;
	bytes::array<16 + 36> data_a;
	memcpy(data_a.data(), &msgKey, 16);
	memcpy(data_a.data() + 16, _key.data() + x, 36);
	openssl::Sha256To(sha256_a, data_a);

	bytes::array<36 + 16> data_b;
	memcpy(data_b.data(), _key.data() + 40 + x, 36);
	memcpy(data_b.data() + 36, &msgKey, 16);
	openssl::Sha256To(sha256_b, data_b);

	auto key = reinterpret_cast<uchar*>(&aesKey);
	auto iv = reinterpret_cast<uchar*>(&aesIV);
	memcpy(key, sha256_a.data(), 8);
	memcpy(key + 8, sha256_b.data() + 8, 16);
	memcpy(key + 8 + 16, sha256_a.data() + 24, 8);
	memcpy(iv, sha256_b.data(), 8);
	memcpy(iv + 8, sha256_a.data() + 8, 16);
	memcpy(iv + 8 + 16, sha256_b.data() + 24, 8);
}

const void *EncryptionKey::partForMsgKey(bool send) const {
	return _key.data() + 88 + (send ? 0 : 8);
}

bytes::const_span EncryptionKey::data() const {
	return _key;
}

bool EncryptionKey::equals(const std::shared_ptr<EncryptionKey> &other) const {
	return other ? (_key == other->_key) : false;
}

crl::time EncryptionKey::creationTime() const {
	return _creationTime;
}

TimeId EncryptionKey::expiresAt() const {
	return _expiresAt;
}

void EncryptionKey::setExpiresAt(TimeId expiresAt) {
	_expiresAt = expiresAt;
}

void aesIgeEncryptRaw(const void *src, void *dst, uint32 len, const void *key, const void *iv) {
	uchar aes_key[32], aes_iv[32];
	memcpy(aes_key, key, 32);
	memcpy(aes_iv, iv, 32);

	AES_KEY aes;
	AES_set_encrypt_key(aes_key, 256, &aes);
	AES_ige_encrypt(static_cast<const uchar*>(src), static_cast<uchar*>(dst), len, &aes, aes_iv, AES_ENCRYPT);
}

void aesIgeDecryptRaw(const void *src, void *dst, uint32 len, const void *key, const void *iv) {
	uchar aes_key[32], aes_iv[32];
	memcpy(aes_key, key, 32);
	memcpy(aes_iv, iv, 32);

	AES_KEY aes;
	AES_set_decrypt_key(aes_key, 256, &aes);
	AES_ige_encrypt(static_cast<const uchar*>(src), static_cast<uchar*>(dst), len, &aes, aes_iv, AES_DECRYPT);
}

} // namespace MTP
