#pragma once

#include <memory>
#include "base/basic_types.h"
#include "data/data_peer_id.h"
#include "QtCore/QString"

#include "encryption_key.h"

namespace DoubleEncryption {

constexpr size_t kSaltSize = 32;

EncryptionKey::Data GenerateSecret();
EncryptionKeyPtr GenerateKey();

struct DHInitiatorParams {
    bytes::vector prime;
    bytes::vector g_a;
    bytes::vector a;
    uint32 g = 0;

    ~DHInitiatorParams();
};

struct DHPartParams {
    bytes::vector prime;
    bytes::vector g_a;
    uint32 g = 0;

    ~DHPartParams();
};

struct DHAcceptorPrivateParams {
    bytes::vector b;
    bytes::vector g_b;
    ~DHAcceptorPrivateParams();
};

struct DHAuthState {
    DHInitiatorParams params;
    MTPint128 nonce;
    PeerId acceptor_id = 0;
};

struct DHAuthPart {
    DHPartParams params;
    MTPint128 nonce;
    PeerId acceptor_id;
    PeerId initiator_id;
};

using DHAuthStatePtr = std::unique_ptr<DHAuthState>;

DHAuthState MakeDH(PeerId acceptor_id);
DHAcceptorPrivateParams MakeDHAcceptorPrivate(const DHAuthPart& initiator_part);

bool IsGAGood(bytes::const_span g_a, bytes::const_span prime);
bool IsPrimeGood(bytes::const_span prime);
bool IsGGood(uint32 g);

EncryptionKeyPtr CreateKey(bytes::const_span g_b, bytes::const_span a, bytes::const_span prime);

};  // namespace DoubleEncryption
