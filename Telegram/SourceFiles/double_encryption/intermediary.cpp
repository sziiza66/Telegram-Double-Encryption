#include "intermediary.h"
#include <cassert>

#include "base/random.h"
#include "base/unixtime.h"
#include "history/history_item.h"
#include "history/history.h"
#include "data/data_session.h"
#include "data/data_histories.h"
#include "main/main_account.h"
#include "main/main_session.h"
#include "data/data_peer.h"
#include "window/window_session_controller.h"
#include "apiwrap.h"
#include "base/openssl_help.h"
#include "storage/gpg_manager.h"
#include "storage/secret_storage.h"
#include "storage/settings_manager.h"
#include "base91/base91.h"
#include "common.h"

namespace DoubleEncryption {

namespace {

size_t CalculateRandomPadding(size_t size) {
    constexpr size_t kMinPaddingSize = 16;
    constexpr size_t kMaxNormalPaddingSize = kMinPaddingSize + 64;
    constexpr size_t kMaxTotalPayloadSizeWithPadding = kMaxMessageSizeWhenEncrypted + kMaxNormalPaddingSize;

    uint8 byte;
    bytes::set_random(bytes::make_span(&byte, 1));
    if (byte < 3 && size <= kMaxMessageSizeWhenEncrypted) {
        return kMaxTotalPayloadSizeWithPadding - size;
    }
    bytes::set_random(bytes::make_span(&byte, 1));
    uint16 padding_size = kMinPaddingSize + byte / 4;
    assert(padding_size < kMaxNormalPaddingSize);

    return padding_size;
}

}  // namespace

Intermediary::Intermediary(Account* account, UserId self_id)
    : storage_(SettingsManager::Instance().GetSecretStorageDirPath()
    , peerFromUser(self_id))
    , auth_stream_(std::make_shared<rpl::event_stream<PeerId>>())
    , account_(account)
    , self_id_(peerFromUser(self_id)) {
    assert(account);
}

PeerId Intermediary::GetSelfId() const {
    return self_id_;
}

std::shared_ptr<rpl::event_stream<PeerId>> Intermediary::GetAuthStream() {
    return auth_stream_;
}

void Intermediary::CancelAuth() {
    dm_auth_state_ = nullptr;
}

bool Intermediary::IsPeerEncrypted(PeerId peer_id) {
    return storage_.IsPeerEncrypted(peer_id);
}

void Intermediary::SwitchEncryptionForSelf() {
    assert(self_id_);
    auto last_message = account_->session().data().history(self_id_)->lastMessage();
    MsgId64 last_msg_id = last_message ? last_message->id.bare : 0;
    if (IsPeerEncrypted(self_id_)) {
        storage_.CloseInterval(self_id_, last_msg_id + 1);
    } else {
        auto key = GenerateKey();
        storage_.OpenNewInterval(self_id_, last_msg_id + 1, key);
    }
}

void Intermediary::EnableEncryptionForPeer(EncryptionKeyPtr key, PeerId peer_id, MsgId64 msg_begin_id) {
    assert(!IsPeerEncrypted(peer_id));
    assert(key);
    // auto last_message = account_->session().data().history(peer_id)->lastMessage();
    // MsgId64 last_msg_id = last_message ? last_message->id.bare : 0;
    storage_.OpenNewInterval(peer_id, msg_begin_id, key);    
}

void Intermediary::DisableEncryptionForPeer(PeerId peer_id) {
    assert(IsPeerEncrypted(peer_id));
    auto history = account_->session().data().history(peer_id);
    if (history->lastMessageKnown()) {
        storage_.CloseInterval(peer_id, history->lastMessage()->id.bare + 1);
    }
}

void Intermediary::SendE2EServiceMessage(const QString& text, PeerId peer_id, DoneCallback done, FailCallback fail) {
    auto session = &account_->session();
    auto history = session->data().history(peer_id);
    auto peer = history->peer;
    const auto localMessageId = session->data().nextLocalMessageId();

    auto newId = FullMsgId(
        peer_id,
        localMessageId);
    auto randomId = base::RandomValue<uint64>();

    session->data().registerMessageRandomId(randomId, newId);
    session->data().registerMessageSentData(
        randomId,
        peer_id,
        text);

    auto flags = MessageFlag::BeingSent | (peer_id == self_id_ ? MessageFlag() : MessageFlag::Outgoing);

    HistoryItem* lastMessage = history->addNewLocalMessage(HistoryItemCommonFields{
        .id = newId.msg,
        .flags = flags,
        .from = self_id_,
        .replyTo = FullReplyTo{FullMsgId{}, TextWithEntities{}, FullStoryId{}, 0, 0, 0, 0},
        .date = base::unixtime::now(),
        .scheduleRepeatPeriod = 0,
        .shortcutId = 0,
        .starsPaid = 0,
        .postAuthor = QString{},
        .effectId = 0,
        .suggest = HistoryMessageSuggestInfo{},
    }, {text, {}}, MTP_messageMediaEmpty());

    auto &histories = session->data().histories();

    auto request = MTPmessages_SendMessage(
        MTP_flags(MTPmessages_sendMessage::Flag::f_no_webpage),
        peer->input(),
        MTP_inputReplyToMonoForum(
            MTP_inputPeerEmpty()
        ),
        tl::make_string(text),
        MTP_long(randomId),
        MTP_replyKeyboardHide(
            MTP_flags(0)
        ),
        MTPVector<MTPMessageEntity>(),
        MTP_int(0),
        MTP_int(0),
        MTP_inputPeerEmpty(),
        MTP_inputQuickReplyShortcutId(
            MTP_int(0)
        ),
        MTP_long(0),
        MTP_long(0),
        MTP_suggestedPost(
            MTP_flags(0),
            MTP_starsTonAmount(
                MTP_long(0)
            ),
            MTP_int(0)
        )
    );

    histories.sendRequest(history, Data::Histories::RequestType::Send, [=](Fn<void()> finish) {
        const auto api = &session->api();
        history->sendRequestId = api->request(
            base::duplicate(request)
        ).done([=](
                const MTPUpdates &result,
                const MTP::Response &response) {
            api->applyUpdates(result, randomId);
            done(result, response);
            finish();
        }).fail([=](
                const MTP::Error &error,
                const MTP::Response &response) {
            fail(error, response);
            if (error.type() == u"MESSAGE_EMPTY"_q) {
                lastMessage->destroy();
            } else {
                api->sendMessageFail(error, peer, randomId, newId);
            }
            finish();
        }).afterRequest(
            history->sendRequestId
        ).send();
        return history->sendRequestId;
    });

}

bool Intermediary::TryToEstablishSecureConnectionWithUser(not_null<Window::SessionController*> controller,
                                                          const QString& fingerprint,
                                                          PeerId peer_id) {
    assert(!IsPeerEncrypted(peer_id) && peer_id != self_id_ && peerIsUser(peer_id));
    dm_auth_state_ = MakeDH(peer_id);
    if (!dm_auth_state_) {
        return false;
    }

    QByteArray encrypted_data = GPGManager::Instance().EncryptData(SerializeInitiatorDH(*dm_auth_state_, self_id_), fingerprint);
    if (encrypted_data.isEmpty()) {
        return false;
    }

    SendE2EServiceMessage(ToBase91(encrypted_data), peer_id,
        [=](const MTPUpdates &result, const MTP::Response &response) {
            return;
        }, [=](const MTP::Error &error, const MTP::Response &response) {
            return;
        }
    );

    return true;
}

bool Intermediary::TryToAcceptEncryptionRequest(const QString& request, const QString& fingerprint, PeerId peer_id, MsgId64 msg_id) {
    assert(self_id_);
    auto request_decrypted = GPGManager::Instance().DecryptData(FromBase91(request.toUtf8()));
    if (request_decrypted.isEmpty()) {
        return false;
    }

    auto request_deserialized = DeserializeDHPart(request_decrypted);

    if (request_deserialized.initiator_id != peer_id ||
        request_deserialized.acceptor_id != self_id_ ||
        !IsPrimeGood(request_deserialized.params.prime) ||
        !IsGGood(request_deserialized.params.g) ||
        !IsGAGood(request_deserialized.params.g_a, request_deserialized.params.prime)) {
        return false;
    }

    auto acceptor_private = MakeDHAcceptorPrivate(request_deserialized);

    auto data = SerializeDHPart(request_deserialized, acceptor_private.g_b);
    
    auto encrypted_data = GPGManager::Instance().EncryptData(data, fingerprint);
    if (encrypted_data.isEmpty()) {
        return false;
    }

    auto key = CreateKey(request_deserialized.params.g_a, acceptor_private.b, request_deserialized.params.prime);
    if (!key) {
        return false;
    }

    SendE2EServiceMessage(ToBase91(encrypted_data), peer_id,
        [=](const MTPUpdates &result, const MTP::Response &response) {
            return;
        }, [=](const MTP::Error &error, const MTP::Response &response) {
            return;
        }
    );

    MsgId64 last_msg_id = msg_id;
    auto session = &account_->session();
    auto history = session->data().history(peer_id);
    if (history->lastMessageKnown()) {
        MsgId64 actual_last = history->lastMessage()->id.bare;
        last_msg_id = last_msg_id < actual_last ? actual_last : last_msg_id;
    }

    auto& histories = session->data().histories();
    histories.deleteMessages(
        {{peer_id, msg_id}},
        true
    );
    
    EnableEncryptionForPeer(key, peer_id, last_msg_id + 1);
    return true;
}

bool Intermediary::TryToAcceptEncryptionResponse(const QByteArray& response, PeerId peer_id, MsgId64 msg_id) {
    assert(!storage_.IsPeerEncrypted(peer_id));
    assert(self_id_);
    assert(peer_id);
    assert(dm_auth_state_ && dm_auth_state_->acceptor_id == peer_id && peer_id != self_id_);

    auto decrypted = GPGManager::Instance().DecryptData(FromBase91(response));
    if (decrypted.isEmpty()) {
        return false;
    }

    auto state = DeserializeDHPart(decrypted);
    if (state.acceptor_id != peer_id ||
        state.initiator_id != self_id_ ||
        state.nonce != dm_auth_state_->nonce ||
        state.params.g != dm_auth_state_->params.g ||
        bytes::compare(bytes::make_span(dm_auth_state_->params.prime), bytes::make_span(state.params.prime)) != 0 ||
        !IsGAGood(state.params.g_a, state.params.prime)) {
        return false;
    }

    auto key = CreateKey(state.params.g_a, dm_auth_state_->params.a, dm_auth_state_->params.prime);
    if (!key) {
        return false;
    }

    MsgId64 last_msg_id = msg_id;
    auto session = &account_->session();
    auto history = session->data().history(peer_id);
    if (history->lastMessageKnown()) {
        MsgId64 actual_last = history->lastMessage()->id.bare;
        last_msg_id = last_msg_id < actual_last ? actual_last : last_msg_id;
    }

    auto& histories = session->data().histories();

    histories.deleteMessages(
		history,
		{MTP_int(msg_id)},
		true
    );

    EnableEncryptionForPeer(key, peer_id, last_msg_id + 1);
    auth_stream_->fire(PeerId(peer_id));
    return true;
}

MTPmessages_SendMessage Intermediary::ProcessRequest(const MTPmessages_SendMessage& request) {
    auto peer_id = peerFromMTPInput(request._peer);
    auto key = storage_.GetCurrentEncryptionKey(peer_id);
    auto& settings = SettingsManager::Instance();

    if (!key) {
        return request;
    }
    auto new_flags = request._flags.v | MTPmessages_SendMessage::Flag::f_entities;
    return MTPmessages_SendMessage(
        MTP_flags(new_flags),
        request._peer,
        request._reply_to,
        EncryptMTPString(request._message, key),
        request._random_id,
        request._reply_markup,
        EncryptMTPMessageEntities(request._entities, key, request._random_id.v),
        request._schedule_date,
        request._schedule_repeat_period,
        request._send_as,
        // Это поле тоже нужно шифровать/отбрасывать, позже разберусь.
        request._quick_reply_shortcut,
        request._effect,
        request._allow_paid_stars,
        request._suggested_post
    );
}

MTPmessages_SendMedia Intermediary::ProcessRequest(const MTPmessages_SendMedia& request) {
    auto peer_id = peerFromMTPInput(request._peer);
    auto key = storage_.GetCurrentEncryptionKey(peer_id);
    if (!key) {
        return request;
    }
    auto new_flags = request._flags.v | MTPmessages_SendMedia::Flag::f_entities;
    return MTPmessages_SendMedia(
        MTP_flags(new_flags),
        request._peer,
        request._reply_to,
        request._media,
        EncryptMTPString(request._message, key),
        request._random_id,
        request._reply_markup,
        EncryptMTPMessageEntities(request._entities, key, request._random_id.v),
        request._schedule_date,
        request._schedule_repeat_period,
        request._send_as,
        // Это поле тоже нужно шифровать/отбрасывать, позже разберусь.
        request._quick_reply_shortcut,
        request._effect,
        request._allow_paid_stars,
        request._suggested_post
    );
}

MTPmessages_sendMultiMedia Intermediary::ProcessRequest(const MTPmessages_sendMultiMedia& request) {
    auto peer_id = peerFromMTPInput(request._peer);
    auto key = storage_.GetCurrentEncryptionKey(peer_id);
    if (!key) {
        return request;
    }
    return MTPmessages_sendMultiMedia(
        request._flags,
        request._peer,
        request._reply_to,
        EncryptMTPMultiMedia(request._multi_media, key),
        request._schedule_date,
        request._send_as,
        request._quick_reply_shortcut,
        request._effect,
        request._allow_paid_stars
    );
}

MTPmessages_EditMessage Intermediary::ProcessRequest(const MTPmessages_EditMessage& request) {
    auto peer_id = peerFromMTPInput(request._peer);
    auto key = storage_.GetCurrentEncryptionKey(peer_id);
    if (!key) {
        return request;
    }
    auto new_flags = request._flags.v | MTPmessages_EditMessage::Flag::f_entities;
    return MTPmessages_EditMessage(
        MTP_flags(new_flags),
        request._peer,
        request._id,
        EncryptMTPString(request._message, key),
        request._media,
        request._reply_markup,
        EncryptMTPMessageEntities(request._entities, key),
        request._schedule_date,
        request._schedule_repeat_period,
        request._quick_reply_shortcut_id
    );
}

MTPmessages_SaveDraft Intermediary::ProcessRequest(const MTPmessages_SaveDraft& request) {
    return request;  // temporary

    auto peer_id = peerFromMTPInput(request._peer);
    auto key = storage_.GetCurrentEncryptionKey(peer_id);
    if (!key) {
        return request;
    }

    auto new_flags = request._flags.v | MTPmessages_SaveDraft::Flag::f_entities;
    return MTPmessages_SaveDraft(
        MTP_flags(new_flags),
        request._reply_to,
        request._peer,
        EncryptMTPString(request._message, key),
        EncryptMTPMessageEntities(request._entities, key),
        request._media,
        request._effect,
        request._suggested_post
    );
}

QByteArray Intermediary::SerializeInitiatorDH(const DHAuthState& state, PeerId initiator_id) {
    bytes::array<kSaltSize> salt;
    bytes::set_random(salt);
    
    uint32 g_a_size = state.params.g_a.size();
    uint32 prime_size = state.params.prime.size();

    const uint32 total_size = sizeof(g_a_size)
                            + g_a_size
                            + sizeof(prime_size)
                            + prime_size
                            + sizeof(state.params.g)
                            + 2 * sizeof(state.acceptor_id.value)
                            + sizeof(state.nonce)
                            + kSaltSize; 
    QByteArray result;
    result.resize(total_size);
    char* dst = result.data();
    auto serializer = [&](const char* src, uint32 size) {
        ::memcpy(dst, src, size);
        dst += size; 
    };
    serializer(reinterpret_cast<const char*>(&g_a_size), sizeof(g_a_size));
    serializer(reinterpret_cast<const char*>(state.params.g_a.data()), g_a_size);
    serializer(reinterpret_cast<const char*>(&prime_size), sizeof(prime_size));
    serializer(reinterpret_cast<const char*>(state.params.prime.data()), prime_size);
    serializer(reinterpret_cast<const char*>(&state.params.g), sizeof(state.params.g));
    serializer(reinterpret_cast<const char*>(&state.nonce), sizeof(state.nonce));
    serializer(reinterpret_cast<const char*>(&initiator_id.value), sizeof(initiator_id.value));
    serializer(reinterpret_cast<const char*>(&state.acceptor_id.value), sizeof(state.acceptor_id.value));
    serializer(reinterpret_cast<const char*>(salt.data()), kSaltSize);
    return result;
}

DHAuthPart Intermediary::DeserializeDHPart(const QByteArray& serialized) {
    DHAuthPart state;
    const char* src = serialized.constData(); 
    uint32 total_size = 0;
    auto deserializer = [&](char* dst, uint32 size) {
        total_size += size;
        if (total_size > serialized.size()) {
            return true;
        }
        ::memcpy(dst, src, size);
        src += size;
        return false;
    };

    uint32 g_a_size;
    uint32 prime_size;

    if (deserializer(reinterpret_cast<char*>(&g_a_size), sizeof(g_a_size))) {
        return {};
    }
    state.params.g_a.resize(g_a_size);
    if (deserializer(reinterpret_cast<char*>(state.params.g_a.data()), g_a_size) |
        deserializer(reinterpret_cast<char*>(&prime_size), sizeof(prime_size))) {
        return {};
    }
    state.params.prime.resize(prime_size);
    if (deserializer(reinterpret_cast<char*>(state.params.prime.data()), prime_size) |
        deserializer(reinterpret_cast<char*>(&state.params.g), sizeof(state.params.g)) |
        deserializer(reinterpret_cast<char*>(&state.nonce), sizeof(state.nonce)) |
        deserializer(reinterpret_cast<char*>(&state.initiator_id.value), sizeof(state.initiator_id.value)) |
        deserializer(reinterpret_cast<char*>(&state.acceptor_id.value), sizeof(state.acceptor_id.value))) {
        return {};
    }
    return state;
}

QByteArray Intermediary::SerializeDHPart(const DHAuthPart& initiator_part, bytes::const_span g_b) {
    bytes::array<kSaltSize> salt;
    bytes::set_random(salt);
    
    uint32 g_b_size = g_b.size();
    uint32 prime_size = initiator_part.params.prime.size();

    const uint32 total_size = sizeof(g_b_size)
                            + g_b_size
                            + sizeof(prime_size)
                            + prime_size
                            + sizeof(initiator_part.params.g)
                            + 2 * sizeof(initiator_part.acceptor_id.value)
                            + sizeof(initiator_part.nonce)
                            + kSaltSize;
    QByteArray result;
    result.resize(total_size);
    char* dst = result.data();
    auto serializer = [&](const char* src, uint32 size) {
        ::memcpy(dst, src, size);
        dst += size; 
    };
    serializer(reinterpret_cast<const char*>(&g_b_size), sizeof(g_b_size));
    serializer(reinterpret_cast<const char*>(g_b.data()), g_b_size);
    serializer(reinterpret_cast<const char*>(&prime_size), sizeof(prime_size));
    serializer(reinterpret_cast<const char*>(initiator_part.params.prime.data()), prime_size);
    serializer(reinterpret_cast<const char*>(&initiator_part.params.g), sizeof(initiator_part.params.g));
    serializer(reinterpret_cast<const char*>(&initiator_part.nonce), sizeof(initiator_part.nonce));
    serializer(reinterpret_cast<const char*>(&initiator_part.initiator_id.value), sizeof(initiator_part.initiator_id.value));
    serializer(reinterpret_cast<const char*>(&initiator_part.acceptor_id.value), sizeof(initiator_part.acceptor_id.value));
    serializer(reinterpret_cast<const char*>(salt.data()), kSaltSize);
    return result;
}


PeerId Intermediary::peerFromMTPInput(const MTPInputPeer& peer) {
    return peer.match([&](const MTPDinputPeerSelf&) {
        return self_id_;
    }, [](const MTPDinputPeerEmpty&) {
        return PeerId(0);
    }, [](const MTPDinputPeerChannel& data) {
        return peerFromChannel(data.vchannel_id());
    }, [](const MTPDinputPeerChannelFromMessage& data) {
        return peerFromChannel(data.vchannel_id());
    }, [](const MTPDinputPeerChat& data) {
        return peerFromChat(data.vchat_id());
    }, [](const MTPDinputPeerUser& data) {
        return peerFromUser(data.vuser_id());
    }, [](const MTPDinputPeerUserFromMessage& data) {
        return peerFromUser(data.vuser_id());
    });
}

MTPInputSingleMedia Intermediary::EncryptMTPInputSingleMedia(const MTPInputSingleMedia& media, EncryptionKeyPtr key) const {
    const auto& data = media.data();
    auto new_flags = data.vflags().v | MTPDinputSingleMedia::Flag::f_entities;
    return MTP_inputSingleMedia(
        MTP_flags(new_flags),
        data.vmedia(),
        data.vrandom_id(),
        EncryptMTPString(data.vmessage(), key),
        data.ventities() ? EncryptMTPMessageEntities(*data.ventities(), key, data.vrandom_id().v) : MTPVector<MTPMessageEntity>()
    );
}

MTPVector<MTPInputSingleMedia> Intermediary::EncryptMTPMultiMedia(const MTPVector<MTPInputSingleMedia>& multi_media, EncryptionKeyPtr key) const {
    QVector<MTPInputSingleMedia> result;
    result.reserve(multi_media.v.size());
    for (const auto& media : multi_media.v) {
        result.emplace_back(EncryptMTPInputSingleMedia(media, key));
    }
    return tl::make_vector(std::move(result));
}

QByteArray Intermediary::EncryptBytes(QByteArray bytes, EncryptionKeyPtr key) const {
    uint16 text_size = bytes.size();
    size_t random_padding_size = CalculateRandomPadding(bytes.size());
    // кратность AES_BLOCK_SIZE.
    size_t total_unaligned = sizeof(text_size) + text_size + random_padding_size;
    size_t alignment = (AES_BLOCK_SIZE - total_unaligned % AES_BLOCK_SIZE) % AES_BLOCK_SIZE;
    random_padding_size += alignment;

    bytes.resize(sizeof(text_size) + text_size + random_padding_size);
    ::memmove(&bytes[sizeof(text_size)], bytes.data(), text_size);
    ::memcpy(&bytes[0], &text_size, sizeof(text_size));
    bytes::set_random(bytes::make_span(&bytes[sizeof(text_size) + text_size], random_padding_size));

    uchar encryptedSHA256[32];
    MTPint128& msgKey(*(MTPint128*)(encryptedSHA256 + 8));

    SHA256_CTX msgKeyLargeContext;
    SHA256_Init(&msgKeyLargeContext);
    SHA256_Update(&msgKeyLargeContext, key->partForMsgKey(), 32);
    SHA256_Update(&msgKeyLargeContext, bytes.constData(), bytes.size());
    SHA256_Final(encryptedSHA256, &msgKeyLargeContext);

    QByteArray encrypted_bytes;
    encrypted_bytes.resize(sizeof(msgKey) + bytes.size());
    ::memcpy(&encrypted_bytes[0], &msgKey, sizeof(msgKey));

    DoubleEncryption::aesIgeEncrypt(bytes.constData(), &encrypted_bytes[sizeof(msgKey)], bytes.size(), key, msgKey);
    return encrypted_bytes;
}

MTPstring Intermediary::EncryptMTPString(const MTPstring& str, EncryptionKeyPtr key) const {
    return tl::make_string(ToBase91(EncryptBytes(str.v, key)));
}

MTPVector<MTPMessageEntity> Intermediary::EncryptMTPMessageEntities(const MTPVector<MTPMessageEntity>& entities, EncryptionKeyPtr key, MsgId64 random_id) const {
    mtpBuffer buf;
    entities.write(buf);
    QByteArray bytes(reinterpret_cast<const char*>(buf.constData()), buf.size() * sizeof(buf[0]));
    
    bytes = EncryptBytes(bytes, key);
    // Кладём сюда id чата, куда отправляется сообщение с этими entities.
    constexpr auto msg_id_size = sizeof(random_id);
    bytes.resize(bytes.size() + msg_id_size);
    ::memcpy(&bytes[bytes.size() - msg_id_size], &random_id, msg_id_size);
    bytes = bytes.toBase64(QByteArray::OmitTrailingEquals | QByteArray::Base64UrlEncoding);

    QVector<MTPMessageEntity> vec;
    vec.reserve(1);
    vec.emplace_back(MTP_messageEntityTextUrl(MTP_int(0), MTP_int(1), tl::make_string(kLinkAbuse + bytes)));
    return tl::make_vector(std::move(vec));
}

MTP::Response Intermediary::ProcessResponse(const MTP::Response& response) {
    if (response.reply.isEmpty()) {  // Вроде лишняя проверка, но пусть пока будет.
        return response;
    }

    // Пытаемся определить тип сообщения через метод read каждого кандидата,
    // мне показалось это лучше, чем ещё более огромный switch-case, хотя
    // по факту весь объем кода просто уйдёт внутрь других функций.
    const mtpPrime* from = nullptr;
    mtpBuffer processed_reply;
    if (auto message = MTPmessages_Messages();
        message.read(from = response.reply.constData(), response.reply.constData() + response.reply.size())) {
        ProcessMessage(message).write(processed_reply);
        return {processed_reply, response.outerMsgId, response.requestId};
    }
    if (auto message = MTPUpdates();
        message.read(from = response.reply.constData(), response.reply.constData() + response.reply.size())) {
        ProcessMessage(message).write(processed_reply);
        return {processed_reply, response.outerMsgId, response.requestId};
    }
    if (auto message = MTPupdates_Difference();
        message.read(from = response.reply.constData(), response.reply.constData() + response.reply.size())) {
        ProcessMessage(message).write(processed_reply);
        return {processed_reply, response.outerMsgId, response.requestId};
    }
    if (auto message = MTPmessages_Dialogs();
        message.read(from = response.reply.constData(), response.reply.constData() + response.reply.size())) {
        ProcessMessage(message).write(processed_reply);
        return {processed_reply, response.outerMsgId, response.requestId};
    }
    if (auto message = MTPmessages_PeerDialogs();
        message.read(from = response.reply.constData(), response.reply.constData() + response.reply.size())) {
        ProcessMessage(message).write(processed_reply);
        return {processed_reply, response.outerMsgId, response.requestId};
    }
    if (auto message = MTPmessages_SavedDialogs();
        message.read(from = response.reply.constData(), response.reply.constData() + response.reply.size())) {
        ProcessMessage(message).write(processed_reply);
        return {processed_reply, response.outerMsgId, response.requestId};
    }

    // Ничего не делаем, если не нашли подходщий тип.
    return response;
}

QByteArray Intermediary::DecryptBytes(QByteArray bytes, EncryptionKeyPtr key) const {
    // должно быть bytes.size() >= sizeof(msgKey)//, иначе вернем bytes как есть и ошибку.
    MTPint128 msgKey;
    if (bytes.size() < sizeof(msgKey)) {
        return bytes;
    }
    uint16 data_size = bytes.size() - sizeof(msgKey);
    ::memcpy(&msgKey, &bytes[0], sizeof(msgKey));
    auto text = QByteArray(data_size, Qt::Uninitialized);
    const char* encrypted_text = bytes.constData() + sizeof(msgKey);

    // assert(data_size % AES_BLOCK_SIZE == 0); //, иначе вернем bytes как есть и ошибку.
    if (data_size % AES_BLOCK_SIZE != 0) {
        return bytes;
    }

    DoubleEncryption::aesIgeDecrypt(encrypted_text, text.data(), data_size, key, msgKey);
    uint16 text_size;
    ::memcpy(&text_size, text.constData(), sizeof(text_size));
    
    if (text_size > text.size() - sizeof(text_size)) {
        return bytes;
    }

    return QByteArray(text.constData() + sizeof(text_size), text_size);
}

MTPstring Intermediary::DecryptMTPString(const MTPstring& str, EncryptionKeyPtr key) const {
    return tl::make_string(DecryptBytes(FromBase91(str.v), key));
}

MTPVector<MTPMessageEntity> Intermediary::DecryptMTPMessageEntities(const MTPVector<MTPMessageEntity>& entities, MsgId64 msg_id) {
    // entities.size() > 0, иначе вернем entities как есть и ошибку.
    if (entities.v.isEmpty()) {
        return entities;
    }

    // assert(entities.v[0].type() == mtpc_messageEntityTextUrl); // temporary, иначе вернем entities как есть и ошибку.
    if (entities.v[0].type() != mtpc_messageEntityTextUrl) {
        return entities;
    }

    size_t data_size = entities.v[0].c_messageEntityTextUrl().vurl().v.size() - kLinkAbuse.size();
    MsgId64 random_id;
    constexpr auto msg_id_size = sizeof(random_id);
    // assert(data_size > msg_id_size); // иначе вернем entities как есть и ошибку.
    if (data_size <= msg_id_size) {
        return entities;
    }

    QByteArray data = QByteArray::fromBase64(entities.v[0].c_messageEntityTextUrl().vurl().v.last(data_size), QByteArray::Base64UrlEncoding);
    ::memcpy(&random_id, &data[data.size() - msg_id_size], msg_id_size);
    
    PeerId peer_id = account_->session().data().messageSentData(random_id).peerId;
    if (!peer_id) {
        return entities;
    }

    auto [key, msg_end_id] = storage_.FindKey(peer_id, msg_id);
    if (!key) {
        return entities;
    }

    data.resize(data.size() - msg_id_size);

    QByteArray decrypted_bytes = DecryptBytes(data, key);
    mtpBuffer buf;
    // assert(decrypted_bytes.size() % sizeof(buf[0]) == 0); // temporary, вернем entities как есть и ошибку.
    if (decrypted_bytes.size() % sizeof(buf[0]) != 0) {
        return entities;
    }
    buf.resize(decrypted_bytes.size() / sizeof(buf[0]));
    ::memcpy(buf.data(), decrypted_bytes.constData(), decrypted_bytes.size());
    MTPVector<MTPMessageEntity> decrypted_vec;
    const mtpPrime* from = buf.constData();
    bool successful = decrypted_vec.read(from, buf.constData() + buf.size());
    if (!successful) {
        return entities;
    }
    return decrypted_vec;
}

MTPVector<MTPMessageEntity> Intermediary::DecryptMTPMessageEntities(const MTPVector<MTPMessageEntity>& entities, EncryptionKeyPtr key) const {    
    // entities.size() > 0, иначе вернем entities как есть и ошибку.
    if (entities.v.isEmpty()) {
        return entities;
    }

    if (entities.v[0].type() != mtpc_messageEntityTextUrl) {
        return entities;
    }
    size_t data_size = entities.v[0].c_messageEntityTextUrl().vurl().v.size() - kLinkAbuse.size();
    constexpr auto msg_id_size = sizeof(MsgId64);
    if (data_size <= msg_id_size) {
        return entities;
    }

    QByteArray data = QByteArray::fromBase64(entities.v[0].c_messageEntityTextUrl().vurl().v.last(data_size), QByteArray::Base64UrlEncoding);
    data.resize(data.size() - msg_id_size);

    QByteArray decrypted_bytes = DecryptBytes(data, key);
    mtpBuffer buf;
    if (decrypted_bytes.size() % sizeof(buf[0]) != 0) {
        return entities;
    }
    buf.resize(decrypted_bytes.size() / sizeof(buf[0]));
    ::memcpy(buf.data(), decrypted_bytes.constData(), decrypted_bytes.size());
    MTPVector<MTPMessageEntity> decrypted_vec;
    const mtpPrime* from = buf.constData();
    bool successful = decrypted_vec.read(from, buf.constData() + buf.size());
    if (!successful) {
        return entities;
    }
    return decrypted_vec;
}

MTPMessage Intermediary::ProcessMessage(const MTPMessage& message) {
    return message.match(
        [&](const MTPDmessage& data) {
            auto peer_id = peerFromMTP(data.vpeer_id());
            PeerId from_id = data.vfrom_id() ? peerFromMTP(*data.vfrom_id()) : 0;

            if (dm_auth_state_ && dm_auth_state_->acceptor_id == peer_id && peer_id == from_id) {
                assert(peer_id != self_id_);
                if (!TryToAcceptEncryptionResponse(data.vmessage().v, peer_id, data.vid().v)) {
                    qCritical() << "failed to accept encryption response";
                } else {
                    return MTP_messageEmpty(
                        MTP_flags(0),
                        MTP_int(1),
                        MTPPeer()
                    );
                }
            }

            auto [key, msg_end_id] = storage_.FindKey(peer_id, data.vid().v);

            assert(data.vid().v < msg_end_id);
            return MTP_message(
                data.vflags(),
                data.vid(),
                UnpackConditional(data.vfrom_id()),
                UnpackConditional(data.vfrom_boosts_applied()),
                UnpackConditional(data.vfrom_rank()),
                data.vpeer_id(),
                UnpackConditional(data.vsaved_peer_id()),
                UnpackConditional(data.vfwd_from()),
                UnpackConditional(data.vvia_bot_id()),
                UnpackConditional(data.vvia_business_bot_id()),
                UnpackConditional(data.vreply_to()),
                data.vdate(),
                key ? DecryptMTPString(data.vmessage(), key) : data.vmessage(), // расшифрование сообщения
                UnpackConditional(data.vmedia()),
                UnpackConditional(data.vreply_markup()),
                data.ventities() ? (key ? DecryptMTPMessageEntities(*data.ventities(), key) : *data.ventities()) : MTPVector<MTPMessageEntity>(),
                UnpackConditional(data.vviews()),
                UnpackConditional(data.vforwards()),
                UnpackConditional(data.vreplies()),
                UnpackConditional(data.vedit_date()),
                UnpackConditional(data.vpost_author()),
                UnpackConditional(data.vgrouped_id()),
                UnpackConditional(data.vreactions()),
                UnpackConditional(data.vrestriction_reason()),
                UnpackConditional(data.vttl_period()),
                UnpackConditional(data.vquick_reply_shortcut_id()),
                UnpackConditional(data.veffect()),
                UnpackConditional(data.vfactcheck()),
                UnpackConditional(data.vreport_delivery_until_date()),
                UnpackConditional(data.vpaid_message_stars()),
                UnpackConditional(data.vsuggested_post()),
                UnpackConditional(data.vschedule_repeat_period()),
                UnpackConditional(data.vsummary_from_language())
            );
        },
        [&](const MTPDmessageEmpty& data) {
            return MTP_messageEmpty(
                data.vflags(),
                data.vid(),
                UnpackConditional(data.vpeer_id())
            );
        },
        [&](const MTPDmessageService& data) {
            return MTP_messageService(
                data.vflags(),
                data.vid(),
                UnpackConditional(data.vfrom_id()),
                data.vpeer_id(),
                UnpackConditional(data.vsaved_peer_id()),
                UnpackConditional(data.vreply_to()),
                data.vdate(),
                data.vaction(),
                UnpackConditional(data.vreactions()),
                UnpackConditional(data.vttl_period())
            );
        });
}

MTPmessages_Messages Intermediary::ProcessMessage(const MTPmessages_Messages& messages) {
    return messages.match(
        [&](const MTPDmessages_messages& data) {
            return MTP_messages_messages(
                ProcessMessage(data.vmessages()),  // расшифрование сообщений
                data.vtopics(),
                data.vchats(),
                data.vusers()
            );
        },
        [&](const MTPDmessages_messagesSlice& data) {
            return MTP_messages_messagesSlice(
                data.vflags(),
                data.vcount(),
                UnpackConditional(data.vnext_rate()),
                UnpackConditional(data.voffset_id_offset()),
                UnpackConditional(data.vsearch_flood()),
                ProcessMessage(data.vmessages()), // расшифрование сообщений
                data.vtopics(),
                data.vchats(),
                data.vusers()
            );
        },
        [&](const MTPDmessages_channelMessages& data) {
            return MTP_messages_channelMessages(
                data.vflags(),
                data.vpts(),
                data.vcount(),
                UnpackConditional(data.voffset_id_offset()),
                data.vmessages(), // Не шифруем каналы.
                data.vtopics(),
                data.vchats(),
                data.vusers()
            );
        },
        [&](const MTPDmessages_messagesNotModified& data) { return MTP_messages_messagesNotModified(data.vcount()); });
}

MTPUpdate Intermediary::ProcessMessage(const MTPUpdate& update) {
    // Здесь лучше использовать switch вместо match, т.к.
    // типов очень много, но не далеко все нужно обрабатывать
    switch (update.type()) {
        case mtpc_updateNewMessage: {
            const auto& data = update.c_updateNewMessage();
            return MTP_updateNewMessage(
                ProcessMessage(data.vmessage()),
                data.vpts(),
                data.vpts_count()
            );
        }
            // case mtpc_updateNewChannelMessage: {
            //     const auto &data = update.c_updateNewChannelMessage();
            //     return MTP_updateNewChannelMessage(
            //         ProcessMessage(data.vmessage()), // расшифрование сообщения
            //         data.vpts(),
            //         data.vpts_count()
            //     );
            // }
            // case mtpc_updateEditChannelMessage: {
            //     const auto &data = update.c_updateEditChannelMessage();
            //     return MTP_updateEditChannelMessage(
            //         ProcessMessage(data.vmessage()), // расшифрование сообщения
            //         data.vpts(),
            //         data.vpts_count()
            //     );
            // }
        case mtpc_updateEditMessage: {
            const auto& data = update.c_updateEditMessage();
            return MTP_updateEditMessage(
                ProcessMessage(data.vmessage()), // расшифрование сообщения
                data.vpts(),
                data.vpts_count()
            );
        }
    }
    return update;
}

MTPUpdates Intermediary::ProcessMessage(const MTPUpdates& updates) {
    return updates.match(
        [&](const MTPDupdatesTooLong& data) { return MTP_updatesTooLong(); },
        [&](const MTPDupdateShortMessage& data) {
            auto peer_id = peerFromMTP(MTP_peerUser(data.vuser_id()));

            if (dm_auth_state_ && dm_auth_state_->acceptor_id == peer_id) {
                assert(peer_id != self_id_);
                if (!TryToAcceptEncryptionResponse(data.vmessage().v, peer_id, data.vid().v)) {
                    qCritical() << "failed to accept encryption response";
                } else {
                    return MTP_updatesTooLong();
                }
            }

            auto [key, msg_end_id] = storage_.FindKey(peer_id, data.vid().v);
            
            assert(data.vid().v < msg_end_id);

            return MTP_updateShortMessage(
                data.vflags(),
                data.vid(),
                data.vuser_id(),
                key ? DecryptMTPString(data.vmessage(), key) : data.vmessage(), // расшифрование сообщения
                data.vpts(),
                data.vpts_count(),
                data.vdate(),
                UnpackConditional(data.vfwd_from()),
                UnpackConditional(data.vvia_bot_id()),
                UnpackConditional(data.vreply_to()),
                data.ventities() ? (key ? DecryptMTPMessageEntities(*data.ventities(), key) : *data.ventities()) : MTPVector<MTPMessageEntity>(),
                UnpackConditional(data.vttl_period())
            );
        },
        [&](const MTPDupdateShortChatMessage& data) {
            auto peer_id = peerFromMTP(MTP_peerChat(data.vchat_id()));
            auto [key, msg_end_id] = storage_.FindKey(peer_id, data.vid().v);

            assert(data.vid().v < msg_end_id);

            return MTP_updateShortChatMessage(
                data.vflags(),
                data.vid(),
                data.vfrom_id(),
                data.vchat_id(),
                key ? DecryptMTPString(data.vmessage(), key) : data.vmessage(), // расшифрование сообщения
                data.vpts(),
                data.vpts_count(),
                data.vdate(),
                UnpackConditional(data.vfwd_from()),
                UnpackConditional(data.vvia_bot_id()),
                UnpackConditional(data.vreply_to()),
                data.ventities() ? (key ? DecryptMTPMessageEntities(*data.ventities(), key) : *data.ventities()) : MTPVector<MTPMessageEntity>(),
                UnpackConditional(data.vttl_period())
            );
        },
        [&](const MTPDupdateShort& data) {
            return MTP_updateShort(
                ProcessMessage(data.vupdate()), // расшифрование апдейтов
                data.vdate()
            );
        },
        [&](const MTPDupdatesCombined& data) {
            return MTP_updatesCombined(
                ProcessMessage(data.vupdates()), // расшифрование апдейтов
                data.vusers(),
                data.vchats(),
                data.vdate(),
                data.vseq_start(),
                data.vseq()
            );
        },
        [&](const MTPDupdates& data) {
            return MTP_updates(
                ProcessMessage(data.vupdates()), // расшифрование апдейтов
                data.vusers(),
                data.vchats(),
                data.vdate(),
                data.vseq()
            );
        },
        [&](const MTPDupdateShortSentMessage& data) {
            // Проблема с этим вариантом, т.к. тут нет peer_id
            // Только ради этого варианта updates пришлось вставлять
            // random_id (генерируется телеграмом) в entities при отправке.
            // Есть более простой вариант -- вставлять peer_id, но это будет
            // уязвимостью по меркам оригинального телеграма, т.к. позволит
            // кому угодно узнать по сообщению, кому оно адресовано.

            MTPVector<MTPMessageEntity> entities = data.ventities() ?
                                                   DecryptMTPMessageEntities(*data.ventities(), data.vid().v) :
                                                   MTPVector<MTPMessageEntity>();

            return MTP_updateShortSentMessage(
                data.vflags(),
                data.vid(),
                data.vpts(),
                data.vpts_count(),
                data.vdate(),
                UnpackConditional(data.vmedia()), 
                entities,
                UnpackConditional(data.vttl_period())
            );
        });
}

MTPupdates_Difference Intermediary::ProcessMessage(const MTPupdates_Difference& updates) {
    return updates.match(
        [&](const MTPDupdates_differenceEmpty& data) { return MTP_updates_differenceEmpty(data.vdate(), data.vseq()); },
        [&](const MTPDupdates_difference& data) {
            return MTP_updates_difference(
                ProcessMessage(data.vnew_messages()), // расшифрование сообщений
                data.vnew_encrypted_messages(),
                ProcessMessage(data.vother_updates()), // расшифрование апдейтов
                data.vchats(),
                data.vusers(),
                data.vstate()
            );
        },
        [&](const MTPDupdates_differenceSlice& data) {
            return MTP_updates_differenceSlice(
                ProcessMessage(data.vnew_messages()),  // расшифрование сообщений
                data.vnew_encrypted_messages(),
                ProcessMessage(data.vother_updates()),  // расшифрование апдейтов
                data.vchats(),
                data.vusers(),
                data.vintermediate_state()
            );
        },
        [&](const MTPDupdates_differenceTooLong& data) { 
            return MTP_updates_differenceTooLong(data.vpts());
        });
}

MTPmessages_Dialogs Intermediary::ProcessMessage(const MTPmessages_Dialogs& dialogs) {
    return dialogs.match(
        [&](const MTPDmessages_dialogs& data) {
            return MTP_messages_dialogs(
                data.vdialogs(),
                ProcessMessage(data.vmessages()), // расшифрование сообщений
                data.vchats(),
                data.vusers()
            );
        },
        [&](const MTPDmessages_dialogsSlice& data) {
            return MTP_messages_dialogsSlice(
                data.vcount(),
                data.vdialogs(),
                ProcessMessage(data.vmessages()),  // расшифрование сообщений
                data.vchats(), data.vusers()
            );
        },
        [&](const MTPDmessages_dialogsNotModified& data) {
            return MTP_messages_dialogsNotModified(data.vcount());
        });
}

MTPmessages_PeerDialogs Intermediary::ProcessMessage(const MTPmessages_PeerDialogs& dialogs) {
    const auto& data = dialogs.data();
    return MTP_messages_peerDialogs(
        data.vdialogs(),
        ProcessMessage(data.vmessages()), // расшифрование сообщений
        data.vchats(),
        data.vusers(),
        data.vstate()
    );
}

MTPmessages_SavedDialogs Intermediary::ProcessMessage(const MTPmessages_SavedDialogs& dialogs) {
    return dialogs.match(
        [&](const MTPDmessages_savedDialogs& data) {
            return MTP_messages_savedDialogs(
                data.vdialogs(),
                ProcessMessage(data.vmessages()), // расшифрование сообщений
                data.vchats(),
                data.vusers()
            );
        },
        [&](const MTPDmessages_savedDialogsSlice& data) {
            return MTP_messages_savedDialogsSlice(
                data.vcount(),
                data.vdialogs(),
                ProcessMessage(data.vmessages()), // расшифрование сообщений
                data.vchats(),
                data.vusers()
            );
        },
        [&](const MTPDmessages_savedDialogsNotModified& data) {
            return MTP_messages_savedDialogsNotModified(data.vcount());
        });
}

const QByteArray Intermediary::kLinkAbuse = "http://a.io/";

}  // namespace DoubleEncryption
