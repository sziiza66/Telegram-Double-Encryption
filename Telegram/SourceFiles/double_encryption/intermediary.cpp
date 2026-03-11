#include "intermediary.h"
#include <cassert>

#include "encryption_key.h"

#include "history/history_item.h"
#include "history/history.h"
#include "data/data_session.h"
#include "main/main_account.h"
#include "main/main_session.h"
#include "data/data_peer.h"
#include "base/openssl_help.h"
#include "storage/secret_storage.h"

namespace DoubleEncryption {

Intermediary::Intermediary(Account* account, UserId self_id)
    : storage_(peerFromUser(self_id)), account_(account), self_id_(peerFromUser(self_id)) {
    assert(account);
}

bool Intermediary::IsPeerEncrypted(PeerId peer_id) {
    return storage_.IsPeerEncrypted(peer_id);
}

void Intermediary::SwitchEncryptionForPeer(PeerId peer_id) {
    auto last_message = account_->session().data().history(peer_id)->lastMessage();
    MsgId64 last_msg_id = last_message ? last_message->id.bare : 0;
    if (IsPeerEncrypted(peer_id)) {
        storage_.CloseInterval(peer_id, last_msg_id + 1);
    } else {
        EncryptionKeyPtr key = GenerateSecret();
        storage_.OpenNewInterval(peer_id, last_msg_id + 1, key);
    }
}

EncryptionKeyPtr Intermediary::GenerateSecret() const {
    // Нужно будет всё-таки убедиться в безопасности этого генератора,
    // Telegram генерирует параметры DH через него, так что скорее всего все норм
    EncryptionKey::Data random;
    bytes::set_random(random);
    return std::make_shared<EncryptionKey>(random);
}

MTPmessages_SendMessage Intermediary::ProcessRequest(const MTPmessages_SendMessage& request) {
    auto peer_id = peerFromMTPInput(request._peer);
    auto key = storage_.GetCurrentEncryptionKey(peer_id);
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
    // bytes.size() не больше 4096 (ограничение Telegram)
    uint16 text_size = bytes.size();
    
    // кратность AES_BLOCK_SIZE.
    auto padding_size = (AES_BLOCK_SIZE - (text_size + sizeof(text_size)) % AES_BLOCK_SIZE) % AES_BLOCK_SIZE;
    bytes.resize(text_size + padding_size + sizeof(text_size));
    ::memcpy(&bytes[text_size + padding_size], &text_size, sizeof(text_size));

    uchar encryptedSHA256[32];
    MTPint128& msgKey(*(MTPint128*)(encryptedSHA256 + 8));

    SHA256_CTX msgKeyLargeContext;
    SHA256_Init(&msgKeyLargeContext);
    SHA256_Update(&msgKeyLargeContext, key->partForMsgKey(true), 32);
    SHA256_Update(&msgKeyLargeContext, bytes.constData(), bytes.size());
    SHA256_Final(encryptedSHA256, &msgKeyLargeContext);

    QByteArray encrypted_bytes;
    encrypted_bytes.resize(sizeof(msgKey) + bytes.size());
    ::memcpy(&encrypted_bytes[0], &msgKey, sizeof(msgKey));


    auto prefix_size = 0 + sizeof(msgKey);

    DoubleEncryption::aesIgeEncrypt(bytes.constData(), &encrypted_bytes[prefix_size], bytes.size(), key, msgKey);
    return encrypted_bytes;
}

MTPstring Intermediary::EncryptMTPString(const MTPstring& str, EncryptionKeyPtr key) const {
    return tl::make_string(EncryptBytes(str.v, key).toBase64(QByteArray::OmitTrailingEquals));
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

    // MTPString test = tl::make_string(QString("https://test.net"));
    // QVector<MTPMessageEntity> vec;
    // vec.reserve(1);
    // vec.emplace_back(MTP_messageEntityTextUrl(MTP_int(0), MTP_int(1), test));
    // return tl::make_vector(std::move(vec));
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
    uint16 data_size = bytes.size() - sizeof(msgKey);
    ::memcpy(&msgKey, &bytes[0], sizeof(msgKey));
    auto text = QByteArray(data_size, Qt::Uninitialized);
    const char* encrypted_text = bytes.constData() + sizeof(msgKey);

    assert(data_size % AES_BLOCK_SIZE == 0); //, иначе вернем bytes как есть и ошибку.

    DoubleEncryption::aesIgeDecrypt(encrypted_text, text.data(), data_size, key, msgKey);
    uint16 text_size;
    ::memcpy(&text_size, &text[data_size - sizeof(text_size)], sizeof(text_size));
    
    // text_size <= data_size - sizeof(text_size)//, иначе вернем bytes как есть и ошибку.

    text.resize(text_size);
    return text;
}

MTPstring Intermediary::DecryptMTPString(const MTPstring& str, EncryptionKeyPtr key) const {
    return tl::make_string(DecryptBytes(QByteArray::fromBase64(str.v), key));
}

MTPVector<MTPMessageEntity> Intermediary::DecryptMTPMessageEntities(const MTPVector<MTPMessageEntity>& entities, MsgId64 msg_id) {
    // entities.size() == 1, иначе вернем entities как есть и ошибку.
    assert(entities.v.size() > 0); // temporary

    assert(entities.v[0].type() == mtpc_messageEntityTextUrl); // temporary, иначе вернем entities как есть и ошибку.
    size_t data_size = entities.v[0].c_messageEntityTextUrl().vurl().v.size() - kLinkAbuse.size();
    MsgId64 random_id;
    constexpr auto msg_id_size = sizeof(random_id);
    assert(data_size > msg_id_size); // иначе вернем entities как есть и ошибку.

    QByteArray data = QByteArray::fromBase64(entities.v[0].c_messageEntityTextUrl().vurl().v.last(data_size), QByteArray::Base64UrlEncoding);
    ::memcpy(&random_id, &data[data.size() - msg_id_size], msg_id_size);
    
    PeerId peer_id = account_->session().data().messageSentData(random_id).peerId;
    assert(peer_id); // иначе вернем entities как есть и ошибку.

    auto [key, msg_end_id] = storage_.FindKey(peer_id, msg_id);
    assert(key); // иначе вернем entities как есть и ошибку.

    data.resize(data.size() - msg_id_size);

    QByteArray decrypted_bytes = DecryptBytes(data, key);
    mtpBuffer buf;
    assert(decrypted_bytes.size() % sizeof(buf[0]) == 0); // temporary, вернем entities как есть и ошибку.
    buf.resize(decrypted_bytes.size() / sizeof(buf[0]));
    ::memcpy(buf.data(), decrypted_bytes.constData(), decrypted_bytes.size());
    MTPVector<MTPMessageEntity> decrypted_vec;
    const mtpPrime* from = buf.constData();
    bool successful = decrypted_vec.read(from, buf.constData() + buf.size());
    assert(successful); // temporary
    return decrypted_vec;
}

MTPVector<MTPMessageEntity> Intermediary::DecryptMTPMessageEntities(const MTPVector<MTPMessageEntity>& entities, EncryptionKeyPtr key) const {    
    // entities.size() == 1, иначе вернем entities как есть и ошибку.
    assert(entities.v.size() > 0); // temporary

    assert(entities.v[0].type() == mtpc_messageEntityTextUrl); // temporary, иначе вернем entities как есть и ошибку.
    size_t data_size = entities.v[0].c_messageEntityTextUrl().vurl().v.size() - kLinkAbuse.size();
    constexpr auto msg_id_size = sizeof(MsgId64);
    assert(data_size > msg_id_size); // иначе вернем entities как есть и ошибку.

    QByteArray data = QByteArray::fromBase64(entities.v[0].c_messageEntityTextUrl().vurl().v.last(data_size), QByteArray::Base64UrlEncoding);
    data.resize(data.size() - msg_id_size);

    QByteArray decrypted_bytes = DecryptBytes(data, key);
    mtpBuffer buf;
    assert(decrypted_bytes.size() % sizeof(buf[0]) == 0); // temporary, вернем entities как есть и ошибку.
    buf.resize(decrypted_bytes.size() / sizeof(buf[0]));
    ::memcpy(buf.data(), decrypted_bytes.constData(), decrypted_bytes.size());
    MTPVector<MTPMessageEntity> decrypted_vec;
    const mtpPrime* from = buf.constData();
    bool successful = decrypted_vec.read(from, buf.constData() + buf.size());
    assert(successful); // temporary
    return decrypted_vec;

    // if (entities.v.size() > 0) {
    //     auto type = entities.v[0].type(); 
    //     auto str = entities.v[0].c_messageEntityTextUrl().vurl().v;
    //     return MTPVector<MTPMessageEntity>();
    // }
    // return entities;
}

MTPMessage Intermediary::ProcessMessage(const MTPMessage& message) {
    return message.match(
        [&](const MTPDmessage& data) {
            auto peer_id = peerFromMTP(data.vpeer_id());
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
            return MTP_messageEmpty(data.vflags(),
                data.vid(),
                UnpackConditional(data.vpeer_id())
            );
        },
        [&](const MTPDmessageService& data) {
            return MTP_messageService(data.vflags(),
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
            return MTP_updateShortSentMessage(
                data.vflags(),
                data.vid(),
                data.vpts(),
                data.vpts_count(),
                data.vdate(),
                UnpackConditional(data.vmedia()), 
                data.ventities() ? DecryptMTPMessageEntities(*data.ventities(), data.vid().v) : MTPVector<MTPMessageEntity>(),
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
