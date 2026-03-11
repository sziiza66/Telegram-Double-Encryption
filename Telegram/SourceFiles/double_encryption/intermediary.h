#pragma once

#include "mtproto/mtproto_response.h"
#include "scheme.h"
#include "storage/secret_storage.h"

class PeerId;
class PeerData;

namespace Main {

class Account;

}

namespace DoubleEncryption {

class Intermediary {
    using Account = Main::Account;

public:
    Intermediary(Account* account, UserId self_id);

    bool IsPeerEncrypted(PeerId peer_id);
    void SwitchEncryptionForPeer(PeerId peer_id);

    EncryptionKeyPtr GenerateSecret() const;

    // Ничего не делаем, если для сообщения сделать нечего.
    // Возможно, стоит кидать ошибку компиляции, в случае неизвестного
    // запроса в целях безопасности при обновлении клиента,
    // но тогда нужно как-то по-другому это всё организовать,
    // чтобы не добавлять по функции каждому известному запросу.
    template <typename Request>
    Request ProcessRequest(const Request& request) {
        return request;
    }

    MTPmessages_SendMessage ProcessRequest(const MTPmessages_SendMessage& request);
    MTPmessages_SendMedia ProcessRequest(const MTPmessages_SendMedia& request);
    MTPmessages_sendMultiMedia ProcessRequest(const MTPmessages_sendMultiMedia& request);
    MTPmessages_EditMessage ProcessRequest(const MTPmessages_EditMessage& request);
    MTPmessages_SaveDraft ProcessRequest(const MTPmessages_SaveDraft& request);

    MTP::Response ProcessResponse(const MTP::Response& response);

private:
    PeerId peerFromMTPInput(const MTPInputPeer& peer);

    MTPInputSingleMedia EncryptMTPInputSingleMedia(const MTPInputSingleMedia& media, EncryptionKeyPtr key) const;
    MTPVector<MTPInputSingleMedia> EncryptMTPMultiMedia(const MTPVector<MTPInputSingleMedia>& multi_media, EncryptionKeyPtr key) const;
    QByteArray EncryptBytes(QByteArray bytes, EncryptionKeyPtr key) const;
    MTPstring EncryptMTPString(const MTPstring& str, EncryptionKeyPtr key) const;
    MTPVector<MTPMessageEntity> EncryptMTPMessageEntities(const MTPVector<MTPMessageEntity>& entities, EncryptionKeyPtr key, MsgId64 random_id = 0) const;

    QByteArray DecryptBytes(QByteArray bytes, EncryptionKeyPtr key) const;
    MTPstring DecryptMTPString(const MTPstring& str, EncryptionKeyPtr key) const;
    MTPVector<MTPMessageEntity> DecryptMTPMessageEntities(const MTPVector<MTPMessageEntity>& entities, MsgId64 msg_id);
    MTPVector<MTPMessageEntity> DecryptMTPMessageEntities(const MTPVector<MTPMessageEntity>& entities, EncryptionKeyPtr key) const;
    MTPMessage ProcessMessage(const MTPMessage& message);
    MTPmessages_Messages ProcessMessage(const MTPmessages_Messages& messages);
    MTPUpdate ProcessMessage(const MTPUpdate& update);
    MTPUpdates ProcessMessage(const MTPUpdates& updates);
    MTPupdates_Difference ProcessMessage(const MTPupdates_Difference& updates);
    MTPmessages_Dialogs ProcessMessage(const MTPmessages_Dialogs& dialogs);
    MTPmessages_PeerDialogs ProcessMessage(const MTPmessages_PeerDialogs& dialogs);
    MTPmessages_SavedDialogs ProcessMessage(const MTPmessages_SavedDialogs& dialogs);

    template <typename MessageType>
    MessageType ProcessMessage(const MessageType& message) {
        static_assert(false, "Trying to process unexpected message type.");
        return MessageType();
    }

    template <typename MessageType>
    MTPVector<MessageType> ProcessMessage(const MTPVector<MessageType>& messages) {
        QVector<MessageType> result;
        result.reserve(messages.v.size());
        for (const auto& message : messages.v) {
            result.emplace_back(ProcessMessage(message));
        }
        return tl::make_vector(std::move(result));
    }

    template <typename T>
    T UnpackConditional(const tl::conditional<T>& c) {
        return c ? *c : T();
    }

    template <typename T>
    T UnpackConditionalAndProcess(const tl::conditional<T>& c) {
        return c ? ProcessMessage(*c) : T();
    }

private:
    SecretStorage storage_;
    Account* account_;  // Не ноль, аккаунт гарантированно существует, пока существует Intermediary, т.к. первый им
                        // управляет через unique_ptr
    PeerId self_id_;
    // Вообще self_id, я лишний раз тут храню это, потому что получить это можно из session, но пока оставлю так.

private:
    // Самое короткое, что я нашел из того, что пропускает телеграм.
    static const QByteArray kLinkAbuse;
};

}  // namespace DoubleEncryption
