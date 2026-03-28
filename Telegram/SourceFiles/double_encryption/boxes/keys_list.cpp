#include "keys_list.h"

#include <algorithm>
#include "base/openssl_help.h"
#include "window/window_controller.h"
#include "window/window_session_controller.h"

#include "../texts_and_titles.h"
#include "../storage/gpg_manager.h"

namespace DoubleEncryption {

object_ptr<Ui::BoxContent> PrepareManageKeysList(not_null<Window::SessionController*> controller, bool pub) {
    auto init = [=](not_null<Ui::GenericBox*> box) {
        box->setTitle(rpl::single(pub ? QString(settings_manage_public_keys_button_name)
                                      : QString(settings_manage_private_keys_button_name)) |
                      rpl::type_erased);
        auto layout = box->verticalLayout();
        auto changes_stream = std::make_shared<rpl::event_stream<>>();
        auto rebuild_box = [=]() {
            layout->clear();
            auto insert_operation = [=](const QString& key) { return GPGManager::Instance().InsertKey(key); };
            auto delete_operation = [=](const QString& fingerprint) {
                pub ? GPGManager::Instance().DeletePublicKey(fingerprint)
                    : GPGManager::Instance().DeletePrivateKey(fingerprint);
            };
            auto key_infos = pub ? GPGManager::Instance().ListPublicKeys() : GPGManager::Instance().ListPrivateKeys();
            std::sort(key_infos.begin(), key_infos.end(),
                      [](const auto& info1, const auto& info2) { return info1.creation_time < info2.creation_time; });

            for (const auto& info : key_infos) {
                auto button = object_ptr<Ui::SettingsButton>(layout, rpl::single(info.name));
                button->setClickedCallback([=] {
                    qDebug() << "Button clicked\n";
                    auto key = pub ? GPGManager::Instance().FindPublicKey(info.fingerprint)
                                   : GPGManager::Instance().FindPrivateKey(info.fingerprint);
                    if (key) {
                        controller->window().show(
                            Box<ManageKeyBox>(info, *key, changes_stream, insert_operation, delete_operation));
                        OPENSSL_cleanse(key->data(), key->size());
                    }
                });

                layout->add(std::move(button));
            }
            auto last_button = object_ptr<Ui::SettingsButton>(layout, rpl::single(QString("Add new key")));
            last_button->setClickedCallback([=] {
                // qDebug() << "Button clicked\n";
                controller->window().show(Box<ManageKeyBox>(changes_stream, insert_operation, delete_operation));
            });
            layout->add(std::move(last_button));
        };

        rebuild_box();
        changes_stream->events() | rpl::on_next([=] { rebuild_box(); }, box->lifetime());
    };

    return Box<Ui::GenericBox>(std::move(init));
}

object_ptr<Ui::BoxContent> PrepareSelectionKeysList(std::function<std::vector<AuthKeyInfo>()> fetcher,
                                                    std::function<bool(const AuthKeyInfo&)> button_callback) {
    auto init = [=](not_null<Ui::GenericBox*> box) {
        box->setTitle(rpl::single(QString(secure_connection_public_keys_menu_title_)) | rpl::type_erased);

        auto layout = box->verticalLayout();
        auto key_infos = fetcher();
        for (const auto& info : key_infos) {
            auto button = object_ptr<Ui::SettingsButton>(layout, rpl::single(info.name));
            button->setClickedCallback([=] {
                if (button_callback(info)) {
                    box->closeBox();
                    return;
                }
                qCritical() << "Task with key" << '\"' << info.name << '\"' << "failed";
            });
            layout->add(std::move(button));
        }
    };

    return Box<Ui::GenericBox>(std::move(init));
}

object_ptr<Ui::BoxContent> PreparePublicKeysSelectionList(not_null<Window::SessionController*> controller,
                                                           std::function<bool(const AuthKeyInfo&)> selection_action) {
    return PrepareSelectionKeysList(
        []() {
            auto key_infos = GPGManager::Instance().ListPublicKeys();
            std::sort(key_infos.begin(), key_infos.end(),
                      [](const auto& info1, const auto& info2) { return info1.creation_time < info2.creation_time; });
            return key_infos;
        },
        selection_action
    );
}

}  // namespace DoubleEncryption
