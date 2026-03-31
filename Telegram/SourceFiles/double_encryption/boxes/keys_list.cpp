#include "keys_list.h"

#include <algorithm>
#include "base/openssl_help.h"
#include "window/window_controller.h"
#include "window/window_session_controller.h"
// #include "styles/style_boxes.h"
// #include "styles/style_chat_helpers.h"
#include "styles/style_layers.h"
#include "styles/style_settings.h"
// #include "styles/style_menu_icons.h"

#include "../texts_and_titles.h"
#include "../storage/gpg_manager.h"

namespace DoubleEncryption {

object_ptr<Ui::BoxContent> PrepareManageKeysList(not_null<Window::SessionController*> controller, bool pub) {
    auto init = [=](not_null<Ui::GenericBox*> box) {
        const auto title = pub ? QString(settings_manage_public_keys_button_name)
                                      : QString(settings_manage_private_keys_button_name);
        box->setTitle(rpl::single(title) | rpl::type_erased);
        auto layout = box->verticalLayout();
        auto changes_stream = std::make_shared<rpl::event_stream<>>();

        constexpr int kMinWidth = 360;
        constexpr int kMaxWidth = 640;

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

            int required_width = 0;
            required_width = std::max(required_width, st::boxTitleFont->width(title));

            for (const auto& info : key_infos) {
                required_width = std::max(required_width, st::settingsButton.style.font->width(info.name));

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

            const auto new_button_text = QString("Add new key");

            required_width = std::max(required_width, st::settingsButton.style.font->width(new_button_text));

            required_width += st::boxPadding.left() + st::boxPadding.right() + 80;
            required_width = std::clamp(required_width, kMinWidth, kMaxWidth);
            box->setWidth(required_width);

            auto last_button = object_ptr<Ui::SettingsButton>(layout, rpl::single(new_button_text));
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
                                                    const QString& title,
                                                    std::function<bool(const AuthKeyInfo&)> button_callback) {
    auto init = [=](not_null<Ui::GenericBox*> box) {
        box->setTitle(rpl::single(title) | rpl::type_erased);

        constexpr int kMinWidth = 360;
        constexpr int kMaxWidth = 640;

        int required_width = 0;
        required_width = std::max(required_width, st::boxTitleFont->width(title));

        auto layout = box->verticalLayout();
        auto key_infos = fetcher();
        for (const auto& info : key_infos) {
            required_width = std::max(required_width, st::settingsButton.style.font->width(info.name));

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
        required_width += st::boxPadding.left() + st::boxPadding.right() + 80;
        required_width = std::clamp(required_width, kMinWidth, kMaxWidth);
        box->setWidth(required_width);
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
        secure_connection_public_keys_menu_title_,
        selection_action);
}

object_ptr<Ui::BoxContent> PreparePrivateKeysSelectionList(not_null<Window::SessionController*> controller,
                                                           std::function<bool(const AuthKeyInfo&)> selection_action) {
    return PrepareSelectionKeysList(
        []() {
            auto key_infos = GPGManager::Instance().ListPrivateKeys();
            std::sort(key_infos.begin(), key_infos.end(),
                      [](const auto& info1, const auto& info2) { return info1.creation_time < info2.creation_time; });
            return key_infos;
        },
        secure_connection_private_keys_menu_title_,
        selection_action);
}

}  // namespace DoubleEncryption
