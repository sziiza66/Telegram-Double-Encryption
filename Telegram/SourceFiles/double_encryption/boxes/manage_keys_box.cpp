#include "manage_keys_box.h"

#include "lang/lang_keys.h"
#include "base/call_delayed.h"
#include "base/random.h"
#include "ui/boxes/confirm_box.h"
#include "boxes/abstract_box.h"
#include "boxes/premium_limits_box.h"
#include "boxes/peers/add_participants_box.h"
#include "boxes/peers/edit_peer_common.h"
#include "boxes/peers/edit_participant_box.h"
#include "core/application.h"
#include "core/core_settings.h"
#include "chat_helpers/emoji_suggestions_widget.h"
#include "countries/countries_instance.h" // Countries::ExtractPhoneCode.
#include "history/history_item_reply_markup.h"
#include "window/window_session_controller.h"
#include "menu/menu_ttl.h"
#include "ui/controls/userpic_button.h"
#include "ui/widgets/checkbox.h"
#include "ui/toast/toast.h"
#include "ui/widgets/fields/input_field.h"
#include "ui/widgets/fields/special_fields.h"
#include "ui/widgets/popup_menu.h"
#include "ui/text/format_values.h"
#include "ui/text/text_utilities.h"
#include "ui/painter.h"
#include "data/data_channel.h"
#include "data/data_chat.h"
#include "data/data_user.h"
#include "data/data_session.h"
#include "data/data_changes.h"
#include "apiwrap.h"
#include "api/api_invite_links.h"
#include "api/api_peer_photo.h"
#include "api/api_self_destruct.h"
#include "main/main_session.h"
#include "styles/style_info.h"
#include "styles/style_layers.h"
#include "styles/style_menu_icons.h"

#include "styles/style_settings.h"

#include <QtGui/QGuiApplication>
#include <QtGui/QClipboard>

QString current_key = "default";

ManageKeysBox::ManageKeysBox(QWidget *) : _key(this, st::defaultInputField, Ui::InputField::Mode::MultiLine, rpl::single(QString("Public key")), current_key) {
}

void ManageKeysBox::prepare() {
    setTitle(rpl::single(QString("Edit key")));
    updateButtons();

    // const auto submitted = [=] { submit(); };
    // _first->submits(
    // ) | rpl::on_next(submitted, _first->lifetime());
    // _last->submits(
    // ) | rpl::on_next(submitted, _last->lifetime());
    // connect(_phone, &Ui::PhoneInput::submitted, [=] { submit(); });
    _key->setMaxHeight(650);
    _key->setMinHeight(650);
    setDimensions(700, 700);
}

void ManageKeysBox::setInnerFocus() {
    _key->setFocusFast();
    // if ((_first->getLastText().isEmpty() && _last->getLastText().isEmpty())
    // 	|| !_phone->isEnabled()) {
    // 	(_invertOrder ? _last : _first)->setFocusFast();
    // 	_phone->finishAnimating();
    // } else {
    // 	_phone->setFocusFast();
    // }
}

void ManageKeysBox::paintEvent(QPaintEvent *e) {
    BoxContent::paintEvent(e);

    auto p = QPainter(this);

    st::settingsIconPasskeysAboutIcon1.paint(p, st::boxPadding.left() + st::contactIconPosition.x(),
                                             _key->y() + st::contactIconPosition.y(), width());
}

void ManageKeysBox::resizeEvent(QResizeEvent *e) {
    BoxContent::resizeEvent(e);

    _key->resize(width() - st::boxPadding.left() - st::contactPadding.left() - st::boxPadding.right(), _key->height());
    const auto left = st::boxPadding.left() + st::contactPadding.left();
    _key->moveToLeft(left, st::contactPadding.top());
}

void ManageKeysBox::submit() {
    if (_key->hasFocus()) {
        save();
    } else {
        _key->setFocus();
    }
}

void ManageKeysBox::save() {

    auto key = _key->getLastText();
    if (/*key if invalid*/ false) {
        _key->setFocus();
        _key->showError();
        return;
    }
    if (key.isEmpty()) {
        /// something
    }
    current_key = key;
    closeBox();
}

void ManageKeysBox::updateButtons() {
    clearButtons();
    addButton(rpl::single(QString("Save key")), [=] { save(); });
    addButton(rpl::single(QString("Cancel")), [=] { closeBox(); });
}
