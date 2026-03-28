#include "manage_key_box.h"


#include "ui/widgets/fields/input_field.h"

#include "styles/style_info.h"
#include "styles/style_layers.h"
#include "styles/style_menu_icons.h"
#include "styles/style_settings.h"

#include <QtGui/QGuiApplication>
#include <QtGui/QClipboard>

namespace DoubleEncryption {

ManageKeyBox::ManageKeyBox(QWidget *, const AuthKeyInfo &key_info, const AuthKey &key,
                           std::shared_ptr<rpl::event_stream<>> changes_stream,
                           std::function<bool(const QString &)> insert_operation,
                           std::function<void(const QString &)> delete_operation)
    : key_info_(key_info),
      key_field_(this, st::defaultInputField, Ui::InputField::Mode::MultiLine, rpl::single(QString("Key")), key),
      changes_stream_(std::move(changes_stream)),
      insert_operation_(std::move(insert_operation)),
      delete_operation_(std::move(delete_operation)) {
}

ManageKeyBox::ManageKeyBox(QWidget *, std::shared_ptr<rpl::event_stream<>> changes_stream,
                           std::function<bool(const QString &)> insert_operation,
                           std::function<void(const QString &)> delete_operation)
    : key_field_(this, st::defaultInputField, Ui::InputField::Mode::MultiLine, rpl::single(QString("Key")), ""),
      changes_stream_(std::move(changes_stream)),
      insert_operation_(std::move(insert_operation)),
      delete_operation_(std::move(delete_operation)) {
}

void ManageKeyBox::prepare() {
    setTitle(rpl::single(key_info_ ? key_info_->name : QString("New key")));
    updateButtons();

    boxClosing() | rpl::on_next([=] {
        QString blank(key_field_->getLastText().size(), '\0');
        key_field_->setText(blank);
    }, lifetime());

    key_field_->setMaxHeight(650);
    key_field_->setMinHeight(650);
    setDimensions(700, 700);
}

void ManageKeyBox::setInnerFocus() {
    key_field_->setFocusFast();
}

void ManageKeyBox::paintEvent(QPaintEvent *e) {
    BoxContent::paintEvent(e);

    auto p = QPainter(this);

    st::settingsIconPasskeysAboutIcon1.paint(p, st::boxPadding.left() + st::contactIconPosition.x(),
                                             key_field_->y() + st::contactIconPosition.y(), width());
}

void ManageKeyBox::resizeEvent(QResizeEvent *e) {
    BoxContent::resizeEvent(e);

    const auto width_available = width() - st::boxPadding.left() - st::contactPadding.left() - st::boxPadding.right();

    key_field_->resize(width_available, 650);
    const auto left = st::boxPadding.left() + st::contactPadding.left();
    key_field_->moveToLeft(left, st::contactSkip);
}

void ManageKeyBox::save() {
    if (key_field_->getLastText().isEmpty() || !insert_operation_(key_field_->getLastText())) {
        key_field_->setFocus();
        key_field_->showError();
        return;
    }
    changes_stream_->fire({});
    closeBox();
}

void ManageKeyBox::del() {
    assert(key_info_);
    delete_operation_(key_info_->fingerprint);
    changes_stream_->fire({});
    closeBox();
}

void ManageKeyBox::updateButtons() {
    clearButtons();
    if (key_info_) {
        addButton(rpl::single(QString("Delete key")), [=] { del(); });
        addButton(rpl::single(QString("Cancel")), [=] { closeBox(); });
    } else {
        addButton(rpl::single(QString("Save key")), [=] { save(); });
        addButton(rpl::single(QString("Cancel")), [=] { closeBox(); });
    }
}

}  // namespace DoubleEncryption
