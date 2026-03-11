#pragma once

#include "ui/layers/box_content.h"

class PeerListBox;
struct RequestPeerQuery;

namespace Window {
class SessionNavigation;
}  // namespace Window

namespace Main {
class Session;
}  // namespace Main

namespace Ui {
class FlatLabel;
class InputField;
class PhoneInput;
class UsernameInput;
class Checkbox;
template <typename Enum>
class RadioenumGroup;
template <typename Enum>
class Radioenum;
class LinkButton;
class UserpicButton;
class Show;
}  // namespace Ui

enum class PeerFloodType {
    Send,
    InviteGroup,
    InviteChannel,
};

struct ForbiddenInvites;

class ManageKeysBox : public Ui::BoxContent {
public:
    ManageKeysBox(QWidget *);

protected:
    void prepare() override;

    void paintEvent(QPaintEvent *e) override;
    void resizeEvent(QResizeEvent *e) override;

    void setInnerFocus() override;

private:
    void submit();
    void save();
    void updateButtons();

    object_ptr<Ui::InputField> _key;
};
