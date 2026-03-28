#pragma once

#include <string>
#include "ui/layers/generic_box.h"
#include "ui/widgets/buttons.h"

#include "manage_key_box.h"

namespace Window {
class SessionController;
}  // namespace Window

namespace DoubleEncryption {

object_ptr<Ui::BoxContent> PrepareManageKeysList(not_null<Window::SessionController*> controller, bool pub);
object_ptr<Ui::BoxContent> PrepareSelectionKeysList(std::function<std::vector<AuthKeyInfo>()> fetcher,
                                                    std::function<bool(AuthKeyInfo)> button_callback);
object_ptr<Ui::BoxContent> PreparePublicKeysSelectionList(not_null<Window::SessionController*> controller, std::function<bool(const AuthKeyInfo&)> selection_action);

}  // namespace DoubleEncryption
