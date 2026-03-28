#pragma once

#include <functional>
#include <optional>
#include "ui/layers/box_content.h"

#include "../storage/auth_key.h"

namespace Ui {
class InputField;
}  // namespace Ui

namespace DoubleEncryption {

class ManageKeyBox : public Ui::BoxContent {
public:
    ManageKeyBox(QWidget*, const AuthKeyInfo& key_info, const AuthKey& key,
                 std::shared_ptr<rpl::event_stream<>> changes_stream,
                 std::function<bool(const QString&)> insert_operation,
                 std::function<void(const QString&)> delete_operation);
    ManageKeyBox(QWidget*, std::shared_ptr<rpl::event_stream<>> changes_stream,
                 std::function<bool(const QString&)> insert_operation,
                 std::function<void(const QString&)> delete_operation);

protected:
    void prepare() override;

    void paintEvent(QPaintEvent* e) override;
    void resizeEvent(QResizeEvent* e) override;

    void setInnerFocus() override;

private:
    void submit();
    void save();
    void del();
    void updateButtons();

private:
    std::optional<AuthKeyInfo> key_info_;
    object_ptr<Ui::InputField> key_field_;
    std::shared_ptr<rpl::event_stream<>> changes_stream_;
    std::function<bool(const QString&)> insert_operation_;
    std::function<void(const QString&)> delete_operation_;
};

}  // namespace DoubleEncryption
