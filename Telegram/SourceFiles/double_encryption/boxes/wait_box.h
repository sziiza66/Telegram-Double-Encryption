#pragma once

#include <functional>
#include "ui/layers/box_content.h"
#include "ui/widgets/labels.h"

namespace DoubleEncryption {

class WaitBox : public Ui::BoxContent {
public:
    WaitBox(
        QWidget*,
        const QString &text,
        std::function<void()> callback,
        std::shared_ptr<rpl::event_stream<PeerId>> changes_stream,
        PeerId peer_id);

protected:
    void prepare() override;
    void resizeEvent(QResizeEvent *e) override;

private:
    QString text_;
    std::function<void()> callback_;
    object_ptr<Ui::FlatLabel> label_;
    std::shared_ptr<rpl::event_stream<PeerId>> changes_stream_;
    PeerId peer_id_;
};
}  // namespace DoubleEncryption
