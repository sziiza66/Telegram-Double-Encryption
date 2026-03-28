#include "wait_box.h"

#include "QtCore/QString"
#include "styles/style_layers.h" 


namespace DoubleEncryption {

WaitBox::WaitBox(
    QWidget*,
    const QString &text,
    std::function<void()> callback,
    std::shared_ptr<rpl::event_stream<PeerId>> changes_stream,
    PeerId peer_id)
: text_(text)
, callback_(std::move(callback))
, label_(this, text_, st::boxLabel)
, changes_stream_(std::move(changes_stream))
, peer_id_(peer_id) {
}

void WaitBox::prepare() {
    setTitle(rpl::single(QString("Please wait")));

    changes_stream_->events() | rpl::on_next([=](PeerId id) {
        if (id == peer_id_) {
            closeBox();
        }
    }, lifetime());

    boxClosing() | rpl::on_next([=] {
        if (callback_) {
            callback_();
        }
    }, lifetime());

    const auto contentWidth = 360;
    const auto textWidth =
        contentWidth
        - st::boxPadding.left()
        - st::boxPadding.right();

    label_->resizeToWidth(textWidth);

    const auto height =
        st::boxPadding.top()
        + label_->height()
        + st::boxPadding.bottom()
        + 40;

    setDimensions(contentWidth, height);

    addButton(rpl::single(QString("Cancel")), [=] {
        closeBox();
    });
}

void WaitBox::resizeEvent(QResizeEvent *e) {
    BoxContent::resizeEvent(e);

    const auto textWidth =
        width()
        - st::boxPadding.left()
        - st::boxPadding.right();

    label_->resizeToWidth(textWidth);
    label_->moveToLeft(
        st::boxPadding.left(),
        st::boxPadding.top());
}

}  // namespace DoubleEncryption
