#include "info_box.h"

#include "QtCore/QString"
#include "styles/style_layers.h" 

namespace DoubleEncryption {

InfoBox::InfoBox(
    QWidget*,
    const QString &title,
    const QString &text)
: title_(title)
, text_(text)
, label_(this, text_, st::boxLabel) {
}

void InfoBox::prepare() {
    setTitle(rpl::single(title_));

    const auto contentWidth = 560;
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

    addButton(rpl::single(QString("Ok")), [=] {
        closeBox();
    });
}

void InfoBox::resizeEvent(QResizeEvent *e) {
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
