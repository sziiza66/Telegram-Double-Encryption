#pragma once

#include "ui/layers/box_content.h"
#include "ui/widgets/labels.h"

namespace DoubleEncryption {

class InfoBox : public Ui::BoxContent {
public:
    InfoBox(
        QWidget*,
        const QString &title,
        const QString &text);

protected:
    void prepare() override;
    void resizeEvent(QResizeEvent *e) override;

private:
    QString title_;
    QString text_;
    object_ptr<Ui::FlatLabel> label_;
};

}  // namespace DoubleEncryption
