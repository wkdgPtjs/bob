#ifndef WIDGET_H
#define WIDGET_H

#include <QWidget>

QT_BEGIN_NAMESPACE
namespace Ui { class Widget; }
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = nullptr);
    ~Widget();
    int money ={0};
    int cnt500 = {0};
    int cnt100 = {0};
    int cnt50 = {0};
    int cnt10 = {0};
    void changeMoney(int diff);
    void change(int ch);

private slots:

    void on_pb_10_clicked();

    void on_pb_50_clicked();

    void on_pb_100_clicked();

    void on_pb_500_clicked();

    void on_pb_coffee_clicked();

    void on_pb_tea_clicked();

    void on_pb_milk_clicked();

    void on_pb_reset_clicked();

private:
    Ui::Widget *ui;
};
#endif // WIDGET_H
