#include "widget.h"
#include "ui_widget.h"
#include <QMessageBox>


Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    ui->pb_coffee->setEnabled(false);
    ui->pb_tea->setEnabled(false);
    ui->pb_milk->setEnabled(false);
}

Widget::~Widget()
{
    delete ui;
}


void Widget::changeMoney(int diff)
{
    money+= diff;
    ui ->lcdNumber -> display(money);

    if(money>=100 and money<150){
        ui->pb_coffee->setEnabled(true);
        ui->pb_tea->setEnabled(false);
        ui->pb_milk->setEnabled(false);
    }
    else if(money>=150 and money<200){
        ui->pb_coffee->setEnabled(true);
        ui->pb_tea->setEnabled(true);
        ui->pb_milk->setEnabled(false);
    }
    else if (money>=200){
        ui->pb_coffee->setEnabled(true);
        ui->pb_tea->setEnabled(true);
        ui->pb_milk->setEnabled(true);
    }
    else{
        ui->pb_coffee->setEnabled(false);
        ui->pb_tea->setEnabled(false);
        ui->pb_milk->setEnabled(false);
    }

}

void Widget::change(int ch){
    cnt500 = ch/500;
    ch -= 500*cnt500;
    cnt100 = ch/100;
    ch -= 100*cnt100;
    cnt50 = ch/50;
    ch -= 50*cnt50;
    cnt10 = ch/10;
    ch -= 10*cnt10;

    QMessageBox mb;
    QString m = QString("500 : %1\n 100 : %2\n 50 : %3\n 10 : %4").arg(cnt500).arg(cnt100).arg(cnt50).arg(cnt10);
       mb.information(nullptr, "change", m);
}

void Widget::on_pb_10_clicked()
{
    changeMoney(10);
}


void Widget::on_pb_50_clicked()
{
    changeMoney(50);
}


void Widget::on_pb_100_clicked()
{
    changeMoney(100);
}


void Widget::on_pb_500_clicked()
{
    changeMoney(500);
}


void Widget::on_pb_coffee_clicked()
{
    changeMoney(-100);
}


void Widget::on_pb_tea_clicked()
{
    changeMoney(-150);
}


void Widget::on_pb_milk_clicked()
{
    changeMoney(-200);
}


void Widget::on_pb_reset_clicked()
{
    change(money);
}

