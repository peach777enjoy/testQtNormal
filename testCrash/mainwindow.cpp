#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_btnTest_clicked()
{

    int num=8;
//    int num=0;
//    int result =7;
//    result=70/num;
    int *p = 0;
    *p = 900;
}
