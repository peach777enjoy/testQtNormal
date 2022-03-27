#-------------------------------------------------
#
# Project created by QtCreator 2017-06-18T13:36:28
#
#-------------------------------------------------

QT       += core gui sql

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += debug_and_release
CONFIG(debug, debug|release){
    TARGET = ../../_debug/CRM
} else {
    TARGET = ../../_release/CRM
}
TEMPLATE = app

DEFINES += QT_DEPRECATED_WARNINGS

SOURCES += main.cpp\
        mainwindow.cpp \
    dlgitem.cpp

HEADERS  += mainwindow.h \
    dlgitem.h

FORMS    += mainwindow.ui \
    dlgitem.ui

RC_FILE += app.rc

RESOURCES += \
    rc.qrc
