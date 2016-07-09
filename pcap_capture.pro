#-------------------------------------------------
#
# Project created by QtCreator 2016-07-07T14:21:32
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = pcap_capture
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp

HEADERS  += mainwindow.h

FORMS    += mainwindow.ui
LIBS += -L/usr/include/pcap
LIBS += -lpcap
INCLUDEPATH += /usr/include/pcap
DEPENDPATH += /usr/include/pcap
