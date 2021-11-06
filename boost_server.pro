TEMPLATE = app
CONFIG += console c++14
CONFIG -= app_bundle
CONFIG -= qt

QMAKE_CXXFLAGS += -pthread
LIBS += -pthread
LIBS += -lssl -lcrypto

SOURCES += \
        main.cpp

HEADERS += \
    cpp_signals.h \
    server_certificate.h
