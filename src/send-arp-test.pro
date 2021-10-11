TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap

SOURCES += \
	arphdr.cpp \
	ethhdr.cpp \
	ip.cpp \
	mac.cpp \
	main.cpp

HEADERS += \
	arphdr.h \
	ethhdr.h \
	ip.h \
	mac.h
