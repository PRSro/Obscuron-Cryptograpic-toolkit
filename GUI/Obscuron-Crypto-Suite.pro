QT += widgets

CONFIG += c++17

INCLUDEPATH += ../CLI/includes

# NTL / GMP integration
NTL_INCLUDE = /usr/include
INCLUDEPATH += $$NTL_INCLUDE
LIBS += -lntl -lm

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    menuwindow.cpp \
    numberwindow.cpp \
    recipe_engine.cpp \
    visualizer_widgets.cpp \
    theme_manager.cpp \
    advanced_number_dialog.cpp \
    advanced_crypt_dialog.cpp \
    rsa_attack_dialog.cpp \
    tls_attack_dialog.cpp \
    settings_dialog.cpp \
    ../CLI/src/modern_ciphers.cpp \
    ../CLI/src/ntl_bridge.cpp \
    ../CLI/src/basic_ciphers.cpp \
    ../CLI/src/historical_ciphers.cpp \
    ../CLI/src/essential_ciphers.cpp \
    ../CLI/src/bruteforce_ciphers.cpp \
    ../CLI/src/bytes.cpp \
    ../CLI/src/standard_ciphers.cpp \
    ../CLI/src/outdated_ciphers.cpp \
    ../CLI/src/detector.cpp \
    ../CLI/src/bigint.cpp

HEADERS += \
    colours.h \
    includes.h \
    mainwindow.h \
    menuwindow.h \
    numberwindow.h \
    recipe_engine.h \
    visualizer_widgets.h \
    theme_manager.h \
    advanced_number_dialog.h \
    advanced_crypt_dialog.h \
    rsa_attack_dialog.h \
    tls_attack_dialog.h \
    settings_dialog.h \
    ../CLI/includes/modern_ciphers.h \
    ../CLI/includes/basic.h \
    ../CLI/includes/basic_ciphers.h \
    ../CLI/includes/historical_ciphers.h \
    ../CLI/includes/essential_ciphers.h \
    ../CLI/includes/bruteforce_ciphers.h \
    ../CLI/includes/bytes.h \
    ../CLI/includes/standard_ciphers.h \
    ../CLI/includes/outdated_ciphers.h \
    ../CLI/includes/detector.h \
    ../CLI/includes/ntl_bridge.h \
    ../CLI/includes/bigint.hpp

FORMS +=

qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

