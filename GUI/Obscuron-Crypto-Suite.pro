QT += widgets qml

CONFIG += c++17

INCLUDEPATH += ../CLI/includes

# NTL / GMP integration
NTL_INCLUDE = /usr/include
INCLUDEPATH += $$NTL_INCLUDE
LIBS += -lntl -lm -ldl

SOURCES += \
    main.cpp \
    mainwindow.cpp \
    menuwindow.cpp \
    basewindow.cpp \
    numberwindow.cpp \
    passivewindow.cpp \
    recipe_engine.cpp \
    recipe_model.cpp \
    recipe_commands.cpp \
    visualizer_widgets.cpp \
    theme_manager.cpp \
    advanced_number_dialog.cpp \
    advanced_crypt_dialog.cpp \
    rsa_attack_dialog.cpp \
    tls_attack_dialog.cpp \
    settings_dialog.cpp \
    toast_widget.cpp \
    command_palette.cpp \
    plugin_loader.cpp \
    plugin_browser_dialog.cpp \
    script_engine.cpp \
    script_console_dialog.cpp \
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
    ../CLI/src/bigint.cpp \
    ../CLI/src/quadgram.cpp \
    ../CLI/src/branch_explorer.cpp \
    ../CLI/src/pcap_reader.cpp \
    ../CLI/src/register_tls.cpp

HEADERS += \
    colours.h \
    includes.h \
    mainwindow.h \
    menuwindow.h \
    basewindow.h \
    numberwindow.h \
    passivewindow.h \
    recipe_engine.h \
    recipe_model.h \
    recipe_commands.h \
    visualizer_widgets.h \
    theme_manager.h \
    advanced_number_dialog.h \
    advanced_crypt_dialog.h \
    rsa_attack_dialog.h \
    tls_attack_dialog.h \
    settings_dialog.h \
    toast_widget.h \
    command_palette.h \
    plugin_loader.h \
    plugin_browser_dialog.h \
    script_engine.h \
    script_console_dialog.h \
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
    ../CLI/includes/bigint.hpp \
    ../CLI/includes/quadgram.h \
    ../CLI/includes/branch_explorer.h \
    ../CLI/includes/pcap_reader.h \
    ../CLI/includes/detector_helpers.h \
    ../CLI/includes/plugin_api.h

FORMS +=

qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

