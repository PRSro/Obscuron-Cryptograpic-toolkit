QT += widgets qml

CONFIG += c++17

INCLUDEPATH += ../CLI/includes include

# NTL / GMP integration
NTL_INCLUDE = /usr/include
INCLUDEPATH += $$NTL_INCLUDE
INCLUDEPATH += /usr/include/python3.14
LIBS += -lntl -lm -ldl -lpython3.14

SOURCES += \
    src/main.cpp \
    src/mainwindow.cpp \
    src/menuwindow.cpp \
    src/basewindow.cpp \
    src/numberwindow.cpp \
    src/passivewindow.cpp \
    src/solve_window.cpp \
    src/sage_runner.cpp \
    src/terminal_widget.cpp \
    src/solve_ctf_panel.cpp \
    src/recipe_engine.cpp \
    src/recipe_model.cpp \
    src/recipe_commands.cpp \
    src/visualizer_widgets.cpp \
    src/theme_manager.cpp \
    src/advanced_number_dialog.cpp \
    src/advanced_crypt_dialog.cpp \
    src/rsa_attack_dialog.cpp \
    src/tls_attack_dialog.cpp \
    src/settings_dialog.cpp \
    src/toast_widget.cpp \
    src/command_palette.cpp \
    src/plugin_loader.cpp \
    src/plugin_browser_dialog.cpp \
    src/script_engine.cpp \
    src/script_console_dialog.cpp \
    src/plugin_crypto_bridge.cpp \
    src/py_plugin_host.cpp \
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
    ../CLI/src/register_tls.cpp \
    ../CLI/src/asn1.cpp

HEADERS += \
    include/colours.h \
    include/includes.h \
    include/mainwindow.h \
    include/menuwindow.h \
    include/basewindow.h \
    include/numberwindow.h \
    include/passivewindow.h \
    include/solve_window.h \
    include/sage_runner.h \
    include/terminal_widget.h \
    include/solve_ctf_panel.h \
    include/recipe_engine.h \
    include/recipe_model.h \
    include/recipe_commands.h \
    include/visualizer_widgets.h \
    include/theme_manager.h \
    include/advanced_number_dialog.h \
    include/advanced_crypt_dialog.h \
    include/rsa_attack_dialog.h \
    include/tls_attack_dialog.h \
    include/settings_dialog.h \
    include/toast_widget.h \
    include/command_palette.h \
    include/plugin_loader.h \
    include/plugin_browser_dialog.h \
    include/script_engine.h \
    include/script_console_dialog.h \
    include/plugin_crypto_bridge.h \
    include/py_plugin_host.h \
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
    ../CLI/includes/plugin_api.h \
    ../CLI/includes/asn1.h

FORMS +=

qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

