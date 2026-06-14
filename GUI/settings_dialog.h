#ifndef SETTINGS_DIALOG_H
#define SETTINGS_DIALOG_H

#include <QDialog>
#include <QComboBox>
#include <QSpinBox>
#include <QPushButton>
#include <QLabel>
#include <QCheckBox>
#include <QTabWidget>
#include <QSlider>
#include <QColor>
#include <QFontComboBox>

class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit SettingsDialog(QWidget *parent = nullptr);

private:
    void setupUI();
    void loadSettings();
    void saveSettings();
    void apply();

    QTabWidget *m_tabs;

    // Theme tab
    QComboBox *m_themeCombo;
    QCheckBox *m_accentEnabled;
    QSlider *m_accentR, *m_accentG, *m_accentB;
    QLabel *m_accentPreview;
    QPushButton *m_applyThemeBtn;

    // Font tab
    QFontComboBox *m_fontFamily;
    QSpinBox *m_fontSize;
    QCheckBox *m_fontBold;

    // Display tab
    QCheckBox *m_showHexAddr;
    QCheckBox *m_autoRunDefault;
    QSpinBox *m_maxOutputLines;

private slots:
    void onApply();
    void onAccentSliderChanged();
    void onClose();
};

#endif
