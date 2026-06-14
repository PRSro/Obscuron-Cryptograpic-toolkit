#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPlainTextEdit>
#include <QComboBox>
#include <QLineEdit>
#include <QSpinBox>
#include <QPushButton>
#include <QLabel>
#include <QListWidget>
#include <QTreeWidget>
#include <QTabWidget>
#include <QSplitter>
#include <QCheckBox>
#include <QStackedWidget>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QProgressBar>
#include <QVBoxLayout>
#include <QHBoxLayout>


#include "recipe_engine.h"
#include "visualizer_widgets.h"
#include "theme_manager.h"

// DropEdit for handling file drops
class DropEdit : public QPlainTextEdit {
    Q_OBJECT
public:
    DropEdit(QWidget *parent = nullptr);
signals:
    void fileDropped(const QString &filePath, const QByteArray &content);
protected:
    void dragEnterEvent(QDragEnterEvent *e) override;
    void dropEvent(QDropEvent *e) override;
};

// Custom widget for items in the Recipe Canvas list
class RecipeCardWidget : public QWidget {
    Q_OBJECT
public:
    RecipeCardWidget(const QString &name, int index, QWidget *parent = nullptr);
    void setStatus(bool success, const QString &err_msg = "");
    void setEnabledState(bool enabled);

signals:
    void deleteClicked(int index);
    void toggleEnabledClicked(int index, bool enabled);
    void moveUpClicked(int index);
    void moveDownClicked(int index);

private:
    QLabel *m_nameLabel;
    QLabel *m_statusLabel;
    QPushButton *m_toggleBtn;
    QPushButton *m_deleteBtn;
    QPushButton *m_upBtn;
    QPushButton *m_downBtn;
    int m_index;
    bool m_isEnabled;
};

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow() = default;

private slots:
    void onRunRecipe();
    void onAddOperation(QTreeWidgetItem *item, int column);
    void onRecipeItemSelectionChanged();
    void onRecipeCardDelete(int index);
    void onRecipeCardToggleEnabled(int index, bool enabled);
    void onRecipeCardMoveUp(int index);
    void onRecipeCardMoveDown(int index);
    void onParameterChanged();
    
    // Bottom panel UI updates
    void onInputTextChanged();
    void onFileLoaded(const QString &filePath, const QByteArray &content);
    void onClearFile();
    void onCopyOutput();
    void onExportOutput(const QString &ext);
    void onWheelBaseSelected(int radix);

    // Menu and settings actions
    void onThemeChanged(int index);
    void onOpenSettings();
    void onUndo();
    void onRedo();
    
    void onDetectCipher();
    
    // Macro and recipe templates
    void onApplyMacro();
    void onSaveRecipe();
    void onLoadRecipe();
    void onTemplateSelected(int index);

    // CTF mode
    void onRunCtfSearch();
    void onCtfFlagCheck();
    void onRunTlsAttack();

private:
    void setupUI();
    void updateRecipeCanvas();
    void updateSettingsPanel(int stepIndex);
    void displayOutputFormat(const std::string &output);
    void runCtfDictionaryBrute(const std::string &input, const std::string &flagFormat);
    void pushUndo();

    // UI Widgets
    QTreeWidget *m_opLibrary;
    QLineEdit *m_librarySearch;
    QListWidget *m_recipeList;
    QWidget *m_settingsContainer;
    QVBoxLayout *m_settingsLayout;
    
    DropEdit *m_inputEdit;
    QFrame *m_fileUploadFrame;
    QLabel *m_fileNameLabel;
    QProgressBar *m_fileProgress;
    
    QTabWidget *m_outputTabs;
    QPlainTextEdit *m_outputText;
    QPlainTextEdit *m_outputByteBreakdown;
    QPlainTextEdit *m_outputDiff;
    
    // Plots / charts
    FrequencyHistogram *m_histogram;
    EntropyHeatmap *m_heatmap;
    ShannonEntropyGraph *m_entropyGraph;
    EncodingWheel *m_encodingWheel;

    // Top Bar controls
    QLabel *m_metricsLabel;
    QCheckBox *m_autoRunCheck;
    QPushButton *m_undoBtn;
    QPushButton *m_redoBtn;
    QComboBox *m_themeCombo;

    // CTF sidebar panel
    QLineEdit *m_ctfFlagRegex;
    QPlainTextEdit *m_ctfWordlist;
    QListWidget *m_ctfResults;
    QLabel *m_ctfMatchCount;

    // Backend engine
    RecipeEngine m_engine;
    std::string m_rawInput;
    
    // History stacks for Undo/Redo
    std::vector<std::string> m_undoStack;
    std::vector<std::string> m_redoStack;
    bool m_isUndoingOrRedoing = false;
};

#endif // MAINWINDOW_H
