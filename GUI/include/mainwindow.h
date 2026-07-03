#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPlainTextEdit>
#include <QTextEdit>
#include <QComboBox>
#include <QLineEdit>
#include <QSpinBox>
#include <QPushButton>
#include <QLabel>
#include <QListView>
#include <QTreeWidget>
#include <QTabWidget>
#include <QSplitter>
#include <QCheckBox>
#include <QListWidget>
#include <QStackedWidget>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QProgressBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QUndoStack>

#include "recipe_engine.h"
#include "recipe_model.h"
#include "recipe_commands.h"
#include "visualizer_widgets.h"
#include "theme_manager.h"
#include "plugin_loader.h"

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
    void onRecipeCardToggleEnabled(int index);
    void onRecipeCardMoveUp(int index);
    void onRecipeCardMoveDown(int index);
    void onParameterChanged();

    void onInputTextChanged();
    void onInputDebounceTimeout();
    void onFileLoaded(const QString &filePath, const QByteArray &content);
    void onClearFile();
    void onCopyOutput();
    void onExportOutput(const QString &ext);
    void onWheelBaseSelected(int radix);

    void onOpenSettings();
    void onDetectCipher();

    void onApplyMacro();
    void onSaveRecipe();
    void onLoadRecipe();
    void onTemplateSelected(int index);

    void onOpenPluginBrowser();
    void onPluginLibraryChanged();

    void onRunCtfSearch();
    void onCtfFlagCheck();
    void onRunTlsAttack();

    void onAsyncExecutionFinished(const std::string &output, const RecipeMetrics &metrics);
    void onCancelAsync();

    void onSetMode(int mode);

private:
    void setupUI();
    void setupWorkspacePage(QWidget *page);
    void setupNetworkPage(QWidget *page);
    void setupStegoPage(QWidget *page);
    void updateRecipeCanvas();
    void updateSettingsPanel(int stepIndex);
    void displayOutputFormat(const std::string &output);
    void runCtfDictionaryBrute(const std::string &input, const std::string &flagFormat);
    void applyPipelineResults(const std::string &out);
    void setUIControlsEnabled(bool enabled);

    void runRecipeOnSteps();

    // UI Widgets
    QTreeWidget *m_opLibrary;
    QLineEdit *m_librarySearch;
    QListView *m_recipeView;
    RecipeDelegate *m_recipeDelegate;
    QWidget *m_settingsContainer;
    QVBoxLayout *m_settingsLayout;

    DropEdit *m_inputEdit;
    QFrame *m_fileUploadFrame;
    QLabel *m_fileNameLabel;
    QProgressBar *m_fileProgress;

    QTabWidget *m_outputTabs;
    QTextEdit *m_outputText;
    QPlainTextEdit *m_outputByteBreakdown;
    QPlainTextEdit *m_outputDiff;

    // Plots / charts
    FrequencyHistogram *m_histogram;
    EntropyHeatmap *m_heatmap;
    ShannonEntropyGraph *m_entropyGraph;
    EncodingWheel *m_encodingWheel;
    AutocorrelationGraph *m_autocorrGraph;
    NGramHeatmap *m_ngramHeatmap;
    HexDiffViewer *m_hexDiff;
    DataMiniMap *m_miniMap;
    BlockCipherModeViz *m_blockViz;

    QTimer *m_inputDebounce;

    // Top Bar controls
    QLabel *m_metricsLabel;
    QCheckBox *m_autoRunCheck;
    QPushButton *m_undoBtn;
    QPushButton *m_redoBtn;
    QPushButton *m_cancelBtn;
    // Mode switching
    QStackedWidget *m_modeStack;
    QPushButton *m_workspaceBtn;
    QPushButton *m_networkBtn;
    QPushButton *m_stegoBtn;
    int m_currentMode;
    QWidget *m_networkPage;
    QWidget *m_stegoPage;

    // Network Decrypter page widgets
    QPlainTextEdit *m_netPcapEdit;
    QPushButton *m_netLoadPcapBtn;
    QTextEdit *m_netOutput;

    // Steganography page widgets
    QPlainTextEdit *m_stegoInput;
    QPushButton *m_stegoLoadImgBtn;
    QTextEdit *m_stegoOutput;

    // CTF sidebar panel
    QLineEdit *m_ctfFlagRegex;
    QPlainTextEdit *m_ctfWordlist;
    QListWidget *m_ctfResults;
    QLabel *m_ctfMatchCount;

    // Backend engine, model, undo
    RecipeEngine m_engine;
    RecipeModel *m_recipeModel;
    QUndoStack *m_undoStack;
    PluginLoader m_pluginLoader;
    std::string m_rawInput;

    // Async execution tracking
    QMetaObject::Connection m_asyncFinishConn;

    // Theme state
    ThemePalette m_pal;
    QString m_cAccent, m_cText, m_cLabel, m_cSuccess, m_cDanger;
    QString m_bgAccent, m_bgSuccess, m_bgDanger;
};

#endif // MAINWINDOW_H
