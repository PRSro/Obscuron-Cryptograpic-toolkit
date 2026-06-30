#ifndef RECIPE_ENGINE_H
#define RECIPE_ENGINE_H

#include <string>
#include <vector>
#include <map>
#include <QObject>
#include <QDateTime>
#include <QThread>

struct StepParams {
    std::string key;
    std::string iv;
    int param1 = 0;
    int param2 = 0;
    bool encrypt = true;
    std::map<std::string, std::string> custom_params;
};

struct RecipeStep {
    std::string operation_name;
    bool enabled = true;
    StepParams params;
    std::string intermediate_output;
    bool has_error = false;
    std::string error_message;
    double execution_time_ms = 0.0;
};

struct RecipeMetrics {
    double total_time_ms = 0.0;
    double throughput_mbs = 0.0;
    size_t memory_used_bytes = 0;
    QDateTime timestamp;
};

class PluginLoader;
class RecipeModel;

class RecipeEngine : public QObject {
    Q_OBJECT
public:
    RecipeEngine(QObject *parent = nullptr);
    ~RecipeEngine();

    void setPluginLoader(PluginLoader *loader) { m_pluginLoader = loader; }

    // Synchronous execution — takes steps, writes results back, returns output
    std::string run(const std::string &input, std::vector<RecipeStep> &steps, int debug_until_step = -1);

    // Async execution
    void setThreadingEnabled(bool enabled) { m_threadingEnabled = enabled; }
    bool isThreadingEnabled() const { return m_threadingEnabled; }
    void runAsync(const std::string &input, const std::vector<RecipeStep> &steps);
    void cancelAsync();
    bool isRunningAsync() const { return m_workerThread && m_workerThread->isRunning(); }

    // Copy async execution results into a model
    void syncResultsToModel(RecipeModel *model) const;

    // Macro Scripting Parser — adds steps to model
    bool parseMacroScript(const std::string &script, RecipeModel *model, std::string &error_msg);

    const RecipeMetrics& getLatestMetrics() const { return m_metrics; }
    const std::vector<RecipeStep>& asyncSteps() const { return m_asyncSteps; }

signals:
    void executionFinished(const std::string &final_output, const RecipeMetrics &metrics);
    void stepExecuted(int step_index, bool success, double time_ms);
    void executionProgress(int currentStep, int totalSteps);

private:
    std::string executeSingleStep(const std::string &input, const RecipeStep &step, bool &success, std::string &error_msg);

    RecipeMetrics m_metrics;
    PluginLoader *m_pluginLoader = nullptr;
    bool m_threadingEnabled = false;
    QThread *m_workerThread = nullptr;
    std::vector<RecipeStep> m_asyncSteps;
};

#endif // RECIPE_ENGINE_H
