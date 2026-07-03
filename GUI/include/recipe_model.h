#ifndef RECIPE_MODEL_H
#define RECIPE_MODEL_H

#include <QAbstractListModel>
#include <QStyledItemDelegate>
#include "recipe_engine.h"

class RecipeModel : public QAbstractListModel {
    Q_OBJECT
public:
    enum Role {
        NameRole = Qt::UserRole + 1,
        EnabledRole,
        HasErrorRole,
        ErrorMessageRole,
        ExecTimeRole,
        OutputRole
    };

    RecipeModel(QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    bool setData(const QModelIndex &index, const QVariant &value, int role) override;
    Qt::ItemFlags flags(const QModelIndex &index) const override;
    Qt::DropActions supportedDropActions() const override;
    QStringList mimeTypes() const override;
    QMimeData *mimeData(const QModelIndexList &indexes) const override;
    bool dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column, const QModelIndex &parent) override;

    // Mutation (emits proper signals)
    void addStep(const std::string &name, const StepParams &params = {});
    void insertStep(int row, const RecipeStep &step);
    void removeStep(int row);
    void moveStep(int from, int to);
    void clear();
    void setStepEnabled(int row, bool enabled);
    void setStepParam(int row, const StepParams &params);
    void setStepResult(int row, const std::string &output, bool hasError, const std::string &errorMsg, double timeMs);

    // Access
    RecipeStep stepAt(int row) const;
    int stepCount() const { return (int)m_steps.size(); }
    const std::vector<RecipeStep>& steps() const { return m_steps; }
    void setSteps(const std::vector<RecipeStep> &steps);

    // Serialization
    std::string exportToJSON() const;
    bool importFromJSON(const std::string &json, std::string &error_msg);

signals:
    void stepModified(int row);

private:
    std::vector<RecipeStep> m_steps;
};

class RecipeDelegate : public QStyledItemDelegate {
    Q_OBJECT
public:
    enum HitArea { None, UpBtn, DownBtn, ToggleBtn, DeleteBtn };

    RecipeDelegate(QObject *parent = nullptr);

    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;
    QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override;
    bool editorEvent(QEvent *event, QAbstractItemModel *model, const QStyleOptionViewItem &option, const QModelIndex &index) override;

    static HitArea hitTest(const QRect &itemRect, const QPoint &pos);
    static constexpr int BTN_W = 22;
    static constexpr int ITEM_H = 36;

signals:
    void deleteClicked(int row);
    void toggleEnabledClicked(int row);
    void moveUpClicked(int row);
    void moveDownClicked(int row);
};

#endif
