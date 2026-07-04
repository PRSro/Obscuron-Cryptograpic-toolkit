#include "recipe_model.h"
#include <QMimeData>
#include <QPainter>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QEvent>
#include <QMouseEvent>

// ── RecipeModel ─────────────────────────────────────────────────────────

RecipeModel::RecipeModel(QObject *parent) : QAbstractListModel(parent) {}

int RecipeModel::rowCount(const QModelIndex &parent) const {
    if (parent.isValid()) return 0;
    return (int)m_steps.size();
}

QVariant RecipeModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= (int)m_steps.size())
        return {};
    const auto &s = m_steps[index.row()];
    switch (role) {
    case Qt::DisplayRole:
    case NameRole:       return QString::fromStdString(s.operation_name);
    case EnabledRole:    return s.enabled;
    case HasErrorRole:   return s.has_error;
    case ErrorMessageRole: return QString::fromStdString(s.error_message);
    case ExecTimeRole:   return s.execution_time_ms;
    case OutputRole:     return QString::fromStdString(s.intermediate_output);
    }
    return {};
}

bool RecipeModel::setData(const QModelIndex &index, const QVariant &value, int role) {
    if (!index.isValid() || index.row() < 0 || index.row() >= (int)m_steps.size())
        return false;
    if (role == EnabledRole) {
        m_steps[index.row()].enabled = value.toBool();
        emit dataChanged(index, index, {EnabledRole});
        return true;
    }
    return false;
}

Qt::ItemFlags RecipeModel::flags(const QModelIndex &index) const {
    if (!index.isValid()) return Qt::ItemIsDropEnabled;
    return Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemIsDragEnabled | Qt::ItemIsDropEnabled;
}

Qt::DropActions RecipeModel::supportedDropActions() const {
    return Qt::MoveAction;
}

QStringList RecipeModel::mimeTypes() const {
    return {"application/x-obscuron-recipe-step"};
}

QMimeData *RecipeModel::mimeData(const QModelIndexList &indexes) const {
    if (indexes.isEmpty()) return nullptr;
    int row = indexes.first().row();
    QMimeData *data = new QMimeData();
    QByteArray ba;
    ba.append((const char*)&row, sizeof(int));
    data->setData("application/x-obscuron-recipe-step", ba);
    return data;
}

bool RecipeModel::dropMimeData(const QMimeData *data, Qt::DropAction action, int row, int column, const QModelIndex &parent) {
    Q_UNUSED(column);
    Q_UNUSED(parent);
    if (action != Qt::MoveAction) return false;
    if (!data->hasFormat("application/x-obscuron-recipe-step")) return false;
    int fromRow;
    QByteArray ba = data->data("application/x-obscuron-recipe-step");
    if (ba.size() != sizeof(int)) return false;
    memcpy(&fromRow, ba.constData(), sizeof(int));
    if (row < 0) row = (int)m_steps.size();
    if (fromRow == row || fromRow == row - 1) return false;
    moveStep(fromRow, row > fromRow ? row - 1 : row);
    return true;
}

void RecipeModel::addStep(const std::string &name, const StepParams &params) {
    beginInsertRows({}, (int)m_steps.size(), (int)m_steps.size());
    RecipeStep s;
    s.operation_name = name;
    s.enabled = true;
    s.params = params;
    m_steps.push_back(s);
    endInsertRows();
}

void RecipeModel::insertStep(int row, const RecipeStep &step) {
    if (row < 0 || row > (int)m_steps.size()) row = (int)m_steps.size();
    beginInsertRows({}, row, row);
    m_steps.insert(m_steps.begin() + row, step);
    endInsertRows();
}

void RecipeModel::removeStep(int row) {
    if (row < 0 || row >= (int)m_steps.size()) return;
    beginRemoveRows({}, row, row);
    m_steps.erase(m_steps.begin() + row);
    endRemoveRows();
}

void RecipeModel::moveStep(int from, int to) {
    if (from < 0 || from >= (int)m_steps.size()) return;
    if (to < 0 || to >= (int)m_steps.size()) return;
    if (from == to) return;
    if (!beginMoveRows({}, from, from, {}, to > from ? to + 1 : to))
        return;
    RecipeStep s = m_steps[from];
    m_steps.erase(m_steps.begin() + from);
    m_steps.insert(m_steps.begin() + (to > from ? to - 1 : to), s);
    endMoveRows();
}

void RecipeModel::clear() {
    if (m_steps.empty()) return;
    beginResetModel();
    m_steps.clear();
    endResetModel();
}

void RecipeModel::setStepEnabled(int row, bool enabled) {
    if (row < 0 || row >= (int)m_steps.size()) return;
    m_steps[row].enabled = enabled;
    QModelIndex idx = index(row);
    emit dataChanged(idx, idx, {EnabledRole});
}

void RecipeModel::setStepParam(int row, const StepParams &params) {
    if (row < 0 || row >= (int)m_steps.size()) return;
    m_steps[row].params = params;
    QModelIndex idx = index(row);
    emit dataChanged(idx, idx);
    emit stepModified(row);
}

void RecipeModel::setStepResult(int row, const std::string &output, bool hasError, const std::string &errorMsg, double timeMs) {
    if (row < 0 || row >= (int)m_steps.size()) return;
    auto &s = m_steps[row];
    s.intermediate_output = output;
    s.has_error = hasError;
    s.error_message = errorMsg;
    s.execution_time_ms = timeMs;
    QModelIndex idx = index(row);
    emit dataChanged(idx, idx, {HasErrorRole, ErrorMessageRole, ExecTimeRole, OutputRole});
}

RecipeStep RecipeModel::stepAt(int row) const {
    if (row < 0 || row >= (int)m_steps.size()) return {};
    return m_steps[row];
}

void RecipeModel::setSteps(const std::vector<RecipeStep> &steps) {
    beginResetModel();
    m_steps = steps;
    endResetModel();
}

std::string RecipeModel::exportToJSON() const {
    QJsonArray array;
    for (const auto &step : m_steps) {
        QJsonObject obj;
        obj["name"] = QString::fromStdString(step.operation_name);
        obj["enabled"] = step.enabled;
        QJsonObject params;
        params["key"] = QString::fromStdString(step.params.key);
        params["iv"] = QString::fromStdString(step.params.iv);
        params["param1"] = step.params.param1;
        params["param2"] = step.params.param2;
        params["param3"] = step.params.param3;
        params["param4"] = step.params.param4;
        params["encrypt"] = step.params.encrypt;
        QJsonObject custom;
        for (const auto &pair : step.params.custom_params)
            custom[QString::fromStdString(pair.first)] = QString::fromStdString(pair.second);
        if (!custom.isEmpty()) params["custom"] = custom;
        obj["params"] = params;
        array.append(obj);
    }
    QJsonDocument doc(array);
    return doc.toJson(QJsonDocument::Compact).toStdString();
}

bool RecipeModel::importFromJSON(const std::string &json_str, std::string &error_msg) {
    QJsonParseError parse_err;
    QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(json_str), &parse_err);
    if (doc.isNull()) {
        error_msg = "JSON Parse Error: " + parse_err.errorString().toStdString();
        return false;
    }
    if (!doc.isArray()) {
        error_msg = "Root element is not a JSON array";
        return false;
    }
    std::vector<RecipeStep> steps;
    QJsonArray array = doc.array();
    for (int i = 0; i < array.size(); ++i) {
        QJsonObject obj = array[i].toObject();
        RecipeStep step;
        step.operation_name = obj["name"].toString().toStdString();
        step.enabled = obj["enabled"].toBool(true);
        QJsonObject params = obj["params"].toObject();
        step.params.key = params["key"].toString().toStdString();
        step.params.iv = params["iv"].toString().toStdString();
        step.params.param1 = params["param1"].toInt(0);
        step.params.param2 = params["param2"].toInt(0);
        step.params.param3 = params["param3"].toInt(0);
        step.params.param4 = params["param4"].toInt(0);
        step.params.encrypt = params["encrypt"].toBool(true);
        QJsonObject custom = params["custom"].toObject();
        for (auto it = custom.begin(); it != custom.end(); ++it)
            step.params.custom_params[it.key().toStdString()] = it.value().toString().toStdString();
        steps.push_back(step);
    }
    setSteps(steps);
    return true;
}

// ── RecipeDelegate ──────────────────────────────────────────────────────

RecipeDelegate::RecipeDelegate(QObject *parent) : QStyledItemDelegate(parent) {}

QSize RecipeDelegate::sizeHint(const QStyleOptionViewItem &, const QModelIndex &) const {
    return QSize(100, ITEM_H);
}

RecipeDelegate::HitArea RecipeDelegate::hitTest(const QRect &itemRect, const QPoint &pos) {
    int right = itemRect.right() - 8;
    int y = itemRect.top() + (itemRect.height() - BTN_W) / 2;

    // Delete (22px) — matches paint: right -= 22; drawBtn(right, 22, ...)
    right -= 22;
    QRect del(right - 22, y, 22, BTN_W);
    if (del.contains(pos)) return DeleteBtn;
    right -= 28;

    // Toggle (24px)
    right -= 24;
    QRect tog(right - 24, y, 24, BTN_W);
    if (tog.contains(pos)) return ToggleBtn;
    right -= 30;

    // Down (22px)
    right -= 22;
    QRect dn(right - 22, y, 22, BTN_W);
    if (dn.contains(pos)) return DownBtn;
    right -= 28;

    // Up (22px)
    right -= 22;
    QRect up(right - 22, y, 22, BTN_W);
    if (up.contains(pos)) return UpBtn;

    return None;
}

bool RecipeDelegate::editorEvent(QEvent *event, QAbstractItemModel *model, const QStyleOptionViewItem &option, const QModelIndex &index) {
    if (event->type() != QEvent::MouseButtonRelease)
        return false;
    QMouseEvent *me = static_cast<QMouseEvent*>(event);
    if (me->button() != Qt::LeftButton)
        return false;

    HitArea area = hitTest(option.rect, me->pos());
    int row = index.row();

    switch (area) {
    case DeleteBtn:
        emit deleteClicked(row);
        return true;
    case ToggleBtn: {
        bool wasEnabled = model->data(index, RecipeModel::EnabledRole).toBool();
        model->setData(index, !wasEnabled, RecipeModel::EnabledRole);
        emit toggleEnabledClicked(row);
        return true;
    }
    case UpBtn:
        emit moveUpClicked(row);
        return true;
    case DownBtn:
        emit moveDownClicked(row);
        return true;
    default:
        return false;
    }
}

void RecipeDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const {
    painter->save();

    // Background
    QRect r = option.rect;
    bool selected = option.state & QStyle::State_Selected;
    bool hovered = option.state & QStyle::State_MouseOver;

    QColor bg = selected ? QColor("#1a1030") : (hovered ? QColor("#1a1030") : QColor("#120a20"));
    QColor border = selected ? QColor("#4a7cff") : QColor("#1e1850");
    painter->setRenderHint(QPainter::Antialiasing, true);
    painter->setPen(QPen(border, 1));
    painter->setBrush(bg);
    painter->drawRoundedRect(r.adjusted(1, 2, -1, -2), 4, 4);

    // Data
    QString name = index.data(RecipeModel::NameRole).toString();
    bool enabled = index.data(RecipeModel::EnabledRole).toBool();
    bool hasError = index.data(RecipeModel::HasErrorRole).toBool();

    int left = r.left() + 8;
    int cy = r.top() + r.height() / 2;

    // Status dot
    QColor dotColor;
    if (!enabled)
        dotColor = QColor("#3a3060");
    else if (hasError)
        dotColor = QColor("#ff6b6b");
    else
        dotColor = QColor("#00cc88");
    painter->setPen(Qt::NoPen);
    painter->setBrush(dotColor);
    painter->drawEllipse(QPoint(left + 7, cy), 5, 5);
    left += 18;

    // Name
    QFont nameFont("Courier New", 11, QFont::Bold);
    painter->setFont(nameFont);
    QColor textColor = enabled ? QColor("#e0e0f0") : QColor("#3a3060");
    if (selected) textColor = QColor("#ffffff");
    painter->setPen(textColor);

    // Buttons occupy the right 116px + padding
    int btnAreaWidth = 116;
    int nameMaxW = r.right() - 8 - left - 6 - btnAreaWidth;
    QString elidedName = painter->fontMetrics().elidedText(name, Qt::ElideRight, nameMaxW);
    painter->drawText(left, r.top() + 10, nameMaxW, r.height(), Qt::AlignVCenter | Qt::AlignLeft, elidedName);

    // Buttons
    int right = r.right() - 8;
    QFont btnFont("Courier New", 9, QFont::Bold);
    painter->setFont(btnFont);

    auto drawBtn = [&](int &rx, int w, const QString &text, const QColor &fg) {
        QRect br(rx - w, r.top() + (r.height() - BTN_W) / 2, w, 22);
        painter->setPen(fg);
        painter->drawText(br, Qt::AlignCenter, text);
        rx -= (w + 6);
    };

    right -= 22; // delete btn
    drawBtn(right, 22, "✕", QColor("#ff6b6b"));
    right -= 24; // toggle btn
    drawBtn(right, 24, enabled ? "👁" : "❌", enabled ? QColor("#e0e0f0") : QColor("#3a3060"));
    right -= 22; // down btn
    drawBtn(right, 22, "▼", QColor("#8880a0"));
    right -= 22; // up btn
    drawBtn(right, 22, "▲", QColor("#8880a0"));

    painter->restore();
}
