#include "recipe_commands.h"
#include "recipe_model.h"

// ── AddStepCommand ──────────────────────────────────────────────────────

AddStepCommand::AddStepCommand(RecipeModel *model, const RecipeStep &step, int row, QUndoCommand *parent)
    : QUndoCommand(parent), m_model(model), m_step(step), m_row(row) {
    setText(QString("Add %1").arg(QString::fromStdString(step.operation_name)));
}

void AddStepCommand::undo() {
    if (m_row < 0) m_row = m_model->stepCount() - 1;
    m_model->removeStep(m_row);
}

void AddStepCommand::redo() {
    if (m_row < 0 || m_row > m_model->stepCount())
        m_row = m_model->stepCount();
    m_model->insertStep(m_row, m_step);
}

// ── RemoveStepCommand ───────────────────────────────────────────────────

RemoveStepCommand::RemoveStepCommand(RecipeModel *model, int row, QUndoCommand *parent)
    : QUndoCommand(parent), m_model(model), m_row(row) {
    m_step = model->stepAt(row);
    setText(QString("Remove %1").arg(QString::fromStdString(m_step.operation_name)));
}

void RemoveStepCommand::undo() {
    m_model->insertStep(m_row, m_step);
}

void RemoveStepCommand::redo() {
    m_step = m_model->stepAt(m_row);
    m_model->removeStep(m_row);
}

// ── MoveStepCommand ─────────────────────────────────────────────────────

MoveStepCommand::MoveStepCommand(RecipeModel *model, int from, int to, QUndoCommand *parent)
    : QUndoCommand(parent), m_model(model), m_from(from), m_to(to) {
    setText("Move step");
}

void MoveStepCommand::undo() {
    m_model->moveStep(m_to, m_from);
}

void MoveStepCommand::redo() {
    m_model->moveStep(m_from, m_to);
}

bool MoveStepCommand::mergeWith(const QUndoCommand *other) {
    const MoveStepCommand *cmd = dynamic_cast<const MoveStepCommand*>(other);
    if (!cmd) return false;
    m_to = cmd->m_to;
    return true;
}

// ── ModifyStepCommand ───────────────────────────────────────────────────

ModifyStepCommand::ModifyStepCommand(RecipeModel *model, int row, const RecipeStep &oldState, const RecipeStep &newState, QUndoCommand *parent)
    : QUndoCommand(parent), m_model(model), m_row(row), m_oldState(oldState), m_newState(newState) {
    setText(QString("Modify %1").arg(QString::fromStdString(oldState.operation_name)));
}

void ModifyStepCommand::undo() {
    m_model->setStepParam(m_row, m_oldState.params);
}

void ModifyStepCommand::redo() {
    m_model->setStepParam(m_row, m_newState.params);
}

bool ModifyStepCommand::mergeWith(const QUndoCommand *other) {
    const ModifyStepCommand *cmd = dynamic_cast<const ModifyStepCommand*>(other);
    if (!cmd || cmd->m_row != m_row) return false;
    m_newState = cmd->m_newState;
    return true;
}

// ── ToggleStepCommand ───────────────────────────────────────────────────

ToggleStepCommand::ToggleStepCommand(RecipeModel *model, int row, QUndoCommand *parent)
    : QUndoCommand(parent), m_model(model), m_row(row) {
    setText("Toggle step");
}

void ToggleStepCommand::undo() {
    m_model->setStepEnabled(m_row, !m_model->stepAt(m_row).enabled);
}

void ToggleStepCommand::redo() {
    m_model->setStepEnabled(m_row, !m_model->stepAt(m_row).enabled);
}

bool ToggleStepCommand::mergeWith(const QUndoCommand *other) {
    Q_UNUSED(other);
    return false;
}
