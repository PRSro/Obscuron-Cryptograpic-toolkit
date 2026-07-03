#ifndef RECIPE_COMMANDS_H
#define RECIPE_COMMANDS_H

#include <QUndoCommand>
#include "recipe_engine.h"

class RecipeModel;

class AddStepCommand : public QUndoCommand {
public:
    AddStepCommand(RecipeModel *model, const RecipeStep &step, int row = -1, QUndoCommand *parent = nullptr);
    void undo() override;
    void redo() override;
private:
    RecipeModel *m_model;
    RecipeStep m_step;
    int m_row;
};

class RemoveStepCommand : public QUndoCommand {
public:
    RemoveStepCommand(RecipeModel *model, int row, QUndoCommand *parent = nullptr);
    void undo() override;
    void redo() override;
private:
    RecipeModel *m_model;
    RecipeStep m_step;
    int m_row;
};

class MoveStepCommand : public QUndoCommand {
public:
    MoveStepCommand(RecipeModel *model, int from, int to, QUndoCommand *parent = nullptr);
    void undo() override;
    void redo() override;
    int id() const override { return 1002; }
    bool mergeWith(const QUndoCommand *other) override;
private:
    RecipeModel *m_model;
    int m_from, m_to;
};

class ModifyStepCommand : public QUndoCommand {
public:
    ModifyStepCommand(RecipeModel *model, int row, const RecipeStep &oldState, const RecipeStep &newState, QUndoCommand *parent = nullptr);
    void undo() override;
    void redo() override;
    int id() const override { return 1001; }
    bool mergeWith(const QUndoCommand *other) override;
private:
    RecipeModel *m_model;
    int m_row;
    RecipeStep m_oldState;
    RecipeStep m_newState;
};

class ToggleStepCommand : public QUndoCommand {
public:
    ToggleStepCommand(RecipeModel *model, int row, QUndoCommand *parent = nullptr);
    void undo() override;
    void redo() override;
    int id() const override { return 1003; }
    bool mergeWith(const QUndoCommand *other) override;
private:
    RecipeModel *m_model;
    int m_row;
};

#endif
