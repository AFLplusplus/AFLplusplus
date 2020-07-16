
// Generated from C:\Users\xiang\Documents\GitHub\js_parser\ECMAScript.g4 by ANTLR 4.7

#pragma once

#include <iostream>
#include <vector>
#include "antlr4-runtime.h"
#include "ECMAScriptVisitor.h"

using namespace std;

/**
 * This class provides an empty implementation of ECMAScriptVisitor, which can be
 * extended to create a visitor which only needs to handle a subset of the available methods.
 */
class  ECMAScriptBaseVisitor : public ECMAScriptVisitor {
public:
  vector<misc::Interval> intervals;
  vector<string> texts;

  virtual antlrcpp::Any visitProgram(ECMAScriptParser::ProgramContext *ctx) override {
    //intervals.push_back(ctx->getSourceInterval());
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSourceElements(ECMAScriptParser::SourceElementsContext *ctx) override {
    //intervals.push_back(ctx->getSourceInterval());
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSourceElement(ECMAScriptParser::SourceElementContext *ctx) override {
    //intervals.push_back(ctx->getSourceInterval());
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitStatement(ECMAScriptParser::StatementContext *ctx) override {
    //intervals.push_back(ctx->getSourceInterval());
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBlock(ECMAScriptParser::BlockContext *ctx) override {
    //intervals.push_back(ctx->getSourceInterval());
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitStatementList(ECMAScriptParser::StatementListContext *ctx) override {
    //intervals.push_back(ctx->getSourceInterval());
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVariableStatement(ECMAScriptParser::VariableStatementContext *ctx) override {
    //intervals.push_back(ctx->getSourceInterval());
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVariableDeclarationList(ECMAScriptParser::VariableDeclarationListContext *ctx) override {
    //intervals.push_back(ctx->getSourceInterval());
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVariableDeclaration(ECMAScriptParser::VariableDeclarationContext *ctx) override {
    //intervals.push_back(ctx->getSourceInterval());
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitInitialiser(ECMAScriptParser::InitialiserContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitEmptyStatement(ECMAScriptParser::EmptyStatementContext *ctx) override {
    //intervals.push_back(ctx->getSourceInterval());
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitExpressionStatement(ECMAScriptParser::ExpressionStatementContext *ctx) override {
    //intervals.push_back(ctx->getSourceInterval());
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitIfStatement(ECMAScriptParser::IfStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDoStatement(ECMAScriptParser::DoStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitWhileStatement(ECMAScriptParser::WhileStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForStatement(ECMAScriptParser::ForStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForVarStatement(ECMAScriptParser::ForVarStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForLetStatement(ECMAScriptParser::ForLetStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForInStatement(ECMAScriptParser::ForInStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForVarInStatement(ECMAScriptParser::ForVarInStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForLetInStatement(ECMAScriptParser::ForLetInStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitContinueStatement(ECMAScriptParser::ContinueStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBreakStatement(ECMAScriptParser::BreakStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitReturnStatement(ECMAScriptParser::ReturnStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitWithStatement(ECMAScriptParser::WithStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSwitchStatement(ECMAScriptParser::SwitchStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCaseBlock(ECMAScriptParser::CaseBlockContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCaseClauses(ECMAScriptParser::CaseClausesContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCaseClause(ECMAScriptParser::CaseClauseContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDefaultClause(ECMAScriptParser::DefaultClauseContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLabelledStatement(ECMAScriptParser::LabelledStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitThrowStatement(ECMAScriptParser::ThrowStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTryStatement(ECMAScriptParser::TryStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCatchProduction(ECMAScriptParser::CatchProductionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFinallyProduction(ECMAScriptParser::FinallyProductionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDebuggerStatement(ECMAScriptParser::DebuggerStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFunctionDeclaration(ECMAScriptParser::FunctionDeclarationContext *ctx) override {
    //intervals.push_back(ctx->getSourceInterval());
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFormalParameterList(ECMAScriptParser::FormalParameterListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFunctionBody(ECMAScriptParser::FunctionBodyContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArrayLiteral(ECMAScriptParser::ArrayLiteralContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitElementList(ECMAScriptParser::ElementListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitElision(ECMAScriptParser::ElisionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitObjectLiteral(ECMAScriptParser::ObjectLiteralContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertyNameAndValueList(ECMAScriptParser::PropertyNameAndValueListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertyExpressionAssignment(ECMAScriptParser::PropertyExpressionAssignmentContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertyGetter(ECMAScriptParser::PropertyGetterContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertySetter(ECMAScriptParser::PropertySetterContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertyName(ECMAScriptParser::PropertyNameContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertySetParameterList(ECMAScriptParser::PropertySetParameterListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArguments(ECMAScriptParser::ArgumentsContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArgumentList(ECMAScriptParser::ArgumentListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitExpressionSequence(ECMAScriptParser::ExpressionSequenceContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTernaryExpression(ECMAScriptParser::TernaryExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLogicalAndExpression(ECMAScriptParser::LogicalAndExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPreIncrementExpression(ECMAScriptParser::PreIncrementExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitObjectLiteralExpression(ECMAScriptParser::ObjectLiteralExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitInExpression(ECMAScriptParser::InExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLogicalOrExpression(ECMAScriptParser::LogicalOrExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitNotExpression(ECMAScriptParser::NotExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPreDecreaseExpression(ECMAScriptParser::PreDecreaseExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArgumentsExpression(ECMAScriptParser::ArgumentsExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitThisExpression(ECMAScriptParser::ThisExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFunctionExpression(ECMAScriptParser::FunctionExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitUnaryMinusExpression(ECMAScriptParser::UnaryMinusExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAssignmentExpression(ECMAScriptParser::AssignmentExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPostDecreaseExpression(ECMAScriptParser::PostDecreaseExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTypeofExpression(ECMAScriptParser::TypeofExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitInstanceofExpression(ECMAScriptParser::InstanceofExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitUnaryPlusExpression(ECMAScriptParser::UnaryPlusExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDeleteExpression(ECMAScriptParser::DeleteExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitEqualityExpression(ECMAScriptParser::EqualityExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBitXOrExpression(ECMAScriptParser::BitXOrExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMultiplicativeExpression(ECMAScriptParser::MultiplicativeExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBitShiftExpression(ECMAScriptParser::BitShiftExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitParenthesizedExpression(ECMAScriptParser::ParenthesizedExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAdditiveExpression(ECMAScriptParser::AdditiveExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitRelationalExpression(ECMAScriptParser::RelationalExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPostIncrementExpression(ECMAScriptParser::PostIncrementExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBitNotExpression(ECMAScriptParser::BitNotExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitNewExpression(ECMAScriptParser::NewExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLiteralExpression(ECMAScriptParser::LiteralExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArrayLiteralExpression(ECMAScriptParser::ArrayLiteralExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMemberDotExpression(ECMAScriptParser::MemberDotExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMemberIndexExpression(ECMAScriptParser::MemberIndexExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitIdentifierExpression(ECMAScriptParser::IdentifierExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBitAndExpression(ECMAScriptParser::BitAndExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBitOrExpression(ECMAScriptParser::BitOrExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAssignmentOperatorExpression(ECMAScriptParser::AssignmentOperatorExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVoidExpression(ECMAScriptParser::VoidExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAssignmentOperator(ECMAScriptParser::AssignmentOperatorContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLiteral(ECMAScriptParser::LiteralContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitNumericLiteral(ECMAScriptParser::NumericLiteralContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitIdentifierName(ECMAScriptParser::IdentifierNameContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitReservedWord(ECMAScriptParser::ReservedWordContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitKeyword(ECMAScriptParser::KeywordContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFutureReservedWord(ECMAScriptParser::FutureReservedWordContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitGetter(ECMAScriptParser::GetterContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSetter(ECMAScriptParser::SetterContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitEos(ECMAScriptParser::EosContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitEof(ECMAScriptParser::EofContext *ctx) override {
    //intervals.push_back(ctx->getSourceInterval());
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }


};

