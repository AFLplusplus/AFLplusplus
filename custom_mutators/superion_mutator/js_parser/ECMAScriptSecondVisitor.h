
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
class  ECMAScriptSecondVisitor : public ECMAScriptVisitor {
public:
  vector<string> texts;

  virtual antlrcpp::Any visitProgram(ECMAScriptParser::ProgramContext *ctx) override {
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSourceElements(ECMAScriptParser::SourceElementsContext *ctx) override {
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSourceElement(ECMAScriptParser::SourceElementContext *ctx) override {
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitStatement(ECMAScriptParser::StatementContext *ctx) override {
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBlock(ECMAScriptParser::BlockContext *ctx) override {
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitStatementList(ECMAScriptParser::StatementListContext *ctx) override {
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVariableStatement(ECMAScriptParser::VariableStatementContext *ctx) override {
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVariableDeclarationList(ECMAScriptParser::VariableDeclarationListContext *ctx) override {
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVariableDeclaration(ECMAScriptParser::VariableDeclarationContext *ctx) override {
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitInitialiser(ECMAScriptParser::InitialiserContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitEmptyStatement(ECMAScriptParser::EmptyStatementContext *ctx) override {
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitExpressionStatement(ECMAScriptParser::ExpressionStatementContext *ctx) override {
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitIfStatement(ECMAScriptParser::IfStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDoStatement(ECMAScriptParser::DoStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitWhileStatement(ECMAScriptParser::WhileStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForStatement(ECMAScriptParser::ForStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForVarStatement(ECMAScriptParser::ForVarStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForLetStatement(ECMAScriptParser::ForLetStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForInStatement(ECMAScriptParser::ForInStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForVarInStatement(ECMAScriptParser::ForVarInStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForLetInStatement(ECMAScriptParser::ForLetInStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitContinueStatement(ECMAScriptParser::ContinueStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBreakStatement(ECMAScriptParser::BreakStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitReturnStatement(ECMAScriptParser::ReturnStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitWithStatement(ECMAScriptParser::WithStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSwitchStatement(ECMAScriptParser::SwitchStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCaseBlock(ECMAScriptParser::CaseBlockContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCaseClauses(ECMAScriptParser::CaseClausesContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCaseClause(ECMAScriptParser::CaseClauseContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDefaultClause(ECMAScriptParser::DefaultClauseContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLabelledStatement(ECMAScriptParser::LabelledStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitThrowStatement(ECMAScriptParser::ThrowStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTryStatement(ECMAScriptParser::TryStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCatchProduction(ECMAScriptParser::CatchProductionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFinallyProduction(ECMAScriptParser::FinallyProductionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDebuggerStatement(ECMAScriptParser::DebuggerStatementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFunctionDeclaration(ECMAScriptParser::FunctionDeclarationContext *ctx) override {
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFormalParameterList(ECMAScriptParser::FormalParameterListContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFunctionBody(ECMAScriptParser::FunctionBodyContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArrayLiteral(ECMAScriptParser::ArrayLiteralContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitElementList(ECMAScriptParser::ElementListContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitElision(ECMAScriptParser::ElisionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitObjectLiteral(ECMAScriptParser::ObjectLiteralContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertyNameAndValueList(ECMAScriptParser::PropertyNameAndValueListContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertyExpressionAssignment(ECMAScriptParser::PropertyExpressionAssignmentContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertyGetter(ECMAScriptParser::PropertyGetterContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertySetter(ECMAScriptParser::PropertySetterContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertyName(ECMAScriptParser::PropertyNameContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertySetParameterList(ECMAScriptParser::PropertySetParameterListContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArguments(ECMAScriptParser::ArgumentsContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArgumentList(ECMAScriptParser::ArgumentListContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitExpressionSequence(ECMAScriptParser::ExpressionSequenceContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTernaryExpression(ECMAScriptParser::TernaryExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLogicalAndExpression(ECMAScriptParser::LogicalAndExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPreIncrementExpression(ECMAScriptParser::PreIncrementExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitObjectLiteralExpression(ECMAScriptParser::ObjectLiteralExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitInExpression(ECMAScriptParser::InExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLogicalOrExpression(ECMAScriptParser::LogicalOrExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitNotExpression(ECMAScriptParser::NotExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPreDecreaseExpression(ECMAScriptParser::PreDecreaseExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArgumentsExpression(ECMAScriptParser::ArgumentsExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitThisExpression(ECMAScriptParser::ThisExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFunctionExpression(ECMAScriptParser::FunctionExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitUnaryMinusExpression(ECMAScriptParser::UnaryMinusExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAssignmentExpression(ECMAScriptParser::AssignmentExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPostDecreaseExpression(ECMAScriptParser::PostDecreaseExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTypeofExpression(ECMAScriptParser::TypeofExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitInstanceofExpression(ECMAScriptParser::InstanceofExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitUnaryPlusExpression(ECMAScriptParser::UnaryPlusExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDeleteExpression(ECMAScriptParser::DeleteExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitEqualityExpression(ECMAScriptParser::EqualityExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBitXOrExpression(ECMAScriptParser::BitXOrExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMultiplicativeExpression(ECMAScriptParser::MultiplicativeExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBitShiftExpression(ECMAScriptParser::BitShiftExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitParenthesizedExpression(ECMAScriptParser::ParenthesizedExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAdditiveExpression(ECMAScriptParser::AdditiveExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitRelationalExpression(ECMAScriptParser::RelationalExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPostIncrementExpression(ECMAScriptParser::PostIncrementExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBitNotExpression(ECMAScriptParser::BitNotExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitNewExpression(ECMAScriptParser::NewExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLiteralExpression(ECMAScriptParser::LiteralExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArrayLiteralExpression(ECMAScriptParser::ArrayLiteralExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMemberDotExpression(ECMAScriptParser::MemberDotExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMemberIndexExpression(ECMAScriptParser::MemberIndexExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitIdentifierExpression(ECMAScriptParser::IdentifierExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBitAndExpression(ECMAScriptParser::BitAndExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBitOrExpression(ECMAScriptParser::BitOrExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAssignmentOperatorExpression(ECMAScriptParser::AssignmentOperatorExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVoidExpression(ECMAScriptParser::VoidExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAssignmentOperator(ECMAScriptParser::AssignmentOperatorContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLiteral(ECMAScriptParser::LiteralContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitNumericLiteral(ECMAScriptParser::NumericLiteralContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitIdentifierName(ECMAScriptParser::IdentifierNameContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitReservedWord(ECMAScriptParser::ReservedWordContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitKeyword(ECMAScriptParser::KeywordContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFutureReservedWord(ECMAScriptParser::FutureReservedWordContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitGetter(ECMAScriptParser::GetterContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSetter(ECMAScriptParser::SetterContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitEos(ECMAScriptParser::EosContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitEof(ECMAScriptParser::EofContext *ctx) override {
    //texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }


};

