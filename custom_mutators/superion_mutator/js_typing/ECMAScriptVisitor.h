
// Generated from C:\Users\xiang\Documents\GitHub\js_parser\ECMAScript.g4 by ANTLR 4.7

#pragma once


#include "antlr4-runtime.h"
#include "ECMAScriptParser.h"



/**
 * This class defines an abstract visitor for a parse tree
 * produced by ECMAScriptParser.
 */
class  ECMAScriptVisitor : public antlr4::tree::AbstractParseTreeVisitor {
public:

  /**
   * Visit parse trees produced by ECMAScriptParser.
   */
    virtual antlrcpp::Any visitProgram(ECMAScriptParser::ProgramContext *context) = 0;

    virtual antlrcpp::Any visitSourceElements(ECMAScriptParser::SourceElementsContext *context) = 0;

    virtual antlrcpp::Any visitSourceElement(ECMAScriptParser::SourceElementContext *context) = 0;

    virtual antlrcpp::Any visitStatement(ECMAScriptParser::StatementContext *context) = 0;

    virtual antlrcpp::Any visitBlock(ECMAScriptParser::BlockContext *context) = 0;

    virtual antlrcpp::Any visitStatementList(ECMAScriptParser::StatementListContext *context) = 0;

    virtual antlrcpp::Any visitVariableStatement(ECMAScriptParser::VariableStatementContext *context) = 0;

    virtual antlrcpp::Any visitVariableDeclarationList(ECMAScriptParser::VariableDeclarationListContext *context) = 0;

    virtual antlrcpp::Any visitVariableDeclaration(ECMAScriptParser::VariableDeclarationContext *context) = 0;

    virtual antlrcpp::Any visitInitialiser(ECMAScriptParser::InitialiserContext *context) = 0;

    virtual antlrcpp::Any visitEmptyStatement(ECMAScriptParser::EmptyStatementContext *context) = 0;

    virtual antlrcpp::Any visitExpressionStatement(ECMAScriptParser::ExpressionStatementContext *context) = 0;

    virtual antlrcpp::Any visitIfStatement(ECMAScriptParser::IfStatementContext *context) = 0;

    virtual antlrcpp::Any visitDoStatement(ECMAScriptParser::DoStatementContext *context) = 0;

    virtual antlrcpp::Any visitWhileStatement(ECMAScriptParser::WhileStatementContext *context) = 0;

    virtual antlrcpp::Any visitForStatement(ECMAScriptParser::ForStatementContext *context) = 0;

    virtual antlrcpp::Any visitForVarStatement(ECMAScriptParser::ForVarStatementContext *context) = 0;

    virtual antlrcpp::Any visitForLetStatement(ECMAScriptParser::ForLetStatementContext *context) = 0;

    virtual antlrcpp::Any visitForInStatement(ECMAScriptParser::ForInStatementContext *context) = 0;

    virtual antlrcpp::Any visitForVarInStatement(ECMAScriptParser::ForVarInStatementContext *context) = 0;

    virtual antlrcpp::Any visitForLetInStatement(ECMAScriptParser::ForLetInStatementContext *context) = 0;

    virtual antlrcpp::Any visitContinueStatement(ECMAScriptParser::ContinueStatementContext *context) = 0;

    virtual antlrcpp::Any visitBreakStatement(ECMAScriptParser::BreakStatementContext *context) = 0;

    virtual antlrcpp::Any visitReturnStatement(ECMAScriptParser::ReturnStatementContext *context) = 0;

    virtual antlrcpp::Any visitWithStatement(ECMAScriptParser::WithStatementContext *context) = 0;

    virtual antlrcpp::Any visitSwitchStatement(ECMAScriptParser::SwitchStatementContext *context) = 0;

    virtual antlrcpp::Any visitCaseBlock(ECMAScriptParser::CaseBlockContext *context) = 0;

    virtual antlrcpp::Any visitCaseClauses(ECMAScriptParser::CaseClausesContext *context) = 0;

    virtual antlrcpp::Any visitCaseClause(ECMAScriptParser::CaseClauseContext *context) = 0;

    virtual antlrcpp::Any visitDefaultClause(ECMAScriptParser::DefaultClauseContext *context) = 0;

    virtual antlrcpp::Any visitLabelledStatement(ECMAScriptParser::LabelledStatementContext *context) = 0;

    virtual antlrcpp::Any visitThrowStatement(ECMAScriptParser::ThrowStatementContext *context) = 0;

    virtual antlrcpp::Any visitTryStatement(ECMAScriptParser::TryStatementContext *context) = 0;

    virtual antlrcpp::Any visitCatchProduction(ECMAScriptParser::CatchProductionContext *context) = 0;

    virtual antlrcpp::Any visitFinallyProduction(ECMAScriptParser::FinallyProductionContext *context) = 0;

    virtual antlrcpp::Any visitDebuggerStatement(ECMAScriptParser::DebuggerStatementContext *context) = 0;

    virtual antlrcpp::Any visitFunctionDeclaration(ECMAScriptParser::FunctionDeclarationContext *context) = 0;

    virtual antlrcpp::Any visitFormalParameterList(ECMAScriptParser::FormalParameterListContext *context) = 0;

    virtual antlrcpp::Any visitFunctionBody(ECMAScriptParser::FunctionBodyContext *context) = 0;

    virtual antlrcpp::Any visitArrayLiteral(ECMAScriptParser::ArrayLiteralContext *context) = 0;

    virtual antlrcpp::Any visitElementList(ECMAScriptParser::ElementListContext *context) = 0;

    virtual antlrcpp::Any visitElision(ECMAScriptParser::ElisionContext *context) = 0;

    virtual antlrcpp::Any visitObjectLiteral(ECMAScriptParser::ObjectLiteralContext *context) = 0;

    virtual antlrcpp::Any visitPropertyNameAndValueList(ECMAScriptParser::PropertyNameAndValueListContext *context) = 0;

    virtual antlrcpp::Any visitPropertyExpressionAssignment(ECMAScriptParser::PropertyExpressionAssignmentContext *context) = 0;

    virtual antlrcpp::Any visitPropertyGetter(ECMAScriptParser::PropertyGetterContext *context) = 0;

    virtual antlrcpp::Any visitPropertySetter(ECMAScriptParser::PropertySetterContext *context) = 0;

    virtual antlrcpp::Any visitPropertyName(ECMAScriptParser::PropertyNameContext *context) = 0;

    virtual antlrcpp::Any visitPropertySetParameterList(ECMAScriptParser::PropertySetParameterListContext *context) = 0;

    virtual antlrcpp::Any visitArguments(ECMAScriptParser::ArgumentsContext *context) = 0;

    virtual antlrcpp::Any visitArgumentList(ECMAScriptParser::ArgumentListContext *context) = 0;

    virtual antlrcpp::Any visitExpressionSequence(ECMAScriptParser::ExpressionSequenceContext *context) = 0;

    virtual antlrcpp::Any visitTernaryExpression(ECMAScriptParser::TernaryExpressionContext *context) = 0;

    virtual antlrcpp::Any visitLogicalAndExpression(ECMAScriptParser::LogicalAndExpressionContext *context) = 0;

    virtual antlrcpp::Any visitPreIncrementExpression(ECMAScriptParser::PreIncrementExpressionContext *context) = 0;

    virtual antlrcpp::Any visitObjectLiteralExpression(ECMAScriptParser::ObjectLiteralExpressionContext *context) = 0;

    virtual antlrcpp::Any visitInExpression(ECMAScriptParser::InExpressionContext *context) = 0;

    virtual antlrcpp::Any visitLogicalOrExpression(ECMAScriptParser::LogicalOrExpressionContext *context) = 0;

    virtual antlrcpp::Any visitNotExpression(ECMAScriptParser::NotExpressionContext *context) = 0;

    virtual antlrcpp::Any visitPreDecreaseExpression(ECMAScriptParser::PreDecreaseExpressionContext *context) = 0;

    virtual antlrcpp::Any visitArgumentsExpression(ECMAScriptParser::ArgumentsExpressionContext *context) = 0;

    virtual antlrcpp::Any visitThisExpression(ECMAScriptParser::ThisExpressionContext *context) = 0;

    virtual antlrcpp::Any visitFunctionExpression(ECMAScriptParser::FunctionExpressionContext *context) = 0;

    virtual antlrcpp::Any visitUnaryMinusExpression(ECMAScriptParser::UnaryMinusExpressionContext *context) = 0;

    virtual antlrcpp::Any visitAssignmentExpression(ECMAScriptParser::AssignmentExpressionContext *context) = 0;

    virtual antlrcpp::Any visitPostDecreaseExpression(ECMAScriptParser::PostDecreaseExpressionContext *context) = 0;

    virtual antlrcpp::Any visitTypeofExpression(ECMAScriptParser::TypeofExpressionContext *context) = 0;

    virtual antlrcpp::Any visitInstanceofExpression(ECMAScriptParser::InstanceofExpressionContext *context) = 0;

    virtual antlrcpp::Any visitUnaryPlusExpression(ECMAScriptParser::UnaryPlusExpressionContext *context) = 0;

    virtual antlrcpp::Any visitDeleteExpression(ECMAScriptParser::DeleteExpressionContext *context) = 0;

    virtual antlrcpp::Any visitEqualityExpression(ECMAScriptParser::EqualityExpressionContext *context) = 0;

    virtual antlrcpp::Any visitBitXOrExpression(ECMAScriptParser::BitXOrExpressionContext *context) = 0;

    virtual antlrcpp::Any visitMultiplicativeExpression(ECMAScriptParser::MultiplicativeExpressionContext *context) = 0;

    virtual antlrcpp::Any visitBitShiftExpression(ECMAScriptParser::BitShiftExpressionContext *context) = 0;

    virtual antlrcpp::Any visitParenthesizedExpression(ECMAScriptParser::ParenthesizedExpressionContext *context) = 0;

    virtual antlrcpp::Any visitAdditiveExpression(ECMAScriptParser::AdditiveExpressionContext *context) = 0;

    virtual antlrcpp::Any visitRelationalExpression(ECMAScriptParser::RelationalExpressionContext *context) = 0;

    virtual antlrcpp::Any visitPostIncrementExpression(ECMAScriptParser::PostIncrementExpressionContext *context) = 0;

    virtual antlrcpp::Any visitBitNotExpression(ECMAScriptParser::BitNotExpressionContext *context) = 0;

    virtual antlrcpp::Any visitNewExpression(ECMAScriptParser::NewExpressionContext *context) = 0;

    virtual antlrcpp::Any visitLiteralExpression(ECMAScriptParser::LiteralExpressionContext *context) = 0;

    virtual antlrcpp::Any visitArrayLiteralExpression(ECMAScriptParser::ArrayLiteralExpressionContext *context) = 0;

    virtual antlrcpp::Any visitMemberDotExpression(ECMAScriptParser::MemberDotExpressionContext *context) = 0;

    virtual antlrcpp::Any visitMemberIndexExpression(ECMAScriptParser::MemberIndexExpressionContext *context) = 0;

    virtual antlrcpp::Any visitIdentifierExpression(ECMAScriptParser::IdentifierExpressionContext *context) = 0;

    virtual antlrcpp::Any visitBitAndExpression(ECMAScriptParser::BitAndExpressionContext *context) = 0;

    virtual antlrcpp::Any visitBitOrExpression(ECMAScriptParser::BitOrExpressionContext *context) = 0;

    virtual antlrcpp::Any visitAssignmentOperatorExpression(ECMAScriptParser::AssignmentOperatorExpressionContext *context) = 0;

    virtual antlrcpp::Any visitVoidExpression(ECMAScriptParser::VoidExpressionContext *context) = 0;

    virtual antlrcpp::Any visitAssignmentOperator(ECMAScriptParser::AssignmentOperatorContext *context) = 0;

    virtual antlrcpp::Any visitLiteral(ECMAScriptParser::LiteralContext *context) = 0;

    virtual antlrcpp::Any visitNumericLiteral(ECMAScriptParser::NumericLiteralContext *context) = 0;

    virtual antlrcpp::Any visitIdentifierName(ECMAScriptParser::IdentifierNameContext *context) = 0;

    virtual antlrcpp::Any visitReservedWord(ECMAScriptParser::ReservedWordContext *context) = 0;

    virtual antlrcpp::Any visitKeyword(ECMAScriptParser::KeywordContext *context) = 0;

    virtual antlrcpp::Any visitFutureReservedWord(ECMAScriptParser::FutureReservedWordContext *context) = 0;

    virtual antlrcpp::Any visitGetter(ECMAScriptParser::GetterContext *context) = 0;

    virtual antlrcpp::Any visitSetter(ECMAScriptParser::SetterContext *context) = 0;

    virtual antlrcpp::Any visitEos(ECMAScriptParser::EosContext *context) = 0;

    virtual antlrcpp::Any visitEof(ECMAScriptParser::EofContext *context) = 0;


};

