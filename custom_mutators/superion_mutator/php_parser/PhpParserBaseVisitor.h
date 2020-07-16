
// Generated from C:\Users\xiang\Documents\GitHub\php_parser\PhpParser.g4 by ANTLR 4.7

#pragma once


#include "antlr4-runtime.h"
#include "PhpParserVisitor.h"
using namespace std;
using namespace antlr4;

/**
 * This class provides an empty implementation of PhpParserVisitor, which can be
 * extended to create a visitor which only needs to handle a subset of the available methods.
 */
class  PhpParserBaseVisitor : public PhpParserVisitor {
public:
  vector<misc::Interval> intervals;
  vector<string> texts;

  virtual antlrcpp::Any visitPhpBlock(PhpParser::PhpBlockContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitImportStatement(PhpParser::ImportStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTopStatement(PhpParser::TopStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitUseDeclaration(PhpParser::UseDeclarationContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitUseDeclarationContentList(PhpParser::UseDeclarationContentListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitUseDeclarationContent(PhpParser::UseDeclarationContentContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitNamespaceDeclaration(PhpParser::NamespaceDeclarationContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitNamespaceStatement(PhpParser::NamespaceStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFunctionDeclaration(PhpParser::FunctionDeclarationContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitClassDeclaration(PhpParser::ClassDeclarationContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitClassEntryType(PhpParser::ClassEntryTypeContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitInterfaceList(PhpParser::InterfaceListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTypeParameterListInBrackets(PhpParser::TypeParameterListInBracketsContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTypeParameterList(PhpParser::TypeParameterListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTypeParameterWithDefaultsList(PhpParser::TypeParameterWithDefaultsListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTypeParameterDecl(PhpParser::TypeParameterDeclContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTypeParameterWithDefaultDecl(PhpParser::TypeParameterWithDefaultDeclContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitGenericDynamicArgs(PhpParser::GenericDynamicArgsContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAttributes(PhpParser::AttributesContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAttributesGroup(PhpParser::AttributesGroupContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAttribute(PhpParser::AttributeContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAttributeArgList(PhpParser::AttributeArgListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAttributeNamedArgList(PhpParser::AttributeNamedArgListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAttributeNamedArg(PhpParser::AttributeNamedArgContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitInnerStatementList(PhpParser::InnerStatementListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitInnerStatement(PhpParser::InnerStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitStatement(PhpParser::StatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitEmptyStatement(PhpParser::EmptyStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBlockStatement(PhpParser::BlockStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitIfStatement(PhpParser::IfStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitElseIfStatement(PhpParser::ElseIfStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitElseIfColonStatement(PhpParser::ElseIfColonStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitElseStatement(PhpParser::ElseStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitElseColonStatement(PhpParser::ElseColonStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitWhileStatement(PhpParser::WhileStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDoWhileStatement(PhpParser::DoWhileStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForStatement(PhpParser::ForStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForInit(PhpParser::ForInitContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForUpdate(PhpParser::ForUpdateContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSwitchStatement(PhpParser::SwitchStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSwitchBlock(PhpParser::SwitchBlockContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBreakStatement(PhpParser::BreakStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitContinueStatement(PhpParser::ContinueStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitReturnStatement(PhpParser::ReturnStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitExpressionStatement(PhpParser::ExpressionStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitUnsetStatement(PhpParser::UnsetStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForeachStatement(PhpParser::ForeachStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTryCatchFinally(PhpParser::TryCatchFinallyContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCatchClause(PhpParser::CatchClauseContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFinallyStatement(PhpParser::FinallyStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitThrowStatement(PhpParser::ThrowStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitGotoStatement(PhpParser::GotoStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDeclareStatement(PhpParser::DeclareStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDeclareList(PhpParser::DeclareListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFormalParameterList(PhpParser::FormalParameterListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFormalParameter(PhpParser::FormalParameterContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTypeHint(PhpParser::TypeHintContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitGlobalStatement(PhpParser::GlobalStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitGlobalVar(PhpParser::GlobalVarContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitEchoStatement(PhpParser::EchoStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitStaticVariableStatement(PhpParser::StaticVariableStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitClassStatement(PhpParser::ClassStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTraitAdaptations(PhpParser::TraitAdaptationsContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTraitAdaptationStatement(PhpParser::TraitAdaptationStatementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTraitPrecedence(PhpParser::TraitPrecedenceContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTraitAlias(PhpParser::TraitAliasContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTraitMethodReference(PhpParser::TraitMethodReferenceContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBaseCtorCall(PhpParser::BaseCtorCallContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMethodBody(PhpParser::MethodBodyContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertyModifiers(PhpParser::PropertyModifiersContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMemberModifiers(PhpParser::MemberModifiersContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVariableInitializer(PhpParser::VariableInitializerContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitIdentifierInititalizer(PhpParser::IdentifierInititalizerContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitGlobalConstantDeclaration(PhpParser::GlobalConstantDeclarationContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitExpressionList(PhpParser::ExpressionListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitParenthesis(PhpParser::ParenthesisContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitChainExpression(PhpParser::ChainExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitUnaryOperatorExpression(PhpParser::UnaryOperatorExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSpecialWordExpression(PhpParser::SpecialWordExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArrayCreationExpression(PhpParser::ArrayCreationExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitNewExpression(PhpParser::NewExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitParenthesisExpression(PhpParser::ParenthesisExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBackQuoteStringExpression(PhpParser::BackQuoteStringExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitConditionalExpression(PhpParser::ConditionalExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArithmeticExpression(PhpParser::ArithmeticExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitIndexerExpression(PhpParser::IndexerExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitScalarExpression(PhpParser::ScalarExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPrefixIncDecExpression(PhpParser::PrefixIncDecExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitComparisonExpression(PhpParser::ComparisonExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLogicalExpression(PhpParser::LogicalExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPrintExpression(PhpParser::PrintExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAssignmentExpression(PhpParser::AssignmentExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPostfixIncDecExpression(PhpParser::PostfixIncDecExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCastExpression(PhpParser::CastExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitInstanceOfExpression(PhpParser::InstanceOfExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLambdaFunctionExpression(PhpParser::LambdaFunctionExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBitwiseExpression(PhpParser::BitwiseExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCloneExpression(PhpParser::CloneExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitNewExpr(PhpParser::NewExprContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAssignmentOperator(PhpParser::AssignmentOperatorContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitYieldExpression(PhpParser::YieldExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArrayItemList(PhpParser::ArrayItemListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArrayItem(PhpParser::ArrayItemContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLambdaFunctionUseVars(PhpParser::LambdaFunctionUseVarsContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLambdaFunctionUseVar(PhpParser::LambdaFunctionUseVarContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitQualifiedStaticTypeRef(PhpParser::QualifiedStaticTypeRefContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTypeRef(PhpParser::TypeRefContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitIndirectTypeRef(PhpParser::IndirectTypeRefContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitQualifiedNamespaceName(PhpParser::QualifiedNamespaceNameContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitNamespaceNameList(PhpParser::NamespaceNameListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitQualifiedNamespaceNameList(PhpParser::QualifiedNamespaceNameListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArguments(PhpParser::ArgumentsContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitActualArgument(PhpParser::ActualArgumentContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitConstantInititalizer(PhpParser::ConstantInititalizerContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitConstantArrayItemList(PhpParser::ConstantArrayItemListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitConstantArrayItem(PhpParser::ConstantArrayItemContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitConstant(PhpParser::ConstantContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLiteralConstant(PhpParser::LiteralConstantContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitNumericConstant(PhpParser::NumericConstantContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitClassConstant(PhpParser::ClassConstantContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitStringConstant(PhpParser::StringConstantContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitString(PhpParser::StringContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitInterpolatedStringPart(PhpParser::InterpolatedStringPartContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitChainList(PhpParser::ChainListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitChain(PhpParser::ChainContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMemberAccess(PhpParser::MemberAccessContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFunctionCall(PhpParser::FunctionCallContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFunctionCallName(PhpParser::FunctionCallNameContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitActualArguments(PhpParser::ActualArgumentsContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitChainBase(PhpParser::ChainBaseContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitKeyedFieldName(PhpParser::KeyedFieldNameContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitKeyedSimpleFieldName(PhpParser::KeyedSimpleFieldNameContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitKeyedVariable(PhpParser::KeyedVariableContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSquareCurlyExpression(PhpParser::SquareCurlyExpressionContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAssignmentList(PhpParser::AssignmentListContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAssignmentListElement(PhpParser::AssignmentListElementContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitModifier(PhpParser::ModifierContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitIdentifier(PhpParser::IdentifierContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMemberModifier(PhpParser::MemberModifierContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMagicConstant(PhpParser::MagicConstantContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMagicMethod(PhpParser::MagicMethodContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPrimitiveType(PhpParser::PrimitiveTypeContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCastOperation(PhpParser::CastOperationContext *ctx) override {
    intervals.push_back(ctx->getSourceInterval());
    texts.push_back(ctx->start->getInputStream()->getText(misc::Interval(ctx->start->getStartIndex(),ctx->stop->getStopIndex())));
    return visitChildren(ctx);
  }


};

