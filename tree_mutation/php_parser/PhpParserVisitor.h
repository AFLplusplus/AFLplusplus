
// Generated from C:\Users\xiang\Documents\GitHub\php_parser\PhpParser.g4 by ANTLR 4.7

#pragma once


#include "antlr4-runtime.h"
#include "PhpParser.h"



/**
 * This class defines an abstract visitor for a parse tree
 * produced by PhpParser.
 */
class  PhpParserVisitor : public antlr4::tree::AbstractParseTreeVisitor {
public:

  /**
   * Visit parse trees produced by PhpParser.
   */
    virtual antlrcpp::Any visitPhpBlock(PhpParser::PhpBlockContext *context) = 0;

    virtual antlrcpp::Any visitImportStatement(PhpParser::ImportStatementContext *context) = 0;

    virtual antlrcpp::Any visitTopStatement(PhpParser::TopStatementContext *context) = 0;

    virtual antlrcpp::Any visitUseDeclaration(PhpParser::UseDeclarationContext *context) = 0;

    virtual antlrcpp::Any visitUseDeclarationContentList(PhpParser::UseDeclarationContentListContext *context) = 0;

    virtual antlrcpp::Any visitUseDeclarationContent(PhpParser::UseDeclarationContentContext *context) = 0;

    virtual antlrcpp::Any visitNamespaceDeclaration(PhpParser::NamespaceDeclarationContext *context) = 0;

    virtual antlrcpp::Any visitNamespaceStatement(PhpParser::NamespaceStatementContext *context) = 0;

    virtual antlrcpp::Any visitFunctionDeclaration(PhpParser::FunctionDeclarationContext *context) = 0;

    virtual antlrcpp::Any visitClassDeclaration(PhpParser::ClassDeclarationContext *context) = 0;

    virtual antlrcpp::Any visitClassEntryType(PhpParser::ClassEntryTypeContext *context) = 0;

    virtual antlrcpp::Any visitInterfaceList(PhpParser::InterfaceListContext *context) = 0;

    virtual antlrcpp::Any visitTypeParameterListInBrackets(PhpParser::TypeParameterListInBracketsContext *context) = 0;

    virtual antlrcpp::Any visitTypeParameterList(PhpParser::TypeParameterListContext *context) = 0;

    virtual antlrcpp::Any visitTypeParameterWithDefaultsList(PhpParser::TypeParameterWithDefaultsListContext *context) = 0;

    virtual antlrcpp::Any visitTypeParameterDecl(PhpParser::TypeParameterDeclContext *context) = 0;

    virtual antlrcpp::Any visitTypeParameterWithDefaultDecl(PhpParser::TypeParameterWithDefaultDeclContext *context) = 0;

    virtual antlrcpp::Any visitGenericDynamicArgs(PhpParser::GenericDynamicArgsContext *context) = 0;

    virtual antlrcpp::Any visitAttributes(PhpParser::AttributesContext *context) = 0;

    virtual antlrcpp::Any visitAttributesGroup(PhpParser::AttributesGroupContext *context) = 0;

    virtual antlrcpp::Any visitAttribute(PhpParser::AttributeContext *context) = 0;

    virtual antlrcpp::Any visitAttributeArgList(PhpParser::AttributeArgListContext *context) = 0;

    virtual antlrcpp::Any visitAttributeNamedArgList(PhpParser::AttributeNamedArgListContext *context) = 0;

    virtual antlrcpp::Any visitAttributeNamedArg(PhpParser::AttributeNamedArgContext *context) = 0;

    virtual antlrcpp::Any visitInnerStatementList(PhpParser::InnerStatementListContext *context) = 0;

    virtual antlrcpp::Any visitInnerStatement(PhpParser::InnerStatementContext *context) = 0;

    virtual antlrcpp::Any visitStatement(PhpParser::StatementContext *context) = 0;

    virtual antlrcpp::Any visitEmptyStatement(PhpParser::EmptyStatementContext *context) = 0;

    virtual antlrcpp::Any visitBlockStatement(PhpParser::BlockStatementContext *context) = 0;

    virtual antlrcpp::Any visitIfStatement(PhpParser::IfStatementContext *context) = 0;

    virtual antlrcpp::Any visitElseIfStatement(PhpParser::ElseIfStatementContext *context) = 0;

    virtual antlrcpp::Any visitElseIfColonStatement(PhpParser::ElseIfColonStatementContext *context) = 0;

    virtual antlrcpp::Any visitElseStatement(PhpParser::ElseStatementContext *context) = 0;

    virtual antlrcpp::Any visitElseColonStatement(PhpParser::ElseColonStatementContext *context) = 0;

    virtual antlrcpp::Any visitWhileStatement(PhpParser::WhileStatementContext *context) = 0;

    virtual antlrcpp::Any visitDoWhileStatement(PhpParser::DoWhileStatementContext *context) = 0;

    virtual antlrcpp::Any visitForStatement(PhpParser::ForStatementContext *context) = 0;

    virtual antlrcpp::Any visitForInit(PhpParser::ForInitContext *context) = 0;

    virtual antlrcpp::Any visitForUpdate(PhpParser::ForUpdateContext *context) = 0;

    virtual antlrcpp::Any visitSwitchStatement(PhpParser::SwitchStatementContext *context) = 0;

    virtual antlrcpp::Any visitSwitchBlock(PhpParser::SwitchBlockContext *context) = 0;

    virtual antlrcpp::Any visitBreakStatement(PhpParser::BreakStatementContext *context) = 0;

    virtual antlrcpp::Any visitContinueStatement(PhpParser::ContinueStatementContext *context) = 0;

    virtual antlrcpp::Any visitReturnStatement(PhpParser::ReturnStatementContext *context) = 0;

    virtual antlrcpp::Any visitExpressionStatement(PhpParser::ExpressionStatementContext *context) = 0;

    virtual antlrcpp::Any visitUnsetStatement(PhpParser::UnsetStatementContext *context) = 0;

    virtual antlrcpp::Any visitForeachStatement(PhpParser::ForeachStatementContext *context) = 0;

    virtual antlrcpp::Any visitTryCatchFinally(PhpParser::TryCatchFinallyContext *context) = 0;

    virtual antlrcpp::Any visitCatchClause(PhpParser::CatchClauseContext *context) = 0;

    virtual antlrcpp::Any visitFinallyStatement(PhpParser::FinallyStatementContext *context) = 0;

    virtual antlrcpp::Any visitThrowStatement(PhpParser::ThrowStatementContext *context) = 0;

    virtual antlrcpp::Any visitGotoStatement(PhpParser::GotoStatementContext *context) = 0;

    virtual antlrcpp::Any visitDeclareStatement(PhpParser::DeclareStatementContext *context) = 0;

    virtual antlrcpp::Any visitDeclareList(PhpParser::DeclareListContext *context) = 0;

    virtual antlrcpp::Any visitFormalParameterList(PhpParser::FormalParameterListContext *context) = 0;

    virtual antlrcpp::Any visitFormalParameter(PhpParser::FormalParameterContext *context) = 0;

    virtual antlrcpp::Any visitTypeHint(PhpParser::TypeHintContext *context) = 0;

    virtual antlrcpp::Any visitGlobalStatement(PhpParser::GlobalStatementContext *context) = 0;

    virtual antlrcpp::Any visitGlobalVar(PhpParser::GlobalVarContext *context) = 0;

    virtual antlrcpp::Any visitEchoStatement(PhpParser::EchoStatementContext *context) = 0;

    virtual antlrcpp::Any visitStaticVariableStatement(PhpParser::StaticVariableStatementContext *context) = 0;

    virtual antlrcpp::Any visitClassStatement(PhpParser::ClassStatementContext *context) = 0;

    virtual antlrcpp::Any visitTraitAdaptations(PhpParser::TraitAdaptationsContext *context) = 0;

    virtual antlrcpp::Any visitTraitAdaptationStatement(PhpParser::TraitAdaptationStatementContext *context) = 0;

    virtual antlrcpp::Any visitTraitPrecedence(PhpParser::TraitPrecedenceContext *context) = 0;

    virtual antlrcpp::Any visitTraitAlias(PhpParser::TraitAliasContext *context) = 0;

    virtual antlrcpp::Any visitTraitMethodReference(PhpParser::TraitMethodReferenceContext *context) = 0;

    virtual antlrcpp::Any visitBaseCtorCall(PhpParser::BaseCtorCallContext *context) = 0;

    virtual antlrcpp::Any visitMethodBody(PhpParser::MethodBodyContext *context) = 0;

    virtual antlrcpp::Any visitPropertyModifiers(PhpParser::PropertyModifiersContext *context) = 0;

    virtual antlrcpp::Any visitMemberModifiers(PhpParser::MemberModifiersContext *context) = 0;

    virtual antlrcpp::Any visitVariableInitializer(PhpParser::VariableInitializerContext *context) = 0;

    virtual antlrcpp::Any visitIdentifierInititalizer(PhpParser::IdentifierInititalizerContext *context) = 0;

    virtual antlrcpp::Any visitGlobalConstantDeclaration(PhpParser::GlobalConstantDeclarationContext *context) = 0;

    virtual antlrcpp::Any visitExpressionList(PhpParser::ExpressionListContext *context) = 0;

    virtual antlrcpp::Any visitParenthesis(PhpParser::ParenthesisContext *context) = 0;

    virtual antlrcpp::Any visitChainExpression(PhpParser::ChainExpressionContext *context) = 0;

    virtual antlrcpp::Any visitUnaryOperatorExpression(PhpParser::UnaryOperatorExpressionContext *context) = 0;

    virtual antlrcpp::Any visitSpecialWordExpression(PhpParser::SpecialWordExpressionContext *context) = 0;

    virtual antlrcpp::Any visitArrayCreationExpression(PhpParser::ArrayCreationExpressionContext *context) = 0;

    virtual antlrcpp::Any visitNewExpression(PhpParser::NewExpressionContext *context) = 0;

    virtual antlrcpp::Any visitParenthesisExpression(PhpParser::ParenthesisExpressionContext *context) = 0;

    virtual antlrcpp::Any visitBackQuoteStringExpression(PhpParser::BackQuoteStringExpressionContext *context) = 0;

    virtual antlrcpp::Any visitConditionalExpression(PhpParser::ConditionalExpressionContext *context) = 0;

    virtual antlrcpp::Any visitArithmeticExpression(PhpParser::ArithmeticExpressionContext *context) = 0;

    virtual antlrcpp::Any visitIndexerExpression(PhpParser::IndexerExpressionContext *context) = 0;

    virtual antlrcpp::Any visitScalarExpression(PhpParser::ScalarExpressionContext *context) = 0;

    virtual antlrcpp::Any visitPrefixIncDecExpression(PhpParser::PrefixIncDecExpressionContext *context) = 0;

    virtual antlrcpp::Any visitComparisonExpression(PhpParser::ComparisonExpressionContext *context) = 0;

    virtual antlrcpp::Any visitLogicalExpression(PhpParser::LogicalExpressionContext *context) = 0;

    virtual antlrcpp::Any visitPrintExpression(PhpParser::PrintExpressionContext *context) = 0;

    virtual antlrcpp::Any visitAssignmentExpression(PhpParser::AssignmentExpressionContext *context) = 0;

    virtual antlrcpp::Any visitPostfixIncDecExpression(PhpParser::PostfixIncDecExpressionContext *context) = 0;

    virtual antlrcpp::Any visitCastExpression(PhpParser::CastExpressionContext *context) = 0;

    virtual antlrcpp::Any visitInstanceOfExpression(PhpParser::InstanceOfExpressionContext *context) = 0;

    virtual antlrcpp::Any visitLambdaFunctionExpression(PhpParser::LambdaFunctionExpressionContext *context) = 0;

    virtual antlrcpp::Any visitBitwiseExpression(PhpParser::BitwiseExpressionContext *context) = 0;

    virtual antlrcpp::Any visitCloneExpression(PhpParser::CloneExpressionContext *context) = 0;

    virtual antlrcpp::Any visitNewExpr(PhpParser::NewExprContext *context) = 0;

    virtual antlrcpp::Any visitAssignmentOperator(PhpParser::AssignmentOperatorContext *context) = 0;

    virtual antlrcpp::Any visitYieldExpression(PhpParser::YieldExpressionContext *context) = 0;

    virtual antlrcpp::Any visitArrayItemList(PhpParser::ArrayItemListContext *context) = 0;

    virtual antlrcpp::Any visitArrayItem(PhpParser::ArrayItemContext *context) = 0;

    virtual antlrcpp::Any visitLambdaFunctionUseVars(PhpParser::LambdaFunctionUseVarsContext *context) = 0;

    virtual antlrcpp::Any visitLambdaFunctionUseVar(PhpParser::LambdaFunctionUseVarContext *context) = 0;

    virtual antlrcpp::Any visitQualifiedStaticTypeRef(PhpParser::QualifiedStaticTypeRefContext *context) = 0;

    virtual antlrcpp::Any visitTypeRef(PhpParser::TypeRefContext *context) = 0;

    virtual antlrcpp::Any visitIndirectTypeRef(PhpParser::IndirectTypeRefContext *context) = 0;

    virtual antlrcpp::Any visitQualifiedNamespaceName(PhpParser::QualifiedNamespaceNameContext *context) = 0;

    virtual antlrcpp::Any visitNamespaceNameList(PhpParser::NamespaceNameListContext *context) = 0;

    virtual antlrcpp::Any visitQualifiedNamespaceNameList(PhpParser::QualifiedNamespaceNameListContext *context) = 0;

    virtual antlrcpp::Any visitArguments(PhpParser::ArgumentsContext *context) = 0;

    virtual antlrcpp::Any visitActualArgument(PhpParser::ActualArgumentContext *context) = 0;

    virtual antlrcpp::Any visitConstantInititalizer(PhpParser::ConstantInititalizerContext *context) = 0;

    virtual antlrcpp::Any visitConstantArrayItemList(PhpParser::ConstantArrayItemListContext *context) = 0;

    virtual antlrcpp::Any visitConstantArrayItem(PhpParser::ConstantArrayItemContext *context) = 0;

    virtual antlrcpp::Any visitConstant(PhpParser::ConstantContext *context) = 0;

    virtual antlrcpp::Any visitLiteralConstant(PhpParser::LiteralConstantContext *context) = 0;

    virtual antlrcpp::Any visitNumericConstant(PhpParser::NumericConstantContext *context) = 0;

    virtual antlrcpp::Any visitClassConstant(PhpParser::ClassConstantContext *context) = 0;

    virtual antlrcpp::Any visitStringConstant(PhpParser::StringConstantContext *context) = 0;

    virtual antlrcpp::Any visitString(PhpParser::StringContext *context) = 0;

    virtual antlrcpp::Any visitInterpolatedStringPart(PhpParser::InterpolatedStringPartContext *context) = 0;

    virtual antlrcpp::Any visitChainList(PhpParser::ChainListContext *context) = 0;

    virtual antlrcpp::Any visitChain(PhpParser::ChainContext *context) = 0;

    virtual antlrcpp::Any visitMemberAccess(PhpParser::MemberAccessContext *context) = 0;

    virtual antlrcpp::Any visitFunctionCall(PhpParser::FunctionCallContext *context) = 0;

    virtual antlrcpp::Any visitFunctionCallName(PhpParser::FunctionCallNameContext *context) = 0;

    virtual antlrcpp::Any visitActualArguments(PhpParser::ActualArgumentsContext *context) = 0;

    virtual antlrcpp::Any visitChainBase(PhpParser::ChainBaseContext *context) = 0;

    virtual antlrcpp::Any visitKeyedFieldName(PhpParser::KeyedFieldNameContext *context) = 0;

    virtual antlrcpp::Any visitKeyedSimpleFieldName(PhpParser::KeyedSimpleFieldNameContext *context) = 0;

    virtual antlrcpp::Any visitKeyedVariable(PhpParser::KeyedVariableContext *context) = 0;

    virtual antlrcpp::Any visitSquareCurlyExpression(PhpParser::SquareCurlyExpressionContext *context) = 0;

    virtual antlrcpp::Any visitAssignmentList(PhpParser::AssignmentListContext *context) = 0;

    virtual antlrcpp::Any visitAssignmentListElement(PhpParser::AssignmentListElementContext *context) = 0;

    virtual antlrcpp::Any visitModifier(PhpParser::ModifierContext *context) = 0;

    virtual antlrcpp::Any visitIdentifier(PhpParser::IdentifierContext *context) = 0;

    virtual antlrcpp::Any visitMemberModifier(PhpParser::MemberModifierContext *context) = 0;

    virtual antlrcpp::Any visitMagicConstant(PhpParser::MagicConstantContext *context) = 0;

    virtual antlrcpp::Any visitMagicMethod(PhpParser::MagicMethodContext *context) = 0;

    virtual antlrcpp::Any visitPrimitiveType(PhpParser::PrimitiveTypeContext *context) = 0;

    virtual antlrcpp::Any visitCastOperation(PhpParser::CastOperationContext *context) = 0;


};

