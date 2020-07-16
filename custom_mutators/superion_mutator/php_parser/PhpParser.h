
// Generated from C:\Users\xiang\Documents\GitHub\php_parser\PhpParser.g4 by ANTLR 4.7

#pragma once


#include "antlr4-runtime.h"




class  PhpParser : public antlr4::Parser {
public:
  enum {
    PHPStart = 1, Shebang = 2, Error = 3, PHPEnd = 4, Whitespace = 5, MultiLineComment = 6, 
    SingleLineComment = 7, ShellStyleComment = 8, Abstract = 9, Array = 10, 
    As = 11, BinaryCast = 12, BoolType = 13, BooleanConstant = 14, Break = 15, 
    Callable = 16, Case = 17, Catch = 18, Class = 19, Clone = 20, Const = 21, 
    Continue = 22, Declare = 23, Default = 24, Do = 25, DoubleCast = 26, 
    DoubleType = 27, Echo = 28, Else = 29, ElseIf = 30, Empty = 31, EndDeclare = 32, 
    EndFor = 33, EndForeach = 34, EndIf = 35, EndSwitch = 36, EndWhile = 37, 
    Eval = 38, Exit = 39, Extends = 40, Final = 41, Finally = 42, FloatCast = 43, 
    For = 44, Foreach = 45, Function = 46, Global = 47, Goto = 48, If = 49, 
    Implements = 50, Import = 51, Include = 52, IncludeOnce = 53, InstanceOf = 54, 
    InsteadOf = 55, Int8Cast = 56, Int16Cast = 57, Int64Type = 58, IntType = 59, 
    Interface = 60, IsSet = 61, List = 62, LogicalAnd = 63, LogicalOr = 64, 
    LogicalXor = 65, Namespace = 66, New = 67, Null = 68, ObjectType = 69, 
    Parent_ = 70, Partial = 71, Print = 72, Private = 73, Protected = 74, 
    Public = 75, Require = 76, RequireOnce = 77, Resource = 78, Return = 79, 
    Static = 80, StringType = 81, Switch = 82, Throw = 83, Trait = 84, Try = 85, 
    Typeof = 86, UintCast = 87, UnicodeCast = 88, Unset = 89, Use = 90, 
    Var = 91, While = 92, Yield = 93, Get = 94, Set = 95, Call = 96, CallStatic = 97, 
    Constructor = 98, Destruct = 99, Wakeup = 100, Sleep = 101, Autoload = 102, 
    IsSet__ = 103, Unset__ = 104, ToString__ = 105, Invoke = 106, SetState = 107, 
    Clone__ = 108, DebugInfo = 109, Namespace__ = 110, Class__ = 111, Traic__ = 112, 
    Function__ = 113, Method__ = 114, Line__ = 115, File__ = 116, Dir__ = 117, 
    Lgeneric = 118, Rgeneric = 119, DoubleArrow = 120, Inc = 121, Dec = 122, 
    IsIdentical = 123, IsNoidentical = 124, IsEqual = 125, IsNotEq = 126, 
    IsSmallerOrEqual = 127, IsGreaterOrEqual = 128, PlusEqual = 129, MinusEqual = 130, 
    MulEqual = 131, Pow = 132, PowEqual = 133, DivEqual = 134, Concaequal = 135, 
    ModEqual = 136, ShiftLeftEqual = 137, ShiftRightEqual = 138, AndEqual = 139, 
    OrEqual = 140, XorEqual = 141, BooleanOr = 142, BooleanAnd = 143, ShiftLeft = 144, 
    ShiftRight = 145, DoubleColon = 146, ObjectOperator = 147, NamespaceSeparator = 148, 
    Ellipsis = 149, Less = 150, Greater = 151, Ampersand = 152, Pipe = 153, 
    Bang = 154, Caret = 155, Plus = 156, Minus = 157, Asterisk = 158, Percent = 159, 
    Divide = 160, Tilde = 161, SuppressWarnings = 162, Dollar = 163, Dot = 164, 
    QuestionMark = 165, OpenRoundBracket = 166, CloseRoundBracket = 167, 
    OpenSquareBracket = 168, CloseSquareBracket = 169, OpenCurlyBracket = 170, 
    CloseCurlyBracket = 171, Comma = 172, Colon = 173, SemiColon = 174, 
    Eq = 175, Quote = 176, BackQuote = 177, VarName = 178, Label = 179, 
    Octal = 180, Decimal = 181, Real = 182, Hex = 183, Binary = 184, BackQuoteString = 185, 
    SingleQuoteString = 186, DoubleQuote = 187, StartNowDoc = 188, StartHereDoc = 189, 
    ErrorPhp = 190, CurlyDollar = 191, StringPart = 192, Comment = 193, 
    PHPEndSingleLineComment = 194, CommentEnd = 195, HereDocText = 196
  };

  enum {
    RulePhpBlock = 0, RuleImportStatement = 1, RuleTopStatement = 2, RuleUseDeclaration = 3, 
    RuleUseDeclarationContentList = 4, RuleUseDeclarationContent = 5, RuleNamespaceDeclaration = 6, 
    RuleNamespaceStatement = 7, RuleFunctionDeclaration = 8, RuleClassDeclaration = 9, 
    RuleClassEntryType = 10, RuleInterfaceList = 11, RuleTypeParameterListInBrackets = 12, 
    RuleTypeParameterList = 13, RuleTypeParameterWithDefaultsList = 14, 
    RuleTypeParameterDecl = 15, RuleTypeParameterWithDefaultDecl = 16, RuleGenericDynamicArgs = 17, 
    RuleAttributes = 18, RuleAttributesGroup = 19, RuleAttribute = 20, RuleAttributeArgList = 21, 
    RuleAttributeNamedArgList = 22, RuleAttributeNamedArg = 23, RuleInnerStatementList = 24, 
    RuleInnerStatement = 25, RuleStatement = 26, RuleEmptyStatement = 27, 
    RuleBlockStatement = 28, RuleIfStatement = 29, RuleElseIfStatement = 30, 
    RuleElseIfColonStatement = 31, RuleElseStatement = 32, RuleElseColonStatement = 33, 
    RuleWhileStatement = 34, RuleDoWhileStatement = 35, RuleForStatement = 36, 
    RuleForInit = 37, RuleForUpdate = 38, RuleSwitchStatement = 39, RuleSwitchBlock = 40, 
    RuleBreakStatement = 41, RuleContinueStatement = 42, RuleReturnStatement = 43, 
    RuleExpressionStatement = 44, RuleUnsetStatement = 45, RuleForeachStatement = 46, 
    RuleTryCatchFinally = 47, RuleCatchClause = 48, RuleFinallyStatement = 49, 
    RuleThrowStatement = 50, RuleGotoStatement = 51, RuleDeclareStatement = 52, 
    RuleDeclareList = 53, RuleFormalParameterList = 54, RuleFormalParameter = 55, 
    RuleTypeHint = 56, RuleGlobalStatement = 57, RuleGlobalVar = 58, RuleEchoStatement = 59, 
    RuleStaticVariableStatement = 60, RuleClassStatement = 61, RuleTraitAdaptations = 62, 
    RuleTraitAdaptationStatement = 63, RuleTraitPrecedence = 64, RuleTraitAlias = 65, 
    RuleTraitMethodReference = 66, RuleBaseCtorCall = 67, RuleMethodBody = 68, 
    RulePropertyModifiers = 69, RuleMemberModifiers = 70, RuleVariableInitializer = 71, 
    RuleIdentifierInititalizer = 72, RuleGlobalConstantDeclaration = 73, 
    RuleExpressionList = 74, RuleParenthesis = 75, RuleExpression = 76, 
    RuleNewExpr = 77, RuleAssignmentOperator = 78, RuleYieldExpression = 79, 
    RuleArrayItemList = 80, RuleArrayItem = 81, RuleLambdaFunctionUseVars = 82, 
    RuleLambdaFunctionUseVar = 83, RuleQualifiedStaticTypeRef = 84, RuleTypeRef = 85, 
    RuleIndirectTypeRef = 86, RuleQualifiedNamespaceName = 87, RuleNamespaceNameList = 88, 
    RuleQualifiedNamespaceNameList = 89, RuleArguments = 90, RuleActualArgument = 91, 
    RuleConstantInititalizer = 92, RuleConstantArrayItemList = 93, RuleConstantArrayItem = 94, 
    RuleConstant = 95, RuleLiteralConstant = 96, RuleNumericConstant = 97, 
    RuleClassConstant = 98, RuleStringConstant = 99, RuleString = 100, RuleInterpolatedStringPart = 101, 
    RuleChainList = 102, RuleChain = 103, RuleMemberAccess = 104, RuleFunctionCall = 105, 
    RuleFunctionCallName = 106, RuleActualArguments = 107, RuleChainBase = 108, 
    RuleKeyedFieldName = 109, RuleKeyedSimpleFieldName = 110, RuleKeyedVariable = 111, 
    RuleSquareCurlyExpression = 112, RuleAssignmentList = 113, RuleAssignmentListElement = 114, 
    RuleModifier = 115, RuleIdentifier = 116, RuleMemberModifier = 117, 
    RuleMagicConstant = 118, RuleMagicMethod = 119, RulePrimitiveType = 120, 
    RuleCastOperation = 121
  };

  PhpParser(antlr4::TokenStream *input);
  ~PhpParser();

  virtual std::string getGrammarFileName() const override;
  virtual const antlr4::atn::ATN& getATN() const override { return _atn; };
  virtual const std::vector<std::string>& getTokenNames() const override { return _tokenNames; }; // deprecated: use vocabulary instead.
  virtual const std::vector<std::string>& getRuleNames() const override;
  virtual antlr4::dfa::Vocabulary& getVocabulary() const override;


  class PhpBlockContext;
  class ImportStatementContext;
  class TopStatementContext;
  class UseDeclarationContext;
  class UseDeclarationContentListContext;
  class UseDeclarationContentContext;
  class NamespaceDeclarationContext;
  class NamespaceStatementContext;
  class FunctionDeclarationContext;
  class ClassDeclarationContext;
  class ClassEntryTypeContext;
  class InterfaceListContext;
  class TypeParameterListInBracketsContext;
  class TypeParameterListContext;
  class TypeParameterWithDefaultsListContext;
  class TypeParameterDeclContext;
  class TypeParameterWithDefaultDeclContext;
  class GenericDynamicArgsContext;
  class AttributesContext;
  class AttributesGroupContext;
  class AttributeContext;
  class AttributeArgListContext;
  class AttributeNamedArgListContext;
  class AttributeNamedArgContext;
  class InnerStatementListContext;
  class InnerStatementContext;
  class StatementContext;
  class EmptyStatementContext;
  class BlockStatementContext;
  class IfStatementContext;
  class ElseIfStatementContext;
  class ElseIfColonStatementContext;
  class ElseStatementContext;
  class ElseColonStatementContext;
  class WhileStatementContext;
  class DoWhileStatementContext;
  class ForStatementContext;
  class ForInitContext;
  class ForUpdateContext;
  class SwitchStatementContext;
  class SwitchBlockContext;
  class BreakStatementContext;
  class ContinueStatementContext;
  class ReturnStatementContext;
  class ExpressionStatementContext;
  class UnsetStatementContext;
  class ForeachStatementContext;
  class TryCatchFinallyContext;
  class CatchClauseContext;
  class FinallyStatementContext;
  class ThrowStatementContext;
  class GotoStatementContext;
  class DeclareStatementContext;
  class DeclareListContext;
  class FormalParameterListContext;
  class FormalParameterContext;
  class TypeHintContext;
  class GlobalStatementContext;
  class GlobalVarContext;
  class EchoStatementContext;
  class StaticVariableStatementContext;
  class ClassStatementContext;
  class TraitAdaptationsContext;
  class TraitAdaptationStatementContext;
  class TraitPrecedenceContext;
  class TraitAliasContext;
  class TraitMethodReferenceContext;
  class BaseCtorCallContext;
  class MethodBodyContext;
  class PropertyModifiersContext;
  class MemberModifiersContext;
  class VariableInitializerContext;
  class IdentifierInititalizerContext;
  class GlobalConstantDeclarationContext;
  class ExpressionListContext;
  class ParenthesisContext;
  class ExpressionContext;
  class NewExprContext;
  class AssignmentOperatorContext;
  class YieldExpressionContext;
  class ArrayItemListContext;
  class ArrayItemContext;
  class LambdaFunctionUseVarsContext;
  class LambdaFunctionUseVarContext;
  class QualifiedStaticTypeRefContext;
  class TypeRefContext;
  class IndirectTypeRefContext;
  class QualifiedNamespaceNameContext;
  class NamespaceNameListContext;
  class QualifiedNamespaceNameListContext;
  class ArgumentsContext;
  class ActualArgumentContext;
  class ConstantInititalizerContext;
  class ConstantArrayItemListContext;
  class ConstantArrayItemContext;
  class ConstantContext;
  class LiteralConstantContext;
  class NumericConstantContext;
  class ClassConstantContext;
  class StringConstantContext;
  class StringContext;
  class InterpolatedStringPartContext;
  class ChainListContext;
  class ChainContext;
  class MemberAccessContext;
  class FunctionCallContext;
  class FunctionCallNameContext;
  class ActualArgumentsContext;
  class ChainBaseContext;
  class KeyedFieldNameContext;
  class KeyedSimpleFieldNameContext;
  class KeyedVariableContext;
  class SquareCurlyExpressionContext;
  class AssignmentListContext;
  class AssignmentListElementContext;
  class ModifierContext;
  class IdentifierContext;
  class MemberModifierContext;
  class MagicConstantContext;
  class MagicMethodContext;
  class PrimitiveTypeContext;
  class CastOperationContext; 

  class  PhpBlockContext : public antlr4::ParserRuleContext {
  public:
    PhpBlockContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<ImportStatementContext *> importStatement();
    ImportStatementContext* importStatement(size_t i);
    std::vector<TopStatementContext *> topStatement();
    TopStatementContext* topStatement(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  PhpBlockContext* phpBlock();

  class  ImportStatementContext : public antlr4::ParserRuleContext {
  public:
    ImportStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Import();
    antlr4::tree::TerminalNode *Namespace();
    NamespaceNameListContext *namespaceNameList();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ImportStatementContext* importStatement();

  class  TopStatementContext : public antlr4::ParserRuleContext {
  public:
    TopStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    StatementContext *statement();
    UseDeclarationContext *useDeclaration();
    NamespaceDeclarationContext *namespaceDeclaration();
    FunctionDeclarationContext *functionDeclaration();
    ClassDeclarationContext *classDeclaration();
    GlobalConstantDeclarationContext *globalConstantDeclaration();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TopStatementContext* topStatement();

  class  UseDeclarationContext : public antlr4::ParserRuleContext {
  public:
    UseDeclarationContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Use();
    UseDeclarationContentListContext *useDeclarationContentList();
    antlr4::tree::TerminalNode *Function();
    antlr4::tree::TerminalNode *Const();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  UseDeclarationContext* useDeclaration();

  class  UseDeclarationContentListContext : public antlr4::ParserRuleContext {
  public:
    UseDeclarationContentListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<UseDeclarationContentContext *> useDeclarationContent();
    UseDeclarationContentContext* useDeclarationContent(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  UseDeclarationContentListContext* useDeclarationContentList();

  class  UseDeclarationContentContext : public antlr4::ParserRuleContext {
  public:
    UseDeclarationContentContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    NamespaceNameListContext *namespaceNameList();
    antlr4::tree::TerminalNode *As();
    IdentifierContext *identifier();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  UseDeclarationContentContext* useDeclarationContent();

  class  NamespaceDeclarationContext : public antlr4::ParserRuleContext {
  public:
    NamespaceDeclarationContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Namespace();
    antlr4::tree::TerminalNode *OpenCurlyBracket();
    NamespaceNameListContext *namespaceNameList();
    std::vector<NamespaceStatementContext *> namespaceStatement();
    NamespaceStatementContext* namespaceStatement(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  NamespaceDeclarationContext* namespaceDeclaration();

  class  NamespaceStatementContext : public antlr4::ParserRuleContext {
  public:
    NamespaceStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    StatementContext *statement();
    UseDeclarationContext *useDeclaration();
    FunctionDeclarationContext *functionDeclaration();
    ClassDeclarationContext *classDeclaration();
    GlobalConstantDeclarationContext *globalConstantDeclaration();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  NamespaceStatementContext* namespaceStatement();

  class  FunctionDeclarationContext : public antlr4::ParserRuleContext {
  public:
    FunctionDeclarationContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AttributesContext *attributes();
    antlr4::tree::TerminalNode *Function();
    IdentifierContext *identifier();
    FormalParameterListContext *formalParameterList();
    BlockStatementContext *blockStatement();
    TypeParameterListInBracketsContext *typeParameterListInBrackets();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  FunctionDeclarationContext* functionDeclaration();

  class  ClassDeclarationContext : public antlr4::ParserRuleContext {
  public:
    ClassDeclarationContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AttributesContext *attributes();
    antlr4::tree::TerminalNode *OpenCurlyBracket();
    ClassEntryTypeContext *classEntryType();
    IdentifierContext *identifier();
    antlr4::tree::TerminalNode *Interface();
    antlr4::tree::TerminalNode *Private();
    ModifierContext *modifier();
    antlr4::tree::TerminalNode *Partial();
    std::vector<ClassStatementContext *> classStatement();
    ClassStatementContext* classStatement(size_t i);
    TypeParameterListInBracketsContext *typeParameterListInBrackets();
    antlr4::tree::TerminalNode *Extends();
    QualifiedStaticTypeRefContext *qualifiedStaticTypeRef();
    antlr4::tree::TerminalNode *Implements();
    InterfaceListContext *interfaceList();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ClassDeclarationContext* classDeclaration();

  class  ClassEntryTypeContext : public antlr4::ParserRuleContext {
  public:
    ClassEntryTypeContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Class();
    antlr4::tree::TerminalNode *Trait();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ClassEntryTypeContext* classEntryType();

  class  InterfaceListContext : public antlr4::ParserRuleContext {
  public:
    InterfaceListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<QualifiedStaticTypeRefContext *> qualifiedStaticTypeRef();
    QualifiedStaticTypeRefContext* qualifiedStaticTypeRef(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  InterfaceListContext* interfaceList();

  class  TypeParameterListInBracketsContext : public antlr4::ParserRuleContext {
  public:
    TypeParameterListInBracketsContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TypeParameterListContext *typeParameterList();
    TypeParameterWithDefaultsListContext *typeParameterWithDefaultsList();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TypeParameterListInBracketsContext* typeParameterListInBrackets();

  class  TypeParameterListContext : public antlr4::ParserRuleContext {
  public:
    TypeParameterListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<TypeParameterDeclContext *> typeParameterDecl();
    TypeParameterDeclContext* typeParameterDecl(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TypeParameterListContext* typeParameterList();

  class  TypeParameterWithDefaultsListContext : public antlr4::ParserRuleContext {
  public:
    TypeParameterWithDefaultsListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<TypeParameterWithDefaultDeclContext *> typeParameterWithDefaultDecl();
    TypeParameterWithDefaultDeclContext* typeParameterWithDefaultDecl(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TypeParameterWithDefaultsListContext* typeParameterWithDefaultsList();

  class  TypeParameterDeclContext : public antlr4::ParserRuleContext {
  public:
    TypeParameterDeclContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AttributesContext *attributes();
    IdentifierContext *identifier();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TypeParameterDeclContext* typeParameterDecl();

  class  TypeParameterWithDefaultDeclContext : public antlr4::ParserRuleContext {
  public:
    TypeParameterWithDefaultDeclContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AttributesContext *attributes();
    IdentifierContext *identifier();
    antlr4::tree::TerminalNode *Eq();
    QualifiedStaticTypeRefContext *qualifiedStaticTypeRef();
    PrimitiveTypeContext *primitiveType();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TypeParameterWithDefaultDeclContext* typeParameterWithDefaultDecl();

  class  GenericDynamicArgsContext : public antlr4::ParserRuleContext {
  public:
    GenericDynamicArgsContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<TypeRefContext *> typeRef();
    TypeRefContext* typeRef(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  GenericDynamicArgsContext* genericDynamicArgs();

  class  AttributesContext : public antlr4::ParserRuleContext {
  public:
    AttributesContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<AttributesGroupContext *> attributesGroup();
    AttributesGroupContext* attributesGroup(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  AttributesContext* attributes();

  class  AttributesGroupContext : public antlr4::ParserRuleContext {
  public:
    AttributesGroupContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<AttributeContext *> attribute();
    AttributeContext* attribute(size_t i);
    IdentifierContext *identifier();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  AttributesGroupContext* attributesGroup();

  class  AttributeContext : public antlr4::ParserRuleContext {
  public:
    AttributeContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    QualifiedNamespaceNameContext *qualifiedNamespaceName();
    AttributeArgListContext *attributeArgList();
    AttributeNamedArgListContext *attributeNamedArgList();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  AttributeContext* attribute();

  class  AttributeArgListContext : public antlr4::ParserRuleContext {
  public:
    AttributeArgListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<ExpressionContext *> expression();
    ExpressionContext* expression(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  AttributeArgListContext* attributeArgList();

  class  AttributeNamedArgListContext : public antlr4::ParserRuleContext {
  public:
    AttributeNamedArgListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<AttributeNamedArgContext *> attributeNamedArg();
    AttributeNamedArgContext* attributeNamedArg(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  AttributeNamedArgListContext* attributeNamedArgList();

  class  AttributeNamedArgContext : public antlr4::ParserRuleContext {
  public:
    AttributeNamedArgContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *VarName();
    ExpressionContext *expression();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  AttributeNamedArgContext* attributeNamedArg();

  class  InnerStatementListContext : public antlr4::ParserRuleContext {
  public:
    InnerStatementListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<InnerStatementContext *> innerStatement();
    InnerStatementContext* innerStatement(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  InnerStatementListContext* innerStatementList();

  class  InnerStatementContext : public antlr4::ParserRuleContext {
  public:
    InnerStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    StatementContext *statement();
    FunctionDeclarationContext *functionDeclaration();
    ClassDeclarationContext *classDeclaration();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  InnerStatementContext* innerStatement();

  class  StatementContext : public antlr4::ParserRuleContext {
  public:
    StatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    IdentifierContext *identifier();
    BlockStatementContext *blockStatement();
    IfStatementContext *ifStatement();
    WhileStatementContext *whileStatement();
    DoWhileStatementContext *doWhileStatement();
    ForStatementContext *forStatement();
    SwitchStatementContext *switchStatement();
    BreakStatementContext *breakStatement();
    ContinueStatementContext *continueStatement();
    ReturnStatementContext *returnStatement();
    YieldExpressionContext *yieldExpression();
    GlobalStatementContext *globalStatement();
    StaticVariableStatementContext *staticVariableStatement();
    EchoStatementContext *echoStatement();
    ExpressionStatementContext *expressionStatement();
    UnsetStatementContext *unsetStatement();
    ForeachStatementContext *foreachStatement();
    TryCatchFinallyContext *tryCatchFinally();
    ThrowStatementContext *throwStatement();
    GotoStatementContext *gotoStatement();
    DeclareStatementContext *declareStatement();
    EmptyStatementContext *emptyStatement();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  StatementContext* statement();

  class  EmptyStatementContext : public antlr4::ParserRuleContext {
  public:
    EmptyStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  EmptyStatementContext* emptyStatement();

  class  BlockStatementContext : public antlr4::ParserRuleContext {
  public:
    BlockStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *OpenCurlyBracket();
    InnerStatementListContext *innerStatementList();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  BlockStatementContext* blockStatement();

  class  IfStatementContext : public antlr4::ParserRuleContext {
  public:
    IfStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *If();
    ParenthesisContext *parenthesis();
    StatementContext *statement();
    std::vector<ElseIfStatementContext *> elseIfStatement();
    ElseIfStatementContext* elseIfStatement(size_t i);
    ElseStatementContext *elseStatement();
    InnerStatementListContext *innerStatementList();
    antlr4::tree::TerminalNode *EndIf();
    std::vector<ElseIfColonStatementContext *> elseIfColonStatement();
    ElseIfColonStatementContext* elseIfColonStatement(size_t i);
    ElseColonStatementContext *elseColonStatement();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  IfStatementContext* ifStatement();

  class  ElseIfStatementContext : public antlr4::ParserRuleContext {
  public:
    ElseIfStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ElseIf();
    ParenthesisContext *parenthesis();
    StatementContext *statement();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ElseIfStatementContext* elseIfStatement();

  class  ElseIfColonStatementContext : public antlr4::ParserRuleContext {
  public:
    ElseIfColonStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ElseIf();
    ParenthesisContext *parenthesis();
    InnerStatementListContext *innerStatementList();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ElseIfColonStatementContext* elseIfColonStatement();

  class  ElseStatementContext : public antlr4::ParserRuleContext {
  public:
    ElseStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Else();
    StatementContext *statement();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ElseStatementContext* elseStatement();

  class  ElseColonStatementContext : public antlr4::ParserRuleContext {
  public:
    ElseColonStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Else();
    InnerStatementListContext *innerStatementList();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ElseColonStatementContext* elseColonStatement();

  class  WhileStatementContext : public antlr4::ParserRuleContext {
  public:
    WhileStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *While();
    ParenthesisContext *parenthesis();
    StatementContext *statement();
    InnerStatementListContext *innerStatementList();
    antlr4::tree::TerminalNode *EndWhile();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  WhileStatementContext* whileStatement();

  class  DoWhileStatementContext : public antlr4::ParserRuleContext {
  public:
    DoWhileStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Do();
    StatementContext *statement();
    antlr4::tree::TerminalNode *While();
    ParenthesisContext *parenthesis();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  DoWhileStatementContext* doWhileStatement();

  class  ForStatementContext : public antlr4::ParserRuleContext {
  public:
    ForStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *For();
    StatementContext *statement();
    InnerStatementListContext *innerStatementList();
    antlr4::tree::TerminalNode *EndFor();
    ForInitContext *forInit();
    ExpressionListContext *expressionList();
    ForUpdateContext *forUpdate();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ForStatementContext* forStatement();

  class  ForInitContext : public antlr4::ParserRuleContext {
  public:
    ForInitContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ExpressionListContext *expressionList();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ForInitContext* forInit();

  class  ForUpdateContext : public antlr4::ParserRuleContext {
  public:
    ForUpdateContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ExpressionListContext *expressionList();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ForUpdateContext* forUpdate();

  class  SwitchStatementContext : public antlr4::ParserRuleContext {
  public:
    SwitchStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Switch();
    ParenthesisContext *parenthesis();
    antlr4::tree::TerminalNode *OpenCurlyBracket();
    antlr4::tree::TerminalNode *EndSwitch();
    std::vector<SwitchBlockContext *> switchBlock();
    SwitchBlockContext* switchBlock(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  SwitchStatementContext* switchStatement();

  class  SwitchBlockContext : public antlr4::ParserRuleContext {
  public:
    SwitchBlockContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    InnerStatementListContext *innerStatementList();
    std::vector<antlr4::tree::TerminalNode *> Case();
    antlr4::tree::TerminalNode* Case(size_t i);
    std::vector<ExpressionContext *> expression();
    ExpressionContext* expression(size_t i);
    std::vector<antlr4::tree::TerminalNode *> Default();
    antlr4::tree::TerminalNode* Default(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  SwitchBlockContext* switchBlock();

  class  BreakStatementContext : public antlr4::ParserRuleContext {
  public:
    BreakStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Break();
    ExpressionContext *expression();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  BreakStatementContext* breakStatement();

  class  ContinueStatementContext : public antlr4::ParserRuleContext {
  public:
    ContinueStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Continue();
    ExpressionContext *expression();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ContinueStatementContext* continueStatement();

  class  ReturnStatementContext : public antlr4::ParserRuleContext {
  public:
    ReturnStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Return();
    ExpressionContext *expression();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ReturnStatementContext* returnStatement();

  class  ExpressionStatementContext : public antlr4::ParserRuleContext {
  public:
    ExpressionStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ExpressionContext *expression();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ExpressionStatementContext* expressionStatement();

  class  UnsetStatementContext : public antlr4::ParserRuleContext {
  public:
    UnsetStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Unset();
    ChainListContext *chainList();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  UnsetStatementContext* unsetStatement();

  class  ForeachStatementContext : public antlr4::ParserRuleContext {
  public:
    ForeachStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Foreach();
    std::vector<ChainContext *> chain();
    ChainContext* chain(size_t i);
    antlr4::tree::TerminalNode *As();
    ExpressionContext *expression();
    antlr4::tree::TerminalNode *List();
    AssignmentListContext *assignmentList();
    StatementContext *statement();
    InnerStatementListContext *innerStatementList();
    antlr4::tree::TerminalNode *EndForeach();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ForeachStatementContext* foreachStatement();

  class  TryCatchFinallyContext : public antlr4::ParserRuleContext {
  public:
    TryCatchFinallyContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Try();
    BlockStatementContext *blockStatement();
    FinallyStatementContext *finallyStatement();
    std::vector<CatchClauseContext *> catchClause();
    CatchClauseContext* catchClause(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TryCatchFinallyContext* tryCatchFinally();

  class  CatchClauseContext : public antlr4::ParserRuleContext {
  public:
    CatchClauseContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Catch();
    QualifiedStaticTypeRefContext *qualifiedStaticTypeRef();
    antlr4::tree::TerminalNode *VarName();
    BlockStatementContext *blockStatement();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  CatchClauseContext* catchClause();

  class  FinallyStatementContext : public antlr4::ParserRuleContext {
  public:
    FinallyStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Finally();
    BlockStatementContext *blockStatement();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  FinallyStatementContext* finallyStatement();

  class  ThrowStatementContext : public antlr4::ParserRuleContext {
  public:
    ThrowStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Throw();
    ExpressionContext *expression();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ThrowStatementContext* throwStatement();

  class  GotoStatementContext : public antlr4::ParserRuleContext {
  public:
    GotoStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Goto();
    IdentifierContext *identifier();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  GotoStatementContext* gotoStatement();

  class  DeclareStatementContext : public antlr4::ParserRuleContext {
  public:
    DeclareStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Declare();
    DeclareListContext *declareList();
    StatementContext *statement();
    InnerStatementListContext *innerStatementList();
    antlr4::tree::TerminalNode *EndDeclare();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  DeclareStatementContext* declareStatement();

  class  DeclareListContext : public antlr4::ParserRuleContext {
  public:
    DeclareListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<IdentifierInititalizerContext *> identifierInititalizer();
    IdentifierInititalizerContext* identifierInititalizer(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  DeclareListContext* declareList();

  class  FormalParameterListContext : public antlr4::ParserRuleContext {
  public:
    FormalParameterListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<FormalParameterContext *> formalParameter();
    FormalParameterContext* formalParameter(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  FormalParameterListContext* formalParameterList();

  class  FormalParameterContext : public antlr4::ParserRuleContext {
  public:
    FormalParameterContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AttributesContext *attributes();
    VariableInitializerContext *variableInitializer();
    TypeHintContext *typeHint();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  FormalParameterContext* formalParameter();

  class  TypeHintContext : public antlr4::ParserRuleContext {
  public:
    TypeHintContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    QualifiedStaticTypeRefContext *qualifiedStaticTypeRef();
    antlr4::tree::TerminalNode *Callable();
    PrimitiveTypeContext *primitiveType();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TypeHintContext* typeHint();

  class  GlobalStatementContext : public antlr4::ParserRuleContext {
  public:
    GlobalStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Global();
    std::vector<GlobalVarContext *> globalVar();
    GlobalVarContext* globalVar(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  GlobalStatementContext* globalStatement();

  class  GlobalVarContext : public antlr4::ParserRuleContext {
  public:
    GlobalVarContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *VarName();
    antlr4::tree::TerminalNode *Dollar();
    ChainContext *chain();
    antlr4::tree::TerminalNode *OpenCurlyBracket();
    ExpressionContext *expression();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  GlobalVarContext* globalVar();

  class  EchoStatementContext : public antlr4::ParserRuleContext {
  public:
    EchoStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Echo();
    ExpressionListContext *expressionList();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  EchoStatementContext* echoStatement();

  class  StaticVariableStatementContext : public antlr4::ParserRuleContext {
  public:
    StaticVariableStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Static();
    std::vector<VariableInitializerContext *> variableInitializer();
    VariableInitializerContext* variableInitializer(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  StaticVariableStatementContext* staticVariableStatement();

  class  ClassStatementContext : public antlr4::ParserRuleContext {
  public:
    ClassStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AttributesContext *attributes();
    PropertyModifiersContext *propertyModifiers();
    std::vector<VariableInitializerContext *> variableInitializer();
    VariableInitializerContext* variableInitializer(size_t i);
    antlr4::tree::TerminalNode *Const();
    std::vector<IdentifierInititalizerContext *> identifierInititalizer();
    IdentifierInititalizerContext* identifierInititalizer(size_t i);
    antlr4::tree::TerminalNode *Function();
    IdentifierContext *identifier();
    FormalParameterListContext *formalParameterList();
    MethodBodyContext *methodBody();
    MemberModifiersContext *memberModifiers();
    TypeParameterListInBracketsContext *typeParameterListInBrackets();
    BaseCtorCallContext *baseCtorCall();
    antlr4::tree::TerminalNode *Use();
    QualifiedNamespaceNameListContext *qualifiedNamespaceNameList();
    TraitAdaptationsContext *traitAdaptations();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ClassStatementContext* classStatement();

  class  TraitAdaptationsContext : public antlr4::ParserRuleContext {
  public:
    TraitAdaptationsContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *OpenCurlyBracket();
    std::vector<TraitAdaptationStatementContext *> traitAdaptationStatement();
    TraitAdaptationStatementContext* traitAdaptationStatement(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TraitAdaptationsContext* traitAdaptations();

  class  TraitAdaptationStatementContext : public antlr4::ParserRuleContext {
  public:
    TraitAdaptationStatementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TraitPrecedenceContext *traitPrecedence();
    TraitAliasContext *traitAlias();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TraitAdaptationStatementContext* traitAdaptationStatement();

  class  TraitPrecedenceContext : public antlr4::ParserRuleContext {
  public:
    TraitPrecedenceContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    QualifiedNamespaceNameContext *qualifiedNamespaceName();
    IdentifierContext *identifier();
    antlr4::tree::TerminalNode *InsteadOf();
    QualifiedNamespaceNameListContext *qualifiedNamespaceNameList();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TraitPrecedenceContext* traitPrecedence();

  class  TraitAliasContext : public antlr4::ParserRuleContext {
  public:
    TraitAliasContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    TraitMethodReferenceContext *traitMethodReference();
    antlr4::tree::TerminalNode *As();
    MemberModifierContext *memberModifier();
    IdentifierContext *identifier();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TraitAliasContext* traitAlias();

  class  TraitMethodReferenceContext : public antlr4::ParserRuleContext {
  public:
    TraitMethodReferenceContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    IdentifierContext *identifier();
    QualifiedNamespaceNameContext *qualifiedNamespaceName();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TraitMethodReferenceContext* traitMethodReference();

  class  BaseCtorCallContext : public antlr4::ParserRuleContext {
  public:
    BaseCtorCallContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    IdentifierContext *identifier();
    ArgumentsContext *arguments();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  BaseCtorCallContext* baseCtorCall();

  class  MethodBodyContext : public antlr4::ParserRuleContext {
  public:
    MethodBodyContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    BlockStatementContext *blockStatement();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  MethodBodyContext* methodBody();

  class  PropertyModifiersContext : public antlr4::ParserRuleContext {
  public:
    PropertyModifiersContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    MemberModifiersContext *memberModifiers();
    antlr4::tree::TerminalNode *Var();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  PropertyModifiersContext* propertyModifiers();

  class  MemberModifiersContext : public antlr4::ParserRuleContext {
  public:
    MemberModifiersContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<MemberModifierContext *> memberModifier();
    MemberModifierContext* memberModifier(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  MemberModifiersContext* memberModifiers();

  class  VariableInitializerContext : public antlr4::ParserRuleContext {
  public:
    VariableInitializerContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *VarName();
    antlr4::tree::TerminalNode *Eq();
    ConstantInititalizerContext *constantInititalizer();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  VariableInitializerContext* variableInitializer();

  class  IdentifierInititalizerContext : public antlr4::ParserRuleContext {
  public:
    IdentifierInititalizerContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    IdentifierContext *identifier();
    antlr4::tree::TerminalNode *Eq();
    ConstantInititalizerContext *constantInititalizer();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  IdentifierInititalizerContext* identifierInititalizer();

  class  GlobalConstantDeclarationContext : public antlr4::ParserRuleContext {
  public:
    GlobalConstantDeclarationContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AttributesContext *attributes();
    antlr4::tree::TerminalNode *Const();
    std::vector<IdentifierInititalizerContext *> identifierInititalizer();
    IdentifierInititalizerContext* identifierInititalizer(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  GlobalConstantDeclarationContext* globalConstantDeclaration();

  class  ExpressionListContext : public antlr4::ParserRuleContext {
  public:
    ExpressionListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<ExpressionContext *> expression();
    ExpressionContext* expression(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ExpressionListContext* expressionList();

  class  ParenthesisContext : public antlr4::ParserRuleContext {
  public:
    ParenthesisContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ExpressionContext *expression();
    YieldExpressionContext *yieldExpression();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ParenthesisContext* parenthesis();

  class  ExpressionContext : public antlr4::ParserRuleContext {
  public:
    ExpressionContext(antlr4::ParserRuleContext *parent, size_t invokingState);
   
    ExpressionContext() : antlr4::ParserRuleContext() { }
    void copyFrom(ExpressionContext *context);
    using antlr4::ParserRuleContext::copyFrom;

    virtual size_t getRuleIndex() const override;

   
  };

  class  ChainExpressionContext : public ExpressionContext {
  public:
    ChainExpressionContext(ExpressionContext *ctx);

    ChainContext *chain();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  UnaryOperatorExpressionContext : public ExpressionContext {
  public:
    UnaryOperatorExpressionContext(ExpressionContext *ctx);

    ExpressionContext *expression();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  SpecialWordExpressionContext : public ExpressionContext {
  public:
    SpecialWordExpressionContext(ExpressionContext *ctx);

    antlr4::tree::TerminalNode *Yield();
    antlr4::tree::TerminalNode *List();
    AssignmentListContext *assignmentList();
    antlr4::tree::TerminalNode *Eq();
    ExpressionContext *expression();
    antlr4::tree::TerminalNode *IsSet();
    ChainListContext *chainList();
    antlr4::tree::TerminalNode *Empty();
    ChainContext *chain();
    antlr4::tree::TerminalNode *Eval();
    antlr4::tree::TerminalNode *Exit();
    ParenthesisContext *parenthesis();
    antlr4::tree::TerminalNode *Include();
    antlr4::tree::TerminalNode *IncludeOnce();
    antlr4::tree::TerminalNode *Require();
    antlr4::tree::TerminalNode *RequireOnce();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  ArrayCreationExpressionContext : public ExpressionContext {
  public:
    ArrayCreationExpressionContext(ExpressionContext *ctx);

    antlr4::tree::TerminalNode *Array();
    ExpressionContext *expression();
    ArrayItemListContext *arrayItemList();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  NewExpressionContext : public ExpressionContext {
  public:
    NewExpressionContext(ExpressionContext *ctx);

    NewExprContext *newExpr();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  ParenthesisExpressionContext : public ExpressionContext {
  public:
    ParenthesisExpressionContext(ExpressionContext *ctx);

    ParenthesisContext *parenthesis();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  BackQuoteStringExpressionContext : public ExpressionContext {
  public:
    BackQuoteStringExpressionContext(ExpressionContext *ctx);

    antlr4::tree::TerminalNode *BackQuoteString();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  ConditionalExpressionContext : public ExpressionContext {
  public:
    ConditionalExpressionContext(ExpressionContext *ctx);

    antlr4::Token *op = nullptr;
    std::vector<ExpressionContext *> expression();
    ExpressionContext* expression(size_t i);
    antlr4::tree::TerminalNode *QuestionMark();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  ArithmeticExpressionContext : public ExpressionContext {
  public:
    ArithmeticExpressionContext(ExpressionContext *ctx);

    antlr4::Token *op = nullptr;
    std::vector<ExpressionContext *> expression();
    ExpressionContext* expression(size_t i);
    antlr4::tree::TerminalNode *Divide();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  IndexerExpressionContext : public ExpressionContext {
  public:
    IndexerExpressionContext(ExpressionContext *ctx);

    StringConstantContext *stringConstant();
    ExpressionContext *expression();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  ScalarExpressionContext : public ExpressionContext {
  public:
    ScalarExpressionContext(ExpressionContext *ctx);

    ConstantContext *constant();
    StringContext *string();
    antlr4::tree::TerminalNode *Label();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  PrefixIncDecExpressionContext : public ExpressionContext {
  public:
    PrefixIncDecExpressionContext(ExpressionContext *ctx);

    ChainContext *chain();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  ComparisonExpressionContext : public ExpressionContext {
  public:
    ComparisonExpressionContext(ExpressionContext *ctx);

    antlr4::Token *op = nullptr;
    std::vector<ExpressionContext *> expression();
    ExpressionContext* expression(size_t i);
    antlr4::tree::TerminalNode *Less();
    antlr4::tree::TerminalNode *Greater();
    antlr4::tree::TerminalNode *IsNotEq();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  LogicalExpressionContext : public ExpressionContext {
  public:
    LogicalExpressionContext(ExpressionContext *ctx);

    antlr4::Token *op = nullptr;
    std::vector<ExpressionContext *> expression();
    ExpressionContext* expression(size_t i);
    antlr4::tree::TerminalNode *LogicalAnd();
    antlr4::tree::TerminalNode *LogicalXor();
    antlr4::tree::TerminalNode *LogicalOr();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  PrintExpressionContext : public ExpressionContext {
  public:
    PrintExpressionContext(ExpressionContext *ctx);

    antlr4::tree::TerminalNode *Print();
    ExpressionContext *expression();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  AssignmentExpressionContext : public ExpressionContext {
  public:
    AssignmentExpressionContext(ExpressionContext *ctx);

    std::vector<ChainContext *> chain();
    ChainContext* chain(size_t i);
    AssignmentOperatorContext *assignmentOperator();
    ExpressionContext *expression();
    antlr4::tree::TerminalNode *Eq();
    NewExprContext *newExpr();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  PostfixIncDecExpressionContext : public ExpressionContext {
  public:
    PostfixIncDecExpressionContext(ExpressionContext *ctx);

    ChainContext *chain();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  CastExpressionContext : public ExpressionContext {
  public:
    CastExpressionContext(ExpressionContext *ctx);

    CastOperationContext *castOperation();
    ExpressionContext *expression();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  InstanceOfExpressionContext : public ExpressionContext {
  public:
    InstanceOfExpressionContext(ExpressionContext *ctx);

    ExpressionContext *expression();
    antlr4::tree::TerminalNode *InstanceOf();
    TypeRefContext *typeRef();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  LambdaFunctionExpressionContext : public ExpressionContext {
  public:
    LambdaFunctionExpressionContext(ExpressionContext *ctx);

    antlr4::tree::TerminalNode *Function();
    FormalParameterListContext *formalParameterList();
    BlockStatementContext *blockStatement();
    antlr4::tree::TerminalNode *Static();
    LambdaFunctionUseVarsContext *lambdaFunctionUseVars();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  BitwiseExpressionContext : public ExpressionContext {
  public:
    BitwiseExpressionContext(ExpressionContext *ctx);

    antlr4::Token *op = nullptr;
    std::vector<ExpressionContext *> expression();
    ExpressionContext* expression(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  CloneExpressionContext : public ExpressionContext {
  public:
    CloneExpressionContext(ExpressionContext *ctx);

    antlr4::tree::TerminalNode *Clone();
    ExpressionContext *expression();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  ExpressionContext* expression();
  ExpressionContext* expression(int precedence);
  class  NewExprContext : public antlr4::ParserRuleContext {
  public:
    NewExprContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *New();
    TypeRefContext *typeRef();
    ArgumentsContext *arguments();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  NewExprContext* newExpr();

  class  AssignmentOperatorContext : public antlr4::ParserRuleContext {
  public:
    AssignmentOperatorContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Eq();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  AssignmentOperatorContext* assignmentOperator();

  class  YieldExpressionContext : public antlr4::ParserRuleContext {
  public:
    YieldExpressionContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Yield();
    std::vector<ExpressionContext *> expression();
    ExpressionContext* expression(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  YieldExpressionContext* yieldExpression();

  class  ArrayItemListContext : public antlr4::ParserRuleContext {
  public:
    ArrayItemListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<ArrayItemContext *> arrayItem();
    ArrayItemContext* arrayItem(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ArrayItemListContext* arrayItemList();

  class  ArrayItemContext : public antlr4::ParserRuleContext {
  public:
    ArrayItemContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<ExpressionContext *> expression();
    ExpressionContext* expression(size_t i);
    ChainContext *chain();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ArrayItemContext* arrayItem();

  class  LambdaFunctionUseVarsContext : public antlr4::ParserRuleContext {
  public:
    LambdaFunctionUseVarsContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Use();
    std::vector<LambdaFunctionUseVarContext *> lambdaFunctionUseVar();
    LambdaFunctionUseVarContext* lambdaFunctionUseVar(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  LambdaFunctionUseVarsContext* lambdaFunctionUseVars();

  class  LambdaFunctionUseVarContext : public antlr4::ParserRuleContext {
  public:
    LambdaFunctionUseVarContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *VarName();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  LambdaFunctionUseVarContext* lambdaFunctionUseVar();

  class  QualifiedStaticTypeRefContext : public antlr4::ParserRuleContext {
  public:
    QualifiedStaticTypeRefContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    QualifiedNamespaceNameContext *qualifiedNamespaceName();
    GenericDynamicArgsContext *genericDynamicArgs();
    antlr4::tree::TerminalNode *Static();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  QualifiedStaticTypeRefContext* qualifiedStaticTypeRef();

  class  TypeRefContext : public antlr4::ParserRuleContext {
  public:
    TypeRefContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    QualifiedNamespaceNameContext *qualifiedNamespaceName();
    IndirectTypeRefContext *indirectTypeRef();
    GenericDynamicArgsContext *genericDynamicArgs();
    PrimitiveTypeContext *primitiveType();
    antlr4::tree::TerminalNode *Static();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TypeRefContext* typeRef();

  class  IndirectTypeRefContext : public antlr4::ParserRuleContext {
  public:
    IndirectTypeRefContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ChainBaseContext *chainBase();
    std::vector<KeyedFieldNameContext *> keyedFieldName();
    KeyedFieldNameContext* keyedFieldName(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  IndirectTypeRefContext* indirectTypeRef();

  class  QualifiedNamespaceNameContext : public antlr4::ParserRuleContext {
  public:
    QualifiedNamespaceNameContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    NamespaceNameListContext *namespaceNameList();
    antlr4::tree::TerminalNode *Namespace();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  QualifiedNamespaceNameContext* qualifiedNamespaceName();

  class  NamespaceNameListContext : public antlr4::ParserRuleContext {
  public:
    NamespaceNameListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<IdentifierContext *> identifier();
    IdentifierContext* identifier(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  NamespaceNameListContext* namespaceNameList();

  class  QualifiedNamespaceNameListContext : public antlr4::ParserRuleContext {
  public:
    QualifiedNamespaceNameListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<QualifiedNamespaceNameContext *> qualifiedNamespaceName();
    QualifiedNamespaceNameContext* qualifiedNamespaceName(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  QualifiedNamespaceNameListContext* qualifiedNamespaceNameList();

  class  ArgumentsContext : public antlr4::ParserRuleContext {
  public:
    ArgumentsContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<ActualArgumentContext *> actualArgument();
    ActualArgumentContext* actualArgument(size_t i);
    YieldExpressionContext *yieldExpression();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ArgumentsContext* arguments();

  class  ActualArgumentContext : public antlr4::ParserRuleContext {
  public:
    ActualArgumentContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ExpressionContext *expression();
    ChainContext *chain();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ActualArgumentContext* actualArgument();

  class  ConstantInititalizerContext : public antlr4::ParserRuleContext {
  public:
    ConstantInititalizerContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ConstantContext *constant();
    StringContext *string();
    antlr4::tree::TerminalNode *Array();
    ConstantArrayItemListContext *constantArrayItemList();
    ConstantInititalizerContext *constantInititalizer();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ConstantInititalizerContext* constantInititalizer();

  class  ConstantArrayItemListContext : public antlr4::ParserRuleContext {
  public:
    ConstantArrayItemListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<ConstantArrayItemContext *> constantArrayItem();
    ConstantArrayItemContext* constantArrayItem(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ConstantArrayItemListContext* constantArrayItemList();

  class  ConstantArrayItemContext : public antlr4::ParserRuleContext {
  public:
    ConstantArrayItemContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<ConstantInititalizerContext *> constantInititalizer();
    ConstantInititalizerContext* constantInititalizer(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ConstantArrayItemContext* constantArrayItem();

  class  ConstantContext : public antlr4::ParserRuleContext {
  public:
    ConstantContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Null();
    LiteralConstantContext *literalConstant();
    MagicConstantContext *magicConstant();
    ClassConstantContext *classConstant();
    QualifiedNamespaceNameContext *qualifiedNamespaceName();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ConstantContext* constant();

  class  LiteralConstantContext : public antlr4::ParserRuleContext {
  public:
    LiteralConstantContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Real();
    antlr4::tree::TerminalNode *BooleanConstant();
    NumericConstantContext *numericConstant();
    StringConstantContext *stringConstant();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  LiteralConstantContext* literalConstant();

  class  NumericConstantContext : public antlr4::ParserRuleContext {
  public:
    NumericConstantContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Octal();
    antlr4::tree::TerminalNode *Decimal();
    antlr4::tree::TerminalNode *Hex();
    antlr4::tree::TerminalNode *Binary();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  NumericConstantContext* numericConstant();

  class  ClassConstantContext : public antlr4::ParserRuleContext {
  public:
    ClassConstantContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Class();
    antlr4::tree::TerminalNode *Parent_();
    IdentifierContext *identifier();
    antlr4::tree::TerminalNode *Constructor();
    antlr4::tree::TerminalNode *Get();
    antlr4::tree::TerminalNode *Set();
    QualifiedStaticTypeRefContext *qualifiedStaticTypeRef();
    KeyedVariableContext *keyedVariable();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ClassConstantContext* classConstant();

  class  StringConstantContext : public antlr4::ParserRuleContext {
  public:
    StringConstantContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Label();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  StringConstantContext* stringConstant();

  class  StringContext : public antlr4::ParserRuleContext {
  public:
    StringContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *StartHereDoc();
    std::vector<antlr4::tree::TerminalNode *> HereDocText();
    antlr4::tree::TerminalNode* HereDocText(size_t i);
    antlr4::tree::TerminalNode *StartNowDoc();
    antlr4::tree::TerminalNode *SingleQuoteString();
    std::vector<antlr4::tree::TerminalNode *> DoubleQuote();
    antlr4::tree::TerminalNode* DoubleQuote(size_t i);
    std::vector<InterpolatedStringPartContext *> interpolatedStringPart();
    InterpolatedStringPartContext* interpolatedStringPart(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  StringContext* string();

  class  InterpolatedStringPartContext : public antlr4::ParserRuleContext {
  public:
    InterpolatedStringPartContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *StringPart();
    ChainContext *chain();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  InterpolatedStringPartContext* interpolatedStringPart();

  class  ChainListContext : public antlr4::ParserRuleContext {
  public:
    ChainListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<ChainContext *> chain();
    ChainContext* chain(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ChainListContext* chainList();

  class  ChainContext : public antlr4::ParserRuleContext {
  public:
    ChainContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ChainBaseContext *chainBase();
    FunctionCallContext *functionCall();
    NewExprContext *newExpr();
    std::vector<MemberAccessContext *> memberAccess();
    MemberAccessContext* memberAccess(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ChainContext* chain();

  class  MemberAccessContext : public antlr4::ParserRuleContext {
  public:
    MemberAccessContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    KeyedFieldNameContext *keyedFieldName();
    ActualArgumentsContext *actualArguments();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  MemberAccessContext* memberAccess();

  class  FunctionCallContext : public antlr4::ParserRuleContext {
  public:
    FunctionCallContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    FunctionCallNameContext *functionCallName();
    ActualArgumentsContext *actualArguments();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  FunctionCallContext* functionCall();

  class  FunctionCallNameContext : public antlr4::ParserRuleContext {
  public:
    FunctionCallNameContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    QualifiedNamespaceNameContext *qualifiedNamespaceName();
    ClassConstantContext *classConstant();
    ChainBaseContext *chainBase();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  FunctionCallNameContext* functionCallName();

  class  ActualArgumentsContext : public antlr4::ParserRuleContext {
  public:
    ActualArgumentsContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ArgumentsContext *arguments();
    GenericDynamicArgsContext *genericDynamicArgs();
    std::vector<SquareCurlyExpressionContext *> squareCurlyExpression();
    SquareCurlyExpressionContext* squareCurlyExpression(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ActualArgumentsContext* actualArguments();

  class  ChainBaseContext : public antlr4::ParserRuleContext {
  public:
    ChainBaseContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<KeyedVariableContext *> keyedVariable();
    KeyedVariableContext* keyedVariable(size_t i);
    QualifiedStaticTypeRefContext *qualifiedStaticTypeRef();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ChainBaseContext* chainBase();

  class  KeyedFieldNameContext : public antlr4::ParserRuleContext {
  public:
    KeyedFieldNameContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    KeyedSimpleFieldNameContext *keyedSimpleFieldName();
    KeyedVariableContext *keyedVariable();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  KeyedFieldNameContext* keyedFieldName();

  class  KeyedSimpleFieldNameContext : public antlr4::ParserRuleContext {
  public:
    KeyedSimpleFieldNameContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    IdentifierContext *identifier();
    antlr4::tree::TerminalNode *OpenCurlyBracket();
    ExpressionContext *expression();
    std::vector<SquareCurlyExpressionContext *> squareCurlyExpression();
    SquareCurlyExpressionContext* squareCurlyExpression(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  KeyedSimpleFieldNameContext* keyedSimpleFieldName();

  class  KeyedVariableContext : public antlr4::ParserRuleContext {
  public:
    KeyedVariableContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *VarName();
    std::vector<antlr4::tree::TerminalNode *> Dollar();
    antlr4::tree::TerminalNode* Dollar(size_t i);
    antlr4::tree::TerminalNode *OpenCurlyBracket();
    ExpressionContext *expression();
    std::vector<SquareCurlyExpressionContext *> squareCurlyExpression();
    SquareCurlyExpressionContext* squareCurlyExpression(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  KeyedVariableContext* keyedVariable();

  class  SquareCurlyExpressionContext : public antlr4::ParserRuleContext {
  public:
    SquareCurlyExpressionContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ExpressionContext *expression();
    antlr4::tree::TerminalNode *OpenCurlyBracket();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  SquareCurlyExpressionContext* squareCurlyExpression();

  class  AssignmentListContext : public antlr4::ParserRuleContext {
  public:
    AssignmentListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<AssignmentListElementContext *> assignmentListElement();
    AssignmentListElementContext* assignmentListElement(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  AssignmentListContext* assignmentList();

  class  AssignmentListElementContext : public antlr4::ParserRuleContext {
  public:
    AssignmentListElementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ChainContext *chain();
    antlr4::tree::TerminalNode *List();
    AssignmentListContext *assignmentList();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  AssignmentListElementContext* assignmentListElement();

  class  ModifierContext : public antlr4::ParserRuleContext {
  public:
    ModifierContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Abstract();
    antlr4::tree::TerminalNode *Final();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ModifierContext* modifier();

  class  IdentifierContext : public antlr4::ParserRuleContext {
  public:
    IdentifierContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Label();
    antlr4::tree::TerminalNode *Abstract();
    antlr4::tree::TerminalNode *Array();
    antlr4::tree::TerminalNode *As();
    antlr4::tree::TerminalNode *BinaryCast();
    antlr4::tree::TerminalNode *BoolType();
    antlr4::tree::TerminalNode *BooleanConstant();
    antlr4::tree::TerminalNode *Break();
    antlr4::tree::TerminalNode *Callable();
    antlr4::tree::TerminalNode *Case();
    antlr4::tree::TerminalNode *Catch();
    antlr4::tree::TerminalNode *Class();
    antlr4::tree::TerminalNode *Clone();
    antlr4::tree::TerminalNode *Const();
    antlr4::tree::TerminalNode *Continue();
    antlr4::tree::TerminalNode *Declare();
    antlr4::tree::TerminalNode *Default();
    antlr4::tree::TerminalNode *Do();
    antlr4::tree::TerminalNode *DoubleCast();
    antlr4::tree::TerminalNode *DoubleType();
    antlr4::tree::TerminalNode *Echo();
    antlr4::tree::TerminalNode *Else();
    antlr4::tree::TerminalNode *ElseIf();
    antlr4::tree::TerminalNode *Empty();
    antlr4::tree::TerminalNode *EndDeclare();
    antlr4::tree::TerminalNode *EndFor();
    antlr4::tree::TerminalNode *EndForeach();
    antlr4::tree::TerminalNode *EndIf();
    antlr4::tree::TerminalNode *EndSwitch();
    antlr4::tree::TerminalNode *EndWhile();
    antlr4::tree::TerminalNode *Eval();
    antlr4::tree::TerminalNode *Exit();
    antlr4::tree::TerminalNode *Extends();
    antlr4::tree::TerminalNode *Final();
    antlr4::tree::TerminalNode *Finally();
    antlr4::tree::TerminalNode *FloatCast();
    antlr4::tree::TerminalNode *For();
    antlr4::tree::TerminalNode *Foreach();
    antlr4::tree::TerminalNode *Function();
    antlr4::tree::TerminalNode *Global();
    antlr4::tree::TerminalNode *Goto();
    antlr4::tree::TerminalNode *If();
    antlr4::tree::TerminalNode *Implements();
    antlr4::tree::TerminalNode *Import();
    antlr4::tree::TerminalNode *Include();
    antlr4::tree::TerminalNode *IncludeOnce();
    antlr4::tree::TerminalNode *InstanceOf();
    antlr4::tree::TerminalNode *InsteadOf();
    antlr4::tree::TerminalNode *Int16Cast();
    antlr4::tree::TerminalNode *Int64Type();
    antlr4::tree::TerminalNode *Int8Cast();
    antlr4::tree::TerminalNode *Interface();
    antlr4::tree::TerminalNode *IntType();
    antlr4::tree::TerminalNode *IsSet();
    antlr4::tree::TerminalNode *List();
    antlr4::tree::TerminalNode *LogicalAnd();
    antlr4::tree::TerminalNode *LogicalOr();
    antlr4::tree::TerminalNode *LogicalXor();
    antlr4::tree::TerminalNode *Namespace();
    antlr4::tree::TerminalNode *New();
    antlr4::tree::TerminalNode *Null();
    antlr4::tree::TerminalNode *ObjectType();
    antlr4::tree::TerminalNode *Parent_();
    antlr4::tree::TerminalNode *Partial();
    antlr4::tree::TerminalNode *Print();
    antlr4::tree::TerminalNode *Private();
    antlr4::tree::TerminalNode *Protected();
    antlr4::tree::TerminalNode *Public();
    antlr4::tree::TerminalNode *Require();
    antlr4::tree::TerminalNode *RequireOnce();
    antlr4::tree::TerminalNode *Resource();
    antlr4::tree::TerminalNode *Return();
    antlr4::tree::TerminalNode *Static();
    antlr4::tree::TerminalNode *StringType();
    antlr4::tree::TerminalNode *Switch();
    antlr4::tree::TerminalNode *Throw();
    antlr4::tree::TerminalNode *Trait();
    antlr4::tree::TerminalNode *Try();
    antlr4::tree::TerminalNode *Typeof();
    antlr4::tree::TerminalNode *UintCast();
    antlr4::tree::TerminalNode *UnicodeCast();
    antlr4::tree::TerminalNode *Unset();
    antlr4::tree::TerminalNode *Use();
    antlr4::tree::TerminalNode *Var();
    antlr4::tree::TerminalNode *While();
    antlr4::tree::TerminalNode *Yield();
    antlr4::tree::TerminalNode *Get();
    antlr4::tree::TerminalNode *Set();
    antlr4::tree::TerminalNode *Call();
    antlr4::tree::TerminalNode *CallStatic();
    antlr4::tree::TerminalNode *Constructor();
    antlr4::tree::TerminalNode *Destruct();
    antlr4::tree::TerminalNode *Wakeup();
    antlr4::tree::TerminalNode *Sleep();
    antlr4::tree::TerminalNode *Autoload();
    antlr4::tree::TerminalNode *IsSet__();
    antlr4::tree::TerminalNode *Unset__();
    antlr4::tree::TerminalNode *ToString__();
    antlr4::tree::TerminalNode *Invoke();
    antlr4::tree::TerminalNode *SetState();
    antlr4::tree::TerminalNode *Clone__();
    antlr4::tree::TerminalNode *DebugInfo();
    antlr4::tree::TerminalNode *Namespace__();
    antlr4::tree::TerminalNode *Class__();
    antlr4::tree::TerminalNode *Traic__();
    antlr4::tree::TerminalNode *Function__();
    antlr4::tree::TerminalNode *Method__();
    antlr4::tree::TerminalNode *Line__();
    antlr4::tree::TerminalNode *File__();
    antlr4::tree::TerminalNode *Dir__();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  IdentifierContext* identifier();

  class  MemberModifierContext : public antlr4::ParserRuleContext {
  public:
    MemberModifierContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Public();
    antlr4::tree::TerminalNode *Protected();
    antlr4::tree::TerminalNode *Private();
    antlr4::tree::TerminalNode *Static();
    antlr4::tree::TerminalNode *Abstract();
    antlr4::tree::TerminalNode *Final();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  MemberModifierContext* memberModifier();

  class  MagicConstantContext : public antlr4::ParserRuleContext {
  public:
    MagicConstantContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Namespace__();
    antlr4::tree::TerminalNode *Class__();
    antlr4::tree::TerminalNode *Traic__();
    antlr4::tree::TerminalNode *Function__();
    antlr4::tree::TerminalNode *Method__();
    antlr4::tree::TerminalNode *Line__();
    antlr4::tree::TerminalNode *File__();
    antlr4::tree::TerminalNode *Dir__();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  MagicConstantContext* magicConstant();

  class  MagicMethodContext : public antlr4::ParserRuleContext {
  public:
    MagicMethodContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Get();
    antlr4::tree::TerminalNode *Set();
    antlr4::tree::TerminalNode *Call();
    antlr4::tree::TerminalNode *CallStatic();
    antlr4::tree::TerminalNode *Constructor();
    antlr4::tree::TerminalNode *Destruct();
    antlr4::tree::TerminalNode *Wakeup();
    antlr4::tree::TerminalNode *Sleep();
    antlr4::tree::TerminalNode *Autoload();
    antlr4::tree::TerminalNode *IsSet__();
    antlr4::tree::TerminalNode *Unset__();
    antlr4::tree::TerminalNode *ToString__();
    antlr4::tree::TerminalNode *Invoke();
    antlr4::tree::TerminalNode *SetState();
    antlr4::tree::TerminalNode *Clone__();
    antlr4::tree::TerminalNode *DebugInfo();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  MagicMethodContext* magicMethod();

  class  PrimitiveTypeContext : public antlr4::ParserRuleContext {
  public:
    PrimitiveTypeContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *BoolType();
    antlr4::tree::TerminalNode *IntType();
    antlr4::tree::TerminalNode *Int64Type();
    antlr4::tree::TerminalNode *DoubleType();
    antlr4::tree::TerminalNode *StringType();
    antlr4::tree::TerminalNode *Resource();
    antlr4::tree::TerminalNode *ObjectType();
    antlr4::tree::TerminalNode *Array();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  PrimitiveTypeContext* primitiveType();

  class  CastOperationContext : public antlr4::ParserRuleContext {
  public:
    CastOperationContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *BoolType();
    antlr4::tree::TerminalNode *Int8Cast();
    antlr4::tree::TerminalNode *Int16Cast();
    antlr4::tree::TerminalNode *IntType();
    antlr4::tree::TerminalNode *Int64Type();
    antlr4::tree::TerminalNode *UintCast();
    antlr4::tree::TerminalNode *DoubleCast();
    antlr4::tree::TerminalNode *DoubleType();
    antlr4::tree::TerminalNode *FloatCast();
    antlr4::tree::TerminalNode *StringType();
    antlr4::tree::TerminalNode *BinaryCast();
    antlr4::tree::TerminalNode *UnicodeCast();
    antlr4::tree::TerminalNode *Array();
    antlr4::tree::TerminalNode *ObjectType();
    antlr4::tree::TerminalNode *Resource();
    antlr4::tree::TerminalNode *Unset();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  CastOperationContext* castOperation();


  virtual bool sempred(antlr4::RuleContext *_localctx, size_t ruleIndex, size_t predicateIndex) override;
  bool expressionSempred(ExpressionContext *_localctx, size_t predicateIndex);

private:
  static std::vector<antlr4::dfa::DFA> _decisionToDFA;
  static antlr4::atn::PredictionContextCache _sharedContextCache;
  static std::vector<std::string> _ruleNames;
  static std::vector<std::string> _tokenNames;

  static std::vector<std::string> _literalNames;
  static std::vector<std::string> _symbolicNames;
  static antlr4::dfa::Vocabulary _vocabulary;
  static antlr4::atn::ATN _atn;
  static std::vector<uint16_t> _serializedATN;


  struct Initializer {
    Initializer();
  };
  static Initializer _init;
};

