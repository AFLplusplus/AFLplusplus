
// Generated from C:\Users\xiang\Desktop\vbs_parser\VisualBasic6.g4 by ANTLR 4.7

#pragma once


#include "antlr4-runtime.h"




class  VisualBasic6Parser : public antlr4::Parser {
public:
  enum {
    ACCESS = 1, ADDRESSOF = 2, ALIAS = 3, AND = 4, ATTRIBUTE = 5, APPACTIVATE = 6, 
    APPEND = 7, AS = 8, BEEP = 9, BEGIN = 10, BEGINPROPERTY = 11, BINARY = 12, 
    BOOLEAN = 13, BYVAL = 14, BYREF = 15, BYTE = 16, CALL = 17, CASE = 18, 
    CHDIR = 19, CHDRIVE = 20, CLASS = 21, CLOSE = 22, COLLECTION = 23, CONST = 24, 
    DATE = 25, DECLARE = 26, DEFBOOL = 27, DEFBYTE = 28, DEFDATE = 29, DEFDBL = 30, 
    DEFDEC = 31, DEFCUR = 32, DEFINT = 33, DEFLNG = 34, DEFOBJ = 35, DEFSNG = 36, 
    DEFSTR = 37, DEFVAR = 38, DELETESETTING = 39, DIM = 40, DO = 41, DOUBLE = 42, 
    EACH = 43, ELSE = 44, ELSEIF = 45, END_ENUM = 46, END_FUNCTION = 47, 
    END_IF = 48, END_PROPERTY = 49, END_SELECT = 50, END_SUB = 51, END_TYPE = 52, 
    END_WITH = 53, END = 54, ENDPROPERTY = 55, ENUM = 56, EQV = 57, ERASE = 58, 
    ERROR = 59, EVENT = 60, EXIT_DO = 61, EXIT_FOR = 62, EXIT_FUNCTION = 63, 
    EXIT_PROPERTY = 64, EXIT_SUB = 65, FALSE1 = 66, FILECOPY = 67, FRIEND = 68, 
    FOR = 69, FUNCTION = 70, GET = 71, GLOBAL = 72, GOSUB = 73, GOTO = 74, 
    IF = 75, IMP = 76, IMPLEMENTS = 77, IN = 78, INPUT = 79, IS = 80, INTEGER = 81, 
    KILL = 82, LOAD = 83, LOCK = 84, LONG = 85, LOOP = 86, LEN = 87, LET = 88, 
    LIB = 89, LIKE = 90, LINE_INPUT = 91, LOCK_READ = 92, LOCK_WRITE = 93, 
    LOCK_READ_WRITE = 94, LSET = 95, MACRO_IF = 96, MACRO_ELSEIF = 97, MACRO_ELSE = 98, 
    MACRO_END_IF = 99, ME = 100, MID = 101, MKDIR = 102, MOD = 103, NAME = 104, 
    NEXT = 105, NEW = 106, NOT = 107, NOTHING = 108, NULL1 = 109, OBJECT = 110, 
    ON = 111, ON_ERROR = 112, ON_LOCAL_ERROR = 113, OPEN = 114, OPTIONAL = 115, 
    OPTION_BASE = 116, OPTION_EXPLICIT = 117, OPTION_COMPARE = 118, OPTION_PRIVATE_MODULE = 119, 
    OR = 120, OUTPUT = 121, PARAMARRAY = 122, PRESERVE = 123, PRINT = 124, 
    PRIVATE = 125, PROPERTY_GET = 126, PROPERTY_LET = 127, PROPERTY_SET = 128, 
    PUBLIC = 129, PUT = 130, RANDOM = 131, RANDOMIZE = 132, RAISEEVENT = 133, 
    READ = 134, READ_WRITE = 135, REDIM = 136, REM = 137, RESET = 138, RESUME = 139, 
    RETURN = 140, RMDIR = 141, RSET = 142, SAVEPICTURE = 143, SAVESETTING = 144, 
    SEEK = 145, SELECT = 146, SENDKEYS = 147, SET = 148, SETATTR = 149, 
    SHARED = 150, SINGLE = 151, SPC = 152, STATIC = 153, STEP = 154, STOP = 155, 
    STRING = 156, SUB = 157, TAB = 158, TEXT = 159, THEN = 160, TIME = 161, 
    TO = 162, TRUE1 = 163, TYPE = 164, TYPEOF = 165, UNLOAD = 166, UNLOCK = 167, 
    UNTIL = 168, VARIANT = 169, VERSION = 170, WEND = 171, WHILE = 172, 
    WIDTH = 173, WITH = 174, WITHEVENTS = 175, WRITE = 176, XOR = 177, AMPERSAND = 178, 
    ASSIGN = 179, AT = 180, COLON = 181, COMMA = 182, DIV = 183, DOLLAR = 184, 
    DOT = 185, EQ = 186, EXCLAMATIONMARK = 187, GEQ = 188, GT = 189, HASH = 190, 
    LEQ = 191, LBRACE = 192, LPAREN = 193, LT = 194, MINUS = 195, MINUS_EQ = 196, 
    MULT = 197, NEQ = 198, PERCENT = 199, PLUS = 200, PLUS_EQ = 201, POW = 202, 
    RBRACE = 203, RPAREN = 204, SEMICOLON = 205, L_SQUARE_BRACKET = 206, 
    R_SQUARE_BRACKET = 207, STRINGLITERAL = 208, DATELITERAL = 209, COLORLITERAL = 210, 
    INTEGERLITERAL = 211, DOUBLELITERAL = 212, FILENUMBER = 213, OCTALLITERAL = 214, 
    FRX_OFFSET = 215, GUID = 216, IDENTIFIER = 217, LINE_CONTINUATION = 218, 
    NEWLINE = 219, COMMENT = 220, WS = 221
  };

  enum {
    RuleStartRule = 0, RuleModule = 1, RuleModuleReferences = 2, RuleModuleReference = 3, 
    RuleModuleReferenceValue = 4, RuleModuleReferenceComponent = 5, RuleModuleHeader = 6, 
    RuleModuleConfig = 7, RuleModuleConfigElement = 8, RuleModuleAttributes = 9, 
    RuleModuleOptions = 10, RuleModuleOption = 11, RuleModuleBody = 12, 
    RuleModuleBodyElement = 13, RuleControlProperties = 14, RuleCp_Properties = 15, 
    RuleCp_SingleProperty = 16, RuleCp_PropertyName = 17, RuleCp_PropertyValue = 18, 
    RuleCp_NestedProperty = 19, RuleCp_ControlType = 20, RuleCp_ControlIdentifier = 21, 
    RuleModuleBlock = 22, RuleAttributeStmt = 23, RuleBlock = 24, RuleBlockStmt = 25, 
    RuleAppActivateStmt = 26, RuleBeepStmt = 27, RuleChDirStmt = 28, RuleChDriveStmt = 29, 
    RuleCloseStmt = 30, RuleConstStmt = 31, RuleConstSubStmt = 32, RuleDateStmt = 33, 
    RuleDeclareStmt = 34, RuleDeftypeStmt = 35, RuleDeleteSettingStmt = 36, 
    RuleDoLoopStmt = 37, RuleEndStmt = 38, RuleEnumerationStmt = 39, RuleEnumerationStmt_Constant = 40, 
    RuleEraseStmt = 41, RuleErrorStmt = 42, RuleEventStmt = 43, RuleExitStmt = 44, 
    RuleFilecopyStmt = 45, RuleForEachStmt = 46, RuleForNextStmt = 47, RuleFunctionStmt = 48, 
    RuleGetStmt = 49, RuleGoSubStmt = 50, RuleGoToStmt = 51, RuleIfThenElseStmt = 52, 
    RuleIfBlockStmt = 53, RuleIfConditionStmt = 54, RuleIfElseIfBlockStmt = 55, 
    RuleIfElseBlockStmt = 56, RuleImplementsStmt = 57, RuleInputStmt = 58, 
    RuleKillStmt = 59, RuleLetStmt = 60, RuleLineInputStmt = 61, RuleLoadStmt = 62, 
    RuleLockStmt = 63, RuleLsetStmt = 64, RuleMacroIfThenElseStmt = 65, 
    RuleMacroIfBlockStmt = 66, RuleMacroElseIfBlockStmt = 67, RuleMacroElseBlockStmt = 68, 
    RuleMidStmt = 69, RuleMkdirStmt = 70, RuleNameStmt = 71, RuleOnErrorStmt = 72, 
    RuleOnGoToStmt = 73, RuleOnGoSubStmt = 74, RuleOpenStmt = 75, RuleOutputList = 76, 
    RuleOutputList_Expression = 77, RulePrintStmt = 78, RulePropertyGetStmt = 79, 
    RulePropertySetStmt = 80, RulePropertyLetStmt = 81, RulePutStmt = 82, 
    RuleRaiseEventStmt = 83, RuleRandomizeStmt = 84, RuleRedimStmt = 85, 
    RuleRedimSubStmt = 86, RuleResetStmt = 87, RuleResumeStmt = 88, RuleReturnStmt = 89, 
    RuleRmdirStmt = 90, RuleRsetStmt = 91, RuleSavepictureStmt = 92, RuleSaveSettingStmt = 93, 
    RuleSeekStmt = 94, RuleSelectCaseStmt = 95, RuleSC_Case = 96, RuleSC_Cond = 97, 
    RuleSC_CondExpr = 98, RuleSendkeysStmt = 99, RuleSetattrStmt = 100, 
    RuleSetStmt = 101, RuleStopStmt = 102, RuleSubStmt = 103, RuleTimeStmt = 104, 
    RuleTypeStmt = 105, RuleTypeStmt_Element = 106, RuleTypeOfStmt = 107, 
    RuleUnloadStmt = 108, RuleUnlockStmt = 109, RuleValueStmt = 110, RuleVariableStmt = 111, 
    RuleVariableListStmt = 112, RuleVariableSubStmt = 113, RuleWhileWendStmt = 114, 
    RuleWidthStmt = 115, RuleWithStmt = 116, RuleWriteStmt = 117, RuleExplicitCallStmt = 118, 
    RuleECS_ProcedureCall = 119, RuleECS_MemberProcedureCall = 120, RuleImplicitCallStmt_InBlock = 121, 
    RuleICS_B_ProcedureCall = 122, RuleICS_B_MemberProcedureCall = 123, 
    RuleImplicitCallStmt_InStmt = 124, RuleICS_S_VariableOrProcedureCall = 125, 
    RuleICS_S_ProcedureOrArrayCall = 126, RuleICS_S_NestedProcedureCall = 127, 
    RuleICS_S_MembersCall = 128, RuleICS_S_MemberCall = 129, RuleICS_S_DictionaryCall = 130, 
    RuleArgsCall = 131, RuleArgCall = 132, RuleDictionaryCallStmt = 133, 
    RuleArgList = 134, RuleArg = 135, RuleArgDefaultValue = 136, RuleSubscripts = 137, 
    RuleSubscript = 138, RuleAmbiguousIdentifier = 139, RuleAsTypeClause = 140, 
    RuleBaseType = 141, RuleCertainIdentifier = 142, RuleComparisonOperator = 143, 
    RuleComplexType = 144, RuleFieldLength = 145, RuleLetterrange = 146, 
    RuleLineLabel = 147, RuleLiteral = 148, RulePublicPrivateVisibility = 149, 
    RulePublicPrivateGlobalVisibility = 150, RuleType = 151, RuleTypeHint = 152, 
    RuleVisibility = 153, RuleAmbiguousKeyword = 154
  };

  VisualBasic6Parser(antlr4::TokenStream *input);
  ~VisualBasic6Parser();

  virtual std::string getGrammarFileName() const override;
  virtual const antlr4::atn::ATN& getATN() const override { return _atn; };
  virtual const std::vector<std::string>& getTokenNames() const override { return _tokenNames; }; // deprecated: use vocabulary instead.
  virtual const std::vector<std::string>& getRuleNames() const override;
  virtual antlr4::dfa::Vocabulary& getVocabulary() const override;


  class StartRuleContext;
  class ModuleContext;
  class ModuleReferencesContext;
  class ModuleReferenceContext;
  class ModuleReferenceValueContext;
  class ModuleReferenceComponentContext;
  class ModuleHeaderContext;
  class ModuleConfigContext;
  class ModuleConfigElementContext;
  class ModuleAttributesContext;
  class ModuleOptionsContext;
  class ModuleOptionContext;
  class ModuleBodyContext;
  class ModuleBodyElementContext;
  class ControlPropertiesContext;
  class Cp_PropertiesContext;
  class Cp_SinglePropertyContext;
  class Cp_PropertyNameContext;
  class Cp_PropertyValueContext;
  class Cp_NestedPropertyContext;
  class Cp_ControlTypeContext;
  class Cp_ControlIdentifierContext;
  class ModuleBlockContext;
  class AttributeStmtContext;
  class BlockContext;
  class BlockStmtContext;
  class AppActivateStmtContext;
  class BeepStmtContext;
  class ChDirStmtContext;
  class ChDriveStmtContext;
  class CloseStmtContext;
  class ConstStmtContext;
  class ConstSubStmtContext;
  class DateStmtContext;
  class DeclareStmtContext;
  class DeftypeStmtContext;
  class DeleteSettingStmtContext;
  class DoLoopStmtContext;
  class EndStmtContext;
  class EnumerationStmtContext;
  class EnumerationStmt_ConstantContext;
  class EraseStmtContext;
  class ErrorStmtContext;
  class EventStmtContext;
  class ExitStmtContext;
  class FilecopyStmtContext;
  class ForEachStmtContext;
  class ForNextStmtContext;
  class FunctionStmtContext;
  class GetStmtContext;
  class GoSubStmtContext;
  class GoToStmtContext;
  class IfThenElseStmtContext;
  class IfBlockStmtContext;
  class IfConditionStmtContext;
  class IfElseIfBlockStmtContext;
  class IfElseBlockStmtContext;
  class ImplementsStmtContext;
  class InputStmtContext;
  class KillStmtContext;
  class LetStmtContext;
  class LineInputStmtContext;
  class LoadStmtContext;
  class LockStmtContext;
  class LsetStmtContext;
  class MacroIfThenElseStmtContext;
  class MacroIfBlockStmtContext;
  class MacroElseIfBlockStmtContext;
  class MacroElseBlockStmtContext;
  class MidStmtContext;
  class MkdirStmtContext;
  class NameStmtContext;
  class OnErrorStmtContext;
  class OnGoToStmtContext;
  class OnGoSubStmtContext;
  class OpenStmtContext;
  class OutputListContext;
  class OutputList_ExpressionContext;
  class PrintStmtContext;
  class PropertyGetStmtContext;
  class PropertySetStmtContext;
  class PropertyLetStmtContext;
  class PutStmtContext;
  class RaiseEventStmtContext;
  class RandomizeStmtContext;
  class RedimStmtContext;
  class RedimSubStmtContext;
  class ResetStmtContext;
  class ResumeStmtContext;
  class ReturnStmtContext;
  class RmdirStmtContext;
  class RsetStmtContext;
  class SavepictureStmtContext;
  class SaveSettingStmtContext;
  class SeekStmtContext;
  class SelectCaseStmtContext;
  class SC_CaseContext;
  class SC_CondContext;
  class SC_CondExprContext;
  class SendkeysStmtContext;
  class SetattrStmtContext;
  class SetStmtContext;
  class StopStmtContext;
  class SubStmtContext;
  class TimeStmtContext;
  class TypeStmtContext;
  class TypeStmt_ElementContext;
  class TypeOfStmtContext;
  class UnloadStmtContext;
  class UnlockStmtContext;
  class ValueStmtContext;
  class VariableStmtContext;
  class VariableListStmtContext;
  class VariableSubStmtContext;
  class WhileWendStmtContext;
  class WidthStmtContext;
  class WithStmtContext;
  class WriteStmtContext;
  class ExplicitCallStmtContext;
  class ECS_ProcedureCallContext;
  class ECS_MemberProcedureCallContext;
  class ImplicitCallStmt_InBlockContext;
  class ICS_B_ProcedureCallContext;
  class ICS_B_MemberProcedureCallContext;
  class ImplicitCallStmt_InStmtContext;
  class ICS_S_VariableOrProcedureCallContext;
  class ICS_S_ProcedureOrArrayCallContext;
  class ICS_S_NestedProcedureCallContext;
  class ICS_S_MembersCallContext;
  class ICS_S_MemberCallContext;
  class ICS_S_DictionaryCallContext;
  class ArgsCallContext;
  class ArgCallContext;
  class DictionaryCallStmtContext;
  class ArgListContext;
  class ArgContext;
  class ArgDefaultValueContext;
  class SubscriptsContext;
  class SubscriptContext;
  class AmbiguousIdentifierContext;
  class AsTypeClauseContext;
  class BaseTypeContext;
  class CertainIdentifierContext;
  class ComparisonOperatorContext;
  class ComplexTypeContext;
  class FieldLengthContext;
  class LetterrangeContext;
  class LineLabelContext;
  class LiteralContext;
  class PublicPrivateVisibilityContext;
  class PublicPrivateGlobalVisibilityContext;
  class TypeContext;
  class TypeHintContext;
  class VisibilityContext;
  class AmbiguousKeywordContext; 

  class  StartRuleContext : public antlr4::ParserRuleContext {
  public:
    StartRuleContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ModuleContext *module();
    antlr4::tree::TerminalNode *EOF();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  StartRuleContext* startRule();

  class  ModuleContext : public antlr4::ParserRuleContext {
  public:
    ModuleContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    ModuleHeaderContext *moduleHeader();
    ModuleReferencesContext *moduleReferences();
    ControlPropertiesContext *controlProperties();
    ModuleConfigContext *moduleConfig();
    ModuleAttributesContext *moduleAttributes();
    ModuleOptionsContext *moduleOptions();
    ModuleBodyContext *moduleBody();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ModuleContext* module();

  class  ModuleReferencesContext : public antlr4::ParserRuleContext {
  public:
    ModuleReferencesContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<ModuleReferenceContext *> moduleReference();
    ModuleReferenceContext* moduleReference(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ModuleReferencesContext* moduleReferences();

  class  ModuleReferenceContext : public antlr4::ParserRuleContext {
  public:
    ModuleReferenceContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *OBJECT();
    antlr4::tree::TerminalNode *EQ();
    ModuleReferenceValueContext *moduleReferenceValue();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    antlr4::tree::TerminalNode *SEMICOLON();
    ModuleReferenceComponentContext *moduleReferenceComponent();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ModuleReferenceContext* moduleReference();

  class  ModuleReferenceValueContext : public antlr4::ParserRuleContext {
  public:
    ModuleReferenceValueContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *STRINGLITERAL();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ModuleReferenceValueContext* moduleReferenceValue();

  class  ModuleReferenceComponentContext : public antlr4::ParserRuleContext {
  public:
    ModuleReferenceComponentContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *STRINGLITERAL();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ModuleReferenceComponentContext* moduleReferenceComponent();

  class  ModuleHeaderContext : public antlr4::ParserRuleContext {
  public:
    ModuleHeaderContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *VERSION();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    antlr4::tree::TerminalNode *DOUBLELITERAL();
    antlr4::tree::TerminalNode *CLASS();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ModuleHeaderContext* moduleHeader();

  class  ModuleConfigContext : public antlr4::ParserRuleContext {
  public:
    ModuleConfigContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *BEGIN();
    antlr4::tree::TerminalNode *END();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    std::vector<ModuleConfigElementContext *> moduleConfigElement();
    ModuleConfigElementContext* moduleConfigElement(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ModuleConfigContext* moduleConfig();

  class  ModuleConfigElementContext : public antlr4::ParserRuleContext {
  public:
    ModuleConfigElementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *EQ();
    LiteralContext *literal();
    antlr4::tree::TerminalNode *NEWLINE();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ModuleConfigElementContext* moduleConfigElement();

  class  ModuleAttributesContext : public antlr4::ParserRuleContext {
  public:
    ModuleAttributesContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<AttributeStmtContext *> attributeStmt();
    AttributeStmtContext* attributeStmt(size_t i);
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ModuleAttributesContext* moduleAttributes();

  class  ModuleOptionsContext : public antlr4::ParserRuleContext {
  public:
    ModuleOptionsContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<ModuleOptionContext *> moduleOption();
    ModuleOptionContext* moduleOption(size_t i);
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ModuleOptionsContext* moduleOptions();

  class  ModuleOptionContext : public antlr4::ParserRuleContext {
  public:
    ModuleOptionContext(antlr4::ParserRuleContext *parent, size_t invokingState);
   
    ModuleOptionContext() : antlr4::ParserRuleContext() { }
    void copyFrom(ModuleOptionContext *context);
    using antlr4::ParserRuleContext::copyFrom;

    virtual size_t getRuleIndex() const override;

   
  };

  class  OptionExplicitStmtContext : public ModuleOptionContext {
  public:
    OptionExplicitStmtContext(ModuleOptionContext *ctx);

    antlr4::tree::TerminalNode *OPTION_EXPLICIT();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  OptionBaseStmtContext : public ModuleOptionContext {
  public:
    OptionBaseStmtContext(ModuleOptionContext *ctx);

    antlr4::tree::TerminalNode *OPTION_BASE();
    antlr4::tree::TerminalNode *WS();
    antlr4::tree::TerminalNode *INTEGERLITERAL();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  OptionPrivateModuleStmtContext : public ModuleOptionContext {
  public:
    OptionPrivateModuleStmtContext(ModuleOptionContext *ctx);

    antlr4::tree::TerminalNode *OPTION_PRIVATE_MODULE();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  OptionCompareStmtContext : public ModuleOptionContext {
  public:
    OptionCompareStmtContext(ModuleOptionContext *ctx);

    antlr4::tree::TerminalNode *OPTION_COMPARE();
    antlr4::tree::TerminalNode *WS();
    antlr4::tree::TerminalNode *BINARY();
    antlr4::tree::TerminalNode *TEXT();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  ModuleOptionContext* moduleOption();

  class  ModuleBodyContext : public antlr4::ParserRuleContext {
  public:
    ModuleBodyContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<ModuleBodyElementContext *> moduleBodyElement();
    ModuleBodyElementContext* moduleBodyElement(size_t i);
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ModuleBodyContext* moduleBody();

  class  ModuleBodyElementContext : public antlr4::ParserRuleContext {
  public:
    ModuleBodyElementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ModuleBlockContext *moduleBlock();
    ModuleOptionContext *moduleOption();
    DeclareStmtContext *declareStmt();
    EnumerationStmtContext *enumerationStmt();
    EventStmtContext *eventStmt();
    FunctionStmtContext *functionStmt();
    MacroIfThenElseStmtContext *macroIfThenElseStmt();
    PropertyGetStmtContext *propertyGetStmt();
    PropertySetStmtContext *propertySetStmt();
    PropertyLetStmtContext *propertyLetStmt();
    SubStmtContext *subStmt();
    TypeStmtContext *typeStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ModuleBodyElementContext* moduleBodyElement();

  class  ControlPropertiesContext : public antlr4::ParserRuleContext {
  public:
    ControlPropertiesContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *BEGIN();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    Cp_ControlTypeContext *cp_ControlType();
    Cp_ControlIdentifierContext *cp_ControlIdentifier();
    antlr4::tree::TerminalNode *END();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    std::vector<Cp_PropertiesContext *> cp_Properties();
    Cp_PropertiesContext* cp_Properties(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ControlPropertiesContext* controlProperties();

  class  Cp_PropertiesContext : public antlr4::ParserRuleContext {
  public:
    Cp_PropertiesContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    Cp_SinglePropertyContext *cp_SingleProperty();
    Cp_NestedPropertyContext *cp_NestedProperty();
    ControlPropertiesContext *controlProperties();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  Cp_PropertiesContext* cp_Properties();

  class  Cp_SinglePropertyContext : public antlr4::ParserRuleContext {
  public:
    Cp_SinglePropertyContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ImplicitCallStmt_InStmtContext *implicitCallStmt_InStmt();
    antlr4::tree::TerminalNode *EQ();
    Cp_PropertyValueContext *cp_PropertyValue();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    antlr4::tree::TerminalNode *FRX_OFFSET();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  Cp_SinglePropertyContext* cp_SingleProperty();

  class  Cp_PropertyNameContext : public antlr4::ParserRuleContext {
  public:
    Cp_PropertyNameContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<AmbiguousIdentifierContext *> ambiguousIdentifier();
    AmbiguousIdentifierContext* ambiguousIdentifier(size_t i);
    antlr4::tree::TerminalNode *OBJECT();
    std::vector<antlr4::tree::TerminalNode *> DOT();
    antlr4::tree::TerminalNode* DOT(size_t i);
    std::vector<antlr4::tree::TerminalNode *> LPAREN();
    antlr4::tree::TerminalNode* LPAREN(size_t i);
    std::vector<LiteralContext *> literal();
    LiteralContext* literal(size_t i);
    std::vector<antlr4::tree::TerminalNode *> RPAREN();
    antlr4::tree::TerminalNode* RPAREN(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  Cp_PropertyNameContext* cp_PropertyName();

  class  Cp_PropertyValueContext : public antlr4::ParserRuleContext {
  public:
    Cp_PropertyValueContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    LiteralContext *literal();
    antlr4::tree::TerminalNode *POW();
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *DOLLAR();
    antlr4::tree::TerminalNode *LBRACE();
    antlr4::tree::TerminalNode *RBRACE();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  Cp_PropertyValueContext* cp_PropertyValue();

  class  Cp_NestedPropertyContext : public antlr4::ParserRuleContext {
  public:
    Cp_NestedPropertyContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *BEGINPROPERTY();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *ENDPROPERTY();
    antlr4::tree::TerminalNode *LPAREN();
    antlr4::tree::TerminalNode *INTEGERLITERAL();
    antlr4::tree::TerminalNode *RPAREN();
    antlr4::tree::TerminalNode *GUID();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    std::vector<Cp_PropertiesContext *> cp_Properties();
    Cp_PropertiesContext* cp_Properties(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  Cp_NestedPropertyContext* cp_NestedProperty();

  class  Cp_ControlTypeContext : public antlr4::ParserRuleContext {
  public:
    Cp_ControlTypeContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ComplexTypeContext *complexType();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  Cp_ControlTypeContext* cp_ControlType();

  class  Cp_ControlIdentifierContext : public antlr4::ParserRuleContext {
  public:
    Cp_ControlIdentifierContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AmbiguousIdentifierContext *ambiguousIdentifier();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  Cp_ControlIdentifierContext* cp_ControlIdentifier();

  class  ModuleBlockContext : public antlr4::ParserRuleContext {
  public:
    ModuleBlockContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    BlockContext *block();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ModuleBlockContext* moduleBlock();

  class  AttributeStmtContext : public antlr4::ParserRuleContext {
  public:
    AttributeStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ATTRIBUTE();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    ImplicitCallStmt_InStmtContext *implicitCallStmt_InStmt();
    antlr4::tree::TerminalNode *EQ();
    std::vector<LiteralContext *> literal();
    LiteralContext* literal(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  AttributeStmtContext* attributeStmt();

  class  BlockContext : public antlr4::ParserRuleContext {
  public:
    BlockContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<BlockStmtContext *> blockStmt();
    BlockStmtContext* blockStmt(size_t i);
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  BlockContext* block();

  class  BlockStmtContext : public antlr4::ParserRuleContext {
  public:
    BlockStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AppActivateStmtContext *appActivateStmt();
    AttributeStmtContext *attributeStmt();
    BeepStmtContext *beepStmt();
    ChDirStmtContext *chDirStmt();
    ChDriveStmtContext *chDriveStmt();
    CloseStmtContext *closeStmt();
    ConstStmtContext *constStmt();
    DateStmtContext *dateStmt();
    DeleteSettingStmtContext *deleteSettingStmt();
    DeftypeStmtContext *deftypeStmt();
    DoLoopStmtContext *doLoopStmt();
    EndStmtContext *endStmt();
    EraseStmtContext *eraseStmt();
    ErrorStmtContext *errorStmt();
    ExitStmtContext *exitStmt();
    ExplicitCallStmtContext *explicitCallStmt();
    FilecopyStmtContext *filecopyStmt();
    ForEachStmtContext *forEachStmt();
    ForNextStmtContext *forNextStmt();
    GetStmtContext *getStmt();
    GoSubStmtContext *goSubStmt();
    GoToStmtContext *goToStmt();
    IfThenElseStmtContext *ifThenElseStmt();
    ImplementsStmtContext *implementsStmt();
    InputStmtContext *inputStmt();
    KillStmtContext *killStmt();
    LetStmtContext *letStmt();
    LineInputStmtContext *lineInputStmt();
    LineLabelContext *lineLabel();
    LoadStmtContext *loadStmt();
    LockStmtContext *lockStmt();
    LsetStmtContext *lsetStmt();
    MacroIfThenElseStmtContext *macroIfThenElseStmt();
    MidStmtContext *midStmt();
    MkdirStmtContext *mkdirStmt();
    NameStmtContext *nameStmt();
    OnErrorStmtContext *onErrorStmt();
    OnGoToStmtContext *onGoToStmt();
    OnGoSubStmtContext *onGoSubStmt();
    OpenStmtContext *openStmt();
    PrintStmtContext *printStmt();
    PutStmtContext *putStmt();
    RaiseEventStmtContext *raiseEventStmt();
    RandomizeStmtContext *randomizeStmt();
    RedimStmtContext *redimStmt();
    ResetStmtContext *resetStmt();
    ResumeStmtContext *resumeStmt();
    ReturnStmtContext *returnStmt();
    RmdirStmtContext *rmdirStmt();
    RsetStmtContext *rsetStmt();
    SavepictureStmtContext *savepictureStmt();
    SaveSettingStmtContext *saveSettingStmt();
    SeekStmtContext *seekStmt();
    SelectCaseStmtContext *selectCaseStmt();
    SendkeysStmtContext *sendkeysStmt();
    SetattrStmtContext *setattrStmt();
    SetStmtContext *setStmt();
    StopStmtContext *stopStmt();
    TimeStmtContext *timeStmt();
    UnloadStmtContext *unloadStmt();
    UnlockStmtContext *unlockStmt();
    VariableStmtContext *variableStmt();
    WhileWendStmtContext *whileWendStmt();
    WidthStmtContext *widthStmt();
    WithStmtContext *withStmt();
    WriteStmtContext *writeStmt();
    ImplicitCallStmt_InBlockContext *implicitCallStmt_InBlock();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  BlockStmtContext* blockStmt();

  class  AppActivateStmtContext : public antlr4::ParserRuleContext {
  public:
    AppActivateStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *APPACTIVATE();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *COMMA();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  AppActivateStmtContext* appActivateStmt();

  class  BeepStmtContext : public antlr4::ParserRuleContext {
  public:
    BeepStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *BEEP();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  BeepStmtContext* beepStmt();

  class  ChDirStmtContext : public antlr4::ParserRuleContext {
  public:
    ChDirStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *CHDIR();
    antlr4::tree::TerminalNode *WS();
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ChDirStmtContext* chDirStmt();

  class  ChDriveStmtContext : public antlr4::ParserRuleContext {
  public:
    ChDriveStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *CHDRIVE();
    antlr4::tree::TerminalNode *WS();
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ChDriveStmtContext* chDriveStmt();

  class  CloseStmtContext : public antlr4::ParserRuleContext {
  public:
    CloseStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *CLOSE();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  CloseStmtContext* closeStmt();

  class  ConstStmtContext : public antlr4::ParserRuleContext {
  public:
    ConstStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *CONST();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ConstSubStmtContext *> constSubStmt();
    ConstSubStmtContext* constSubStmt(size_t i);
    PublicPrivateGlobalVisibilityContext *publicPrivateGlobalVisibility();
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ConstStmtContext* constStmt();

  class  ConstSubStmtContext : public antlr4::ParserRuleContext {
  public:
    ConstSubStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *EQ();
    ValueStmtContext *valueStmt();
    TypeHintContext *typeHint();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AsTypeClauseContext *asTypeClause();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ConstSubStmtContext* constSubStmt();

  class  DateStmtContext : public antlr4::ParserRuleContext {
  public:
    DateStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *DATE();
    antlr4::tree::TerminalNode *EQ();
    ValueStmtContext *valueStmt();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  DateStmtContext* dateStmt();

  class  DeclareStmtContext : public antlr4::ParserRuleContext {
  public:
    DeclareStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *DECLARE();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *LIB();
    std::vector<antlr4::tree::TerminalNode *> STRINGLITERAL();
    antlr4::tree::TerminalNode* STRINGLITERAL(size_t i);
    antlr4::tree::TerminalNode *FUNCTION();
    antlr4::tree::TerminalNode *SUB();
    VisibilityContext *visibility();
    std::vector<TypeHintContext *> typeHint();
    TypeHintContext* typeHint(size_t i);
    antlr4::tree::TerminalNode *ALIAS();
    ArgListContext *argList();
    AsTypeClauseContext *asTypeClause();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  DeclareStmtContext* declareStmt();

  class  DeftypeStmtContext : public antlr4::ParserRuleContext {
  public:
    DeftypeStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<LetterrangeContext *> letterrange();
    LetterrangeContext* letterrange(size_t i);
    antlr4::tree::TerminalNode *DEFBOOL();
    antlr4::tree::TerminalNode *DEFBYTE();
    antlr4::tree::TerminalNode *DEFINT();
    antlr4::tree::TerminalNode *DEFLNG();
    antlr4::tree::TerminalNode *DEFCUR();
    antlr4::tree::TerminalNode *DEFSNG();
    antlr4::tree::TerminalNode *DEFDBL();
    antlr4::tree::TerminalNode *DEFDEC();
    antlr4::tree::TerminalNode *DEFDATE();
    antlr4::tree::TerminalNode *DEFSTR();
    antlr4::tree::TerminalNode *DEFOBJ();
    antlr4::tree::TerminalNode *DEFVAR();
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  DeftypeStmtContext* deftypeStmt();

  class  DeleteSettingStmtContext : public antlr4::ParserRuleContext {
  public:
    DeleteSettingStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *DELETESETTING();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  DeleteSettingStmtContext* deleteSettingStmt();

  class  DoLoopStmtContext : public antlr4::ParserRuleContext {
  public:
    DoLoopStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *DO();
    antlr4::tree::TerminalNode *LOOP();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    BlockContext *block();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    ValueStmtContext *valueStmt();
    antlr4::tree::TerminalNode *WHILE();
    antlr4::tree::TerminalNode *UNTIL();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  DoLoopStmtContext* doLoopStmt();

  class  EndStmtContext : public antlr4::ParserRuleContext {
  public:
    EndStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *END();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  EndStmtContext* endStmt();

  class  EnumerationStmtContext : public antlr4::ParserRuleContext {
  public:
    EnumerationStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ENUM();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *END_ENUM();
    PublicPrivateVisibilityContext *publicPrivateVisibility();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    std::vector<EnumerationStmt_ConstantContext *> enumerationStmt_Constant();
    EnumerationStmt_ConstantContext* enumerationStmt_Constant(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  EnumerationStmtContext* enumerationStmt();

  class  EnumerationStmt_ConstantContext : public antlr4::ParserRuleContext {
  public:
    EnumerationStmt_ConstantContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *EQ();
    ValueStmtContext *valueStmt();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  EnumerationStmt_ConstantContext* enumerationStmt_Constant();

  class  EraseStmtContext : public antlr4::ParserRuleContext {
  public:
    EraseStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ERASE();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  EraseStmtContext* eraseStmt();

  class  ErrorStmtContext : public antlr4::ParserRuleContext {
  public:
    ErrorStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ERROR();
    antlr4::tree::TerminalNode *WS();
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ErrorStmtContext* errorStmt();

  class  EventStmtContext : public antlr4::ParserRuleContext {
  public:
    EventStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *EVENT();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AmbiguousIdentifierContext *ambiguousIdentifier();
    ArgListContext *argList();
    VisibilityContext *visibility();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  EventStmtContext* eventStmt();

  class  ExitStmtContext : public antlr4::ParserRuleContext {
  public:
    ExitStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *EXIT_DO();
    antlr4::tree::TerminalNode *EXIT_FOR();
    antlr4::tree::TerminalNode *EXIT_FUNCTION();
    antlr4::tree::TerminalNode *EXIT_PROPERTY();
    antlr4::tree::TerminalNode *EXIT_SUB();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ExitStmtContext* exitStmt();

  class  FilecopyStmtContext : public antlr4::ParserRuleContext {
  public:
    FilecopyStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *FILECOPY();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *COMMA();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  FilecopyStmtContext* filecopyStmt();

  class  ForEachStmtContext : public antlr4::ParserRuleContext {
  public:
    ForEachStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *FOR();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    antlr4::tree::TerminalNode *EACH();
    std::vector<AmbiguousIdentifierContext *> ambiguousIdentifier();
    AmbiguousIdentifierContext* ambiguousIdentifier(size_t i);
    antlr4::tree::TerminalNode *IN();
    ValueStmtContext *valueStmt();
    antlr4::tree::TerminalNode *NEXT();
    TypeHintContext *typeHint();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    BlockContext *block();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ForEachStmtContext* forEachStmt();

  class  ForNextStmtContext : public antlr4::ParserRuleContext {
  public:
    ForNextStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *FOR();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    ICS_S_VariableOrProcedureCallContext *iCS_S_VariableOrProcedureCall();
    antlr4::tree::TerminalNode *EQ();
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *TO();
    antlr4::tree::TerminalNode *NEXT();
    std::vector<TypeHintContext *> typeHint();
    TypeHintContext* typeHint(size_t i);
    AsTypeClauseContext *asTypeClause();
    antlr4::tree::TerminalNode *STEP();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    BlockContext *block();
    AmbiguousIdentifierContext *ambiguousIdentifier();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ForNextStmtContext* forNextStmt();

  class  FunctionStmtContext : public antlr4::ParserRuleContext {
  public:
    FunctionStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *FUNCTION();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *END_FUNCTION();
    VisibilityContext *visibility();
    antlr4::tree::TerminalNode *STATIC();
    ArgListContext *argList();
    AsTypeClauseContext *asTypeClause();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    BlockContext *block();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  FunctionStmtContext* functionStmt();

  class  GetStmtContext : public antlr4::ParserRuleContext {
  public:
    GetStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *GET();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  GetStmtContext* getStmt();

  class  GoSubStmtContext : public antlr4::ParserRuleContext {
  public:
    GoSubStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *GOSUB();
    antlr4::tree::TerminalNode *WS();
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  GoSubStmtContext* goSubStmt();

  class  GoToStmtContext : public antlr4::ParserRuleContext {
  public:
    GoToStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *GOTO();
    antlr4::tree::TerminalNode *WS();
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  GoToStmtContext* goToStmt();

  class  IfThenElseStmtContext : public antlr4::ParserRuleContext {
  public:
    IfThenElseStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
   
    IfThenElseStmtContext() : antlr4::ParserRuleContext() { }
    void copyFrom(IfThenElseStmtContext *context);
    using antlr4::ParserRuleContext::copyFrom;

    virtual size_t getRuleIndex() const override;

   
  };

  class  BlockIfThenElseContext : public IfThenElseStmtContext {
  public:
    BlockIfThenElseContext(IfThenElseStmtContext *ctx);

    IfBlockStmtContext *ifBlockStmt();
    antlr4::tree::TerminalNode *END_IF();
    std::vector<IfElseIfBlockStmtContext *> ifElseIfBlockStmt();
    IfElseIfBlockStmtContext* ifElseIfBlockStmt(size_t i);
    IfElseBlockStmtContext *ifElseBlockStmt();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  InlineIfThenElseContext : public IfThenElseStmtContext {
  public:
    InlineIfThenElseContext(IfThenElseStmtContext *ctx);

    antlr4::tree::TerminalNode *IF();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    IfConditionStmtContext *ifConditionStmt();
    antlr4::tree::TerminalNode *THEN();
    std::vector<BlockStmtContext *> blockStmt();
    BlockStmtContext* blockStmt(size_t i);
    antlr4::tree::TerminalNode *ELSE();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  IfThenElseStmtContext* ifThenElseStmt();

  class  IfBlockStmtContext : public antlr4::ParserRuleContext {
  public:
    IfBlockStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *IF();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    IfConditionStmtContext *ifConditionStmt();
    antlr4::tree::TerminalNode *THEN();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    BlockContext *block();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  IfBlockStmtContext* ifBlockStmt();

  class  IfConditionStmtContext : public antlr4::ParserRuleContext {
  public:
    IfConditionStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  IfConditionStmtContext* ifConditionStmt();

  class  IfElseIfBlockStmtContext : public antlr4::ParserRuleContext {
  public:
    IfElseIfBlockStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ELSEIF();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    IfConditionStmtContext *ifConditionStmt();
    antlr4::tree::TerminalNode *THEN();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    BlockContext *block();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  IfElseIfBlockStmtContext* ifElseIfBlockStmt();

  class  IfElseBlockStmtContext : public antlr4::ParserRuleContext {
  public:
    IfElseBlockStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ELSE();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    BlockContext *block();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  IfElseBlockStmtContext* ifElseBlockStmt();

  class  ImplementsStmtContext : public antlr4::ParserRuleContext {
  public:
    ImplementsStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *IMPLEMENTS();
    antlr4::tree::TerminalNode *WS();
    AmbiguousIdentifierContext *ambiguousIdentifier();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ImplementsStmtContext* implementsStmt();

  class  InputStmtContext : public antlr4::ParserRuleContext {
  public:
    InputStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *INPUT();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  InputStmtContext* inputStmt();

  class  KillStmtContext : public antlr4::ParserRuleContext {
  public:
    KillStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *KILL();
    antlr4::tree::TerminalNode *WS();
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  KillStmtContext* killStmt();

  class  LetStmtContext : public antlr4::ParserRuleContext {
  public:
    LetStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ImplicitCallStmt_InStmtContext *implicitCallStmt_InStmt();
    ValueStmtContext *valueStmt();
    antlr4::tree::TerminalNode *EQ();
    antlr4::tree::TerminalNode *PLUS_EQ();
    antlr4::tree::TerminalNode *MINUS_EQ();
    antlr4::tree::TerminalNode *LET();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  LetStmtContext* letStmt();

  class  LineInputStmtContext : public antlr4::ParserRuleContext {
  public:
    LineInputStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *LINE_INPUT();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *COMMA();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  LineInputStmtContext* lineInputStmt();

  class  LoadStmtContext : public antlr4::ParserRuleContext {
  public:
    LoadStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *LOAD();
    antlr4::tree::TerminalNode *WS();
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  LoadStmtContext* loadStmt();

  class  LockStmtContext : public antlr4::ParserRuleContext {
  public:
    LockStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *LOCK();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *COMMA();
    antlr4::tree::TerminalNode *TO();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  LockStmtContext* lockStmt();

  class  LsetStmtContext : public antlr4::ParserRuleContext {
  public:
    LsetStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *LSET();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    ImplicitCallStmt_InStmtContext *implicitCallStmt_InStmt();
    antlr4::tree::TerminalNode *EQ();
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  LsetStmtContext* lsetStmt();

  class  MacroIfThenElseStmtContext : public antlr4::ParserRuleContext {
  public:
    MacroIfThenElseStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    MacroIfBlockStmtContext *macroIfBlockStmt();
    antlr4::tree::TerminalNode *MACRO_END_IF();
    std::vector<MacroElseIfBlockStmtContext *> macroElseIfBlockStmt();
    MacroElseIfBlockStmtContext* macroElseIfBlockStmt(size_t i);
    MacroElseBlockStmtContext *macroElseBlockStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  MacroIfThenElseStmtContext* macroIfThenElseStmt();

  class  MacroIfBlockStmtContext : public antlr4::ParserRuleContext {
  public:
    MacroIfBlockStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *MACRO_IF();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    IfConditionStmtContext *ifConditionStmt();
    antlr4::tree::TerminalNode *THEN();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    ModuleBodyContext *moduleBody();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  MacroIfBlockStmtContext* macroIfBlockStmt();

  class  MacroElseIfBlockStmtContext : public antlr4::ParserRuleContext {
  public:
    MacroElseIfBlockStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *MACRO_ELSEIF();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    IfConditionStmtContext *ifConditionStmt();
    antlr4::tree::TerminalNode *THEN();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    ModuleBodyContext *moduleBody();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  MacroElseIfBlockStmtContext* macroElseIfBlockStmt();

  class  MacroElseBlockStmtContext : public antlr4::ParserRuleContext {
  public:
    MacroElseBlockStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *MACRO_ELSE();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    ModuleBodyContext *moduleBody();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  MacroElseBlockStmtContext* macroElseBlockStmt();

  class  MidStmtContext : public antlr4::ParserRuleContext {
  public:
    MidStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *MID();
    antlr4::tree::TerminalNode *LPAREN();
    ArgsCallContext *argsCall();
    antlr4::tree::TerminalNode *RPAREN();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  MidStmtContext* midStmt();

  class  MkdirStmtContext : public antlr4::ParserRuleContext {
  public:
    MkdirStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *MKDIR();
    antlr4::tree::TerminalNode *WS();
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  MkdirStmtContext* mkdirStmt();

  class  NameStmtContext : public antlr4::ParserRuleContext {
  public:
    NameStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *NAME();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *AS();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  NameStmtContext* nameStmt();

  class  OnErrorStmtContext : public antlr4::ParserRuleContext {
  public:
    OnErrorStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    antlr4::tree::TerminalNode *ON_ERROR();
    antlr4::tree::TerminalNode *ON_LOCAL_ERROR();
    antlr4::tree::TerminalNode *GOTO();
    ValueStmtContext *valueStmt();
    antlr4::tree::TerminalNode *RESUME();
    antlr4::tree::TerminalNode *NEXT();
    antlr4::tree::TerminalNode *COLON();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  OnErrorStmtContext* onErrorStmt();

  class  OnGoToStmtContext : public antlr4::ParserRuleContext {
  public:
    OnGoToStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ON();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *GOTO();
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  OnGoToStmtContext* onGoToStmt();

  class  OnGoSubStmtContext : public antlr4::ParserRuleContext {
  public:
    OnGoSubStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ON();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *GOSUB();
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  OnGoSubStmtContext* onGoSubStmt();

  class  OpenStmtContext : public antlr4::ParserRuleContext {
  public:
    OpenStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *OPEN();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *FOR();
    antlr4::tree::TerminalNode *AS();
    antlr4::tree::TerminalNode *APPEND();
    antlr4::tree::TerminalNode *BINARY();
    antlr4::tree::TerminalNode *INPUT();
    antlr4::tree::TerminalNode *OUTPUT();
    antlr4::tree::TerminalNode *RANDOM();
    antlr4::tree::TerminalNode *ACCESS();
    antlr4::tree::TerminalNode *LEN();
    antlr4::tree::TerminalNode *EQ();
    antlr4::tree::TerminalNode *READ();
    antlr4::tree::TerminalNode *WRITE();
    antlr4::tree::TerminalNode *READ_WRITE();
    antlr4::tree::TerminalNode *SHARED();
    antlr4::tree::TerminalNode *LOCK_READ();
    antlr4::tree::TerminalNode *LOCK_WRITE();
    antlr4::tree::TerminalNode *LOCK_READ_WRITE();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  OpenStmtContext* openStmt();

  class  OutputListContext : public antlr4::ParserRuleContext {
  public:
    OutputListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<OutputList_ExpressionContext *> outputList_Expression();
    OutputList_ExpressionContext* outputList_Expression(size_t i);
    std::vector<antlr4::tree::TerminalNode *> SEMICOLON();
    antlr4::tree::TerminalNode* SEMICOLON(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  OutputListContext* outputList();

  class  OutputList_ExpressionContext : public antlr4::ParserRuleContext {
  public:
    OutputList_ExpressionContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *SPC();
    antlr4::tree::TerminalNode *TAB();
    antlr4::tree::TerminalNode *LPAREN();
    ArgsCallContext *argsCall();
    antlr4::tree::TerminalNode *RPAREN();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  OutputList_ExpressionContext* outputList_Expression();

  class  PrintStmtContext : public antlr4::ParserRuleContext {
  public:
    PrintStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *PRINT();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    ValueStmtContext *valueStmt();
    antlr4::tree::TerminalNode *COMMA();
    OutputListContext *outputList();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  PrintStmtContext* printStmt();

  class  PropertyGetStmtContext : public antlr4::ParserRuleContext {
  public:
    PropertyGetStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *PROPERTY_GET();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *END_PROPERTY();
    VisibilityContext *visibility();
    antlr4::tree::TerminalNode *STATIC();
    TypeHintContext *typeHint();
    ArgListContext *argList();
    AsTypeClauseContext *asTypeClause();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    BlockContext *block();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  PropertyGetStmtContext* propertyGetStmt();

  class  PropertySetStmtContext : public antlr4::ParserRuleContext {
  public:
    PropertySetStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *PROPERTY_SET();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *END_PROPERTY();
    VisibilityContext *visibility();
    antlr4::tree::TerminalNode *STATIC();
    ArgListContext *argList();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    BlockContext *block();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  PropertySetStmtContext* propertySetStmt();

  class  PropertyLetStmtContext : public antlr4::ParserRuleContext {
  public:
    PropertyLetStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *PROPERTY_LET();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *END_PROPERTY();
    VisibilityContext *visibility();
    antlr4::tree::TerminalNode *STATIC();
    ArgListContext *argList();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    BlockContext *block();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  PropertyLetStmtContext* propertyLetStmt();

  class  PutStmtContext : public antlr4::ParserRuleContext {
  public:
    PutStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *PUT();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  PutStmtContext* putStmt();

  class  RaiseEventStmtContext : public antlr4::ParserRuleContext {
  public:
    RaiseEventStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *RAISEEVENT();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *LPAREN();
    antlr4::tree::TerminalNode *RPAREN();
    ArgsCallContext *argsCall();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  RaiseEventStmtContext* raiseEventStmt();

  class  RandomizeStmtContext : public antlr4::ParserRuleContext {
  public:
    RandomizeStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *RANDOMIZE();
    antlr4::tree::TerminalNode *WS();
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  RandomizeStmtContext* randomizeStmt();

  class  RedimStmtContext : public antlr4::ParserRuleContext {
  public:
    RedimStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *REDIM();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<RedimSubStmtContext *> redimSubStmt();
    RedimSubStmtContext* redimSubStmt(size_t i);
    antlr4::tree::TerminalNode *PRESERVE();
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  RedimStmtContext* redimStmt();

  class  RedimSubStmtContext : public antlr4::ParserRuleContext {
  public:
    RedimSubStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ImplicitCallStmt_InStmtContext *implicitCallStmt_InStmt();
    antlr4::tree::TerminalNode *LPAREN();
    SubscriptsContext *subscripts();
    antlr4::tree::TerminalNode *RPAREN();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AsTypeClauseContext *asTypeClause();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  RedimSubStmtContext* redimSubStmt();

  class  ResetStmtContext : public antlr4::ParserRuleContext {
  public:
    ResetStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *RESET();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ResetStmtContext* resetStmt();

  class  ResumeStmtContext : public antlr4::ParserRuleContext {
  public:
    ResumeStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *RESUME();
    antlr4::tree::TerminalNode *WS();
    antlr4::tree::TerminalNode *NEXT();
    AmbiguousIdentifierContext *ambiguousIdentifier();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ResumeStmtContext* resumeStmt();

  class  ReturnStmtContext : public antlr4::ParserRuleContext {
  public:
    ReturnStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *RETURN();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ReturnStmtContext* returnStmt();

  class  RmdirStmtContext : public antlr4::ParserRuleContext {
  public:
    RmdirStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *RMDIR();
    antlr4::tree::TerminalNode *WS();
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  RmdirStmtContext* rmdirStmt();

  class  RsetStmtContext : public antlr4::ParserRuleContext {
  public:
    RsetStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *RSET();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    ImplicitCallStmt_InStmtContext *implicitCallStmt_InStmt();
    antlr4::tree::TerminalNode *EQ();
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  RsetStmtContext* rsetStmt();

  class  SavepictureStmtContext : public antlr4::ParserRuleContext {
  public:
    SavepictureStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *SAVEPICTURE();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *COMMA();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  SavepictureStmtContext* savepictureStmt();

  class  SaveSettingStmtContext : public antlr4::ParserRuleContext {
  public:
    SaveSettingStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *SAVESETTING();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  SaveSettingStmtContext* saveSettingStmt();

  class  SeekStmtContext : public antlr4::ParserRuleContext {
  public:
    SeekStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *SEEK();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *COMMA();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  SeekStmtContext* seekStmt();

  class  SelectCaseStmtContext : public antlr4::ParserRuleContext {
  public:
    SelectCaseStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *SELECT();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    antlr4::tree::TerminalNode *CASE();
    ValueStmtContext *valueStmt();
    antlr4::tree::TerminalNode *END_SELECT();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    std::vector<SC_CaseContext *> sC_Case();
    SC_CaseContext* sC_Case(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  SelectCaseStmtContext* selectCaseStmt();

  class  SC_CaseContext : public antlr4::ParserRuleContext {
  public:
    SC_CaseContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *CASE();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    SC_CondContext *sC_Cond();
    BlockContext *block();
    antlr4::tree::TerminalNode *COLON();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  SC_CaseContext* sC_Case();

  class  SC_CondContext : public antlr4::ParserRuleContext {
  public:
    SC_CondContext(antlr4::ParserRuleContext *parent, size_t invokingState);
   
    SC_CondContext() : antlr4::ParserRuleContext() { }
    void copyFrom(SC_CondContext *context);
    using antlr4::ParserRuleContext::copyFrom;

    virtual size_t getRuleIndex() const override;

   
  };

  class  CaseCondExprContext : public SC_CondContext {
  public:
    CaseCondExprContext(SC_CondContext *ctx);

    std::vector<SC_CondExprContext *> sC_CondExpr();
    SC_CondExprContext* sC_CondExpr(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  CaseCondElseContext : public SC_CondContext {
  public:
    CaseCondElseContext(SC_CondContext *ctx);

    antlr4::tree::TerminalNode *ELSE();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  SC_CondContext* sC_Cond();

  class  SC_CondExprContext : public antlr4::ParserRuleContext {
  public:
    SC_CondExprContext(antlr4::ParserRuleContext *parent, size_t invokingState);
   
    SC_CondExprContext() : antlr4::ParserRuleContext() { }
    void copyFrom(SC_CondExprContext *context);
    using antlr4::ParserRuleContext::copyFrom;

    virtual size_t getRuleIndex() const override;

   
  };

  class  CaseCondExprValueContext : public SC_CondExprContext {
  public:
    CaseCondExprValueContext(SC_CondExprContext *ctx);

    ValueStmtContext *valueStmt();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  CaseCondExprIsContext : public SC_CondExprContext {
  public:
    CaseCondExprIsContext(SC_CondExprContext *ctx);

    antlr4::tree::TerminalNode *IS();
    ComparisonOperatorContext *comparisonOperator();
    ValueStmtContext *valueStmt();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  CaseCondExprToContext : public SC_CondExprContext {
  public:
    CaseCondExprToContext(SC_CondExprContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    antlr4::tree::TerminalNode *TO();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  SC_CondExprContext* sC_CondExpr();

  class  SendkeysStmtContext : public antlr4::ParserRuleContext {
  public:
    SendkeysStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *SENDKEYS();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *COMMA();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  SendkeysStmtContext* sendkeysStmt();

  class  SetattrStmtContext : public antlr4::ParserRuleContext {
  public:
    SetattrStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *SETATTR();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *COMMA();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  SetattrStmtContext* setattrStmt();

  class  SetStmtContext : public antlr4::ParserRuleContext {
  public:
    SetStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *SET();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    ImplicitCallStmt_InStmtContext *implicitCallStmt_InStmt();
    antlr4::tree::TerminalNode *EQ();
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  SetStmtContext* setStmt();

  class  StopStmtContext : public antlr4::ParserRuleContext {
  public:
    StopStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *STOP();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  StopStmtContext* stopStmt();

  class  SubStmtContext : public antlr4::ParserRuleContext {
  public:
    SubStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *SUB();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *END_SUB();
    VisibilityContext *visibility();
    antlr4::tree::TerminalNode *STATIC();
    ArgListContext *argList();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    BlockContext *block();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  SubStmtContext* subStmt();

  class  TimeStmtContext : public antlr4::ParserRuleContext {
  public:
    TimeStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *TIME();
    antlr4::tree::TerminalNode *EQ();
    ValueStmtContext *valueStmt();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TimeStmtContext* timeStmt();

  class  TypeStmtContext : public antlr4::ParserRuleContext {
  public:
    TypeStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *TYPE();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *END_TYPE();
    VisibilityContext *visibility();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    std::vector<TypeStmt_ElementContext *> typeStmt_Element();
    TypeStmt_ElementContext* typeStmt_Element(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TypeStmtContext* typeStmt();

  class  TypeStmt_ElementContext : public antlr4::ParserRuleContext {
  public:
    TypeStmt_ElementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *LPAREN();
    antlr4::tree::TerminalNode *RPAREN();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AsTypeClauseContext *asTypeClause();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    SubscriptsContext *subscripts();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TypeStmt_ElementContext* typeStmt_Element();

  class  TypeOfStmtContext : public antlr4::ParserRuleContext {
  public:
    TypeOfStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *TYPEOF();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    ValueStmtContext *valueStmt();
    antlr4::tree::TerminalNode *IS();
    TypeContext *type();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TypeOfStmtContext* typeOfStmt();

  class  UnloadStmtContext : public antlr4::ParserRuleContext {
  public:
    UnloadStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *UNLOAD();
    antlr4::tree::TerminalNode *WS();
    ValueStmtContext *valueStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  UnloadStmtContext* unloadStmt();

  class  UnlockStmtContext : public antlr4::ParserRuleContext {
  public:
    UnlockStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *UNLOCK();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *COMMA();
    antlr4::tree::TerminalNode *TO();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  UnlockStmtContext* unlockStmt();

  class  ValueStmtContext : public antlr4::ParserRuleContext {
  public:
    ValueStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
   
    ValueStmtContext() : antlr4::ParserRuleContext() { }
    void copyFrom(ValueStmtContext *context);
    using antlr4::ParserRuleContext::copyFrom;

    virtual size_t getRuleIndex() const override;

   
  };

  class  VsStructContext : public ValueStmtContext {
  public:
    VsStructContext(ValueStmtContext *ctx);

    antlr4::tree::TerminalNode *LPAREN();
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *RPAREN();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsAddContext : public ValueStmtContext {
  public:
    VsAddContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *PLUS();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsLtContext : public ValueStmtContext {
  public:
    VsLtContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *LT();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsAddressOfContext : public ValueStmtContext {
  public:
    VsAddressOfContext(ValueStmtContext *ctx);

    antlr4::tree::TerminalNode *ADDRESSOF();
    antlr4::tree::TerminalNode *WS();
    ValueStmtContext *valueStmt();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsNewContext : public ValueStmtContext {
  public:
    VsNewContext(ValueStmtContext *ctx);

    antlr4::tree::TerminalNode *NEW();
    antlr4::tree::TerminalNode *WS();
    ValueStmtContext *valueStmt();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsMultContext : public ValueStmtContext {
  public:
    VsMultContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *MULT();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsNegationContext : public ValueStmtContext {
  public:
    VsNegationContext(ValueStmtContext *ctx);

    antlr4::tree::TerminalNode *MINUS();
    ValueStmtContext *valueStmt();
    antlr4::tree::TerminalNode *WS();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsAssignContext : public ValueStmtContext {
  public:
    VsAssignContext(ValueStmtContext *ctx);

    ImplicitCallStmt_InStmtContext *implicitCallStmt_InStmt();
    antlr4::tree::TerminalNode *ASSIGN();
    ValueStmtContext *valueStmt();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsDivContext : public ValueStmtContext {
  public:
    VsDivContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *DIV();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsLikeContext : public ValueStmtContext {
  public:
    VsLikeContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    antlr4::tree::TerminalNode *LIKE();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsPlusContext : public ValueStmtContext {
  public:
    VsPlusContext(ValueStmtContext *ctx);

    antlr4::tree::TerminalNode *PLUS();
    ValueStmtContext *valueStmt();
    antlr4::tree::TerminalNode *WS();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsNotContext : public ValueStmtContext {
  public:
    VsNotContext(ValueStmtContext *ctx);

    antlr4::tree::TerminalNode *NOT();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    ValueStmtContext *valueStmt();
    antlr4::tree::TerminalNode *LPAREN();
    antlr4::tree::TerminalNode *RPAREN();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsGeqContext : public ValueStmtContext {
  public:
    VsGeqContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *GEQ();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsTypeOfContext : public ValueStmtContext {
  public:
    VsTypeOfContext(ValueStmtContext *ctx);

    TypeOfStmtContext *typeOfStmt();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsICSContext : public ValueStmtContext {
  public:
    VsICSContext(ValueStmtContext *ctx);

    ImplicitCallStmt_InStmtContext *implicitCallStmt_InStmt();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsNeqContext : public ValueStmtContext {
  public:
    VsNeqContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *NEQ();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsXorContext : public ValueStmtContext {
  public:
    VsXorContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *XOR();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsAndContext : public ValueStmtContext {
  public:
    VsAndContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *AND();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsPowContext : public ValueStmtContext {
  public:
    VsPowContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *POW();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsLeqContext : public ValueStmtContext {
  public:
    VsLeqContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *LEQ();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsIsContext : public ValueStmtContext {
  public:
    VsIsContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    antlr4::tree::TerminalNode *IS();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsModContext : public ValueStmtContext {
  public:
    VsModContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *MOD();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsAmpContext : public ValueStmtContext {
  public:
    VsAmpContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *AMPERSAND();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsOrContext : public ValueStmtContext {
  public:
    VsOrContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *OR();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsMinusContext : public ValueStmtContext {
  public:
    VsMinusContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *MINUS();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsLiteralContext : public ValueStmtContext {
  public:
    VsLiteralContext(ValueStmtContext *ctx);

    LiteralContext *literal();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsEqvContext : public ValueStmtContext {
  public:
    VsEqvContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *EQV();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsImpContext : public ValueStmtContext {
  public:
    VsImpContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *IMP();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsGtContext : public ValueStmtContext {
  public:
    VsGtContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *GT();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsEqContext : public ValueStmtContext {
  public:
    VsEqContext(ValueStmtContext *ctx);

    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *EQ();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  class  VsMidContext : public ValueStmtContext {
  public:
    VsMidContext(ValueStmtContext *ctx);

    MidStmtContext *midStmt();
    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
  };

  ValueStmtContext* valueStmt();
  ValueStmtContext* valueStmt(int precedence);
  class  VariableStmtContext : public antlr4::ParserRuleContext {
  public:
    VariableStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    VariableListStmtContext *variableListStmt();
    antlr4::tree::TerminalNode *DIM();
    antlr4::tree::TerminalNode *STATIC();
    VisibilityContext *visibility();
    antlr4::tree::TerminalNode *WITHEVENTS();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  VariableStmtContext* variableStmt();

  class  VariableListStmtContext : public antlr4::ParserRuleContext {
  public:
    VariableListStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<VariableSubStmtContext *> variableSubStmt();
    VariableSubStmtContext* variableSubStmt(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  VariableListStmtContext* variableListStmt();

  class  VariableSubStmtContext : public antlr4::ParserRuleContext {
  public:
    VariableSubStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AmbiguousIdentifierContext *ambiguousIdentifier();
    TypeHintContext *typeHint();
    antlr4::tree::TerminalNode *LPAREN();
    antlr4::tree::TerminalNode *RPAREN();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AsTypeClauseContext *asTypeClause();
    SubscriptsContext *subscripts();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  VariableSubStmtContext* variableSubStmt();

  class  WhileWendStmtContext : public antlr4::ParserRuleContext {
  public:
    WhileWendStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *WHILE();
    antlr4::tree::TerminalNode *WS();
    ValueStmtContext *valueStmt();
    antlr4::tree::TerminalNode *WEND();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    std::vector<BlockContext *> block();
    BlockContext* block(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  WhileWendStmtContext* whileWendStmt();

  class  WidthStmtContext : public antlr4::ParserRuleContext {
  public:
    WidthStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *WIDTH();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    antlr4::tree::TerminalNode *COMMA();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  WidthStmtContext* widthStmt();

  class  WithStmtContext : public antlr4::ParserRuleContext {
  public:
    WithStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *WITH();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    ImplicitCallStmt_InStmtContext *implicitCallStmt_InStmt();
    antlr4::tree::TerminalNode *END_WITH();
    antlr4::tree::TerminalNode *NEW();
    std::vector<antlr4::tree::TerminalNode *> NEWLINE();
    antlr4::tree::TerminalNode* NEWLINE(size_t i);
    BlockContext *block();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  WithStmtContext* withStmt();

  class  WriteStmtContext : public antlr4::ParserRuleContext {
  public:
    WriteStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *WRITE();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    ValueStmtContext *valueStmt();
    antlr4::tree::TerminalNode *COMMA();
    OutputListContext *outputList();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  WriteStmtContext* writeStmt();

  class  ExplicitCallStmtContext : public antlr4::ParserRuleContext {
  public:
    ExplicitCallStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ECS_ProcedureCallContext *eCS_ProcedureCall();
    ECS_MemberProcedureCallContext *eCS_MemberProcedureCall();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ExplicitCallStmtContext* explicitCallStmt();

  class  ECS_ProcedureCallContext : public antlr4::ParserRuleContext {
  public:
    ECS_ProcedureCallContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *CALL();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    AmbiguousIdentifierContext *ambiguousIdentifier();
    TypeHintContext *typeHint();
    antlr4::tree::TerminalNode *LPAREN();
    ArgsCallContext *argsCall();
    antlr4::tree::TerminalNode *RPAREN();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ECS_ProcedureCallContext* eCS_ProcedureCall();

  class  ECS_MemberProcedureCallContext : public antlr4::ParserRuleContext {
  public:
    ECS_MemberProcedureCallContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *CALL();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    antlr4::tree::TerminalNode *DOT();
    AmbiguousIdentifierContext *ambiguousIdentifier();
    ImplicitCallStmt_InStmtContext *implicitCallStmt_InStmt();
    TypeHintContext *typeHint();
    antlr4::tree::TerminalNode *LPAREN();
    ArgsCallContext *argsCall();
    antlr4::tree::TerminalNode *RPAREN();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ECS_MemberProcedureCallContext* eCS_MemberProcedureCall();

  class  ImplicitCallStmt_InBlockContext : public antlr4::ParserRuleContext {
  public:
    ImplicitCallStmt_InBlockContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ICS_B_ProcedureCallContext *iCS_B_ProcedureCall();
    ICS_B_MemberProcedureCallContext *iCS_B_MemberProcedureCall();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ImplicitCallStmt_InBlockContext* implicitCallStmt_InBlock();

  class  ICS_B_ProcedureCallContext : public antlr4::ParserRuleContext {
  public:
    ICS_B_ProcedureCallContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    CertainIdentifierContext *certainIdentifier();
    antlr4::tree::TerminalNode *WS();
    ArgsCallContext *argsCall();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ICS_B_ProcedureCallContext* iCS_B_ProcedureCall();

  class  ICS_B_MemberProcedureCallContext : public antlr4::ParserRuleContext {
  public:
    ICS_B_MemberProcedureCallContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *DOT();
    AmbiguousIdentifierContext *ambiguousIdentifier();
    ImplicitCallStmt_InStmtContext *implicitCallStmt_InStmt();
    TypeHintContext *typeHint();
    antlr4::tree::TerminalNode *WS();
    ArgsCallContext *argsCall();
    DictionaryCallStmtContext *dictionaryCallStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ICS_B_MemberProcedureCallContext* iCS_B_MemberProcedureCall();

  class  ImplicitCallStmt_InStmtContext : public antlr4::ParserRuleContext {
  public:
    ImplicitCallStmt_InStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ICS_S_MembersCallContext *iCS_S_MembersCall();
    ICS_S_VariableOrProcedureCallContext *iCS_S_VariableOrProcedureCall();
    ICS_S_ProcedureOrArrayCallContext *iCS_S_ProcedureOrArrayCall();
    ICS_S_DictionaryCallContext *iCS_S_DictionaryCall();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ImplicitCallStmt_InStmtContext* implicitCallStmt_InStmt();

  class  ICS_S_VariableOrProcedureCallContext : public antlr4::ParserRuleContext {
  public:
    ICS_S_VariableOrProcedureCallContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AmbiguousIdentifierContext *ambiguousIdentifier();
    TypeHintContext *typeHint();
    DictionaryCallStmtContext *dictionaryCallStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ICS_S_VariableOrProcedureCallContext* iCS_S_VariableOrProcedureCall();

  class  ICS_S_ProcedureOrArrayCallContext : public antlr4::ParserRuleContext {
  public:
    ICS_S_ProcedureOrArrayCallContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AmbiguousIdentifierContext *ambiguousIdentifier();
    BaseTypeContext *baseType();
    ICS_S_NestedProcedureCallContext *iCS_S_NestedProcedureCall();
    TypeHintContext *typeHint();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<antlr4::tree::TerminalNode *> LPAREN();
    antlr4::tree::TerminalNode* LPAREN(size_t i);
    std::vector<antlr4::tree::TerminalNode *> RPAREN();
    antlr4::tree::TerminalNode* RPAREN(size_t i);
    DictionaryCallStmtContext *dictionaryCallStmt();
    std::vector<ArgsCallContext *> argsCall();
    ArgsCallContext* argsCall(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ICS_S_ProcedureOrArrayCallContext* iCS_S_ProcedureOrArrayCall();

  class  ICS_S_NestedProcedureCallContext : public antlr4::ParserRuleContext {
  public:
    ICS_S_NestedProcedureCallContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *LPAREN();
    antlr4::tree::TerminalNode *RPAREN();
    TypeHintContext *typeHint();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    ArgsCallContext *argsCall();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ICS_S_NestedProcedureCallContext* iCS_S_NestedProcedureCall();

  class  ICS_S_MembersCallContext : public antlr4::ParserRuleContext {
  public:
    ICS_S_MembersCallContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ICS_S_VariableOrProcedureCallContext *iCS_S_VariableOrProcedureCall();
    ICS_S_ProcedureOrArrayCallContext *iCS_S_ProcedureOrArrayCall();
    std::vector<ICS_S_MemberCallContext *> iCS_S_MemberCall();
    ICS_S_MemberCallContext* iCS_S_MemberCall(size_t i);
    DictionaryCallStmtContext *dictionaryCallStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ICS_S_MembersCallContext* iCS_S_MembersCall();

  class  ICS_S_MemberCallContext : public antlr4::ParserRuleContext {
  public:
    ICS_S_MemberCallContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *DOT();
    ICS_S_VariableOrProcedureCallContext *iCS_S_VariableOrProcedureCall();
    ICS_S_ProcedureOrArrayCallContext *iCS_S_ProcedureOrArrayCall();
    antlr4::tree::TerminalNode *WS();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ICS_S_MemberCallContext* iCS_S_MemberCall();

  class  ICS_S_DictionaryCallContext : public antlr4::ParserRuleContext {
  public:
    ICS_S_DictionaryCallContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    DictionaryCallStmtContext *dictionaryCallStmt();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ICS_S_DictionaryCallContext* iCS_S_DictionaryCall();

  class  ArgsCallContext : public antlr4::ParserRuleContext {
  public:
    ArgsCallContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<ArgCallContext *> argCall();
    ArgCallContext* argCall(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);
    std::vector<antlr4::tree::TerminalNode *> SEMICOLON();
    antlr4::tree::TerminalNode* SEMICOLON(size_t i);
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ArgsCallContext* argsCall();

  class  ArgCallContext : public antlr4::ParserRuleContext {
  public:
    ArgCallContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ValueStmtContext *valueStmt();
    antlr4::tree::TerminalNode *WS();
    antlr4::tree::TerminalNode *BYVAL();
    antlr4::tree::TerminalNode *BYREF();
    antlr4::tree::TerminalNode *PARAMARRAY();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ArgCallContext* argCall();

  class  DictionaryCallStmtContext : public antlr4::ParserRuleContext {
  public:
    DictionaryCallStmtContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *EXCLAMATIONMARK();
    AmbiguousIdentifierContext *ambiguousIdentifier();
    TypeHintContext *typeHint();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  DictionaryCallStmtContext* dictionaryCallStmt();

  class  ArgListContext : public antlr4::ParserRuleContext {
  public:
    ArgListContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *LPAREN();
    antlr4::tree::TerminalNode *RPAREN();
    std::vector<ArgContext *> arg();
    ArgContext* arg(size_t i);
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ArgListContext* argList();

  class  ArgContext : public antlr4::ParserRuleContext {
  public:
    ArgContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *OPTIONAL();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    antlr4::tree::TerminalNode *PARAMARRAY();
    TypeHintContext *typeHint();
    antlr4::tree::TerminalNode *LPAREN();
    antlr4::tree::TerminalNode *RPAREN();
    AsTypeClauseContext *asTypeClause();
    ArgDefaultValueContext *argDefaultValue();
    antlr4::tree::TerminalNode *BYVAL();
    antlr4::tree::TerminalNode *BYREF();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ArgContext* arg();

  class  ArgDefaultValueContext : public antlr4::ParserRuleContext {
  public:
    ArgDefaultValueContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *EQ();
    ValueStmtContext *valueStmt();
    antlr4::tree::TerminalNode *WS();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ArgDefaultValueContext* argDefaultValue();

  class  SubscriptsContext : public antlr4::ParserRuleContext {
  public:
    SubscriptsContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<SubscriptContext *> subscript();
    SubscriptContext* subscript(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMA();
    antlr4::tree::TerminalNode* COMMA(size_t i);
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  SubscriptsContext* subscripts();

  class  SubscriptContext : public antlr4::ParserRuleContext {
  public:
    SubscriptContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<ValueStmtContext *> valueStmt();
    ValueStmtContext* valueStmt(size_t i);
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    antlr4::tree::TerminalNode *TO();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  SubscriptContext* subscript();

  class  AmbiguousIdentifierContext : public antlr4::ParserRuleContext {
  public:
    AmbiguousIdentifierContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<antlr4::tree::TerminalNode *> IDENTIFIER();
    antlr4::tree::TerminalNode* IDENTIFIER(size_t i);
    std::vector<AmbiguousKeywordContext *> ambiguousKeyword();
    AmbiguousKeywordContext* ambiguousKeyword(size_t i);
    antlr4::tree::TerminalNode *L_SQUARE_BRACKET();
    antlr4::tree::TerminalNode *R_SQUARE_BRACKET();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  AmbiguousIdentifierContext* ambiguousIdentifier();

  class  AsTypeClauseContext : public antlr4::ParserRuleContext {
  public:
    AsTypeClauseContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *AS();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);
    TypeContext *type();
    antlr4::tree::TerminalNode *NEW();
    FieldLengthContext *fieldLength();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  AsTypeClauseContext* asTypeClause();

  class  BaseTypeContext : public antlr4::ParserRuleContext {
  public:
    BaseTypeContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *BOOLEAN();
    antlr4::tree::TerminalNode *BYTE();
    antlr4::tree::TerminalNode *COLLECTION();
    antlr4::tree::TerminalNode *DATE();
    antlr4::tree::TerminalNode *DOUBLE();
    antlr4::tree::TerminalNode *INTEGER();
    antlr4::tree::TerminalNode *LONG();
    antlr4::tree::TerminalNode *OBJECT();
    antlr4::tree::TerminalNode *SINGLE();
    antlr4::tree::TerminalNode *STRING();
    antlr4::tree::TerminalNode *VARIANT();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  BaseTypeContext* baseType();

  class  CertainIdentifierContext : public antlr4::ParserRuleContext {
  public:
    CertainIdentifierContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<antlr4::tree::TerminalNode *> IDENTIFIER();
    antlr4::tree::TerminalNode* IDENTIFIER(size_t i);
    std::vector<AmbiguousKeywordContext *> ambiguousKeyword();
    AmbiguousKeywordContext* ambiguousKeyword(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  CertainIdentifierContext* certainIdentifier();

  class  ComparisonOperatorContext : public antlr4::ParserRuleContext {
  public:
    ComparisonOperatorContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *LT();
    antlr4::tree::TerminalNode *LEQ();
    antlr4::tree::TerminalNode *GT();
    antlr4::tree::TerminalNode *GEQ();
    antlr4::tree::TerminalNode *EQ();
    antlr4::tree::TerminalNode *NEQ();
    antlr4::tree::TerminalNode *IS();
    antlr4::tree::TerminalNode *LIKE();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ComparisonOperatorContext* comparisonOperator();

  class  ComplexTypeContext : public antlr4::ParserRuleContext {
  public:
    ComplexTypeContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<AmbiguousIdentifierContext *> ambiguousIdentifier();
    AmbiguousIdentifierContext* ambiguousIdentifier(size_t i);
    std::vector<antlr4::tree::TerminalNode *> DOT();
    antlr4::tree::TerminalNode* DOT(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ComplexTypeContext* complexType();

  class  FieldLengthContext : public antlr4::ParserRuleContext {
  public:
    FieldLengthContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *MULT();
    antlr4::tree::TerminalNode *INTEGERLITERAL();
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *WS();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  FieldLengthContext* fieldLength();

  class  LetterrangeContext : public antlr4::ParserRuleContext {
  public:
    LetterrangeContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<CertainIdentifierContext *> certainIdentifier();
    CertainIdentifierContext* certainIdentifier(size_t i);
    antlr4::tree::TerminalNode *MINUS();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  LetterrangeContext* letterrange();

  class  LineLabelContext : public antlr4::ParserRuleContext {
  public:
    LineLabelContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    AmbiguousIdentifierContext *ambiguousIdentifier();
    antlr4::tree::TerminalNode *COLON();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  LineLabelContext* lineLabel();

  class  LiteralContext : public antlr4::ParserRuleContext {
  public:
    LiteralContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *COLORLITERAL();
    antlr4::tree::TerminalNode *DATELITERAL();
    antlr4::tree::TerminalNode *DOUBLELITERAL();
    antlr4::tree::TerminalNode *FILENUMBER();
    antlr4::tree::TerminalNode *INTEGERLITERAL();
    antlr4::tree::TerminalNode *OCTALLITERAL();
    antlr4::tree::TerminalNode *STRINGLITERAL();
    antlr4::tree::TerminalNode *TRUE1();
    antlr4::tree::TerminalNode *FALSE1();
    antlr4::tree::TerminalNode *NOTHING();
    antlr4::tree::TerminalNode *NULL1();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  LiteralContext* literal();

  class  PublicPrivateVisibilityContext : public antlr4::ParserRuleContext {
  public:
    PublicPrivateVisibilityContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *PRIVATE();
    antlr4::tree::TerminalNode *PUBLIC();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  PublicPrivateVisibilityContext* publicPrivateVisibility();

  class  PublicPrivateGlobalVisibilityContext : public antlr4::ParserRuleContext {
  public:
    PublicPrivateGlobalVisibilityContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *PRIVATE();
    antlr4::tree::TerminalNode *PUBLIC();
    antlr4::tree::TerminalNode *GLOBAL();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  PublicPrivateGlobalVisibilityContext* publicPrivateGlobalVisibility();

  class  TypeContext : public antlr4::ParserRuleContext {
  public:
    TypeContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    BaseTypeContext *baseType();
    ComplexTypeContext *complexType();
    antlr4::tree::TerminalNode *LPAREN();
    antlr4::tree::TerminalNode *RPAREN();
    std::vector<antlr4::tree::TerminalNode *> WS();
    antlr4::tree::TerminalNode* WS(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TypeContext* type();

  class  TypeHintContext : public antlr4::ParserRuleContext {
  public:
    TypeHintContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *AMPERSAND();
    antlr4::tree::TerminalNode *AT();
    antlr4::tree::TerminalNode *DOLLAR();
    antlr4::tree::TerminalNode *EXCLAMATIONMARK();
    antlr4::tree::TerminalNode *HASH();
    antlr4::tree::TerminalNode *PERCENT();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  TypeHintContext* typeHint();

  class  VisibilityContext : public antlr4::ParserRuleContext {
  public:
    VisibilityContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *PRIVATE();
    antlr4::tree::TerminalNode *PUBLIC();
    antlr4::tree::TerminalNode *FRIEND();
    antlr4::tree::TerminalNode *GLOBAL();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  VisibilityContext* visibility();

  class  AmbiguousKeywordContext : public antlr4::ParserRuleContext {
  public:
    AmbiguousKeywordContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *ACCESS();
    antlr4::tree::TerminalNode *ADDRESSOF();
    antlr4::tree::TerminalNode *ALIAS();
    antlr4::tree::TerminalNode *AND();
    antlr4::tree::TerminalNode *ATTRIBUTE();
    antlr4::tree::TerminalNode *APPACTIVATE();
    antlr4::tree::TerminalNode *APPEND();
    antlr4::tree::TerminalNode *AS();
    antlr4::tree::TerminalNode *BEEP();
    antlr4::tree::TerminalNode *BEGIN();
    antlr4::tree::TerminalNode *BINARY();
    antlr4::tree::TerminalNode *BOOLEAN();
    antlr4::tree::TerminalNode *BYVAL();
    antlr4::tree::TerminalNode *BYREF();
    antlr4::tree::TerminalNode *BYTE();
    antlr4::tree::TerminalNode *CALL();
    antlr4::tree::TerminalNode *CASE();
    antlr4::tree::TerminalNode *CLASS();
    antlr4::tree::TerminalNode *CLOSE();
    antlr4::tree::TerminalNode *CHDIR();
    antlr4::tree::TerminalNode *CHDRIVE();
    antlr4::tree::TerminalNode *COLLECTION();
    antlr4::tree::TerminalNode *CONST();
    antlr4::tree::TerminalNode *DATE();
    antlr4::tree::TerminalNode *DECLARE();
    antlr4::tree::TerminalNode *DEFBOOL();
    antlr4::tree::TerminalNode *DEFBYTE();
    antlr4::tree::TerminalNode *DEFCUR();
    antlr4::tree::TerminalNode *DEFDBL();
    antlr4::tree::TerminalNode *DEFDATE();
    antlr4::tree::TerminalNode *DEFDEC();
    antlr4::tree::TerminalNode *DEFINT();
    antlr4::tree::TerminalNode *DEFLNG();
    antlr4::tree::TerminalNode *DEFOBJ();
    antlr4::tree::TerminalNode *DEFSNG();
    antlr4::tree::TerminalNode *DEFSTR();
    antlr4::tree::TerminalNode *DEFVAR();
    antlr4::tree::TerminalNode *DELETESETTING();
    antlr4::tree::TerminalNode *DIM();
    antlr4::tree::TerminalNode *DO();
    antlr4::tree::TerminalNode *DOUBLE();
    antlr4::tree::TerminalNode *EACH();
    antlr4::tree::TerminalNode *ELSE();
    antlr4::tree::TerminalNode *ELSEIF();
    antlr4::tree::TerminalNode *END();
    antlr4::tree::TerminalNode *ENUM();
    antlr4::tree::TerminalNode *EQV();
    antlr4::tree::TerminalNode *ERASE();
    antlr4::tree::TerminalNode *ERROR();
    antlr4::tree::TerminalNode *EVENT();
    antlr4::tree::TerminalNode *FALSE1();
    antlr4::tree::TerminalNode *FILECOPY();
    antlr4::tree::TerminalNode *FRIEND();
    antlr4::tree::TerminalNode *FOR();
    antlr4::tree::TerminalNode *FUNCTION();
    antlr4::tree::TerminalNode *GET();
    antlr4::tree::TerminalNode *GLOBAL();
    antlr4::tree::TerminalNode *GOSUB();
    antlr4::tree::TerminalNode *GOTO();
    antlr4::tree::TerminalNode *IF();
    antlr4::tree::TerminalNode *IMP();
    antlr4::tree::TerminalNode *IMPLEMENTS();
    antlr4::tree::TerminalNode *IN();
    antlr4::tree::TerminalNode *INPUT();
    antlr4::tree::TerminalNode *IS();
    antlr4::tree::TerminalNode *INTEGER();
    antlr4::tree::TerminalNode *KILL();
    antlr4::tree::TerminalNode *LOAD();
    antlr4::tree::TerminalNode *LOCK();
    antlr4::tree::TerminalNode *LONG();
    antlr4::tree::TerminalNode *LOOP();
    antlr4::tree::TerminalNode *LEN();
    antlr4::tree::TerminalNode *LET();
    antlr4::tree::TerminalNode *LIB();
    antlr4::tree::TerminalNode *LIKE();
    antlr4::tree::TerminalNode *LSET();
    antlr4::tree::TerminalNode *ME();
    antlr4::tree::TerminalNode *MID();
    antlr4::tree::TerminalNode *MKDIR();
    antlr4::tree::TerminalNode *MOD();
    antlr4::tree::TerminalNode *NAME();
    antlr4::tree::TerminalNode *NEXT();
    antlr4::tree::TerminalNode *NEW();
    antlr4::tree::TerminalNode *NOT();
    antlr4::tree::TerminalNode *NOTHING();
    antlr4::tree::TerminalNode *NULL1();
    antlr4::tree::TerminalNode *OBJECT();
    antlr4::tree::TerminalNode *ON();
    antlr4::tree::TerminalNode *OPEN();
    antlr4::tree::TerminalNode *OPTIONAL();
    antlr4::tree::TerminalNode *OR();
    antlr4::tree::TerminalNode *OUTPUT();
    antlr4::tree::TerminalNode *PARAMARRAY();
    antlr4::tree::TerminalNode *PRESERVE();
    antlr4::tree::TerminalNode *PRINT();
    antlr4::tree::TerminalNode *PRIVATE();
    antlr4::tree::TerminalNode *PUBLIC();
    antlr4::tree::TerminalNode *PUT();
    antlr4::tree::TerminalNode *RANDOM();
    antlr4::tree::TerminalNode *RANDOMIZE();
    antlr4::tree::TerminalNode *RAISEEVENT();
    antlr4::tree::TerminalNode *READ();
    antlr4::tree::TerminalNode *REDIM();
    antlr4::tree::TerminalNode *REM();
    antlr4::tree::TerminalNode *RESET();
    antlr4::tree::TerminalNode *RESUME();
    antlr4::tree::TerminalNode *RETURN();
    antlr4::tree::TerminalNode *RMDIR();
    antlr4::tree::TerminalNode *RSET();
    antlr4::tree::TerminalNode *SAVEPICTURE();
    antlr4::tree::TerminalNode *SAVESETTING();
    antlr4::tree::TerminalNode *SEEK();
    antlr4::tree::TerminalNode *SELECT();
    antlr4::tree::TerminalNode *SENDKEYS();
    antlr4::tree::TerminalNode *SET();
    antlr4::tree::TerminalNode *SETATTR();
    antlr4::tree::TerminalNode *SHARED();
    antlr4::tree::TerminalNode *SINGLE();
    antlr4::tree::TerminalNode *SPC();
    antlr4::tree::TerminalNode *STATIC();
    antlr4::tree::TerminalNode *STEP();
    antlr4::tree::TerminalNode *STOP();
    antlr4::tree::TerminalNode *STRING();
    antlr4::tree::TerminalNode *SUB();
    antlr4::tree::TerminalNode *TAB();
    antlr4::tree::TerminalNode *TEXT();
    antlr4::tree::TerminalNode *THEN();
    antlr4::tree::TerminalNode *TIME();
    antlr4::tree::TerminalNode *TO();
    antlr4::tree::TerminalNode *TRUE1();
    antlr4::tree::TerminalNode *TYPE();
    antlr4::tree::TerminalNode *TYPEOF();
    antlr4::tree::TerminalNode *UNLOAD();
    antlr4::tree::TerminalNode *UNLOCK();
    antlr4::tree::TerminalNode *UNTIL();
    antlr4::tree::TerminalNode *VARIANT();
    antlr4::tree::TerminalNode *VERSION();
    antlr4::tree::TerminalNode *WEND();
    antlr4::tree::TerminalNode *WHILE();
    antlr4::tree::TerminalNode *WIDTH();
    antlr4::tree::TerminalNode *WITH();
    antlr4::tree::TerminalNode *WITHEVENTS();
    antlr4::tree::TerminalNode *WRITE();
    antlr4::tree::TerminalNode *XOR();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  AmbiguousKeywordContext* ambiguousKeyword();


  virtual bool sempred(antlr4::RuleContext *_localctx, size_t ruleIndex, size_t predicateIndex) override;
  bool valueStmtSempred(ValueStmtContext *_localctx, size_t predicateIndex);

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

