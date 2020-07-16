
// Generated from C:\Users\xiang\Desktop\vbs_parser\VisualBasic6.g4 by ANTLR 4.7

#pragma once


#include "antlr4-runtime.h"
#include "VisualBasic6Parser.h"



/**
 * This class defines an abstract visitor for a parse tree
 * produced by VisualBasic6Parser.
 */
class  VisualBasic6Visitor : public antlr4::tree::AbstractParseTreeVisitor {
public:

  /**
   * Visit parse trees produced by VisualBasic6Parser.
   */
    virtual antlrcpp::Any visitStartRule(VisualBasic6Parser::StartRuleContext *context) = 0;

    virtual antlrcpp::Any visitModule(VisualBasic6Parser::ModuleContext *context) = 0;

    virtual antlrcpp::Any visitModuleReferences(VisualBasic6Parser::ModuleReferencesContext *context) = 0;

    virtual antlrcpp::Any visitModuleReference(VisualBasic6Parser::ModuleReferenceContext *context) = 0;

    virtual antlrcpp::Any visitModuleReferenceValue(VisualBasic6Parser::ModuleReferenceValueContext *context) = 0;

    virtual antlrcpp::Any visitModuleReferenceComponent(VisualBasic6Parser::ModuleReferenceComponentContext *context) = 0;

    virtual antlrcpp::Any visitModuleHeader(VisualBasic6Parser::ModuleHeaderContext *context) = 0;

    virtual antlrcpp::Any visitModuleConfig(VisualBasic6Parser::ModuleConfigContext *context) = 0;

    virtual antlrcpp::Any visitModuleConfigElement(VisualBasic6Parser::ModuleConfigElementContext *context) = 0;

    virtual antlrcpp::Any visitModuleAttributes(VisualBasic6Parser::ModuleAttributesContext *context) = 0;

    virtual antlrcpp::Any visitModuleOptions(VisualBasic6Parser::ModuleOptionsContext *context) = 0;

    virtual antlrcpp::Any visitOptionBaseStmt(VisualBasic6Parser::OptionBaseStmtContext *context) = 0;

    virtual antlrcpp::Any visitOptionCompareStmt(VisualBasic6Parser::OptionCompareStmtContext *context) = 0;

    virtual antlrcpp::Any visitOptionExplicitStmt(VisualBasic6Parser::OptionExplicitStmtContext *context) = 0;

    virtual antlrcpp::Any visitOptionPrivateModuleStmt(VisualBasic6Parser::OptionPrivateModuleStmtContext *context) = 0;

    virtual antlrcpp::Any visitModuleBody(VisualBasic6Parser::ModuleBodyContext *context) = 0;

    virtual antlrcpp::Any visitModuleBodyElement(VisualBasic6Parser::ModuleBodyElementContext *context) = 0;

    virtual antlrcpp::Any visitControlProperties(VisualBasic6Parser::ControlPropertiesContext *context) = 0;

    virtual antlrcpp::Any visitCp_Properties(VisualBasic6Parser::Cp_PropertiesContext *context) = 0;

    virtual antlrcpp::Any visitCp_SingleProperty(VisualBasic6Parser::Cp_SinglePropertyContext *context) = 0;

    virtual antlrcpp::Any visitCp_PropertyName(VisualBasic6Parser::Cp_PropertyNameContext *context) = 0;

    virtual antlrcpp::Any visitCp_PropertyValue(VisualBasic6Parser::Cp_PropertyValueContext *context) = 0;

    virtual antlrcpp::Any visitCp_NestedProperty(VisualBasic6Parser::Cp_NestedPropertyContext *context) = 0;

    virtual antlrcpp::Any visitCp_ControlType(VisualBasic6Parser::Cp_ControlTypeContext *context) = 0;

    virtual antlrcpp::Any visitCp_ControlIdentifier(VisualBasic6Parser::Cp_ControlIdentifierContext *context) = 0;

    virtual antlrcpp::Any visitModuleBlock(VisualBasic6Parser::ModuleBlockContext *context) = 0;

    virtual antlrcpp::Any visitAttributeStmt(VisualBasic6Parser::AttributeStmtContext *context) = 0;

    virtual antlrcpp::Any visitBlock(VisualBasic6Parser::BlockContext *context) = 0;

    virtual antlrcpp::Any visitBlockStmt(VisualBasic6Parser::BlockStmtContext *context) = 0;

    virtual antlrcpp::Any visitAppActivateStmt(VisualBasic6Parser::AppActivateStmtContext *context) = 0;

    virtual antlrcpp::Any visitBeepStmt(VisualBasic6Parser::BeepStmtContext *context) = 0;

    virtual antlrcpp::Any visitChDirStmt(VisualBasic6Parser::ChDirStmtContext *context) = 0;

    virtual antlrcpp::Any visitChDriveStmt(VisualBasic6Parser::ChDriveStmtContext *context) = 0;

    virtual antlrcpp::Any visitCloseStmt(VisualBasic6Parser::CloseStmtContext *context) = 0;

    virtual antlrcpp::Any visitConstStmt(VisualBasic6Parser::ConstStmtContext *context) = 0;

    virtual antlrcpp::Any visitConstSubStmt(VisualBasic6Parser::ConstSubStmtContext *context) = 0;

    virtual antlrcpp::Any visitDateStmt(VisualBasic6Parser::DateStmtContext *context) = 0;

    virtual antlrcpp::Any visitDeclareStmt(VisualBasic6Parser::DeclareStmtContext *context) = 0;

    virtual antlrcpp::Any visitDeftypeStmt(VisualBasic6Parser::DeftypeStmtContext *context) = 0;

    virtual antlrcpp::Any visitDeleteSettingStmt(VisualBasic6Parser::DeleteSettingStmtContext *context) = 0;

    virtual antlrcpp::Any visitDoLoopStmt(VisualBasic6Parser::DoLoopStmtContext *context) = 0;

    virtual antlrcpp::Any visitEndStmt(VisualBasic6Parser::EndStmtContext *context) = 0;

    virtual antlrcpp::Any visitEnumerationStmt(VisualBasic6Parser::EnumerationStmtContext *context) = 0;

    virtual antlrcpp::Any visitEnumerationStmt_Constant(VisualBasic6Parser::EnumerationStmt_ConstantContext *context) = 0;

    virtual antlrcpp::Any visitEraseStmt(VisualBasic6Parser::EraseStmtContext *context) = 0;

    virtual antlrcpp::Any visitErrorStmt(VisualBasic6Parser::ErrorStmtContext *context) = 0;

    virtual antlrcpp::Any visitEventStmt(VisualBasic6Parser::EventStmtContext *context) = 0;

    virtual antlrcpp::Any visitExitStmt(VisualBasic6Parser::ExitStmtContext *context) = 0;

    virtual antlrcpp::Any visitFilecopyStmt(VisualBasic6Parser::FilecopyStmtContext *context) = 0;

    virtual antlrcpp::Any visitForEachStmt(VisualBasic6Parser::ForEachStmtContext *context) = 0;

    virtual antlrcpp::Any visitForNextStmt(VisualBasic6Parser::ForNextStmtContext *context) = 0;

    virtual antlrcpp::Any visitFunctionStmt(VisualBasic6Parser::FunctionStmtContext *context) = 0;

    virtual antlrcpp::Any visitGetStmt(VisualBasic6Parser::GetStmtContext *context) = 0;

    virtual antlrcpp::Any visitGoSubStmt(VisualBasic6Parser::GoSubStmtContext *context) = 0;

    virtual antlrcpp::Any visitGoToStmt(VisualBasic6Parser::GoToStmtContext *context) = 0;

    virtual antlrcpp::Any visitInlineIfThenElse(VisualBasic6Parser::InlineIfThenElseContext *context) = 0;

    virtual antlrcpp::Any visitBlockIfThenElse(VisualBasic6Parser::BlockIfThenElseContext *context) = 0;

    virtual antlrcpp::Any visitIfBlockStmt(VisualBasic6Parser::IfBlockStmtContext *context) = 0;

    virtual antlrcpp::Any visitIfConditionStmt(VisualBasic6Parser::IfConditionStmtContext *context) = 0;

    virtual antlrcpp::Any visitIfElseIfBlockStmt(VisualBasic6Parser::IfElseIfBlockStmtContext *context) = 0;

    virtual antlrcpp::Any visitIfElseBlockStmt(VisualBasic6Parser::IfElseBlockStmtContext *context) = 0;

    virtual antlrcpp::Any visitImplementsStmt(VisualBasic6Parser::ImplementsStmtContext *context) = 0;

    virtual antlrcpp::Any visitInputStmt(VisualBasic6Parser::InputStmtContext *context) = 0;

    virtual antlrcpp::Any visitKillStmt(VisualBasic6Parser::KillStmtContext *context) = 0;

    virtual antlrcpp::Any visitLetStmt(VisualBasic6Parser::LetStmtContext *context) = 0;

    virtual antlrcpp::Any visitLineInputStmt(VisualBasic6Parser::LineInputStmtContext *context) = 0;

    virtual antlrcpp::Any visitLoadStmt(VisualBasic6Parser::LoadStmtContext *context) = 0;

    virtual antlrcpp::Any visitLockStmt(VisualBasic6Parser::LockStmtContext *context) = 0;

    virtual antlrcpp::Any visitLsetStmt(VisualBasic6Parser::LsetStmtContext *context) = 0;

    virtual antlrcpp::Any visitMacroIfThenElseStmt(VisualBasic6Parser::MacroIfThenElseStmtContext *context) = 0;

    virtual antlrcpp::Any visitMacroIfBlockStmt(VisualBasic6Parser::MacroIfBlockStmtContext *context) = 0;

    virtual antlrcpp::Any visitMacroElseIfBlockStmt(VisualBasic6Parser::MacroElseIfBlockStmtContext *context) = 0;

    virtual antlrcpp::Any visitMacroElseBlockStmt(VisualBasic6Parser::MacroElseBlockStmtContext *context) = 0;

    virtual antlrcpp::Any visitMidStmt(VisualBasic6Parser::MidStmtContext *context) = 0;

    virtual antlrcpp::Any visitMkdirStmt(VisualBasic6Parser::MkdirStmtContext *context) = 0;

    virtual antlrcpp::Any visitNameStmt(VisualBasic6Parser::NameStmtContext *context) = 0;

    virtual antlrcpp::Any visitOnErrorStmt(VisualBasic6Parser::OnErrorStmtContext *context) = 0;

    virtual antlrcpp::Any visitOnGoToStmt(VisualBasic6Parser::OnGoToStmtContext *context) = 0;

    virtual antlrcpp::Any visitOnGoSubStmt(VisualBasic6Parser::OnGoSubStmtContext *context) = 0;

    virtual antlrcpp::Any visitOpenStmt(VisualBasic6Parser::OpenStmtContext *context) = 0;

    virtual antlrcpp::Any visitOutputList(VisualBasic6Parser::OutputListContext *context) = 0;

    virtual antlrcpp::Any visitOutputList_Expression(VisualBasic6Parser::OutputList_ExpressionContext *context) = 0;

    virtual antlrcpp::Any visitPrintStmt(VisualBasic6Parser::PrintStmtContext *context) = 0;

    virtual antlrcpp::Any visitPropertyGetStmt(VisualBasic6Parser::PropertyGetStmtContext *context) = 0;

    virtual antlrcpp::Any visitPropertySetStmt(VisualBasic6Parser::PropertySetStmtContext *context) = 0;

    virtual antlrcpp::Any visitPropertyLetStmt(VisualBasic6Parser::PropertyLetStmtContext *context) = 0;

    virtual antlrcpp::Any visitPutStmt(VisualBasic6Parser::PutStmtContext *context) = 0;

    virtual antlrcpp::Any visitRaiseEventStmt(VisualBasic6Parser::RaiseEventStmtContext *context) = 0;

    virtual antlrcpp::Any visitRandomizeStmt(VisualBasic6Parser::RandomizeStmtContext *context) = 0;

    virtual antlrcpp::Any visitRedimStmt(VisualBasic6Parser::RedimStmtContext *context) = 0;

    virtual antlrcpp::Any visitRedimSubStmt(VisualBasic6Parser::RedimSubStmtContext *context) = 0;

    virtual antlrcpp::Any visitResetStmt(VisualBasic6Parser::ResetStmtContext *context) = 0;

    virtual antlrcpp::Any visitResumeStmt(VisualBasic6Parser::ResumeStmtContext *context) = 0;

    virtual antlrcpp::Any visitReturnStmt(VisualBasic6Parser::ReturnStmtContext *context) = 0;

    virtual antlrcpp::Any visitRmdirStmt(VisualBasic6Parser::RmdirStmtContext *context) = 0;

    virtual antlrcpp::Any visitRsetStmt(VisualBasic6Parser::RsetStmtContext *context) = 0;

    virtual antlrcpp::Any visitSavepictureStmt(VisualBasic6Parser::SavepictureStmtContext *context) = 0;

    virtual antlrcpp::Any visitSaveSettingStmt(VisualBasic6Parser::SaveSettingStmtContext *context) = 0;

    virtual antlrcpp::Any visitSeekStmt(VisualBasic6Parser::SeekStmtContext *context) = 0;

    virtual antlrcpp::Any visitSelectCaseStmt(VisualBasic6Parser::SelectCaseStmtContext *context) = 0;

    virtual antlrcpp::Any visitSC_Case(VisualBasic6Parser::SC_CaseContext *context) = 0;

    virtual antlrcpp::Any visitCaseCondElse(VisualBasic6Parser::CaseCondElseContext *context) = 0;

    virtual antlrcpp::Any visitCaseCondExpr(VisualBasic6Parser::CaseCondExprContext *context) = 0;

    virtual antlrcpp::Any visitCaseCondExprIs(VisualBasic6Parser::CaseCondExprIsContext *context) = 0;

    virtual antlrcpp::Any visitCaseCondExprValue(VisualBasic6Parser::CaseCondExprValueContext *context) = 0;

    virtual antlrcpp::Any visitCaseCondExprTo(VisualBasic6Parser::CaseCondExprToContext *context) = 0;

    virtual antlrcpp::Any visitSendkeysStmt(VisualBasic6Parser::SendkeysStmtContext *context) = 0;

    virtual antlrcpp::Any visitSetattrStmt(VisualBasic6Parser::SetattrStmtContext *context) = 0;

    virtual antlrcpp::Any visitSetStmt(VisualBasic6Parser::SetStmtContext *context) = 0;

    virtual antlrcpp::Any visitStopStmt(VisualBasic6Parser::StopStmtContext *context) = 0;

    virtual antlrcpp::Any visitSubStmt(VisualBasic6Parser::SubStmtContext *context) = 0;

    virtual antlrcpp::Any visitTimeStmt(VisualBasic6Parser::TimeStmtContext *context) = 0;

    virtual antlrcpp::Any visitTypeStmt(VisualBasic6Parser::TypeStmtContext *context) = 0;

    virtual antlrcpp::Any visitTypeStmt_Element(VisualBasic6Parser::TypeStmt_ElementContext *context) = 0;

    virtual antlrcpp::Any visitTypeOfStmt(VisualBasic6Parser::TypeOfStmtContext *context) = 0;

    virtual antlrcpp::Any visitUnloadStmt(VisualBasic6Parser::UnloadStmtContext *context) = 0;

    virtual antlrcpp::Any visitUnlockStmt(VisualBasic6Parser::UnlockStmtContext *context) = 0;

    virtual antlrcpp::Any visitVsStruct(VisualBasic6Parser::VsStructContext *context) = 0;

    virtual antlrcpp::Any visitVsAdd(VisualBasic6Parser::VsAddContext *context) = 0;

    virtual antlrcpp::Any visitVsLt(VisualBasic6Parser::VsLtContext *context) = 0;

    virtual antlrcpp::Any visitVsAddressOf(VisualBasic6Parser::VsAddressOfContext *context) = 0;

    virtual antlrcpp::Any visitVsNew(VisualBasic6Parser::VsNewContext *context) = 0;

    virtual antlrcpp::Any visitVsMult(VisualBasic6Parser::VsMultContext *context) = 0;

    virtual antlrcpp::Any visitVsNegation(VisualBasic6Parser::VsNegationContext *context) = 0;

    virtual antlrcpp::Any visitVsAssign(VisualBasic6Parser::VsAssignContext *context) = 0;

    virtual antlrcpp::Any visitVsDiv(VisualBasic6Parser::VsDivContext *context) = 0;

    virtual antlrcpp::Any visitVsLike(VisualBasic6Parser::VsLikeContext *context) = 0;

    virtual antlrcpp::Any visitVsPlus(VisualBasic6Parser::VsPlusContext *context) = 0;

    virtual antlrcpp::Any visitVsNot(VisualBasic6Parser::VsNotContext *context) = 0;

    virtual antlrcpp::Any visitVsGeq(VisualBasic6Parser::VsGeqContext *context) = 0;

    virtual antlrcpp::Any visitVsTypeOf(VisualBasic6Parser::VsTypeOfContext *context) = 0;

    virtual antlrcpp::Any visitVsICS(VisualBasic6Parser::VsICSContext *context) = 0;

    virtual antlrcpp::Any visitVsNeq(VisualBasic6Parser::VsNeqContext *context) = 0;

    virtual antlrcpp::Any visitVsXor(VisualBasic6Parser::VsXorContext *context) = 0;

    virtual antlrcpp::Any visitVsAnd(VisualBasic6Parser::VsAndContext *context) = 0;

    virtual antlrcpp::Any visitVsPow(VisualBasic6Parser::VsPowContext *context) = 0;

    virtual antlrcpp::Any visitVsLeq(VisualBasic6Parser::VsLeqContext *context) = 0;

    virtual antlrcpp::Any visitVsIs(VisualBasic6Parser::VsIsContext *context) = 0;

    virtual antlrcpp::Any visitVsMod(VisualBasic6Parser::VsModContext *context) = 0;

    virtual antlrcpp::Any visitVsAmp(VisualBasic6Parser::VsAmpContext *context) = 0;

    virtual antlrcpp::Any visitVsOr(VisualBasic6Parser::VsOrContext *context) = 0;

    virtual antlrcpp::Any visitVsMinus(VisualBasic6Parser::VsMinusContext *context) = 0;

    virtual antlrcpp::Any visitVsLiteral(VisualBasic6Parser::VsLiteralContext *context) = 0;

    virtual antlrcpp::Any visitVsEqv(VisualBasic6Parser::VsEqvContext *context) = 0;

    virtual antlrcpp::Any visitVsImp(VisualBasic6Parser::VsImpContext *context) = 0;

    virtual antlrcpp::Any visitVsGt(VisualBasic6Parser::VsGtContext *context) = 0;

    virtual antlrcpp::Any visitVsEq(VisualBasic6Parser::VsEqContext *context) = 0;

    virtual antlrcpp::Any visitVsMid(VisualBasic6Parser::VsMidContext *context) = 0;

    virtual antlrcpp::Any visitVariableStmt(VisualBasic6Parser::VariableStmtContext *context) = 0;

    virtual antlrcpp::Any visitVariableListStmt(VisualBasic6Parser::VariableListStmtContext *context) = 0;

    virtual antlrcpp::Any visitVariableSubStmt(VisualBasic6Parser::VariableSubStmtContext *context) = 0;

    virtual antlrcpp::Any visitWhileWendStmt(VisualBasic6Parser::WhileWendStmtContext *context) = 0;

    virtual antlrcpp::Any visitWidthStmt(VisualBasic6Parser::WidthStmtContext *context) = 0;

    virtual antlrcpp::Any visitWithStmt(VisualBasic6Parser::WithStmtContext *context) = 0;

    virtual antlrcpp::Any visitWriteStmt(VisualBasic6Parser::WriteStmtContext *context) = 0;

    virtual antlrcpp::Any visitExplicitCallStmt(VisualBasic6Parser::ExplicitCallStmtContext *context) = 0;

    virtual antlrcpp::Any visitECS_ProcedureCall(VisualBasic6Parser::ECS_ProcedureCallContext *context) = 0;

    virtual antlrcpp::Any visitECS_MemberProcedureCall(VisualBasic6Parser::ECS_MemberProcedureCallContext *context) = 0;

    virtual antlrcpp::Any visitImplicitCallStmt_InBlock(VisualBasic6Parser::ImplicitCallStmt_InBlockContext *context) = 0;

    virtual antlrcpp::Any visitICS_B_ProcedureCall(VisualBasic6Parser::ICS_B_ProcedureCallContext *context) = 0;

    virtual antlrcpp::Any visitICS_B_MemberProcedureCall(VisualBasic6Parser::ICS_B_MemberProcedureCallContext *context) = 0;

    virtual antlrcpp::Any visitImplicitCallStmt_InStmt(VisualBasic6Parser::ImplicitCallStmt_InStmtContext *context) = 0;

    virtual antlrcpp::Any visitICS_S_VariableOrProcedureCall(VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext *context) = 0;

    virtual antlrcpp::Any visitICS_S_ProcedureOrArrayCall(VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext *context) = 0;

    virtual antlrcpp::Any visitICS_S_NestedProcedureCall(VisualBasic6Parser::ICS_S_NestedProcedureCallContext *context) = 0;

    virtual antlrcpp::Any visitICS_S_MembersCall(VisualBasic6Parser::ICS_S_MembersCallContext *context) = 0;

    virtual antlrcpp::Any visitICS_S_MemberCall(VisualBasic6Parser::ICS_S_MemberCallContext *context) = 0;

    virtual antlrcpp::Any visitICS_S_DictionaryCall(VisualBasic6Parser::ICS_S_DictionaryCallContext *context) = 0;

    virtual antlrcpp::Any visitArgsCall(VisualBasic6Parser::ArgsCallContext *context) = 0;

    virtual antlrcpp::Any visitArgCall(VisualBasic6Parser::ArgCallContext *context) = 0;

    virtual antlrcpp::Any visitDictionaryCallStmt(VisualBasic6Parser::DictionaryCallStmtContext *context) = 0;

    virtual antlrcpp::Any visitArgList(VisualBasic6Parser::ArgListContext *context) = 0;

    virtual antlrcpp::Any visitArg(VisualBasic6Parser::ArgContext *context) = 0;

    virtual antlrcpp::Any visitArgDefaultValue(VisualBasic6Parser::ArgDefaultValueContext *context) = 0;

    virtual antlrcpp::Any visitSubscripts(VisualBasic6Parser::SubscriptsContext *context) = 0;

    virtual antlrcpp::Any visitSubscript(VisualBasic6Parser::SubscriptContext *context) = 0;

    virtual antlrcpp::Any visitAmbiguousIdentifier(VisualBasic6Parser::AmbiguousIdentifierContext *context) = 0;

    virtual antlrcpp::Any visitAsTypeClause(VisualBasic6Parser::AsTypeClauseContext *context) = 0;

    virtual antlrcpp::Any visitBaseType(VisualBasic6Parser::BaseTypeContext *context) = 0;

    virtual antlrcpp::Any visitCertainIdentifier(VisualBasic6Parser::CertainIdentifierContext *context) = 0;

    virtual antlrcpp::Any visitComparisonOperator(VisualBasic6Parser::ComparisonOperatorContext *context) = 0;

    virtual antlrcpp::Any visitComplexType(VisualBasic6Parser::ComplexTypeContext *context) = 0;

    virtual antlrcpp::Any visitFieldLength(VisualBasic6Parser::FieldLengthContext *context) = 0;

    virtual antlrcpp::Any visitLetterrange(VisualBasic6Parser::LetterrangeContext *context) = 0;

    virtual antlrcpp::Any visitLineLabel(VisualBasic6Parser::LineLabelContext *context) = 0;

    virtual antlrcpp::Any visitLiteral(VisualBasic6Parser::LiteralContext *context) = 0;

    virtual antlrcpp::Any visitPublicPrivateVisibility(VisualBasic6Parser::PublicPrivateVisibilityContext *context) = 0;

    virtual antlrcpp::Any visitPublicPrivateGlobalVisibility(VisualBasic6Parser::PublicPrivateGlobalVisibilityContext *context) = 0;

    virtual antlrcpp::Any visitType(VisualBasic6Parser::TypeContext *context) = 0;

    virtual antlrcpp::Any visitTypeHint(VisualBasic6Parser::TypeHintContext *context) = 0;

    virtual antlrcpp::Any visitVisibility(VisualBasic6Parser::VisibilityContext *context) = 0;

    virtual antlrcpp::Any visitAmbiguousKeyword(VisualBasic6Parser::AmbiguousKeywordContext *context) = 0;


};

