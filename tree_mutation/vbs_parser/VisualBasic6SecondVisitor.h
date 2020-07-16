
// Generated from C:\Users\xiang\Desktop\vbs_parser\VisualBasic6.g4 by ANTLR 4.7

#pragma once

#include <iostream>
#include <vector>
#include "antlr4-runtime.h"
#include "VisualBasic6Visitor.h"

using namespace std;

/**
 * This class provides an empty implementation of VisualBasic6Visitor, which can be
 * extended to create a visitor which only needs to handle a subset of the available methods.
 */
class  VisualBasic6SecondVisitor : public VisualBasic6Visitor {
public:

  vector<string> texts;

  virtual antlrcpp::Any visitStartRule(VisualBasic6Parser::StartRuleContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitModule(VisualBasic6Parser::ModuleContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitModuleReferences(VisualBasic6Parser::ModuleReferencesContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitModuleReference(VisualBasic6Parser::ModuleReferenceContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitModuleReferenceValue(VisualBasic6Parser::ModuleReferenceValueContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitModuleReferenceComponent(VisualBasic6Parser::ModuleReferenceComponentContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitModuleHeader(VisualBasic6Parser::ModuleHeaderContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitModuleConfig(VisualBasic6Parser::ModuleConfigContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitModuleConfigElement(VisualBasic6Parser::ModuleConfigElementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitModuleAttributes(VisualBasic6Parser::ModuleAttributesContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitModuleOptions(VisualBasic6Parser::ModuleOptionsContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitOptionBaseStmt(VisualBasic6Parser::OptionBaseStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitOptionCompareStmt(VisualBasic6Parser::OptionCompareStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitOptionExplicitStmt(VisualBasic6Parser::OptionExplicitStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitOptionPrivateModuleStmt(VisualBasic6Parser::OptionPrivateModuleStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitModuleBody(VisualBasic6Parser::ModuleBodyContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitModuleBodyElement(VisualBasic6Parser::ModuleBodyElementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitControlProperties(VisualBasic6Parser::ControlPropertiesContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCp_Properties(VisualBasic6Parser::Cp_PropertiesContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCp_SingleProperty(VisualBasic6Parser::Cp_SinglePropertyContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCp_PropertyName(VisualBasic6Parser::Cp_PropertyNameContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCp_PropertyValue(VisualBasic6Parser::Cp_PropertyValueContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCp_NestedProperty(VisualBasic6Parser::Cp_NestedPropertyContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCp_ControlType(VisualBasic6Parser::Cp_ControlTypeContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCp_ControlIdentifier(VisualBasic6Parser::Cp_ControlIdentifierContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitModuleBlock(VisualBasic6Parser::ModuleBlockContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAttributeStmt(VisualBasic6Parser::AttributeStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBlock(VisualBasic6Parser::BlockContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBlockStmt(VisualBasic6Parser::BlockStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAppActivateStmt(VisualBasic6Parser::AppActivateStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBeepStmt(VisualBasic6Parser::BeepStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitChDirStmt(VisualBasic6Parser::ChDirStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitChDriveStmt(VisualBasic6Parser::ChDriveStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCloseStmt(VisualBasic6Parser::CloseStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitConstStmt(VisualBasic6Parser::ConstStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitConstSubStmt(VisualBasic6Parser::ConstSubStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDateStmt(VisualBasic6Parser::DateStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDeclareStmt(VisualBasic6Parser::DeclareStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDeftypeStmt(VisualBasic6Parser::DeftypeStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDeleteSettingStmt(VisualBasic6Parser::DeleteSettingStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDoLoopStmt(VisualBasic6Parser::DoLoopStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitEndStmt(VisualBasic6Parser::EndStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitEnumerationStmt(VisualBasic6Parser::EnumerationStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitEnumerationStmt_Constant(VisualBasic6Parser::EnumerationStmt_ConstantContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitEraseStmt(VisualBasic6Parser::EraseStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitErrorStmt(VisualBasic6Parser::ErrorStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitEventStmt(VisualBasic6Parser::EventStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitExitStmt(VisualBasic6Parser::ExitStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFilecopyStmt(VisualBasic6Parser::FilecopyStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForEachStmt(VisualBasic6Parser::ForEachStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitForNextStmt(VisualBasic6Parser::ForNextStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFunctionStmt(VisualBasic6Parser::FunctionStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitGetStmt(VisualBasic6Parser::GetStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitGoSubStmt(VisualBasic6Parser::GoSubStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitGoToStmt(VisualBasic6Parser::GoToStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitInlineIfThenElse(VisualBasic6Parser::InlineIfThenElseContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBlockIfThenElse(VisualBasic6Parser::BlockIfThenElseContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitIfBlockStmt(VisualBasic6Parser::IfBlockStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitIfConditionStmt(VisualBasic6Parser::IfConditionStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitIfElseIfBlockStmt(VisualBasic6Parser::IfElseIfBlockStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitIfElseBlockStmt(VisualBasic6Parser::IfElseBlockStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitImplementsStmt(VisualBasic6Parser::ImplementsStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitInputStmt(VisualBasic6Parser::InputStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitKillStmt(VisualBasic6Parser::KillStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLetStmt(VisualBasic6Parser::LetStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLineInputStmt(VisualBasic6Parser::LineInputStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLoadStmt(VisualBasic6Parser::LoadStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLockStmt(VisualBasic6Parser::LockStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLsetStmt(VisualBasic6Parser::LsetStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMacroIfThenElseStmt(VisualBasic6Parser::MacroIfThenElseStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMacroIfBlockStmt(VisualBasic6Parser::MacroIfBlockStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMacroElseIfBlockStmt(VisualBasic6Parser::MacroElseIfBlockStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMacroElseBlockStmt(VisualBasic6Parser::MacroElseBlockStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMidStmt(VisualBasic6Parser::MidStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMkdirStmt(VisualBasic6Parser::MkdirStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitNameStmt(VisualBasic6Parser::NameStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitOnErrorStmt(VisualBasic6Parser::OnErrorStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitOnGoToStmt(VisualBasic6Parser::OnGoToStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitOnGoSubStmt(VisualBasic6Parser::OnGoSubStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitOpenStmt(VisualBasic6Parser::OpenStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitOutputList(VisualBasic6Parser::OutputListContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitOutputList_Expression(VisualBasic6Parser::OutputList_ExpressionContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPrintStmt(VisualBasic6Parser::PrintStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertyGetStmt(VisualBasic6Parser::PropertyGetStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertySetStmt(VisualBasic6Parser::PropertySetStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPropertyLetStmt(VisualBasic6Parser::PropertyLetStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPutStmt(VisualBasic6Parser::PutStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitRaiseEventStmt(VisualBasic6Parser::RaiseEventStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitRandomizeStmt(VisualBasic6Parser::RandomizeStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitRedimStmt(VisualBasic6Parser::RedimStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitRedimSubStmt(VisualBasic6Parser::RedimSubStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitResetStmt(VisualBasic6Parser::ResetStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitResumeStmt(VisualBasic6Parser::ResumeStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitReturnStmt(VisualBasic6Parser::ReturnStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitRmdirStmt(VisualBasic6Parser::RmdirStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitRsetStmt(VisualBasic6Parser::RsetStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSavepictureStmt(VisualBasic6Parser::SavepictureStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSaveSettingStmt(VisualBasic6Parser::SaveSettingStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSeekStmt(VisualBasic6Parser::SeekStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSelectCaseStmt(VisualBasic6Parser::SelectCaseStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSC_Case(VisualBasic6Parser::SC_CaseContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCaseCondElse(VisualBasic6Parser::CaseCondElseContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCaseCondExpr(VisualBasic6Parser::CaseCondExprContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCaseCondExprIs(VisualBasic6Parser::CaseCondExprIsContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCaseCondExprValue(VisualBasic6Parser::CaseCondExprValueContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCaseCondExprTo(VisualBasic6Parser::CaseCondExprToContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSendkeysStmt(VisualBasic6Parser::SendkeysStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSetattrStmt(VisualBasic6Parser::SetattrStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSetStmt(VisualBasic6Parser::SetStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitStopStmt(VisualBasic6Parser::StopStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSubStmt(VisualBasic6Parser::SubStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTimeStmt(VisualBasic6Parser::TimeStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTypeStmt(VisualBasic6Parser::TypeStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTypeStmt_Element(VisualBasic6Parser::TypeStmt_ElementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTypeOfStmt(VisualBasic6Parser::TypeOfStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitUnloadStmt(VisualBasic6Parser::UnloadStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitUnlockStmt(VisualBasic6Parser::UnlockStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsStruct(VisualBasic6Parser::VsStructContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsAdd(VisualBasic6Parser::VsAddContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsLt(VisualBasic6Parser::VsLtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsAddressOf(VisualBasic6Parser::VsAddressOfContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsNew(VisualBasic6Parser::VsNewContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsMult(VisualBasic6Parser::VsMultContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsNegation(VisualBasic6Parser::VsNegationContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsAssign(VisualBasic6Parser::VsAssignContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsDiv(VisualBasic6Parser::VsDivContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsLike(VisualBasic6Parser::VsLikeContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsPlus(VisualBasic6Parser::VsPlusContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsNot(VisualBasic6Parser::VsNotContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsGeq(VisualBasic6Parser::VsGeqContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsTypeOf(VisualBasic6Parser::VsTypeOfContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsICS(VisualBasic6Parser::VsICSContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsNeq(VisualBasic6Parser::VsNeqContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsXor(VisualBasic6Parser::VsXorContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsAnd(VisualBasic6Parser::VsAndContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsPow(VisualBasic6Parser::VsPowContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsLeq(VisualBasic6Parser::VsLeqContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsIs(VisualBasic6Parser::VsIsContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsMod(VisualBasic6Parser::VsModContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsAmp(VisualBasic6Parser::VsAmpContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsOr(VisualBasic6Parser::VsOrContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsMinus(VisualBasic6Parser::VsMinusContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsLiteral(VisualBasic6Parser::VsLiteralContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsEqv(VisualBasic6Parser::VsEqvContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsImp(VisualBasic6Parser::VsImpContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsGt(VisualBasic6Parser::VsGtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsEq(VisualBasic6Parser::VsEqContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVsMid(VisualBasic6Parser::VsMidContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVariableStmt(VisualBasic6Parser::VariableStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVariableListStmt(VisualBasic6Parser::VariableListStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVariableSubStmt(VisualBasic6Parser::VariableSubStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitWhileWendStmt(VisualBasic6Parser::WhileWendStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitWidthStmt(VisualBasic6Parser::WidthStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitWithStmt(VisualBasic6Parser::WithStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitWriteStmt(VisualBasic6Parser::WriteStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitExplicitCallStmt(VisualBasic6Parser::ExplicitCallStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitECS_ProcedureCall(VisualBasic6Parser::ECS_ProcedureCallContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitECS_MemberProcedureCall(VisualBasic6Parser::ECS_MemberProcedureCallContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitImplicitCallStmt_InBlock(VisualBasic6Parser::ImplicitCallStmt_InBlockContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitICS_B_ProcedureCall(VisualBasic6Parser::ICS_B_ProcedureCallContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitICS_B_MemberProcedureCall(VisualBasic6Parser::ICS_B_MemberProcedureCallContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitImplicitCallStmt_InStmt(VisualBasic6Parser::ImplicitCallStmt_InStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitICS_S_VariableOrProcedureCall(VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitICS_S_ProcedureOrArrayCall(VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitICS_S_NestedProcedureCall(VisualBasic6Parser::ICS_S_NestedProcedureCallContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitICS_S_MembersCall(VisualBasic6Parser::ICS_S_MembersCallContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitICS_S_MemberCall(VisualBasic6Parser::ICS_S_MemberCallContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitICS_S_DictionaryCall(VisualBasic6Parser::ICS_S_DictionaryCallContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArgsCall(VisualBasic6Parser::ArgsCallContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArgCall(VisualBasic6Parser::ArgCallContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitDictionaryCallStmt(VisualBasic6Parser::DictionaryCallStmtContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArgList(VisualBasic6Parser::ArgListContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArg(VisualBasic6Parser::ArgContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitArgDefaultValue(VisualBasic6Parser::ArgDefaultValueContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSubscripts(VisualBasic6Parser::SubscriptsContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitSubscript(VisualBasic6Parser::SubscriptContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAmbiguousIdentifier(VisualBasic6Parser::AmbiguousIdentifierContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAsTypeClause(VisualBasic6Parser::AsTypeClauseContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitBaseType(VisualBasic6Parser::BaseTypeContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitCertainIdentifier(VisualBasic6Parser::CertainIdentifierContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitComparisonOperator(VisualBasic6Parser::ComparisonOperatorContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitComplexType(VisualBasic6Parser::ComplexTypeContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitFieldLength(VisualBasic6Parser::FieldLengthContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLetterrange(VisualBasic6Parser::LetterrangeContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLineLabel(VisualBasic6Parser::LineLabelContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitLiteral(VisualBasic6Parser::LiteralContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPublicPrivateVisibility(VisualBasic6Parser::PublicPrivateVisibilityContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitPublicPrivateGlobalVisibility(VisualBasic6Parser::PublicPrivateGlobalVisibilityContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitType(VisualBasic6Parser::TypeContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitTypeHint(VisualBasic6Parser::TypeHintContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitVisibility(VisualBasic6Parser::VisibilityContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAmbiguousKeyword(VisualBasic6Parser::AmbiguousKeywordContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }


};

