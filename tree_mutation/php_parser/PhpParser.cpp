
// Generated from C:\Users\xiang\Documents\GitHub\php_parser\PhpParser.g4 by ANTLR 4.7


#include "PhpParserVisitor.h"

#include "PhpParser.h"


using namespace antlrcpp;
using namespace antlr4;

PhpParser::PhpParser(TokenStream *input) : Parser(input) {
  _interpreter = new atn::ParserATNSimulator(this, _atn, _decisionToDFA, _sharedContextCache);
}

PhpParser::~PhpParser() {
  delete _interpreter;
}

std::string PhpParser::getGrammarFileName() const {
  return "PhpParser.g4";
}

const std::vector<std::string>& PhpParser::getRuleNames() const {
  return _ruleNames;
}

dfa::Vocabulary& PhpParser::getVocabulary() const {
  return _vocabulary;
}


//----------------- PhpBlockContext ------------------------------------------------------------------

PhpParser::PhpBlockContext::PhpBlockContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::ImportStatementContext *> PhpParser::PhpBlockContext::importStatement() {
  return getRuleContexts<PhpParser::ImportStatementContext>();
}

PhpParser::ImportStatementContext* PhpParser::PhpBlockContext::importStatement(size_t i) {
  return getRuleContext<PhpParser::ImportStatementContext>(i);
}

std::vector<PhpParser::TopStatementContext *> PhpParser::PhpBlockContext::topStatement() {
  return getRuleContexts<PhpParser::TopStatementContext>();
}

PhpParser::TopStatementContext* PhpParser::PhpBlockContext::topStatement(size_t i) {
  return getRuleContext<PhpParser::TopStatementContext>(i);
}


size_t PhpParser::PhpBlockContext::getRuleIndex() const {
  return PhpParser::RulePhpBlock;
}

antlrcpp::Any PhpParser::PhpBlockContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitPhpBlock(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::PhpBlockContext* PhpParser::phpBlock() {
  PhpBlockContext *_localctx = _tracker.createInstance<PhpBlockContext>(_ctx, getState());
  enterRule(_localctx, 0, PhpParser::RulePhpBlock);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(247);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 0, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(244);
        importStatement(); 
      }
      setState(249);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 0, _ctx);
    }
    setState(251); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(250);
      topStatement();
      setState(253); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
      | (1ULL << PhpParser::Array)
      | (1ULL << PhpParser::As)
      | (1ULL << PhpParser::BinaryCast)
      | (1ULL << PhpParser::BoolType)
      | (1ULL << PhpParser::BooleanConstant)
      | (1ULL << PhpParser::Break)
      | (1ULL << PhpParser::Callable)
      | (1ULL << PhpParser::Case)
      | (1ULL << PhpParser::Catch)
      | (1ULL << PhpParser::Class)
      | (1ULL << PhpParser::Clone)
      | (1ULL << PhpParser::Const)
      | (1ULL << PhpParser::Continue)
      | (1ULL << PhpParser::Declare)
      | (1ULL << PhpParser::Default)
      | (1ULL << PhpParser::Do)
      | (1ULL << PhpParser::DoubleCast)
      | (1ULL << PhpParser::DoubleType)
      | (1ULL << PhpParser::Echo)
      | (1ULL << PhpParser::Else)
      | (1ULL << PhpParser::ElseIf)
      | (1ULL << PhpParser::Empty)
      | (1ULL << PhpParser::EndDeclare)
      | (1ULL << PhpParser::EndFor)
      | (1ULL << PhpParser::EndForeach)
      | (1ULL << PhpParser::EndIf)
      | (1ULL << PhpParser::EndSwitch)
      | (1ULL << PhpParser::EndWhile)
      | (1ULL << PhpParser::Eval)
      | (1ULL << PhpParser::Exit)
      | (1ULL << PhpParser::Extends)
      | (1ULL << PhpParser::Final)
      | (1ULL << PhpParser::Finally)
      | (1ULL << PhpParser::FloatCast)
      | (1ULL << PhpParser::For)
      | (1ULL << PhpParser::Foreach)
      | (1ULL << PhpParser::Function)
      | (1ULL << PhpParser::Global)
      | (1ULL << PhpParser::Goto)
      | (1ULL << PhpParser::If)
      | (1ULL << PhpParser::Implements)
      | (1ULL << PhpParser::Import)
      | (1ULL << PhpParser::Include)
      | (1ULL << PhpParser::IncludeOnce)
      | (1ULL << PhpParser::InstanceOf)
      | (1ULL << PhpParser::InsteadOf)
      | (1ULL << PhpParser::Int8Cast)
      | (1ULL << PhpParser::Int16Cast)
      | (1ULL << PhpParser::Int64Type)
      | (1ULL << PhpParser::IntType)
      | (1ULL << PhpParser::Interface)
      | (1ULL << PhpParser::IsSet)
      | (1ULL << PhpParser::List)
      | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
      | (1ULL << (PhpParser::LogicalXor - 64))
      | (1ULL << (PhpParser::Namespace - 64))
      | (1ULL << (PhpParser::New - 64))
      | (1ULL << (PhpParser::Null - 64))
      | (1ULL << (PhpParser::ObjectType - 64))
      | (1ULL << (PhpParser::Parent_ - 64))
      | (1ULL << (PhpParser::Partial - 64))
      | (1ULL << (PhpParser::Print - 64))
      | (1ULL << (PhpParser::Private - 64))
      | (1ULL << (PhpParser::Protected - 64))
      | (1ULL << (PhpParser::Public - 64))
      | (1ULL << (PhpParser::Require - 64))
      | (1ULL << (PhpParser::RequireOnce - 64))
      | (1ULL << (PhpParser::Resource - 64))
      | (1ULL << (PhpParser::Return - 64))
      | (1ULL << (PhpParser::Static - 64))
      | (1ULL << (PhpParser::StringType - 64))
      | (1ULL << (PhpParser::Switch - 64))
      | (1ULL << (PhpParser::Throw - 64))
      | (1ULL << (PhpParser::Trait - 64))
      | (1ULL << (PhpParser::Try - 64))
      | (1ULL << (PhpParser::Typeof - 64))
      | (1ULL << (PhpParser::UintCast - 64))
      | (1ULL << (PhpParser::UnicodeCast - 64))
      | (1ULL << (PhpParser::Unset - 64))
      | (1ULL << (PhpParser::Use - 64))
      | (1ULL << (PhpParser::Var - 64))
      | (1ULL << (PhpParser::While - 64))
      | (1ULL << (PhpParser::Yield - 64))
      | (1ULL << (PhpParser::Get - 64))
      | (1ULL << (PhpParser::Set - 64))
      | (1ULL << (PhpParser::Call - 64))
      | (1ULL << (PhpParser::CallStatic - 64))
      | (1ULL << (PhpParser::Constructor - 64))
      | (1ULL << (PhpParser::Destruct - 64))
      | (1ULL << (PhpParser::Wakeup - 64))
      | (1ULL << (PhpParser::Sleep - 64))
      | (1ULL << (PhpParser::Autoload - 64))
      | (1ULL << (PhpParser::IsSet__ - 64))
      | (1ULL << (PhpParser::Unset__ - 64))
      | (1ULL << (PhpParser::ToString__ - 64))
      | (1ULL << (PhpParser::Invoke - 64))
      | (1ULL << (PhpParser::SetState - 64))
      | (1ULL << (PhpParser::Clone__ - 64))
      | (1ULL << (PhpParser::DebugInfo - 64))
      | (1ULL << (PhpParser::Namespace__ - 64))
      | (1ULL << (PhpParser::Class__ - 64))
      | (1ULL << (PhpParser::Traic__ - 64))
      | (1ULL << (PhpParser::Function__ - 64))
      | (1ULL << (PhpParser::Method__ - 64))
      | (1ULL << (PhpParser::Line__ - 64))
      | (1ULL << (PhpParser::File__ - 64))
      | (1ULL << (PhpParser::Dir__ - 64))
      | (1ULL << (PhpParser::Inc - 64))
      | (1ULL << (PhpParser::Dec - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
      | (1ULL << (PhpParser::Bang - 148))
      | (1ULL << (PhpParser::Plus - 148))
      | (1ULL << (PhpParser::Minus - 148))
      | (1ULL << (PhpParser::Tilde - 148))
      | (1ULL << (PhpParser::SuppressWarnings - 148))
      | (1ULL << (PhpParser::Dollar - 148))
      | (1ULL << (PhpParser::OpenRoundBracket - 148))
      | (1ULL << (PhpParser::OpenSquareBracket - 148))
      | (1ULL << (PhpParser::OpenCurlyBracket - 148))
      | (1ULL << (PhpParser::SemiColon - 148))
      | (1ULL << (PhpParser::VarName - 148))
      | (1ULL << (PhpParser::Label - 148))
      | (1ULL << (PhpParser::Octal - 148))
      | (1ULL << (PhpParser::Decimal - 148))
      | (1ULL << (PhpParser::Real - 148))
      | (1ULL << (PhpParser::Hex - 148))
      | (1ULL << (PhpParser::Binary - 148))
      | (1ULL << (PhpParser::BackQuoteString - 148))
      | (1ULL << (PhpParser::SingleQuoteString - 148))
      | (1ULL << (PhpParser::DoubleQuote - 148))
      | (1ULL << (PhpParser::StartNowDoc - 148))
      | (1ULL << (PhpParser::StartHereDoc - 148)))) != 0));
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ImportStatementContext ------------------------------------------------------------------

PhpParser::ImportStatementContext::ImportStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::ImportStatementContext::Import() {
  return getToken(PhpParser::Import, 0);
}

tree::TerminalNode* PhpParser::ImportStatementContext::Namespace() {
  return getToken(PhpParser::Namespace, 0);
}

PhpParser::NamespaceNameListContext* PhpParser::ImportStatementContext::namespaceNameList() {
  return getRuleContext<PhpParser::NamespaceNameListContext>(0);
}


size_t PhpParser::ImportStatementContext::getRuleIndex() const {
  return PhpParser::RuleImportStatement;
}

antlrcpp::Any PhpParser::ImportStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitImportStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ImportStatementContext* PhpParser::importStatement() {
  ImportStatementContext *_localctx = _tracker.createInstance<ImportStatementContext>(_ctx, getState());
  enterRule(_localctx, 2, PhpParser::RuleImportStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(255);
    match(PhpParser::Import);
    setState(256);
    match(PhpParser::Namespace);
    setState(257);
    namespaceNameList();
    setState(258);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TopStatementContext ------------------------------------------------------------------

PhpParser::TopStatementContext::TopStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::StatementContext* PhpParser::TopStatementContext::statement() {
  return getRuleContext<PhpParser::StatementContext>(0);
}

PhpParser::UseDeclarationContext* PhpParser::TopStatementContext::useDeclaration() {
  return getRuleContext<PhpParser::UseDeclarationContext>(0);
}

PhpParser::NamespaceDeclarationContext* PhpParser::TopStatementContext::namespaceDeclaration() {
  return getRuleContext<PhpParser::NamespaceDeclarationContext>(0);
}

PhpParser::FunctionDeclarationContext* PhpParser::TopStatementContext::functionDeclaration() {
  return getRuleContext<PhpParser::FunctionDeclarationContext>(0);
}

PhpParser::ClassDeclarationContext* PhpParser::TopStatementContext::classDeclaration() {
  return getRuleContext<PhpParser::ClassDeclarationContext>(0);
}

PhpParser::GlobalConstantDeclarationContext* PhpParser::TopStatementContext::globalConstantDeclaration() {
  return getRuleContext<PhpParser::GlobalConstantDeclarationContext>(0);
}


size_t PhpParser::TopStatementContext::getRuleIndex() const {
  return PhpParser::RuleTopStatement;
}

antlrcpp::Any PhpParser::TopStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitTopStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::TopStatementContext* PhpParser::topStatement() {
  TopStatementContext *_localctx = _tracker.createInstance<TopStatementContext>(_ctx, getState());
  enterRule(_localctx, 4, PhpParser::RuleTopStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(266);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 2, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(260);
      statement();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(261);
      useDeclaration();
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(262);
      namespaceDeclaration();
      break;
    }

    case 4: {
      enterOuterAlt(_localctx, 4);
      setState(263);
      functionDeclaration();
      break;
    }

    case 5: {
      enterOuterAlt(_localctx, 5);
      setState(264);
      classDeclaration();
      break;
    }

    case 6: {
      enterOuterAlt(_localctx, 6);
      setState(265);
      globalConstantDeclaration();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- UseDeclarationContext ------------------------------------------------------------------

PhpParser::UseDeclarationContext::UseDeclarationContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::UseDeclarationContext::Use() {
  return getToken(PhpParser::Use, 0);
}

PhpParser::UseDeclarationContentListContext* PhpParser::UseDeclarationContext::useDeclarationContentList() {
  return getRuleContext<PhpParser::UseDeclarationContentListContext>(0);
}

tree::TerminalNode* PhpParser::UseDeclarationContext::Function() {
  return getToken(PhpParser::Function, 0);
}

tree::TerminalNode* PhpParser::UseDeclarationContext::Const() {
  return getToken(PhpParser::Const, 0);
}


size_t PhpParser::UseDeclarationContext::getRuleIndex() const {
  return PhpParser::RuleUseDeclaration;
}

antlrcpp::Any PhpParser::UseDeclarationContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitUseDeclaration(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::UseDeclarationContext* PhpParser::useDeclaration() {
  UseDeclarationContext *_localctx = _tracker.createInstance<UseDeclarationContext>(_ctx, getState());
  enterRule(_localctx, 6, PhpParser::RuleUseDeclaration);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(268);
    match(PhpParser::Use);
    setState(270);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 3, _ctx)) {
    case 1: {
      setState(269);
      _la = _input->LA(1);
      if (!(_la == PhpParser::Const

      || _la == PhpParser::Function)) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      break;
    }

    }
    setState(272);
    useDeclarationContentList();
    setState(273);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- UseDeclarationContentListContext ------------------------------------------------------------------

PhpParser::UseDeclarationContentListContext::UseDeclarationContentListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::UseDeclarationContentContext *> PhpParser::UseDeclarationContentListContext::useDeclarationContent() {
  return getRuleContexts<PhpParser::UseDeclarationContentContext>();
}

PhpParser::UseDeclarationContentContext* PhpParser::UseDeclarationContentListContext::useDeclarationContent(size_t i) {
  return getRuleContext<PhpParser::UseDeclarationContentContext>(i);
}


size_t PhpParser::UseDeclarationContentListContext::getRuleIndex() const {
  return PhpParser::RuleUseDeclarationContentList;
}

antlrcpp::Any PhpParser::UseDeclarationContentListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitUseDeclarationContentList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::UseDeclarationContentListContext* PhpParser::useDeclarationContentList() {
  UseDeclarationContentListContext *_localctx = _tracker.createInstance<UseDeclarationContentListContext>(_ctx, getState());
  enterRule(_localctx, 8, PhpParser::RuleUseDeclarationContentList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(276);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::NamespaceSeparator) {
      setState(275);
      match(PhpParser::NamespaceSeparator);
    }
    setState(278);
    useDeclarationContent();
    setState(286);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(279);
      match(PhpParser::Comma);
      setState(281);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == PhpParser::NamespaceSeparator) {
        setState(280);
        match(PhpParser::NamespaceSeparator);
      }
      setState(283);
      useDeclarationContent();
      setState(288);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- UseDeclarationContentContext ------------------------------------------------------------------

PhpParser::UseDeclarationContentContext::UseDeclarationContentContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::NamespaceNameListContext* PhpParser::UseDeclarationContentContext::namespaceNameList() {
  return getRuleContext<PhpParser::NamespaceNameListContext>(0);
}

tree::TerminalNode* PhpParser::UseDeclarationContentContext::As() {
  return getToken(PhpParser::As, 0);
}

PhpParser::IdentifierContext* PhpParser::UseDeclarationContentContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}


size_t PhpParser::UseDeclarationContentContext::getRuleIndex() const {
  return PhpParser::RuleUseDeclarationContent;
}

antlrcpp::Any PhpParser::UseDeclarationContentContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitUseDeclarationContent(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::UseDeclarationContentContext* PhpParser::useDeclarationContent() {
  UseDeclarationContentContext *_localctx = _tracker.createInstance<UseDeclarationContentContext>(_ctx, getState());
  enterRule(_localctx, 10, PhpParser::RuleUseDeclarationContent);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(289);
    namespaceNameList();
    setState(292);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::As) {
      setState(290);
      match(PhpParser::As);
      setState(291);
      identifier();
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- NamespaceDeclarationContext ------------------------------------------------------------------

PhpParser::NamespaceDeclarationContext::NamespaceDeclarationContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::NamespaceDeclarationContext::Namespace() {
  return getToken(PhpParser::Namespace, 0);
}

tree::TerminalNode* PhpParser::NamespaceDeclarationContext::OpenCurlyBracket() {
  return getToken(PhpParser::OpenCurlyBracket, 0);
}

PhpParser::NamespaceNameListContext* PhpParser::NamespaceDeclarationContext::namespaceNameList() {
  return getRuleContext<PhpParser::NamespaceNameListContext>(0);
}

std::vector<PhpParser::NamespaceStatementContext *> PhpParser::NamespaceDeclarationContext::namespaceStatement() {
  return getRuleContexts<PhpParser::NamespaceStatementContext>();
}

PhpParser::NamespaceStatementContext* PhpParser::NamespaceDeclarationContext::namespaceStatement(size_t i) {
  return getRuleContext<PhpParser::NamespaceStatementContext>(i);
}


size_t PhpParser::NamespaceDeclarationContext::getRuleIndex() const {
  return PhpParser::RuleNamespaceDeclaration;
}

antlrcpp::Any PhpParser::NamespaceDeclarationContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitNamespaceDeclaration(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::NamespaceDeclarationContext* PhpParser::namespaceDeclaration() {
  NamespaceDeclarationContext *_localctx = _tracker.createInstance<NamespaceDeclarationContext>(_ctx, getState());
  enterRule(_localctx, 12, PhpParser::RuleNamespaceDeclaration);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(294);
    match(PhpParser::Namespace);
    setState(309);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 10, _ctx)) {
    case 1: {
      setState(296);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
        | (1ULL << PhpParser::Array)
        | (1ULL << PhpParser::As)
        | (1ULL << PhpParser::BinaryCast)
        | (1ULL << PhpParser::BoolType)
        | (1ULL << PhpParser::BooleanConstant)
        | (1ULL << PhpParser::Break)
        | (1ULL << PhpParser::Callable)
        | (1ULL << PhpParser::Case)
        | (1ULL << PhpParser::Catch)
        | (1ULL << PhpParser::Class)
        | (1ULL << PhpParser::Clone)
        | (1ULL << PhpParser::Const)
        | (1ULL << PhpParser::Continue)
        | (1ULL << PhpParser::Declare)
        | (1ULL << PhpParser::Default)
        | (1ULL << PhpParser::Do)
        | (1ULL << PhpParser::DoubleCast)
        | (1ULL << PhpParser::DoubleType)
        | (1ULL << PhpParser::Echo)
        | (1ULL << PhpParser::Else)
        | (1ULL << PhpParser::ElseIf)
        | (1ULL << PhpParser::Empty)
        | (1ULL << PhpParser::EndDeclare)
        | (1ULL << PhpParser::EndFor)
        | (1ULL << PhpParser::EndForeach)
        | (1ULL << PhpParser::EndIf)
        | (1ULL << PhpParser::EndSwitch)
        | (1ULL << PhpParser::EndWhile)
        | (1ULL << PhpParser::Eval)
        | (1ULL << PhpParser::Exit)
        | (1ULL << PhpParser::Extends)
        | (1ULL << PhpParser::Final)
        | (1ULL << PhpParser::Finally)
        | (1ULL << PhpParser::FloatCast)
        | (1ULL << PhpParser::For)
        | (1ULL << PhpParser::Foreach)
        | (1ULL << PhpParser::Function)
        | (1ULL << PhpParser::Global)
        | (1ULL << PhpParser::Goto)
        | (1ULL << PhpParser::If)
        | (1ULL << PhpParser::Implements)
        | (1ULL << PhpParser::Import)
        | (1ULL << PhpParser::Include)
        | (1ULL << PhpParser::IncludeOnce)
        | (1ULL << PhpParser::InstanceOf)
        | (1ULL << PhpParser::InsteadOf)
        | (1ULL << PhpParser::Int8Cast)
        | (1ULL << PhpParser::Int16Cast)
        | (1ULL << PhpParser::Int64Type)
        | (1ULL << PhpParser::IntType)
        | (1ULL << PhpParser::Interface)
        | (1ULL << PhpParser::IsSet)
        | (1ULL << PhpParser::List)
        | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
        | (1ULL << (PhpParser::LogicalXor - 64))
        | (1ULL << (PhpParser::Namespace - 64))
        | (1ULL << (PhpParser::New - 64))
        | (1ULL << (PhpParser::Null - 64))
        | (1ULL << (PhpParser::ObjectType - 64))
        | (1ULL << (PhpParser::Parent_ - 64))
        | (1ULL << (PhpParser::Partial - 64))
        | (1ULL << (PhpParser::Print - 64))
        | (1ULL << (PhpParser::Private - 64))
        | (1ULL << (PhpParser::Protected - 64))
        | (1ULL << (PhpParser::Public - 64))
        | (1ULL << (PhpParser::Require - 64))
        | (1ULL << (PhpParser::RequireOnce - 64))
        | (1ULL << (PhpParser::Resource - 64))
        | (1ULL << (PhpParser::Return - 64))
        | (1ULL << (PhpParser::Static - 64))
        | (1ULL << (PhpParser::StringType - 64))
        | (1ULL << (PhpParser::Switch - 64))
        | (1ULL << (PhpParser::Throw - 64))
        | (1ULL << (PhpParser::Trait - 64))
        | (1ULL << (PhpParser::Try - 64))
        | (1ULL << (PhpParser::Typeof - 64))
        | (1ULL << (PhpParser::UintCast - 64))
        | (1ULL << (PhpParser::UnicodeCast - 64))
        | (1ULL << (PhpParser::Unset - 64))
        | (1ULL << (PhpParser::Use - 64))
        | (1ULL << (PhpParser::Var - 64))
        | (1ULL << (PhpParser::While - 64))
        | (1ULL << (PhpParser::Yield - 64))
        | (1ULL << (PhpParser::Get - 64))
        | (1ULL << (PhpParser::Set - 64))
        | (1ULL << (PhpParser::Call - 64))
        | (1ULL << (PhpParser::CallStatic - 64))
        | (1ULL << (PhpParser::Constructor - 64))
        | (1ULL << (PhpParser::Destruct - 64))
        | (1ULL << (PhpParser::Wakeup - 64))
        | (1ULL << (PhpParser::Sleep - 64))
        | (1ULL << (PhpParser::Autoload - 64))
        | (1ULL << (PhpParser::IsSet__ - 64))
        | (1ULL << (PhpParser::Unset__ - 64))
        | (1ULL << (PhpParser::ToString__ - 64))
        | (1ULL << (PhpParser::Invoke - 64))
        | (1ULL << (PhpParser::SetState - 64))
        | (1ULL << (PhpParser::Clone__ - 64))
        | (1ULL << (PhpParser::DebugInfo - 64))
        | (1ULL << (PhpParser::Namespace__ - 64))
        | (1ULL << (PhpParser::Class__ - 64))
        | (1ULL << (PhpParser::Traic__ - 64))
        | (1ULL << (PhpParser::Function__ - 64))
        | (1ULL << (PhpParser::Method__ - 64))
        | (1ULL << (PhpParser::Line__ - 64))
        | (1ULL << (PhpParser::File__ - 64))
        | (1ULL << (PhpParser::Dir__ - 64)))) != 0) || _la == PhpParser::Label) {
        setState(295);
        namespaceNameList();
      }
      setState(298);
      match(PhpParser::OpenCurlyBracket);
      setState(302);
      _errHandler->sync(this);
      _la = _input->LA(1);
      while ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
        | (1ULL << PhpParser::Array)
        | (1ULL << PhpParser::As)
        | (1ULL << PhpParser::BinaryCast)
        | (1ULL << PhpParser::BoolType)
        | (1ULL << PhpParser::BooleanConstant)
        | (1ULL << PhpParser::Break)
        | (1ULL << PhpParser::Callable)
        | (1ULL << PhpParser::Case)
        | (1ULL << PhpParser::Catch)
        | (1ULL << PhpParser::Class)
        | (1ULL << PhpParser::Clone)
        | (1ULL << PhpParser::Const)
        | (1ULL << PhpParser::Continue)
        | (1ULL << PhpParser::Declare)
        | (1ULL << PhpParser::Default)
        | (1ULL << PhpParser::Do)
        | (1ULL << PhpParser::DoubleCast)
        | (1ULL << PhpParser::DoubleType)
        | (1ULL << PhpParser::Echo)
        | (1ULL << PhpParser::Else)
        | (1ULL << PhpParser::ElseIf)
        | (1ULL << PhpParser::Empty)
        | (1ULL << PhpParser::EndDeclare)
        | (1ULL << PhpParser::EndFor)
        | (1ULL << PhpParser::EndForeach)
        | (1ULL << PhpParser::EndIf)
        | (1ULL << PhpParser::EndSwitch)
        | (1ULL << PhpParser::EndWhile)
        | (1ULL << PhpParser::Eval)
        | (1ULL << PhpParser::Exit)
        | (1ULL << PhpParser::Extends)
        | (1ULL << PhpParser::Final)
        | (1ULL << PhpParser::Finally)
        | (1ULL << PhpParser::FloatCast)
        | (1ULL << PhpParser::For)
        | (1ULL << PhpParser::Foreach)
        | (1ULL << PhpParser::Function)
        | (1ULL << PhpParser::Global)
        | (1ULL << PhpParser::Goto)
        | (1ULL << PhpParser::If)
        | (1ULL << PhpParser::Implements)
        | (1ULL << PhpParser::Import)
        | (1ULL << PhpParser::Include)
        | (1ULL << PhpParser::IncludeOnce)
        | (1ULL << PhpParser::InstanceOf)
        | (1ULL << PhpParser::InsteadOf)
        | (1ULL << PhpParser::Int8Cast)
        | (1ULL << PhpParser::Int16Cast)
        | (1ULL << PhpParser::Int64Type)
        | (1ULL << PhpParser::IntType)
        | (1ULL << PhpParser::Interface)
        | (1ULL << PhpParser::IsSet)
        | (1ULL << PhpParser::List)
        | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
        | (1ULL << (PhpParser::LogicalXor - 64))
        | (1ULL << (PhpParser::Namespace - 64))
        | (1ULL << (PhpParser::New - 64))
        | (1ULL << (PhpParser::Null - 64))
        | (1ULL << (PhpParser::ObjectType - 64))
        | (1ULL << (PhpParser::Parent_ - 64))
        | (1ULL << (PhpParser::Partial - 64))
        | (1ULL << (PhpParser::Print - 64))
        | (1ULL << (PhpParser::Private - 64))
        | (1ULL << (PhpParser::Protected - 64))
        | (1ULL << (PhpParser::Public - 64))
        | (1ULL << (PhpParser::Require - 64))
        | (1ULL << (PhpParser::RequireOnce - 64))
        | (1ULL << (PhpParser::Resource - 64))
        | (1ULL << (PhpParser::Return - 64))
        | (1ULL << (PhpParser::Static - 64))
        | (1ULL << (PhpParser::StringType - 64))
        | (1ULL << (PhpParser::Switch - 64))
        | (1ULL << (PhpParser::Throw - 64))
        | (1ULL << (PhpParser::Trait - 64))
        | (1ULL << (PhpParser::Try - 64))
        | (1ULL << (PhpParser::Typeof - 64))
        | (1ULL << (PhpParser::UintCast - 64))
        | (1ULL << (PhpParser::UnicodeCast - 64))
        | (1ULL << (PhpParser::Unset - 64))
        | (1ULL << (PhpParser::Use - 64))
        | (1ULL << (PhpParser::Var - 64))
        | (1ULL << (PhpParser::While - 64))
        | (1ULL << (PhpParser::Yield - 64))
        | (1ULL << (PhpParser::Get - 64))
        | (1ULL << (PhpParser::Set - 64))
        | (1ULL << (PhpParser::Call - 64))
        | (1ULL << (PhpParser::CallStatic - 64))
        | (1ULL << (PhpParser::Constructor - 64))
        | (1ULL << (PhpParser::Destruct - 64))
        | (1ULL << (PhpParser::Wakeup - 64))
        | (1ULL << (PhpParser::Sleep - 64))
        | (1ULL << (PhpParser::Autoload - 64))
        | (1ULL << (PhpParser::IsSet__ - 64))
        | (1ULL << (PhpParser::Unset__ - 64))
        | (1ULL << (PhpParser::ToString__ - 64))
        | (1ULL << (PhpParser::Invoke - 64))
        | (1ULL << (PhpParser::SetState - 64))
        | (1ULL << (PhpParser::Clone__ - 64))
        | (1ULL << (PhpParser::DebugInfo - 64))
        | (1ULL << (PhpParser::Namespace__ - 64))
        | (1ULL << (PhpParser::Class__ - 64))
        | (1ULL << (PhpParser::Traic__ - 64))
        | (1ULL << (PhpParser::Function__ - 64))
        | (1ULL << (PhpParser::Method__ - 64))
        | (1ULL << (PhpParser::Line__ - 64))
        | (1ULL << (PhpParser::File__ - 64))
        | (1ULL << (PhpParser::Dir__ - 64))
        | (1ULL << (PhpParser::Inc - 64))
        | (1ULL << (PhpParser::Dec - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
        | (1ULL << (PhpParser::Bang - 148))
        | (1ULL << (PhpParser::Plus - 148))
        | (1ULL << (PhpParser::Minus - 148))
        | (1ULL << (PhpParser::Tilde - 148))
        | (1ULL << (PhpParser::SuppressWarnings - 148))
        | (1ULL << (PhpParser::Dollar - 148))
        | (1ULL << (PhpParser::OpenRoundBracket - 148))
        | (1ULL << (PhpParser::OpenSquareBracket - 148))
        | (1ULL << (PhpParser::OpenCurlyBracket - 148))
        | (1ULL << (PhpParser::SemiColon - 148))
        | (1ULL << (PhpParser::VarName - 148))
        | (1ULL << (PhpParser::Label - 148))
        | (1ULL << (PhpParser::Octal - 148))
        | (1ULL << (PhpParser::Decimal - 148))
        | (1ULL << (PhpParser::Real - 148))
        | (1ULL << (PhpParser::Hex - 148))
        | (1ULL << (PhpParser::Binary - 148))
        | (1ULL << (PhpParser::BackQuoteString - 148))
        | (1ULL << (PhpParser::SingleQuoteString - 148))
        | (1ULL << (PhpParser::DoubleQuote - 148))
        | (1ULL << (PhpParser::StartNowDoc - 148))
        | (1ULL << (PhpParser::StartHereDoc - 148)))) != 0)) {
        setState(299);
        namespaceStatement();
        setState(304);
        _errHandler->sync(this);
        _la = _input->LA(1);
      }
      setState(305);
      match(PhpParser::CloseCurlyBracket);
      break;
    }

    case 2: {
      setState(306);
      namespaceNameList();
      setState(307);
      match(PhpParser::SemiColon);
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- NamespaceStatementContext ------------------------------------------------------------------

PhpParser::NamespaceStatementContext::NamespaceStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::StatementContext* PhpParser::NamespaceStatementContext::statement() {
  return getRuleContext<PhpParser::StatementContext>(0);
}

PhpParser::UseDeclarationContext* PhpParser::NamespaceStatementContext::useDeclaration() {
  return getRuleContext<PhpParser::UseDeclarationContext>(0);
}

PhpParser::FunctionDeclarationContext* PhpParser::NamespaceStatementContext::functionDeclaration() {
  return getRuleContext<PhpParser::FunctionDeclarationContext>(0);
}

PhpParser::ClassDeclarationContext* PhpParser::NamespaceStatementContext::classDeclaration() {
  return getRuleContext<PhpParser::ClassDeclarationContext>(0);
}

PhpParser::GlobalConstantDeclarationContext* PhpParser::NamespaceStatementContext::globalConstantDeclaration() {
  return getRuleContext<PhpParser::GlobalConstantDeclarationContext>(0);
}


size_t PhpParser::NamespaceStatementContext::getRuleIndex() const {
  return PhpParser::RuleNamespaceStatement;
}

antlrcpp::Any PhpParser::NamespaceStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitNamespaceStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::NamespaceStatementContext* PhpParser::namespaceStatement() {
  NamespaceStatementContext *_localctx = _tracker.createInstance<NamespaceStatementContext>(_ctx, getState());
  enterRule(_localctx, 14, PhpParser::RuleNamespaceStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(316);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 11, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(311);
      statement();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(312);
      useDeclaration();
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(313);
      functionDeclaration();
      break;
    }

    case 4: {
      enterOuterAlt(_localctx, 4);
      setState(314);
      classDeclaration();
      break;
    }

    case 5: {
      enterOuterAlt(_localctx, 5);
      setState(315);
      globalConstantDeclaration();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- FunctionDeclarationContext ------------------------------------------------------------------

PhpParser::FunctionDeclarationContext::FunctionDeclarationContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::AttributesContext* PhpParser::FunctionDeclarationContext::attributes() {
  return getRuleContext<PhpParser::AttributesContext>(0);
}

tree::TerminalNode* PhpParser::FunctionDeclarationContext::Function() {
  return getToken(PhpParser::Function, 0);
}

PhpParser::IdentifierContext* PhpParser::FunctionDeclarationContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}

PhpParser::FormalParameterListContext* PhpParser::FunctionDeclarationContext::formalParameterList() {
  return getRuleContext<PhpParser::FormalParameterListContext>(0);
}

PhpParser::BlockStatementContext* PhpParser::FunctionDeclarationContext::blockStatement() {
  return getRuleContext<PhpParser::BlockStatementContext>(0);
}

PhpParser::TypeParameterListInBracketsContext* PhpParser::FunctionDeclarationContext::typeParameterListInBrackets() {
  return getRuleContext<PhpParser::TypeParameterListInBracketsContext>(0);
}


size_t PhpParser::FunctionDeclarationContext::getRuleIndex() const {
  return PhpParser::RuleFunctionDeclaration;
}

antlrcpp::Any PhpParser::FunctionDeclarationContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitFunctionDeclaration(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::FunctionDeclarationContext* PhpParser::functionDeclaration() {
  FunctionDeclarationContext *_localctx = _tracker.createInstance<FunctionDeclarationContext>(_ctx, getState());
  enterRule(_localctx, 16, PhpParser::RuleFunctionDeclaration);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(318);
    attributes();
    setState(319);
    match(PhpParser::Function);
    setState(321);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::Ampersand) {
      setState(320);
      match(PhpParser::Ampersand);
    }
    setState(323);
    identifier();
    setState(325);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::Lgeneric) {
      setState(324);
      typeParameterListInBrackets();
    }
    setState(327);
    match(PhpParser::OpenRoundBracket);
    setState(328);
    formalParameterList();
    setState(329);
    match(PhpParser::CloseRoundBracket);
    setState(330);
    blockStatement();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ClassDeclarationContext ------------------------------------------------------------------

PhpParser::ClassDeclarationContext::ClassDeclarationContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::AttributesContext* PhpParser::ClassDeclarationContext::attributes() {
  return getRuleContext<PhpParser::AttributesContext>(0);
}

tree::TerminalNode* PhpParser::ClassDeclarationContext::OpenCurlyBracket() {
  return getToken(PhpParser::OpenCurlyBracket, 0);
}

PhpParser::ClassEntryTypeContext* PhpParser::ClassDeclarationContext::classEntryType() {
  return getRuleContext<PhpParser::ClassEntryTypeContext>(0);
}

PhpParser::IdentifierContext* PhpParser::ClassDeclarationContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}

tree::TerminalNode* PhpParser::ClassDeclarationContext::Interface() {
  return getToken(PhpParser::Interface, 0);
}

tree::TerminalNode* PhpParser::ClassDeclarationContext::Private() {
  return getToken(PhpParser::Private, 0);
}

PhpParser::ModifierContext* PhpParser::ClassDeclarationContext::modifier() {
  return getRuleContext<PhpParser::ModifierContext>(0);
}

tree::TerminalNode* PhpParser::ClassDeclarationContext::Partial() {
  return getToken(PhpParser::Partial, 0);
}

std::vector<PhpParser::ClassStatementContext *> PhpParser::ClassDeclarationContext::classStatement() {
  return getRuleContexts<PhpParser::ClassStatementContext>();
}

PhpParser::ClassStatementContext* PhpParser::ClassDeclarationContext::classStatement(size_t i) {
  return getRuleContext<PhpParser::ClassStatementContext>(i);
}

PhpParser::TypeParameterListInBracketsContext* PhpParser::ClassDeclarationContext::typeParameterListInBrackets() {
  return getRuleContext<PhpParser::TypeParameterListInBracketsContext>(0);
}

tree::TerminalNode* PhpParser::ClassDeclarationContext::Extends() {
  return getToken(PhpParser::Extends, 0);
}

PhpParser::QualifiedStaticTypeRefContext* PhpParser::ClassDeclarationContext::qualifiedStaticTypeRef() {
  return getRuleContext<PhpParser::QualifiedStaticTypeRefContext>(0);
}

tree::TerminalNode* PhpParser::ClassDeclarationContext::Implements() {
  return getToken(PhpParser::Implements, 0);
}

PhpParser::InterfaceListContext* PhpParser::ClassDeclarationContext::interfaceList() {
  return getRuleContext<PhpParser::InterfaceListContext>(0);
}


size_t PhpParser::ClassDeclarationContext::getRuleIndex() const {
  return PhpParser::RuleClassDeclaration;
}

antlrcpp::Any PhpParser::ClassDeclarationContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitClassDeclaration(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ClassDeclarationContext* PhpParser::classDeclaration() {
  ClassDeclarationContext *_localctx = _tracker.createInstance<ClassDeclarationContext>(_ctx, getState());
  enterRule(_localctx, 18, PhpParser::RuleClassDeclaration);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(332);
    attributes();
    setState(334);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::Private) {
      setState(333);
      match(PhpParser::Private);
    }
    setState(337);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::Abstract

    || _la == PhpParser::Final) {
      setState(336);
      modifier();
    }
    setState(340);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::Partial) {
      setState(339);
      match(PhpParser::Partial);
    }
    setState(364);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::Class:
      case PhpParser::Trait: {
        setState(342);
        classEntryType();
        setState(343);
        identifier();
        setState(345);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == PhpParser::Lgeneric) {
          setState(344);
          typeParameterListInBrackets();
        }
        setState(349);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == PhpParser::Extends) {
          setState(347);
          match(PhpParser::Extends);
          setState(348);
          qualifiedStaticTypeRef();
        }
        setState(353);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == PhpParser::Implements) {
          setState(351);
          match(PhpParser::Implements);
          setState(352);
          interfaceList();
        }
        break;
      }

      case PhpParser::Interface: {
        setState(355);
        match(PhpParser::Interface);
        setState(356);
        identifier();
        setState(358);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == PhpParser::Lgeneric) {
          setState(357);
          typeParameterListInBrackets();
        }
        setState(362);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == PhpParser::Extends) {
          setState(360);
          match(PhpParser::Extends);
          setState(361);
          interfaceList();
        }
        break;
      }

    default:
      throw NoViableAltException(this);
    }
    setState(366);
    match(PhpParser::OpenCurlyBracket);
    setState(370);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
      | (1ULL << PhpParser::Const)
      | (1ULL << PhpParser::Final)
      | (1ULL << PhpParser::Function))) != 0) || ((((_la - 73) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 73)) & ((1ULL << (PhpParser::Private - 73))
      | (1ULL << (PhpParser::Protected - 73))
      | (1ULL << (PhpParser::Public - 73))
      | (1ULL << (PhpParser::Static - 73))
      | (1ULL << (PhpParser::Use - 73))
      | (1ULL << (PhpParser::Var - 73)))) != 0) || _la == PhpParser::OpenSquareBracket) {
      setState(367);
      classStatement();
      setState(372);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
    setState(373);
    match(PhpParser::CloseCurlyBracket);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ClassEntryTypeContext ------------------------------------------------------------------

PhpParser::ClassEntryTypeContext::ClassEntryTypeContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::ClassEntryTypeContext::Class() {
  return getToken(PhpParser::Class, 0);
}

tree::TerminalNode* PhpParser::ClassEntryTypeContext::Trait() {
  return getToken(PhpParser::Trait, 0);
}


size_t PhpParser::ClassEntryTypeContext::getRuleIndex() const {
  return PhpParser::RuleClassEntryType;
}

antlrcpp::Any PhpParser::ClassEntryTypeContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitClassEntryType(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ClassEntryTypeContext* PhpParser::classEntryType() {
  ClassEntryTypeContext *_localctx = _tracker.createInstance<ClassEntryTypeContext>(_ctx, getState());
  enterRule(_localctx, 20, PhpParser::RuleClassEntryType);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(375);
    _la = _input->LA(1);
    if (!(_la == PhpParser::Class || _la == PhpParser::Trait)) {
    _errHandler->recoverInline(this);
    }
    else {
      _errHandler->reportMatch(this);
      consume();
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- InterfaceListContext ------------------------------------------------------------------

PhpParser::InterfaceListContext::InterfaceListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::QualifiedStaticTypeRefContext *> PhpParser::InterfaceListContext::qualifiedStaticTypeRef() {
  return getRuleContexts<PhpParser::QualifiedStaticTypeRefContext>();
}

PhpParser::QualifiedStaticTypeRefContext* PhpParser::InterfaceListContext::qualifiedStaticTypeRef(size_t i) {
  return getRuleContext<PhpParser::QualifiedStaticTypeRefContext>(i);
}


size_t PhpParser::InterfaceListContext::getRuleIndex() const {
  return PhpParser::RuleInterfaceList;
}

antlrcpp::Any PhpParser::InterfaceListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitInterfaceList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::InterfaceListContext* PhpParser::interfaceList() {
  InterfaceListContext *_localctx = _tracker.createInstance<InterfaceListContext>(_ctx, getState());
  enterRule(_localctx, 22, PhpParser::RuleInterfaceList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(377);
    qualifiedStaticTypeRef();
    setState(382);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(378);
      match(PhpParser::Comma);
      setState(379);
      qualifiedStaticTypeRef();
      setState(384);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TypeParameterListInBracketsContext ------------------------------------------------------------------

PhpParser::TypeParameterListInBracketsContext::TypeParameterListInBracketsContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::TypeParameterListContext* PhpParser::TypeParameterListInBracketsContext::typeParameterList() {
  return getRuleContext<PhpParser::TypeParameterListContext>(0);
}

PhpParser::TypeParameterWithDefaultsListContext* PhpParser::TypeParameterListInBracketsContext::typeParameterWithDefaultsList() {
  return getRuleContext<PhpParser::TypeParameterWithDefaultsListContext>(0);
}


size_t PhpParser::TypeParameterListInBracketsContext::getRuleIndex() const {
  return PhpParser::RuleTypeParameterListInBrackets;
}

antlrcpp::Any PhpParser::TypeParameterListInBracketsContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitTypeParameterListInBrackets(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::TypeParameterListInBracketsContext* PhpParser::typeParameterListInBrackets() {
  TypeParameterListInBracketsContext *_localctx = _tracker.createInstance<TypeParameterListInBracketsContext>(_ctx, getState());
  enterRule(_localctx, 24, PhpParser::RuleTypeParameterListInBrackets);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(399);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 25, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(385);
      match(PhpParser::Lgeneric);
      setState(386);
      typeParameterList();
      setState(387);
      match(PhpParser::Rgeneric);
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(389);
      match(PhpParser::Lgeneric);
      setState(390);
      typeParameterWithDefaultsList();
      setState(391);
      match(PhpParser::Rgeneric);
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(393);
      match(PhpParser::Lgeneric);
      setState(394);
      typeParameterList();
      setState(395);
      match(PhpParser::Comma);
      setState(396);
      typeParameterWithDefaultsList();
      setState(397);
      match(PhpParser::Rgeneric);
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TypeParameterListContext ------------------------------------------------------------------

PhpParser::TypeParameterListContext::TypeParameterListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::TypeParameterDeclContext *> PhpParser::TypeParameterListContext::typeParameterDecl() {
  return getRuleContexts<PhpParser::TypeParameterDeclContext>();
}

PhpParser::TypeParameterDeclContext* PhpParser::TypeParameterListContext::typeParameterDecl(size_t i) {
  return getRuleContext<PhpParser::TypeParameterDeclContext>(i);
}


size_t PhpParser::TypeParameterListContext::getRuleIndex() const {
  return PhpParser::RuleTypeParameterList;
}

antlrcpp::Any PhpParser::TypeParameterListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitTypeParameterList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::TypeParameterListContext* PhpParser::typeParameterList() {
  TypeParameterListContext *_localctx = _tracker.createInstance<TypeParameterListContext>(_ctx, getState());
  enterRule(_localctx, 26, PhpParser::RuleTypeParameterList);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(401);
    typeParameterDecl();
    setState(406);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 26, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(402);
        match(PhpParser::Comma);
        setState(403);
        typeParameterDecl(); 
      }
      setState(408);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 26, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TypeParameterWithDefaultsListContext ------------------------------------------------------------------

PhpParser::TypeParameterWithDefaultsListContext::TypeParameterWithDefaultsListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::TypeParameterWithDefaultDeclContext *> PhpParser::TypeParameterWithDefaultsListContext::typeParameterWithDefaultDecl() {
  return getRuleContexts<PhpParser::TypeParameterWithDefaultDeclContext>();
}

PhpParser::TypeParameterWithDefaultDeclContext* PhpParser::TypeParameterWithDefaultsListContext::typeParameterWithDefaultDecl(size_t i) {
  return getRuleContext<PhpParser::TypeParameterWithDefaultDeclContext>(i);
}


size_t PhpParser::TypeParameterWithDefaultsListContext::getRuleIndex() const {
  return PhpParser::RuleTypeParameterWithDefaultsList;
}

antlrcpp::Any PhpParser::TypeParameterWithDefaultsListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitTypeParameterWithDefaultsList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::TypeParameterWithDefaultsListContext* PhpParser::typeParameterWithDefaultsList() {
  TypeParameterWithDefaultsListContext *_localctx = _tracker.createInstance<TypeParameterWithDefaultsListContext>(_ctx, getState());
  enterRule(_localctx, 28, PhpParser::RuleTypeParameterWithDefaultsList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(409);
    typeParameterWithDefaultDecl();
    setState(414);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(410);
      match(PhpParser::Comma);
      setState(411);
      typeParameterWithDefaultDecl();
      setState(416);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TypeParameterDeclContext ------------------------------------------------------------------

PhpParser::TypeParameterDeclContext::TypeParameterDeclContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::AttributesContext* PhpParser::TypeParameterDeclContext::attributes() {
  return getRuleContext<PhpParser::AttributesContext>(0);
}

PhpParser::IdentifierContext* PhpParser::TypeParameterDeclContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}


size_t PhpParser::TypeParameterDeclContext::getRuleIndex() const {
  return PhpParser::RuleTypeParameterDecl;
}

antlrcpp::Any PhpParser::TypeParameterDeclContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitTypeParameterDecl(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::TypeParameterDeclContext* PhpParser::typeParameterDecl() {
  TypeParameterDeclContext *_localctx = _tracker.createInstance<TypeParameterDeclContext>(_ctx, getState());
  enterRule(_localctx, 30, PhpParser::RuleTypeParameterDecl);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(417);
    attributes();
    setState(418);
    identifier();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TypeParameterWithDefaultDeclContext ------------------------------------------------------------------

PhpParser::TypeParameterWithDefaultDeclContext::TypeParameterWithDefaultDeclContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::AttributesContext* PhpParser::TypeParameterWithDefaultDeclContext::attributes() {
  return getRuleContext<PhpParser::AttributesContext>(0);
}

PhpParser::IdentifierContext* PhpParser::TypeParameterWithDefaultDeclContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}

tree::TerminalNode* PhpParser::TypeParameterWithDefaultDeclContext::Eq() {
  return getToken(PhpParser::Eq, 0);
}

PhpParser::QualifiedStaticTypeRefContext* PhpParser::TypeParameterWithDefaultDeclContext::qualifiedStaticTypeRef() {
  return getRuleContext<PhpParser::QualifiedStaticTypeRefContext>(0);
}

PhpParser::PrimitiveTypeContext* PhpParser::TypeParameterWithDefaultDeclContext::primitiveType() {
  return getRuleContext<PhpParser::PrimitiveTypeContext>(0);
}


size_t PhpParser::TypeParameterWithDefaultDeclContext::getRuleIndex() const {
  return PhpParser::RuleTypeParameterWithDefaultDecl;
}

antlrcpp::Any PhpParser::TypeParameterWithDefaultDeclContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitTypeParameterWithDefaultDecl(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::TypeParameterWithDefaultDeclContext* PhpParser::typeParameterWithDefaultDecl() {
  TypeParameterWithDefaultDeclContext *_localctx = _tracker.createInstance<TypeParameterWithDefaultDeclContext>(_ctx, getState());
  enterRule(_localctx, 32, PhpParser::RuleTypeParameterWithDefaultDecl);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(420);
    attributes();
    setState(421);
    identifier();
    setState(422);
    match(PhpParser::Eq);
    setState(425);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 28, _ctx)) {
    case 1: {
      setState(423);
      qualifiedStaticTypeRef();
      break;
    }

    case 2: {
      setState(424);
      primitiveType();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- GenericDynamicArgsContext ------------------------------------------------------------------

PhpParser::GenericDynamicArgsContext::GenericDynamicArgsContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::TypeRefContext *> PhpParser::GenericDynamicArgsContext::typeRef() {
  return getRuleContexts<PhpParser::TypeRefContext>();
}

PhpParser::TypeRefContext* PhpParser::GenericDynamicArgsContext::typeRef(size_t i) {
  return getRuleContext<PhpParser::TypeRefContext>(i);
}


size_t PhpParser::GenericDynamicArgsContext::getRuleIndex() const {
  return PhpParser::RuleGenericDynamicArgs;
}

antlrcpp::Any PhpParser::GenericDynamicArgsContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitGenericDynamicArgs(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::GenericDynamicArgsContext* PhpParser::genericDynamicArgs() {
  GenericDynamicArgsContext *_localctx = _tracker.createInstance<GenericDynamicArgsContext>(_ctx, getState());
  enterRule(_localctx, 34, PhpParser::RuleGenericDynamicArgs);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(427);
    match(PhpParser::Lgeneric);
    setState(428);
    typeRef();
    setState(433);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(429);
      match(PhpParser::Comma);
      setState(430);
      typeRef();
      setState(435);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
    setState(436);
    match(PhpParser::Rgeneric);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- AttributesContext ------------------------------------------------------------------

PhpParser::AttributesContext::AttributesContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::AttributesGroupContext *> PhpParser::AttributesContext::attributesGroup() {
  return getRuleContexts<PhpParser::AttributesGroupContext>();
}

PhpParser::AttributesGroupContext* PhpParser::AttributesContext::attributesGroup(size_t i) {
  return getRuleContext<PhpParser::AttributesGroupContext>(i);
}


size_t PhpParser::AttributesContext::getRuleIndex() const {
  return PhpParser::RuleAttributes;
}

antlrcpp::Any PhpParser::AttributesContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitAttributes(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::AttributesContext* PhpParser::attributes() {
  AttributesContext *_localctx = _tracker.createInstance<AttributesContext>(_ctx, getState());
  enterRule(_localctx, 36, PhpParser::RuleAttributes);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(441);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::OpenSquareBracket) {
      setState(438);
      attributesGroup();
      setState(443);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- AttributesGroupContext ------------------------------------------------------------------

PhpParser::AttributesGroupContext::AttributesGroupContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::AttributeContext *> PhpParser::AttributesGroupContext::attribute() {
  return getRuleContexts<PhpParser::AttributeContext>();
}

PhpParser::AttributeContext* PhpParser::AttributesGroupContext::attribute(size_t i) {
  return getRuleContext<PhpParser::AttributeContext>(i);
}

PhpParser::IdentifierContext* PhpParser::AttributesGroupContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}


size_t PhpParser::AttributesGroupContext::getRuleIndex() const {
  return PhpParser::RuleAttributesGroup;
}

antlrcpp::Any PhpParser::AttributesGroupContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitAttributesGroup(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::AttributesGroupContext* PhpParser::attributesGroup() {
  AttributesGroupContext *_localctx = _tracker.createInstance<AttributesGroupContext>(_ctx, getState());
  enterRule(_localctx, 38, PhpParser::RuleAttributesGroup);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(444);
    match(PhpParser::OpenSquareBracket);
    setState(448);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 31, _ctx)) {
    case 1: {
      setState(445);
      identifier();
      setState(446);
      match(PhpParser::Colon);
      break;
    }

    }
    setState(450);
    attribute();
    setState(455);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(451);
      match(PhpParser::Comma);
      setState(452);
      attribute();
      setState(457);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
    setState(458);
    match(PhpParser::CloseSquareBracket);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- AttributeContext ------------------------------------------------------------------

PhpParser::AttributeContext::AttributeContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::QualifiedNamespaceNameContext* PhpParser::AttributeContext::qualifiedNamespaceName() {
  return getRuleContext<PhpParser::QualifiedNamespaceNameContext>(0);
}

PhpParser::AttributeArgListContext* PhpParser::AttributeContext::attributeArgList() {
  return getRuleContext<PhpParser::AttributeArgListContext>(0);
}

PhpParser::AttributeNamedArgListContext* PhpParser::AttributeContext::attributeNamedArgList() {
  return getRuleContext<PhpParser::AttributeNamedArgListContext>(0);
}


size_t PhpParser::AttributeContext::getRuleIndex() const {
  return PhpParser::RuleAttribute;
}

antlrcpp::Any PhpParser::AttributeContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitAttribute(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::AttributeContext* PhpParser::attribute() {
  AttributeContext *_localctx = _tracker.createInstance<AttributeContext>(_ctx, getState());
  enterRule(_localctx, 40, PhpParser::RuleAttribute);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(478);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 33, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(460);
      qualifiedNamespaceName();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(461);
      qualifiedNamespaceName();
      setState(462);
      match(PhpParser::OpenRoundBracket);
      setState(463);
      attributeArgList();
      setState(464);
      match(PhpParser::CloseRoundBracket);
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(466);
      qualifiedNamespaceName();
      setState(467);
      match(PhpParser::OpenRoundBracket);
      setState(468);
      attributeNamedArgList();
      setState(469);
      match(PhpParser::CloseRoundBracket);
      break;
    }

    case 4: {
      enterOuterAlt(_localctx, 4);
      setState(471);
      qualifiedNamespaceName();
      setState(472);
      match(PhpParser::OpenRoundBracket);
      setState(473);
      attributeArgList();
      setState(474);
      match(PhpParser::Comma);
      setState(475);
      attributeNamedArgList();
      setState(476);
      match(PhpParser::CloseRoundBracket);
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- AttributeArgListContext ------------------------------------------------------------------

PhpParser::AttributeArgListContext::AttributeArgListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::ExpressionContext *> PhpParser::AttributeArgListContext::expression() {
  return getRuleContexts<PhpParser::ExpressionContext>();
}

PhpParser::ExpressionContext* PhpParser::AttributeArgListContext::expression(size_t i) {
  return getRuleContext<PhpParser::ExpressionContext>(i);
}


size_t PhpParser::AttributeArgListContext::getRuleIndex() const {
  return PhpParser::RuleAttributeArgList;
}

antlrcpp::Any PhpParser::AttributeArgListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitAttributeArgList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::AttributeArgListContext* PhpParser::attributeArgList() {
  AttributeArgListContext *_localctx = _tracker.createInstance<AttributeArgListContext>(_ctx, getState());
  enterRule(_localctx, 42, PhpParser::RuleAttributeArgList);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(480);
    expression(0);
    setState(485);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 34, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(481);
        match(PhpParser::Comma);
        setState(482);
        expression(0); 
      }
      setState(487);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 34, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- AttributeNamedArgListContext ------------------------------------------------------------------

PhpParser::AttributeNamedArgListContext::AttributeNamedArgListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::AttributeNamedArgContext *> PhpParser::AttributeNamedArgListContext::attributeNamedArg() {
  return getRuleContexts<PhpParser::AttributeNamedArgContext>();
}

PhpParser::AttributeNamedArgContext* PhpParser::AttributeNamedArgListContext::attributeNamedArg(size_t i) {
  return getRuleContext<PhpParser::AttributeNamedArgContext>(i);
}


size_t PhpParser::AttributeNamedArgListContext::getRuleIndex() const {
  return PhpParser::RuleAttributeNamedArgList;
}

antlrcpp::Any PhpParser::AttributeNamedArgListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitAttributeNamedArgList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::AttributeNamedArgListContext* PhpParser::attributeNamedArgList() {
  AttributeNamedArgListContext *_localctx = _tracker.createInstance<AttributeNamedArgListContext>(_ctx, getState());
  enterRule(_localctx, 44, PhpParser::RuleAttributeNamedArgList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(488);
    attributeNamedArg();
    setState(493);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(489);
      match(PhpParser::Comma);
      setState(490);
      attributeNamedArg();
      setState(495);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- AttributeNamedArgContext ------------------------------------------------------------------

PhpParser::AttributeNamedArgContext::AttributeNamedArgContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::AttributeNamedArgContext::VarName() {
  return getToken(PhpParser::VarName, 0);
}

PhpParser::ExpressionContext* PhpParser::AttributeNamedArgContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}


size_t PhpParser::AttributeNamedArgContext::getRuleIndex() const {
  return PhpParser::RuleAttributeNamedArg;
}

antlrcpp::Any PhpParser::AttributeNamedArgContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitAttributeNamedArg(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::AttributeNamedArgContext* PhpParser::attributeNamedArg() {
  AttributeNamedArgContext *_localctx = _tracker.createInstance<AttributeNamedArgContext>(_ctx, getState());
  enterRule(_localctx, 46, PhpParser::RuleAttributeNamedArg);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(496);
    match(PhpParser::VarName);
    setState(497);
    match(PhpParser::DoubleArrow);
    setState(498);
    expression(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- InnerStatementListContext ------------------------------------------------------------------

PhpParser::InnerStatementListContext::InnerStatementListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::InnerStatementContext *> PhpParser::InnerStatementListContext::innerStatement() {
  return getRuleContexts<PhpParser::InnerStatementContext>();
}

PhpParser::InnerStatementContext* PhpParser::InnerStatementListContext::innerStatement(size_t i) {
  return getRuleContext<PhpParser::InnerStatementContext>(i);
}


size_t PhpParser::InnerStatementListContext::getRuleIndex() const {
  return PhpParser::RuleInnerStatementList;
}

antlrcpp::Any PhpParser::InnerStatementListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitInnerStatementList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::InnerStatementListContext* PhpParser::innerStatementList() {
  InnerStatementListContext *_localctx = _tracker.createInstance<InnerStatementListContext>(_ctx, getState());
  enterRule(_localctx, 48, PhpParser::RuleInnerStatementList);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(503);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 36, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(500);
        innerStatement(); 
      }
      setState(505);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 36, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- InnerStatementContext ------------------------------------------------------------------

PhpParser::InnerStatementContext::InnerStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::StatementContext* PhpParser::InnerStatementContext::statement() {
  return getRuleContext<PhpParser::StatementContext>(0);
}

PhpParser::FunctionDeclarationContext* PhpParser::InnerStatementContext::functionDeclaration() {
  return getRuleContext<PhpParser::FunctionDeclarationContext>(0);
}

PhpParser::ClassDeclarationContext* PhpParser::InnerStatementContext::classDeclaration() {
  return getRuleContext<PhpParser::ClassDeclarationContext>(0);
}


size_t PhpParser::InnerStatementContext::getRuleIndex() const {
  return PhpParser::RuleInnerStatement;
}

antlrcpp::Any PhpParser::InnerStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitInnerStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::InnerStatementContext* PhpParser::innerStatement() {
  InnerStatementContext *_localctx = _tracker.createInstance<InnerStatementContext>(_ctx, getState());
  enterRule(_localctx, 50, PhpParser::RuleInnerStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(509);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 37, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(506);
      statement();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(507);
      functionDeclaration();
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(508);
      classDeclaration();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- StatementContext ------------------------------------------------------------------

PhpParser::StatementContext::StatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::IdentifierContext* PhpParser::StatementContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}

PhpParser::BlockStatementContext* PhpParser::StatementContext::blockStatement() {
  return getRuleContext<PhpParser::BlockStatementContext>(0);
}

PhpParser::IfStatementContext* PhpParser::StatementContext::ifStatement() {
  return getRuleContext<PhpParser::IfStatementContext>(0);
}

PhpParser::WhileStatementContext* PhpParser::StatementContext::whileStatement() {
  return getRuleContext<PhpParser::WhileStatementContext>(0);
}

PhpParser::DoWhileStatementContext* PhpParser::StatementContext::doWhileStatement() {
  return getRuleContext<PhpParser::DoWhileStatementContext>(0);
}

PhpParser::ForStatementContext* PhpParser::StatementContext::forStatement() {
  return getRuleContext<PhpParser::ForStatementContext>(0);
}

PhpParser::SwitchStatementContext* PhpParser::StatementContext::switchStatement() {
  return getRuleContext<PhpParser::SwitchStatementContext>(0);
}

PhpParser::BreakStatementContext* PhpParser::StatementContext::breakStatement() {
  return getRuleContext<PhpParser::BreakStatementContext>(0);
}

PhpParser::ContinueStatementContext* PhpParser::StatementContext::continueStatement() {
  return getRuleContext<PhpParser::ContinueStatementContext>(0);
}

PhpParser::ReturnStatementContext* PhpParser::StatementContext::returnStatement() {
  return getRuleContext<PhpParser::ReturnStatementContext>(0);
}

PhpParser::YieldExpressionContext* PhpParser::StatementContext::yieldExpression() {
  return getRuleContext<PhpParser::YieldExpressionContext>(0);
}

PhpParser::GlobalStatementContext* PhpParser::StatementContext::globalStatement() {
  return getRuleContext<PhpParser::GlobalStatementContext>(0);
}

PhpParser::StaticVariableStatementContext* PhpParser::StatementContext::staticVariableStatement() {
  return getRuleContext<PhpParser::StaticVariableStatementContext>(0);
}

PhpParser::EchoStatementContext* PhpParser::StatementContext::echoStatement() {
  return getRuleContext<PhpParser::EchoStatementContext>(0);
}

PhpParser::ExpressionStatementContext* PhpParser::StatementContext::expressionStatement() {
  return getRuleContext<PhpParser::ExpressionStatementContext>(0);
}

PhpParser::UnsetStatementContext* PhpParser::StatementContext::unsetStatement() {
  return getRuleContext<PhpParser::UnsetStatementContext>(0);
}

PhpParser::ForeachStatementContext* PhpParser::StatementContext::foreachStatement() {
  return getRuleContext<PhpParser::ForeachStatementContext>(0);
}

PhpParser::TryCatchFinallyContext* PhpParser::StatementContext::tryCatchFinally() {
  return getRuleContext<PhpParser::TryCatchFinallyContext>(0);
}

PhpParser::ThrowStatementContext* PhpParser::StatementContext::throwStatement() {
  return getRuleContext<PhpParser::ThrowStatementContext>(0);
}

PhpParser::GotoStatementContext* PhpParser::StatementContext::gotoStatement() {
  return getRuleContext<PhpParser::GotoStatementContext>(0);
}

PhpParser::DeclareStatementContext* PhpParser::StatementContext::declareStatement() {
  return getRuleContext<PhpParser::DeclareStatementContext>(0);
}

PhpParser::EmptyStatementContext* PhpParser::StatementContext::emptyStatement() {
  return getRuleContext<PhpParser::EmptyStatementContext>(0);
}


size_t PhpParser::StatementContext::getRuleIndex() const {
  return PhpParser::RuleStatement;
}

antlrcpp::Any PhpParser::StatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::StatementContext* PhpParser::statement() {
  StatementContext *_localctx = _tracker.createInstance<StatementContext>(_ctx, getState());
  enterRule(_localctx, 52, PhpParser::RuleStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(537);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 38, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(511);
      identifier();
      setState(512);
      match(PhpParser::Colon);
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(514);
      blockStatement();
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(515);
      ifStatement();
      break;
    }

    case 4: {
      enterOuterAlt(_localctx, 4);
      setState(516);
      whileStatement();
      break;
    }

    case 5: {
      enterOuterAlt(_localctx, 5);
      setState(517);
      doWhileStatement();
      break;
    }

    case 6: {
      enterOuterAlt(_localctx, 6);
      setState(518);
      forStatement();
      break;
    }

    case 7: {
      enterOuterAlt(_localctx, 7);
      setState(519);
      switchStatement();
      break;
    }

    case 8: {
      enterOuterAlt(_localctx, 8);
      setState(520);
      breakStatement();
      break;
    }

    case 9: {
      enterOuterAlt(_localctx, 9);
      setState(521);
      continueStatement();
      break;
    }

    case 10: {
      enterOuterAlt(_localctx, 10);
      setState(522);
      returnStatement();
      break;
    }

    case 11: {
      enterOuterAlt(_localctx, 11);
      setState(523);
      yieldExpression();
      setState(524);
      match(PhpParser::SemiColon);
      break;
    }

    case 12: {
      enterOuterAlt(_localctx, 12);
      setState(526);
      globalStatement();
      break;
    }

    case 13: {
      enterOuterAlt(_localctx, 13);
      setState(527);
      staticVariableStatement();
      break;
    }

    case 14: {
      enterOuterAlt(_localctx, 14);
      setState(528);
      echoStatement();
      break;
    }

    case 15: {
      enterOuterAlt(_localctx, 15);
      setState(529);
      expressionStatement();
      break;
    }

    case 16: {
      enterOuterAlt(_localctx, 16);
      setState(530);
      unsetStatement();
      break;
    }

    case 17: {
      enterOuterAlt(_localctx, 17);
      setState(531);
      foreachStatement();
      break;
    }

    case 18: {
      enterOuterAlt(_localctx, 18);
      setState(532);
      tryCatchFinally();
      break;
    }

    case 19: {
      enterOuterAlt(_localctx, 19);
      setState(533);
      throwStatement();
      break;
    }

    case 20: {
      enterOuterAlt(_localctx, 20);
      setState(534);
      gotoStatement();
      break;
    }

    case 21: {
      enterOuterAlt(_localctx, 21);
      setState(535);
      declareStatement();
      break;
    }

    case 22: {
      enterOuterAlt(_localctx, 22);
      setState(536);
      emptyStatement();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- EmptyStatementContext ------------------------------------------------------------------

PhpParser::EmptyStatementContext::EmptyStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}


size_t PhpParser::EmptyStatementContext::getRuleIndex() const {
  return PhpParser::RuleEmptyStatement;
}

antlrcpp::Any PhpParser::EmptyStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitEmptyStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::EmptyStatementContext* PhpParser::emptyStatement() {
  EmptyStatementContext *_localctx = _tracker.createInstance<EmptyStatementContext>(_ctx, getState());
  enterRule(_localctx, 54, PhpParser::RuleEmptyStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(539);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- BlockStatementContext ------------------------------------------------------------------

PhpParser::BlockStatementContext::BlockStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::BlockStatementContext::OpenCurlyBracket() {
  return getToken(PhpParser::OpenCurlyBracket, 0);
}

PhpParser::InnerStatementListContext* PhpParser::BlockStatementContext::innerStatementList() {
  return getRuleContext<PhpParser::InnerStatementListContext>(0);
}


size_t PhpParser::BlockStatementContext::getRuleIndex() const {
  return PhpParser::RuleBlockStatement;
}

antlrcpp::Any PhpParser::BlockStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitBlockStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::BlockStatementContext* PhpParser::blockStatement() {
  BlockStatementContext *_localctx = _tracker.createInstance<BlockStatementContext>(_ctx, getState());
  enterRule(_localctx, 56, PhpParser::RuleBlockStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(541);
    match(PhpParser::OpenCurlyBracket);
    setState(542);
    innerStatementList();
    setState(543);
    match(PhpParser::CloseCurlyBracket);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- IfStatementContext ------------------------------------------------------------------

PhpParser::IfStatementContext::IfStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::IfStatementContext::If() {
  return getToken(PhpParser::If, 0);
}

PhpParser::ParenthesisContext* PhpParser::IfStatementContext::parenthesis() {
  return getRuleContext<PhpParser::ParenthesisContext>(0);
}

PhpParser::StatementContext* PhpParser::IfStatementContext::statement() {
  return getRuleContext<PhpParser::StatementContext>(0);
}

std::vector<PhpParser::ElseIfStatementContext *> PhpParser::IfStatementContext::elseIfStatement() {
  return getRuleContexts<PhpParser::ElseIfStatementContext>();
}

PhpParser::ElseIfStatementContext* PhpParser::IfStatementContext::elseIfStatement(size_t i) {
  return getRuleContext<PhpParser::ElseIfStatementContext>(i);
}

PhpParser::ElseStatementContext* PhpParser::IfStatementContext::elseStatement() {
  return getRuleContext<PhpParser::ElseStatementContext>(0);
}

PhpParser::InnerStatementListContext* PhpParser::IfStatementContext::innerStatementList() {
  return getRuleContext<PhpParser::InnerStatementListContext>(0);
}

tree::TerminalNode* PhpParser::IfStatementContext::EndIf() {
  return getToken(PhpParser::EndIf, 0);
}

std::vector<PhpParser::ElseIfColonStatementContext *> PhpParser::IfStatementContext::elseIfColonStatement() {
  return getRuleContexts<PhpParser::ElseIfColonStatementContext>();
}

PhpParser::ElseIfColonStatementContext* PhpParser::IfStatementContext::elseIfColonStatement(size_t i) {
  return getRuleContext<PhpParser::ElseIfColonStatementContext>(i);
}

PhpParser::ElseColonStatementContext* PhpParser::IfStatementContext::elseColonStatement() {
  return getRuleContext<PhpParser::ElseColonStatementContext>(0);
}


size_t PhpParser::IfStatementContext::getRuleIndex() const {
  return PhpParser::RuleIfStatement;
}

antlrcpp::Any PhpParser::IfStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitIfStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::IfStatementContext* PhpParser::ifStatement() {
  IfStatementContext *_localctx = _tracker.createInstance<IfStatementContext>(_ctx, getState());
  enterRule(_localctx, 58, PhpParser::RuleIfStatement);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    setState(573);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 43, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(545);
      match(PhpParser::If);
      setState(546);
      parenthesis();
      setState(547);
      statement();
      setState(551);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 39, _ctx);
      while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
        if (alt == 1) {
          setState(548);
          elseIfStatement(); 
        }
        setState(553);
        _errHandler->sync(this);
        alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 39, _ctx);
      }
      setState(555);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 40, _ctx)) {
      case 1: {
        setState(554);
        elseStatement();
        break;
      }

      }
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(557);
      match(PhpParser::If);
      setState(558);
      parenthesis();
      setState(559);
      match(PhpParser::Colon);
      setState(560);
      innerStatementList();
      setState(564);
      _errHandler->sync(this);
      _la = _input->LA(1);
      while (_la == PhpParser::ElseIf) {
        setState(561);
        elseIfColonStatement();
        setState(566);
        _errHandler->sync(this);
        _la = _input->LA(1);
      }
      setState(568);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == PhpParser::Else) {
        setState(567);
        elseColonStatement();
      }
      setState(570);
      match(PhpParser::EndIf);
      setState(571);
      match(PhpParser::SemiColon);
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ElseIfStatementContext ------------------------------------------------------------------

PhpParser::ElseIfStatementContext::ElseIfStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::ElseIfStatementContext::ElseIf() {
  return getToken(PhpParser::ElseIf, 0);
}

PhpParser::ParenthesisContext* PhpParser::ElseIfStatementContext::parenthesis() {
  return getRuleContext<PhpParser::ParenthesisContext>(0);
}

PhpParser::StatementContext* PhpParser::ElseIfStatementContext::statement() {
  return getRuleContext<PhpParser::StatementContext>(0);
}


size_t PhpParser::ElseIfStatementContext::getRuleIndex() const {
  return PhpParser::RuleElseIfStatement;
}

antlrcpp::Any PhpParser::ElseIfStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitElseIfStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ElseIfStatementContext* PhpParser::elseIfStatement() {
  ElseIfStatementContext *_localctx = _tracker.createInstance<ElseIfStatementContext>(_ctx, getState());
  enterRule(_localctx, 60, PhpParser::RuleElseIfStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(575);
    match(PhpParser::ElseIf);
    setState(576);
    parenthesis();
    setState(577);
    statement();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ElseIfColonStatementContext ------------------------------------------------------------------

PhpParser::ElseIfColonStatementContext::ElseIfColonStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::ElseIfColonStatementContext::ElseIf() {
  return getToken(PhpParser::ElseIf, 0);
}

PhpParser::ParenthesisContext* PhpParser::ElseIfColonStatementContext::parenthesis() {
  return getRuleContext<PhpParser::ParenthesisContext>(0);
}

PhpParser::InnerStatementListContext* PhpParser::ElseIfColonStatementContext::innerStatementList() {
  return getRuleContext<PhpParser::InnerStatementListContext>(0);
}


size_t PhpParser::ElseIfColonStatementContext::getRuleIndex() const {
  return PhpParser::RuleElseIfColonStatement;
}

antlrcpp::Any PhpParser::ElseIfColonStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitElseIfColonStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ElseIfColonStatementContext* PhpParser::elseIfColonStatement() {
  ElseIfColonStatementContext *_localctx = _tracker.createInstance<ElseIfColonStatementContext>(_ctx, getState());
  enterRule(_localctx, 62, PhpParser::RuleElseIfColonStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(579);
    match(PhpParser::ElseIf);
    setState(580);
    parenthesis();
    setState(581);
    match(PhpParser::Colon);
    setState(582);
    innerStatementList();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ElseStatementContext ------------------------------------------------------------------

PhpParser::ElseStatementContext::ElseStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::ElseStatementContext::Else() {
  return getToken(PhpParser::Else, 0);
}

PhpParser::StatementContext* PhpParser::ElseStatementContext::statement() {
  return getRuleContext<PhpParser::StatementContext>(0);
}


size_t PhpParser::ElseStatementContext::getRuleIndex() const {
  return PhpParser::RuleElseStatement;
}

antlrcpp::Any PhpParser::ElseStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitElseStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ElseStatementContext* PhpParser::elseStatement() {
  ElseStatementContext *_localctx = _tracker.createInstance<ElseStatementContext>(_ctx, getState());
  enterRule(_localctx, 64, PhpParser::RuleElseStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(584);
    match(PhpParser::Else);
    setState(585);
    statement();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ElseColonStatementContext ------------------------------------------------------------------

PhpParser::ElseColonStatementContext::ElseColonStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::ElseColonStatementContext::Else() {
  return getToken(PhpParser::Else, 0);
}

PhpParser::InnerStatementListContext* PhpParser::ElseColonStatementContext::innerStatementList() {
  return getRuleContext<PhpParser::InnerStatementListContext>(0);
}


size_t PhpParser::ElseColonStatementContext::getRuleIndex() const {
  return PhpParser::RuleElseColonStatement;
}

antlrcpp::Any PhpParser::ElseColonStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitElseColonStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ElseColonStatementContext* PhpParser::elseColonStatement() {
  ElseColonStatementContext *_localctx = _tracker.createInstance<ElseColonStatementContext>(_ctx, getState());
  enterRule(_localctx, 66, PhpParser::RuleElseColonStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(587);
    match(PhpParser::Else);
    setState(588);
    match(PhpParser::Colon);
    setState(589);
    innerStatementList();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- WhileStatementContext ------------------------------------------------------------------

PhpParser::WhileStatementContext::WhileStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::WhileStatementContext::While() {
  return getToken(PhpParser::While, 0);
}

PhpParser::ParenthesisContext* PhpParser::WhileStatementContext::parenthesis() {
  return getRuleContext<PhpParser::ParenthesisContext>(0);
}

PhpParser::StatementContext* PhpParser::WhileStatementContext::statement() {
  return getRuleContext<PhpParser::StatementContext>(0);
}

PhpParser::InnerStatementListContext* PhpParser::WhileStatementContext::innerStatementList() {
  return getRuleContext<PhpParser::InnerStatementListContext>(0);
}

tree::TerminalNode* PhpParser::WhileStatementContext::EndWhile() {
  return getToken(PhpParser::EndWhile, 0);
}


size_t PhpParser::WhileStatementContext::getRuleIndex() const {
  return PhpParser::RuleWhileStatement;
}

antlrcpp::Any PhpParser::WhileStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitWhileStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::WhileStatementContext* PhpParser::whileStatement() {
  WhileStatementContext *_localctx = _tracker.createInstance<WhileStatementContext>(_ctx, getState());
  enterRule(_localctx, 68, PhpParser::RuleWhileStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(591);
    match(PhpParser::While);
    setState(592);
    parenthesis();
    setState(599);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::Abstract:
      case PhpParser::Array:
      case PhpParser::As:
      case PhpParser::BinaryCast:
      case PhpParser::BoolType:
      case PhpParser::BooleanConstant:
      case PhpParser::Break:
      case PhpParser::Callable:
      case PhpParser::Case:
      case PhpParser::Catch:
      case PhpParser::Class:
      case PhpParser::Clone:
      case PhpParser::Const:
      case PhpParser::Continue:
      case PhpParser::Declare:
      case PhpParser::Default:
      case PhpParser::Do:
      case PhpParser::DoubleCast:
      case PhpParser::DoubleType:
      case PhpParser::Echo:
      case PhpParser::Else:
      case PhpParser::ElseIf:
      case PhpParser::Empty:
      case PhpParser::EndDeclare:
      case PhpParser::EndFor:
      case PhpParser::EndForeach:
      case PhpParser::EndIf:
      case PhpParser::EndSwitch:
      case PhpParser::EndWhile:
      case PhpParser::Eval:
      case PhpParser::Exit:
      case PhpParser::Extends:
      case PhpParser::Final:
      case PhpParser::Finally:
      case PhpParser::FloatCast:
      case PhpParser::For:
      case PhpParser::Foreach:
      case PhpParser::Function:
      case PhpParser::Global:
      case PhpParser::Goto:
      case PhpParser::If:
      case PhpParser::Implements:
      case PhpParser::Import:
      case PhpParser::Include:
      case PhpParser::IncludeOnce:
      case PhpParser::InstanceOf:
      case PhpParser::InsteadOf:
      case PhpParser::Int8Cast:
      case PhpParser::Int16Cast:
      case PhpParser::Int64Type:
      case PhpParser::IntType:
      case PhpParser::Interface:
      case PhpParser::IsSet:
      case PhpParser::List:
      case PhpParser::LogicalAnd:
      case PhpParser::LogicalOr:
      case PhpParser::LogicalXor:
      case PhpParser::Namespace:
      case PhpParser::New:
      case PhpParser::Null:
      case PhpParser::ObjectType:
      case PhpParser::Parent_:
      case PhpParser::Partial:
      case PhpParser::Print:
      case PhpParser::Private:
      case PhpParser::Protected:
      case PhpParser::Public:
      case PhpParser::Require:
      case PhpParser::RequireOnce:
      case PhpParser::Resource:
      case PhpParser::Return:
      case PhpParser::Static:
      case PhpParser::StringType:
      case PhpParser::Switch:
      case PhpParser::Throw:
      case PhpParser::Trait:
      case PhpParser::Try:
      case PhpParser::Typeof:
      case PhpParser::UintCast:
      case PhpParser::UnicodeCast:
      case PhpParser::Unset:
      case PhpParser::Use:
      case PhpParser::Var:
      case PhpParser::While:
      case PhpParser::Yield:
      case PhpParser::Get:
      case PhpParser::Set:
      case PhpParser::Call:
      case PhpParser::CallStatic:
      case PhpParser::Constructor:
      case PhpParser::Destruct:
      case PhpParser::Wakeup:
      case PhpParser::Sleep:
      case PhpParser::Autoload:
      case PhpParser::IsSet__:
      case PhpParser::Unset__:
      case PhpParser::ToString__:
      case PhpParser::Invoke:
      case PhpParser::SetState:
      case PhpParser::Clone__:
      case PhpParser::DebugInfo:
      case PhpParser::Namespace__:
      case PhpParser::Class__:
      case PhpParser::Traic__:
      case PhpParser::Function__:
      case PhpParser::Method__:
      case PhpParser::Line__:
      case PhpParser::File__:
      case PhpParser::Dir__:
      case PhpParser::Inc:
      case PhpParser::Dec:
      case PhpParser::NamespaceSeparator:
      case PhpParser::Bang:
      case PhpParser::Plus:
      case PhpParser::Minus:
      case PhpParser::Tilde:
      case PhpParser::SuppressWarnings:
      case PhpParser::Dollar:
      case PhpParser::OpenRoundBracket:
      case PhpParser::OpenSquareBracket:
      case PhpParser::OpenCurlyBracket:
      case PhpParser::SemiColon:
      case PhpParser::VarName:
      case PhpParser::Label:
      case PhpParser::Octal:
      case PhpParser::Decimal:
      case PhpParser::Real:
      case PhpParser::Hex:
      case PhpParser::Binary:
      case PhpParser::BackQuoteString:
      case PhpParser::SingleQuoteString:
      case PhpParser::DoubleQuote:
      case PhpParser::StartNowDoc:
      case PhpParser::StartHereDoc: {
        setState(593);
        statement();
        break;
      }

      case PhpParser::Colon: {
        setState(594);
        match(PhpParser::Colon);
        setState(595);
        innerStatementList();
        setState(596);
        match(PhpParser::EndWhile);
        setState(597);
        match(PhpParser::SemiColon);
        break;
      }

    default:
      throw NoViableAltException(this);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- DoWhileStatementContext ------------------------------------------------------------------

PhpParser::DoWhileStatementContext::DoWhileStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::DoWhileStatementContext::Do() {
  return getToken(PhpParser::Do, 0);
}

PhpParser::StatementContext* PhpParser::DoWhileStatementContext::statement() {
  return getRuleContext<PhpParser::StatementContext>(0);
}

tree::TerminalNode* PhpParser::DoWhileStatementContext::While() {
  return getToken(PhpParser::While, 0);
}

PhpParser::ParenthesisContext* PhpParser::DoWhileStatementContext::parenthesis() {
  return getRuleContext<PhpParser::ParenthesisContext>(0);
}


size_t PhpParser::DoWhileStatementContext::getRuleIndex() const {
  return PhpParser::RuleDoWhileStatement;
}

antlrcpp::Any PhpParser::DoWhileStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitDoWhileStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::DoWhileStatementContext* PhpParser::doWhileStatement() {
  DoWhileStatementContext *_localctx = _tracker.createInstance<DoWhileStatementContext>(_ctx, getState());
  enterRule(_localctx, 70, PhpParser::RuleDoWhileStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(601);
    match(PhpParser::Do);
    setState(602);
    statement();
    setState(603);
    match(PhpParser::While);
    setState(604);
    parenthesis();
    setState(605);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ForStatementContext ------------------------------------------------------------------

PhpParser::ForStatementContext::ForStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::ForStatementContext::For() {
  return getToken(PhpParser::For, 0);
}

PhpParser::StatementContext* PhpParser::ForStatementContext::statement() {
  return getRuleContext<PhpParser::StatementContext>(0);
}

PhpParser::InnerStatementListContext* PhpParser::ForStatementContext::innerStatementList() {
  return getRuleContext<PhpParser::InnerStatementListContext>(0);
}

tree::TerminalNode* PhpParser::ForStatementContext::EndFor() {
  return getToken(PhpParser::EndFor, 0);
}

PhpParser::ForInitContext* PhpParser::ForStatementContext::forInit() {
  return getRuleContext<PhpParser::ForInitContext>(0);
}

PhpParser::ExpressionListContext* PhpParser::ForStatementContext::expressionList() {
  return getRuleContext<PhpParser::ExpressionListContext>(0);
}

PhpParser::ForUpdateContext* PhpParser::ForStatementContext::forUpdate() {
  return getRuleContext<PhpParser::ForUpdateContext>(0);
}


size_t PhpParser::ForStatementContext::getRuleIndex() const {
  return PhpParser::RuleForStatement;
}

antlrcpp::Any PhpParser::ForStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitForStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ForStatementContext* PhpParser::forStatement() {
  ForStatementContext *_localctx = _tracker.createInstance<ForStatementContext>(_ctx, getState());
  enterRule(_localctx, 72, PhpParser::RuleForStatement);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(607);
    match(PhpParser::For);
    setState(608);
    match(PhpParser::OpenRoundBracket);
    setState(610);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
      | (1ULL << PhpParser::Array)
      | (1ULL << PhpParser::As)
      | (1ULL << PhpParser::BinaryCast)
      | (1ULL << PhpParser::BoolType)
      | (1ULL << PhpParser::BooleanConstant)
      | (1ULL << PhpParser::Break)
      | (1ULL << PhpParser::Callable)
      | (1ULL << PhpParser::Case)
      | (1ULL << PhpParser::Catch)
      | (1ULL << PhpParser::Class)
      | (1ULL << PhpParser::Clone)
      | (1ULL << PhpParser::Const)
      | (1ULL << PhpParser::Continue)
      | (1ULL << PhpParser::Declare)
      | (1ULL << PhpParser::Default)
      | (1ULL << PhpParser::Do)
      | (1ULL << PhpParser::DoubleCast)
      | (1ULL << PhpParser::DoubleType)
      | (1ULL << PhpParser::Echo)
      | (1ULL << PhpParser::Else)
      | (1ULL << PhpParser::ElseIf)
      | (1ULL << PhpParser::Empty)
      | (1ULL << PhpParser::EndDeclare)
      | (1ULL << PhpParser::EndFor)
      | (1ULL << PhpParser::EndForeach)
      | (1ULL << PhpParser::EndIf)
      | (1ULL << PhpParser::EndSwitch)
      | (1ULL << PhpParser::EndWhile)
      | (1ULL << PhpParser::Eval)
      | (1ULL << PhpParser::Exit)
      | (1ULL << PhpParser::Extends)
      | (1ULL << PhpParser::Final)
      | (1ULL << PhpParser::Finally)
      | (1ULL << PhpParser::FloatCast)
      | (1ULL << PhpParser::For)
      | (1ULL << PhpParser::Foreach)
      | (1ULL << PhpParser::Function)
      | (1ULL << PhpParser::Global)
      | (1ULL << PhpParser::Goto)
      | (1ULL << PhpParser::If)
      | (1ULL << PhpParser::Implements)
      | (1ULL << PhpParser::Import)
      | (1ULL << PhpParser::Include)
      | (1ULL << PhpParser::IncludeOnce)
      | (1ULL << PhpParser::InstanceOf)
      | (1ULL << PhpParser::InsteadOf)
      | (1ULL << PhpParser::Int8Cast)
      | (1ULL << PhpParser::Int16Cast)
      | (1ULL << PhpParser::Int64Type)
      | (1ULL << PhpParser::IntType)
      | (1ULL << PhpParser::Interface)
      | (1ULL << PhpParser::IsSet)
      | (1ULL << PhpParser::List)
      | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
      | (1ULL << (PhpParser::LogicalXor - 64))
      | (1ULL << (PhpParser::Namespace - 64))
      | (1ULL << (PhpParser::New - 64))
      | (1ULL << (PhpParser::Null - 64))
      | (1ULL << (PhpParser::ObjectType - 64))
      | (1ULL << (PhpParser::Parent_ - 64))
      | (1ULL << (PhpParser::Partial - 64))
      | (1ULL << (PhpParser::Print - 64))
      | (1ULL << (PhpParser::Private - 64))
      | (1ULL << (PhpParser::Protected - 64))
      | (1ULL << (PhpParser::Public - 64))
      | (1ULL << (PhpParser::Require - 64))
      | (1ULL << (PhpParser::RequireOnce - 64))
      | (1ULL << (PhpParser::Resource - 64))
      | (1ULL << (PhpParser::Return - 64))
      | (1ULL << (PhpParser::Static - 64))
      | (1ULL << (PhpParser::StringType - 64))
      | (1ULL << (PhpParser::Switch - 64))
      | (1ULL << (PhpParser::Throw - 64))
      | (1ULL << (PhpParser::Trait - 64))
      | (1ULL << (PhpParser::Try - 64))
      | (1ULL << (PhpParser::Typeof - 64))
      | (1ULL << (PhpParser::UintCast - 64))
      | (1ULL << (PhpParser::UnicodeCast - 64))
      | (1ULL << (PhpParser::Unset - 64))
      | (1ULL << (PhpParser::Use - 64))
      | (1ULL << (PhpParser::Var - 64))
      | (1ULL << (PhpParser::While - 64))
      | (1ULL << (PhpParser::Yield - 64))
      | (1ULL << (PhpParser::Get - 64))
      | (1ULL << (PhpParser::Set - 64))
      | (1ULL << (PhpParser::Call - 64))
      | (1ULL << (PhpParser::CallStatic - 64))
      | (1ULL << (PhpParser::Constructor - 64))
      | (1ULL << (PhpParser::Destruct - 64))
      | (1ULL << (PhpParser::Wakeup - 64))
      | (1ULL << (PhpParser::Sleep - 64))
      | (1ULL << (PhpParser::Autoload - 64))
      | (1ULL << (PhpParser::IsSet__ - 64))
      | (1ULL << (PhpParser::Unset__ - 64))
      | (1ULL << (PhpParser::ToString__ - 64))
      | (1ULL << (PhpParser::Invoke - 64))
      | (1ULL << (PhpParser::SetState - 64))
      | (1ULL << (PhpParser::Clone__ - 64))
      | (1ULL << (PhpParser::DebugInfo - 64))
      | (1ULL << (PhpParser::Namespace__ - 64))
      | (1ULL << (PhpParser::Class__ - 64))
      | (1ULL << (PhpParser::Traic__ - 64))
      | (1ULL << (PhpParser::Function__ - 64))
      | (1ULL << (PhpParser::Method__ - 64))
      | (1ULL << (PhpParser::Line__ - 64))
      | (1ULL << (PhpParser::File__ - 64))
      | (1ULL << (PhpParser::Dir__ - 64))
      | (1ULL << (PhpParser::Inc - 64))
      | (1ULL << (PhpParser::Dec - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
      | (1ULL << (PhpParser::Bang - 148))
      | (1ULL << (PhpParser::Plus - 148))
      | (1ULL << (PhpParser::Minus - 148))
      | (1ULL << (PhpParser::Tilde - 148))
      | (1ULL << (PhpParser::SuppressWarnings - 148))
      | (1ULL << (PhpParser::Dollar - 148))
      | (1ULL << (PhpParser::OpenRoundBracket - 148))
      | (1ULL << (PhpParser::OpenSquareBracket - 148))
      | (1ULL << (PhpParser::VarName - 148))
      | (1ULL << (PhpParser::Label - 148))
      | (1ULL << (PhpParser::Octal - 148))
      | (1ULL << (PhpParser::Decimal - 148))
      | (1ULL << (PhpParser::Real - 148))
      | (1ULL << (PhpParser::Hex - 148))
      | (1ULL << (PhpParser::Binary - 148))
      | (1ULL << (PhpParser::BackQuoteString - 148))
      | (1ULL << (PhpParser::SingleQuoteString - 148))
      | (1ULL << (PhpParser::DoubleQuote - 148))
      | (1ULL << (PhpParser::StartNowDoc - 148))
      | (1ULL << (PhpParser::StartHereDoc - 148)))) != 0)) {
      setState(609);
      forInit();
    }
    setState(612);
    match(PhpParser::SemiColon);
    setState(614);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
      | (1ULL << PhpParser::Array)
      | (1ULL << PhpParser::As)
      | (1ULL << PhpParser::BinaryCast)
      | (1ULL << PhpParser::BoolType)
      | (1ULL << PhpParser::BooleanConstant)
      | (1ULL << PhpParser::Break)
      | (1ULL << PhpParser::Callable)
      | (1ULL << PhpParser::Case)
      | (1ULL << PhpParser::Catch)
      | (1ULL << PhpParser::Class)
      | (1ULL << PhpParser::Clone)
      | (1ULL << PhpParser::Const)
      | (1ULL << PhpParser::Continue)
      | (1ULL << PhpParser::Declare)
      | (1ULL << PhpParser::Default)
      | (1ULL << PhpParser::Do)
      | (1ULL << PhpParser::DoubleCast)
      | (1ULL << PhpParser::DoubleType)
      | (1ULL << PhpParser::Echo)
      | (1ULL << PhpParser::Else)
      | (1ULL << PhpParser::ElseIf)
      | (1ULL << PhpParser::Empty)
      | (1ULL << PhpParser::EndDeclare)
      | (1ULL << PhpParser::EndFor)
      | (1ULL << PhpParser::EndForeach)
      | (1ULL << PhpParser::EndIf)
      | (1ULL << PhpParser::EndSwitch)
      | (1ULL << PhpParser::EndWhile)
      | (1ULL << PhpParser::Eval)
      | (1ULL << PhpParser::Exit)
      | (1ULL << PhpParser::Extends)
      | (1ULL << PhpParser::Final)
      | (1ULL << PhpParser::Finally)
      | (1ULL << PhpParser::FloatCast)
      | (1ULL << PhpParser::For)
      | (1ULL << PhpParser::Foreach)
      | (1ULL << PhpParser::Function)
      | (1ULL << PhpParser::Global)
      | (1ULL << PhpParser::Goto)
      | (1ULL << PhpParser::If)
      | (1ULL << PhpParser::Implements)
      | (1ULL << PhpParser::Import)
      | (1ULL << PhpParser::Include)
      | (1ULL << PhpParser::IncludeOnce)
      | (1ULL << PhpParser::InstanceOf)
      | (1ULL << PhpParser::InsteadOf)
      | (1ULL << PhpParser::Int8Cast)
      | (1ULL << PhpParser::Int16Cast)
      | (1ULL << PhpParser::Int64Type)
      | (1ULL << PhpParser::IntType)
      | (1ULL << PhpParser::Interface)
      | (1ULL << PhpParser::IsSet)
      | (1ULL << PhpParser::List)
      | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
      | (1ULL << (PhpParser::LogicalXor - 64))
      | (1ULL << (PhpParser::Namespace - 64))
      | (1ULL << (PhpParser::New - 64))
      | (1ULL << (PhpParser::Null - 64))
      | (1ULL << (PhpParser::ObjectType - 64))
      | (1ULL << (PhpParser::Parent_ - 64))
      | (1ULL << (PhpParser::Partial - 64))
      | (1ULL << (PhpParser::Print - 64))
      | (1ULL << (PhpParser::Private - 64))
      | (1ULL << (PhpParser::Protected - 64))
      | (1ULL << (PhpParser::Public - 64))
      | (1ULL << (PhpParser::Require - 64))
      | (1ULL << (PhpParser::RequireOnce - 64))
      | (1ULL << (PhpParser::Resource - 64))
      | (1ULL << (PhpParser::Return - 64))
      | (1ULL << (PhpParser::Static - 64))
      | (1ULL << (PhpParser::StringType - 64))
      | (1ULL << (PhpParser::Switch - 64))
      | (1ULL << (PhpParser::Throw - 64))
      | (1ULL << (PhpParser::Trait - 64))
      | (1ULL << (PhpParser::Try - 64))
      | (1ULL << (PhpParser::Typeof - 64))
      | (1ULL << (PhpParser::UintCast - 64))
      | (1ULL << (PhpParser::UnicodeCast - 64))
      | (1ULL << (PhpParser::Unset - 64))
      | (1ULL << (PhpParser::Use - 64))
      | (1ULL << (PhpParser::Var - 64))
      | (1ULL << (PhpParser::While - 64))
      | (1ULL << (PhpParser::Yield - 64))
      | (1ULL << (PhpParser::Get - 64))
      | (1ULL << (PhpParser::Set - 64))
      | (1ULL << (PhpParser::Call - 64))
      | (1ULL << (PhpParser::CallStatic - 64))
      | (1ULL << (PhpParser::Constructor - 64))
      | (1ULL << (PhpParser::Destruct - 64))
      | (1ULL << (PhpParser::Wakeup - 64))
      | (1ULL << (PhpParser::Sleep - 64))
      | (1ULL << (PhpParser::Autoload - 64))
      | (1ULL << (PhpParser::IsSet__ - 64))
      | (1ULL << (PhpParser::Unset__ - 64))
      | (1ULL << (PhpParser::ToString__ - 64))
      | (1ULL << (PhpParser::Invoke - 64))
      | (1ULL << (PhpParser::SetState - 64))
      | (1ULL << (PhpParser::Clone__ - 64))
      | (1ULL << (PhpParser::DebugInfo - 64))
      | (1ULL << (PhpParser::Namespace__ - 64))
      | (1ULL << (PhpParser::Class__ - 64))
      | (1ULL << (PhpParser::Traic__ - 64))
      | (1ULL << (PhpParser::Function__ - 64))
      | (1ULL << (PhpParser::Method__ - 64))
      | (1ULL << (PhpParser::Line__ - 64))
      | (1ULL << (PhpParser::File__ - 64))
      | (1ULL << (PhpParser::Dir__ - 64))
      | (1ULL << (PhpParser::Inc - 64))
      | (1ULL << (PhpParser::Dec - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
      | (1ULL << (PhpParser::Bang - 148))
      | (1ULL << (PhpParser::Plus - 148))
      | (1ULL << (PhpParser::Minus - 148))
      | (1ULL << (PhpParser::Tilde - 148))
      | (1ULL << (PhpParser::SuppressWarnings - 148))
      | (1ULL << (PhpParser::Dollar - 148))
      | (1ULL << (PhpParser::OpenRoundBracket - 148))
      | (1ULL << (PhpParser::OpenSquareBracket - 148))
      | (1ULL << (PhpParser::VarName - 148))
      | (1ULL << (PhpParser::Label - 148))
      | (1ULL << (PhpParser::Octal - 148))
      | (1ULL << (PhpParser::Decimal - 148))
      | (1ULL << (PhpParser::Real - 148))
      | (1ULL << (PhpParser::Hex - 148))
      | (1ULL << (PhpParser::Binary - 148))
      | (1ULL << (PhpParser::BackQuoteString - 148))
      | (1ULL << (PhpParser::SingleQuoteString - 148))
      | (1ULL << (PhpParser::DoubleQuote - 148))
      | (1ULL << (PhpParser::StartNowDoc - 148))
      | (1ULL << (PhpParser::StartHereDoc - 148)))) != 0)) {
      setState(613);
      expressionList();
    }
    setState(616);
    match(PhpParser::SemiColon);
    setState(618);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
      | (1ULL << PhpParser::Array)
      | (1ULL << PhpParser::As)
      | (1ULL << PhpParser::BinaryCast)
      | (1ULL << PhpParser::BoolType)
      | (1ULL << PhpParser::BooleanConstant)
      | (1ULL << PhpParser::Break)
      | (1ULL << PhpParser::Callable)
      | (1ULL << PhpParser::Case)
      | (1ULL << PhpParser::Catch)
      | (1ULL << PhpParser::Class)
      | (1ULL << PhpParser::Clone)
      | (1ULL << PhpParser::Const)
      | (1ULL << PhpParser::Continue)
      | (1ULL << PhpParser::Declare)
      | (1ULL << PhpParser::Default)
      | (1ULL << PhpParser::Do)
      | (1ULL << PhpParser::DoubleCast)
      | (1ULL << PhpParser::DoubleType)
      | (1ULL << PhpParser::Echo)
      | (1ULL << PhpParser::Else)
      | (1ULL << PhpParser::ElseIf)
      | (1ULL << PhpParser::Empty)
      | (1ULL << PhpParser::EndDeclare)
      | (1ULL << PhpParser::EndFor)
      | (1ULL << PhpParser::EndForeach)
      | (1ULL << PhpParser::EndIf)
      | (1ULL << PhpParser::EndSwitch)
      | (1ULL << PhpParser::EndWhile)
      | (1ULL << PhpParser::Eval)
      | (1ULL << PhpParser::Exit)
      | (1ULL << PhpParser::Extends)
      | (1ULL << PhpParser::Final)
      | (1ULL << PhpParser::Finally)
      | (1ULL << PhpParser::FloatCast)
      | (1ULL << PhpParser::For)
      | (1ULL << PhpParser::Foreach)
      | (1ULL << PhpParser::Function)
      | (1ULL << PhpParser::Global)
      | (1ULL << PhpParser::Goto)
      | (1ULL << PhpParser::If)
      | (1ULL << PhpParser::Implements)
      | (1ULL << PhpParser::Import)
      | (1ULL << PhpParser::Include)
      | (1ULL << PhpParser::IncludeOnce)
      | (1ULL << PhpParser::InstanceOf)
      | (1ULL << PhpParser::InsteadOf)
      | (1ULL << PhpParser::Int8Cast)
      | (1ULL << PhpParser::Int16Cast)
      | (1ULL << PhpParser::Int64Type)
      | (1ULL << PhpParser::IntType)
      | (1ULL << PhpParser::Interface)
      | (1ULL << PhpParser::IsSet)
      | (1ULL << PhpParser::List)
      | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
      | (1ULL << (PhpParser::LogicalXor - 64))
      | (1ULL << (PhpParser::Namespace - 64))
      | (1ULL << (PhpParser::New - 64))
      | (1ULL << (PhpParser::Null - 64))
      | (1ULL << (PhpParser::ObjectType - 64))
      | (1ULL << (PhpParser::Parent_ - 64))
      | (1ULL << (PhpParser::Partial - 64))
      | (1ULL << (PhpParser::Print - 64))
      | (1ULL << (PhpParser::Private - 64))
      | (1ULL << (PhpParser::Protected - 64))
      | (1ULL << (PhpParser::Public - 64))
      | (1ULL << (PhpParser::Require - 64))
      | (1ULL << (PhpParser::RequireOnce - 64))
      | (1ULL << (PhpParser::Resource - 64))
      | (1ULL << (PhpParser::Return - 64))
      | (1ULL << (PhpParser::Static - 64))
      | (1ULL << (PhpParser::StringType - 64))
      | (1ULL << (PhpParser::Switch - 64))
      | (1ULL << (PhpParser::Throw - 64))
      | (1ULL << (PhpParser::Trait - 64))
      | (1ULL << (PhpParser::Try - 64))
      | (1ULL << (PhpParser::Typeof - 64))
      | (1ULL << (PhpParser::UintCast - 64))
      | (1ULL << (PhpParser::UnicodeCast - 64))
      | (1ULL << (PhpParser::Unset - 64))
      | (1ULL << (PhpParser::Use - 64))
      | (1ULL << (PhpParser::Var - 64))
      | (1ULL << (PhpParser::While - 64))
      | (1ULL << (PhpParser::Yield - 64))
      | (1ULL << (PhpParser::Get - 64))
      | (1ULL << (PhpParser::Set - 64))
      | (1ULL << (PhpParser::Call - 64))
      | (1ULL << (PhpParser::CallStatic - 64))
      | (1ULL << (PhpParser::Constructor - 64))
      | (1ULL << (PhpParser::Destruct - 64))
      | (1ULL << (PhpParser::Wakeup - 64))
      | (1ULL << (PhpParser::Sleep - 64))
      | (1ULL << (PhpParser::Autoload - 64))
      | (1ULL << (PhpParser::IsSet__ - 64))
      | (1ULL << (PhpParser::Unset__ - 64))
      | (1ULL << (PhpParser::ToString__ - 64))
      | (1ULL << (PhpParser::Invoke - 64))
      | (1ULL << (PhpParser::SetState - 64))
      | (1ULL << (PhpParser::Clone__ - 64))
      | (1ULL << (PhpParser::DebugInfo - 64))
      | (1ULL << (PhpParser::Namespace__ - 64))
      | (1ULL << (PhpParser::Class__ - 64))
      | (1ULL << (PhpParser::Traic__ - 64))
      | (1ULL << (PhpParser::Function__ - 64))
      | (1ULL << (PhpParser::Method__ - 64))
      | (1ULL << (PhpParser::Line__ - 64))
      | (1ULL << (PhpParser::File__ - 64))
      | (1ULL << (PhpParser::Dir__ - 64))
      | (1ULL << (PhpParser::Inc - 64))
      | (1ULL << (PhpParser::Dec - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
      | (1ULL << (PhpParser::Bang - 148))
      | (1ULL << (PhpParser::Plus - 148))
      | (1ULL << (PhpParser::Minus - 148))
      | (1ULL << (PhpParser::Tilde - 148))
      | (1ULL << (PhpParser::SuppressWarnings - 148))
      | (1ULL << (PhpParser::Dollar - 148))
      | (1ULL << (PhpParser::OpenRoundBracket - 148))
      | (1ULL << (PhpParser::OpenSquareBracket - 148))
      | (1ULL << (PhpParser::VarName - 148))
      | (1ULL << (PhpParser::Label - 148))
      | (1ULL << (PhpParser::Octal - 148))
      | (1ULL << (PhpParser::Decimal - 148))
      | (1ULL << (PhpParser::Real - 148))
      | (1ULL << (PhpParser::Hex - 148))
      | (1ULL << (PhpParser::Binary - 148))
      | (1ULL << (PhpParser::BackQuoteString - 148))
      | (1ULL << (PhpParser::SingleQuoteString - 148))
      | (1ULL << (PhpParser::DoubleQuote - 148))
      | (1ULL << (PhpParser::StartNowDoc - 148))
      | (1ULL << (PhpParser::StartHereDoc - 148)))) != 0)) {
      setState(617);
      forUpdate();
    }
    setState(620);
    match(PhpParser::CloseRoundBracket);
    setState(627);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::Abstract:
      case PhpParser::Array:
      case PhpParser::As:
      case PhpParser::BinaryCast:
      case PhpParser::BoolType:
      case PhpParser::BooleanConstant:
      case PhpParser::Break:
      case PhpParser::Callable:
      case PhpParser::Case:
      case PhpParser::Catch:
      case PhpParser::Class:
      case PhpParser::Clone:
      case PhpParser::Const:
      case PhpParser::Continue:
      case PhpParser::Declare:
      case PhpParser::Default:
      case PhpParser::Do:
      case PhpParser::DoubleCast:
      case PhpParser::DoubleType:
      case PhpParser::Echo:
      case PhpParser::Else:
      case PhpParser::ElseIf:
      case PhpParser::Empty:
      case PhpParser::EndDeclare:
      case PhpParser::EndFor:
      case PhpParser::EndForeach:
      case PhpParser::EndIf:
      case PhpParser::EndSwitch:
      case PhpParser::EndWhile:
      case PhpParser::Eval:
      case PhpParser::Exit:
      case PhpParser::Extends:
      case PhpParser::Final:
      case PhpParser::Finally:
      case PhpParser::FloatCast:
      case PhpParser::For:
      case PhpParser::Foreach:
      case PhpParser::Function:
      case PhpParser::Global:
      case PhpParser::Goto:
      case PhpParser::If:
      case PhpParser::Implements:
      case PhpParser::Import:
      case PhpParser::Include:
      case PhpParser::IncludeOnce:
      case PhpParser::InstanceOf:
      case PhpParser::InsteadOf:
      case PhpParser::Int8Cast:
      case PhpParser::Int16Cast:
      case PhpParser::Int64Type:
      case PhpParser::IntType:
      case PhpParser::Interface:
      case PhpParser::IsSet:
      case PhpParser::List:
      case PhpParser::LogicalAnd:
      case PhpParser::LogicalOr:
      case PhpParser::LogicalXor:
      case PhpParser::Namespace:
      case PhpParser::New:
      case PhpParser::Null:
      case PhpParser::ObjectType:
      case PhpParser::Parent_:
      case PhpParser::Partial:
      case PhpParser::Print:
      case PhpParser::Private:
      case PhpParser::Protected:
      case PhpParser::Public:
      case PhpParser::Require:
      case PhpParser::RequireOnce:
      case PhpParser::Resource:
      case PhpParser::Return:
      case PhpParser::Static:
      case PhpParser::StringType:
      case PhpParser::Switch:
      case PhpParser::Throw:
      case PhpParser::Trait:
      case PhpParser::Try:
      case PhpParser::Typeof:
      case PhpParser::UintCast:
      case PhpParser::UnicodeCast:
      case PhpParser::Unset:
      case PhpParser::Use:
      case PhpParser::Var:
      case PhpParser::While:
      case PhpParser::Yield:
      case PhpParser::Get:
      case PhpParser::Set:
      case PhpParser::Call:
      case PhpParser::CallStatic:
      case PhpParser::Constructor:
      case PhpParser::Destruct:
      case PhpParser::Wakeup:
      case PhpParser::Sleep:
      case PhpParser::Autoload:
      case PhpParser::IsSet__:
      case PhpParser::Unset__:
      case PhpParser::ToString__:
      case PhpParser::Invoke:
      case PhpParser::SetState:
      case PhpParser::Clone__:
      case PhpParser::DebugInfo:
      case PhpParser::Namespace__:
      case PhpParser::Class__:
      case PhpParser::Traic__:
      case PhpParser::Function__:
      case PhpParser::Method__:
      case PhpParser::Line__:
      case PhpParser::File__:
      case PhpParser::Dir__:
      case PhpParser::Inc:
      case PhpParser::Dec:
      case PhpParser::NamespaceSeparator:
      case PhpParser::Bang:
      case PhpParser::Plus:
      case PhpParser::Minus:
      case PhpParser::Tilde:
      case PhpParser::SuppressWarnings:
      case PhpParser::Dollar:
      case PhpParser::OpenRoundBracket:
      case PhpParser::OpenSquareBracket:
      case PhpParser::OpenCurlyBracket:
      case PhpParser::SemiColon:
      case PhpParser::VarName:
      case PhpParser::Label:
      case PhpParser::Octal:
      case PhpParser::Decimal:
      case PhpParser::Real:
      case PhpParser::Hex:
      case PhpParser::Binary:
      case PhpParser::BackQuoteString:
      case PhpParser::SingleQuoteString:
      case PhpParser::DoubleQuote:
      case PhpParser::StartNowDoc:
      case PhpParser::StartHereDoc: {
        setState(621);
        statement();
        break;
      }

      case PhpParser::Colon: {
        setState(622);
        match(PhpParser::Colon);
        setState(623);
        innerStatementList();
        setState(624);
        match(PhpParser::EndFor);
        setState(625);
        match(PhpParser::SemiColon);
        break;
      }

    default:
      throw NoViableAltException(this);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ForInitContext ------------------------------------------------------------------

PhpParser::ForInitContext::ForInitContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::ExpressionListContext* PhpParser::ForInitContext::expressionList() {
  return getRuleContext<PhpParser::ExpressionListContext>(0);
}


size_t PhpParser::ForInitContext::getRuleIndex() const {
  return PhpParser::RuleForInit;
}

antlrcpp::Any PhpParser::ForInitContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitForInit(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ForInitContext* PhpParser::forInit() {
  ForInitContext *_localctx = _tracker.createInstance<ForInitContext>(_ctx, getState());
  enterRule(_localctx, 74, PhpParser::RuleForInit);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(629);
    expressionList();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ForUpdateContext ------------------------------------------------------------------

PhpParser::ForUpdateContext::ForUpdateContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::ExpressionListContext* PhpParser::ForUpdateContext::expressionList() {
  return getRuleContext<PhpParser::ExpressionListContext>(0);
}


size_t PhpParser::ForUpdateContext::getRuleIndex() const {
  return PhpParser::RuleForUpdate;
}

antlrcpp::Any PhpParser::ForUpdateContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitForUpdate(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ForUpdateContext* PhpParser::forUpdate() {
  ForUpdateContext *_localctx = _tracker.createInstance<ForUpdateContext>(_ctx, getState());
  enterRule(_localctx, 76, PhpParser::RuleForUpdate);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(631);
    expressionList();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SwitchStatementContext ------------------------------------------------------------------

PhpParser::SwitchStatementContext::SwitchStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::SwitchStatementContext::Switch() {
  return getToken(PhpParser::Switch, 0);
}

PhpParser::ParenthesisContext* PhpParser::SwitchStatementContext::parenthesis() {
  return getRuleContext<PhpParser::ParenthesisContext>(0);
}

tree::TerminalNode* PhpParser::SwitchStatementContext::OpenCurlyBracket() {
  return getToken(PhpParser::OpenCurlyBracket, 0);
}

tree::TerminalNode* PhpParser::SwitchStatementContext::EndSwitch() {
  return getToken(PhpParser::EndSwitch, 0);
}

std::vector<PhpParser::SwitchBlockContext *> PhpParser::SwitchStatementContext::switchBlock() {
  return getRuleContexts<PhpParser::SwitchBlockContext>();
}

PhpParser::SwitchBlockContext* PhpParser::SwitchStatementContext::switchBlock(size_t i) {
  return getRuleContext<PhpParser::SwitchBlockContext>(i);
}


size_t PhpParser::SwitchStatementContext::getRuleIndex() const {
  return PhpParser::RuleSwitchStatement;
}

antlrcpp::Any PhpParser::SwitchStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitSwitchStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::SwitchStatementContext* PhpParser::switchStatement() {
  SwitchStatementContext *_localctx = _tracker.createInstance<SwitchStatementContext>(_ctx, getState());
  enterRule(_localctx, 78, PhpParser::RuleSwitchStatement);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(633);
    match(PhpParser::Switch);
    setState(634);
    parenthesis();
    setState(658);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::OpenCurlyBracket: {
        setState(635);
        match(PhpParser::OpenCurlyBracket);
        setState(637);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == PhpParser::SemiColon) {
          setState(636);
          match(PhpParser::SemiColon);
        }
        setState(642);
        _errHandler->sync(this);
        _la = _input->LA(1);
        while (_la == PhpParser::Case

        || _la == PhpParser::Default) {
          setState(639);
          switchBlock();
          setState(644);
          _errHandler->sync(this);
          _la = _input->LA(1);
        }
        setState(645);
        match(PhpParser::CloseCurlyBracket);
        break;
      }

      case PhpParser::Colon: {
        setState(646);
        match(PhpParser::Colon);
        setState(648);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == PhpParser::SemiColon) {
          setState(647);
          match(PhpParser::SemiColon);
        }
        setState(653);
        _errHandler->sync(this);
        _la = _input->LA(1);
        while (_la == PhpParser::Case

        || _la == PhpParser::Default) {
          setState(650);
          switchBlock();
          setState(655);
          _errHandler->sync(this);
          _la = _input->LA(1);
        }
        setState(656);
        match(PhpParser::EndSwitch);
        setState(657);
        match(PhpParser::SemiColon);
        break;
      }

    default:
      throw NoViableAltException(this);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SwitchBlockContext ------------------------------------------------------------------

PhpParser::SwitchBlockContext::SwitchBlockContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::InnerStatementListContext* PhpParser::SwitchBlockContext::innerStatementList() {
  return getRuleContext<PhpParser::InnerStatementListContext>(0);
}

std::vector<tree::TerminalNode *> PhpParser::SwitchBlockContext::Case() {
  return getTokens(PhpParser::Case);
}

tree::TerminalNode* PhpParser::SwitchBlockContext::Case(size_t i) {
  return getToken(PhpParser::Case, i);
}

std::vector<PhpParser::ExpressionContext *> PhpParser::SwitchBlockContext::expression() {
  return getRuleContexts<PhpParser::ExpressionContext>();
}

PhpParser::ExpressionContext* PhpParser::SwitchBlockContext::expression(size_t i) {
  return getRuleContext<PhpParser::ExpressionContext>(i);
}

std::vector<tree::TerminalNode *> PhpParser::SwitchBlockContext::Default() {
  return getTokens(PhpParser::Default);
}

tree::TerminalNode* PhpParser::SwitchBlockContext::Default(size_t i) {
  return getToken(PhpParser::Default, i);
}


size_t PhpParser::SwitchBlockContext::getRuleIndex() const {
  return PhpParser::RuleSwitchBlock;
}

antlrcpp::Any PhpParser::SwitchBlockContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitSwitchBlock(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::SwitchBlockContext* PhpParser::switchBlock() {
  SwitchBlockContext *_localctx = _tracker.createInstance<SwitchBlockContext>(_ctx, getState());
  enterRule(_localctx, 80, PhpParser::RuleSwitchBlock);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(666); 
    _errHandler->sync(this);
    alt = 1;
    do {
      switch (alt) {
        case 1: {
              setState(663);
              _errHandler->sync(this);
              switch (_input->LA(1)) {
                case PhpParser::Case: {
                  setState(660);
                  match(PhpParser::Case);
                  setState(661);
                  expression(0);
                  break;
                }

                case PhpParser::Default: {
                  setState(662);
                  match(PhpParser::Default);
                  break;
                }

              default:
                throw NoViableAltException(this);
              }
              setState(665);
              _la = _input->LA(1);
              if (!(_la == PhpParser::Colon

              || _la == PhpParser::SemiColon)) {
              _errHandler->recoverInline(this);
              }
              else {
                _errHandler->reportMatch(this);
                consume();
              }
              break;
            }

      default:
        throw NoViableAltException(this);
      }
      setState(668); 
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 55, _ctx);
    } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
    setState(670);
    innerStatementList();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- BreakStatementContext ------------------------------------------------------------------

PhpParser::BreakStatementContext::BreakStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::BreakStatementContext::Break() {
  return getToken(PhpParser::Break, 0);
}

PhpParser::ExpressionContext* PhpParser::BreakStatementContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}


size_t PhpParser::BreakStatementContext::getRuleIndex() const {
  return PhpParser::RuleBreakStatement;
}

antlrcpp::Any PhpParser::BreakStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitBreakStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::BreakStatementContext* PhpParser::breakStatement() {
  BreakStatementContext *_localctx = _tracker.createInstance<BreakStatementContext>(_ctx, getState());
  enterRule(_localctx, 82, PhpParser::RuleBreakStatement);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(672);
    match(PhpParser::Break);
    setState(674);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
      | (1ULL << PhpParser::Array)
      | (1ULL << PhpParser::As)
      | (1ULL << PhpParser::BinaryCast)
      | (1ULL << PhpParser::BoolType)
      | (1ULL << PhpParser::BooleanConstant)
      | (1ULL << PhpParser::Break)
      | (1ULL << PhpParser::Callable)
      | (1ULL << PhpParser::Case)
      | (1ULL << PhpParser::Catch)
      | (1ULL << PhpParser::Class)
      | (1ULL << PhpParser::Clone)
      | (1ULL << PhpParser::Const)
      | (1ULL << PhpParser::Continue)
      | (1ULL << PhpParser::Declare)
      | (1ULL << PhpParser::Default)
      | (1ULL << PhpParser::Do)
      | (1ULL << PhpParser::DoubleCast)
      | (1ULL << PhpParser::DoubleType)
      | (1ULL << PhpParser::Echo)
      | (1ULL << PhpParser::Else)
      | (1ULL << PhpParser::ElseIf)
      | (1ULL << PhpParser::Empty)
      | (1ULL << PhpParser::EndDeclare)
      | (1ULL << PhpParser::EndFor)
      | (1ULL << PhpParser::EndForeach)
      | (1ULL << PhpParser::EndIf)
      | (1ULL << PhpParser::EndSwitch)
      | (1ULL << PhpParser::EndWhile)
      | (1ULL << PhpParser::Eval)
      | (1ULL << PhpParser::Exit)
      | (1ULL << PhpParser::Extends)
      | (1ULL << PhpParser::Final)
      | (1ULL << PhpParser::Finally)
      | (1ULL << PhpParser::FloatCast)
      | (1ULL << PhpParser::For)
      | (1ULL << PhpParser::Foreach)
      | (1ULL << PhpParser::Function)
      | (1ULL << PhpParser::Global)
      | (1ULL << PhpParser::Goto)
      | (1ULL << PhpParser::If)
      | (1ULL << PhpParser::Implements)
      | (1ULL << PhpParser::Import)
      | (1ULL << PhpParser::Include)
      | (1ULL << PhpParser::IncludeOnce)
      | (1ULL << PhpParser::InstanceOf)
      | (1ULL << PhpParser::InsteadOf)
      | (1ULL << PhpParser::Int8Cast)
      | (1ULL << PhpParser::Int16Cast)
      | (1ULL << PhpParser::Int64Type)
      | (1ULL << PhpParser::IntType)
      | (1ULL << PhpParser::Interface)
      | (1ULL << PhpParser::IsSet)
      | (1ULL << PhpParser::List)
      | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
      | (1ULL << (PhpParser::LogicalXor - 64))
      | (1ULL << (PhpParser::Namespace - 64))
      | (1ULL << (PhpParser::New - 64))
      | (1ULL << (PhpParser::Null - 64))
      | (1ULL << (PhpParser::ObjectType - 64))
      | (1ULL << (PhpParser::Parent_ - 64))
      | (1ULL << (PhpParser::Partial - 64))
      | (1ULL << (PhpParser::Print - 64))
      | (1ULL << (PhpParser::Private - 64))
      | (1ULL << (PhpParser::Protected - 64))
      | (1ULL << (PhpParser::Public - 64))
      | (1ULL << (PhpParser::Require - 64))
      | (1ULL << (PhpParser::RequireOnce - 64))
      | (1ULL << (PhpParser::Resource - 64))
      | (1ULL << (PhpParser::Return - 64))
      | (1ULL << (PhpParser::Static - 64))
      | (1ULL << (PhpParser::StringType - 64))
      | (1ULL << (PhpParser::Switch - 64))
      | (1ULL << (PhpParser::Throw - 64))
      | (1ULL << (PhpParser::Trait - 64))
      | (1ULL << (PhpParser::Try - 64))
      | (1ULL << (PhpParser::Typeof - 64))
      | (1ULL << (PhpParser::UintCast - 64))
      | (1ULL << (PhpParser::UnicodeCast - 64))
      | (1ULL << (PhpParser::Unset - 64))
      | (1ULL << (PhpParser::Use - 64))
      | (1ULL << (PhpParser::Var - 64))
      | (1ULL << (PhpParser::While - 64))
      | (1ULL << (PhpParser::Yield - 64))
      | (1ULL << (PhpParser::Get - 64))
      | (1ULL << (PhpParser::Set - 64))
      | (1ULL << (PhpParser::Call - 64))
      | (1ULL << (PhpParser::CallStatic - 64))
      | (1ULL << (PhpParser::Constructor - 64))
      | (1ULL << (PhpParser::Destruct - 64))
      | (1ULL << (PhpParser::Wakeup - 64))
      | (1ULL << (PhpParser::Sleep - 64))
      | (1ULL << (PhpParser::Autoload - 64))
      | (1ULL << (PhpParser::IsSet__ - 64))
      | (1ULL << (PhpParser::Unset__ - 64))
      | (1ULL << (PhpParser::ToString__ - 64))
      | (1ULL << (PhpParser::Invoke - 64))
      | (1ULL << (PhpParser::SetState - 64))
      | (1ULL << (PhpParser::Clone__ - 64))
      | (1ULL << (PhpParser::DebugInfo - 64))
      | (1ULL << (PhpParser::Namespace__ - 64))
      | (1ULL << (PhpParser::Class__ - 64))
      | (1ULL << (PhpParser::Traic__ - 64))
      | (1ULL << (PhpParser::Function__ - 64))
      | (1ULL << (PhpParser::Method__ - 64))
      | (1ULL << (PhpParser::Line__ - 64))
      | (1ULL << (PhpParser::File__ - 64))
      | (1ULL << (PhpParser::Dir__ - 64))
      | (1ULL << (PhpParser::Inc - 64))
      | (1ULL << (PhpParser::Dec - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
      | (1ULL << (PhpParser::Bang - 148))
      | (1ULL << (PhpParser::Plus - 148))
      | (1ULL << (PhpParser::Minus - 148))
      | (1ULL << (PhpParser::Tilde - 148))
      | (1ULL << (PhpParser::SuppressWarnings - 148))
      | (1ULL << (PhpParser::Dollar - 148))
      | (1ULL << (PhpParser::OpenRoundBracket - 148))
      | (1ULL << (PhpParser::OpenSquareBracket - 148))
      | (1ULL << (PhpParser::VarName - 148))
      | (1ULL << (PhpParser::Label - 148))
      | (1ULL << (PhpParser::Octal - 148))
      | (1ULL << (PhpParser::Decimal - 148))
      | (1ULL << (PhpParser::Real - 148))
      | (1ULL << (PhpParser::Hex - 148))
      | (1ULL << (PhpParser::Binary - 148))
      | (1ULL << (PhpParser::BackQuoteString - 148))
      | (1ULL << (PhpParser::SingleQuoteString - 148))
      | (1ULL << (PhpParser::DoubleQuote - 148))
      | (1ULL << (PhpParser::StartNowDoc - 148))
      | (1ULL << (PhpParser::StartHereDoc - 148)))) != 0)) {
      setState(673);
      expression(0);
    }
    setState(676);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ContinueStatementContext ------------------------------------------------------------------

PhpParser::ContinueStatementContext::ContinueStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::ContinueStatementContext::Continue() {
  return getToken(PhpParser::Continue, 0);
}

PhpParser::ExpressionContext* PhpParser::ContinueStatementContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}


size_t PhpParser::ContinueStatementContext::getRuleIndex() const {
  return PhpParser::RuleContinueStatement;
}

antlrcpp::Any PhpParser::ContinueStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitContinueStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ContinueStatementContext* PhpParser::continueStatement() {
  ContinueStatementContext *_localctx = _tracker.createInstance<ContinueStatementContext>(_ctx, getState());
  enterRule(_localctx, 84, PhpParser::RuleContinueStatement);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(678);
    match(PhpParser::Continue);
    setState(680);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
      | (1ULL << PhpParser::Array)
      | (1ULL << PhpParser::As)
      | (1ULL << PhpParser::BinaryCast)
      | (1ULL << PhpParser::BoolType)
      | (1ULL << PhpParser::BooleanConstant)
      | (1ULL << PhpParser::Break)
      | (1ULL << PhpParser::Callable)
      | (1ULL << PhpParser::Case)
      | (1ULL << PhpParser::Catch)
      | (1ULL << PhpParser::Class)
      | (1ULL << PhpParser::Clone)
      | (1ULL << PhpParser::Const)
      | (1ULL << PhpParser::Continue)
      | (1ULL << PhpParser::Declare)
      | (1ULL << PhpParser::Default)
      | (1ULL << PhpParser::Do)
      | (1ULL << PhpParser::DoubleCast)
      | (1ULL << PhpParser::DoubleType)
      | (1ULL << PhpParser::Echo)
      | (1ULL << PhpParser::Else)
      | (1ULL << PhpParser::ElseIf)
      | (1ULL << PhpParser::Empty)
      | (1ULL << PhpParser::EndDeclare)
      | (1ULL << PhpParser::EndFor)
      | (1ULL << PhpParser::EndForeach)
      | (1ULL << PhpParser::EndIf)
      | (1ULL << PhpParser::EndSwitch)
      | (1ULL << PhpParser::EndWhile)
      | (1ULL << PhpParser::Eval)
      | (1ULL << PhpParser::Exit)
      | (1ULL << PhpParser::Extends)
      | (1ULL << PhpParser::Final)
      | (1ULL << PhpParser::Finally)
      | (1ULL << PhpParser::FloatCast)
      | (1ULL << PhpParser::For)
      | (1ULL << PhpParser::Foreach)
      | (1ULL << PhpParser::Function)
      | (1ULL << PhpParser::Global)
      | (1ULL << PhpParser::Goto)
      | (1ULL << PhpParser::If)
      | (1ULL << PhpParser::Implements)
      | (1ULL << PhpParser::Import)
      | (1ULL << PhpParser::Include)
      | (1ULL << PhpParser::IncludeOnce)
      | (1ULL << PhpParser::InstanceOf)
      | (1ULL << PhpParser::InsteadOf)
      | (1ULL << PhpParser::Int8Cast)
      | (1ULL << PhpParser::Int16Cast)
      | (1ULL << PhpParser::Int64Type)
      | (1ULL << PhpParser::IntType)
      | (1ULL << PhpParser::Interface)
      | (1ULL << PhpParser::IsSet)
      | (1ULL << PhpParser::List)
      | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
      | (1ULL << (PhpParser::LogicalXor - 64))
      | (1ULL << (PhpParser::Namespace - 64))
      | (1ULL << (PhpParser::New - 64))
      | (1ULL << (PhpParser::Null - 64))
      | (1ULL << (PhpParser::ObjectType - 64))
      | (1ULL << (PhpParser::Parent_ - 64))
      | (1ULL << (PhpParser::Partial - 64))
      | (1ULL << (PhpParser::Print - 64))
      | (1ULL << (PhpParser::Private - 64))
      | (1ULL << (PhpParser::Protected - 64))
      | (1ULL << (PhpParser::Public - 64))
      | (1ULL << (PhpParser::Require - 64))
      | (1ULL << (PhpParser::RequireOnce - 64))
      | (1ULL << (PhpParser::Resource - 64))
      | (1ULL << (PhpParser::Return - 64))
      | (1ULL << (PhpParser::Static - 64))
      | (1ULL << (PhpParser::StringType - 64))
      | (1ULL << (PhpParser::Switch - 64))
      | (1ULL << (PhpParser::Throw - 64))
      | (1ULL << (PhpParser::Trait - 64))
      | (1ULL << (PhpParser::Try - 64))
      | (1ULL << (PhpParser::Typeof - 64))
      | (1ULL << (PhpParser::UintCast - 64))
      | (1ULL << (PhpParser::UnicodeCast - 64))
      | (1ULL << (PhpParser::Unset - 64))
      | (1ULL << (PhpParser::Use - 64))
      | (1ULL << (PhpParser::Var - 64))
      | (1ULL << (PhpParser::While - 64))
      | (1ULL << (PhpParser::Yield - 64))
      | (1ULL << (PhpParser::Get - 64))
      | (1ULL << (PhpParser::Set - 64))
      | (1ULL << (PhpParser::Call - 64))
      | (1ULL << (PhpParser::CallStatic - 64))
      | (1ULL << (PhpParser::Constructor - 64))
      | (1ULL << (PhpParser::Destruct - 64))
      | (1ULL << (PhpParser::Wakeup - 64))
      | (1ULL << (PhpParser::Sleep - 64))
      | (1ULL << (PhpParser::Autoload - 64))
      | (1ULL << (PhpParser::IsSet__ - 64))
      | (1ULL << (PhpParser::Unset__ - 64))
      | (1ULL << (PhpParser::ToString__ - 64))
      | (1ULL << (PhpParser::Invoke - 64))
      | (1ULL << (PhpParser::SetState - 64))
      | (1ULL << (PhpParser::Clone__ - 64))
      | (1ULL << (PhpParser::DebugInfo - 64))
      | (1ULL << (PhpParser::Namespace__ - 64))
      | (1ULL << (PhpParser::Class__ - 64))
      | (1ULL << (PhpParser::Traic__ - 64))
      | (1ULL << (PhpParser::Function__ - 64))
      | (1ULL << (PhpParser::Method__ - 64))
      | (1ULL << (PhpParser::Line__ - 64))
      | (1ULL << (PhpParser::File__ - 64))
      | (1ULL << (PhpParser::Dir__ - 64))
      | (1ULL << (PhpParser::Inc - 64))
      | (1ULL << (PhpParser::Dec - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
      | (1ULL << (PhpParser::Bang - 148))
      | (1ULL << (PhpParser::Plus - 148))
      | (1ULL << (PhpParser::Minus - 148))
      | (1ULL << (PhpParser::Tilde - 148))
      | (1ULL << (PhpParser::SuppressWarnings - 148))
      | (1ULL << (PhpParser::Dollar - 148))
      | (1ULL << (PhpParser::OpenRoundBracket - 148))
      | (1ULL << (PhpParser::OpenSquareBracket - 148))
      | (1ULL << (PhpParser::VarName - 148))
      | (1ULL << (PhpParser::Label - 148))
      | (1ULL << (PhpParser::Octal - 148))
      | (1ULL << (PhpParser::Decimal - 148))
      | (1ULL << (PhpParser::Real - 148))
      | (1ULL << (PhpParser::Hex - 148))
      | (1ULL << (PhpParser::Binary - 148))
      | (1ULL << (PhpParser::BackQuoteString - 148))
      | (1ULL << (PhpParser::SingleQuoteString - 148))
      | (1ULL << (PhpParser::DoubleQuote - 148))
      | (1ULL << (PhpParser::StartNowDoc - 148))
      | (1ULL << (PhpParser::StartHereDoc - 148)))) != 0)) {
      setState(679);
      expression(0);
    }
    setState(682);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ReturnStatementContext ------------------------------------------------------------------

PhpParser::ReturnStatementContext::ReturnStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::ReturnStatementContext::Return() {
  return getToken(PhpParser::Return, 0);
}

PhpParser::ExpressionContext* PhpParser::ReturnStatementContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}


size_t PhpParser::ReturnStatementContext::getRuleIndex() const {
  return PhpParser::RuleReturnStatement;
}

antlrcpp::Any PhpParser::ReturnStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitReturnStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ReturnStatementContext* PhpParser::returnStatement() {
  ReturnStatementContext *_localctx = _tracker.createInstance<ReturnStatementContext>(_ctx, getState());
  enterRule(_localctx, 86, PhpParser::RuleReturnStatement);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(684);
    match(PhpParser::Return);
    setState(686);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
      | (1ULL << PhpParser::Array)
      | (1ULL << PhpParser::As)
      | (1ULL << PhpParser::BinaryCast)
      | (1ULL << PhpParser::BoolType)
      | (1ULL << PhpParser::BooleanConstant)
      | (1ULL << PhpParser::Break)
      | (1ULL << PhpParser::Callable)
      | (1ULL << PhpParser::Case)
      | (1ULL << PhpParser::Catch)
      | (1ULL << PhpParser::Class)
      | (1ULL << PhpParser::Clone)
      | (1ULL << PhpParser::Const)
      | (1ULL << PhpParser::Continue)
      | (1ULL << PhpParser::Declare)
      | (1ULL << PhpParser::Default)
      | (1ULL << PhpParser::Do)
      | (1ULL << PhpParser::DoubleCast)
      | (1ULL << PhpParser::DoubleType)
      | (1ULL << PhpParser::Echo)
      | (1ULL << PhpParser::Else)
      | (1ULL << PhpParser::ElseIf)
      | (1ULL << PhpParser::Empty)
      | (1ULL << PhpParser::EndDeclare)
      | (1ULL << PhpParser::EndFor)
      | (1ULL << PhpParser::EndForeach)
      | (1ULL << PhpParser::EndIf)
      | (1ULL << PhpParser::EndSwitch)
      | (1ULL << PhpParser::EndWhile)
      | (1ULL << PhpParser::Eval)
      | (1ULL << PhpParser::Exit)
      | (1ULL << PhpParser::Extends)
      | (1ULL << PhpParser::Final)
      | (1ULL << PhpParser::Finally)
      | (1ULL << PhpParser::FloatCast)
      | (1ULL << PhpParser::For)
      | (1ULL << PhpParser::Foreach)
      | (1ULL << PhpParser::Function)
      | (1ULL << PhpParser::Global)
      | (1ULL << PhpParser::Goto)
      | (1ULL << PhpParser::If)
      | (1ULL << PhpParser::Implements)
      | (1ULL << PhpParser::Import)
      | (1ULL << PhpParser::Include)
      | (1ULL << PhpParser::IncludeOnce)
      | (1ULL << PhpParser::InstanceOf)
      | (1ULL << PhpParser::InsteadOf)
      | (1ULL << PhpParser::Int8Cast)
      | (1ULL << PhpParser::Int16Cast)
      | (1ULL << PhpParser::Int64Type)
      | (1ULL << PhpParser::IntType)
      | (1ULL << PhpParser::Interface)
      | (1ULL << PhpParser::IsSet)
      | (1ULL << PhpParser::List)
      | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
      | (1ULL << (PhpParser::LogicalXor - 64))
      | (1ULL << (PhpParser::Namespace - 64))
      | (1ULL << (PhpParser::New - 64))
      | (1ULL << (PhpParser::Null - 64))
      | (1ULL << (PhpParser::ObjectType - 64))
      | (1ULL << (PhpParser::Parent_ - 64))
      | (1ULL << (PhpParser::Partial - 64))
      | (1ULL << (PhpParser::Print - 64))
      | (1ULL << (PhpParser::Private - 64))
      | (1ULL << (PhpParser::Protected - 64))
      | (1ULL << (PhpParser::Public - 64))
      | (1ULL << (PhpParser::Require - 64))
      | (1ULL << (PhpParser::RequireOnce - 64))
      | (1ULL << (PhpParser::Resource - 64))
      | (1ULL << (PhpParser::Return - 64))
      | (1ULL << (PhpParser::Static - 64))
      | (1ULL << (PhpParser::StringType - 64))
      | (1ULL << (PhpParser::Switch - 64))
      | (1ULL << (PhpParser::Throw - 64))
      | (1ULL << (PhpParser::Trait - 64))
      | (1ULL << (PhpParser::Try - 64))
      | (1ULL << (PhpParser::Typeof - 64))
      | (1ULL << (PhpParser::UintCast - 64))
      | (1ULL << (PhpParser::UnicodeCast - 64))
      | (1ULL << (PhpParser::Unset - 64))
      | (1ULL << (PhpParser::Use - 64))
      | (1ULL << (PhpParser::Var - 64))
      | (1ULL << (PhpParser::While - 64))
      | (1ULL << (PhpParser::Yield - 64))
      | (1ULL << (PhpParser::Get - 64))
      | (1ULL << (PhpParser::Set - 64))
      | (1ULL << (PhpParser::Call - 64))
      | (1ULL << (PhpParser::CallStatic - 64))
      | (1ULL << (PhpParser::Constructor - 64))
      | (1ULL << (PhpParser::Destruct - 64))
      | (1ULL << (PhpParser::Wakeup - 64))
      | (1ULL << (PhpParser::Sleep - 64))
      | (1ULL << (PhpParser::Autoload - 64))
      | (1ULL << (PhpParser::IsSet__ - 64))
      | (1ULL << (PhpParser::Unset__ - 64))
      | (1ULL << (PhpParser::ToString__ - 64))
      | (1ULL << (PhpParser::Invoke - 64))
      | (1ULL << (PhpParser::SetState - 64))
      | (1ULL << (PhpParser::Clone__ - 64))
      | (1ULL << (PhpParser::DebugInfo - 64))
      | (1ULL << (PhpParser::Namespace__ - 64))
      | (1ULL << (PhpParser::Class__ - 64))
      | (1ULL << (PhpParser::Traic__ - 64))
      | (1ULL << (PhpParser::Function__ - 64))
      | (1ULL << (PhpParser::Method__ - 64))
      | (1ULL << (PhpParser::Line__ - 64))
      | (1ULL << (PhpParser::File__ - 64))
      | (1ULL << (PhpParser::Dir__ - 64))
      | (1ULL << (PhpParser::Inc - 64))
      | (1ULL << (PhpParser::Dec - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
      | (1ULL << (PhpParser::Bang - 148))
      | (1ULL << (PhpParser::Plus - 148))
      | (1ULL << (PhpParser::Minus - 148))
      | (1ULL << (PhpParser::Tilde - 148))
      | (1ULL << (PhpParser::SuppressWarnings - 148))
      | (1ULL << (PhpParser::Dollar - 148))
      | (1ULL << (PhpParser::OpenRoundBracket - 148))
      | (1ULL << (PhpParser::OpenSquareBracket - 148))
      | (1ULL << (PhpParser::VarName - 148))
      | (1ULL << (PhpParser::Label - 148))
      | (1ULL << (PhpParser::Octal - 148))
      | (1ULL << (PhpParser::Decimal - 148))
      | (1ULL << (PhpParser::Real - 148))
      | (1ULL << (PhpParser::Hex - 148))
      | (1ULL << (PhpParser::Binary - 148))
      | (1ULL << (PhpParser::BackQuoteString - 148))
      | (1ULL << (PhpParser::SingleQuoteString - 148))
      | (1ULL << (PhpParser::DoubleQuote - 148))
      | (1ULL << (PhpParser::StartNowDoc - 148))
      | (1ULL << (PhpParser::StartHereDoc - 148)))) != 0)) {
      setState(685);
      expression(0);
    }
    setState(688);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ExpressionStatementContext ------------------------------------------------------------------

PhpParser::ExpressionStatementContext::ExpressionStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::ExpressionContext* PhpParser::ExpressionStatementContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}


size_t PhpParser::ExpressionStatementContext::getRuleIndex() const {
  return PhpParser::RuleExpressionStatement;
}

antlrcpp::Any PhpParser::ExpressionStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitExpressionStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ExpressionStatementContext* PhpParser::expressionStatement() {
  ExpressionStatementContext *_localctx = _tracker.createInstance<ExpressionStatementContext>(_ctx, getState());
  enterRule(_localctx, 88, PhpParser::RuleExpressionStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(690);
    expression(0);
    setState(691);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- UnsetStatementContext ------------------------------------------------------------------

PhpParser::UnsetStatementContext::UnsetStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::UnsetStatementContext::Unset() {
  return getToken(PhpParser::Unset, 0);
}

PhpParser::ChainListContext* PhpParser::UnsetStatementContext::chainList() {
  return getRuleContext<PhpParser::ChainListContext>(0);
}


size_t PhpParser::UnsetStatementContext::getRuleIndex() const {
  return PhpParser::RuleUnsetStatement;
}

antlrcpp::Any PhpParser::UnsetStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitUnsetStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::UnsetStatementContext* PhpParser::unsetStatement() {
  UnsetStatementContext *_localctx = _tracker.createInstance<UnsetStatementContext>(_ctx, getState());
  enterRule(_localctx, 90, PhpParser::RuleUnsetStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(693);
    match(PhpParser::Unset);
    setState(694);
    match(PhpParser::OpenRoundBracket);
    setState(695);
    chainList();
    setState(696);
    match(PhpParser::CloseRoundBracket);
    setState(697);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ForeachStatementContext ------------------------------------------------------------------

PhpParser::ForeachStatementContext::ForeachStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::ForeachStatementContext::Foreach() {
  return getToken(PhpParser::Foreach, 0);
}

std::vector<PhpParser::ChainContext *> PhpParser::ForeachStatementContext::chain() {
  return getRuleContexts<PhpParser::ChainContext>();
}

PhpParser::ChainContext* PhpParser::ForeachStatementContext::chain(size_t i) {
  return getRuleContext<PhpParser::ChainContext>(i);
}

tree::TerminalNode* PhpParser::ForeachStatementContext::As() {
  return getToken(PhpParser::As, 0);
}

PhpParser::ExpressionContext* PhpParser::ForeachStatementContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}

tree::TerminalNode* PhpParser::ForeachStatementContext::List() {
  return getToken(PhpParser::List, 0);
}

PhpParser::AssignmentListContext* PhpParser::ForeachStatementContext::assignmentList() {
  return getRuleContext<PhpParser::AssignmentListContext>(0);
}

PhpParser::StatementContext* PhpParser::ForeachStatementContext::statement() {
  return getRuleContext<PhpParser::StatementContext>(0);
}

PhpParser::InnerStatementListContext* PhpParser::ForeachStatementContext::innerStatementList() {
  return getRuleContext<PhpParser::InnerStatementListContext>(0);
}

tree::TerminalNode* PhpParser::ForeachStatementContext::EndForeach() {
  return getToken(PhpParser::EndForeach, 0);
}


size_t PhpParser::ForeachStatementContext::getRuleIndex() const {
  return PhpParser::RuleForeachStatement;
}

antlrcpp::Any PhpParser::ForeachStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitForeachStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ForeachStatementContext* PhpParser::foreachStatement() {
  ForeachStatementContext *_localctx = _tracker.createInstance<ForeachStatementContext>(_ctx, getState());
  enterRule(_localctx, 92, PhpParser::RuleForeachStatement);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(699);
    match(PhpParser::Foreach);
    setState(738);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 64, _ctx)) {
    case 1: {
      setState(700);
      match(PhpParser::OpenRoundBracket);
      setState(701);
      chain();
      setState(702);
      match(PhpParser::As);
      setState(704);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == PhpParser::Ampersand) {
        setState(703);
        match(PhpParser::Ampersand);
      }
      setState(706);
      chain();
      setState(712);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == PhpParser::DoubleArrow) {
        setState(707);
        match(PhpParser::DoubleArrow);
        setState(709);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == PhpParser::Ampersand) {
          setState(708);
          match(PhpParser::Ampersand);
        }
        setState(711);
        chain();
      }
      setState(714);
      match(PhpParser::CloseRoundBracket);
      break;
    }

    case 2: {
      setState(716);
      match(PhpParser::OpenRoundBracket);
      setState(717);
      expression(0);
      setState(718);
      match(PhpParser::As);
      setState(719);
      chain();
      setState(725);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == PhpParser::DoubleArrow) {
        setState(720);
        match(PhpParser::DoubleArrow);
        setState(722);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == PhpParser::Ampersand) {
          setState(721);
          match(PhpParser::Ampersand);
        }
        setState(724);
        chain();
      }
      setState(727);
      match(PhpParser::CloseRoundBracket);
      break;
    }

    case 3: {
      setState(729);
      match(PhpParser::OpenRoundBracket);
      setState(730);
      chain();
      setState(731);
      match(PhpParser::As);
      setState(732);
      match(PhpParser::List);
      setState(733);
      match(PhpParser::OpenRoundBracket);
      setState(734);
      assignmentList();
      setState(735);
      match(PhpParser::CloseRoundBracket);
      setState(736);
      match(PhpParser::CloseRoundBracket);
      break;
    }

    }
    setState(746);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::Abstract:
      case PhpParser::Array:
      case PhpParser::As:
      case PhpParser::BinaryCast:
      case PhpParser::BoolType:
      case PhpParser::BooleanConstant:
      case PhpParser::Break:
      case PhpParser::Callable:
      case PhpParser::Case:
      case PhpParser::Catch:
      case PhpParser::Class:
      case PhpParser::Clone:
      case PhpParser::Const:
      case PhpParser::Continue:
      case PhpParser::Declare:
      case PhpParser::Default:
      case PhpParser::Do:
      case PhpParser::DoubleCast:
      case PhpParser::DoubleType:
      case PhpParser::Echo:
      case PhpParser::Else:
      case PhpParser::ElseIf:
      case PhpParser::Empty:
      case PhpParser::EndDeclare:
      case PhpParser::EndFor:
      case PhpParser::EndForeach:
      case PhpParser::EndIf:
      case PhpParser::EndSwitch:
      case PhpParser::EndWhile:
      case PhpParser::Eval:
      case PhpParser::Exit:
      case PhpParser::Extends:
      case PhpParser::Final:
      case PhpParser::Finally:
      case PhpParser::FloatCast:
      case PhpParser::For:
      case PhpParser::Foreach:
      case PhpParser::Function:
      case PhpParser::Global:
      case PhpParser::Goto:
      case PhpParser::If:
      case PhpParser::Implements:
      case PhpParser::Import:
      case PhpParser::Include:
      case PhpParser::IncludeOnce:
      case PhpParser::InstanceOf:
      case PhpParser::InsteadOf:
      case PhpParser::Int8Cast:
      case PhpParser::Int16Cast:
      case PhpParser::Int64Type:
      case PhpParser::IntType:
      case PhpParser::Interface:
      case PhpParser::IsSet:
      case PhpParser::List:
      case PhpParser::LogicalAnd:
      case PhpParser::LogicalOr:
      case PhpParser::LogicalXor:
      case PhpParser::Namespace:
      case PhpParser::New:
      case PhpParser::Null:
      case PhpParser::ObjectType:
      case PhpParser::Parent_:
      case PhpParser::Partial:
      case PhpParser::Print:
      case PhpParser::Private:
      case PhpParser::Protected:
      case PhpParser::Public:
      case PhpParser::Require:
      case PhpParser::RequireOnce:
      case PhpParser::Resource:
      case PhpParser::Return:
      case PhpParser::Static:
      case PhpParser::StringType:
      case PhpParser::Switch:
      case PhpParser::Throw:
      case PhpParser::Trait:
      case PhpParser::Try:
      case PhpParser::Typeof:
      case PhpParser::UintCast:
      case PhpParser::UnicodeCast:
      case PhpParser::Unset:
      case PhpParser::Use:
      case PhpParser::Var:
      case PhpParser::While:
      case PhpParser::Yield:
      case PhpParser::Get:
      case PhpParser::Set:
      case PhpParser::Call:
      case PhpParser::CallStatic:
      case PhpParser::Constructor:
      case PhpParser::Destruct:
      case PhpParser::Wakeup:
      case PhpParser::Sleep:
      case PhpParser::Autoload:
      case PhpParser::IsSet__:
      case PhpParser::Unset__:
      case PhpParser::ToString__:
      case PhpParser::Invoke:
      case PhpParser::SetState:
      case PhpParser::Clone__:
      case PhpParser::DebugInfo:
      case PhpParser::Namespace__:
      case PhpParser::Class__:
      case PhpParser::Traic__:
      case PhpParser::Function__:
      case PhpParser::Method__:
      case PhpParser::Line__:
      case PhpParser::File__:
      case PhpParser::Dir__:
      case PhpParser::Inc:
      case PhpParser::Dec:
      case PhpParser::NamespaceSeparator:
      case PhpParser::Bang:
      case PhpParser::Plus:
      case PhpParser::Minus:
      case PhpParser::Tilde:
      case PhpParser::SuppressWarnings:
      case PhpParser::Dollar:
      case PhpParser::OpenRoundBracket:
      case PhpParser::OpenSquareBracket:
      case PhpParser::OpenCurlyBracket:
      case PhpParser::SemiColon:
      case PhpParser::VarName:
      case PhpParser::Label:
      case PhpParser::Octal:
      case PhpParser::Decimal:
      case PhpParser::Real:
      case PhpParser::Hex:
      case PhpParser::Binary:
      case PhpParser::BackQuoteString:
      case PhpParser::SingleQuoteString:
      case PhpParser::DoubleQuote:
      case PhpParser::StartNowDoc:
      case PhpParser::StartHereDoc: {
        setState(740);
        statement();
        break;
      }

      case PhpParser::Colon: {
        setState(741);
        match(PhpParser::Colon);
        setState(742);
        innerStatementList();
        setState(743);
        match(PhpParser::EndForeach);
        setState(744);
        match(PhpParser::SemiColon);
        break;
      }

    default:
      throw NoViableAltException(this);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TryCatchFinallyContext ------------------------------------------------------------------

PhpParser::TryCatchFinallyContext::TryCatchFinallyContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::TryCatchFinallyContext::Try() {
  return getToken(PhpParser::Try, 0);
}

PhpParser::BlockStatementContext* PhpParser::TryCatchFinallyContext::blockStatement() {
  return getRuleContext<PhpParser::BlockStatementContext>(0);
}

PhpParser::FinallyStatementContext* PhpParser::TryCatchFinallyContext::finallyStatement() {
  return getRuleContext<PhpParser::FinallyStatementContext>(0);
}

std::vector<PhpParser::CatchClauseContext *> PhpParser::TryCatchFinallyContext::catchClause() {
  return getRuleContexts<PhpParser::CatchClauseContext>();
}

PhpParser::CatchClauseContext* PhpParser::TryCatchFinallyContext::catchClause(size_t i) {
  return getRuleContext<PhpParser::CatchClauseContext>(i);
}


size_t PhpParser::TryCatchFinallyContext::getRuleIndex() const {
  return PhpParser::RuleTryCatchFinally;
}

antlrcpp::Any PhpParser::TryCatchFinallyContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitTryCatchFinally(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::TryCatchFinallyContext* PhpParser::tryCatchFinally() {
  TryCatchFinallyContext *_localctx = _tracker.createInstance<TryCatchFinallyContext>(_ctx, getState());
  enterRule(_localctx, 94, PhpParser::RuleTryCatchFinally);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(748);
    match(PhpParser::Try);
    setState(749);
    blockStatement();
    setState(765);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 69, _ctx)) {
    case 1: {
      setState(751); 
      _errHandler->sync(this);
      alt = 1;
      do {
        switch (alt) {
          case 1: {
                setState(750);
                catchClause();
                break;
              }

        default:
          throw NoViableAltException(this);
        }
        setState(753); 
        _errHandler->sync(this);
        alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 66, _ctx);
      } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
      setState(756);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 67, _ctx)) {
      case 1: {
        setState(755);
        finallyStatement();
        break;
      }

      }
      break;
    }

    case 2: {
      setState(761);
      _errHandler->sync(this);
      _la = _input->LA(1);
      while (_la == PhpParser::Catch) {
        setState(758);
        catchClause();
        setState(763);
        _errHandler->sync(this);
        _la = _input->LA(1);
      }
      setState(764);
      finallyStatement();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- CatchClauseContext ------------------------------------------------------------------

PhpParser::CatchClauseContext::CatchClauseContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::CatchClauseContext::Catch() {
  return getToken(PhpParser::Catch, 0);
}

PhpParser::QualifiedStaticTypeRefContext* PhpParser::CatchClauseContext::qualifiedStaticTypeRef() {
  return getRuleContext<PhpParser::QualifiedStaticTypeRefContext>(0);
}

tree::TerminalNode* PhpParser::CatchClauseContext::VarName() {
  return getToken(PhpParser::VarName, 0);
}

PhpParser::BlockStatementContext* PhpParser::CatchClauseContext::blockStatement() {
  return getRuleContext<PhpParser::BlockStatementContext>(0);
}


size_t PhpParser::CatchClauseContext::getRuleIndex() const {
  return PhpParser::RuleCatchClause;
}

antlrcpp::Any PhpParser::CatchClauseContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitCatchClause(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::CatchClauseContext* PhpParser::catchClause() {
  CatchClauseContext *_localctx = _tracker.createInstance<CatchClauseContext>(_ctx, getState());
  enterRule(_localctx, 96, PhpParser::RuleCatchClause);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(767);
    match(PhpParser::Catch);
    setState(768);
    match(PhpParser::OpenRoundBracket);
    setState(769);
    qualifiedStaticTypeRef();
    setState(770);
    match(PhpParser::VarName);
    setState(771);
    match(PhpParser::CloseRoundBracket);
    setState(772);
    blockStatement();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- FinallyStatementContext ------------------------------------------------------------------

PhpParser::FinallyStatementContext::FinallyStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::FinallyStatementContext::Finally() {
  return getToken(PhpParser::Finally, 0);
}

PhpParser::BlockStatementContext* PhpParser::FinallyStatementContext::blockStatement() {
  return getRuleContext<PhpParser::BlockStatementContext>(0);
}


size_t PhpParser::FinallyStatementContext::getRuleIndex() const {
  return PhpParser::RuleFinallyStatement;
}

antlrcpp::Any PhpParser::FinallyStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitFinallyStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::FinallyStatementContext* PhpParser::finallyStatement() {
  FinallyStatementContext *_localctx = _tracker.createInstance<FinallyStatementContext>(_ctx, getState());
  enterRule(_localctx, 98, PhpParser::RuleFinallyStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(774);
    match(PhpParser::Finally);
    setState(775);
    blockStatement();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ThrowStatementContext ------------------------------------------------------------------

PhpParser::ThrowStatementContext::ThrowStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::ThrowStatementContext::Throw() {
  return getToken(PhpParser::Throw, 0);
}

PhpParser::ExpressionContext* PhpParser::ThrowStatementContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}


size_t PhpParser::ThrowStatementContext::getRuleIndex() const {
  return PhpParser::RuleThrowStatement;
}

antlrcpp::Any PhpParser::ThrowStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitThrowStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ThrowStatementContext* PhpParser::throwStatement() {
  ThrowStatementContext *_localctx = _tracker.createInstance<ThrowStatementContext>(_ctx, getState());
  enterRule(_localctx, 100, PhpParser::RuleThrowStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(777);
    match(PhpParser::Throw);
    setState(778);
    expression(0);
    setState(779);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- GotoStatementContext ------------------------------------------------------------------

PhpParser::GotoStatementContext::GotoStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::GotoStatementContext::Goto() {
  return getToken(PhpParser::Goto, 0);
}

PhpParser::IdentifierContext* PhpParser::GotoStatementContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}


size_t PhpParser::GotoStatementContext::getRuleIndex() const {
  return PhpParser::RuleGotoStatement;
}

antlrcpp::Any PhpParser::GotoStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitGotoStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::GotoStatementContext* PhpParser::gotoStatement() {
  GotoStatementContext *_localctx = _tracker.createInstance<GotoStatementContext>(_ctx, getState());
  enterRule(_localctx, 102, PhpParser::RuleGotoStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(781);
    match(PhpParser::Goto);
    setState(782);
    identifier();
    setState(783);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- DeclareStatementContext ------------------------------------------------------------------

PhpParser::DeclareStatementContext::DeclareStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::DeclareStatementContext::Declare() {
  return getToken(PhpParser::Declare, 0);
}

PhpParser::DeclareListContext* PhpParser::DeclareStatementContext::declareList() {
  return getRuleContext<PhpParser::DeclareListContext>(0);
}

PhpParser::StatementContext* PhpParser::DeclareStatementContext::statement() {
  return getRuleContext<PhpParser::StatementContext>(0);
}

PhpParser::InnerStatementListContext* PhpParser::DeclareStatementContext::innerStatementList() {
  return getRuleContext<PhpParser::InnerStatementListContext>(0);
}

tree::TerminalNode* PhpParser::DeclareStatementContext::EndDeclare() {
  return getToken(PhpParser::EndDeclare, 0);
}


size_t PhpParser::DeclareStatementContext::getRuleIndex() const {
  return PhpParser::RuleDeclareStatement;
}

antlrcpp::Any PhpParser::DeclareStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitDeclareStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::DeclareStatementContext* PhpParser::declareStatement() {
  DeclareStatementContext *_localctx = _tracker.createInstance<DeclareStatementContext>(_ctx, getState());
  enterRule(_localctx, 104, PhpParser::RuleDeclareStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(785);
    match(PhpParser::Declare);
    setState(786);
    match(PhpParser::OpenRoundBracket);
    setState(787);
    declareList();
    setState(788);
    match(PhpParser::CloseRoundBracket);
    setState(795);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::Abstract:
      case PhpParser::Array:
      case PhpParser::As:
      case PhpParser::BinaryCast:
      case PhpParser::BoolType:
      case PhpParser::BooleanConstant:
      case PhpParser::Break:
      case PhpParser::Callable:
      case PhpParser::Case:
      case PhpParser::Catch:
      case PhpParser::Class:
      case PhpParser::Clone:
      case PhpParser::Const:
      case PhpParser::Continue:
      case PhpParser::Declare:
      case PhpParser::Default:
      case PhpParser::Do:
      case PhpParser::DoubleCast:
      case PhpParser::DoubleType:
      case PhpParser::Echo:
      case PhpParser::Else:
      case PhpParser::ElseIf:
      case PhpParser::Empty:
      case PhpParser::EndDeclare:
      case PhpParser::EndFor:
      case PhpParser::EndForeach:
      case PhpParser::EndIf:
      case PhpParser::EndSwitch:
      case PhpParser::EndWhile:
      case PhpParser::Eval:
      case PhpParser::Exit:
      case PhpParser::Extends:
      case PhpParser::Final:
      case PhpParser::Finally:
      case PhpParser::FloatCast:
      case PhpParser::For:
      case PhpParser::Foreach:
      case PhpParser::Function:
      case PhpParser::Global:
      case PhpParser::Goto:
      case PhpParser::If:
      case PhpParser::Implements:
      case PhpParser::Import:
      case PhpParser::Include:
      case PhpParser::IncludeOnce:
      case PhpParser::InstanceOf:
      case PhpParser::InsteadOf:
      case PhpParser::Int8Cast:
      case PhpParser::Int16Cast:
      case PhpParser::Int64Type:
      case PhpParser::IntType:
      case PhpParser::Interface:
      case PhpParser::IsSet:
      case PhpParser::List:
      case PhpParser::LogicalAnd:
      case PhpParser::LogicalOr:
      case PhpParser::LogicalXor:
      case PhpParser::Namespace:
      case PhpParser::New:
      case PhpParser::Null:
      case PhpParser::ObjectType:
      case PhpParser::Parent_:
      case PhpParser::Partial:
      case PhpParser::Print:
      case PhpParser::Private:
      case PhpParser::Protected:
      case PhpParser::Public:
      case PhpParser::Require:
      case PhpParser::RequireOnce:
      case PhpParser::Resource:
      case PhpParser::Return:
      case PhpParser::Static:
      case PhpParser::StringType:
      case PhpParser::Switch:
      case PhpParser::Throw:
      case PhpParser::Trait:
      case PhpParser::Try:
      case PhpParser::Typeof:
      case PhpParser::UintCast:
      case PhpParser::UnicodeCast:
      case PhpParser::Unset:
      case PhpParser::Use:
      case PhpParser::Var:
      case PhpParser::While:
      case PhpParser::Yield:
      case PhpParser::Get:
      case PhpParser::Set:
      case PhpParser::Call:
      case PhpParser::CallStatic:
      case PhpParser::Constructor:
      case PhpParser::Destruct:
      case PhpParser::Wakeup:
      case PhpParser::Sleep:
      case PhpParser::Autoload:
      case PhpParser::IsSet__:
      case PhpParser::Unset__:
      case PhpParser::ToString__:
      case PhpParser::Invoke:
      case PhpParser::SetState:
      case PhpParser::Clone__:
      case PhpParser::DebugInfo:
      case PhpParser::Namespace__:
      case PhpParser::Class__:
      case PhpParser::Traic__:
      case PhpParser::Function__:
      case PhpParser::Method__:
      case PhpParser::Line__:
      case PhpParser::File__:
      case PhpParser::Dir__:
      case PhpParser::Inc:
      case PhpParser::Dec:
      case PhpParser::NamespaceSeparator:
      case PhpParser::Bang:
      case PhpParser::Plus:
      case PhpParser::Minus:
      case PhpParser::Tilde:
      case PhpParser::SuppressWarnings:
      case PhpParser::Dollar:
      case PhpParser::OpenRoundBracket:
      case PhpParser::OpenSquareBracket:
      case PhpParser::OpenCurlyBracket:
      case PhpParser::SemiColon:
      case PhpParser::VarName:
      case PhpParser::Label:
      case PhpParser::Octal:
      case PhpParser::Decimal:
      case PhpParser::Real:
      case PhpParser::Hex:
      case PhpParser::Binary:
      case PhpParser::BackQuoteString:
      case PhpParser::SingleQuoteString:
      case PhpParser::DoubleQuote:
      case PhpParser::StartNowDoc:
      case PhpParser::StartHereDoc: {
        setState(789);
        statement();
        break;
      }

      case PhpParser::Colon: {
        setState(790);
        match(PhpParser::Colon);
        setState(791);
        innerStatementList();
        setState(792);
        match(PhpParser::EndDeclare);
        setState(793);
        match(PhpParser::SemiColon);
        break;
      }

    default:
      throw NoViableAltException(this);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- DeclareListContext ------------------------------------------------------------------

PhpParser::DeclareListContext::DeclareListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::IdentifierInititalizerContext *> PhpParser::DeclareListContext::identifierInititalizer() {
  return getRuleContexts<PhpParser::IdentifierInititalizerContext>();
}

PhpParser::IdentifierInititalizerContext* PhpParser::DeclareListContext::identifierInititalizer(size_t i) {
  return getRuleContext<PhpParser::IdentifierInititalizerContext>(i);
}


size_t PhpParser::DeclareListContext::getRuleIndex() const {
  return PhpParser::RuleDeclareList;
}

antlrcpp::Any PhpParser::DeclareListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitDeclareList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::DeclareListContext* PhpParser::declareList() {
  DeclareListContext *_localctx = _tracker.createInstance<DeclareListContext>(_ctx, getState());
  enterRule(_localctx, 106, PhpParser::RuleDeclareList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(797);
    identifierInititalizer();
    setState(802);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(798);
      match(PhpParser::Comma);
      setState(799);
      identifierInititalizer();
      setState(804);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- FormalParameterListContext ------------------------------------------------------------------

PhpParser::FormalParameterListContext::FormalParameterListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::FormalParameterContext *> PhpParser::FormalParameterListContext::formalParameter() {
  return getRuleContexts<PhpParser::FormalParameterContext>();
}

PhpParser::FormalParameterContext* PhpParser::FormalParameterListContext::formalParameter(size_t i) {
  return getRuleContext<PhpParser::FormalParameterContext>(i);
}


size_t PhpParser::FormalParameterListContext::getRuleIndex() const {
  return PhpParser::RuleFormalParameterList;
}

antlrcpp::Any PhpParser::FormalParameterListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitFormalParameterList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::FormalParameterListContext* PhpParser::formalParameterList() {
  FormalParameterListContext *_localctx = _tracker.createInstance<FormalParameterListContext>(_ctx, getState());
  enterRule(_localctx, 108, PhpParser::RuleFormalParameterList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(806);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
      | (1ULL << PhpParser::Array)
      | (1ULL << PhpParser::As)
      | (1ULL << PhpParser::BinaryCast)
      | (1ULL << PhpParser::BoolType)
      | (1ULL << PhpParser::BooleanConstant)
      | (1ULL << PhpParser::Break)
      | (1ULL << PhpParser::Callable)
      | (1ULL << PhpParser::Case)
      | (1ULL << PhpParser::Catch)
      | (1ULL << PhpParser::Class)
      | (1ULL << PhpParser::Clone)
      | (1ULL << PhpParser::Const)
      | (1ULL << PhpParser::Continue)
      | (1ULL << PhpParser::Declare)
      | (1ULL << PhpParser::Default)
      | (1ULL << PhpParser::Do)
      | (1ULL << PhpParser::DoubleCast)
      | (1ULL << PhpParser::DoubleType)
      | (1ULL << PhpParser::Echo)
      | (1ULL << PhpParser::Else)
      | (1ULL << PhpParser::ElseIf)
      | (1ULL << PhpParser::Empty)
      | (1ULL << PhpParser::EndDeclare)
      | (1ULL << PhpParser::EndFor)
      | (1ULL << PhpParser::EndForeach)
      | (1ULL << PhpParser::EndIf)
      | (1ULL << PhpParser::EndSwitch)
      | (1ULL << PhpParser::EndWhile)
      | (1ULL << PhpParser::Eval)
      | (1ULL << PhpParser::Exit)
      | (1ULL << PhpParser::Extends)
      | (1ULL << PhpParser::Final)
      | (1ULL << PhpParser::Finally)
      | (1ULL << PhpParser::FloatCast)
      | (1ULL << PhpParser::For)
      | (1ULL << PhpParser::Foreach)
      | (1ULL << PhpParser::Function)
      | (1ULL << PhpParser::Global)
      | (1ULL << PhpParser::Goto)
      | (1ULL << PhpParser::If)
      | (1ULL << PhpParser::Implements)
      | (1ULL << PhpParser::Import)
      | (1ULL << PhpParser::Include)
      | (1ULL << PhpParser::IncludeOnce)
      | (1ULL << PhpParser::InstanceOf)
      | (1ULL << PhpParser::InsteadOf)
      | (1ULL << PhpParser::Int8Cast)
      | (1ULL << PhpParser::Int16Cast)
      | (1ULL << PhpParser::Int64Type)
      | (1ULL << PhpParser::IntType)
      | (1ULL << PhpParser::Interface)
      | (1ULL << PhpParser::IsSet)
      | (1ULL << PhpParser::List)
      | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
      | (1ULL << (PhpParser::LogicalXor - 64))
      | (1ULL << (PhpParser::Namespace - 64))
      | (1ULL << (PhpParser::New - 64))
      | (1ULL << (PhpParser::Null - 64))
      | (1ULL << (PhpParser::ObjectType - 64))
      | (1ULL << (PhpParser::Parent_ - 64))
      | (1ULL << (PhpParser::Partial - 64))
      | (1ULL << (PhpParser::Print - 64))
      | (1ULL << (PhpParser::Private - 64))
      | (1ULL << (PhpParser::Protected - 64))
      | (1ULL << (PhpParser::Public - 64))
      | (1ULL << (PhpParser::Require - 64))
      | (1ULL << (PhpParser::RequireOnce - 64))
      | (1ULL << (PhpParser::Resource - 64))
      | (1ULL << (PhpParser::Return - 64))
      | (1ULL << (PhpParser::Static - 64))
      | (1ULL << (PhpParser::StringType - 64))
      | (1ULL << (PhpParser::Switch - 64))
      | (1ULL << (PhpParser::Throw - 64))
      | (1ULL << (PhpParser::Trait - 64))
      | (1ULL << (PhpParser::Try - 64))
      | (1ULL << (PhpParser::Typeof - 64))
      | (1ULL << (PhpParser::UintCast - 64))
      | (1ULL << (PhpParser::UnicodeCast - 64))
      | (1ULL << (PhpParser::Unset - 64))
      | (1ULL << (PhpParser::Use - 64))
      | (1ULL << (PhpParser::Var - 64))
      | (1ULL << (PhpParser::While - 64))
      | (1ULL << (PhpParser::Yield - 64))
      | (1ULL << (PhpParser::Get - 64))
      | (1ULL << (PhpParser::Set - 64))
      | (1ULL << (PhpParser::Call - 64))
      | (1ULL << (PhpParser::CallStatic - 64))
      | (1ULL << (PhpParser::Constructor - 64))
      | (1ULL << (PhpParser::Destruct - 64))
      | (1ULL << (PhpParser::Wakeup - 64))
      | (1ULL << (PhpParser::Sleep - 64))
      | (1ULL << (PhpParser::Autoload - 64))
      | (1ULL << (PhpParser::IsSet__ - 64))
      | (1ULL << (PhpParser::Unset__ - 64))
      | (1ULL << (PhpParser::ToString__ - 64))
      | (1ULL << (PhpParser::Invoke - 64))
      | (1ULL << (PhpParser::SetState - 64))
      | (1ULL << (PhpParser::Clone__ - 64))
      | (1ULL << (PhpParser::DebugInfo - 64))
      | (1ULL << (PhpParser::Namespace__ - 64))
      | (1ULL << (PhpParser::Class__ - 64))
      | (1ULL << (PhpParser::Traic__ - 64))
      | (1ULL << (PhpParser::Function__ - 64))
      | (1ULL << (PhpParser::Method__ - 64))
      | (1ULL << (PhpParser::Line__ - 64))
      | (1ULL << (PhpParser::File__ - 64))
      | (1ULL << (PhpParser::Dir__ - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
      | (1ULL << (PhpParser::Ellipsis - 148))
      | (1ULL << (PhpParser::Ampersand - 148))
      | (1ULL << (PhpParser::OpenSquareBracket - 148))
      | (1ULL << (PhpParser::VarName - 148))
      | (1ULL << (PhpParser::Label - 148)))) != 0)) {
      setState(805);
      formalParameter();
    }
    setState(812);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(808);
      match(PhpParser::Comma);
      setState(809);
      formalParameter();
      setState(814);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- FormalParameterContext ------------------------------------------------------------------

PhpParser::FormalParameterContext::FormalParameterContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::AttributesContext* PhpParser::FormalParameterContext::attributes() {
  return getRuleContext<PhpParser::AttributesContext>(0);
}

PhpParser::VariableInitializerContext* PhpParser::FormalParameterContext::variableInitializer() {
  return getRuleContext<PhpParser::VariableInitializerContext>(0);
}

PhpParser::TypeHintContext* PhpParser::FormalParameterContext::typeHint() {
  return getRuleContext<PhpParser::TypeHintContext>(0);
}


size_t PhpParser::FormalParameterContext::getRuleIndex() const {
  return PhpParser::RuleFormalParameter;
}

antlrcpp::Any PhpParser::FormalParameterContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitFormalParameter(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::FormalParameterContext* PhpParser::formalParameter() {
  FormalParameterContext *_localctx = _tracker.createInstance<FormalParameterContext>(_ctx, getState());
  enterRule(_localctx, 110, PhpParser::RuleFormalParameter);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(815);
    attributes();
    setState(817);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
      | (1ULL << PhpParser::Array)
      | (1ULL << PhpParser::As)
      | (1ULL << PhpParser::BinaryCast)
      | (1ULL << PhpParser::BoolType)
      | (1ULL << PhpParser::BooleanConstant)
      | (1ULL << PhpParser::Break)
      | (1ULL << PhpParser::Callable)
      | (1ULL << PhpParser::Case)
      | (1ULL << PhpParser::Catch)
      | (1ULL << PhpParser::Class)
      | (1ULL << PhpParser::Clone)
      | (1ULL << PhpParser::Const)
      | (1ULL << PhpParser::Continue)
      | (1ULL << PhpParser::Declare)
      | (1ULL << PhpParser::Default)
      | (1ULL << PhpParser::Do)
      | (1ULL << PhpParser::DoubleCast)
      | (1ULL << PhpParser::DoubleType)
      | (1ULL << PhpParser::Echo)
      | (1ULL << PhpParser::Else)
      | (1ULL << PhpParser::ElseIf)
      | (1ULL << PhpParser::Empty)
      | (1ULL << PhpParser::EndDeclare)
      | (1ULL << PhpParser::EndFor)
      | (1ULL << PhpParser::EndForeach)
      | (1ULL << PhpParser::EndIf)
      | (1ULL << PhpParser::EndSwitch)
      | (1ULL << PhpParser::EndWhile)
      | (1ULL << PhpParser::Eval)
      | (1ULL << PhpParser::Exit)
      | (1ULL << PhpParser::Extends)
      | (1ULL << PhpParser::Final)
      | (1ULL << PhpParser::Finally)
      | (1ULL << PhpParser::FloatCast)
      | (1ULL << PhpParser::For)
      | (1ULL << PhpParser::Foreach)
      | (1ULL << PhpParser::Function)
      | (1ULL << PhpParser::Global)
      | (1ULL << PhpParser::Goto)
      | (1ULL << PhpParser::If)
      | (1ULL << PhpParser::Implements)
      | (1ULL << PhpParser::Import)
      | (1ULL << PhpParser::Include)
      | (1ULL << PhpParser::IncludeOnce)
      | (1ULL << PhpParser::InstanceOf)
      | (1ULL << PhpParser::InsteadOf)
      | (1ULL << PhpParser::Int8Cast)
      | (1ULL << PhpParser::Int16Cast)
      | (1ULL << PhpParser::Int64Type)
      | (1ULL << PhpParser::IntType)
      | (1ULL << PhpParser::Interface)
      | (1ULL << PhpParser::IsSet)
      | (1ULL << PhpParser::List)
      | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
      | (1ULL << (PhpParser::LogicalXor - 64))
      | (1ULL << (PhpParser::Namespace - 64))
      | (1ULL << (PhpParser::New - 64))
      | (1ULL << (PhpParser::Null - 64))
      | (1ULL << (PhpParser::ObjectType - 64))
      | (1ULL << (PhpParser::Parent_ - 64))
      | (1ULL << (PhpParser::Partial - 64))
      | (1ULL << (PhpParser::Print - 64))
      | (1ULL << (PhpParser::Private - 64))
      | (1ULL << (PhpParser::Protected - 64))
      | (1ULL << (PhpParser::Public - 64))
      | (1ULL << (PhpParser::Require - 64))
      | (1ULL << (PhpParser::RequireOnce - 64))
      | (1ULL << (PhpParser::Resource - 64))
      | (1ULL << (PhpParser::Return - 64))
      | (1ULL << (PhpParser::Static - 64))
      | (1ULL << (PhpParser::StringType - 64))
      | (1ULL << (PhpParser::Switch - 64))
      | (1ULL << (PhpParser::Throw - 64))
      | (1ULL << (PhpParser::Trait - 64))
      | (1ULL << (PhpParser::Try - 64))
      | (1ULL << (PhpParser::Typeof - 64))
      | (1ULL << (PhpParser::UintCast - 64))
      | (1ULL << (PhpParser::UnicodeCast - 64))
      | (1ULL << (PhpParser::Unset - 64))
      | (1ULL << (PhpParser::Use - 64))
      | (1ULL << (PhpParser::Var - 64))
      | (1ULL << (PhpParser::While - 64))
      | (1ULL << (PhpParser::Yield - 64))
      | (1ULL << (PhpParser::Get - 64))
      | (1ULL << (PhpParser::Set - 64))
      | (1ULL << (PhpParser::Call - 64))
      | (1ULL << (PhpParser::CallStatic - 64))
      | (1ULL << (PhpParser::Constructor - 64))
      | (1ULL << (PhpParser::Destruct - 64))
      | (1ULL << (PhpParser::Wakeup - 64))
      | (1ULL << (PhpParser::Sleep - 64))
      | (1ULL << (PhpParser::Autoload - 64))
      | (1ULL << (PhpParser::IsSet__ - 64))
      | (1ULL << (PhpParser::Unset__ - 64))
      | (1ULL << (PhpParser::ToString__ - 64))
      | (1ULL << (PhpParser::Invoke - 64))
      | (1ULL << (PhpParser::SetState - 64))
      | (1ULL << (PhpParser::Clone__ - 64))
      | (1ULL << (PhpParser::DebugInfo - 64))
      | (1ULL << (PhpParser::Namespace__ - 64))
      | (1ULL << (PhpParser::Class__ - 64))
      | (1ULL << (PhpParser::Traic__ - 64))
      | (1ULL << (PhpParser::Function__ - 64))
      | (1ULL << (PhpParser::Method__ - 64))
      | (1ULL << (PhpParser::Line__ - 64))
      | (1ULL << (PhpParser::File__ - 64))
      | (1ULL << (PhpParser::Dir__ - 64)))) != 0) || _la == PhpParser::NamespaceSeparator

    || _la == PhpParser::Label) {
      setState(816);
      typeHint();
    }
    setState(820);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::Ampersand) {
      setState(819);
      match(PhpParser::Ampersand);
    }
    setState(823);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::Ellipsis) {
      setState(822);
      match(PhpParser::Ellipsis);
    }
    setState(825);
    variableInitializer();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TypeHintContext ------------------------------------------------------------------

PhpParser::TypeHintContext::TypeHintContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::QualifiedStaticTypeRefContext* PhpParser::TypeHintContext::qualifiedStaticTypeRef() {
  return getRuleContext<PhpParser::QualifiedStaticTypeRefContext>(0);
}

tree::TerminalNode* PhpParser::TypeHintContext::Callable() {
  return getToken(PhpParser::Callable, 0);
}

PhpParser::PrimitiveTypeContext* PhpParser::TypeHintContext::primitiveType() {
  return getRuleContext<PhpParser::PrimitiveTypeContext>(0);
}


size_t PhpParser::TypeHintContext::getRuleIndex() const {
  return PhpParser::RuleTypeHint;
}

antlrcpp::Any PhpParser::TypeHintContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitTypeHint(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::TypeHintContext* PhpParser::typeHint() {
  TypeHintContext *_localctx = _tracker.createInstance<TypeHintContext>(_ctx, getState());
  enterRule(_localctx, 112, PhpParser::RuleTypeHint);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(830);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 77, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(827);
      qualifiedStaticTypeRef();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(828);
      match(PhpParser::Callable);
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(829);
      primitiveType();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- GlobalStatementContext ------------------------------------------------------------------

PhpParser::GlobalStatementContext::GlobalStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::GlobalStatementContext::Global() {
  return getToken(PhpParser::Global, 0);
}

std::vector<PhpParser::GlobalVarContext *> PhpParser::GlobalStatementContext::globalVar() {
  return getRuleContexts<PhpParser::GlobalVarContext>();
}

PhpParser::GlobalVarContext* PhpParser::GlobalStatementContext::globalVar(size_t i) {
  return getRuleContext<PhpParser::GlobalVarContext>(i);
}


size_t PhpParser::GlobalStatementContext::getRuleIndex() const {
  return PhpParser::RuleGlobalStatement;
}

antlrcpp::Any PhpParser::GlobalStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitGlobalStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::GlobalStatementContext* PhpParser::globalStatement() {
  GlobalStatementContext *_localctx = _tracker.createInstance<GlobalStatementContext>(_ctx, getState());
  enterRule(_localctx, 114, PhpParser::RuleGlobalStatement);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(832);
    match(PhpParser::Global);
    setState(833);
    globalVar();
    setState(838);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(834);
      match(PhpParser::Comma);
      setState(835);
      globalVar();
      setState(840);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
    setState(841);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- GlobalVarContext ------------------------------------------------------------------

PhpParser::GlobalVarContext::GlobalVarContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::GlobalVarContext::VarName() {
  return getToken(PhpParser::VarName, 0);
}

tree::TerminalNode* PhpParser::GlobalVarContext::Dollar() {
  return getToken(PhpParser::Dollar, 0);
}

PhpParser::ChainContext* PhpParser::GlobalVarContext::chain() {
  return getRuleContext<PhpParser::ChainContext>(0);
}

tree::TerminalNode* PhpParser::GlobalVarContext::OpenCurlyBracket() {
  return getToken(PhpParser::OpenCurlyBracket, 0);
}

PhpParser::ExpressionContext* PhpParser::GlobalVarContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}


size_t PhpParser::GlobalVarContext::getRuleIndex() const {
  return PhpParser::RuleGlobalVar;
}

antlrcpp::Any PhpParser::GlobalVarContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitGlobalVar(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::GlobalVarContext* PhpParser::globalVar() {
  GlobalVarContext *_localctx = _tracker.createInstance<GlobalVarContext>(_ctx, getState());
  enterRule(_localctx, 116, PhpParser::RuleGlobalVar);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(851);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 79, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(843);
      match(PhpParser::VarName);
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(844);
      match(PhpParser::Dollar);
      setState(845);
      chain();
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(846);
      match(PhpParser::Dollar);
      setState(847);
      match(PhpParser::OpenCurlyBracket);
      setState(848);
      expression(0);
      setState(849);
      match(PhpParser::CloseCurlyBracket);
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- EchoStatementContext ------------------------------------------------------------------

PhpParser::EchoStatementContext::EchoStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::EchoStatementContext::Echo() {
  return getToken(PhpParser::Echo, 0);
}

PhpParser::ExpressionListContext* PhpParser::EchoStatementContext::expressionList() {
  return getRuleContext<PhpParser::ExpressionListContext>(0);
}


size_t PhpParser::EchoStatementContext::getRuleIndex() const {
  return PhpParser::RuleEchoStatement;
}

antlrcpp::Any PhpParser::EchoStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitEchoStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::EchoStatementContext* PhpParser::echoStatement() {
  EchoStatementContext *_localctx = _tracker.createInstance<EchoStatementContext>(_ctx, getState());
  enterRule(_localctx, 118, PhpParser::RuleEchoStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(853);
    match(PhpParser::Echo);
    setState(854);
    expressionList();
    setState(855);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- StaticVariableStatementContext ------------------------------------------------------------------

PhpParser::StaticVariableStatementContext::StaticVariableStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::StaticVariableStatementContext::Static() {
  return getToken(PhpParser::Static, 0);
}

std::vector<PhpParser::VariableInitializerContext *> PhpParser::StaticVariableStatementContext::variableInitializer() {
  return getRuleContexts<PhpParser::VariableInitializerContext>();
}

PhpParser::VariableInitializerContext* PhpParser::StaticVariableStatementContext::variableInitializer(size_t i) {
  return getRuleContext<PhpParser::VariableInitializerContext>(i);
}


size_t PhpParser::StaticVariableStatementContext::getRuleIndex() const {
  return PhpParser::RuleStaticVariableStatement;
}

antlrcpp::Any PhpParser::StaticVariableStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitStaticVariableStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::StaticVariableStatementContext* PhpParser::staticVariableStatement() {
  StaticVariableStatementContext *_localctx = _tracker.createInstance<StaticVariableStatementContext>(_ctx, getState());
  enterRule(_localctx, 120, PhpParser::RuleStaticVariableStatement);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(857);
    match(PhpParser::Static);
    setState(858);
    variableInitializer();
    setState(863);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(859);
      match(PhpParser::Comma);
      setState(860);
      variableInitializer();
      setState(865);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
    setState(866);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ClassStatementContext ------------------------------------------------------------------

PhpParser::ClassStatementContext::ClassStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::AttributesContext* PhpParser::ClassStatementContext::attributes() {
  return getRuleContext<PhpParser::AttributesContext>(0);
}

PhpParser::PropertyModifiersContext* PhpParser::ClassStatementContext::propertyModifiers() {
  return getRuleContext<PhpParser::PropertyModifiersContext>(0);
}

std::vector<PhpParser::VariableInitializerContext *> PhpParser::ClassStatementContext::variableInitializer() {
  return getRuleContexts<PhpParser::VariableInitializerContext>();
}

PhpParser::VariableInitializerContext* PhpParser::ClassStatementContext::variableInitializer(size_t i) {
  return getRuleContext<PhpParser::VariableInitializerContext>(i);
}

tree::TerminalNode* PhpParser::ClassStatementContext::Const() {
  return getToken(PhpParser::Const, 0);
}

std::vector<PhpParser::IdentifierInititalizerContext *> PhpParser::ClassStatementContext::identifierInititalizer() {
  return getRuleContexts<PhpParser::IdentifierInititalizerContext>();
}

PhpParser::IdentifierInititalizerContext* PhpParser::ClassStatementContext::identifierInititalizer(size_t i) {
  return getRuleContext<PhpParser::IdentifierInititalizerContext>(i);
}

tree::TerminalNode* PhpParser::ClassStatementContext::Function() {
  return getToken(PhpParser::Function, 0);
}

PhpParser::IdentifierContext* PhpParser::ClassStatementContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}

PhpParser::FormalParameterListContext* PhpParser::ClassStatementContext::formalParameterList() {
  return getRuleContext<PhpParser::FormalParameterListContext>(0);
}

PhpParser::MethodBodyContext* PhpParser::ClassStatementContext::methodBody() {
  return getRuleContext<PhpParser::MethodBodyContext>(0);
}

PhpParser::MemberModifiersContext* PhpParser::ClassStatementContext::memberModifiers() {
  return getRuleContext<PhpParser::MemberModifiersContext>(0);
}

PhpParser::TypeParameterListInBracketsContext* PhpParser::ClassStatementContext::typeParameterListInBrackets() {
  return getRuleContext<PhpParser::TypeParameterListInBracketsContext>(0);
}

PhpParser::BaseCtorCallContext* PhpParser::ClassStatementContext::baseCtorCall() {
  return getRuleContext<PhpParser::BaseCtorCallContext>(0);
}

tree::TerminalNode* PhpParser::ClassStatementContext::Use() {
  return getToken(PhpParser::Use, 0);
}

PhpParser::QualifiedNamespaceNameListContext* PhpParser::ClassStatementContext::qualifiedNamespaceNameList() {
  return getRuleContext<PhpParser::QualifiedNamespaceNameListContext>(0);
}

PhpParser::TraitAdaptationsContext* PhpParser::ClassStatementContext::traitAdaptations() {
  return getRuleContext<PhpParser::TraitAdaptationsContext>(0);
}


size_t PhpParser::ClassStatementContext::getRuleIndex() const {
  return PhpParser::RuleClassStatement;
}

antlrcpp::Any PhpParser::ClassStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitClassStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ClassStatementContext* PhpParser::classStatement() {
  ClassStatementContext *_localctx = _tracker.createInstance<ClassStatementContext>(_ctx, getState());
  enterRule(_localctx, 122, PhpParser::RuleClassStatement);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(916);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 87, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(868);
      attributes();
      setState(869);
      propertyModifiers();
      setState(870);
      variableInitializer();
      setState(875);
      _errHandler->sync(this);
      _la = _input->LA(1);
      while (_la == PhpParser::Comma) {
        setState(871);
        match(PhpParser::Comma);
        setState(872);
        variableInitializer();
        setState(877);
        _errHandler->sync(this);
        _la = _input->LA(1);
      }
      setState(878);
      match(PhpParser::SemiColon);
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(880);
      attributes();
      setState(881);
      match(PhpParser::Const);
      setState(882);
      identifierInititalizer();
      setState(887);
      _errHandler->sync(this);
      _la = _input->LA(1);
      while (_la == PhpParser::Comma) {
        setState(883);
        match(PhpParser::Comma);
        setState(884);
        identifierInititalizer();
        setState(889);
        _errHandler->sync(this);
        _la = _input->LA(1);
      }
      setState(890);
      match(PhpParser::SemiColon);
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(892);
      attributes();
      setState(894);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == PhpParser::Abstract

      || _la == PhpParser::Final || ((((_la - 73) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 73)) & ((1ULL << (PhpParser::Private - 73))
        | (1ULL << (PhpParser::Protected - 73))
        | (1ULL << (PhpParser::Public - 73))
        | (1ULL << (PhpParser::Static - 73)))) != 0)) {
        setState(893);
        memberModifiers();
      }
      setState(896);
      match(PhpParser::Function);
      setState(898);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == PhpParser::Ampersand) {
        setState(897);
        match(PhpParser::Ampersand);
      }
      setState(900);
      identifier();
      setState(902);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == PhpParser::Lgeneric) {
        setState(901);
        typeParameterListInBrackets();
      }
      setState(904);
      match(PhpParser::OpenRoundBracket);
      setState(905);
      formalParameterList();
      setState(906);
      match(PhpParser::CloseRoundBracket);
      setState(908);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == PhpParser::Colon) {
        setState(907);
        baseCtorCall();
      }
      setState(910);
      methodBody();
      break;
    }

    case 4: {
      enterOuterAlt(_localctx, 4);
      setState(912);
      match(PhpParser::Use);
      setState(913);
      qualifiedNamespaceNameList();
      setState(914);
      traitAdaptations();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TraitAdaptationsContext ------------------------------------------------------------------

PhpParser::TraitAdaptationsContext::TraitAdaptationsContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::TraitAdaptationsContext::OpenCurlyBracket() {
  return getToken(PhpParser::OpenCurlyBracket, 0);
}

std::vector<PhpParser::TraitAdaptationStatementContext *> PhpParser::TraitAdaptationsContext::traitAdaptationStatement() {
  return getRuleContexts<PhpParser::TraitAdaptationStatementContext>();
}

PhpParser::TraitAdaptationStatementContext* PhpParser::TraitAdaptationsContext::traitAdaptationStatement(size_t i) {
  return getRuleContext<PhpParser::TraitAdaptationStatementContext>(i);
}


size_t PhpParser::TraitAdaptationsContext::getRuleIndex() const {
  return PhpParser::RuleTraitAdaptations;
}

antlrcpp::Any PhpParser::TraitAdaptationsContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitTraitAdaptations(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::TraitAdaptationsContext* PhpParser::traitAdaptations() {
  TraitAdaptationsContext *_localctx = _tracker.createInstance<TraitAdaptationsContext>(_ctx, getState());
  enterRule(_localctx, 124, PhpParser::RuleTraitAdaptations);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(927);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::SemiColon: {
        enterOuterAlt(_localctx, 1);
        setState(918);
        match(PhpParser::SemiColon);
        break;
      }

      case PhpParser::OpenCurlyBracket: {
        enterOuterAlt(_localctx, 2);
        setState(919);
        match(PhpParser::OpenCurlyBracket);
        setState(923);
        _errHandler->sync(this);
        _la = _input->LA(1);
        while ((((_la & ~ 0x3fULL) == 0) &&
          ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
          | (1ULL << PhpParser::Array)
          | (1ULL << PhpParser::As)
          | (1ULL << PhpParser::BinaryCast)
          | (1ULL << PhpParser::BoolType)
          | (1ULL << PhpParser::BooleanConstant)
          | (1ULL << PhpParser::Break)
          | (1ULL << PhpParser::Callable)
          | (1ULL << PhpParser::Case)
          | (1ULL << PhpParser::Catch)
          | (1ULL << PhpParser::Class)
          | (1ULL << PhpParser::Clone)
          | (1ULL << PhpParser::Const)
          | (1ULL << PhpParser::Continue)
          | (1ULL << PhpParser::Declare)
          | (1ULL << PhpParser::Default)
          | (1ULL << PhpParser::Do)
          | (1ULL << PhpParser::DoubleCast)
          | (1ULL << PhpParser::DoubleType)
          | (1ULL << PhpParser::Echo)
          | (1ULL << PhpParser::Else)
          | (1ULL << PhpParser::ElseIf)
          | (1ULL << PhpParser::Empty)
          | (1ULL << PhpParser::EndDeclare)
          | (1ULL << PhpParser::EndFor)
          | (1ULL << PhpParser::EndForeach)
          | (1ULL << PhpParser::EndIf)
          | (1ULL << PhpParser::EndSwitch)
          | (1ULL << PhpParser::EndWhile)
          | (1ULL << PhpParser::Eval)
          | (1ULL << PhpParser::Exit)
          | (1ULL << PhpParser::Extends)
          | (1ULL << PhpParser::Final)
          | (1ULL << PhpParser::Finally)
          | (1ULL << PhpParser::FloatCast)
          | (1ULL << PhpParser::For)
          | (1ULL << PhpParser::Foreach)
          | (1ULL << PhpParser::Function)
          | (1ULL << PhpParser::Global)
          | (1ULL << PhpParser::Goto)
          | (1ULL << PhpParser::If)
          | (1ULL << PhpParser::Implements)
          | (1ULL << PhpParser::Import)
          | (1ULL << PhpParser::Include)
          | (1ULL << PhpParser::IncludeOnce)
          | (1ULL << PhpParser::InstanceOf)
          | (1ULL << PhpParser::InsteadOf)
          | (1ULL << PhpParser::Int8Cast)
          | (1ULL << PhpParser::Int16Cast)
          | (1ULL << PhpParser::Int64Type)
          | (1ULL << PhpParser::IntType)
          | (1ULL << PhpParser::Interface)
          | (1ULL << PhpParser::IsSet)
          | (1ULL << PhpParser::List)
          | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
          ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
          | (1ULL << (PhpParser::LogicalXor - 64))
          | (1ULL << (PhpParser::Namespace - 64))
          | (1ULL << (PhpParser::New - 64))
          | (1ULL << (PhpParser::Null - 64))
          | (1ULL << (PhpParser::ObjectType - 64))
          | (1ULL << (PhpParser::Parent_ - 64))
          | (1ULL << (PhpParser::Partial - 64))
          | (1ULL << (PhpParser::Print - 64))
          | (1ULL << (PhpParser::Private - 64))
          | (1ULL << (PhpParser::Protected - 64))
          | (1ULL << (PhpParser::Public - 64))
          | (1ULL << (PhpParser::Require - 64))
          | (1ULL << (PhpParser::RequireOnce - 64))
          | (1ULL << (PhpParser::Resource - 64))
          | (1ULL << (PhpParser::Return - 64))
          | (1ULL << (PhpParser::Static - 64))
          | (1ULL << (PhpParser::StringType - 64))
          | (1ULL << (PhpParser::Switch - 64))
          | (1ULL << (PhpParser::Throw - 64))
          | (1ULL << (PhpParser::Trait - 64))
          | (1ULL << (PhpParser::Try - 64))
          | (1ULL << (PhpParser::Typeof - 64))
          | (1ULL << (PhpParser::UintCast - 64))
          | (1ULL << (PhpParser::UnicodeCast - 64))
          | (1ULL << (PhpParser::Unset - 64))
          | (1ULL << (PhpParser::Use - 64))
          | (1ULL << (PhpParser::Var - 64))
          | (1ULL << (PhpParser::While - 64))
          | (1ULL << (PhpParser::Yield - 64))
          | (1ULL << (PhpParser::Get - 64))
          | (1ULL << (PhpParser::Set - 64))
          | (1ULL << (PhpParser::Call - 64))
          | (1ULL << (PhpParser::CallStatic - 64))
          | (1ULL << (PhpParser::Constructor - 64))
          | (1ULL << (PhpParser::Destruct - 64))
          | (1ULL << (PhpParser::Wakeup - 64))
          | (1ULL << (PhpParser::Sleep - 64))
          | (1ULL << (PhpParser::Autoload - 64))
          | (1ULL << (PhpParser::IsSet__ - 64))
          | (1ULL << (PhpParser::Unset__ - 64))
          | (1ULL << (PhpParser::ToString__ - 64))
          | (1ULL << (PhpParser::Invoke - 64))
          | (1ULL << (PhpParser::SetState - 64))
          | (1ULL << (PhpParser::Clone__ - 64))
          | (1ULL << (PhpParser::DebugInfo - 64))
          | (1ULL << (PhpParser::Namespace__ - 64))
          | (1ULL << (PhpParser::Class__ - 64))
          | (1ULL << (PhpParser::Traic__ - 64))
          | (1ULL << (PhpParser::Function__ - 64))
          | (1ULL << (PhpParser::Method__ - 64))
          | (1ULL << (PhpParser::Line__ - 64))
          | (1ULL << (PhpParser::File__ - 64))
          | (1ULL << (PhpParser::Dir__ - 64)))) != 0) || _la == PhpParser::NamespaceSeparator

        || _la == PhpParser::Label) {
          setState(920);
          traitAdaptationStatement();
          setState(925);
          _errHandler->sync(this);
          _la = _input->LA(1);
        }
        setState(926);
        match(PhpParser::CloseCurlyBracket);
        break;
      }

    default:
      throw NoViableAltException(this);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TraitAdaptationStatementContext ------------------------------------------------------------------

PhpParser::TraitAdaptationStatementContext::TraitAdaptationStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::TraitPrecedenceContext* PhpParser::TraitAdaptationStatementContext::traitPrecedence() {
  return getRuleContext<PhpParser::TraitPrecedenceContext>(0);
}

PhpParser::TraitAliasContext* PhpParser::TraitAdaptationStatementContext::traitAlias() {
  return getRuleContext<PhpParser::TraitAliasContext>(0);
}


size_t PhpParser::TraitAdaptationStatementContext::getRuleIndex() const {
  return PhpParser::RuleTraitAdaptationStatement;
}

antlrcpp::Any PhpParser::TraitAdaptationStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitTraitAdaptationStatement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::TraitAdaptationStatementContext* PhpParser::traitAdaptationStatement() {
  TraitAdaptationStatementContext *_localctx = _tracker.createInstance<TraitAdaptationStatementContext>(_ctx, getState());
  enterRule(_localctx, 126, PhpParser::RuleTraitAdaptationStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(931);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 90, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(929);
      traitPrecedence();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(930);
      traitAlias();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TraitPrecedenceContext ------------------------------------------------------------------

PhpParser::TraitPrecedenceContext::TraitPrecedenceContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::QualifiedNamespaceNameContext* PhpParser::TraitPrecedenceContext::qualifiedNamespaceName() {
  return getRuleContext<PhpParser::QualifiedNamespaceNameContext>(0);
}

PhpParser::IdentifierContext* PhpParser::TraitPrecedenceContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}

tree::TerminalNode* PhpParser::TraitPrecedenceContext::InsteadOf() {
  return getToken(PhpParser::InsteadOf, 0);
}

PhpParser::QualifiedNamespaceNameListContext* PhpParser::TraitPrecedenceContext::qualifiedNamespaceNameList() {
  return getRuleContext<PhpParser::QualifiedNamespaceNameListContext>(0);
}


size_t PhpParser::TraitPrecedenceContext::getRuleIndex() const {
  return PhpParser::RuleTraitPrecedence;
}

antlrcpp::Any PhpParser::TraitPrecedenceContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitTraitPrecedence(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::TraitPrecedenceContext* PhpParser::traitPrecedence() {
  TraitPrecedenceContext *_localctx = _tracker.createInstance<TraitPrecedenceContext>(_ctx, getState());
  enterRule(_localctx, 128, PhpParser::RuleTraitPrecedence);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(933);
    qualifiedNamespaceName();
    setState(934);
    match(PhpParser::DoubleColon);
    setState(935);
    identifier();
    setState(936);
    match(PhpParser::InsteadOf);
    setState(937);
    qualifiedNamespaceNameList();
    setState(938);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TraitAliasContext ------------------------------------------------------------------

PhpParser::TraitAliasContext::TraitAliasContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::TraitMethodReferenceContext* PhpParser::TraitAliasContext::traitMethodReference() {
  return getRuleContext<PhpParser::TraitMethodReferenceContext>(0);
}

tree::TerminalNode* PhpParser::TraitAliasContext::As() {
  return getToken(PhpParser::As, 0);
}

PhpParser::MemberModifierContext* PhpParser::TraitAliasContext::memberModifier() {
  return getRuleContext<PhpParser::MemberModifierContext>(0);
}

PhpParser::IdentifierContext* PhpParser::TraitAliasContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}


size_t PhpParser::TraitAliasContext::getRuleIndex() const {
  return PhpParser::RuleTraitAlias;
}

antlrcpp::Any PhpParser::TraitAliasContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitTraitAlias(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::TraitAliasContext* PhpParser::traitAlias() {
  TraitAliasContext *_localctx = _tracker.createInstance<TraitAliasContext>(_ctx, getState());
  enterRule(_localctx, 130, PhpParser::RuleTraitAlias);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(940);
    traitMethodReference();
    setState(941);
    match(PhpParser::As);
    setState(947);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 92, _ctx)) {
    case 1: {
      setState(942);
      memberModifier();
      break;
    }

    case 2: {
      setState(944);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 91, _ctx)) {
      case 1: {
        setState(943);
        memberModifier();
        break;
      }

      }
      setState(946);
      identifier();
      break;
    }

    }
    setState(949);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TraitMethodReferenceContext ------------------------------------------------------------------

PhpParser::TraitMethodReferenceContext::TraitMethodReferenceContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::IdentifierContext* PhpParser::TraitMethodReferenceContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}

PhpParser::QualifiedNamespaceNameContext* PhpParser::TraitMethodReferenceContext::qualifiedNamespaceName() {
  return getRuleContext<PhpParser::QualifiedNamespaceNameContext>(0);
}


size_t PhpParser::TraitMethodReferenceContext::getRuleIndex() const {
  return PhpParser::RuleTraitMethodReference;
}

antlrcpp::Any PhpParser::TraitMethodReferenceContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitTraitMethodReference(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::TraitMethodReferenceContext* PhpParser::traitMethodReference() {
  TraitMethodReferenceContext *_localctx = _tracker.createInstance<TraitMethodReferenceContext>(_ctx, getState());
  enterRule(_localctx, 132, PhpParser::RuleTraitMethodReference);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(954);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 93, _ctx)) {
    case 1: {
      setState(951);
      qualifiedNamespaceName();
      setState(952);
      match(PhpParser::DoubleColon);
      break;
    }

    }
    setState(956);
    identifier();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- BaseCtorCallContext ------------------------------------------------------------------

PhpParser::BaseCtorCallContext::BaseCtorCallContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::IdentifierContext* PhpParser::BaseCtorCallContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}

PhpParser::ArgumentsContext* PhpParser::BaseCtorCallContext::arguments() {
  return getRuleContext<PhpParser::ArgumentsContext>(0);
}


size_t PhpParser::BaseCtorCallContext::getRuleIndex() const {
  return PhpParser::RuleBaseCtorCall;
}

antlrcpp::Any PhpParser::BaseCtorCallContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitBaseCtorCall(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::BaseCtorCallContext* PhpParser::baseCtorCall() {
  BaseCtorCallContext *_localctx = _tracker.createInstance<BaseCtorCallContext>(_ctx, getState());
  enterRule(_localctx, 134, PhpParser::RuleBaseCtorCall);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(958);
    match(PhpParser::Colon);
    setState(959);
    identifier();
    setState(960);
    arguments();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- MethodBodyContext ------------------------------------------------------------------

PhpParser::MethodBodyContext::MethodBodyContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::BlockStatementContext* PhpParser::MethodBodyContext::blockStatement() {
  return getRuleContext<PhpParser::BlockStatementContext>(0);
}


size_t PhpParser::MethodBodyContext::getRuleIndex() const {
  return PhpParser::RuleMethodBody;
}

antlrcpp::Any PhpParser::MethodBodyContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitMethodBody(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::MethodBodyContext* PhpParser::methodBody() {
  MethodBodyContext *_localctx = _tracker.createInstance<MethodBodyContext>(_ctx, getState());
  enterRule(_localctx, 136, PhpParser::RuleMethodBody);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(964);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::SemiColon: {
        enterOuterAlt(_localctx, 1);
        setState(962);
        match(PhpParser::SemiColon);
        break;
      }

      case PhpParser::OpenCurlyBracket: {
        enterOuterAlt(_localctx, 2);
        setState(963);
        blockStatement();
        break;
      }

    default:
      throw NoViableAltException(this);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- PropertyModifiersContext ------------------------------------------------------------------

PhpParser::PropertyModifiersContext::PropertyModifiersContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::MemberModifiersContext* PhpParser::PropertyModifiersContext::memberModifiers() {
  return getRuleContext<PhpParser::MemberModifiersContext>(0);
}

tree::TerminalNode* PhpParser::PropertyModifiersContext::Var() {
  return getToken(PhpParser::Var, 0);
}


size_t PhpParser::PropertyModifiersContext::getRuleIndex() const {
  return PhpParser::RulePropertyModifiers;
}

antlrcpp::Any PhpParser::PropertyModifiersContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitPropertyModifiers(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::PropertyModifiersContext* PhpParser::propertyModifiers() {
  PropertyModifiersContext *_localctx = _tracker.createInstance<PropertyModifiersContext>(_ctx, getState());
  enterRule(_localctx, 138, PhpParser::RulePropertyModifiers);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(968);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::Abstract:
      case PhpParser::Final:
      case PhpParser::Private:
      case PhpParser::Protected:
      case PhpParser::Public:
      case PhpParser::Static: {
        enterOuterAlt(_localctx, 1);
        setState(966);
        memberModifiers();
        break;
      }

      case PhpParser::Var: {
        enterOuterAlt(_localctx, 2);
        setState(967);
        match(PhpParser::Var);
        break;
      }

    default:
      throw NoViableAltException(this);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- MemberModifiersContext ------------------------------------------------------------------

PhpParser::MemberModifiersContext::MemberModifiersContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::MemberModifierContext *> PhpParser::MemberModifiersContext::memberModifier() {
  return getRuleContexts<PhpParser::MemberModifierContext>();
}

PhpParser::MemberModifierContext* PhpParser::MemberModifiersContext::memberModifier(size_t i) {
  return getRuleContext<PhpParser::MemberModifierContext>(i);
}


size_t PhpParser::MemberModifiersContext::getRuleIndex() const {
  return PhpParser::RuleMemberModifiers;
}

antlrcpp::Any PhpParser::MemberModifiersContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitMemberModifiers(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::MemberModifiersContext* PhpParser::memberModifiers() {
  MemberModifiersContext *_localctx = _tracker.createInstance<MemberModifiersContext>(_ctx, getState());
  enterRule(_localctx, 140, PhpParser::RuleMemberModifiers);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(971); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(970);
      memberModifier();
      setState(973); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == PhpParser::Abstract

    || _la == PhpParser::Final || ((((_la - 73) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 73)) & ((1ULL << (PhpParser::Private - 73))
      | (1ULL << (PhpParser::Protected - 73))
      | (1ULL << (PhpParser::Public - 73))
      | (1ULL << (PhpParser::Static - 73)))) != 0));
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- VariableInitializerContext ------------------------------------------------------------------

PhpParser::VariableInitializerContext::VariableInitializerContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::VariableInitializerContext::VarName() {
  return getToken(PhpParser::VarName, 0);
}

tree::TerminalNode* PhpParser::VariableInitializerContext::Eq() {
  return getToken(PhpParser::Eq, 0);
}

PhpParser::ConstantInititalizerContext* PhpParser::VariableInitializerContext::constantInititalizer() {
  return getRuleContext<PhpParser::ConstantInititalizerContext>(0);
}


size_t PhpParser::VariableInitializerContext::getRuleIndex() const {
  return PhpParser::RuleVariableInitializer;
}

antlrcpp::Any PhpParser::VariableInitializerContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitVariableInitializer(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::VariableInitializerContext* PhpParser::variableInitializer() {
  VariableInitializerContext *_localctx = _tracker.createInstance<VariableInitializerContext>(_ctx, getState());
  enterRule(_localctx, 142, PhpParser::RuleVariableInitializer);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(975);
    match(PhpParser::VarName);
    setState(978);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::Eq) {
      setState(976);
      match(PhpParser::Eq);
      setState(977);
      constantInititalizer();
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- IdentifierInititalizerContext ------------------------------------------------------------------

PhpParser::IdentifierInititalizerContext::IdentifierInititalizerContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::IdentifierContext* PhpParser::IdentifierInititalizerContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}

tree::TerminalNode* PhpParser::IdentifierInititalizerContext::Eq() {
  return getToken(PhpParser::Eq, 0);
}

PhpParser::ConstantInititalizerContext* PhpParser::IdentifierInititalizerContext::constantInititalizer() {
  return getRuleContext<PhpParser::ConstantInititalizerContext>(0);
}


size_t PhpParser::IdentifierInititalizerContext::getRuleIndex() const {
  return PhpParser::RuleIdentifierInititalizer;
}

antlrcpp::Any PhpParser::IdentifierInititalizerContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitIdentifierInititalizer(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::IdentifierInititalizerContext* PhpParser::identifierInititalizer() {
  IdentifierInititalizerContext *_localctx = _tracker.createInstance<IdentifierInititalizerContext>(_ctx, getState());
  enterRule(_localctx, 144, PhpParser::RuleIdentifierInititalizer);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(980);
    identifier();
    setState(981);
    match(PhpParser::Eq);
    setState(982);
    constantInititalizer();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- GlobalConstantDeclarationContext ------------------------------------------------------------------

PhpParser::GlobalConstantDeclarationContext::GlobalConstantDeclarationContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::AttributesContext* PhpParser::GlobalConstantDeclarationContext::attributes() {
  return getRuleContext<PhpParser::AttributesContext>(0);
}

tree::TerminalNode* PhpParser::GlobalConstantDeclarationContext::Const() {
  return getToken(PhpParser::Const, 0);
}

std::vector<PhpParser::IdentifierInititalizerContext *> PhpParser::GlobalConstantDeclarationContext::identifierInititalizer() {
  return getRuleContexts<PhpParser::IdentifierInititalizerContext>();
}

PhpParser::IdentifierInititalizerContext* PhpParser::GlobalConstantDeclarationContext::identifierInititalizer(size_t i) {
  return getRuleContext<PhpParser::IdentifierInititalizerContext>(i);
}


size_t PhpParser::GlobalConstantDeclarationContext::getRuleIndex() const {
  return PhpParser::RuleGlobalConstantDeclaration;
}

antlrcpp::Any PhpParser::GlobalConstantDeclarationContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitGlobalConstantDeclaration(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::GlobalConstantDeclarationContext* PhpParser::globalConstantDeclaration() {
  GlobalConstantDeclarationContext *_localctx = _tracker.createInstance<GlobalConstantDeclarationContext>(_ctx, getState());
  enterRule(_localctx, 146, PhpParser::RuleGlobalConstantDeclaration);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(984);
    attributes();
    setState(985);
    match(PhpParser::Const);
    setState(986);
    identifierInititalizer();
    setState(991);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(987);
      match(PhpParser::Comma);
      setState(988);
      identifierInititalizer();
      setState(993);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
    setState(994);
    match(PhpParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ExpressionListContext ------------------------------------------------------------------

PhpParser::ExpressionListContext::ExpressionListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::ExpressionContext *> PhpParser::ExpressionListContext::expression() {
  return getRuleContexts<PhpParser::ExpressionContext>();
}

PhpParser::ExpressionContext* PhpParser::ExpressionListContext::expression(size_t i) {
  return getRuleContext<PhpParser::ExpressionContext>(i);
}


size_t PhpParser::ExpressionListContext::getRuleIndex() const {
  return PhpParser::RuleExpressionList;
}

antlrcpp::Any PhpParser::ExpressionListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitExpressionList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ExpressionListContext* PhpParser::expressionList() {
  ExpressionListContext *_localctx = _tracker.createInstance<ExpressionListContext>(_ctx, getState());
  enterRule(_localctx, 148, PhpParser::RuleExpressionList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(996);
    expression(0);
    setState(1001);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(997);
      match(PhpParser::Comma);
      setState(998);
      expression(0);
      setState(1003);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ParenthesisContext ------------------------------------------------------------------

PhpParser::ParenthesisContext::ParenthesisContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::ExpressionContext* PhpParser::ParenthesisContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}

PhpParser::YieldExpressionContext* PhpParser::ParenthesisContext::yieldExpression() {
  return getRuleContext<PhpParser::YieldExpressionContext>(0);
}


size_t PhpParser::ParenthesisContext::getRuleIndex() const {
  return PhpParser::RuleParenthesis;
}

antlrcpp::Any PhpParser::ParenthesisContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitParenthesis(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ParenthesisContext* PhpParser::parenthesis() {
  ParenthesisContext *_localctx = _tracker.createInstance<ParenthesisContext>(_ctx, getState());
  enterRule(_localctx, 150, PhpParser::RuleParenthesis);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1004);
    match(PhpParser::OpenRoundBracket);
    setState(1007);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 100, _ctx)) {
    case 1: {
      setState(1005);
      expression(0);
      break;
    }

    case 2: {
      setState(1006);
      yieldExpression();
      break;
    }

    }
    setState(1009);
    match(PhpParser::CloseRoundBracket);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ExpressionContext ------------------------------------------------------------------

PhpParser::ExpressionContext::ExpressionContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}


size_t PhpParser::ExpressionContext::getRuleIndex() const {
  return PhpParser::RuleExpression;
}

void PhpParser::ExpressionContext::copyFrom(ExpressionContext *ctx) {
  ParserRuleContext::copyFrom(ctx);
}

//----------------- ChainExpressionContext ------------------------------------------------------------------

PhpParser::ChainContext* PhpParser::ChainExpressionContext::chain() {
  return getRuleContext<PhpParser::ChainContext>(0);
}

PhpParser::ChainExpressionContext::ChainExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::ChainExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitChainExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- UnaryOperatorExpressionContext ------------------------------------------------------------------

PhpParser::ExpressionContext* PhpParser::UnaryOperatorExpressionContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}

PhpParser::UnaryOperatorExpressionContext::UnaryOperatorExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::UnaryOperatorExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitUnaryOperatorExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- SpecialWordExpressionContext ------------------------------------------------------------------

tree::TerminalNode* PhpParser::SpecialWordExpressionContext::Yield() {
  return getToken(PhpParser::Yield, 0);
}

tree::TerminalNode* PhpParser::SpecialWordExpressionContext::List() {
  return getToken(PhpParser::List, 0);
}

PhpParser::AssignmentListContext* PhpParser::SpecialWordExpressionContext::assignmentList() {
  return getRuleContext<PhpParser::AssignmentListContext>(0);
}

tree::TerminalNode* PhpParser::SpecialWordExpressionContext::Eq() {
  return getToken(PhpParser::Eq, 0);
}

PhpParser::ExpressionContext* PhpParser::SpecialWordExpressionContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}

tree::TerminalNode* PhpParser::SpecialWordExpressionContext::IsSet() {
  return getToken(PhpParser::IsSet, 0);
}

PhpParser::ChainListContext* PhpParser::SpecialWordExpressionContext::chainList() {
  return getRuleContext<PhpParser::ChainListContext>(0);
}

tree::TerminalNode* PhpParser::SpecialWordExpressionContext::Empty() {
  return getToken(PhpParser::Empty, 0);
}

PhpParser::ChainContext* PhpParser::SpecialWordExpressionContext::chain() {
  return getRuleContext<PhpParser::ChainContext>(0);
}

tree::TerminalNode* PhpParser::SpecialWordExpressionContext::Eval() {
  return getToken(PhpParser::Eval, 0);
}

tree::TerminalNode* PhpParser::SpecialWordExpressionContext::Exit() {
  return getToken(PhpParser::Exit, 0);
}

PhpParser::ParenthesisContext* PhpParser::SpecialWordExpressionContext::parenthesis() {
  return getRuleContext<PhpParser::ParenthesisContext>(0);
}

tree::TerminalNode* PhpParser::SpecialWordExpressionContext::Include() {
  return getToken(PhpParser::Include, 0);
}

tree::TerminalNode* PhpParser::SpecialWordExpressionContext::IncludeOnce() {
  return getToken(PhpParser::IncludeOnce, 0);
}

tree::TerminalNode* PhpParser::SpecialWordExpressionContext::Require() {
  return getToken(PhpParser::Require, 0);
}

tree::TerminalNode* PhpParser::SpecialWordExpressionContext::RequireOnce() {
  return getToken(PhpParser::RequireOnce, 0);
}

PhpParser::SpecialWordExpressionContext::SpecialWordExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::SpecialWordExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitSpecialWordExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ArrayCreationExpressionContext ------------------------------------------------------------------

tree::TerminalNode* PhpParser::ArrayCreationExpressionContext::Array() {
  return getToken(PhpParser::Array, 0);
}

PhpParser::ExpressionContext* PhpParser::ArrayCreationExpressionContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}

PhpParser::ArrayItemListContext* PhpParser::ArrayCreationExpressionContext::arrayItemList() {
  return getRuleContext<PhpParser::ArrayItemListContext>(0);
}

PhpParser::ArrayCreationExpressionContext::ArrayCreationExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::ArrayCreationExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitArrayCreationExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- NewExpressionContext ------------------------------------------------------------------

PhpParser::NewExprContext* PhpParser::NewExpressionContext::newExpr() {
  return getRuleContext<PhpParser::NewExprContext>(0);
}

PhpParser::NewExpressionContext::NewExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::NewExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitNewExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ParenthesisExpressionContext ------------------------------------------------------------------

PhpParser::ParenthesisContext* PhpParser::ParenthesisExpressionContext::parenthesis() {
  return getRuleContext<PhpParser::ParenthesisContext>(0);
}

PhpParser::ParenthesisExpressionContext::ParenthesisExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::ParenthesisExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitParenthesisExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- BackQuoteStringExpressionContext ------------------------------------------------------------------

tree::TerminalNode* PhpParser::BackQuoteStringExpressionContext::BackQuoteString() {
  return getToken(PhpParser::BackQuoteString, 0);
}

PhpParser::BackQuoteStringExpressionContext::BackQuoteStringExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::BackQuoteStringExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitBackQuoteStringExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ConditionalExpressionContext ------------------------------------------------------------------

std::vector<PhpParser::ExpressionContext *> PhpParser::ConditionalExpressionContext::expression() {
  return getRuleContexts<PhpParser::ExpressionContext>();
}

PhpParser::ExpressionContext* PhpParser::ConditionalExpressionContext::expression(size_t i) {
  return getRuleContext<PhpParser::ExpressionContext>(i);
}

tree::TerminalNode* PhpParser::ConditionalExpressionContext::QuestionMark() {
  return getToken(PhpParser::QuestionMark, 0);
}

PhpParser::ConditionalExpressionContext::ConditionalExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::ConditionalExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitConditionalExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ArithmeticExpressionContext ------------------------------------------------------------------

std::vector<PhpParser::ExpressionContext *> PhpParser::ArithmeticExpressionContext::expression() {
  return getRuleContexts<PhpParser::ExpressionContext>();
}

PhpParser::ExpressionContext* PhpParser::ArithmeticExpressionContext::expression(size_t i) {
  return getRuleContext<PhpParser::ExpressionContext>(i);
}

tree::TerminalNode* PhpParser::ArithmeticExpressionContext::Divide() {
  return getToken(PhpParser::Divide, 0);
}

PhpParser::ArithmeticExpressionContext::ArithmeticExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::ArithmeticExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitArithmeticExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- IndexerExpressionContext ------------------------------------------------------------------

PhpParser::StringConstantContext* PhpParser::IndexerExpressionContext::stringConstant() {
  return getRuleContext<PhpParser::StringConstantContext>(0);
}

PhpParser::ExpressionContext* PhpParser::IndexerExpressionContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}

PhpParser::IndexerExpressionContext::IndexerExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::IndexerExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitIndexerExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ScalarExpressionContext ------------------------------------------------------------------

PhpParser::ConstantContext* PhpParser::ScalarExpressionContext::constant() {
  return getRuleContext<PhpParser::ConstantContext>(0);
}

PhpParser::StringContext* PhpParser::ScalarExpressionContext::string() {
  return getRuleContext<PhpParser::StringContext>(0);
}

tree::TerminalNode* PhpParser::ScalarExpressionContext::Label() {
  return getToken(PhpParser::Label, 0);
}

PhpParser::ScalarExpressionContext::ScalarExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::ScalarExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitScalarExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- PrefixIncDecExpressionContext ------------------------------------------------------------------

PhpParser::ChainContext* PhpParser::PrefixIncDecExpressionContext::chain() {
  return getRuleContext<PhpParser::ChainContext>(0);
}

PhpParser::PrefixIncDecExpressionContext::PrefixIncDecExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::PrefixIncDecExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitPrefixIncDecExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ComparisonExpressionContext ------------------------------------------------------------------

std::vector<PhpParser::ExpressionContext *> PhpParser::ComparisonExpressionContext::expression() {
  return getRuleContexts<PhpParser::ExpressionContext>();
}

PhpParser::ExpressionContext* PhpParser::ComparisonExpressionContext::expression(size_t i) {
  return getRuleContext<PhpParser::ExpressionContext>(i);
}

tree::TerminalNode* PhpParser::ComparisonExpressionContext::Less() {
  return getToken(PhpParser::Less, 0);
}

tree::TerminalNode* PhpParser::ComparisonExpressionContext::Greater() {
  return getToken(PhpParser::Greater, 0);
}

tree::TerminalNode* PhpParser::ComparisonExpressionContext::IsNotEq() {
  return getToken(PhpParser::IsNotEq, 0);
}

PhpParser::ComparisonExpressionContext::ComparisonExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::ComparisonExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitComparisonExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- LogicalExpressionContext ------------------------------------------------------------------

std::vector<PhpParser::ExpressionContext *> PhpParser::LogicalExpressionContext::expression() {
  return getRuleContexts<PhpParser::ExpressionContext>();
}

PhpParser::ExpressionContext* PhpParser::LogicalExpressionContext::expression(size_t i) {
  return getRuleContext<PhpParser::ExpressionContext>(i);
}

tree::TerminalNode* PhpParser::LogicalExpressionContext::LogicalAnd() {
  return getToken(PhpParser::LogicalAnd, 0);
}

tree::TerminalNode* PhpParser::LogicalExpressionContext::LogicalXor() {
  return getToken(PhpParser::LogicalXor, 0);
}

tree::TerminalNode* PhpParser::LogicalExpressionContext::LogicalOr() {
  return getToken(PhpParser::LogicalOr, 0);
}

PhpParser::LogicalExpressionContext::LogicalExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::LogicalExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitLogicalExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- PrintExpressionContext ------------------------------------------------------------------

tree::TerminalNode* PhpParser::PrintExpressionContext::Print() {
  return getToken(PhpParser::Print, 0);
}

PhpParser::ExpressionContext* PhpParser::PrintExpressionContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}

PhpParser::PrintExpressionContext::PrintExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::PrintExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitPrintExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- AssignmentExpressionContext ------------------------------------------------------------------

std::vector<PhpParser::ChainContext *> PhpParser::AssignmentExpressionContext::chain() {
  return getRuleContexts<PhpParser::ChainContext>();
}

PhpParser::ChainContext* PhpParser::AssignmentExpressionContext::chain(size_t i) {
  return getRuleContext<PhpParser::ChainContext>(i);
}

PhpParser::AssignmentOperatorContext* PhpParser::AssignmentExpressionContext::assignmentOperator() {
  return getRuleContext<PhpParser::AssignmentOperatorContext>(0);
}

PhpParser::ExpressionContext* PhpParser::AssignmentExpressionContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}

tree::TerminalNode* PhpParser::AssignmentExpressionContext::Eq() {
  return getToken(PhpParser::Eq, 0);
}

PhpParser::NewExprContext* PhpParser::AssignmentExpressionContext::newExpr() {
  return getRuleContext<PhpParser::NewExprContext>(0);
}

PhpParser::AssignmentExpressionContext::AssignmentExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::AssignmentExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitAssignmentExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- PostfixIncDecExpressionContext ------------------------------------------------------------------

PhpParser::ChainContext* PhpParser::PostfixIncDecExpressionContext::chain() {
  return getRuleContext<PhpParser::ChainContext>(0);
}

PhpParser::PostfixIncDecExpressionContext::PostfixIncDecExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::PostfixIncDecExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitPostfixIncDecExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- CastExpressionContext ------------------------------------------------------------------

PhpParser::CastOperationContext* PhpParser::CastExpressionContext::castOperation() {
  return getRuleContext<PhpParser::CastOperationContext>(0);
}

PhpParser::ExpressionContext* PhpParser::CastExpressionContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}

PhpParser::CastExpressionContext::CastExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::CastExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitCastExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- InstanceOfExpressionContext ------------------------------------------------------------------

PhpParser::ExpressionContext* PhpParser::InstanceOfExpressionContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}

tree::TerminalNode* PhpParser::InstanceOfExpressionContext::InstanceOf() {
  return getToken(PhpParser::InstanceOf, 0);
}

PhpParser::TypeRefContext* PhpParser::InstanceOfExpressionContext::typeRef() {
  return getRuleContext<PhpParser::TypeRefContext>(0);
}

PhpParser::InstanceOfExpressionContext::InstanceOfExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::InstanceOfExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitInstanceOfExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- LambdaFunctionExpressionContext ------------------------------------------------------------------

tree::TerminalNode* PhpParser::LambdaFunctionExpressionContext::Function() {
  return getToken(PhpParser::Function, 0);
}

PhpParser::FormalParameterListContext* PhpParser::LambdaFunctionExpressionContext::formalParameterList() {
  return getRuleContext<PhpParser::FormalParameterListContext>(0);
}

PhpParser::BlockStatementContext* PhpParser::LambdaFunctionExpressionContext::blockStatement() {
  return getRuleContext<PhpParser::BlockStatementContext>(0);
}

tree::TerminalNode* PhpParser::LambdaFunctionExpressionContext::Static() {
  return getToken(PhpParser::Static, 0);
}

PhpParser::LambdaFunctionUseVarsContext* PhpParser::LambdaFunctionExpressionContext::lambdaFunctionUseVars() {
  return getRuleContext<PhpParser::LambdaFunctionUseVarsContext>(0);
}

PhpParser::LambdaFunctionExpressionContext::LambdaFunctionExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::LambdaFunctionExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitLambdaFunctionExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- BitwiseExpressionContext ------------------------------------------------------------------

std::vector<PhpParser::ExpressionContext *> PhpParser::BitwiseExpressionContext::expression() {
  return getRuleContexts<PhpParser::ExpressionContext>();
}

PhpParser::ExpressionContext* PhpParser::BitwiseExpressionContext::expression(size_t i) {
  return getRuleContext<PhpParser::ExpressionContext>(i);
}

PhpParser::BitwiseExpressionContext::BitwiseExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::BitwiseExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitBitwiseExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- CloneExpressionContext ------------------------------------------------------------------

tree::TerminalNode* PhpParser::CloneExpressionContext::Clone() {
  return getToken(PhpParser::Clone, 0);
}

PhpParser::ExpressionContext* PhpParser::CloneExpressionContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}

PhpParser::CloneExpressionContext::CloneExpressionContext(ExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any PhpParser::CloneExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitCloneExpression(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ExpressionContext* PhpParser::expression() {
   return expression(0);
}

PhpParser::ExpressionContext* PhpParser::expression(int precedence) {
  ParserRuleContext *parentContext = _ctx;
  size_t parentState = getState();
  PhpParser::ExpressionContext *_localctx = _tracker.createInstance<ExpressionContext>(_ctx, parentState);
  PhpParser::ExpressionContext *previousContext = _localctx;
  size_t startState = 152;
  enterRecursionRule(_localctx, 152, PhpParser::RuleExpression, precedence);

    size_t _la = 0;

  auto onExit = finally([=] {
    unrollRecursionContexts(parentContext);
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(1120);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 110, _ctx)) {
    case 1: {
      _localctx = _tracker.createInstance<CloneExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;

      setState(1012);
      match(PhpParser::Clone);
      setState(1013);
      expression(43);
      break;
    }

    case 2: {
      _localctx = _tracker.createInstance<NewExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1014);
      newExpr();
      break;
    }

    case 3: {
      _localctx = _tracker.createInstance<IndexerExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1015);
      stringConstant();
      setState(1016);
      match(PhpParser::OpenSquareBracket);
      setState(1017);
      expression(0);
      setState(1018);
      match(PhpParser::CloseSquareBracket);
      break;
    }

    case 4: {
      _localctx = _tracker.createInstance<CastExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1020);
      match(PhpParser::OpenRoundBracket);
      setState(1021);
      castOperation();
      setState(1022);
      match(PhpParser::CloseRoundBracket);
      setState(1023);
      expression(40);
      break;
    }

    case 5: {
      _localctx = _tracker.createInstance<UnaryOperatorExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1025);
      _la = _input->LA(1);
      if (!(_la == PhpParser::Tilde

      || _la == PhpParser::SuppressWarnings)) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      setState(1026);
      expression(39);
      break;
    }

    case 6: {
      _localctx = _tracker.createInstance<UnaryOperatorExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1027);
      _la = _input->LA(1);
      if (!(((((_la - 154) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 154)) & ((1ULL << (PhpParser::Bang - 154))
        | (1ULL << (PhpParser::Plus - 154))
        | (1ULL << (PhpParser::Minus - 154)))) != 0))) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      setState(1028);
      expression(38);
      break;
    }

    case 7: {
      _localctx = _tracker.createInstance<PrefixIncDecExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1029);
      _la = _input->LA(1);
      if (!(_la == PhpParser::Inc

      || _la == PhpParser::Dec)) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      setState(1030);
      chain();
      break;
    }

    case 8: {
      _localctx = _tracker.createInstance<PostfixIncDecExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1031);
      chain();
      setState(1032);
      _la = _input->LA(1);
      if (!(_la == PhpParser::Inc

      || _la == PhpParser::Dec)) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      break;
    }

    case 9: {
      _localctx = _tracker.createInstance<PrintExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1034);
      match(PhpParser::Print);
      setState(1035);
      expression(35);
      break;
    }

    case 10: {
      _localctx = _tracker.createInstance<ChainExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1036);
      chain();
      break;
    }

    case 11: {
      _localctx = _tracker.createInstance<ScalarExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1037);
      constant();
      break;
    }

    case 12: {
      _localctx = _tracker.createInstance<ScalarExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1038);
      string();
      break;
    }

    case 13: {
      _localctx = _tracker.createInstance<ScalarExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1039);
      match(PhpParser::Label);
      break;
    }

    case 14: {
      _localctx = _tracker.createInstance<BackQuoteStringExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1040);
      match(PhpParser::BackQuoteString);
      break;
    }

    case 15: {
      _localctx = _tracker.createInstance<ParenthesisExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1041);
      parenthesis();
      break;
    }

    case 16: {
      _localctx = _tracker.createInstance<ArrayCreationExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1053);
      _errHandler->sync(this);
      switch (_input->LA(1)) {
        case PhpParser::Array: {
          setState(1042);
          match(PhpParser::Array);
          setState(1043);
          match(PhpParser::OpenRoundBracket);
          setState(1045);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if ((((_la & ~ 0x3fULL) == 0) &&
            ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
            | (1ULL << PhpParser::Array)
            | (1ULL << PhpParser::As)
            | (1ULL << PhpParser::BinaryCast)
            | (1ULL << PhpParser::BoolType)
            | (1ULL << PhpParser::BooleanConstant)
            | (1ULL << PhpParser::Break)
            | (1ULL << PhpParser::Callable)
            | (1ULL << PhpParser::Case)
            | (1ULL << PhpParser::Catch)
            | (1ULL << PhpParser::Class)
            | (1ULL << PhpParser::Clone)
            | (1ULL << PhpParser::Const)
            | (1ULL << PhpParser::Continue)
            | (1ULL << PhpParser::Declare)
            | (1ULL << PhpParser::Default)
            | (1ULL << PhpParser::Do)
            | (1ULL << PhpParser::DoubleCast)
            | (1ULL << PhpParser::DoubleType)
            | (1ULL << PhpParser::Echo)
            | (1ULL << PhpParser::Else)
            | (1ULL << PhpParser::ElseIf)
            | (1ULL << PhpParser::Empty)
            | (1ULL << PhpParser::EndDeclare)
            | (1ULL << PhpParser::EndFor)
            | (1ULL << PhpParser::EndForeach)
            | (1ULL << PhpParser::EndIf)
            | (1ULL << PhpParser::EndSwitch)
            | (1ULL << PhpParser::EndWhile)
            | (1ULL << PhpParser::Eval)
            | (1ULL << PhpParser::Exit)
            | (1ULL << PhpParser::Extends)
            | (1ULL << PhpParser::Final)
            | (1ULL << PhpParser::Finally)
            | (1ULL << PhpParser::FloatCast)
            | (1ULL << PhpParser::For)
            | (1ULL << PhpParser::Foreach)
            | (1ULL << PhpParser::Function)
            | (1ULL << PhpParser::Global)
            | (1ULL << PhpParser::Goto)
            | (1ULL << PhpParser::If)
            | (1ULL << PhpParser::Implements)
            | (1ULL << PhpParser::Import)
            | (1ULL << PhpParser::Include)
            | (1ULL << PhpParser::IncludeOnce)
            | (1ULL << PhpParser::InstanceOf)
            | (1ULL << PhpParser::InsteadOf)
            | (1ULL << PhpParser::Int8Cast)
            | (1ULL << PhpParser::Int16Cast)
            | (1ULL << PhpParser::Int64Type)
            | (1ULL << PhpParser::IntType)
            | (1ULL << PhpParser::Interface)
            | (1ULL << PhpParser::IsSet)
            | (1ULL << PhpParser::List)
            | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
            ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
            | (1ULL << (PhpParser::LogicalXor - 64))
            | (1ULL << (PhpParser::Namespace - 64))
            | (1ULL << (PhpParser::New - 64))
            | (1ULL << (PhpParser::Null - 64))
            | (1ULL << (PhpParser::ObjectType - 64))
            | (1ULL << (PhpParser::Parent_ - 64))
            | (1ULL << (PhpParser::Partial - 64))
            | (1ULL << (PhpParser::Print - 64))
            | (1ULL << (PhpParser::Private - 64))
            | (1ULL << (PhpParser::Protected - 64))
            | (1ULL << (PhpParser::Public - 64))
            | (1ULL << (PhpParser::Require - 64))
            | (1ULL << (PhpParser::RequireOnce - 64))
            | (1ULL << (PhpParser::Resource - 64))
            | (1ULL << (PhpParser::Return - 64))
            | (1ULL << (PhpParser::Static - 64))
            | (1ULL << (PhpParser::StringType - 64))
            | (1ULL << (PhpParser::Switch - 64))
            | (1ULL << (PhpParser::Throw - 64))
            | (1ULL << (PhpParser::Trait - 64))
            | (1ULL << (PhpParser::Try - 64))
            | (1ULL << (PhpParser::Typeof - 64))
            | (1ULL << (PhpParser::UintCast - 64))
            | (1ULL << (PhpParser::UnicodeCast - 64))
            | (1ULL << (PhpParser::Unset - 64))
            | (1ULL << (PhpParser::Use - 64))
            | (1ULL << (PhpParser::Var - 64))
            | (1ULL << (PhpParser::While - 64))
            | (1ULL << (PhpParser::Yield - 64))
            | (1ULL << (PhpParser::Get - 64))
            | (1ULL << (PhpParser::Set - 64))
            | (1ULL << (PhpParser::Call - 64))
            | (1ULL << (PhpParser::CallStatic - 64))
            | (1ULL << (PhpParser::Constructor - 64))
            | (1ULL << (PhpParser::Destruct - 64))
            | (1ULL << (PhpParser::Wakeup - 64))
            | (1ULL << (PhpParser::Sleep - 64))
            | (1ULL << (PhpParser::Autoload - 64))
            | (1ULL << (PhpParser::IsSet__ - 64))
            | (1ULL << (PhpParser::Unset__ - 64))
            | (1ULL << (PhpParser::ToString__ - 64))
            | (1ULL << (PhpParser::Invoke - 64))
            | (1ULL << (PhpParser::SetState - 64))
            | (1ULL << (PhpParser::Clone__ - 64))
            | (1ULL << (PhpParser::DebugInfo - 64))
            | (1ULL << (PhpParser::Namespace__ - 64))
            | (1ULL << (PhpParser::Class__ - 64))
            | (1ULL << (PhpParser::Traic__ - 64))
            | (1ULL << (PhpParser::Function__ - 64))
            | (1ULL << (PhpParser::Method__ - 64))
            | (1ULL << (PhpParser::Line__ - 64))
            | (1ULL << (PhpParser::File__ - 64))
            | (1ULL << (PhpParser::Dir__ - 64))
            | (1ULL << (PhpParser::Inc - 64))
            | (1ULL << (PhpParser::Dec - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
            ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
            | (1ULL << (PhpParser::Ampersand - 148))
            | (1ULL << (PhpParser::Bang - 148))
            | (1ULL << (PhpParser::Plus - 148))
            | (1ULL << (PhpParser::Minus - 148))
            | (1ULL << (PhpParser::Tilde - 148))
            | (1ULL << (PhpParser::SuppressWarnings - 148))
            | (1ULL << (PhpParser::Dollar - 148))
            | (1ULL << (PhpParser::OpenRoundBracket - 148))
            | (1ULL << (PhpParser::OpenSquareBracket - 148))
            | (1ULL << (PhpParser::VarName - 148))
            | (1ULL << (PhpParser::Label - 148))
            | (1ULL << (PhpParser::Octal - 148))
            | (1ULL << (PhpParser::Decimal - 148))
            | (1ULL << (PhpParser::Real - 148))
            | (1ULL << (PhpParser::Hex - 148))
            | (1ULL << (PhpParser::Binary - 148))
            | (1ULL << (PhpParser::BackQuoteString - 148))
            | (1ULL << (PhpParser::SingleQuoteString - 148))
            | (1ULL << (PhpParser::DoubleQuote - 148))
            | (1ULL << (PhpParser::StartNowDoc - 148))
            | (1ULL << (PhpParser::StartHereDoc - 148)))) != 0)) {
            setState(1044);
            arrayItemList();
          }
          setState(1047);
          match(PhpParser::CloseRoundBracket);
          break;
        }

        case PhpParser::OpenSquareBracket: {
          setState(1048);
          match(PhpParser::OpenSquareBracket);
          setState(1050);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if ((((_la & ~ 0x3fULL) == 0) &&
            ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
            | (1ULL << PhpParser::Array)
            | (1ULL << PhpParser::As)
            | (1ULL << PhpParser::BinaryCast)
            | (1ULL << PhpParser::BoolType)
            | (1ULL << PhpParser::BooleanConstant)
            | (1ULL << PhpParser::Break)
            | (1ULL << PhpParser::Callable)
            | (1ULL << PhpParser::Case)
            | (1ULL << PhpParser::Catch)
            | (1ULL << PhpParser::Class)
            | (1ULL << PhpParser::Clone)
            | (1ULL << PhpParser::Const)
            | (1ULL << PhpParser::Continue)
            | (1ULL << PhpParser::Declare)
            | (1ULL << PhpParser::Default)
            | (1ULL << PhpParser::Do)
            | (1ULL << PhpParser::DoubleCast)
            | (1ULL << PhpParser::DoubleType)
            | (1ULL << PhpParser::Echo)
            | (1ULL << PhpParser::Else)
            | (1ULL << PhpParser::ElseIf)
            | (1ULL << PhpParser::Empty)
            | (1ULL << PhpParser::EndDeclare)
            | (1ULL << PhpParser::EndFor)
            | (1ULL << PhpParser::EndForeach)
            | (1ULL << PhpParser::EndIf)
            | (1ULL << PhpParser::EndSwitch)
            | (1ULL << PhpParser::EndWhile)
            | (1ULL << PhpParser::Eval)
            | (1ULL << PhpParser::Exit)
            | (1ULL << PhpParser::Extends)
            | (1ULL << PhpParser::Final)
            | (1ULL << PhpParser::Finally)
            | (1ULL << PhpParser::FloatCast)
            | (1ULL << PhpParser::For)
            | (1ULL << PhpParser::Foreach)
            | (1ULL << PhpParser::Function)
            | (1ULL << PhpParser::Global)
            | (1ULL << PhpParser::Goto)
            | (1ULL << PhpParser::If)
            | (1ULL << PhpParser::Implements)
            | (1ULL << PhpParser::Import)
            | (1ULL << PhpParser::Include)
            | (1ULL << PhpParser::IncludeOnce)
            | (1ULL << PhpParser::InstanceOf)
            | (1ULL << PhpParser::InsteadOf)
            | (1ULL << PhpParser::Int8Cast)
            | (1ULL << PhpParser::Int16Cast)
            | (1ULL << PhpParser::Int64Type)
            | (1ULL << PhpParser::IntType)
            | (1ULL << PhpParser::Interface)
            | (1ULL << PhpParser::IsSet)
            | (1ULL << PhpParser::List)
            | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
            ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
            | (1ULL << (PhpParser::LogicalXor - 64))
            | (1ULL << (PhpParser::Namespace - 64))
            | (1ULL << (PhpParser::New - 64))
            | (1ULL << (PhpParser::Null - 64))
            | (1ULL << (PhpParser::ObjectType - 64))
            | (1ULL << (PhpParser::Parent_ - 64))
            | (1ULL << (PhpParser::Partial - 64))
            | (1ULL << (PhpParser::Print - 64))
            | (1ULL << (PhpParser::Private - 64))
            | (1ULL << (PhpParser::Protected - 64))
            | (1ULL << (PhpParser::Public - 64))
            | (1ULL << (PhpParser::Require - 64))
            | (1ULL << (PhpParser::RequireOnce - 64))
            | (1ULL << (PhpParser::Resource - 64))
            | (1ULL << (PhpParser::Return - 64))
            | (1ULL << (PhpParser::Static - 64))
            | (1ULL << (PhpParser::StringType - 64))
            | (1ULL << (PhpParser::Switch - 64))
            | (1ULL << (PhpParser::Throw - 64))
            | (1ULL << (PhpParser::Trait - 64))
            | (1ULL << (PhpParser::Try - 64))
            | (1ULL << (PhpParser::Typeof - 64))
            | (1ULL << (PhpParser::UintCast - 64))
            | (1ULL << (PhpParser::UnicodeCast - 64))
            | (1ULL << (PhpParser::Unset - 64))
            | (1ULL << (PhpParser::Use - 64))
            | (1ULL << (PhpParser::Var - 64))
            | (1ULL << (PhpParser::While - 64))
            | (1ULL << (PhpParser::Yield - 64))
            | (1ULL << (PhpParser::Get - 64))
            | (1ULL << (PhpParser::Set - 64))
            | (1ULL << (PhpParser::Call - 64))
            | (1ULL << (PhpParser::CallStatic - 64))
            | (1ULL << (PhpParser::Constructor - 64))
            | (1ULL << (PhpParser::Destruct - 64))
            | (1ULL << (PhpParser::Wakeup - 64))
            | (1ULL << (PhpParser::Sleep - 64))
            | (1ULL << (PhpParser::Autoload - 64))
            | (1ULL << (PhpParser::IsSet__ - 64))
            | (1ULL << (PhpParser::Unset__ - 64))
            | (1ULL << (PhpParser::ToString__ - 64))
            | (1ULL << (PhpParser::Invoke - 64))
            | (1ULL << (PhpParser::SetState - 64))
            | (1ULL << (PhpParser::Clone__ - 64))
            | (1ULL << (PhpParser::DebugInfo - 64))
            | (1ULL << (PhpParser::Namespace__ - 64))
            | (1ULL << (PhpParser::Class__ - 64))
            | (1ULL << (PhpParser::Traic__ - 64))
            | (1ULL << (PhpParser::Function__ - 64))
            | (1ULL << (PhpParser::Method__ - 64))
            | (1ULL << (PhpParser::Line__ - 64))
            | (1ULL << (PhpParser::File__ - 64))
            | (1ULL << (PhpParser::Dir__ - 64))
            | (1ULL << (PhpParser::Inc - 64))
            | (1ULL << (PhpParser::Dec - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
            ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
            | (1ULL << (PhpParser::Ampersand - 148))
            | (1ULL << (PhpParser::Bang - 148))
            | (1ULL << (PhpParser::Plus - 148))
            | (1ULL << (PhpParser::Minus - 148))
            | (1ULL << (PhpParser::Tilde - 148))
            | (1ULL << (PhpParser::SuppressWarnings - 148))
            | (1ULL << (PhpParser::Dollar - 148))
            | (1ULL << (PhpParser::OpenRoundBracket - 148))
            | (1ULL << (PhpParser::OpenSquareBracket - 148))
            | (1ULL << (PhpParser::VarName - 148))
            | (1ULL << (PhpParser::Label - 148))
            | (1ULL << (PhpParser::Octal - 148))
            | (1ULL << (PhpParser::Decimal - 148))
            | (1ULL << (PhpParser::Real - 148))
            | (1ULL << (PhpParser::Hex - 148))
            | (1ULL << (PhpParser::Binary - 148))
            | (1ULL << (PhpParser::BackQuoteString - 148))
            | (1ULL << (PhpParser::SingleQuoteString - 148))
            | (1ULL << (PhpParser::DoubleQuote - 148))
            | (1ULL << (PhpParser::StartNowDoc - 148))
            | (1ULL << (PhpParser::StartHereDoc - 148)))) != 0)) {
            setState(1049);
            arrayItemList();
          }
          setState(1052);
          match(PhpParser::CloseSquareBracket);
          break;
        }

      default:
        throw NoViableAltException(this);
      }
      setState(1059);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 104, _ctx)) {
      case 1: {
        setState(1055);
        match(PhpParser::OpenSquareBracket);
        setState(1056);
        expression(0);
        setState(1057);
        match(PhpParser::CloseSquareBracket);
        break;
      }

      }
      break;
    }

    case 17: {
      _localctx = _tracker.createInstance<SpecialWordExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1061);
      match(PhpParser::Yield);
      break;
    }

    case 18: {
      _localctx = _tracker.createInstance<SpecialWordExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1062);
      match(PhpParser::List);
      setState(1063);
      match(PhpParser::OpenRoundBracket);
      setState(1064);
      assignmentList();
      setState(1065);
      match(PhpParser::CloseRoundBracket);
      setState(1066);
      match(PhpParser::Eq);
      setState(1067);
      expression(26);
      break;
    }

    case 19: {
      _localctx = _tracker.createInstance<SpecialWordExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1069);
      match(PhpParser::IsSet);
      setState(1070);
      match(PhpParser::OpenRoundBracket);
      setState(1071);
      chainList();
      setState(1072);
      match(PhpParser::CloseRoundBracket);
      break;
    }

    case 20: {
      _localctx = _tracker.createInstance<SpecialWordExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1074);
      match(PhpParser::Empty);
      setState(1075);
      match(PhpParser::OpenRoundBracket);
      setState(1076);
      chain();
      setState(1077);
      match(PhpParser::CloseRoundBracket);
      break;
    }

    case 21: {
      _localctx = _tracker.createInstance<SpecialWordExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1079);
      match(PhpParser::Eval);
      setState(1080);
      match(PhpParser::OpenRoundBracket);
      setState(1081);
      expression(0);
      setState(1082);
      match(PhpParser::CloseRoundBracket);
      break;
    }

    case 22: {
      _localctx = _tracker.createInstance<SpecialWordExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1084);
      match(PhpParser::Exit);
      setState(1088);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 105, _ctx)) {
      case 1: {
        setState(1085);
        match(PhpParser::OpenRoundBracket);
        setState(1086);
        match(PhpParser::CloseRoundBracket);
        break;
      }

      case 2: {
        setState(1087);
        parenthesis();
        break;
      }

      }
      break;
    }

    case 23: {
      _localctx = _tracker.createInstance<SpecialWordExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1090);
      _la = _input->LA(1);
      if (!(_la == PhpParser::Include

      || _la == PhpParser::IncludeOnce)) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      setState(1091);
      expression(21);
      break;
    }

    case 24: {
      _localctx = _tracker.createInstance<SpecialWordExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1092);
      _la = _input->LA(1);
      if (!(_la == PhpParser::Require

      || _la == PhpParser::RequireOnce)) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      setState(1093);
      expression(20);
      break;
    }

    case 25: {
      _localctx = _tracker.createInstance<LambdaFunctionExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1095);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == PhpParser::Static) {
        setState(1094);
        match(PhpParser::Static);
      }
      setState(1097);
      match(PhpParser::Function);
      setState(1099);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == PhpParser::Ampersand) {
        setState(1098);
        match(PhpParser::Ampersand);
      }
      setState(1101);
      match(PhpParser::OpenRoundBracket);
      setState(1102);
      formalParameterList();
      setState(1103);
      match(PhpParser::CloseRoundBracket);
      setState(1105);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == PhpParser::Use) {
        setState(1104);
        lambdaFunctionUseVars();
      }
      setState(1107);
      blockStatement();
      break;
    }

    case 26: {
      _localctx = _tracker.createInstance<AssignmentExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1109);
      chain();
      setState(1110);
      assignmentOperator();
      setState(1111);
      expression(5);
      break;
    }

    case 27: {
      _localctx = _tracker.createInstance<AssignmentExpressionContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(1113);
      chain();
      setState(1114);
      match(PhpParser::Eq);
      setState(1115);
      match(PhpParser::Ampersand);
      setState(1118);
      _errHandler->sync(this);
      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 109, _ctx)) {
      case 1: {
        setState(1116);
        chain();
        break;
      }

      case 2: {
        setState(1117);
        newExpr();
        break;
      }

      }
      break;
    }

    }
    _ctx->stop = _input->LT(-1);
    setState(1176);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 113, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        if (!_parseListeners.empty())
          triggerExitRuleEvent();
        previousContext = _localctx;
        setState(1174);
        _errHandler->sync(this);
        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 112, _ctx)) {
        case 1: {
          auto newContext = _tracker.createInstance<ArithmeticExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1122);

          if (!(precpred(_ctx, 18))) throw FailedPredicateException(this, "precpred(_ctx, 18)");
          setState(1123);
          dynamic_cast<ArithmeticExpressionContext *>(_localctx)->op = match(PhpParser::Pow);
          setState(1124);
          expression(18);
          break;
        }

        case 2: {
          auto newContext = _tracker.createInstance<ArithmeticExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1125);

          if (!(precpred(_ctx, 16))) throw FailedPredicateException(this, "precpred(_ctx, 16)");
          setState(1126);
          dynamic_cast<ArithmeticExpressionContext *>(_localctx)->op = _input->LT(1);
          _la = _input->LA(1);
          if (!(((((_la - 158) & ~ 0x3fULL) == 0) &&
            ((1ULL << (_la - 158)) & ((1ULL << (PhpParser::Asterisk - 158))
            | (1ULL << (PhpParser::Percent - 158))
            | (1ULL << (PhpParser::Divide - 158)))) != 0))) {
            dynamic_cast<ArithmeticExpressionContext *>(_localctx)->op = _errHandler->recoverInline(this);
          }
          else {
            _errHandler->reportMatch(this);
            consume();
          }
          setState(1127);
          expression(17);
          break;
        }

        case 3: {
          auto newContext = _tracker.createInstance<ArithmeticExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1128);

          if (!(precpred(_ctx, 15))) throw FailedPredicateException(this, "precpred(_ctx, 15)");
          setState(1129);
          dynamic_cast<ArithmeticExpressionContext *>(_localctx)->op = _input->LT(1);
          _la = _input->LA(1);
          if (!(((((_la - 156) & ~ 0x3fULL) == 0) &&
            ((1ULL << (_la - 156)) & ((1ULL << (PhpParser::Plus - 156))
            | (1ULL << (PhpParser::Minus - 156))
            | (1ULL << (PhpParser::Dot - 156)))) != 0))) {
            dynamic_cast<ArithmeticExpressionContext *>(_localctx)->op = _errHandler->recoverInline(this);
          }
          else {
            _errHandler->reportMatch(this);
            consume();
          }
          setState(1130);
          expression(16);
          break;
        }

        case 4: {
          auto newContext = _tracker.createInstance<ComparisonExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1131);

          if (!(precpred(_ctx, 14))) throw FailedPredicateException(this, "precpred(_ctx, 14)");
          setState(1132);
          dynamic_cast<ComparisonExpressionContext *>(_localctx)->op = _input->LT(1);
          _la = _input->LA(1);
          if (!(_la == PhpParser::ShiftLeft

          || _la == PhpParser::ShiftRight)) {
            dynamic_cast<ComparisonExpressionContext *>(_localctx)->op = _errHandler->recoverInline(this);
          }
          else {
            _errHandler->reportMatch(this);
            consume();
          }
          setState(1133);
          expression(15);
          break;
        }

        case 5: {
          auto newContext = _tracker.createInstance<ComparisonExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1134);

          if (!(precpred(_ctx, 13))) throw FailedPredicateException(this, "precpred(_ctx, 13)");
          setState(1135);
          dynamic_cast<ComparisonExpressionContext *>(_localctx)->op = _input->LT(1);
          _la = _input->LA(1);
          if (!(((((_la - 127) & ~ 0x3fULL) == 0) &&
            ((1ULL << (_la - 127)) & ((1ULL << (PhpParser::IsSmallerOrEqual - 127))
            | (1ULL << (PhpParser::IsGreaterOrEqual - 127))
            | (1ULL << (PhpParser::Less - 127))
            | (1ULL << (PhpParser::Greater - 127)))) != 0))) {
            dynamic_cast<ComparisonExpressionContext *>(_localctx)->op = _errHandler->recoverInline(this);
          }
          else {
            _errHandler->reportMatch(this);
            consume();
          }
          setState(1136);
          expression(14);
          break;
        }

        case 6: {
          auto newContext = _tracker.createInstance<ComparisonExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1137);

          if (!(precpred(_ctx, 12))) throw FailedPredicateException(this, "precpred(_ctx, 12)");
          setState(1138);
          dynamic_cast<ComparisonExpressionContext *>(_localctx)->op = _input->LT(1);
          _la = _input->LA(1);
          if (!(((((_la - 123) & ~ 0x3fULL) == 0) &&
            ((1ULL << (_la - 123)) & ((1ULL << (PhpParser::IsIdentical - 123))
            | (1ULL << (PhpParser::IsNoidentical - 123))
            | (1ULL << (PhpParser::IsEqual - 123))
            | (1ULL << (PhpParser::IsNotEq - 123)))) != 0))) {
            dynamic_cast<ComparisonExpressionContext *>(_localctx)->op = _errHandler->recoverInline(this);
          }
          else {
            _errHandler->reportMatch(this);
            consume();
          }
          setState(1139);
          expression(13);
          break;
        }

        case 7: {
          auto newContext = _tracker.createInstance<BitwiseExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1140);

          if (!(precpred(_ctx, 11))) throw FailedPredicateException(this, "precpred(_ctx, 11)");
          setState(1141);
          dynamic_cast<BitwiseExpressionContext *>(_localctx)->op = match(PhpParser::Ampersand);
          setState(1142);
          expression(12);
          break;
        }

        case 8: {
          auto newContext = _tracker.createInstance<BitwiseExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1143);

          if (!(precpred(_ctx, 10))) throw FailedPredicateException(this, "precpred(_ctx, 10)");
          setState(1144);
          dynamic_cast<BitwiseExpressionContext *>(_localctx)->op = match(PhpParser::Caret);
          setState(1145);
          expression(11);
          break;
        }

        case 9: {
          auto newContext = _tracker.createInstance<BitwiseExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1146);

          if (!(precpred(_ctx, 9))) throw FailedPredicateException(this, "precpred(_ctx, 9)");
          setState(1147);
          dynamic_cast<BitwiseExpressionContext *>(_localctx)->op = match(PhpParser::Pipe);
          setState(1148);
          expression(10);
          break;
        }

        case 10: {
          auto newContext = _tracker.createInstance<BitwiseExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1149);

          if (!(precpred(_ctx, 8))) throw FailedPredicateException(this, "precpred(_ctx, 8)");
          setState(1150);
          dynamic_cast<BitwiseExpressionContext *>(_localctx)->op = match(PhpParser::BooleanAnd);
          setState(1151);
          expression(9);
          break;
        }

        case 11: {
          auto newContext = _tracker.createInstance<BitwiseExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1152);

          if (!(precpred(_ctx, 7))) throw FailedPredicateException(this, "precpred(_ctx, 7)");
          setState(1153);
          dynamic_cast<BitwiseExpressionContext *>(_localctx)->op = match(PhpParser::BooleanOr);
          setState(1154);
          expression(8);
          break;
        }

        case 12: {
          auto newContext = _tracker.createInstance<ConditionalExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1155);

          if (!(precpred(_ctx, 6))) throw FailedPredicateException(this, "precpred(_ctx, 6)");
          setState(1156);
          dynamic_cast<ConditionalExpressionContext *>(_localctx)->op = match(PhpParser::QuestionMark);
          setState(1158);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if ((((_la & ~ 0x3fULL) == 0) &&
            ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
            | (1ULL << PhpParser::Array)
            | (1ULL << PhpParser::As)
            | (1ULL << PhpParser::BinaryCast)
            | (1ULL << PhpParser::BoolType)
            | (1ULL << PhpParser::BooleanConstant)
            | (1ULL << PhpParser::Break)
            | (1ULL << PhpParser::Callable)
            | (1ULL << PhpParser::Case)
            | (1ULL << PhpParser::Catch)
            | (1ULL << PhpParser::Class)
            | (1ULL << PhpParser::Clone)
            | (1ULL << PhpParser::Const)
            | (1ULL << PhpParser::Continue)
            | (1ULL << PhpParser::Declare)
            | (1ULL << PhpParser::Default)
            | (1ULL << PhpParser::Do)
            | (1ULL << PhpParser::DoubleCast)
            | (1ULL << PhpParser::DoubleType)
            | (1ULL << PhpParser::Echo)
            | (1ULL << PhpParser::Else)
            | (1ULL << PhpParser::ElseIf)
            | (1ULL << PhpParser::Empty)
            | (1ULL << PhpParser::EndDeclare)
            | (1ULL << PhpParser::EndFor)
            | (1ULL << PhpParser::EndForeach)
            | (1ULL << PhpParser::EndIf)
            | (1ULL << PhpParser::EndSwitch)
            | (1ULL << PhpParser::EndWhile)
            | (1ULL << PhpParser::Eval)
            | (1ULL << PhpParser::Exit)
            | (1ULL << PhpParser::Extends)
            | (1ULL << PhpParser::Final)
            | (1ULL << PhpParser::Finally)
            | (1ULL << PhpParser::FloatCast)
            | (1ULL << PhpParser::For)
            | (1ULL << PhpParser::Foreach)
            | (1ULL << PhpParser::Function)
            | (1ULL << PhpParser::Global)
            | (1ULL << PhpParser::Goto)
            | (1ULL << PhpParser::If)
            | (1ULL << PhpParser::Implements)
            | (1ULL << PhpParser::Import)
            | (1ULL << PhpParser::Include)
            | (1ULL << PhpParser::IncludeOnce)
            | (1ULL << PhpParser::InstanceOf)
            | (1ULL << PhpParser::InsteadOf)
            | (1ULL << PhpParser::Int8Cast)
            | (1ULL << PhpParser::Int16Cast)
            | (1ULL << PhpParser::Int64Type)
            | (1ULL << PhpParser::IntType)
            | (1ULL << PhpParser::Interface)
            | (1ULL << PhpParser::IsSet)
            | (1ULL << PhpParser::List)
            | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
            ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
            | (1ULL << (PhpParser::LogicalXor - 64))
            | (1ULL << (PhpParser::Namespace - 64))
            | (1ULL << (PhpParser::New - 64))
            | (1ULL << (PhpParser::Null - 64))
            | (1ULL << (PhpParser::ObjectType - 64))
            | (1ULL << (PhpParser::Parent_ - 64))
            | (1ULL << (PhpParser::Partial - 64))
            | (1ULL << (PhpParser::Print - 64))
            | (1ULL << (PhpParser::Private - 64))
            | (1ULL << (PhpParser::Protected - 64))
            | (1ULL << (PhpParser::Public - 64))
            | (1ULL << (PhpParser::Require - 64))
            | (1ULL << (PhpParser::RequireOnce - 64))
            | (1ULL << (PhpParser::Resource - 64))
            | (1ULL << (PhpParser::Return - 64))
            | (1ULL << (PhpParser::Static - 64))
            | (1ULL << (PhpParser::StringType - 64))
            | (1ULL << (PhpParser::Switch - 64))
            | (1ULL << (PhpParser::Throw - 64))
            | (1ULL << (PhpParser::Trait - 64))
            | (1ULL << (PhpParser::Try - 64))
            | (1ULL << (PhpParser::Typeof - 64))
            | (1ULL << (PhpParser::UintCast - 64))
            | (1ULL << (PhpParser::UnicodeCast - 64))
            | (1ULL << (PhpParser::Unset - 64))
            | (1ULL << (PhpParser::Use - 64))
            | (1ULL << (PhpParser::Var - 64))
            | (1ULL << (PhpParser::While - 64))
            | (1ULL << (PhpParser::Yield - 64))
            | (1ULL << (PhpParser::Get - 64))
            | (1ULL << (PhpParser::Set - 64))
            | (1ULL << (PhpParser::Call - 64))
            | (1ULL << (PhpParser::CallStatic - 64))
            | (1ULL << (PhpParser::Constructor - 64))
            | (1ULL << (PhpParser::Destruct - 64))
            | (1ULL << (PhpParser::Wakeup - 64))
            | (1ULL << (PhpParser::Sleep - 64))
            | (1ULL << (PhpParser::Autoload - 64))
            | (1ULL << (PhpParser::IsSet__ - 64))
            | (1ULL << (PhpParser::Unset__ - 64))
            | (1ULL << (PhpParser::ToString__ - 64))
            | (1ULL << (PhpParser::Invoke - 64))
            | (1ULL << (PhpParser::SetState - 64))
            | (1ULL << (PhpParser::Clone__ - 64))
            | (1ULL << (PhpParser::DebugInfo - 64))
            | (1ULL << (PhpParser::Namespace__ - 64))
            | (1ULL << (PhpParser::Class__ - 64))
            | (1ULL << (PhpParser::Traic__ - 64))
            | (1ULL << (PhpParser::Function__ - 64))
            | (1ULL << (PhpParser::Method__ - 64))
            | (1ULL << (PhpParser::Line__ - 64))
            | (1ULL << (PhpParser::File__ - 64))
            | (1ULL << (PhpParser::Dir__ - 64))
            | (1ULL << (PhpParser::Inc - 64))
            | (1ULL << (PhpParser::Dec - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
            ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
            | (1ULL << (PhpParser::Bang - 148))
            | (1ULL << (PhpParser::Plus - 148))
            | (1ULL << (PhpParser::Minus - 148))
            | (1ULL << (PhpParser::Tilde - 148))
            | (1ULL << (PhpParser::SuppressWarnings - 148))
            | (1ULL << (PhpParser::Dollar - 148))
            | (1ULL << (PhpParser::OpenRoundBracket - 148))
            | (1ULL << (PhpParser::OpenSquareBracket - 148))
            | (1ULL << (PhpParser::VarName - 148))
            | (1ULL << (PhpParser::Label - 148))
            | (1ULL << (PhpParser::Octal - 148))
            | (1ULL << (PhpParser::Decimal - 148))
            | (1ULL << (PhpParser::Real - 148))
            | (1ULL << (PhpParser::Hex - 148))
            | (1ULL << (PhpParser::Binary - 148))
            | (1ULL << (PhpParser::BackQuoteString - 148))
            | (1ULL << (PhpParser::SingleQuoteString - 148))
            | (1ULL << (PhpParser::DoubleQuote - 148))
            | (1ULL << (PhpParser::StartNowDoc - 148))
            | (1ULL << (PhpParser::StartHereDoc - 148)))) != 0)) {
            setState(1157);
            expression(0);
          }
          setState(1160);
          match(PhpParser::Colon);
          setState(1161);
          expression(7);
          break;
        }

        case 13: {
          auto newContext = _tracker.createInstance<LogicalExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1162);

          if (!(precpred(_ctx, 3))) throw FailedPredicateException(this, "precpred(_ctx, 3)");
          setState(1163);
          dynamic_cast<LogicalExpressionContext *>(_localctx)->op = match(PhpParser::LogicalAnd);
          setState(1164);
          expression(4);
          break;
        }

        case 14: {
          auto newContext = _tracker.createInstance<LogicalExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1165);

          if (!(precpred(_ctx, 2))) throw FailedPredicateException(this, "precpred(_ctx, 2)");
          setState(1166);
          dynamic_cast<LogicalExpressionContext *>(_localctx)->op = match(PhpParser::LogicalXor);
          setState(1167);
          expression(3);
          break;
        }

        case 15: {
          auto newContext = _tracker.createInstance<LogicalExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1168);

          if (!(precpred(_ctx, 1))) throw FailedPredicateException(this, "precpred(_ctx, 1)");
          setState(1169);
          dynamic_cast<LogicalExpressionContext *>(_localctx)->op = match(PhpParser::LogicalOr);
          setState(1170);
          expression(2);
          break;
        }

        case 16: {
          auto newContext = _tracker.createInstance<InstanceOfExpressionContext>(_tracker.createInstance<ExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleExpression);
          setState(1171);

          if (!(precpred(_ctx, 17))) throw FailedPredicateException(this, "precpred(_ctx, 17)");
          setState(1172);
          match(PhpParser::InstanceOf);
          setState(1173);
          typeRef();
          break;
        }

        } 
      }
      setState(1178);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 113, _ctx);
    }
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }
  return _localctx;
}

//----------------- NewExprContext ------------------------------------------------------------------

PhpParser::NewExprContext::NewExprContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::NewExprContext::New() {
  return getToken(PhpParser::New, 0);
}

PhpParser::TypeRefContext* PhpParser::NewExprContext::typeRef() {
  return getRuleContext<PhpParser::TypeRefContext>(0);
}

PhpParser::ArgumentsContext* PhpParser::NewExprContext::arguments() {
  return getRuleContext<PhpParser::ArgumentsContext>(0);
}


size_t PhpParser::NewExprContext::getRuleIndex() const {
  return PhpParser::RuleNewExpr;
}

antlrcpp::Any PhpParser::NewExprContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitNewExpr(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::NewExprContext* PhpParser::newExpr() {
  NewExprContext *_localctx = _tracker.createInstance<NewExprContext>(_ctx, getState());
  enterRule(_localctx, 154, PhpParser::RuleNewExpr);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1179);
    match(PhpParser::New);
    setState(1180);
    typeRef();
    setState(1182);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 114, _ctx)) {
    case 1: {
      setState(1181);
      arguments();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- AssignmentOperatorContext ------------------------------------------------------------------

PhpParser::AssignmentOperatorContext::AssignmentOperatorContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::AssignmentOperatorContext::Eq() {
  return getToken(PhpParser::Eq, 0);
}


size_t PhpParser::AssignmentOperatorContext::getRuleIndex() const {
  return PhpParser::RuleAssignmentOperator;
}

antlrcpp::Any PhpParser::AssignmentOperatorContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitAssignmentOperator(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::AssignmentOperatorContext* PhpParser::assignmentOperator() {
  AssignmentOperatorContext *_localctx = _tracker.createInstance<AssignmentOperatorContext>(_ctx, getState());
  enterRule(_localctx, 156, PhpParser::RuleAssignmentOperator);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1184);
    _la = _input->LA(1);
    if (!(((((_la - 129) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 129)) & ((1ULL << (PhpParser::PlusEqual - 129))
      | (1ULL << (PhpParser::MinusEqual - 129))
      | (1ULL << (PhpParser::MulEqual - 129))
      | (1ULL << (PhpParser::PowEqual - 129))
      | (1ULL << (PhpParser::DivEqual - 129))
      | (1ULL << (PhpParser::Concaequal - 129))
      | (1ULL << (PhpParser::ModEqual - 129))
      | (1ULL << (PhpParser::ShiftLeftEqual - 129))
      | (1ULL << (PhpParser::ShiftRightEqual - 129))
      | (1ULL << (PhpParser::AndEqual - 129))
      | (1ULL << (PhpParser::OrEqual - 129))
      | (1ULL << (PhpParser::XorEqual - 129))
      | (1ULL << (PhpParser::Eq - 129)))) != 0))) {
    _errHandler->recoverInline(this);
    }
    else {
      _errHandler->reportMatch(this);
      consume();
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- YieldExpressionContext ------------------------------------------------------------------

PhpParser::YieldExpressionContext::YieldExpressionContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::YieldExpressionContext::Yield() {
  return getToken(PhpParser::Yield, 0);
}

std::vector<PhpParser::ExpressionContext *> PhpParser::YieldExpressionContext::expression() {
  return getRuleContexts<PhpParser::ExpressionContext>();
}

PhpParser::ExpressionContext* PhpParser::YieldExpressionContext::expression(size_t i) {
  return getRuleContext<PhpParser::ExpressionContext>(i);
}


size_t PhpParser::YieldExpressionContext::getRuleIndex() const {
  return PhpParser::RuleYieldExpression;
}

antlrcpp::Any PhpParser::YieldExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitYieldExpression(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::YieldExpressionContext* PhpParser::yieldExpression() {
  YieldExpressionContext *_localctx = _tracker.createInstance<YieldExpressionContext>(_ctx, getState());
  enterRule(_localctx, 158, PhpParser::RuleYieldExpression);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1186);
    match(PhpParser::Yield);
    setState(1187);
    expression(0);
    setState(1190);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::DoubleArrow) {
      setState(1188);
      match(PhpParser::DoubleArrow);
      setState(1189);
      expression(0);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ArrayItemListContext ------------------------------------------------------------------

PhpParser::ArrayItemListContext::ArrayItemListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::ArrayItemContext *> PhpParser::ArrayItemListContext::arrayItem() {
  return getRuleContexts<PhpParser::ArrayItemContext>();
}

PhpParser::ArrayItemContext* PhpParser::ArrayItemListContext::arrayItem(size_t i) {
  return getRuleContext<PhpParser::ArrayItemContext>(i);
}


size_t PhpParser::ArrayItemListContext::getRuleIndex() const {
  return PhpParser::RuleArrayItemList;
}

antlrcpp::Any PhpParser::ArrayItemListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitArrayItemList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ArrayItemListContext* PhpParser::arrayItemList() {
  ArrayItemListContext *_localctx = _tracker.createInstance<ArrayItemListContext>(_ctx, getState());
  enterRule(_localctx, 160, PhpParser::RuleArrayItemList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(1192);
    arrayItem();
    setState(1197);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 116, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(1193);
        match(PhpParser::Comma);
        setState(1194);
        arrayItem(); 
      }
      setState(1199);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 116, _ctx);
    }
    setState(1201);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::Comma) {
      setState(1200);
      match(PhpParser::Comma);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ArrayItemContext ------------------------------------------------------------------

PhpParser::ArrayItemContext::ArrayItemContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::ExpressionContext *> PhpParser::ArrayItemContext::expression() {
  return getRuleContexts<PhpParser::ExpressionContext>();
}

PhpParser::ExpressionContext* PhpParser::ArrayItemContext::expression(size_t i) {
  return getRuleContext<PhpParser::ExpressionContext>(i);
}

PhpParser::ChainContext* PhpParser::ArrayItemContext::chain() {
  return getRuleContext<PhpParser::ChainContext>(0);
}


size_t PhpParser::ArrayItemContext::getRuleIndex() const {
  return PhpParser::RuleArrayItem;
}

antlrcpp::Any PhpParser::ArrayItemContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitArrayItem(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ArrayItemContext* PhpParser::arrayItem() {
  ArrayItemContext *_localctx = _tracker.createInstance<ArrayItemContext>(_ctx, getState());
  enterRule(_localctx, 162, PhpParser::RuleArrayItem);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1215);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 120, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(1203);
      expression(0);
      setState(1206);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == PhpParser::DoubleArrow) {
        setState(1204);
        match(PhpParser::DoubleArrow);
        setState(1205);
        expression(0);
      }
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(1211);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
        | (1ULL << PhpParser::Array)
        | (1ULL << PhpParser::As)
        | (1ULL << PhpParser::BinaryCast)
        | (1ULL << PhpParser::BoolType)
        | (1ULL << PhpParser::BooleanConstant)
        | (1ULL << PhpParser::Break)
        | (1ULL << PhpParser::Callable)
        | (1ULL << PhpParser::Case)
        | (1ULL << PhpParser::Catch)
        | (1ULL << PhpParser::Class)
        | (1ULL << PhpParser::Clone)
        | (1ULL << PhpParser::Const)
        | (1ULL << PhpParser::Continue)
        | (1ULL << PhpParser::Declare)
        | (1ULL << PhpParser::Default)
        | (1ULL << PhpParser::Do)
        | (1ULL << PhpParser::DoubleCast)
        | (1ULL << PhpParser::DoubleType)
        | (1ULL << PhpParser::Echo)
        | (1ULL << PhpParser::Else)
        | (1ULL << PhpParser::ElseIf)
        | (1ULL << PhpParser::Empty)
        | (1ULL << PhpParser::EndDeclare)
        | (1ULL << PhpParser::EndFor)
        | (1ULL << PhpParser::EndForeach)
        | (1ULL << PhpParser::EndIf)
        | (1ULL << PhpParser::EndSwitch)
        | (1ULL << PhpParser::EndWhile)
        | (1ULL << PhpParser::Eval)
        | (1ULL << PhpParser::Exit)
        | (1ULL << PhpParser::Extends)
        | (1ULL << PhpParser::Final)
        | (1ULL << PhpParser::Finally)
        | (1ULL << PhpParser::FloatCast)
        | (1ULL << PhpParser::For)
        | (1ULL << PhpParser::Foreach)
        | (1ULL << PhpParser::Function)
        | (1ULL << PhpParser::Global)
        | (1ULL << PhpParser::Goto)
        | (1ULL << PhpParser::If)
        | (1ULL << PhpParser::Implements)
        | (1ULL << PhpParser::Import)
        | (1ULL << PhpParser::Include)
        | (1ULL << PhpParser::IncludeOnce)
        | (1ULL << PhpParser::InstanceOf)
        | (1ULL << PhpParser::InsteadOf)
        | (1ULL << PhpParser::Int8Cast)
        | (1ULL << PhpParser::Int16Cast)
        | (1ULL << PhpParser::Int64Type)
        | (1ULL << PhpParser::IntType)
        | (1ULL << PhpParser::Interface)
        | (1ULL << PhpParser::IsSet)
        | (1ULL << PhpParser::List)
        | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
        | (1ULL << (PhpParser::LogicalXor - 64))
        | (1ULL << (PhpParser::Namespace - 64))
        | (1ULL << (PhpParser::New - 64))
        | (1ULL << (PhpParser::Null - 64))
        | (1ULL << (PhpParser::ObjectType - 64))
        | (1ULL << (PhpParser::Parent_ - 64))
        | (1ULL << (PhpParser::Partial - 64))
        | (1ULL << (PhpParser::Print - 64))
        | (1ULL << (PhpParser::Private - 64))
        | (1ULL << (PhpParser::Protected - 64))
        | (1ULL << (PhpParser::Public - 64))
        | (1ULL << (PhpParser::Require - 64))
        | (1ULL << (PhpParser::RequireOnce - 64))
        | (1ULL << (PhpParser::Resource - 64))
        | (1ULL << (PhpParser::Return - 64))
        | (1ULL << (PhpParser::Static - 64))
        | (1ULL << (PhpParser::StringType - 64))
        | (1ULL << (PhpParser::Switch - 64))
        | (1ULL << (PhpParser::Throw - 64))
        | (1ULL << (PhpParser::Trait - 64))
        | (1ULL << (PhpParser::Try - 64))
        | (1ULL << (PhpParser::Typeof - 64))
        | (1ULL << (PhpParser::UintCast - 64))
        | (1ULL << (PhpParser::UnicodeCast - 64))
        | (1ULL << (PhpParser::Unset - 64))
        | (1ULL << (PhpParser::Use - 64))
        | (1ULL << (PhpParser::Var - 64))
        | (1ULL << (PhpParser::While - 64))
        | (1ULL << (PhpParser::Yield - 64))
        | (1ULL << (PhpParser::Get - 64))
        | (1ULL << (PhpParser::Set - 64))
        | (1ULL << (PhpParser::Call - 64))
        | (1ULL << (PhpParser::CallStatic - 64))
        | (1ULL << (PhpParser::Constructor - 64))
        | (1ULL << (PhpParser::Destruct - 64))
        | (1ULL << (PhpParser::Wakeup - 64))
        | (1ULL << (PhpParser::Sleep - 64))
        | (1ULL << (PhpParser::Autoload - 64))
        | (1ULL << (PhpParser::IsSet__ - 64))
        | (1ULL << (PhpParser::Unset__ - 64))
        | (1ULL << (PhpParser::ToString__ - 64))
        | (1ULL << (PhpParser::Invoke - 64))
        | (1ULL << (PhpParser::SetState - 64))
        | (1ULL << (PhpParser::Clone__ - 64))
        | (1ULL << (PhpParser::DebugInfo - 64))
        | (1ULL << (PhpParser::Namespace__ - 64))
        | (1ULL << (PhpParser::Class__ - 64))
        | (1ULL << (PhpParser::Traic__ - 64))
        | (1ULL << (PhpParser::Function__ - 64))
        | (1ULL << (PhpParser::Method__ - 64))
        | (1ULL << (PhpParser::Line__ - 64))
        | (1ULL << (PhpParser::File__ - 64))
        | (1ULL << (PhpParser::Dir__ - 64))
        | (1ULL << (PhpParser::Inc - 64))
        | (1ULL << (PhpParser::Dec - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
        | (1ULL << (PhpParser::Bang - 148))
        | (1ULL << (PhpParser::Plus - 148))
        | (1ULL << (PhpParser::Minus - 148))
        | (1ULL << (PhpParser::Tilde - 148))
        | (1ULL << (PhpParser::SuppressWarnings - 148))
        | (1ULL << (PhpParser::Dollar - 148))
        | (1ULL << (PhpParser::OpenRoundBracket - 148))
        | (1ULL << (PhpParser::OpenSquareBracket - 148))
        | (1ULL << (PhpParser::VarName - 148))
        | (1ULL << (PhpParser::Label - 148))
        | (1ULL << (PhpParser::Octal - 148))
        | (1ULL << (PhpParser::Decimal - 148))
        | (1ULL << (PhpParser::Real - 148))
        | (1ULL << (PhpParser::Hex - 148))
        | (1ULL << (PhpParser::Binary - 148))
        | (1ULL << (PhpParser::BackQuoteString - 148))
        | (1ULL << (PhpParser::SingleQuoteString - 148))
        | (1ULL << (PhpParser::DoubleQuote - 148))
        | (1ULL << (PhpParser::StartNowDoc - 148))
        | (1ULL << (PhpParser::StartHereDoc - 148)))) != 0)) {
        setState(1208);
        expression(0);
        setState(1209);
        match(PhpParser::DoubleArrow);
      }
      setState(1213);
      match(PhpParser::Ampersand);
      setState(1214);
      chain();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- LambdaFunctionUseVarsContext ------------------------------------------------------------------

PhpParser::LambdaFunctionUseVarsContext::LambdaFunctionUseVarsContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::LambdaFunctionUseVarsContext::Use() {
  return getToken(PhpParser::Use, 0);
}

std::vector<PhpParser::LambdaFunctionUseVarContext *> PhpParser::LambdaFunctionUseVarsContext::lambdaFunctionUseVar() {
  return getRuleContexts<PhpParser::LambdaFunctionUseVarContext>();
}

PhpParser::LambdaFunctionUseVarContext* PhpParser::LambdaFunctionUseVarsContext::lambdaFunctionUseVar(size_t i) {
  return getRuleContext<PhpParser::LambdaFunctionUseVarContext>(i);
}


size_t PhpParser::LambdaFunctionUseVarsContext::getRuleIndex() const {
  return PhpParser::RuleLambdaFunctionUseVars;
}

antlrcpp::Any PhpParser::LambdaFunctionUseVarsContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitLambdaFunctionUseVars(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::LambdaFunctionUseVarsContext* PhpParser::lambdaFunctionUseVars() {
  LambdaFunctionUseVarsContext *_localctx = _tracker.createInstance<LambdaFunctionUseVarsContext>(_ctx, getState());
  enterRule(_localctx, 164, PhpParser::RuleLambdaFunctionUseVars);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1217);
    match(PhpParser::Use);
    setState(1218);
    match(PhpParser::OpenRoundBracket);
    setState(1219);
    lambdaFunctionUseVar();
    setState(1224);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(1220);
      match(PhpParser::Comma);
      setState(1221);
      lambdaFunctionUseVar();
      setState(1226);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
    setState(1227);
    match(PhpParser::CloseRoundBracket);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- LambdaFunctionUseVarContext ------------------------------------------------------------------

PhpParser::LambdaFunctionUseVarContext::LambdaFunctionUseVarContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::LambdaFunctionUseVarContext::VarName() {
  return getToken(PhpParser::VarName, 0);
}


size_t PhpParser::LambdaFunctionUseVarContext::getRuleIndex() const {
  return PhpParser::RuleLambdaFunctionUseVar;
}

antlrcpp::Any PhpParser::LambdaFunctionUseVarContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitLambdaFunctionUseVar(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::LambdaFunctionUseVarContext* PhpParser::lambdaFunctionUseVar() {
  LambdaFunctionUseVarContext *_localctx = _tracker.createInstance<LambdaFunctionUseVarContext>(_ctx, getState());
  enterRule(_localctx, 166, PhpParser::RuleLambdaFunctionUseVar);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1230);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::Ampersand) {
      setState(1229);
      match(PhpParser::Ampersand);
    }
    setState(1232);
    match(PhpParser::VarName);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- QualifiedStaticTypeRefContext ------------------------------------------------------------------

PhpParser::QualifiedStaticTypeRefContext::QualifiedStaticTypeRefContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::QualifiedNamespaceNameContext* PhpParser::QualifiedStaticTypeRefContext::qualifiedNamespaceName() {
  return getRuleContext<PhpParser::QualifiedNamespaceNameContext>(0);
}

PhpParser::GenericDynamicArgsContext* PhpParser::QualifiedStaticTypeRefContext::genericDynamicArgs() {
  return getRuleContext<PhpParser::GenericDynamicArgsContext>(0);
}

tree::TerminalNode* PhpParser::QualifiedStaticTypeRefContext::Static() {
  return getToken(PhpParser::Static, 0);
}


size_t PhpParser::QualifiedStaticTypeRefContext::getRuleIndex() const {
  return PhpParser::RuleQualifiedStaticTypeRef;
}

antlrcpp::Any PhpParser::QualifiedStaticTypeRefContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitQualifiedStaticTypeRef(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::QualifiedStaticTypeRefContext* PhpParser::qualifiedStaticTypeRef() {
  QualifiedStaticTypeRefContext *_localctx = _tracker.createInstance<QualifiedStaticTypeRefContext>(_ctx, getState());
  enterRule(_localctx, 168, PhpParser::RuleQualifiedStaticTypeRef);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1239);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 124, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(1234);
      qualifiedNamespaceName();
      setState(1236);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == PhpParser::Lgeneric) {
        setState(1235);
        genericDynamicArgs();
      }
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(1238);
      match(PhpParser::Static);
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TypeRefContext ------------------------------------------------------------------

PhpParser::TypeRefContext::TypeRefContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::QualifiedNamespaceNameContext* PhpParser::TypeRefContext::qualifiedNamespaceName() {
  return getRuleContext<PhpParser::QualifiedNamespaceNameContext>(0);
}

PhpParser::IndirectTypeRefContext* PhpParser::TypeRefContext::indirectTypeRef() {
  return getRuleContext<PhpParser::IndirectTypeRefContext>(0);
}

PhpParser::GenericDynamicArgsContext* PhpParser::TypeRefContext::genericDynamicArgs() {
  return getRuleContext<PhpParser::GenericDynamicArgsContext>(0);
}

PhpParser::PrimitiveTypeContext* PhpParser::TypeRefContext::primitiveType() {
  return getRuleContext<PhpParser::PrimitiveTypeContext>(0);
}

tree::TerminalNode* PhpParser::TypeRefContext::Static() {
  return getToken(PhpParser::Static, 0);
}


size_t PhpParser::TypeRefContext::getRuleIndex() const {
  return PhpParser::RuleTypeRef;
}

antlrcpp::Any PhpParser::TypeRefContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitTypeRef(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::TypeRefContext* PhpParser::typeRef() {
  TypeRefContext *_localctx = _tracker.createInstance<TypeRefContext>(_ctx, getState());
  enterRule(_localctx, 170, PhpParser::RuleTypeRef);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1250);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 127, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(1243);
      _errHandler->sync(this);
      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 125, _ctx)) {
      case 1: {
        setState(1241);
        qualifiedNamespaceName();
        break;
      }

      case 2: {
        setState(1242);
        indirectTypeRef();
        break;
      }

      }
      setState(1246);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 126, _ctx)) {
      case 1: {
        setState(1245);
        genericDynamicArgs();
        break;
      }

      }
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(1248);
      primitiveType();
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(1249);
      match(PhpParser::Static);
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- IndirectTypeRefContext ------------------------------------------------------------------

PhpParser::IndirectTypeRefContext::IndirectTypeRefContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::ChainBaseContext* PhpParser::IndirectTypeRefContext::chainBase() {
  return getRuleContext<PhpParser::ChainBaseContext>(0);
}

std::vector<PhpParser::KeyedFieldNameContext *> PhpParser::IndirectTypeRefContext::keyedFieldName() {
  return getRuleContexts<PhpParser::KeyedFieldNameContext>();
}

PhpParser::KeyedFieldNameContext* PhpParser::IndirectTypeRefContext::keyedFieldName(size_t i) {
  return getRuleContext<PhpParser::KeyedFieldNameContext>(i);
}


size_t PhpParser::IndirectTypeRefContext::getRuleIndex() const {
  return PhpParser::RuleIndirectTypeRef;
}

antlrcpp::Any PhpParser::IndirectTypeRefContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitIndirectTypeRef(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::IndirectTypeRefContext* PhpParser::indirectTypeRef() {
  IndirectTypeRefContext *_localctx = _tracker.createInstance<IndirectTypeRefContext>(_ctx, getState());
  enterRule(_localctx, 172, PhpParser::RuleIndirectTypeRef);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(1252);
    chainBase();
    setState(1257);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 128, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(1253);
        match(PhpParser::ObjectOperator);
        setState(1254);
        keyedFieldName(); 
      }
      setState(1259);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 128, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- QualifiedNamespaceNameContext ------------------------------------------------------------------

PhpParser::QualifiedNamespaceNameContext::QualifiedNamespaceNameContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::NamespaceNameListContext* PhpParser::QualifiedNamespaceNameContext::namespaceNameList() {
  return getRuleContext<PhpParser::NamespaceNameListContext>(0);
}

tree::TerminalNode* PhpParser::QualifiedNamespaceNameContext::Namespace() {
  return getToken(PhpParser::Namespace, 0);
}


size_t PhpParser::QualifiedNamespaceNameContext::getRuleIndex() const {
  return PhpParser::RuleQualifiedNamespaceName;
}

antlrcpp::Any PhpParser::QualifiedNamespaceNameContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitQualifiedNamespaceName(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::QualifiedNamespaceNameContext* PhpParser::qualifiedNamespaceName() {
  QualifiedNamespaceNameContext *_localctx = _tracker.createInstance<QualifiedNamespaceNameContext>(_ctx, getState());
  enterRule(_localctx, 174, PhpParser::RuleQualifiedNamespaceName);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1261);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 129, _ctx)) {
    case 1: {
      setState(1260);
      match(PhpParser::Namespace);
      break;
    }

    }
    setState(1264);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::NamespaceSeparator) {
      setState(1263);
      match(PhpParser::NamespaceSeparator);
    }
    setState(1266);
    namespaceNameList();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- NamespaceNameListContext ------------------------------------------------------------------

PhpParser::NamespaceNameListContext::NamespaceNameListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::IdentifierContext *> PhpParser::NamespaceNameListContext::identifier() {
  return getRuleContexts<PhpParser::IdentifierContext>();
}

PhpParser::IdentifierContext* PhpParser::NamespaceNameListContext::identifier(size_t i) {
  return getRuleContext<PhpParser::IdentifierContext>(i);
}


size_t PhpParser::NamespaceNameListContext::getRuleIndex() const {
  return PhpParser::RuleNamespaceNameList;
}

antlrcpp::Any PhpParser::NamespaceNameListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitNamespaceNameList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::NamespaceNameListContext* PhpParser::namespaceNameList() {
  NamespaceNameListContext *_localctx = _tracker.createInstance<NamespaceNameListContext>(_ctx, getState());
  enterRule(_localctx, 176, PhpParser::RuleNamespaceNameList);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(1268);
    identifier();
    setState(1273);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 131, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(1269);
        match(PhpParser::NamespaceSeparator);
        setState(1270);
        identifier(); 
      }
      setState(1275);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 131, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- QualifiedNamespaceNameListContext ------------------------------------------------------------------

PhpParser::QualifiedNamespaceNameListContext::QualifiedNamespaceNameListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::QualifiedNamespaceNameContext *> PhpParser::QualifiedNamespaceNameListContext::qualifiedNamespaceName() {
  return getRuleContexts<PhpParser::QualifiedNamespaceNameContext>();
}

PhpParser::QualifiedNamespaceNameContext* PhpParser::QualifiedNamespaceNameListContext::qualifiedNamespaceName(size_t i) {
  return getRuleContext<PhpParser::QualifiedNamespaceNameContext>(i);
}


size_t PhpParser::QualifiedNamespaceNameListContext::getRuleIndex() const {
  return PhpParser::RuleQualifiedNamespaceNameList;
}

antlrcpp::Any PhpParser::QualifiedNamespaceNameListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitQualifiedNamespaceNameList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::QualifiedNamespaceNameListContext* PhpParser::qualifiedNamespaceNameList() {
  QualifiedNamespaceNameListContext *_localctx = _tracker.createInstance<QualifiedNamespaceNameListContext>(_ctx, getState());
  enterRule(_localctx, 178, PhpParser::RuleQualifiedNamespaceNameList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1276);
    qualifiedNamespaceName();
    setState(1281);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(1277);
      match(PhpParser::Comma);
      setState(1278);
      qualifiedNamespaceName();
      setState(1283);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ArgumentsContext ------------------------------------------------------------------

PhpParser::ArgumentsContext::ArgumentsContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::ActualArgumentContext *> PhpParser::ArgumentsContext::actualArgument() {
  return getRuleContexts<PhpParser::ActualArgumentContext>();
}

PhpParser::ActualArgumentContext* PhpParser::ArgumentsContext::actualArgument(size_t i) {
  return getRuleContext<PhpParser::ActualArgumentContext>(i);
}

PhpParser::YieldExpressionContext* PhpParser::ArgumentsContext::yieldExpression() {
  return getRuleContext<PhpParser::YieldExpressionContext>(0);
}


size_t PhpParser::ArgumentsContext::getRuleIndex() const {
  return PhpParser::RuleArguments;
}

antlrcpp::Any PhpParser::ArgumentsContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitArguments(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ArgumentsContext* PhpParser::arguments() {
  ArgumentsContext *_localctx = _tracker.createInstance<ArgumentsContext>(_ctx, getState());
  enterRule(_localctx, 180, PhpParser::RuleArguments);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1284);
    match(PhpParser::OpenRoundBracket);
    setState(1294);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 134, _ctx)) {
    case 1: {
      setState(1285);
      actualArgument();
      setState(1290);
      _errHandler->sync(this);
      _la = _input->LA(1);
      while (_la == PhpParser::Comma) {
        setState(1286);
        match(PhpParser::Comma);
        setState(1287);
        actualArgument();
        setState(1292);
        _errHandler->sync(this);
        _la = _input->LA(1);
      }
      break;
    }

    case 2: {
      setState(1293);
      yieldExpression();
      break;
    }

    }
    setState(1296);
    match(PhpParser::CloseRoundBracket);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ActualArgumentContext ------------------------------------------------------------------

PhpParser::ActualArgumentContext::ActualArgumentContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::ExpressionContext* PhpParser::ActualArgumentContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}

PhpParser::ChainContext* PhpParser::ActualArgumentContext::chain() {
  return getRuleContext<PhpParser::ChainContext>(0);
}


size_t PhpParser::ActualArgumentContext::getRuleIndex() const {
  return PhpParser::RuleActualArgument;
}

antlrcpp::Any PhpParser::ActualArgumentContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitActualArgument(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ActualArgumentContext* PhpParser::actualArgument() {
  ActualArgumentContext *_localctx = _tracker.createInstance<ActualArgumentContext>(_ctx, getState());
  enterRule(_localctx, 182, PhpParser::RuleActualArgument);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1304);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::Abstract:
      case PhpParser::Array:
      case PhpParser::As:
      case PhpParser::BinaryCast:
      case PhpParser::BoolType:
      case PhpParser::BooleanConstant:
      case PhpParser::Break:
      case PhpParser::Callable:
      case PhpParser::Case:
      case PhpParser::Catch:
      case PhpParser::Class:
      case PhpParser::Clone:
      case PhpParser::Const:
      case PhpParser::Continue:
      case PhpParser::Declare:
      case PhpParser::Default:
      case PhpParser::Do:
      case PhpParser::DoubleCast:
      case PhpParser::DoubleType:
      case PhpParser::Echo:
      case PhpParser::Else:
      case PhpParser::ElseIf:
      case PhpParser::Empty:
      case PhpParser::EndDeclare:
      case PhpParser::EndFor:
      case PhpParser::EndForeach:
      case PhpParser::EndIf:
      case PhpParser::EndSwitch:
      case PhpParser::EndWhile:
      case PhpParser::Eval:
      case PhpParser::Exit:
      case PhpParser::Extends:
      case PhpParser::Final:
      case PhpParser::Finally:
      case PhpParser::FloatCast:
      case PhpParser::For:
      case PhpParser::Foreach:
      case PhpParser::Function:
      case PhpParser::Global:
      case PhpParser::Goto:
      case PhpParser::If:
      case PhpParser::Implements:
      case PhpParser::Import:
      case PhpParser::Include:
      case PhpParser::IncludeOnce:
      case PhpParser::InstanceOf:
      case PhpParser::InsteadOf:
      case PhpParser::Int8Cast:
      case PhpParser::Int16Cast:
      case PhpParser::Int64Type:
      case PhpParser::IntType:
      case PhpParser::Interface:
      case PhpParser::IsSet:
      case PhpParser::List:
      case PhpParser::LogicalAnd:
      case PhpParser::LogicalOr:
      case PhpParser::LogicalXor:
      case PhpParser::Namespace:
      case PhpParser::New:
      case PhpParser::Null:
      case PhpParser::ObjectType:
      case PhpParser::Parent_:
      case PhpParser::Partial:
      case PhpParser::Print:
      case PhpParser::Private:
      case PhpParser::Protected:
      case PhpParser::Public:
      case PhpParser::Require:
      case PhpParser::RequireOnce:
      case PhpParser::Resource:
      case PhpParser::Return:
      case PhpParser::Static:
      case PhpParser::StringType:
      case PhpParser::Switch:
      case PhpParser::Throw:
      case PhpParser::Trait:
      case PhpParser::Try:
      case PhpParser::Typeof:
      case PhpParser::UintCast:
      case PhpParser::UnicodeCast:
      case PhpParser::Unset:
      case PhpParser::Use:
      case PhpParser::Var:
      case PhpParser::While:
      case PhpParser::Yield:
      case PhpParser::Get:
      case PhpParser::Set:
      case PhpParser::Call:
      case PhpParser::CallStatic:
      case PhpParser::Constructor:
      case PhpParser::Destruct:
      case PhpParser::Wakeup:
      case PhpParser::Sleep:
      case PhpParser::Autoload:
      case PhpParser::IsSet__:
      case PhpParser::Unset__:
      case PhpParser::ToString__:
      case PhpParser::Invoke:
      case PhpParser::SetState:
      case PhpParser::Clone__:
      case PhpParser::DebugInfo:
      case PhpParser::Namespace__:
      case PhpParser::Class__:
      case PhpParser::Traic__:
      case PhpParser::Function__:
      case PhpParser::Method__:
      case PhpParser::Line__:
      case PhpParser::File__:
      case PhpParser::Dir__:
      case PhpParser::Inc:
      case PhpParser::Dec:
      case PhpParser::NamespaceSeparator:
      case PhpParser::Ellipsis:
      case PhpParser::Bang:
      case PhpParser::Plus:
      case PhpParser::Minus:
      case PhpParser::Tilde:
      case PhpParser::SuppressWarnings:
      case PhpParser::Dollar:
      case PhpParser::OpenRoundBracket:
      case PhpParser::OpenSquareBracket:
      case PhpParser::VarName:
      case PhpParser::Label:
      case PhpParser::Octal:
      case PhpParser::Decimal:
      case PhpParser::Real:
      case PhpParser::Hex:
      case PhpParser::Binary:
      case PhpParser::BackQuoteString:
      case PhpParser::SingleQuoteString:
      case PhpParser::DoubleQuote:
      case PhpParser::StartNowDoc:
      case PhpParser::StartHereDoc: {
        enterOuterAlt(_localctx, 1);
        setState(1299);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == PhpParser::Ellipsis) {
          setState(1298);
          match(PhpParser::Ellipsis);
        }
        setState(1301);
        expression(0);
        break;
      }

      case PhpParser::Ampersand: {
        enterOuterAlt(_localctx, 2);
        setState(1302);
        match(PhpParser::Ampersand);
        setState(1303);
        chain();
        break;
      }

    default:
      throw NoViableAltException(this);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ConstantInititalizerContext ------------------------------------------------------------------

PhpParser::ConstantInititalizerContext::ConstantInititalizerContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::ConstantContext* PhpParser::ConstantInititalizerContext::constant() {
  return getRuleContext<PhpParser::ConstantContext>(0);
}

PhpParser::StringContext* PhpParser::ConstantInititalizerContext::string() {
  return getRuleContext<PhpParser::StringContext>(0);
}

tree::TerminalNode* PhpParser::ConstantInititalizerContext::Array() {
  return getToken(PhpParser::Array, 0);
}

PhpParser::ConstantArrayItemListContext* PhpParser::ConstantInititalizerContext::constantArrayItemList() {
  return getRuleContext<PhpParser::ConstantArrayItemListContext>(0);
}

PhpParser::ConstantInititalizerContext* PhpParser::ConstantInititalizerContext::constantInititalizer() {
  return getRuleContext<PhpParser::ConstantInititalizerContext>(0);
}


size_t PhpParser::ConstantInititalizerContext::getRuleIndex() const {
  return PhpParser::RuleConstantInititalizer;
}

antlrcpp::Any PhpParser::ConstantInititalizerContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitConstantInititalizer(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ConstantInititalizerContext* PhpParser::constantInititalizer() {
  ConstantInititalizerContext *_localctx = _tracker.createInstance<ConstantInititalizerContext>(_ctx, getState());
  enterRule(_localctx, 184, PhpParser::RuleConstantInititalizer);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1327);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 141, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(1306);
      constant();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(1307);
      string();
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(1308);
      match(PhpParser::Array);
      setState(1309);
      match(PhpParser::OpenRoundBracket);
      setState(1314);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
        | (1ULL << PhpParser::Array)
        | (1ULL << PhpParser::As)
        | (1ULL << PhpParser::BinaryCast)
        | (1ULL << PhpParser::BoolType)
        | (1ULL << PhpParser::BooleanConstant)
        | (1ULL << PhpParser::Break)
        | (1ULL << PhpParser::Callable)
        | (1ULL << PhpParser::Case)
        | (1ULL << PhpParser::Catch)
        | (1ULL << PhpParser::Class)
        | (1ULL << PhpParser::Clone)
        | (1ULL << PhpParser::Const)
        | (1ULL << PhpParser::Continue)
        | (1ULL << PhpParser::Declare)
        | (1ULL << PhpParser::Default)
        | (1ULL << PhpParser::Do)
        | (1ULL << PhpParser::DoubleCast)
        | (1ULL << PhpParser::DoubleType)
        | (1ULL << PhpParser::Echo)
        | (1ULL << PhpParser::Else)
        | (1ULL << PhpParser::ElseIf)
        | (1ULL << PhpParser::Empty)
        | (1ULL << PhpParser::EndDeclare)
        | (1ULL << PhpParser::EndFor)
        | (1ULL << PhpParser::EndForeach)
        | (1ULL << PhpParser::EndIf)
        | (1ULL << PhpParser::EndSwitch)
        | (1ULL << PhpParser::EndWhile)
        | (1ULL << PhpParser::Eval)
        | (1ULL << PhpParser::Exit)
        | (1ULL << PhpParser::Extends)
        | (1ULL << PhpParser::Final)
        | (1ULL << PhpParser::Finally)
        | (1ULL << PhpParser::FloatCast)
        | (1ULL << PhpParser::For)
        | (1ULL << PhpParser::Foreach)
        | (1ULL << PhpParser::Function)
        | (1ULL << PhpParser::Global)
        | (1ULL << PhpParser::Goto)
        | (1ULL << PhpParser::If)
        | (1ULL << PhpParser::Implements)
        | (1ULL << PhpParser::Import)
        | (1ULL << PhpParser::Include)
        | (1ULL << PhpParser::IncludeOnce)
        | (1ULL << PhpParser::InstanceOf)
        | (1ULL << PhpParser::InsteadOf)
        | (1ULL << PhpParser::Int8Cast)
        | (1ULL << PhpParser::Int16Cast)
        | (1ULL << PhpParser::Int64Type)
        | (1ULL << PhpParser::IntType)
        | (1ULL << PhpParser::Interface)
        | (1ULL << PhpParser::IsSet)
        | (1ULL << PhpParser::List)
        | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
        | (1ULL << (PhpParser::LogicalXor - 64))
        | (1ULL << (PhpParser::Namespace - 64))
        | (1ULL << (PhpParser::New - 64))
        | (1ULL << (PhpParser::Null - 64))
        | (1ULL << (PhpParser::ObjectType - 64))
        | (1ULL << (PhpParser::Parent_ - 64))
        | (1ULL << (PhpParser::Partial - 64))
        | (1ULL << (PhpParser::Print - 64))
        | (1ULL << (PhpParser::Private - 64))
        | (1ULL << (PhpParser::Protected - 64))
        | (1ULL << (PhpParser::Public - 64))
        | (1ULL << (PhpParser::Require - 64))
        | (1ULL << (PhpParser::RequireOnce - 64))
        | (1ULL << (PhpParser::Resource - 64))
        | (1ULL << (PhpParser::Return - 64))
        | (1ULL << (PhpParser::Static - 64))
        | (1ULL << (PhpParser::StringType - 64))
        | (1ULL << (PhpParser::Switch - 64))
        | (1ULL << (PhpParser::Throw - 64))
        | (1ULL << (PhpParser::Trait - 64))
        | (1ULL << (PhpParser::Try - 64))
        | (1ULL << (PhpParser::Typeof - 64))
        | (1ULL << (PhpParser::UintCast - 64))
        | (1ULL << (PhpParser::UnicodeCast - 64))
        | (1ULL << (PhpParser::Unset - 64))
        | (1ULL << (PhpParser::Use - 64))
        | (1ULL << (PhpParser::Var - 64))
        | (1ULL << (PhpParser::While - 64))
        | (1ULL << (PhpParser::Yield - 64))
        | (1ULL << (PhpParser::Get - 64))
        | (1ULL << (PhpParser::Set - 64))
        | (1ULL << (PhpParser::Call - 64))
        | (1ULL << (PhpParser::CallStatic - 64))
        | (1ULL << (PhpParser::Constructor - 64))
        | (1ULL << (PhpParser::Destruct - 64))
        | (1ULL << (PhpParser::Wakeup - 64))
        | (1ULL << (PhpParser::Sleep - 64))
        | (1ULL << (PhpParser::Autoload - 64))
        | (1ULL << (PhpParser::IsSet__ - 64))
        | (1ULL << (PhpParser::Unset__ - 64))
        | (1ULL << (PhpParser::ToString__ - 64))
        | (1ULL << (PhpParser::Invoke - 64))
        | (1ULL << (PhpParser::SetState - 64))
        | (1ULL << (PhpParser::Clone__ - 64))
        | (1ULL << (PhpParser::DebugInfo - 64))
        | (1ULL << (PhpParser::Namespace__ - 64))
        | (1ULL << (PhpParser::Class__ - 64))
        | (1ULL << (PhpParser::Traic__ - 64))
        | (1ULL << (PhpParser::Function__ - 64))
        | (1ULL << (PhpParser::Method__ - 64))
        | (1ULL << (PhpParser::Line__ - 64))
        | (1ULL << (PhpParser::File__ - 64))
        | (1ULL << (PhpParser::Dir__ - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
        | (1ULL << (PhpParser::Plus - 148))
        | (1ULL << (PhpParser::Minus - 148))
        | (1ULL << (PhpParser::Dollar - 148))
        | (1ULL << (PhpParser::OpenSquareBracket - 148))
        | (1ULL << (PhpParser::VarName - 148))
        | (1ULL << (PhpParser::Label - 148))
        | (1ULL << (PhpParser::Octal - 148))
        | (1ULL << (PhpParser::Decimal - 148))
        | (1ULL << (PhpParser::Real - 148))
        | (1ULL << (PhpParser::Hex - 148))
        | (1ULL << (PhpParser::Binary - 148))
        | (1ULL << (PhpParser::SingleQuoteString - 148))
        | (1ULL << (PhpParser::DoubleQuote - 148))
        | (1ULL << (PhpParser::StartNowDoc - 148))
        | (1ULL << (PhpParser::StartHereDoc - 148)))) != 0)) {
        setState(1310);
        constantArrayItemList();
        setState(1312);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == PhpParser::Comma) {
          setState(1311);
          match(PhpParser::Comma);
        }
      }
      setState(1316);
      match(PhpParser::CloseRoundBracket);
      break;
    }

    case 4: {
      enterOuterAlt(_localctx, 4);
      setState(1317);
      match(PhpParser::OpenSquareBracket);
      setState(1322);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
        | (1ULL << PhpParser::Array)
        | (1ULL << PhpParser::As)
        | (1ULL << PhpParser::BinaryCast)
        | (1ULL << PhpParser::BoolType)
        | (1ULL << PhpParser::BooleanConstant)
        | (1ULL << PhpParser::Break)
        | (1ULL << PhpParser::Callable)
        | (1ULL << PhpParser::Case)
        | (1ULL << PhpParser::Catch)
        | (1ULL << PhpParser::Class)
        | (1ULL << PhpParser::Clone)
        | (1ULL << PhpParser::Const)
        | (1ULL << PhpParser::Continue)
        | (1ULL << PhpParser::Declare)
        | (1ULL << PhpParser::Default)
        | (1ULL << PhpParser::Do)
        | (1ULL << PhpParser::DoubleCast)
        | (1ULL << PhpParser::DoubleType)
        | (1ULL << PhpParser::Echo)
        | (1ULL << PhpParser::Else)
        | (1ULL << PhpParser::ElseIf)
        | (1ULL << PhpParser::Empty)
        | (1ULL << PhpParser::EndDeclare)
        | (1ULL << PhpParser::EndFor)
        | (1ULL << PhpParser::EndForeach)
        | (1ULL << PhpParser::EndIf)
        | (1ULL << PhpParser::EndSwitch)
        | (1ULL << PhpParser::EndWhile)
        | (1ULL << PhpParser::Eval)
        | (1ULL << PhpParser::Exit)
        | (1ULL << PhpParser::Extends)
        | (1ULL << PhpParser::Final)
        | (1ULL << PhpParser::Finally)
        | (1ULL << PhpParser::FloatCast)
        | (1ULL << PhpParser::For)
        | (1ULL << PhpParser::Foreach)
        | (1ULL << PhpParser::Function)
        | (1ULL << PhpParser::Global)
        | (1ULL << PhpParser::Goto)
        | (1ULL << PhpParser::If)
        | (1ULL << PhpParser::Implements)
        | (1ULL << PhpParser::Import)
        | (1ULL << PhpParser::Include)
        | (1ULL << PhpParser::IncludeOnce)
        | (1ULL << PhpParser::InstanceOf)
        | (1ULL << PhpParser::InsteadOf)
        | (1ULL << PhpParser::Int8Cast)
        | (1ULL << PhpParser::Int16Cast)
        | (1ULL << PhpParser::Int64Type)
        | (1ULL << PhpParser::IntType)
        | (1ULL << PhpParser::Interface)
        | (1ULL << PhpParser::IsSet)
        | (1ULL << PhpParser::List)
        | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
        | (1ULL << (PhpParser::LogicalXor - 64))
        | (1ULL << (PhpParser::Namespace - 64))
        | (1ULL << (PhpParser::New - 64))
        | (1ULL << (PhpParser::Null - 64))
        | (1ULL << (PhpParser::ObjectType - 64))
        | (1ULL << (PhpParser::Parent_ - 64))
        | (1ULL << (PhpParser::Partial - 64))
        | (1ULL << (PhpParser::Print - 64))
        | (1ULL << (PhpParser::Private - 64))
        | (1ULL << (PhpParser::Protected - 64))
        | (1ULL << (PhpParser::Public - 64))
        | (1ULL << (PhpParser::Require - 64))
        | (1ULL << (PhpParser::RequireOnce - 64))
        | (1ULL << (PhpParser::Resource - 64))
        | (1ULL << (PhpParser::Return - 64))
        | (1ULL << (PhpParser::Static - 64))
        | (1ULL << (PhpParser::StringType - 64))
        | (1ULL << (PhpParser::Switch - 64))
        | (1ULL << (PhpParser::Throw - 64))
        | (1ULL << (PhpParser::Trait - 64))
        | (1ULL << (PhpParser::Try - 64))
        | (1ULL << (PhpParser::Typeof - 64))
        | (1ULL << (PhpParser::UintCast - 64))
        | (1ULL << (PhpParser::UnicodeCast - 64))
        | (1ULL << (PhpParser::Unset - 64))
        | (1ULL << (PhpParser::Use - 64))
        | (1ULL << (PhpParser::Var - 64))
        | (1ULL << (PhpParser::While - 64))
        | (1ULL << (PhpParser::Yield - 64))
        | (1ULL << (PhpParser::Get - 64))
        | (1ULL << (PhpParser::Set - 64))
        | (1ULL << (PhpParser::Call - 64))
        | (1ULL << (PhpParser::CallStatic - 64))
        | (1ULL << (PhpParser::Constructor - 64))
        | (1ULL << (PhpParser::Destruct - 64))
        | (1ULL << (PhpParser::Wakeup - 64))
        | (1ULL << (PhpParser::Sleep - 64))
        | (1ULL << (PhpParser::Autoload - 64))
        | (1ULL << (PhpParser::IsSet__ - 64))
        | (1ULL << (PhpParser::Unset__ - 64))
        | (1ULL << (PhpParser::ToString__ - 64))
        | (1ULL << (PhpParser::Invoke - 64))
        | (1ULL << (PhpParser::SetState - 64))
        | (1ULL << (PhpParser::Clone__ - 64))
        | (1ULL << (PhpParser::DebugInfo - 64))
        | (1ULL << (PhpParser::Namespace__ - 64))
        | (1ULL << (PhpParser::Class__ - 64))
        | (1ULL << (PhpParser::Traic__ - 64))
        | (1ULL << (PhpParser::Function__ - 64))
        | (1ULL << (PhpParser::Method__ - 64))
        | (1ULL << (PhpParser::Line__ - 64))
        | (1ULL << (PhpParser::File__ - 64))
        | (1ULL << (PhpParser::Dir__ - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
        | (1ULL << (PhpParser::Plus - 148))
        | (1ULL << (PhpParser::Minus - 148))
        | (1ULL << (PhpParser::Dollar - 148))
        | (1ULL << (PhpParser::OpenSquareBracket - 148))
        | (1ULL << (PhpParser::VarName - 148))
        | (1ULL << (PhpParser::Label - 148))
        | (1ULL << (PhpParser::Octal - 148))
        | (1ULL << (PhpParser::Decimal - 148))
        | (1ULL << (PhpParser::Real - 148))
        | (1ULL << (PhpParser::Hex - 148))
        | (1ULL << (PhpParser::Binary - 148))
        | (1ULL << (PhpParser::SingleQuoteString - 148))
        | (1ULL << (PhpParser::DoubleQuote - 148))
        | (1ULL << (PhpParser::StartNowDoc - 148))
        | (1ULL << (PhpParser::StartHereDoc - 148)))) != 0)) {
        setState(1318);
        constantArrayItemList();
        setState(1320);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == PhpParser::Comma) {
          setState(1319);
          match(PhpParser::Comma);
        }
      }
      setState(1324);
      match(PhpParser::CloseSquareBracket);
      break;
    }

    case 5: {
      enterOuterAlt(_localctx, 5);
      setState(1325);
      _la = _input->LA(1);
      if (!(_la == PhpParser::Plus

      || _la == PhpParser::Minus)) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      setState(1326);
      constantInititalizer();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ConstantArrayItemListContext ------------------------------------------------------------------

PhpParser::ConstantArrayItemListContext::ConstantArrayItemListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::ConstantArrayItemContext *> PhpParser::ConstantArrayItemListContext::constantArrayItem() {
  return getRuleContexts<PhpParser::ConstantArrayItemContext>();
}

PhpParser::ConstantArrayItemContext* PhpParser::ConstantArrayItemListContext::constantArrayItem(size_t i) {
  return getRuleContext<PhpParser::ConstantArrayItemContext>(i);
}


size_t PhpParser::ConstantArrayItemListContext::getRuleIndex() const {
  return PhpParser::RuleConstantArrayItemList;
}

antlrcpp::Any PhpParser::ConstantArrayItemListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitConstantArrayItemList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ConstantArrayItemListContext* PhpParser::constantArrayItemList() {
  ConstantArrayItemListContext *_localctx = _tracker.createInstance<ConstantArrayItemListContext>(_ctx, getState());
  enterRule(_localctx, 186, PhpParser::RuleConstantArrayItemList);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(1329);
    constantArrayItem();
    setState(1334);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 142, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(1330);
        match(PhpParser::Comma);
        setState(1331);
        constantArrayItem(); 
      }
      setState(1336);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 142, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ConstantArrayItemContext ------------------------------------------------------------------

PhpParser::ConstantArrayItemContext::ConstantArrayItemContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::ConstantInititalizerContext *> PhpParser::ConstantArrayItemContext::constantInititalizer() {
  return getRuleContexts<PhpParser::ConstantInititalizerContext>();
}

PhpParser::ConstantInititalizerContext* PhpParser::ConstantArrayItemContext::constantInititalizer(size_t i) {
  return getRuleContext<PhpParser::ConstantInititalizerContext>(i);
}


size_t PhpParser::ConstantArrayItemContext::getRuleIndex() const {
  return PhpParser::RuleConstantArrayItem;
}

antlrcpp::Any PhpParser::ConstantArrayItemContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitConstantArrayItem(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ConstantArrayItemContext* PhpParser::constantArrayItem() {
  ConstantArrayItemContext *_localctx = _tracker.createInstance<ConstantArrayItemContext>(_ctx, getState());
  enterRule(_localctx, 188, PhpParser::RuleConstantArrayItem);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1337);
    constantInititalizer();
    setState(1340);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::DoubleArrow) {
      setState(1338);
      match(PhpParser::DoubleArrow);
      setState(1339);
      constantInititalizer();
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ConstantContext ------------------------------------------------------------------

PhpParser::ConstantContext::ConstantContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::ConstantContext::Null() {
  return getToken(PhpParser::Null, 0);
}

PhpParser::LiteralConstantContext* PhpParser::ConstantContext::literalConstant() {
  return getRuleContext<PhpParser::LiteralConstantContext>(0);
}

PhpParser::MagicConstantContext* PhpParser::ConstantContext::magicConstant() {
  return getRuleContext<PhpParser::MagicConstantContext>(0);
}

PhpParser::ClassConstantContext* PhpParser::ConstantContext::classConstant() {
  return getRuleContext<PhpParser::ClassConstantContext>(0);
}

PhpParser::QualifiedNamespaceNameContext* PhpParser::ConstantContext::qualifiedNamespaceName() {
  return getRuleContext<PhpParser::QualifiedNamespaceNameContext>(0);
}


size_t PhpParser::ConstantContext::getRuleIndex() const {
  return PhpParser::RuleConstant;
}

antlrcpp::Any PhpParser::ConstantContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitConstant(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ConstantContext* PhpParser::constant() {
  ConstantContext *_localctx = _tracker.createInstance<ConstantContext>(_ctx, getState());
  enterRule(_localctx, 190, PhpParser::RuleConstant);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1347);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 144, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(1342);
      match(PhpParser::Null);
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(1343);
      literalConstant();
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(1344);
      magicConstant();
      break;
    }

    case 4: {
      enterOuterAlt(_localctx, 4);
      setState(1345);
      classConstant();
      break;
    }

    case 5: {
      enterOuterAlt(_localctx, 5);
      setState(1346);
      qualifiedNamespaceName();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- LiteralConstantContext ------------------------------------------------------------------

PhpParser::LiteralConstantContext::LiteralConstantContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::LiteralConstantContext::Real() {
  return getToken(PhpParser::Real, 0);
}

tree::TerminalNode* PhpParser::LiteralConstantContext::BooleanConstant() {
  return getToken(PhpParser::BooleanConstant, 0);
}

PhpParser::NumericConstantContext* PhpParser::LiteralConstantContext::numericConstant() {
  return getRuleContext<PhpParser::NumericConstantContext>(0);
}

PhpParser::StringConstantContext* PhpParser::LiteralConstantContext::stringConstant() {
  return getRuleContext<PhpParser::StringConstantContext>(0);
}


size_t PhpParser::LiteralConstantContext::getRuleIndex() const {
  return PhpParser::RuleLiteralConstant;
}

antlrcpp::Any PhpParser::LiteralConstantContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitLiteralConstant(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::LiteralConstantContext* PhpParser::literalConstant() {
  LiteralConstantContext *_localctx = _tracker.createInstance<LiteralConstantContext>(_ctx, getState());
  enterRule(_localctx, 192, PhpParser::RuleLiteralConstant);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1353);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::Real: {
        enterOuterAlt(_localctx, 1);
        setState(1349);
        match(PhpParser::Real);
        break;
      }

      case PhpParser::BooleanConstant: {
        enterOuterAlt(_localctx, 2);
        setState(1350);
        match(PhpParser::BooleanConstant);
        break;
      }

      case PhpParser::Octal:
      case PhpParser::Decimal:
      case PhpParser::Hex:
      case PhpParser::Binary: {
        enterOuterAlt(_localctx, 3);
        setState(1351);
        numericConstant();
        break;
      }

      case PhpParser::Label: {
        enterOuterAlt(_localctx, 4);
        setState(1352);
        stringConstant();
        break;
      }

    default:
      throw NoViableAltException(this);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- NumericConstantContext ------------------------------------------------------------------

PhpParser::NumericConstantContext::NumericConstantContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::NumericConstantContext::Octal() {
  return getToken(PhpParser::Octal, 0);
}

tree::TerminalNode* PhpParser::NumericConstantContext::Decimal() {
  return getToken(PhpParser::Decimal, 0);
}

tree::TerminalNode* PhpParser::NumericConstantContext::Hex() {
  return getToken(PhpParser::Hex, 0);
}

tree::TerminalNode* PhpParser::NumericConstantContext::Binary() {
  return getToken(PhpParser::Binary, 0);
}


size_t PhpParser::NumericConstantContext::getRuleIndex() const {
  return PhpParser::RuleNumericConstant;
}

antlrcpp::Any PhpParser::NumericConstantContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitNumericConstant(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::NumericConstantContext* PhpParser::numericConstant() {
  NumericConstantContext *_localctx = _tracker.createInstance<NumericConstantContext>(_ctx, getState());
  enterRule(_localctx, 194, PhpParser::RuleNumericConstant);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1355);
    _la = _input->LA(1);
    if (!(((((_la - 180) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 180)) & ((1ULL << (PhpParser::Octal - 180))
      | (1ULL << (PhpParser::Decimal - 180))
      | (1ULL << (PhpParser::Hex - 180))
      | (1ULL << (PhpParser::Binary - 180)))) != 0))) {
    _errHandler->recoverInline(this);
    }
    else {
      _errHandler->reportMatch(this);
      consume();
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ClassConstantContext ------------------------------------------------------------------

PhpParser::ClassConstantContext::ClassConstantContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::ClassConstantContext::Class() {
  return getToken(PhpParser::Class, 0);
}

tree::TerminalNode* PhpParser::ClassConstantContext::Parent_() {
  return getToken(PhpParser::Parent_, 0);
}

PhpParser::IdentifierContext* PhpParser::ClassConstantContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}

tree::TerminalNode* PhpParser::ClassConstantContext::Constructor() {
  return getToken(PhpParser::Constructor, 0);
}

tree::TerminalNode* PhpParser::ClassConstantContext::Get() {
  return getToken(PhpParser::Get, 0);
}

tree::TerminalNode* PhpParser::ClassConstantContext::Set() {
  return getToken(PhpParser::Set, 0);
}

PhpParser::QualifiedStaticTypeRefContext* PhpParser::ClassConstantContext::qualifiedStaticTypeRef() {
  return getRuleContext<PhpParser::QualifiedStaticTypeRefContext>(0);
}

PhpParser::KeyedVariableContext* PhpParser::ClassConstantContext::keyedVariable() {
  return getRuleContext<PhpParser::KeyedVariableContext>(0);
}


size_t PhpParser::ClassConstantContext::getRuleIndex() const {
  return PhpParser::RuleClassConstant;
}

antlrcpp::Any PhpParser::ClassConstantContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitClassConstant(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ClassConstantContext* PhpParser::classConstant() {
  ClassConstantContext *_localctx = _tracker.createInstance<ClassConstantContext>(_ctx, getState());
  enterRule(_localctx, 196, PhpParser::RuleClassConstant);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1372);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 148, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(1357);
      _la = _input->LA(1);
      if (!(_la == PhpParser::Class

      || _la == PhpParser::Parent_)) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      setState(1358);
      match(PhpParser::DoubleColon);
      setState(1363);
      _errHandler->sync(this);
      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 146, _ctx)) {
      case 1: {
        setState(1359);
        identifier();
        break;
      }

      case 2: {
        setState(1360);
        match(PhpParser::Constructor);
        break;
      }

      case 3: {
        setState(1361);
        match(PhpParser::Get);
        break;
      }

      case 4: {
        setState(1362);
        match(PhpParser::Set);
        break;
      }

      }
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(1367);
      _errHandler->sync(this);
      switch (_input->LA(1)) {
        case PhpParser::Abstract:
        case PhpParser::Array:
        case PhpParser::As:
        case PhpParser::BinaryCast:
        case PhpParser::BoolType:
        case PhpParser::BooleanConstant:
        case PhpParser::Break:
        case PhpParser::Callable:
        case PhpParser::Case:
        case PhpParser::Catch:
        case PhpParser::Class:
        case PhpParser::Clone:
        case PhpParser::Const:
        case PhpParser::Continue:
        case PhpParser::Declare:
        case PhpParser::Default:
        case PhpParser::Do:
        case PhpParser::DoubleCast:
        case PhpParser::DoubleType:
        case PhpParser::Echo:
        case PhpParser::Else:
        case PhpParser::ElseIf:
        case PhpParser::Empty:
        case PhpParser::EndDeclare:
        case PhpParser::EndFor:
        case PhpParser::EndForeach:
        case PhpParser::EndIf:
        case PhpParser::EndSwitch:
        case PhpParser::EndWhile:
        case PhpParser::Eval:
        case PhpParser::Exit:
        case PhpParser::Extends:
        case PhpParser::Final:
        case PhpParser::Finally:
        case PhpParser::FloatCast:
        case PhpParser::For:
        case PhpParser::Foreach:
        case PhpParser::Function:
        case PhpParser::Global:
        case PhpParser::Goto:
        case PhpParser::If:
        case PhpParser::Implements:
        case PhpParser::Import:
        case PhpParser::Include:
        case PhpParser::IncludeOnce:
        case PhpParser::InstanceOf:
        case PhpParser::InsteadOf:
        case PhpParser::Int8Cast:
        case PhpParser::Int16Cast:
        case PhpParser::Int64Type:
        case PhpParser::IntType:
        case PhpParser::Interface:
        case PhpParser::IsSet:
        case PhpParser::List:
        case PhpParser::LogicalAnd:
        case PhpParser::LogicalOr:
        case PhpParser::LogicalXor:
        case PhpParser::Namespace:
        case PhpParser::New:
        case PhpParser::Null:
        case PhpParser::ObjectType:
        case PhpParser::Parent_:
        case PhpParser::Partial:
        case PhpParser::Print:
        case PhpParser::Private:
        case PhpParser::Protected:
        case PhpParser::Public:
        case PhpParser::Require:
        case PhpParser::RequireOnce:
        case PhpParser::Resource:
        case PhpParser::Return:
        case PhpParser::Static:
        case PhpParser::StringType:
        case PhpParser::Switch:
        case PhpParser::Throw:
        case PhpParser::Trait:
        case PhpParser::Try:
        case PhpParser::Typeof:
        case PhpParser::UintCast:
        case PhpParser::UnicodeCast:
        case PhpParser::Unset:
        case PhpParser::Use:
        case PhpParser::Var:
        case PhpParser::While:
        case PhpParser::Yield:
        case PhpParser::Get:
        case PhpParser::Set:
        case PhpParser::Call:
        case PhpParser::CallStatic:
        case PhpParser::Constructor:
        case PhpParser::Destruct:
        case PhpParser::Wakeup:
        case PhpParser::Sleep:
        case PhpParser::Autoload:
        case PhpParser::IsSet__:
        case PhpParser::Unset__:
        case PhpParser::ToString__:
        case PhpParser::Invoke:
        case PhpParser::SetState:
        case PhpParser::Clone__:
        case PhpParser::DebugInfo:
        case PhpParser::Namespace__:
        case PhpParser::Class__:
        case PhpParser::Traic__:
        case PhpParser::Function__:
        case PhpParser::Method__:
        case PhpParser::Line__:
        case PhpParser::File__:
        case PhpParser::Dir__:
        case PhpParser::NamespaceSeparator:
        case PhpParser::Label: {
          setState(1365);
          qualifiedStaticTypeRef();
          break;
        }

        case PhpParser::Dollar:
        case PhpParser::VarName: {
          setState(1366);
          keyedVariable();
          break;
        }

      default:
        throw NoViableAltException(this);
      }
      setState(1369);
      match(PhpParser::DoubleColon);
      setState(1370);
      identifier();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- StringConstantContext ------------------------------------------------------------------

PhpParser::StringConstantContext::StringConstantContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::StringConstantContext::Label() {
  return getToken(PhpParser::Label, 0);
}


size_t PhpParser::StringConstantContext::getRuleIndex() const {
  return PhpParser::RuleStringConstant;
}

antlrcpp::Any PhpParser::StringConstantContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitStringConstant(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::StringConstantContext* PhpParser::stringConstant() {
  StringConstantContext *_localctx = _tracker.createInstance<StringConstantContext>(_ctx, getState());
  enterRule(_localctx, 198, PhpParser::RuleStringConstant);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1374);
    match(PhpParser::Label);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- StringContext ------------------------------------------------------------------

PhpParser::StringContext::StringContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::StringContext::StartHereDoc() {
  return getToken(PhpParser::StartHereDoc, 0);
}

std::vector<tree::TerminalNode *> PhpParser::StringContext::HereDocText() {
  return getTokens(PhpParser::HereDocText);
}

tree::TerminalNode* PhpParser::StringContext::HereDocText(size_t i) {
  return getToken(PhpParser::HereDocText, i);
}

tree::TerminalNode* PhpParser::StringContext::StartNowDoc() {
  return getToken(PhpParser::StartNowDoc, 0);
}

tree::TerminalNode* PhpParser::StringContext::SingleQuoteString() {
  return getToken(PhpParser::SingleQuoteString, 0);
}

std::vector<tree::TerminalNode *> PhpParser::StringContext::DoubleQuote() {
  return getTokens(PhpParser::DoubleQuote);
}

tree::TerminalNode* PhpParser::StringContext::DoubleQuote(size_t i) {
  return getToken(PhpParser::DoubleQuote, i);
}

std::vector<PhpParser::InterpolatedStringPartContext *> PhpParser::StringContext::interpolatedStringPart() {
  return getRuleContexts<PhpParser::InterpolatedStringPartContext>();
}

PhpParser::InterpolatedStringPartContext* PhpParser::StringContext::interpolatedStringPart(size_t i) {
  return getRuleContext<PhpParser::InterpolatedStringPartContext>(i);
}


size_t PhpParser::StringContext::getRuleIndex() const {
  return PhpParser::RuleString;
}

antlrcpp::Any PhpParser::StringContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitString(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::StringContext* PhpParser::string() {
  StringContext *_localctx = _tracker.createInstance<StringContext>(_ctx, getState());
  enterRule(_localctx, 200, PhpParser::RuleString);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    setState(1397);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::StartHereDoc: {
        enterOuterAlt(_localctx, 1);
        setState(1376);
        match(PhpParser::StartHereDoc);
        setState(1378); 
        _errHandler->sync(this);
        alt = 1;
        do {
          switch (alt) {
            case 1: {
                  setState(1377);
                  match(PhpParser::HereDocText);
                  break;
                }

          default:
            throw NoViableAltException(this);
          }
          setState(1380); 
          _errHandler->sync(this);
          alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 149, _ctx);
        } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
        break;
      }

      case PhpParser::StartNowDoc: {
        enterOuterAlt(_localctx, 2);
        setState(1382);
        match(PhpParser::StartNowDoc);
        setState(1384); 
        _errHandler->sync(this);
        alt = 1;
        do {
          switch (alt) {
            case 1: {
                  setState(1383);
                  match(PhpParser::HereDocText);
                  break;
                }

          default:
            throw NoViableAltException(this);
          }
          setState(1386); 
          _errHandler->sync(this);
          alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 150, _ctx);
        } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
        break;
      }

      case PhpParser::SingleQuoteString: {
        enterOuterAlt(_localctx, 3);
        setState(1388);
        match(PhpParser::SingleQuoteString);
        break;
      }

      case PhpParser::DoubleQuote: {
        enterOuterAlt(_localctx, 4);
        setState(1389);
        match(PhpParser::DoubleQuote);
        setState(1393);
        _errHandler->sync(this);
        _la = _input->LA(1);
        while ((((_la & ~ 0x3fULL) == 0) &&
          ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
          | (1ULL << PhpParser::Array)
          | (1ULL << PhpParser::As)
          | (1ULL << PhpParser::BinaryCast)
          | (1ULL << PhpParser::BoolType)
          | (1ULL << PhpParser::BooleanConstant)
          | (1ULL << PhpParser::Break)
          | (1ULL << PhpParser::Callable)
          | (1ULL << PhpParser::Case)
          | (1ULL << PhpParser::Catch)
          | (1ULL << PhpParser::Class)
          | (1ULL << PhpParser::Clone)
          | (1ULL << PhpParser::Const)
          | (1ULL << PhpParser::Continue)
          | (1ULL << PhpParser::Declare)
          | (1ULL << PhpParser::Default)
          | (1ULL << PhpParser::Do)
          | (1ULL << PhpParser::DoubleCast)
          | (1ULL << PhpParser::DoubleType)
          | (1ULL << PhpParser::Echo)
          | (1ULL << PhpParser::Else)
          | (1ULL << PhpParser::ElseIf)
          | (1ULL << PhpParser::Empty)
          | (1ULL << PhpParser::EndDeclare)
          | (1ULL << PhpParser::EndFor)
          | (1ULL << PhpParser::EndForeach)
          | (1ULL << PhpParser::EndIf)
          | (1ULL << PhpParser::EndSwitch)
          | (1ULL << PhpParser::EndWhile)
          | (1ULL << PhpParser::Eval)
          | (1ULL << PhpParser::Exit)
          | (1ULL << PhpParser::Extends)
          | (1ULL << PhpParser::Final)
          | (1ULL << PhpParser::Finally)
          | (1ULL << PhpParser::FloatCast)
          | (1ULL << PhpParser::For)
          | (1ULL << PhpParser::Foreach)
          | (1ULL << PhpParser::Function)
          | (1ULL << PhpParser::Global)
          | (1ULL << PhpParser::Goto)
          | (1ULL << PhpParser::If)
          | (1ULL << PhpParser::Implements)
          | (1ULL << PhpParser::Import)
          | (1ULL << PhpParser::Include)
          | (1ULL << PhpParser::IncludeOnce)
          | (1ULL << PhpParser::InstanceOf)
          | (1ULL << PhpParser::InsteadOf)
          | (1ULL << PhpParser::Int8Cast)
          | (1ULL << PhpParser::Int16Cast)
          | (1ULL << PhpParser::Int64Type)
          | (1ULL << PhpParser::IntType)
          | (1ULL << PhpParser::Interface)
          | (1ULL << PhpParser::IsSet)
          | (1ULL << PhpParser::List)
          | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
          ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
          | (1ULL << (PhpParser::LogicalXor - 64))
          | (1ULL << (PhpParser::Namespace - 64))
          | (1ULL << (PhpParser::New - 64))
          | (1ULL << (PhpParser::Null - 64))
          | (1ULL << (PhpParser::ObjectType - 64))
          | (1ULL << (PhpParser::Parent_ - 64))
          | (1ULL << (PhpParser::Partial - 64))
          | (1ULL << (PhpParser::Print - 64))
          | (1ULL << (PhpParser::Private - 64))
          | (1ULL << (PhpParser::Protected - 64))
          | (1ULL << (PhpParser::Public - 64))
          | (1ULL << (PhpParser::Require - 64))
          | (1ULL << (PhpParser::RequireOnce - 64))
          | (1ULL << (PhpParser::Resource - 64))
          | (1ULL << (PhpParser::Return - 64))
          | (1ULL << (PhpParser::Static - 64))
          | (1ULL << (PhpParser::StringType - 64))
          | (1ULL << (PhpParser::Switch - 64))
          | (1ULL << (PhpParser::Throw - 64))
          | (1ULL << (PhpParser::Trait - 64))
          | (1ULL << (PhpParser::Try - 64))
          | (1ULL << (PhpParser::Typeof - 64))
          | (1ULL << (PhpParser::UintCast - 64))
          | (1ULL << (PhpParser::UnicodeCast - 64))
          | (1ULL << (PhpParser::Unset - 64))
          | (1ULL << (PhpParser::Use - 64))
          | (1ULL << (PhpParser::Var - 64))
          | (1ULL << (PhpParser::While - 64))
          | (1ULL << (PhpParser::Yield - 64))
          | (1ULL << (PhpParser::Get - 64))
          | (1ULL << (PhpParser::Set - 64))
          | (1ULL << (PhpParser::Call - 64))
          | (1ULL << (PhpParser::CallStatic - 64))
          | (1ULL << (PhpParser::Constructor - 64))
          | (1ULL << (PhpParser::Destruct - 64))
          | (1ULL << (PhpParser::Wakeup - 64))
          | (1ULL << (PhpParser::Sleep - 64))
          | (1ULL << (PhpParser::Autoload - 64))
          | (1ULL << (PhpParser::IsSet__ - 64))
          | (1ULL << (PhpParser::Unset__ - 64))
          | (1ULL << (PhpParser::ToString__ - 64))
          | (1ULL << (PhpParser::Invoke - 64))
          | (1ULL << (PhpParser::SetState - 64))
          | (1ULL << (PhpParser::Clone__ - 64))
          | (1ULL << (PhpParser::DebugInfo - 64))
          | (1ULL << (PhpParser::Namespace__ - 64))
          | (1ULL << (PhpParser::Class__ - 64))
          | (1ULL << (PhpParser::Traic__ - 64))
          | (1ULL << (PhpParser::Function__ - 64))
          | (1ULL << (PhpParser::Method__ - 64))
          | (1ULL << (PhpParser::Line__ - 64))
          | (1ULL << (PhpParser::File__ - 64))
          | (1ULL << (PhpParser::Dir__ - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
          ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
          | (1ULL << (PhpParser::Dollar - 148))
          | (1ULL << (PhpParser::OpenRoundBracket - 148))
          | (1ULL << (PhpParser::VarName - 148))
          | (1ULL << (PhpParser::Label - 148))
          | (1ULL << (PhpParser::StringPart - 148)))) != 0)) {
          setState(1390);
          interpolatedStringPart();
          setState(1395);
          _errHandler->sync(this);
          _la = _input->LA(1);
        }
        setState(1396);
        match(PhpParser::DoubleQuote);
        break;
      }

    default:
      throw NoViableAltException(this);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- InterpolatedStringPartContext ------------------------------------------------------------------

PhpParser::InterpolatedStringPartContext::InterpolatedStringPartContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::InterpolatedStringPartContext::StringPart() {
  return getToken(PhpParser::StringPart, 0);
}

PhpParser::ChainContext* PhpParser::InterpolatedStringPartContext::chain() {
  return getRuleContext<PhpParser::ChainContext>(0);
}


size_t PhpParser::InterpolatedStringPartContext::getRuleIndex() const {
  return PhpParser::RuleInterpolatedStringPart;
}

antlrcpp::Any PhpParser::InterpolatedStringPartContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitInterpolatedStringPart(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::InterpolatedStringPartContext* PhpParser::interpolatedStringPart() {
  InterpolatedStringPartContext *_localctx = _tracker.createInstance<InterpolatedStringPartContext>(_ctx, getState());
  enterRule(_localctx, 202, PhpParser::RuleInterpolatedStringPart);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1401);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::StringPart: {
        enterOuterAlt(_localctx, 1);
        setState(1399);
        match(PhpParser::StringPart);
        break;
      }

      case PhpParser::Abstract:
      case PhpParser::Array:
      case PhpParser::As:
      case PhpParser::BinaryCast:
      case PhpParser::BoolType:
      case PhpParser::BooleanConstant:
      case PhpParser::Break:
      case PhpParser::Callable:
      case PhpParser::Case:
      case PhpParser::Catch:
      case PhpParser::Class:
      case PhpParser::Clone:
      case PhpParser::Const:
      case PhpParser::Continue:
      case PhpParser::Declare:
      case PhpParser::Default:
      case PhpParser::Do:
      case PhpParser::DoubleCast:
      case PhpParser::DoubleType:
      case PhpParser::Echo:
      case PhpParser::Else:
      case PhpParser::ElseIf:
      case PhpParser::Empty:
      case PhpParser::EndDeclare:
      case PhpParser::EndFor:
      case PhpParser::EndForeach:
      case PhpParser::EndIf:
      case PhpParser::EndSwitch:
      case PhpParser::EndWhile:
      case PhpParser::Eval:
      case PhpParser::Exit:
      case PhpParser::Extends:
      case PhpParser::Final:
      case PhpParser::Finally:
      case PhpParser::FloatCast:
      case PhpParser::For:
      case PhpParser::Foreach:
      case PhpParser::Function:
      case PhpParser::Global:
      case PhpParser::Goto:
      case PhpParser::If:
      case PhpParser::Implements:
      case PhpParser::Import:
      case PhpParser::Include:
      case PhpParser::IncludeOnce:
      case PhpParser::InstanceOf:
      case PhpParser::InsteadOf:
      case PhpParser::Int8Cast:
      case PhpParser::Int16Cast:
      case PhpParser::Int64Type:
      case PhpParser::IntType:
      case PhpParser::Interface:
      case PhpParser::IsSet:
      case PhpParser::List:
      case PhpParser::LogicalAnd:
      case PhpParser::LogicalOr:
      case PhpParser::LogicalXor:
      case PhpParser::Namespace:
      case PhpParser::New:
      case PhpParser::Null:
      case PhpParser::ObjectType:
      case PhpParser::Parent_:
      case PhpParser::Partial:
      case PhpParser::Print:
      case PhpParser::Private:
      case PhpParser::Protected:
      case PhpParser::Public:
      case PhpParser::Require:
      case PhpParser::RequireOnce:
      case PhpParser::Resource:
      case PhpParser::Return:
      case PhpParser::Static:
      case PhpParser::StringType:
      case PhpParser::Switch:
      case PhpParser::Throw:
      case PhpParser::Trait:
      case PhpParser::Try:
      case PhpParser::Typeof:
      case PhpParser::UintCast:
      case PhpParser::UnicodeCast:
      case PhpParser::Unset:
      case PhpParser::Use:
      case PhpParser::Var:
      case PhpParser::While:
      case PhpParser::Yield:
      case PhpParser::Get:
      case PhpParser::Set:
      case PhpParser::Call:
      case PhpParser::CallStatic:
      case PhpParser::Constructor:
      case PhpParser::Destruct:
      case PhpParser::Wakeup:
      case PhpParser::Sleep:
      case PhpParser::Autoload:
      case PhpParser::IsSet__:
      case PhpParser::Unset__:
      case PhpParser::ToString__:
      case PhpParser::Invoke:
      case PhpParser::SetState:
      case PhpParser::Clone__:
      case PhpParser::DebugInfo:
      case PhpParser::Namespace__:
      case PhpParser::Class__:
      case PhpParser::Traic__:
      case PhpParser::Function__:
      case PhpParser::Method__:
      case PhpParser::Line__:
      case PhpParser::File__:
      case PhpParser::Dir__:
      case PhpParser::NamespaceSeparator:
      case PhpParser::Dollar:
      case PhpParser::OpenRoundBracket:
      case PhpParser::VarName:
      case PhpParser::Label: {
        enterOuterAlt(_localctx, 2);
        setState(1400);
        chain();
        break;
      }

    default:
      throw NoViableAltException(this);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ChainListContext ------------------------------------------------------------------

PhpParser::ChainListContext::ChainListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::ChainContext *> PhpParser::ChainListContext::chain() {
  return getRuleContexts<PhpParser::ChainContext>();
}

PhpParser::ChainContext* PhpParser::ChainListContext::chain(size_t i) {
  return getRuleContext<PhpParser::ChainContext>(i);
}


size_t PhpParser::ChainListContext::getRuleIndex() const {
  return PhpParser::RuleChainList;
}

antlrcpp::Any PhpParser::ChainListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitChainList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ChainListContext* PhpParser::chainList() {
  ChainListContext *_localctx = _tracker.createInstance<ChainListContext>(_ctx, getState());
  enterRule(_localctx, 204, PhpParser::RuleChainList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1403);
    chain();
    setState(1408);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(1404);
      match(PhpParser::Comma);
      setState(1405);
      chain();
      setState(1410);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ChainContext ------------------------------------------------------------------

PhpParser::ChainContext::ChainContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::ChainBaseContext* PhpParser::ChainContext::chainBase() {
  return getRuleContext<PhpParser::ChainBaseContext>(0);
}

PhpParser::FunctionCallContext* PhpParser::ChainContext::functionCall() {
  return getRuleContext<PhpParser::FunctionCallContext>(0);
}

PhpParser::NewExprContext* PhpParser::ChainContext::newExpr() {
  return getRuleContext<PhpParser::NewExprContext>(0);
}

std::vector<PhpParser::MemberAccessContext *> PhpParser::ChainContext::memberAccess() {
  return getRuleContexts<PhpParser::MemberAccessContext>();
}

PhpParser::MemberAccessContext* PhpParser::ChainContext::memberAccess(size_t i) {
  return getRuleContext<PhpParser::MemberAccessContext>(i);
}


size_t PhpParser::ChainContext::getRuleIndex() const {
  return PhpParser::RuleChain;
}

antlrcpp::Any PhpParser::ChainContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitChain(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ChainContext* PhpParser::chain() {
  ChainContext *_localctx = _tracker.createInstance<ChainContext>(_ctx, getState());
  enterRule(_localctx, 206, PhpParser::RuleChain);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(1417);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 155, _ctx)) {
    case 1: {
      setState(1411);
      chainBase();
      break;
    }

    case 2: {
      setState(1412);
      functionCall();
      break;
    }

    case 3: {
      setState(1413);
      match(PhpParser::OpenRoundBracket);
      setState(1414);
      newExpr();
      setState(1415);
      match(PhpParser::CloseRoundBracket);
      break;
    }

    }
    setState(1422);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 156, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(1419);
        memberAccess(); 
      }
      setState(1424);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 156, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- MemberAccessContext ------------------------------------------------------------------

PhpParser::MemberAccessContext::MemberAccessContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::KeyedFieldNameContext* PhpParser::MemberAccessContext::keyedFieldName() {
  return getRuleContext<PhpParser::KeyedFieldNameContext>(0);
}

PhpParser::ActualArgumentsContext* PhpParser::MemberAccessContext::actualArguments() {
  return getRuleContext<PhpParser::ActualArgumentsContext>(0);
}


size_t PhpParser::MemberAccessContext::getRuleIndex() const {
  return PhpParser::RuleMemberAccess;
}

antlrcpp::Any PhpParser::MemberAccessContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitMemberAccess(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::MemberAccessContext* PhpParser::memberAccess() {
  MemberAccessContext *_localctx = _tracker.createInstance<MemberAccessContext>(_ctx, getState());
  enterRule(_localctx, 208, PhpParser::RuleMemberAccess);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1425);
    match(PhpParser::ObjectOperator);
    setState(1426);
    keyedFieldName();
    setState(1428);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 157, _ctx)) {
    case 1: {
      setState(1427);
      actualArguments();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- FunctionCallContext ------------------------------------------------------------------

PhpParser::FunctionCallContext::FunctionCallContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::FunctionCallNameContext* PhpParser::FunctionCallContext::functionCallName() {
  return getRuleContext<PhpParser::FunctionCallNameContext>(0);
}

PhpParser::ActualArgumentsContext* PhpParser::FunctionCallContext::actualArguments() {
  return getRuleContext<PhpParser::ActualArgumentsContext>(0);
}


size_t PhpParser::FunctionCallContext::getRuleIndex() const {
  return PhpParser::RuleFunctionCall;
}

antlrcpp::Any PhpParser::FunctionCallContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitFunctionCall(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::FunctionCallContext* PhpParser::functionCall() {
  FunctionCallContext *_localctx = _tracker.createInstance<FunctionCallContext>(_ctx, getState());
  enterRule(_localctx, 210, PhpParser::RuleFunctionCall);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1430);
    functionCallName();
    setState(1431);
    actualArguments();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- FunctionCallNameContext ------------------------------------------------------------------

PhpParser::FunctionCallNameContext::FunctionCallNameContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::QualifiedNamespaceNameContext* PhpParser::FunctionCallNameContext::qualifiedNamespaceName() {
  return getRuleContext<PhpParser::QualifiedNamespaceNameContext>(0);
}

PhpParser::ClassConstantContext* PhpParser::FunctionCallNameContext::classConstant() {
  return getRuleContext<PhpParser::ClassConstantContext>(0);
}

PhpParser::ChainBaseContext* PhpParser::FunctionCallNameContext::chainBase() {
  return getRuleContext<PhpParser::ChainBaseContext>(0);
}


size_t PhpParser::FunctionCallNameContext::getRuleIndex() const {
  return PhpParser::RuleFunctionCallName;
}

antlrcpp::Any PhpParser::FunctionCallNameContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitFunctionCallName(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::FunctionCallNameContext* PhpParser::functionCallName() {
  FunctionCallNameContext *_localctx = _tracker.createInstance<FunctionCallNameContext>(_ctx, getState());
  enterRule(_localctx, 212, PhpParser::RuleFunctionCallName);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1436);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 158, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(1433);
      qualifiedNamespaceName();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(1434);
      classConstant();
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(1435);
      chainBase();
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ActualArgumentsContext ------------------------------------------------------------------

PhpParser::ActualArgumentsContext::ActualArgumentsContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::ArgumentsContext* PhpParser::ActualArgumentsContext::arguments() {
  return getRuleContext<PhpParser::ArgumentsContext>(0);
}

PhpParser::GenericDynamicArgsContext* PhpParser::ActualArgumentsContext::genericDynamicArgs() {
  return getRuleContext<PhpParser::GenericDynamicArgsContext>(0);
}

std::vector<PhpParser::SquareCurlyExpressionContext *> PhpParser::ActualArgumentsContext::squareCurlyExpression() {
  return getRuleContexts<PhpParser::SquareCurlyExpressionContext>();
}

PhpParser::SquareCurlyExpressionContext* PhpParser::ActualArgumentsContext::squareCurlyExpression(size_t i) {
  return getRuleContext<PhpParser::SquareCurlyExpressionContext>(i);
}


size_t PhpParser::ActualArgumentsContext::getRuleIndex() const {
  return PhpParser::RuleActualArguments;
}

antlrcpp::Any PhpParser::ActualArgumentsContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitActualArguments(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ActualArgumentsContext* PhpParser::actualArguments() {
  ActualArgumentsContext *_localctx = _tracker.createInstance<ActualArgumentsContext>(_ctx, getState());
  enterRule(_localctx, 214, PhpParser::RuleActualArguments);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(1439);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == PhpParser::Lgeneric) {
      setState(1438);
      genericDynamicArgs();
    }
    setState(1441);
    arguments();
    setState(1445);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 160, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(1442);
        squareCurlyExpression(); 
      }
      setState(1447);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 160, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ChainBaseContext ------------------------------------------------------------------

PhpParser::ChainBaseContext::ChainBaseContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::KeyedVariableContext *> PhpParser::ChainBaseContext::keyedVariable() {
  return getRuleContexts<PhpParser::KeyedVariableContext>();
}

PhpParser::KeyedVariableContext* PhpParser::ChainBaseContext::keyedVariable(size_t i) {
  return getRuleContext<PhpParser::KeyedVariableContext>(i);
}

PhpParser::QualifiedStaticTypeRefContext* PhpParser::ChainBaseContext::qualifiedStaticTypeRef() {
  return getRuleContext<PhpParser::QualifiedStaticTypeRefContext>(0);
}


size_t PhpParser::ChainBaseContext::getRuleIndex() const {
  return PhpParser::RuleChainBase;
}

antlrcpp::Any PhpParser::ChainBaseContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitChainBase(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ChainBaseContext* PhpParser::chainBase() {
  ChainBaseContext *_localctx = _tracker.createInstance<ChainBaseContext>(_ctx, getState());
  enterRule(_localctx, 216, PhpParser::RuleChainBase);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1457);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::Dollar:
      case PhpParser::VarName: {
        enterOuterAlt(_localctx, 1);
        setState(1448);
        keyedVariable();
        setState(1451);
        _errHandler->sync(this);

        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 161, _ctx)) {
        case 1: {
          setState(1449);
          match(PhpParser::DoubleColon);
          setState(1450);
          keyedVariable();
          break;
        }

        }
        break;
      }

      case PhpParser::Abstract:
      case PhpParser::Array:
      case PhpParser::As:
      case PhpParser::BinaryCast:
      case PhpParser::BoolType:
      case PhpParser::BooleanConstant:
      case PhpParser::Break:
      case PhpParser::Callable:
      case PhpParser::Case:
      case PhpParser::Catch:
      case PhpParser::Class:
      case PhpParser::Clone:
      case PhpParser::Const:
      case PhpParser::Continue:
      case PhpParser::Declare:
      case PhpParser::Default:
      case PhpParser::Do:
      case PhpParser::DoubleCast:
      case PhpParser::DoubleType:
      case PhpParser::Echo:
      case PhpParser::Else:
      case PhpParser::ElseIf:
      case PhpParser::Empty:
      case PhpParser::EndDeclare:
      case PhpParser::EndFor:
      case PhpParser::EndForeach:
      case PhpParser::EndIf:
      case PhpParser::EndSwitch:
      case PhpParser::EndWhile:
      case PhpParser::Eval:
      case PhpParser::Exit:
      case PhpParser::Extends:
      case PhpParser::Final:
      case PhpParser::Finally:
      case PhpParser::FloatCast:
      case PhpParser::For:
      case PhpParser::Foreach:
      case PhpParser::Function:
      case PhpParser::Global:
      case PhpParser::Goto:
      case PhpParser::If:
      case PhpParser::Implements:
      case PhpParser::Import:
      case PhpParser::Include:
      case PhpParser::IncludeOnce:
      case PhpParser::InstanceOf:
      case PhpParser::InsteadOf:
      case PhpParser::Int8Cast:
      case PhpParser::Int16Cast:
      case PhpParser::Int64Type:
      case PhpParser::IntType:
      case PhpParser::Interface:
      case PhpParser::IsSet:
      case PhpParser::List:
      case PhpParser::LogicalAnd:
      case PhpParser::LogicalOr:
      case PhpParser::LogicalXor:
      case PhpParser::Namespace:
      case PhpParser::New:
      case PhpParser::Null:
      case PhpParser::ObjectType:
      case PhpParser::Parent_:
      case PhpParser::Partial:
      case PhpParser::Print:
      case PhpParser::Private:
      case PhpParser::Protected:
      case PhpParser::Public:
      case PhpParser::Require:
      case PhpParser::RequireOnce:
      case PhpParser::Resource:
      case PhpParser::Return:
      case PhpParser::Static:
      case PhpParser::StringType:
      case PhpParser::Switch:
      case PhpParser::Throw:
      case PhpParser::Trait:
      case PhpParser::Try:
      case PhpParser::Typeof:
      case PhpParser::UintCast:
      case PhpParser::UnicodeCast:
      case PhpParser::Unset:
      case PhpParser::Use:
      case PhpParser::Var:
      case PhpParser::While:
      case PhpParser::Yield:
      case PhpParser::Get:
      case PhpParser::Set:
      case PhpParser::Call:
      case PhpParser::CallStatic:
      case PhpParser::Constructor:
      case PhpParser::Destruct:
      case PhpParser::Wakeup:
      case PhpParser::Sleep:
      case PhpParser::Autoload:
      case PhpParser::IsSet__:
      case PhpParser::Unset__:
      case PhpParser::ToString__:
      case PhpParser::Invoke:
      case PhpParser::SetState:
      case PhpParser::Clone__:
      case PhpParser::DebugInfo:
      case PhpParser::Namespace__:
      case PhpParser::Class__:
      case PhpParser::Traic__:
      case PhpParser::Function__:
      case PhpParser::Method__:
      case PhpParser::Line__:
      case PhpParser::File__:
      case PhpParser::Dir__:
      case PhpParser::NamespaceSeparator:
      case PhpParser::Label: {
        enterOuterAlt(_localctx, 2);
        setState(1453);
        qualifiedStaticTypeRef();
        setState(1454);
        match(PhpParser::DoubleColon);
        setState(1455);
        keyedVariable();
        break;
      }

    default:
      throw NoViableAltException(this);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- KeyedFieldNameContext ------------------------------------------------------------------

PhpParser::KeyedFieldNameContext::KeyedFieldNameContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::KeyedSimpleFieldNameContext* PhpParser::KeyedFieldNameContext::keyedSimpleFieldName() {
  return getRuleContext<PhpParser::KeyedSimpleFieldNameContext>(0);
}

PhpParser::KeyedVariableContext* PhpParser::KeyedFieldNameContext::keyedVariable() {
  return getRuleContext<PhpParser::KeyedVariableContext>(0);
}


size_t PhpParser::KeyedFieldNameContext::getRuleIndex() const {
  return PhpParser::RuleKeyedFieldName;
}

antlrcpp::Any PhpParser::KeyedFieldNameContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitKeyedFieldName(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::KeyedFieldNameContext* PhpParser::keyedFieldName() {
  KeyedFieldNameContext *_localctx = _tracker.createInstance<KeyedFieldNameContext>(_ctx, getState());
  enterRule(_localctx, 218, PhpParser::RuleKeyedFieldName);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1461);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::Abstract:
      case PhpParser::Array:
      case PhpParser::As:
      case PhpParser::BinaryCast:
      case PhpParser::BoolType:
      case PhpParser::BooleanConstant:
      case PhpParser::Break:
      case PhpParser::Callable:
      case PhpParser::Case:
      case PhpParser::Catch:
      case PhpParser::Class:
      case PhpParser::Clone:
      case PhpParser::Const:
      case PhpParser::Continue:
      case PhpParser::Declare:
      case PhpParser::Default:
      case PhpParser::Do:
      case PhpParser::DoubleCast:
      case PhpParser::DoubleType:
      case PhpParser::Echo:
      case PhpParser::Else:
      case PhpParser::ElseIf:
      case PhpParser::Empty:
      case PhpParser::EndDeclare:
      case PhpParser::EndFor:
      case PhpParser::EndForeach:
      case PhpParser::EndIf:
      case PhpParser::EndSwitch:
      case PhpParser::EndWhile:
      case PhpParser::Eval:
      case PhpParser::Exit:
      case PhpParser::Extends:
      case PhpParser::Final:
      case PhpParser::Finally:
      case PhpParser::FloatCast:
      case PhpParser::For:
      case PhpParser::Foreach:
      case PhpParser::Function:
      case PhpParser::Global:
      case PhpParser::Goto:
      case PhpParser::If:
      case PhpParser::Implements:
      case PhpParser::Import:
      case PhpParser::Include:
      case PhpParser::IncludeOnce:
      case PhpParser::InstanceOf:
      case PhpParser::InsteadOf:
      case PhpParser::Int8Cast:
      case PhpParser::Int16Cast:
      case PhpParser::Int64Type:
      case PhpParser::IntType:
      case PhpParser::Interface:
      case PhpParser::IsSet:
      case PhpParser::List:
      case PhpParser::LogicalAnd:
      case PhpParser::LogicalOr:
      case PhpParser::LogicalXor:
      case PhpParser::Namespace:
      case PhpParser::New:
      case PhpParser::Null:
      case PhpParser::ObjectType:
      case PhpParser::Parent_:
      case PhpParser::Partial:
      case PhpParser::Print:
      case PhpParser::Private:
      case PhpParser::Protected:
      case PhpParser::Public:
      case PhpParser::Require:
      case PhpParser::RequireOnce:
      case PhpParser::Resource:
      case PhpParser::Return:
      case PhpParser::Static:
      case PhpParser::StringType:
      case PhpParser::Switch:
      case PhpParser::Throw:
      case PhpParser::Trait:
      case PhpParser::Try:
      case PhpParser::Typeof:
      case PhpParser::UintCast:
      case PhpParser::UnicodeCast:
      case PhpParser::Unset:
      case PhpParser::Use:
      case PhpParser::Var:
      case PhpParser::While:
      case PhpParser::Yield:
      case PhpParser::Get:
      case PhpParser::Set:
      case PhpParser::Call:
      case PhpParser::CallStatic:
      case PhpParser::Constructor:
      case PhpParser::Destruct:
      case PhpParser::Wakeup:
      case PhpParser::Sleep:
      case PhpParser::Autoload:
      case PhpParser::IsSet__:
      case PhpParser::Unset__:
      case PhpParser::ToString__:
      case PhpParser::Invoke:
      case PhpParser::SetState:
      case PhpParser::Clone__:
      case PhpParser::DebugInfo:
      case PhpParser::Namespace__:
      case PhpParser::Class__:
      case PhpParser::Traic__:
      case PhpParser::Function__:
      case PhpParser::Method__:
      case PhpParser::Line__:
      case PhpParser::File__:
      case PhpParser::Dir__:
      case PhpParser::OpenCurlyBracket:
      case PhpParser::Label: {
        enterOuterAlt(_localctx, 1);
        setState(1459);
        keyedSimpleFieldName();
        break;
      }

      case PhpParser::Dollar:
      case PhpParser::VarName: {
        enterOuterAlt(_localctx, 2);
        setState(1460);
        keyedVariable();
        break;
      }

    default:
      throw NoViableAltException(this);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- KeyedSimpleFieldNameContext ------------------------------------------------------------------

PhpParser::KeyedSimpleFieldNameContext::KeyedSimpleFieldNameContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::IdentifierContext* PhpParser::KeyedSimpleFieldNameContext::identifier() {
  return getRuleContext<PhpParser::IdentifierContext>(0);
}

tree::TerminalNode* PhpParser::KeyedSimpleFieldNameContext::OpenCurlyBracket() {
  return getToken(PhpParser::OpenCurlyBracket, 0);
}

PhpParser::ExpressionContext* PhpParser::KeyedSimpleFieldNameContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}

std::vector<PhpParser::SquareCurlyExpressionContext *> PhpParser::KeyedSimpleFieldNameContext::squareCurlyExpression() {
  return getRuleContexts<PhpParser::SquareCurlyExpressionContext>();
}

PhpParser::SquareCurlyExpressionContext* PhpParser::KeyedSimpleFieldNameContext::squareCurlyExpression(size_t i) {
  return getRuleContext<PhpParser::SquareCurlyExpressionContext>(i);
}


size_t PhpParser::KeyedSimpleFieldNameContext::getRuleIndex() const {
  return PhpParser::RuleKeyedSimpleFieldName;
}

antlrcpp::Any PhpParser::KeyedSimpleFieldNameContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitKeyedSimpleFieldName(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::KeyedSimpleFieldNameContext* PhpParser::keyedSimpleFieldName() {
  KeyedSimpleFieldNameContext *_localctx = _tracker.createInstance<KeyedSimpleFieldNameContext>(_ctx, getState());
  enterRule(_localctx, 220, PhpParser::RuleKeyedSimpleFieldName);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(1468);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::Abstract:
      case PhpParser::Array:
      case PhpParser::As:
      case PhpParser::BinaryCast:
      case PhpParser::BoolType:
      case PhpParser::BooleanConstant:
      case PhpParser::Break:
      case PhpParser::Callable:
      case PhpParser::Case:
      case PhpParser::Catch:
      case PhpParser::Class:
      case PhpParser::Clone:
      case PhpParser::Const:
      case PhpParser::Continue:
      case PhpParser::Declare:
      case PhpParser::Default:
      case PhpParser::Do:
      case PhpParser::DoubleCast:
      case PhpParser::DoubleType:
      case PhpParser::Echo:
      case PhpParser::Else:
      case PhpParser::ElseIf:
      case PhpParser::Empty:
      case PhpParser::EndDeclare:
      case PhpParser::EndFor:
      case PhpParser::EndForeach:
      case PhpParser::EndIf:
      case PhpParser::EndSwitch:
      case PhpParser::EndWhile:
      case PhpParser::Eval:
      case PhpParser::Exit:
      case PhpParser::Extends:
      case PhpParser::Final:
      case PhpParser::Finally:
      case PhpParser::FloatCast:
      case PhpParser::For:
      case PhpParser::Foreach:
      case PhpParser::Function:
      case PhpParser::Global:
      case PhpParser::Goto:
      case PhpParser::If:
      case PhpParser::Implements:
      case PhpParser::Import:
      case PhpParser::Include:
      case PhpParser::IncludeOnce:
      case PhpParser::InstanceOf:
      case PhpParser::InsteadOf:
      case PhpParser::Int8Cast:
      case PhpParser::Int16Cast:
      case PhpParser::Int64Type:
      case PhpParser::IntType:
      case PhpParser::Interface:
      case PhpParser::IsSet:
      case PhpParser::List:
      case PhpParser::LogicalAnd:
      case PhpParser::LogicalOr:
      case PhpParser::LogicalXor:
      case PhpParser::Namespace:
      case PhpParser::New:
      case PhpParser::Null:
      case PhpParser::ObjectType:
      case PhpParser::Parent_:
      case PhpParser::Partial:
      case PhpParser::Print:
      case PhpParser::Private:
      case PhpParser::Protected:
      case PhpParser::Public:
      case PhpParser::Require:
      case PhpParser::RequireOnce:
      case PhpParser::Resource:
      case PhpParser::Return:
      case PhpParser::Static:
      case PhpParser::StringType:
      case PhpParser::Switch:
      case PhpParser::Throw:
      case PhpParser::Trait:
      case PhpParser::Try:
      case PhpParser::Typeof:
      case PhpParser::UintCast:
      case PhpParser::UnicodeCast:
      case PhpParser::Unset:
      case PhpParser::Use:
      case PhpParser::Var:
      case PhpParser::While:
      case PhpParser::Yield:
      case PhpParser::Get:
      case PhpParser::Set:
      case PhpParser::Call:
      case PhpParser::CallStatic:
      case PhpParser::Constructor:
      case PhpParser::Destruct:
      case PhpParser::Wakeup:
      case PhpParser::Sleep:
      case PhpParser::Autoload:
      case PhpParser::IsSet__:
      case PhpParser::Unset__:
      case PhpParser::ToString__:
      case PhpParser::Invoke:
      case PhpParser::SetState:
      case PhpParser::Clone__:
      case PhpParser::DebugInfo:
      case PhpParser::Namespace__:
      case PhpParser::Class__:
      case PhpParser::Traic__:
      case PhpParser::Function__:
      case PhpParser::Method__:
      case PhpParser::Line__:
      case PhpParser::File__:
      case PhpParser::Dir__:
      case PhpParser::Label: {
        setState(1463);
        identifier();
        break;
      }

      case PhpParser::OpenCurlyBracket: {
        setState(1464);
        match(PhpParser::OpenCurlyBracket);
        setState(1465);
        expression(0);
        setState(1466);
        match(PhpParser::CloseCurlyBracket);
        break;
      }

    default:
      throw NoViableAltException(this);
    }
    setState(1473);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 165, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(1470);
        squareCurlyExpression(); 
      }
      setState(1475);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 165, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- KeyedVariableContext ------------------------------------------------------------------

PhpParser::KeyedVariableContext::KeyedVariableContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::KeyedVariableContext::VarName() {
  return getToken(PhpParser::VarName, 0);
}

std::vector<tree::TerminalNode *> PhpParser::KeyedVariableContext::Dollar() {
  return getTokens(PhpParser::Dollar);
}

tree::TerminalNode* PhpParser::KeyedVariableContext::Dollar(size_t i) {
  return getToken(PhpParser::Dollar, i);
}

tree::TerminalNode* PhpParser::KeyedVariableContext::OpenCurlyBracket() {
  return getToken(PhpParser::OpenCurlyBracket, 0);
}

PhpParser::ExpressionContext* PhpParser::KeyedVariableContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}

std::vector<PhpParser::SquareCurlyExpressionContext *> PhpParser::KeyedVariableContext::squareCurlyExpression() {
  return getRuleContexts<PhpParser::SquareCurlyExpressionContext>();
}

PhpParser::SquareCurlyExpressionContext* PhpParser::KeyedVariableContext::squareCurlyExpression(size_t i) {
  return getRuleContext<PhpParser::SquareCurlyExpressionContext>(i);
}


size_t PhpParser::KeyedVariableContext::getRuleIndex() const {
  return PhpParser::RuleKeyedVariable;
}

antlrcpp::Any PhpParser::KeyedVariableContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitKeyedVariable(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::KeyedVariableContext* PhpParser::keyedVariable() {
  KeyedVariableContext *_localctx = _tracker.createInstance<KeyedVariableContext>(_ctx, getState());
  enterRule(_localctx, 222, PhpParser::RuleKeyedVariable);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(1479);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 166, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(1476);
        match(PhpParser::Dollar); 
      }
      setState(1481);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 166, _ctx);
    }
    setState(1488);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::VarName: {
        setState(1482);
        match(PhpParser::VarName);
        break;
      }

      case PhpParser::Dollar: {
        setState(1483);
        match(PhpParser::Dollar);
        setState(1484);
        match(PhpParser::OpenCurlyBracket);
        setState(1485);
        expression(0);
        setState(1486);
        match(PhpParser::CloseCurlyBracket);
        break;
      }

    default:
      throw NoViableAltException(this);
    }
    setState(1493);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 168, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(1490);
        squareCurlyExpression(); 
      }
      setState(1495);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 168, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SquareCurlyExpressionContext ------------------------------------------------------------------

PhpParser::SquareCurlyExpressionContext::SquareCurlyExpressionContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::ExpressionContext* PhpParser::SquareCurlyExpressionContext::expression() {
  return getRuleContext<PhpParser::ExpressionContext>(0);
}

tree::TerminalNode* PhpParser::SquareCurlyExpressionContext::OpenCurlyBracket() {
  return getToken(PhpParser::OpenCurlyBracket, 0);
}


size_t PhpParser::SquareCurlyExpressionContext::getRuleIndex() const {
  return PhpParser::RuleSquareCurlyExpression;
}

antlrcpp::Any PhpParser::SquareCurlyExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitSquareCurlyExpression(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::SquareCurlyExpressionContext* PhpParser::squareCurlyExpression() {
  SquareCurlyExpressionContext *_localctx = _tracker.createInstance<SquareCurlyExpressionContext>(_ctx, getState());
  enterRule(_localctx, 224, PhpParser::RuleSquareCurlyExpression);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1505);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case PhpParser::OpenSquareBracket: {
        enterOuterAlt(_localctx, 1);
        setState(1496);
        match(PhpParser::OpenSquareBracket);
        setState(1498);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if ((((_la & ~ 0x3fULL) == 0) &&
          ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
          | (1ULL << PhpParser::Array)
          | (1ULL << PhpParser::As)
          | (1ULL << PhpParser::BinaryCast)
          | (1ULL << PhpParser::BoolType)
          | (1ULL << PhpParser::BooleanConstant)
          | (1ULL << PhpParser::Break)
          | (1ULL << PhpParser::Callable)
          | (1ULL << PhpParser::Case)
          | (1ULL << PhpParser::Catch)
          | (1ULL << PhpParser::Class)
          | (1ULL << PhpParser::Clone)
          | (1ULL << PhpParser::Const)
          | (1ULL << PhpParser::Continue)
          | (1ULL << PhpParser::Declare)
          | (1ULL << PhpParser::Default)
          | (1ULL << PhpParser::Do)
          | (1ULL << PhpParser::DoubleCast)
          | (1ULL << PhpParser::DoubleType)
          | (1ULL << PhpParser::Echo)
          | (1ULL << PhpParser::Else)
          | (1ULL << PhpParser::ElseIf)
          | (1ULL << PhpParser::Empty)
          | (1ULL << PhpParser::EndDeclare)
          | (1ULL << PhpParser::EndFor)
          | (1ULL << PhpParser::EndForeach)
          | (1ULL << PhpParser::EndIf)
          | (1ULL << PhpParser::EndSwitch)
          | (1ULL << PhpParser::EndWhile)
          | (1ULL << PhpParser::Eval)
          | (1ULL << PhpParser::Exit)
          | (1ULL << PhpParser::Extends)
          | (1ULL << PhpParser::Final)
          | (1ULL << PhpParser::Finally)
          | (1ULL << PhpParser::FloatCast)
          | (1ULL << PhpParser::For)
          | (1ULL << PhpParser::Foreach)
          | (1ULL << PhpParser::Function)
          | (1ULL << PhpParser::Global)
          | (1ULL << PhpParser::Goto)
          | (1ULL << PhpParser::If)
          | (1ULL << PhpParser::Implements)
          | (1ULL << PhpParser::Import)
          | (1ULL << PhpParser::Include)
          | (1ULL << PhpParser::IncludeOnce)
          | (1ULL << PhpParser::InstanceOf)
          | (1ULL << PhpParser::InsteadOf)
          | (1ULL << PhpParser::Int8Cast)
          | (1ULL << PhpParser::Int16Cast)
          | (1ULL << PhpParser::Int64Type)
          | (1ULL << PhpParser::IntType)
          | (1ULL << PhpParser::Interface)
          | (1ULL << PhpParser::IsSet)
          | (1ULL << PhpParser::List)
          | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
          ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
          | (1ULL << (PhpParser::LogicalXor - 64))
          | (1ULL << (PhpParser::Namespace - 64))
          | (1ULL << (PhpParser::New - 64))
          | (1ULL << (PhpParser::Null - 64))
          | (1ULL << (PhpParser::ObjectType - 64))
          | (1ULL << (PhpParser::Parent_ - 64))
          | (1ULL << (PhpParser::Partial - 64))
          | (1ULL << (PhpParser::Print - 64))
          | (1ULL << (PhpParser::Private - 64))
          | (1ULL << (PhpParser::Protected - 64))
          | (1ULL << (PhpParser::Public - 64))
          | (1ULL << (PhpParser::Require - 64))
          | (1ULL << (PhpParser::RequireOnce - 64))
          | (1ULL << (PhpParser::Resource - 64))
          | (1ULL << (PhpParser::Return - 64))
          | (1ULL << (PhpParser::Static - 64))
          | (1ULL << (PhpParser::StringType - 64))
          | (1ULL << (PhpParser::Switch - 64))
          | (1ULL << (PhpParser::Throw - 64))
          | (1ULL << (PhpParser::Trait - 64))
          | (1ULL << (PhpParser::Try - 64))
          | (1ULL << (PhpParser::Typeof - 64))
          | (1ULL << (PhpParser::UintCast - 64))
          | (1ULL << (PhpParser::UnicodeCast - 64))
          | (1ULL << (PhpParser::Unset - 64))
          | (1ULL << (PhpParser::Use - 64))
          | (1ULL << (PhpParser::Var - 64))
          | (1ULL << (PhpParser::While - 64))
          | (1ULL << (PhpParser::Yield - 64))
          | (1ULL << (PhpParser::Get - 64))
          | (1ULL << (PhpParser::Set - 64))
          | (1ULL << (PhpParser::Call - 64))
          | (1ULL << (PhpParser::CallStatic - 64))
          | (1ULL << (PhpParser::Constructor - 64))
          | (1ULL << (PhpParser::Destruct - 64))
          | (1ULL << (PhpParser::Wakeup - 64))
          | (1ULL << (PhpParser::Sleep - 64))
          | (1ULL << (PhpParser::Autoload - 64))
          | (1ULL << (PhpParser::IsSet__ - 64))
          | (1ULL << (PhpParser::Unset__ - 64))
          | (1ULL << (PhpParser::ToString__ - 64))
          | (1ULL << (PhpParser::Invoke - 64))
          | (1ULL << (PhpParser::SetState - 64))
          | (1ULL << (PhpParser::Clone__ - 64))
          | (1ULL << (PhpParser::DebugInfo - 64))
          | (1ULL << (PhpParser::Namespace__ - 64))
          | (1ULL << (PhpParser::Class__ - 64))
          | (1ULL << (PhpParser::Traic__ - 64))
          | (1ULL << (PhpParser::Function__ - 64))
          | (1ULL << (PhpParser::Method__ - 64))
          | (1ULL << (PhpParser::Line__ - 64))
          | (1ULL << (PhpParser::File__ - 64))
          | (1ULL << (PhpParser::Dir__ - 64))
          | (1ULL << (PhpParser::Inc - 64))
          | (1ULL << (PhpParser::Dec - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
          ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
          | (1ULL << (PhpParser::Bang - 148))
          | (1ULL << (PhpParser::Plus - 148))
          | (1ULL << (PhpParser::Minus - 148))
          | (1ULL << (PhpParser::Tilde - 148))
          | (1ULL << (PhpParser::SuppressWarnings - 148))
          | (1ULL << (PhpParser::Dollar - 148))
          | (1ULL << (PhpParser::OpenRoundBracket - 148))
          | (1ULL << (PhpParser::OpenSquareBracket - 148))
          | (1ULL << (PhpParser::VarName - 148))
          | (1ULL << (PhpParser::Label - 148))
          | (1ULL << (PhpParser::Octal - 148))
          | (1ULL << (PhpParser::Decimal - 148))
          | (1ULL << (PhpParser::Real - 148))
          | (1ULL << (PhpParser::Hex - 148))
          | (1ULL << (PhpParser::Binary - 148))
          | (1ULL << (PhpParser::BackQuoteString - 148))
          | (1ULL << (PhpParser::SingleQuoteString - 148))
          | (1ULL << (PhpParser::DoubleQuote - 148))
          | (1ULL << (PhpParser::StartNowDoc - 148))
          | (1ULL << (PhpParser::StartHereDoc - 148)))) != 0)) {
          setState(1497);
          expression(0);
        }
        setState(1500);
        match(PhpParser::CloseSquareBracket);
        break;
      }

      case PhpParser::OpenCurlyBracket: {
        enterOuterAlt(_localctx, 2);
        setState(1501);
        match(PhpParser::OpenCurlyBracket);
        setState(1502);
        expression(0);
        setState(1503);
        match(PhpParser::CloseCurlyBracket);
        break;
      }

    default:
      throw NoViableAltException(this);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- AssignmentListContext ------------------------------------------------------------------

PhpParser::AssignmentListContext::AssignmentListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<PhpParser::AssignmentListElementContext *> PhpParser::AssignmentListContext::assignmentListElement() {
  return getRuleContexts<PhpParser::AssignmentListElementContext>();
}

PhpParser::AssignmentListElementContext* PhpParser::AssignmentListContext::assignmentListElement(size_t i) {
  return getRuleContext<PhpParser::AssignmentListElementContext>(i);
}


size_t PhpParser::AssignmentListContext::getRuleIndex() const {
  return PhpParser::RuleAssignmentList;
}

antlrcpp::Any PhpParser::AssignmentListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitAssignmentList(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::AssignmentListContext* PhpParser::assignmentList() {
  AssignmentListContext *_localctx = _tracker.createInstance<AssignmentListContext>(_ctx, getState());
  enterRule(_localctx, 226, PhpParser::RuleAssignmentList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1508);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
      | (1ULL << PhpParser::Array)
      | (1ULL << PhpParser::As)
      | (1ULL << PhpParser::BinaryCast)
      | (1ULL << PhpParser::BoolType)
      | (1ULL << PhpParser::BooleanConstant)
      | (1ULL << PhpParser::Break)
      | (1ULL << PhpParser::Callable)
      | (1ULL << PhpParser::Case)
      | (1ULL << PhpParser::Catch)
      | (1ULL << PhpParser::Class)
      | (1ULL << PhpParser::Clone)
      | (1ULL << PhpParser::Const)
      | (1ULL << PhpParser::Continue)
      | (1ULL << PhpParser::Declare)
      | (1ULL << PhpParser::Default)
      | (1ULL << PhpParser::Do)
      | (1ULL << PhpParser::DoubleCast)
      | (1ULL << PhpParser::DoubleType)
      | (1ULL << PhpParser::Echo)
      | (1ULL << PhpParser::Else)
      | (1ULL << PhpParser::ElseIf)
      | (1ULL << PhpParser::Empty)
      | (1ULL << PhpParser::EndDeclare)
      | (1ULL << PhpParser::EndFor)
      | (1ULL << PhpParser::EndForeach)
      | (1ULL << PhpParser::EndIf)
      | (1ULL << PhpParser::EndSwitch)
      | (1ULL << PhpParser::EndWhile)
      | (1ULL << PhpParser::Eval)
      | (1ULL << PhpParser::Exit)
      | (1ULL << PhpParser::Extends)
      | (1ULL << PhpParser::Final)
      | (1ULL << PhpParser::Finally)
      | (1ULL << PhpParser::FloatCast)
      | (1ULL << PhpParser::For)
      | (1ULL << PhpParser::Foreach)
      | (1ULL << PhpParser::Function)
      | (1ULL << PhpParser::Global)
      | (1ULL << PhpParser::Goto)
      | (1ULL << PhpParser::If)
      | (1ULL << PhpParser::Implements)
      | (1ULL << PhpParser::Import)
      | (1ULL << PhpParser::Include)
      | (1ULL << PhpParser::IncludeOnce)
      | (1ULL << PhpParser::InstanceOf)
      | (1ULL << PhpParser::InsteadOf)
      | (1ULL << PhpParser::Int8Cast)
      | (1ULL << PhpParser::Int16Cast)
      | (1ULL << PhpParser::Int64Type)
      | (1ULL << PhpParser::IntType)
      | (1ULL << PhpParser::Interface)
      | (1ULL << PhpParser::IsSet)
      | (1ULL << PhpParser::List)
      | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
      | (1ULL << (PhpParser::LogicalXor - 64))
      | (1ULL << (PhpParser::Namespace - 64))
      | (1ULL << (PhpParser::New - 64))
      | (1ULL << (PhpParser::Null - 64))
      | (1ULL << (PhpParser::ObjectType - 64))
      | (1ULL << (PhpParser::Parent_ - 64))
      | (1ULL << (PhpParser::Partial - 64))
      | (1ULL << (PhpParser::Print - 64))
      | (1ULL << (PhpParser::Private - 64))
      | (1ULL << (PhpParser::Protected - 64))
      | (1ULL << (PhpParser::Public - 64))
      | (1ULL << (PhpParser::Require - 64))
      | (1ULL << (PhpParser::RequireOnce - 64))
      | (1ULL << (PhpParser::Resource - 64))
      | (1ULL << (PhpParser::Return - 64))
      | (1ULL << (PhpParser::Static - 64))
      | (1ULL << (PhpParser::StringType - 64))
      | (1ULL << (PhpParser::Switch - 64))
      | (1ULL << (PhpParser::Throw - 64))
      | (1ULL << (PhpParser::Trait - 64))
      | (1ULL << (PhpParser::Try - 64))
      | (1ULL << (PhpParser::Typeof - 64))
      | (1ULL << (PhpParser::UintCast - 64))
      | (1ULL << (PhpParser::UnicodeCast - 64))
      | (1ULL << (PhpParser::Unset - 64))
      | (1ULL << (PhpParser::Use - 64))
      | (1ULL << (PhpParser::Var - 64))
      | (1ULL << (PhpParser::While - 64))
      | (1ULL << (PhpParser::Yield - 64))
      | (1ULL << (PhpParser::Get - 64))
      | (1ULL << (PhpParser::Set - 64))
      | (1ULL << (PhpParser::Call - 64))
      | (1ULL << (PhpParser::CallStatic - 64))
      | (1ULL << (PhpParser::Constructor - 64))
      | (1ULL << (PhpParser::Destruct - 64))
      | (1ULL << (PhpParser::Wakeup - 64))
      | (1ULL << (PhpParser::Sleep - 64))
      | (1ULL << (PhpParser::Autoload - 64))
      | (1ULL << (PhpParser::IsSet__ - 64))
      | (1ULL << (PhpParser::Unset__ - 64))
      | (1ULL << (PhpParser::ToString__ - 64))
      | (1ULL << (PhpParser::Invoke - 64))
      | (1ULL << (PhpParser::SetState - 64))
      | (1ULL << (PhpParser::Clone__ - 64))
      | (1ULL << (PhpParser::DebugInfo - 64))
      | (1ULL << (PhpParser::Namespace__ - 64))
      | (1ULL << (PhpParser::Class__ - 64))
      | (1ULL << (PhpParser::Traic__ - 64))
      | (1ULL << (PhpParser::Function__ - 64))
      | (1ULL << (PhpParser::Method__ - 64))
      | (1ULL << (PhpParser::Line__ - 64))
      | (1ULL << (PhpParser::File__ - 64))
      | (1ULL << (PhpParser::Dir__ - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
      | (1ULL << (PhpParser::Dollar - 148))
      | (1ULL << (PhpParser::OpenRoundBracket - 148))
      | (1ULL << (PhpParser::VarName - 148))
      | (1ULL << (PhpParser::Label - 148)))) != 0)) {
      setState(1507);
      assignmentListElement();
    }
    setState(1516);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == PhpParser::Comma) {
      setState(1510);
      match(PhpParser::Comma);
      setState(1512);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
        | (1ULL << PhpParser::Array)
        | (1ULL << PhpParser::As)
        | (1ULL << PhpParser::BinaryCast)
        | (1ULL << PhpParser::BoolType)
        | (1ULL << PhpParser::BooleanConstant)
        | (1ULL << PhpParser::Break)
        | (1ULL << PhpParser::Callable)
        | (1ULL << PhpParser::Case)
        | (1ULL << PhpParser::Catch)
        | (1ULL << PhpParser::Class)
        | (1ULL << PhpParser::Clone)
        | (1ULL << PhpParser::Const)
        | (1ULL << PhpParser::Continue)
        | (1ULL << PhpParser::Declare)
        | (1ULL << PhpParser::Default)
        | (1ULL << PhpParser::Do)
        | (1ULL << PhpParser::DoubleCast)
        | (1ULL << PhpParser::DoubleType)
        | (1ULL << PhpParser::Echo)
        | (1ULL << PhpParser::Else)
        | (1ULL << PhpParser::ElseIf)
        | (1ULL << PhpParser::Empty)
        | (1ULL << PhpParser::EndDeclare)
        | (1ULL << PhpParser::EndFor)
        | (1ULL << PhpParser::EndForeach)
        | (1ULL << PhpParser::EndIf)
        | (1ULL << PhpParser::EndSwitch)
        | (1ULL << PhpParser::EndWhile)
        | (1ULL << PhpParser::Eval)
        | (1ULL << PhpParser::Exit)
        | (1ULL << PhpParser::Extends)
        | (1ULL << PhpParser::Final)
        | (1ULL << PhpParser::Finally)
        | (1ULL << PhpParser::FloatCast)
        | (1ULL << PhpParser::For)
        | (1ULL << PhpParser::Foreach)
        | (1ULL << PhpParser::Function)
        | (1ULL << PhpParser::Global)
        | (1ULL << PhpParser::Goto)
        | (1ULL << PhpParser::If)
        | (1ULL << PhpParser::Implements)
        | (1ULL << PhpParser::Import)
        | (1ULL << PhpParser::Include)
        | (1ULL << PhpParser::IncludeOnce)
        | (1ULL << PhpParser::InstanceOf)
        | (1ULL << PhpParser::InsteadOf)
        | (1ULL << PhpParser::Int8Cast)
        | (1ULL << PhpParser::Int16Cast)
        | (1ULL << PhpParser::Int64Type)
        | (1ULL << PhpParser::IntType)
        | (1ULL << PhpParser::Interface)
        | (1ULL << PhpParser::IsSet)
        | (1ULL << PhpParser::List)
        | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
        | (1ULL << (PhpParser::LogicalXor - 64))
        | (1ULL << (PhpParser::Namespace - 64))
        | (1ULL << (PhpParser::New - 64))
        | (1ULL << (PhpParser::Null - 64))
        | (1ULL << (PhpParser::ObjectType - 64))
        | (1ULL << (PhpParser::Parent_ - 64))
        | (1ULL << (PhpParser::Partial - 64))
        | (1ULL << (PhpParser::Print - 64))
        | (1ULL << (PhpParser::Private - 64))
        | (1ULL << (PhpParser::Protected - 64))
        | (1ULL << (PhpParser::Public - 64))
        | (1ULL << (PhpParser::Require - 64))
        | (1ULL << (PhpParser::RequireOnce - 64))
        | (1ULL << (PhpParser::Resource - 64))
        | (1ULL << (PhpParser::Return - 64))
        | (1ULL << (PhpParser::Static - 64))
        | (1ULL << (PhpParser::StringType - 64))
        | (1ULL << (PhpParser::Switch - 64))
        | (1ULL << (PhpParser::Throw - 64))
        | (1ULL << (PhpParser::Trait - 64))
        | (1ULL << (PhpParser::Try - 64))
        | (1ULL << (PhpParser::Typeof - 64))
        | (1ULL << (PhpParser::UintCast - 64))
        | (1ULL << (PhpParser::UnicodeCast - 64))
        | (1ULL << (PhpParser::Unset - 64))
        | (1ULL << (PhpParser::Use - 64))
        | (1ULL << (PhpParser::Var - 64))
        | (1ULL << (PhpParser::While - 64))
        | (1ULL << (PhpParser::Yield - 64))
        | (1ULL << (PhpParser::Get - 64))
        | (1ULL << (PhpParser::Set - 64))
        | (1ULL << (PhpParser::Call - 64))
        | (1ULL << (PhpParser::CallStatic - 64))
        | (1ULL << (PhpParser::Constructor - 64))
        | (1ULL << (PhpParser::Destruct - 64))
        | (1ULL << (PhpParser::Wakeup - 64))
        | (1ULL << (PhpParser::Sleep - 64))
        | (1ULL << (PhpParser::Autoload - 64))
        | (1ULL << (PhpParser::IsSet__ - 64))
        | (1ULL << (PhpParser::Unset__ - 64))
        | (1ULL << (PhpParser::ToString__ - 64))
        | (1ULL << (PhpParser::Invoke - 64))
        | (1ULL << (PhpParser::SetState - 64))
        | (1ULL << (PhpParser::Clone__ - 64))
        | (1ULL << (PhpParser::DebugInfo - 64))
        | (1ULL << (PhpParser::Namespace__ - 64))
        | (1ULL << (PhpParser::Class__ - 64))
        | (1ULL << (PhpParser::Traic__ - 64))
        | (1ULL << (PhpParser::Function__ - 64))
        | (1ULL << (PhpParser::Method__ - 64))
        | (1ULL << (PhpParser::Line__ - 64))
        | (1ULL << (PhpParser::File__ - 64))
        | (1ULL << (PhpParser::Dir__ - 64)))) != 0) || ((((_la - 148) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 148)) & ((1ULL << (PhpParser::NamespaceSeparator - 148))
        | (1ULL << (PhpParser::Dollar - 148))
        | (1ULL << (PhpParser::OpenRoundBracket - 148))
        | (1ULL << (PhpParser::VarName - 148))
        | (1ULL << (PhpParser::Label - 148)))) != 0)) {
        setState(1511);
        assignmentListElement();
      }
      setState(1518);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- AssignmentListElementContext ------------------------------------------------------------------

PhpParser::AssignmentListElementContext::AssignmentListElementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

PhpParser::ChainContext* PhpParser::AssignmentListElementContext::chain() {
  return getRuleContext<PhpParser::ChainContext>(0);
}

tree::TerminalNode* PhpParser::AssignmentListElementContext::List() {
  return getToken(PhpParser::List, 0);
}

PhpParser::AssignmentListContext* PhpParser::AssignmentListElementContext::assignmentList() {
  return getRuleContext<PhpParser::AssignmentListContext>(0);
}


size_t PhpParser::AssignmentListElementContext::getRuleIndex() const {
  return PhpParser::RuleAssignmentListElement;
}

antlrcpp::Any PhpParser::AssignmentListElementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitAssignmentListElement(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::AssignmentListElementContext* PhpParser::assignmentListElement() {
  AssignmentListElementContext *_localctx = _tracker.createInstance<AssignmentListElementContext>(_ctx, getState());
  enterRule(_localctx, 228, PhpParser::RuleAssignmentListElement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1525);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 174, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(1519);
      chain();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(1520);
      match(PhpParser::List);
      setState(1521);
      match(PhpParser::OpenRoundBracket);
      setState(1522);
      assignmentList();
      setState(1523);
      match(PhpParser::CloseRoundBracket);
      break;
    }

    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ModifierContext ------------------------------------------------------------------

PhpParser::ModifierContext::ModifierContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::ModifierContext::Abstract() {
  return getToken(PhpParser::Abstract, 0);
}

tree::TerminalNode* PhpParser::ModifierContext::Final() {
  return getToken(PhpParser::Final, 0);
}


size_t PhpParser::ModifierContext::getRuleIndex() const {
  return PhpParser::RuleModifier;
}

antlrcpp::Any PhpParser::ModifierContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitModifier(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::ModifierContext* PhpParser::modifier() {
  ModifierContext *_localctx = _tracker.createInstance<ModifierContext>(_ctx, getState());
  enterRule(_localctx, 230, PhpParser::RuleModifier);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1527);
    _la = _input->LA(1);
    if (!(_la == PhpParser::Abstract

    || _la == PhpParser::Final)) {
    _errHandler->recoverInline(this);
    }
    else {
      _errHandler->reportMatch(this);
      consume();
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- IdentifierContext ------------------------------------------------------------------

PhpParser::IdentifierContext::IdentifierContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::IdentifierContext::Label() {
  return getToken(PhpParser::Label, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Abstract() {
  return getToken(PhpParser::Abstract, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Array() {
  return getToken(PhpParser::Array, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::As() {
  return getToken(PhpParser::As, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::BinaryCast() {
  return getToken(PhpParser::BinaryCast, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::BoolType() {
  return getToken(PhpParser::BoolType, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::BooleanConstant() {
  return getToken(PhpParser::BooleanConstant, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Break() {
  return getToken(PhpParser::Break, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Callable() {
  return getToken(PhpParser::Callable, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Case() {
  return getToken(PhpParser::Case, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Catch() {
  return getToken(PhpParser::Catch, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Class() {
  return getToken(PhpParser::Class, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Clone() {
  return getToken(PhpParser::Clone, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Const() {
  return getToken(PhpParser::Const, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Continue() {
  return getToken(PhpParser::Continue, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Declare() {
  return getToken(PhpParser::Declare, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Default() {
  return getToken(PhpParser::Default, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Do() {
  return getToken(PhpParser::Do, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::DoubleCast() {
  return getToken(PhpParser::DoubleCast, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::DoubleType() {
  return getToken(PhpParser::DoubleType, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Echo() {
  return getToken(PhpParser::Echo, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Else() {
  return getToken(PhpParser::Else, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::ElseIf() {
  return getToken(PhpParser::ElseIf, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Empty() {
  return getToken(PhpParser::Empty, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::EndDeclare() {
  return getToken(PhpParser::EndDeclare, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::EndFor() {
  return getToken(PhpParser::EndFor, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::EndForeach() {
  return getToken(PhpParser::EndForeach, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::EndIf() {
  return getToken(PhpParser::EndIf, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::EndSwitch() {
  return getToken(PhpParser::EndSwitch, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::EndWhile() {
  return getToken(PhpParser::EndWhile, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Eval() {
  return getToken(PhpParser::Eval, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Exit() {
  return getToken(PhpParser::Exit, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Extends() {
  return getToken(PhpParser::Extends, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Final() {
  return getToken(PhpParser::Final, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Finally() {
  return getToken(PhpParser::Finally, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::FloatCast() {
  return getToken(PhpParser::FloatCast, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::For() {
  return getToken(PhpParser::For, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Foreach() {
  return getToken(PhpParser::Foreach, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Function() {
  return getToken(PhpParser::Function, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Global() {
  return getToken(PhpParser::Global, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Goto() {
  return getToken(PhpParser::Goto, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::If() {
  return getToken(PhpParser::If, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Implements() {
  return getToken(PhpParser::Implements, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Import() {
  return getToken(PhpParser::Import, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Include() {
  return getToken(PhpParser::Include, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::IncludeOnce() {
  return getToken(PhpParser::IncludeOnce, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::InstanceOf() {
  return getToken(PhpParser::InstanceOf, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::InsteadOf() {
  return getToken(PhpParser::InsteadOf, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Int16Cast() {
  return getToken(PhpParser::Int16Cast, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Int64Type() {
  return getToken(PhpParser::Int64Type, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Int8Cast() {
  return getToken(PhpParser::Int8Cast, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Interface() {
  return getToken(PhpParser::Interface, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::IntType() {
  return getToken(PhpParser::IntType, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::IsSet() {
  return getToken(PhpParser::IsSet, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::List() {
  return getToken(PhpParser::List, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::LogicalAnd() {
  return getToken(PhpParser::LogicalAnd, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::LogicalOr() {
  return getToken(PhpParser::LogicalOr, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::LogicalXor() {
  return getToken(PhpParser::LogicalXor, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Namespace() {
  return getToken(PhpParser::Namespace, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::New() {
  return getToken(PhpParser::New, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Null() {
  return getToken(PhpParser::Null, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::ObjectType() {
  return getToken(PhpParser::ObjectType, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Parent_() {
  return getToken(PhpParser::Parent_, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Partial() {
  return getToken(PhpParser::Partial, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Print() {
  return getToken(PhpParser::Print, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Private() {
  return getToken(PhpParser::Private, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Protected() {
  return getToken(PhpParser::Protected, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Public() {
  return getToken(PhpParser::Public, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Require() {
  return getToken(PhpParser::Require, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::RequireOnce() {
  return getToken(PhpParser::RequireOnce, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Resource() {
  return getToken(PhpParser::Resource, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Return() {
  return getToken(PhpParser::Return, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Static() {
  return getToken(PhpParser::Static, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::StringType() {
  return getToken(PhpParser::StringType, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Switch() {
  return getToken(PhpParser::Switch, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Throw() {
  return getToken(PhpParser::Throw, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Trait() {
  return getToken(PhpParser::Trait, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Try() {
  return getToken(PhpParser::Try, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Typeof() {
  return getToken(PhpParser::Typeof, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::UintCast() {
  return getToken(PhpParser::UintCast, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::UnicodeCast() {
  return getToken(PhpParser::UnicodeCast, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Unset() {
  return getToken(PhpParser::Unset, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Use() {
  return getToken(PhpParser::Use, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Var() {
  return getToken(PhpParser::Var, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::While() {
  return getToken(PhpParser::While, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Yield() {
  return getToken(PhpParser::Yield, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Get() {
  return getToken(PhpParser::Get, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Set() {
  return getToken(PhpParser::Set, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Call() {
  return getToken(PhpParser::Call, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::CallStatic() {
  return getToken(PhpParser::CallStatic, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Constructor() {
  return getToken(PhpParser::Constructor, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Destruct() {
  return getToken(PhpParser::Destruct, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Wakeup() {
  return getToken(PhpParser::Wakeup, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Sleep() {
  return getToken(PhpParser::Sleep, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Autoload() {
  return getToken(PhpParser::Autoload, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::IsSet__() {
  return getToken(PhpParser::IsSet__, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Unset__() {
  return getToken(PhpParser::Unset__, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::ToString__() {
  return getToken(PhpParser::ToString__, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Invoke() {
  return getToken(PhpParser::Invoke, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::SetState() {
  return getToken(PhpParser::SetState, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Clone__() {
  return getToken(PhpParser::Clone__, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::DebugInfo() {
  return getToken(PhpParser::DebugInfo, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Namespace__() {
  return getToken(PhpParser::Namespace__, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Class__() {
  return getToken(PhpParser::Class__, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Traic__() {
  return getToken(PhpParser::Traic__, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Function__() {
  return getToken(PhpParser::Function__, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Method__() {
  return getToken(PhpParser::Method__, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Line__() {
  return getToken(PhpParser::Line__, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::File__() {
  return getToken(PhpParser::File__, 0);
}

tree::TerminalNode* PhpParser::IdentifierContext::Dir__() {
  return getToken(PhpParser::Dir__, 0);
}


size_t PhpParser::IdentifierContext::getRuleIndex() const {
  return PhpParser::RuleIdentifier;
}

antlrcpp::Any PhpParser::IdentifierContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitIdentifier(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::IdentifierContext* PhpParser::identifier() {
  IdentifierContext *_localctx = _tracker.createInstance<IdentifierContext>(_ctx, getState());
  enterRule(_localctx, 232, PhpParser::RuleIdentifier);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1529);
    _la = _input->LA(1);
    if (!((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << PhpParser::Abstract)
      | (1ULL << PhpParser::Array)
      | (1ULL << PhpParser::As)
      | (1ULL << PhpParser::BinaryCast)
      | (1ULL << PhpParser::BoolType)
      | (1ULL << PhpParser::BooleanConstant)
      | (1ULL << PhpParser::Break)
      | (1ULL << PhpParser::Callable)
      | (1ULL << PhpParser::Case)
      | (1ULL << PhpParser::Catch)
      | (1ULL << PhpParser::Class)
      | (1ULL << PhpParser::Clone)
      | (1ULL << PhpParser::Const)
      | (1ULL << PhpParser::Continue)
      | (1ULL << PhpParser::Declare)
      | (1ULL << PhpParser::Default)
      | (1ULL << PhpParser::Do)
      | (1ULL << PhpParser::DoubleCast)
      | (1ULL << PhpParser::DoubleType)
      | (1ULL << PhpParser::Echo)
      | (1ULL << PhpParser::Else)
      | (1ULL << PhpParser::ElseIf)
      | (1ULL << PhpParser::Empty)
      | (1ULL << PhpParser::EndDeclare)
      | (1ULL << PhpParser::EndFor)
      | (1ULL << PhpParser::EndForeach)
      | (1ULL << PhpParser::EndIf)
      | (1ULL << PhpParser::EndSwitch)
      | (1ULL << PhpParser::EndWhile)
      | (1ULL << PhpParser::Eval)
      | (1ULL << PhpParser::Exit)
      | (1ULL << PhpParser::Extends)
      | (1ULL << PhpParser::Final)
      | (1ULL << PhpParser::Finally)
      | (1ULL << PhpParser::FloatCast)
      | (1ULL << PhpParser::For)
      | (1ULL << PhpParser::Foreach)
      | (1ULL << PhpParser::Function)
      | (1ULL << PhpParser::Global)
      | (1ULL << PhpParser::Goto)
      | (1ULL << PhpParser::If)
      | (1ULL << PhpParser::Implements)
      | (1ULL << PhpParser::Import)
      | (1ULL << PhpParser::Include)
      | (1ULL << PhpParser::IncludeOnce)
      | (1ULL << PhpParser::InstanceOf)
      | (1ULL << PhpParser::InsteadOf)
      | (1ULL << PhpParser::Int8Cast)
      | (1ULL << PhpParser::Int16Cast)
      | (1ULL << PhpParser::Int64Type)
      | (1ULL << PhpParser::IntType)
      | (1ULL << PhpParser::Interface)
      | (1ULL << PhpParser::IsSet)
      | (1ULL << PhpParser::List)
      | (1ULL << PhpParser::LogicalAnd))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (PhpParser::LogicalOr - 64))
      | (1ULL << (PhpParser::LogicalXor - 64))
      | (1ULL << (PhpParser::Namespace - 64))
      | (1ULL << (PhpParser::New - 64))
      | (1ULL << (PhpParser::Null - 64))
      | (1ULL << (PhpParser::ObjectType - 64))
      | (1ULL << (PhpParser::Parent_ - 64))
      | (1ULL << (PhpParser::Partial - 64))
      | (1ULL << (PhpParser::Print - 64))
      | (1ULL << (PhpParser::Private - 64))
      | (1ULL << (PhpParser::Protected - 64))
      | (1ULL << (PhpParser::Public - 64))
      | (1ULL << (PhpParser::Require - 64))
      | (1ULL << (PhpParser::RequireOnce - 64))
      | (1ULL << (PhpParser::Resource - 64))
      | (1ULL << (PhpParser::Return - 64))
      | (1ULL << (PhpParser::Static - 64))
      | (1ULL << (PhpParser::StringType - 64))
      | (1ULL << (PhpParser::Switch - 64))
      | (1ULL << (PhpParser::Throw - 64))
      | (1ULL << (PhpParser::Trait - 64))
      | (1ULL << (PhpParser::Try - 64))
      | (1ULL << (PhpParser::Typeof - 64))
      | (1ULL << (PhpParser::UintCast - 64))
      | (1ULL << (PhpParser::UnicodeCast - 64))
      | (1ULL << (PhpParser::Unset - 64))
      | (1ULL << (PhpParser::Use - 64))
      | (1ULL << (PhpParser::Var - 64))
      | (1ULL << (PhpParser::While - 64))
      | (1ULL << (PhpParser::Yield - 64))
      | (1ULL << (PhpParser::Get - 64))
      | (1ULL << (PhpParser::Set - 64))
      | (1ULL << (PhpParser::Call - 64))
      | (1ULL << (PhpParser::CallStatic - 64))
      | (1ULL << (PhpParser::Constructor - 64))
      | (1ULL << (PhpParser::Destruct - 64))
      | (1ULL << (PhpParser::Wakeup - 64))
      | (1ULL << (PhpParser::Sleep - 64))
      | (1ULL << (PhpParser::Autoload - 64))
      | (1ULL << (PhpParser::IsSet__ - 64))
      | (1ULL << (PhpParser::Unset__ - 64))
      | (1ULL << (PhpParser::ToString__ - 64))
      | (1ULL << (PhpParser::Invoke - 64))
      | (1ULL << (PhpParser::SetState - 64))
      | (1ULL << (PhpParser::Clone__ - 64))
      | (1ULL << (PhpParser::DebugInfo - 64))
      | (1ULL << (PhpParser::Namespace__ - 64))
      | (1ULL << (PhpParser::Class__ - 64))
      | (1ULL << (PhpParser::Traic__ - 64))
      | (1ULL << (PhpParser::Function__ - 64))
      | (1ULL << (PhpParser::Method__ - 64))
      | (1ULL << (PhpParser::Line__ - 64))
      | (1ULL << (PhpParser::File__ - 64))
      | (1ULL << (PhpParser::Dir__ - 64)))) != 0) || _la == PhpParser::Label)) {
    _errHandler->recoverInline(this);
    }
    else {
      _errHandler->reportMatch(this);
      consume();
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- MemberModifierContext ------------------------------------------------------------------

PhpParser::MemberModifierContext::MemberModifierContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::MemberModifierContext::Public() {
  return getToken(PhpParser::Public, 0);
}

tree::TerminalNode* PhpParser::MemberModifierContext::Protected() {
  return getToken(PhpParser::Protected, 0);
}

tree::TerminalNode* PhpParser::MemberModifierContext::Private() {
  return getToken(PhpParser::Private, 0);
}

tree::TerminalNode* PhpParser::MemberModifierContext::Static() {
  return getToken(PhpParser::Static, 0);
}

tree::TerminalNode* PhpParser::MemberModifierContext::Abstract() {
  return getToken(PhpParser::Abstract, 0);
}

tree::TerminalNode* PhpParser::MemberModifierContext::Final() {
  return getToken(PhpParser::Final, 0);
}


size_t PhpParser::MemberModifierContext::getRuleIndex() const {
  return PhpParser::RuleMemberModifier;
}

antlrcpp::Any PhpParser::MemberModifierContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitMemberModifier(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::MemberModifierContext* PhpParser::memberModifier() {
  MemberModifierContext *_localctx = _tracker.createInstance<MemberModifierContext>(_ctx, getState());
  enterRule(_localctx, 234, PhpParser::RuleMemberModifier);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1531);
    _la = _input->LA(1);
    if (!(_la == PhpParser::Abstract

    || _la == PhpParser::Final || ((((_la - 73) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 73)) & ((1ULL << (PhpParser::Private - 73))
      | (1ULL << (PhpParser::Protected - 73))
      | (1ULL << (PhpParser::Public - 73))
      | (1ULL << (PhpParser::Static - 73)))) != 0))) {
    _errHandler->recoverInline(this);
    }
    else {
      _errHandler->reportMatch(this);
      consume();
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- MagicConstantContext ------------------------------------------------------------------

PhpParser::MagicConstantContext::MagicConstantContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::MagicConstantContext::Namespace__() {
  return getToken(PhpParser::Namespace__, 0);
}

tree::TerminalNode* PhpParser::MagicConstantContext::Class__() {
  return getToken(PhpParser::Class__, 0);
}

tree::TerminalNode* PhpParser::MagicConstantContext::Traic__() {
  return getToken(PhpParser::Traic__, 0);
}

tree::TerminalNode* PhpParser::MagicConstantContext::Function__() {
  return getToken(PhpParser::Function__, 0);
}

tree::TerminalNode* PhpParser::MagicConstantContext::Method__() {
  return getToken(PhpParser::Method__, 0);
}

tree::TerminalNode* PhpParser::MagicConstantContext::Line__() {
  return getToken(PhpParser::Line__, 0);
}

tree::TerminalNode* PhpParser::MagicConstantContext::File__() {
  return getToken(PhpParser::File__, 0);
}

tree::TerminalNode* PhpParser::MagicConstantContext::Dir__() {
  return getToken(PhpParser::Dir__, 0);
}


size_t PhpParser::MagicConstantContext::getRuleIndex() const {
  return PhpParser::RuleMagicConstant;
}

antlrcpp::Any PhpParser::MagicConstantContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitMagicConstant(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::MagicConstantContext* PhpParser::magicConstant() {
  MagicConstantContext *_localctx = _tracker.createInstance<MagicConstantContext>(_ctx, getState());
  enterRule(_localctx, 236, PhpParser::RuleMagicConstant);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1533);
    _la = _input->LA(1);
    if (!(((((_la - 110) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 110)) & ((1ULL << (PhpParser::Namespace__ - 110))
      | (1ULL << (PhpParser::Class__ - 110))
      | (1ULL << (PhpParser::Traic__ - 110))
      | (1ULL << (PhpParser::Function__ - 110))
      | (1ULL << (PhpParser::Method__ - 110))
      | (1ULL << (PhpParser::Line__ - 110))
      | (1ULL << (PhpParser::File__ - 110))
      | (1ULL << (PhpParser::Dir__ - 110)))) != 0))) {
    _errHandler->recoverInline(this);
    }
    else {
      _errHandler->reportMatch(this);
      consume();
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- MagicMethodContext ------------------------------------------------------------------

PhpParser::MagicMethodContext::MagicMethodContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::MagicMethodContext::Get() {
  return getToken(PhpParser::Get, 0);
}

tree::TerminalNode* PhpParser::MagicMethodContext::Set() {
  return getToken(PhpParser::Set, 0);
}

tree::TerminalNode* PhpParser::MagicMethodContext::Call() {
  return getToken(PhpParser::Call, 0);
}

tree::TerminalNode* PhpParser::MagicMethodContext::CallStatic() {
  return getToken(PhpParser::CallStatic, 0);
}

tree::TerminalNode* PhpParser::MagicMethodContext::Constructor() {
  return getToken(PhpParser::Constructor, 0);
}

tree::TerminalNode* PhpParser::MagicMethodContext::Destruct() {
  return getToken(PhpParser::Destruct, 0);
}

tree::TerminalNode* PhpParser::MagicMethodContext::Wakeup() {
  return getToken(PhpParser::Wakeup, 0);
}

tree::TerminalNode* PhpParser::MagicMethodContext::Sleep() {
  return getToken(PhpParser::Sleep, 0);
}

tree::TerminalNode* PhpParser::MagicMethodContext::Autoload() {
  return getToken(PhpParser::Autoload, 0);
}

tree::TerminalNode* PhpParser::MagicMethodContext::IsSet__() {
  return getToken(PhpParser::IsSet__, 0);
}

tree::TerminalNode* PhpParser::MagicMethodContext::Unset__() {
  return getToken(PhpParser::Unset__, 0);
}

tree::TerminalNode* PhpParser::MagicMethodContext::ToString__() {
  return getToken(PhpParser::ToString__, 0);
}

tree::TerminalNode* PhpParser::MagicMethodContext::Invoke() {
  return getToken(PhpParser::Invoke, 0);
}

tree::TerminalNode* PhpParser::MagicMethodContext::SetState() {
  return getToken(PhpParser::SetState, 0);
}

tree::TerminalNode* PhpParser::MagicMethodContext::Clone__() {
  return getToken(PhpParser::Clone__, 0);
}

tree::TerminalNode* PhpParser::MagicMethodContext::DebugInfo() {
  return getToken(PhpParser::DebugInfo, 0);
}


size_t PhpParser::MagicMethodContext::getRuleIndex() const {
  return PhpParser::RuleMagicMethod;
}

antlrcpp::Any PhpParser::MagicMethodContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitMagicMethod(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::MagicMethodContext* PhpParser::magicMethod() {
  MagicMethodContext *_localctx = _tracker.createInstance<MagicMethodContext>(_ctx, getState());
  enterRule(_localctx, 238, PhpParser::RuleMagicMethod);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1535);
    _la = _input->LA(1);
    if (!(((((_la - 94) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 94)) & ((1ULL << (PhpParser::Get - 94))
      | (1ULL << (PhpParser::Set - 94))
      | (1ULL << (PhpParser::Call - 94))
      | (1ULL << (PhpParser::CallStatic - 94))
      | (1ULL << (PhpParser::Constructor - 94))
      | (1ULL << (PhpParser::Destruct - 94))
      | (1ULL << (PhpParser::Wakeup - 94))
      | (1ULL << (PhpParser::Sleep - 94))
      | (1ULL << (PhpParser::Autoload - 94))
      | (1ULL << (PhpParser::IsSet__ - 94))
      | (1ULL << (PhpParser::Unset__ - 94))
      | (1ULL << (PhpParser::ToString__ - 94))
      | (1ULL << (PhpParser::Invoke - 94))
      | (1ULL << (PhpParser::SetState - 94))
      | (1ULL << (PhpParser::Clone__ - 94))
      | (1ULL << (PhpParser::DebugInfo - 94)))) != 0))) {
    _errHandler->recoverInline(this);
    }
    else {
      _errHandler->reportMatch(this);
      consume();
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- PrimitiveTypeContext ------------------------------------------------------------------

PhpParser::PrimitiveTypeContext::PrimitiveTypeContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::PrimitiveTypeContext::BoolType() {
  return getToken(PhpParser::BoolType, 0);
}

tree::TerminalNode* PhpParser::PrimitiveTypeContext::IntType() {
  return getToken(PhpParser::IntType, 0);
}

tree::TerminalNode* PhpParser::PrimitiveTypeContext::Int64Type() {
  return getToken(PhpParser::Int64Type, 0);
}

tree::TerminalNode* PhpParser::PrimitiveTypeContext::DoubleType() {
  return getToken(PhpParser::DoubleType, 0);
}

tree::TerminalNode* PhpParser::PrimitiveTypeContext::StringType() {
  return getToken(PhpParser::StringType, 0);
}

tree::TerminalNode* PhpParser::PrimitiveTypeContext::Resource() {
  return getToken(PhpParser::Resource, 0);
}

tree::TerminalNode* PhpParser::PrimitiveTypeContext::ObjectType() {
  return getToken(PhpParser::ObjectType, 0);
}

tree::TerminalNode* PhpParser::PrimitiveTypeContext::Array() {
  return getToken(PhpParser::Array, 0);
}


size_t PhpParser::PrimitiveTypeContext::getRuleIndex() const {
  return PhpParser::RulePrimitiveType;
}

antlrcpp::Any PhpParser::PrimitiveTypeContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitPrimitiveType(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::PrimitiveTypeContext* PhpParser::primitiveType() {
  PrimitiveTypeContext *_localctx = _tracker.createInstance<PrimitiveTypeContext>(_ctx, getState());
  enterRule(_localctx, 240, PhpParser::RulePrimitiveType);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1537);
    _la = _input->LA(1);
    if (!((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << PhpParser::Array)
      | (1ULL << PhpParser::BoolType)
      | (1ULL << PhpParser::DoubleType)
      | (1ULL << PhpParser::Int64Type)
      | (1ULL << PhpParser::IntType))) != 0) || ((((_la - 69) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 69)) & ((1ULL << (PhpParser::ObjectType - 69))
      | (1ULL << (PhpParser::Resource - 69))
      | (1ULL << (PhpParser::StringType - 69)))) != 0))) {
    _errHandler->recoverInline(this);
    }
    else {
      _errHandler->reportMatch(this);
      consume();
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- CastOperationContext ------------------------------------------------------------------

PhpParser::CastOperationContext::CastOperationContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* PhpParser::CastOperationContext::BoolType() {
  return getToken(PhpParser::BoolType, 0);
}

tree::TerminalNode* PhpParser::CastOperationContext::Int8Cast() {
  return getToken(PhpParser::Int8Cast, 0);
}

tree::TerminalNode* PhpParser::CastOperationContext::Int16Cast() {
  return getToken(PhpParser::Int16Cast, 0);
}

tree::TerminalNode* PhpParser::CastOperationContext::IntType() {
  return getToken(PhpParser::IntType, 0);
}

tree::TerminalNode* PhpParser::CastOperationContext::Int64Type() {
  return getToken(PhpParser::Int64Type, 0);
}

tree::TerminalNode* PhpParser::CastOperationContext::UintCast() {
  return getToken(PhpParser::UintCast, 0);
}

tree::TerminalNode* PhpParser::CastOperationContext::DoubleCast() {
  return getToken(PhpParser::DoubleCast, 0);
}

tree::TerminalNode* PhpParser::CastOperationContext::DoubleType() {
  return getToken(PhpParser::DoubleType, 0);
}

tree::TerminalNode* PhpParser::CastOperationContext::FloatCast() {
  return getToken(PhpParser::FloatCast, 0);
}

tree::TerminalNode* PhpParser::CastOperationContext::StringType() {
  return getToken(PhpParser::StringType, 0);
}

tree::TerminalNode* PhpParser::CastOperationContext::BinaryCast() {
  return getToken(PhpParser::BinaryCast, 0);
}

tree::TerminalNode* PhpParser::CastOperationContext::UnicodeCast() {
  return getToken(PhpParser::UnicodeCast, 0);
}

tree::TerminalNode* PhpParser::CastOperationContext::Array() {
  return getToken(PhpParser::Array, 0);
}

tree::TerminalNode* PhpParser::CastOperationContext::ObjectType() {
  return getToken(PhpParser::ObjectType, 0);
}

tree::TerminalNode* PhpParser::CastOperationContext::Resource() {
  return getToken(PhpParser::Resource, 0);
}

tree::TerminalNode* PhpParser::CastOperationContext::Unset() {
  return getToken(PhpParser::Unset, 0);
}


size_t PhpParser::CastOperationContext::getRuleIndex() const {
  return PhpParser::RuleCastOperation;
}

antlrcpp::Any PhpParser::CastOperationContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<PhpParserVisitor*>(visitor))
    return parserVisitor->visitCastOperation(this);
  else
    return visitor->visitChildren(this);
}

PhpParser::CastOperationContext* PhpParser::castOperation() {
  CastOperationContext *_localctx = _tracker.createInstance<CastOperationContext>(_ctx, getState());
  enterRule(_localctx, 242, PhpParser::RuleCastOperation);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1539);
    _la = _input->LA(1);
    if (!((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << PhpParser::Array)
      | (1ULL << PhpParser::BinaryCast)
      | (1ULL << PhpParser::BoolType)
      | (1ULL << PhpParser::DoubleCast)
      | (1ULL << PhpParser::DoubleType)
      | (1ULL << PhpParser::FloatCast)
      | (1ULL << PhpParser::Int8Cast)
      | (1ULL << PhpParser::Int16Cast)
      | (1ULL << PhpParser::Int64Type)
      | (1ULL << PhpParser::IntType))) != 0) || ((((_la - 69) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 69)) & ((1ULL << (PhpParser::ObjectType - 69))
      | (1ULL << (PhpParser::Resource - 69))
      | (1ULL << (PhpParser::StringType - 69))
      | (1ULL << (PhpParser::UintCast - 69))
      | (1ULL << (PhpParser::UnicodeCast - 69))
      | (1ULL << (PhpParser::Unset - 69)))) != 0))) {
    _errHandler->recoverInline(this);
    }
    else {
      _errHandler->reportMatch(this);
      consume();
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

bool PhpParser::sempred(RuleContext *context, size_t ruleIndex, size_t predicateIndex) {
  switch (ruleIndex) {
    case 76: return expressionSempred(dynamic_cast<ExpressionContext *>(context), predicateIndex);

  default:
    break;
  }
  return true;
}

bool PhpParser::expressionSempred(ExpressionContext *_localctx, size_t predicateIndex) {
  switch (predicateIndex) {
    case 0: return precpred(_ctx, 18);
    case 1: return precpred(_ctx, 16);
    case 2: return precpred(_ctx, 15);
    case 3: return precpred(_ctx, 14);
    case 4: return precpred(_ctx, 13);
    case 5: return precpred(_ctx, 12);
    case 6: return precpred(_ctx, 11);
    case 7: return precpred(_ctx, 10);
    case 8: return precpred(_ctx, 9);
    case 9: return precpred(_ctx, 8);
    case 10: return precpred(_ctx, 7);
    case 11: return precpred(_ctx, 6);
    case 12: return precpred(_ctx, 3);
    case 13: return precpred(_ctx, 2);
    case 14: return precpred(_ctx, 1);
    case 15: return precpred(_ctx, 17);

  default:
    break;
  }
  return true;
}

// Static vars and initialization.
std::vector<dfa::DFA> PhpParser::_decisionToDFA;
atn::PredictionContextCache PhpParser::_sharedContextCache;

// We own the ATN which in turn owns the ATN states.
atn::ATN PhpParser::_atn;
std::vector<uint16_t> PhpParser::_serializedATN;

std::vector<std::string> PhpParser::_ruleNames = {
  "phpBlock", "importStatement", "topStatement", "useDeclaration", "useDeclarationContentList", 
  "useDeclarationContent", "namespaceDeclaration", "namespaceStatement", 
  "functionDeclaration", "classDeclaration", "classEntryType", "interfaceList", 
  "typeParameterListInBrackets", "typeParameterList", "typeParameterWithDefaultsList", 
  "typeParameterDecl", "typeParameterWithDefaultDecl", "genericDynamicArgs", 
  "attributes", "attributesGroup", "attribute", "attributeArgList", "attributeNamedArgList", 
  "attributeNamedArg", "innerStatementList", "innerStatement", "statement", 
  "emptyStatement", "blockStatement", "ifStatement", "elseIfStatement", 
  "elseIfColonStatement", "elseStatement", "elseColonStatement", "whileStatement", 
  "doWhileStatement", "forStatement", "forInit", "forUpdate", "switchStatement", 
  "switchBlock", "breakStatement", "continueStatement", "returnStatement", 
  "expressionStatement", "unsetStatement", "foreachStatement", "tryCatchFinally", 
  "catchClause", "finallyStatement", "throwStatement", "gotoStatement", 
  "declareStatement", "declareList", "formalParameterList", "formalParameter", 
  "typeHint", "globalStatement", "globalVar", "echoStatement", "staticVariableStatement", 
  "classStatement", "traitAdaptations", "traitAdaptationStatement", "traitPrecedence", 
  "traitAlias", "traitMethodReference", "baseCtorCall", "methodBody", "propertyModifiers", 
  "memberModifiers", "variableInitializer", "identifierInititalizer", "globalConstantDeclaration", 
  "expressionList", "parenthesis", "expression", "newExpr", "assignmentOperator", 
  "yieldExpression", "arrayItemList", "arrayItem", "lambdaFunctionUseVars", 
  "lambdaFunctionUseVar", "qualifiedStaticTypeRef", "typeRef", "indirectTypeRef", 
  "qualifiedNamespaceName", "namespaceNameList", "qualifiedNamespaceNameList", 
  "arguments", "actualArgument", "constantInititalizer", "constantArrayItemList", 
  "constantArrayItem", "constant", "literalConstant", "numericConstant", 
  "classConstant", "stringConstant", "string", "interpolatedStringPart", 
  "chainList", "chain", "memberAccess", "functionCall", "functionCallName", 
  "actualArguments", "chainBase", "keyedFieldName", "keyedSimpleFieldName", 
  "keyedVariable", "squareCurlyExpression", "assignmentList", "assignmentListElement", 
  "modifier", "identifier", "memberModifier", "magicConstant", "magicMethod", 
  "primitiveType", "castOperation"
};

std::vector<std::string> PhpParser::_literalNames = {
  "", "", "", "", "", "", "", "", "", "'abstract'", "'array'", "'as'", "'binary'", 
  "", "", "'break'", "'callable'", "'case'", "'catch'", "'class'", "'clone'", 
  "'const'", "'continue'", "'declare'", "'default'", "'do'", "'real'", "'double'", 
  "'echo'", "'else'", "'elseif'", "'empty'", "'enddeclare'", "'endfor'", 
  "'endforeach'", "'endif'", "'endswitch'", "'endwhile'", "'eval'", "'die'", 
  "'extends'", "'final'", "'finally'", "'float'", "'for'", "'foreach'", 
  "'function'", "'global'", "'goto'", "'if'", "'implements'", "'import'", 
  "'include'", "'include_once'", "'instanceof'", "'insteadof'", "'int8'", 
  "'int16'", "'int64'", "", "'interface'", "'isset'", "'list'", "'and'", 
  "'or'", "'xor'", "'namespace'", "'new'", "'null'", "'object'", "'parent'", 
  "'partial'", "'print'", "'private'", "'protected'", "'public'", "'require'", 
  "'require_once'", "'resource'", "'return'", "'static'", "'string'", "'switch'", 
  "'throw'", "'trait'", "'try'", "'clrtypeof'", "", "'unicode'", "'unset'", 
  "'use'", "'var'", "'while'", "'yield'", "'__get'", "'__set'", "'__call'", 
  "'__callstatic'", "'__construct'", "'__destruct'", "'__wakeup'", "'__sleep'", 
  "'__autoload'", "'__isset'", "'__unset'", "'__tostring'", "'__invoke'", 
  "'__set_state'", "'__clone'", "'__debuginfo'", "'__namespace__'", "'__class__'", 
  "'__trait__'", "'__function__'", "'__method__'", "'__line__'", "'__file__'", 
  "'__dir__'", "'<:'", "':>'", "'=>'", "'++'", "'--'", "'==='", "'!=='", 
  "'=='", "", "'<='", "'>='", "'+='", "'-='", "'*='", "'**'", "'**='", "'/='", 
  "'.='", "'%='", "'<<='", "'>>='", "'&='", "'|='", "'^='", "'||'", "'&&'", 
  "'<<'", "'>>'", "'::'", "'->'", "'\\'", "'...'", "'<'", "'>'", "'&'", 
  "'|'", "'!'", "'^'", "'+'", "'-'", "'*'", "'%'", "'/'", "'~'", "'@'", 
  "", "'.'", "'?'", "'('", "')'", "'['", "']'", "", "'}'", "','", "':'", 
  "';'", "'='", "'''", "'`'"
};

std::vector<std::string> PhpParser::_symbolicNames = {
  "", "PHPStart", "Shebang", "Error", "PHPEnd", "Whitespace", "MultiLineComment", 
  "SingleLineComment", "ShellStyleComment", "Abstract", "Array", "As", "BinaryCast", 
  "BoolType", "BooleanConstant", "Break", "Callable", "Case", "Catch", "Class", 
  "Clone", "Const", "Continue", "Declare", "Default", "Do", "DoubleCast", 
  "DoubleType", "Echo", "Else", "ElseIf", "Empty", "EndDeclare", "EndFor", 
  "EndForeach", "EndIf", "EndSwitch", "EndWhile", "Eval", "Exit", "Extends", 
  "Final", "Finally", "FloatCast", "For", "Foreach", "Function", "Global", 
  "Goto", "If", "Implements", "Import", "Include", "IncludeOnce", "InstanceOf", 
  "InsteadOf", "Int8Cast", "Int16Cast", "Int64Type", "IntType", "Interface", 
  "IsSet", "List", "LogicalAnd", "LogicalOr", "LogicalXor", "Namespace", 
  "New", "Null", "ObjectType", "Parent_", "Partial", "Print", "Private", 
  "Protected", "Public", "Require", "RequireOnce", "Resource", "Return", 
  "Static", "StringType", "Switch", "Throw", "Trait", "Try", "Typeof", "UintCast", 
  "UnicodeCast", "Unset", "Use", "Var", "While", "Yield", "Get", "Set", 
  "Call", "CallStatic", "Constructor", "Destruct", "Wakeup", "Sleep", "Autoload", 
  "IsSet__", "Unset__", "ToString__", "Invoke", "SetState", "Clone__", "DebugInfo", 
  "Namespace__", "Class__", "Traic__", "Function__", "Method__", "Line__", 
  "File__", "Dir__", "Lgeneric", "Rgeneric", "DoubleArrow", "Inc", "Dec", 
  "IsIdentical", "IsNoidentical", "IsEqual", "IsNotEq", "IsSmallerOrEqual", 
  "IsGreaterOrEqual", "PlusEqual", "MinusEqual", "MulEqual", "Pow", "PowEqual", 
  "DivEqual", "Concaequal", "ModEqual", "ShiftLeftEqual", "ShiftRightEqual", 
  "AndEqual", "OrEqual", "XorEqual", "BooleanOr", "BooleanAnd", "ShiftLeft", 
  "ShiftRight", "DoubleColon", "ObjectOperator", "NamespaceSeparator", "Ellipsis", 
  "Less", "Greater", "Ampersand", "Pipe", "Bang", "Caret", "Plus", "Minus", 
  "Asterisk", "Percent", "Divide", "Tilde", "SuppressWarnings", "Dollar", 
  "Dot", "QuestionMark", "OpenRoundBracket", "CloseRoundBracket", "OpenSquareBracket", 
  "CloseSquareBracket", "OpenCurlyBracket", "CloseCurlyBracket", "Comma", 
  "Colon", "SemiColon", "Eq", "Quote", "BackQuote", "VarName", "Label", 
  "Octal", "Decimal", "Real", "Hex", "Binary", "BackQuoteString", "SingleQuoteString", 
  "DoubleQuote", "StartNowDoc", "StartHereDoc", "ErrorPhp", "CurlyDollar", 
  "StringPart", "Comment", "PHPEndSingleLineComment", "CommentEnd", "HereDocText"
};

dfa::Vocabulary PhpParser::_vocabulary(_literalNames, _symbolicNames);

std::vector<std::string> PhpParser::_tokenNames;

PhpParser::Initializer::Initializer() {
	for (size_t i = 0; i < _symbolicNames.size(); ++i) {
		std::string name = _vocabulary.getLiteralName(i);
		if (name.empty()) {
			name = _vocabulary.getSymbolicName(i);
		}

		if (name.empty()) {
			_tokenNames.push_back("<INVALID>");
		} else {
      _tokenNames.push_back(name);
    }
	}

  _serializedATN = {
    0x3, 0x608b, 0xa72a, 0x8133, 0xb9ed, 0x417c, 0x3be7, 0x7786, 0x5964, 
    0x3, 0xc6, 0x608, 0x4, 0x2, 0x9, 0x2, 0x4, 0x3, 0x9, 0x3, 0x4, 0x4, 
    0x9, 0x4, 0x4, 0x5, 0x9, 0x5, 0x4, 0x6, 0x9, 0x6, 0x4, 0x7, 0x9, 0x7, 
    0x4, 0x8, 0x9, 0x8, 0x4, 0x9, 0x9, 0x9, 0x4, 0xa, 0x9, 0xa, 0x4, 0xb, 
    0x9, 0xb, 0x4, 0xc, 0x9, 0xc, 0x4, 0xd, 0x9, 0xd, 0x4, 0xe, 0x9, 0xe, 
    0x4, 0xf, 0x9, 0xf, 0x4, 0x10, 0x9, 0x10, 0x4, 0x11, 0x9, 0x11, 0x4, 
    0x12, 0x9, 0x12, 0x4, 0x13, 0x9, 0x13, 0x4, 0x14, 0x9, 0x14, 0x4, 0x15, 
    0x9, 0x15, 0x4, 0x16, 0x9, 0x16, 0x4, 0x17, 0x9, 0x17, 0x4, 0x18, 0x9, 
    0x18, 0x4, 0x19, 0x9, 0x19, 0x4, 0x1a, 0x9, 0x1a, 0x4, 0x1b, 0x9, 0x1b, 
    0x4, 0x1c, 0x9, 0x1c, 0x4, 0x1d, 0x9, 0x1d, 0x4, 0x1e, 0x9, 0x1e, 0x4, 
    0x1f, 0x9, 0x1f, 0x4, 0x20, 0x9, 0x20, 0x4, 0x21, 0x9, 0x21, 0x4, 0x22, 
    0x9, 0x22, 0x4, 0x23, 0x9, 0x23, 0x4, 0x24, 0x9, 0x24, 0x4, 0x25, 0x9, 
    0x25, 0x4, 0x26, 0x9, 0x26, 0x4, 0x27, 0x9, 0x27, 0x4, 0x28, 0x9, 0x28, 
    0x4, 0x29, 0x9, 0x29, 0x4, 0x2a, 0x9, 0x2a, 0x4, 0x2b, 0x9, 0x2b, 0x4, 
    0x2c, 0x9, 0x2c, 0x4, 0x2d, 0x9, 0x2d, 0x4, 0x2e, 0x9, 0x2e, 0x4, 0x2f, 
    0x9, 0x2f, 0x4, 0x30, 0x9, 0x30, 0x4, 0x31, 0x9, 0x31, 0x4, 0x32, 0x9, 
    0x32, 0x4, 0x33, 0x9, 0x33, 0x4, 0x34, 0x9, 0x34, 0x4, 0x35, 0x9, 0x35, 
    0x4, 0x36, 0x9, 0x36, 0x4, 0x37, 0x9, 0x37, 0x4, 0x38, 0x9, 0x38, 0x4, 
    0x39, 0x9, 0x39, 0x4, 0x3a, 0x9, 0x3a, 0x4, 0x3b, 0x9, 0x3b, 0x4, 0x3c, 
    0x9, 0x3c, 0x4, 0x3d, 0x9, 0x3d, 0x4, 0x3e, 0x9, 0x3e, 0x4, 0x3f, 0x9, 
    0x3f, 0x4, 0x40, 0x9, 0x40, 0x4, 0x41, 0x9, 0x41, 0x4, 0x42, 0x9, 0x42, 
    0x4, 0x43, 0x9, 0x43, 0x4, 0x44, 0x9, 0x44, 0x4, 0x45, 0x9, 0x45, 0x4, 
    0x46, 0x9, 0x46, 0x4, 0x47, 0x9, 0x47, 0x4, 0x48, 0x9, 0x48, 0x4, 0x49, 
    0x9, 0x49, 0x4, 0x4a, 0x9, 0x4a, 0x4, 0x4b, 0x9, 0x4b, 0x4, 0x4c, 0x9, 
    0x4c, 0x4, 0x4d, 0x9, 0x4d, 0x4, 0x4e, 0x9, 0x4e, 0x4, 0x4f, 0x9, 0x4f, 
    0x4, 0x50, 0x9, 0x50, 0x4, 0x51, 0x9, 0x51, 0x4, 0x52, 0x9, 0x52, 0x4, 
    0x53, 0x9, 0x53, 0x4, 0x54, 0x9, 0x54, 0x4, 0x55, 0x9, 0x55, 0x4, 0x56, 
    0x9, 0x56, 0x4, 0x57, 0x9, 0x57, 0x4, 0x58, 0x9, 0x58, 0x4, 0x59, 0x9, 
    0x59, 0x4, 0x5a, 0x9, 0x5a, 0x4, 0x5b, 0x9, 0x5b, 0x4, 0x5c, 0x9, 0x5c, 
    0x4, 0x5d, 0x9, 0x5d, 0x4, 0x5e, 0x9, 0x5e, 0x4, 0x5f, 0x9, 0x5f, 0x4, 
    0x60, 0x9, 0x60, 0x4, 0x61, 0x9, 0x61, 0x4, 0x62, 0x9, 0x62, 0x4, 0x63, 
    0x9, 0x63, 0x4, 0x64, 0x9, 0x64, 0x4, 0x65, 0x9, 0x65, 0x4, 0x66, 0x9, 
    0x66, 0x4, 0x67, 0x9, 0x67, 0x4, 0x68, 0x9, 0x68, 0x4, 0x69, 0x9, 0x69, 
    0x4, 0x6a, 0x9, 0x6a, 0x4, 0x6b, 0x9, 0x6b, 0x4, 0x6c, 0x9, 0x6c, 0x4, 
    0x6d, 0x9, 0x6d, 0x4, 0x6e, 0x9, 0x6e, 0x4, 0x6f, 0x9, 0x6f, 0x4, 0x70, 
    0x9, 0x70, 0x4, 0x71, 0x9, 0x71, 0x4, 0x72, 0x9, 0x72, 0x4, 0x73, 0x9, 
    0x73, 0x4, 0x74, 0x9, 0x74, 0x4, 0x75, 0x9, 0x75, 0x4, 0x76, 0x9, 0x76, 
    0x4, 0x77, 0x9, 0x77, 0x4, 0x78, 0x9, 0x78, 0x4, 0x79, 0x9, 0x79, 0x4, 
    0x7a, 0x9, 0x7a, 0x4, 0x7b, 0x9, 0x7b, 0x3, 0x2, 0x7, 0x2, 0xf8, 0xa, 
    0x2, 0xc, 0x2, 0xe, 0x2, 0xfb, 0xb, 0x2, 0x3, 0x2, 0x6, 0x2, 0xfe, 0xa, 
    0x2, 0xd, 0x2, 0xe, 0x2, 0xff, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 
    0x3, 0x3, 0x3, 0x4, 0x3, 0x4, 0x3, 0x4, 0x3, 0x4, 0x3, 0x4, 0x3, 0x4, 
    0x5, 0x4, 0x10d, 0xa, 0x4, 0x3, 0x5, 0x3, 0x5, 0x5, 0x5, 0x111, 0xa, 
    0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 0x6, 0x5, 0x6, 0x117, 0xa, 0x6, 
    0x3, 0x6, 0x3, 0x6, 0x3, 0x6, 0x5, 0x6, 0x11c, 0xa, 0x6, 0x3, 0x6, 0x7, 
    0x6, 0x11f, 0xa, 0x6, 0xc, 0x6, 0xe, 0x6, 0x122, 0xb, 0x6, 0x3, 0x7, 
    0x3, 0x7, 0x3, 0x7, 0x5, 0x7, 0x127, 0xa, 0x7, 0x3, 0x8, 0x3, 0x8, 0x5, 
    0x8, 0x12b, 0xa, 0x8, 0x3, 0x8, 0x3, 0x8, 0x7, 0x8, 0x12f, 0xa, 0x8, 
    0xc, 0x8, 0xe, 0x8, 0x132, 0xb, 0x8, 0x3, 0x8, 0x3, 0x8, 0x3, 0x8, 0x3, 
    0x8, 0x5, 0x8, 0x138, 0xa, 0x8, 0x3, 0x9, 0x3, 0x9, 0x3, 0x9, 0x3, 0x9, 
    0x3, 0x9, 0x5, 0x9, 0x13f, 0xa, 0x9, 0x3, 0xa, 0x3, 0xa, 0x3, 0xa, 0x5, 
    0xa, 0x144, 0xa, 0xa, 0x3, 0xa, 0x3, 0xa, 0x5, 0xa, 0x148, 0xa, 0xa, 
    0x3, 0xa, 0x3, 0xa, 0x3, 0xa, 0x3, 0xa, 0x3, 0xa, 0x3, 0xb, 0x3, 0xb, 
    0x5, 0xb, 0x151, 0xa, 0xb, 0x3, 0xb, 0x5, 0xb, 0x154, 0xa, 0xb, 0x3, 
    0xb, 0x5, 0xb, 0x157, 0xa, 0xb, 0x3, 0xb, 0x3, 0xb, 0x3, 0xb, 0x5, 0xb, 
    0x15c, 0xa, 0xb, 0x3, 0xb, 0x3, 0xb, 0x5, 0xb, 0x160, 0xa, 0xb, 0x3, 
    0xb, 0x3, 0xb, 0x5, 0xb, 0x164, 0xa, 0xb, 0x3, 0xb, 0x3, 0xb, 0x3, 0xb, 
    0x5, 0xb, 0x169, 0xa, 0xb, 0x3, 0xb, 0x3, 0xb, 0x5, 0xb, 0x16d, 0xa, 
    0xb, 0x5, 0xb, 0x16f, 0xa, 0xb, 0x3, 0xb, 0x3, 0xb, 0x7, 0xb, 0x173, 
    0xa, 0xb, 0xc, 0xb, 0xe, 0xb, 0x176, 0xb, 0xb, 0x3, 0xb, 0x3, 0xb, 0x3, 
    0xc, 0x3, 0xc, 0x3, 0xd, 0x3, 0xd, 0x3, 0xd, 0x7, 0xd, 0x17f, 0xa, 0xd, 
    0xc, 0xd, 0xe, 0xd, 0x182, 0xb, 0xd, 0x3, 0xe, 0x3, 0xe, 0x3, 0xe, 0x3, 
    0xe, 0x3, 0xe, 0x3, 0xe, 0x3, 0xe, 0x3, 0xe, 0x3, 0xe, 0x3, 0xe, 0x3, 
    0xe, 0x3, 0xe, 0x3, 0xe, 0x3, 0xe, 0x5, 0xe, 0x192, 0xa, 0xe, 0x3, 0xf, 
    0x3, 0xf, 0x3, 0xf, 0x7, 0xf, 0x197, 0xa, 0xf, 0xc, 0xf, 0xe, 0xf, 0x19a, 
    0xb, 0xf, 0x3, 0x10, 0x3, 0x10, 0x3, 0x10, 0x7, 0x10, 0x19f, 0xa, 0x10, 
    0xc, 0x10, 0xe, 0x10, 0x1a2, 0xb, 0x10, 0x3, 0x11, 0x3, 0x11, 0x3, 0x11, 
    0x3, 0x12, 0x3, 0x12, 0x3, 0x12, 0x3, 0x12, 0x3, 0x12, 0x5, 0x12, 0x1ac, 
    0xa, 0x12, 0x3, 0x13, 0x3, 0x13, 0x3, 0x13, 0x3, 0x13, 0x7, 0x13, 0x1b2, 
    0xa, 0x13, 0xc, 0x13, 0xe, 0x13, 0x1b5, 0xb, 0x13, 0x3, 0x13, 0x3, 0x13, 
    0x3, 0x14, 0x7, 0x14, 0x1ba, 0xa, 0x14, 0xc, 0x14, 0xe, 0x14, 0x1bd, 
    0xb, 0x14, 0x3, 0x15, 0x3, 0x15, 0x3, 0x15, 0x3, 0x15, 0x5, 0x15, 0x1c3, 
    0xa, 0x15, 0x3, 0x15, 0x3, 0x15, 0x3, 0x15, 0x7, 0x15, 0x1c8, 0xa, 0x15, 
    0xc, 0x15, 0xe, 0x15, 0x1cb, 0xb, 0x15, 0x3, 0x15, 0x3, 0x15, 0x3, 0x16, 
    0x3, 0x16, 0x3, 0x16, 0x3, 0x16, 0x3, 0x16, 0x3, 0x16, 0x3, 0x16, 0x3, 
    0x16, 0x3, 0x16, 0x3, 0x16, 0x3, 0x16, 0x3, 0x16, 0x3, 0x16, 0x3, 0x16, 
    0x3, 0x16, 0x3, 0x16, 0x3, 0x16, 0x3, 0x16, 0x5, 0x16, 0x1e1, 0xa, 0x16, 
    0x3, 0x17, 0x3, 0x17, 0x3, 0x17, 0x7, 0x17, 0x1e6, 0xa, 0x17, 0xc, 0x17, 
    0xe, 0x17, 0x1e9, 0xb, 0x17, 0x3, 0x18, 0x3, 0x18, 0x3, 0x18, 0x7, 0x18, 
    0x1ee, 0xa, 0x18, 0xc, 0x18, 0xe, 0x18, 0x1f1, 0xb, 0x18, 0x3, 0x19, 
    0x3, 0x19, 0x3, 0x19, 0x3, 0x19, 0x3, 0x1a, 0x7, 0x1a, 0x1f8, 0xa, 0x1a, 
    0xc, 0x1a, 0xe, 0x1a, 0x1fb, 0xb, 0x1a, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 
    0x5, 0x1b, 0x200, 0xa, 0x1b, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 
    0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 
    0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 
    0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 
    0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x5, 0x1c, 0x21c, 0xa, 0x1c, 0x3, 0x1d, 
    0x3, 0x1d, 0x3, 0x1e, 0x3, 0x1e, 0x3, 0x1e, 0x3, 0x1e, 0x3, 0x1f, 0x3, 
    0x1f, 0x3, 0x1f, 0x3, 0x1f, 0x7, 0x1f, 0x228, 0xa, 0x1f, 0xc, 0x1f, 
    0xe, 0x1f, 0x22b, 0xb, 0x1f, 0x3, 0x1f, 0x5, 0x1f, 0x22e, 0xa, 0x1f, 
    0x3, 0x1f, 0x3, 0x1f, 0x3, 0x1f, 0x3, 0x1f, 0x3, 0x1f, 0x7, 0x1f, 0x235, 
    0xa, 0x1f, 0xc, 0x1f, 0xe, 0x1f, 0x238, 0xb, 0x1f, 0x3, 0x1f, 0x5, 0x1f, 
    0x23b, 0xa, 0x1f, 0x3, 0x1f, 0x3, 0x1f, 0x3, 0x1f, 0x5, 0x1f, 0x240, 
    0xa, 0x1f, 0x3, 0x20, 0x3, 0x20, 0x3, 0x20, 0x3, 0x20, 0x3, 0x21, 0x3, 
    0x21, 0x3, 0x21, 0x3, 0x21, 0x3, 0x21, 0x3, 0x22, 0x3, 0x22, 0x3, 0x22, 
    0x3, 0x23, 0x3, 0x23, 0x3, 0x23, 0x3, 0x23, 0x3, 0x24, 0x3, 0x24, 0x3, 
    0x24, 0x3, 0x24, 0x3, 0x24, 0x3, 0x24, 0x3, 0x24, 0x3, 0x24, 0x5, 0x24, 
    0x25a, 0xa, 0x24, 0x3, 0x25, 0x3, 0x25, 0x3, 0x25, 0x3, 0x25, 0x3, 0x25, 
    0x3, 0x25, 0x3, 0x26, 0x3, 0x26, 0x3, 0x26, 0x5, 0x26, 0x265, 0xa, 0x26, 
    0x3, 0x26, 0x3, 0x26, 0x5, 0x26, 0x269, 0xa, 0x26, 0x3, 0x26, 0x3, 0x26, 
    0x5, 0x26, 0x26d, 0xa, 0x26, 0x3, 0x26, 0x3, 0x26, 0x3, 0x26, 0x3, 0x26, 
    0x3, 0x26, 0x3, 0x26, 0x3, 0x26, 0x5, 0x26, 0x276, 0xa, 0x26, 0x3, 0x27, 
    0x3, 0x27, 0x3, 0x28, 0x3, 0x28, 0x3, 0x29, 0x3, 0x29, 0x3, 0x29, 0x3, 
    0x29, 0x5, 0x29, 0x280, 0xa, 0x29, 0x3, 0x29, 0x7, 0x29, 0x283, 0xa, 
    0x29, 0xc, 0x29, 0xe, 0x29, 0x286, 0xb, 0x29, 0x3, 0x29, 0x3, 0x29, 
    0x3, 0x29, 0x5, 0x29, 0x28b, 0xa, 0x29, 0x3, 0x29, 0x7, 0x29, 0x28e, 
    0xa, 0x29, 0xc, 0x29, 0xe, 0x29, 0x291, 0xb, 0x29, 0x3, 0x29, 0x3, 0x29, 
    0x5, 0x29, 0x295, 0xa, 0x29, 0x3, 0x2a, 0x3, 0x2a, 0x3, 0x2a, 0x5, 0x2a, 
    0x29a, 0xa, 0x2a, 0x3, 0x2a, 0x6, 0x2a, 0x29d, 0xa, 0x2a, 0xd, 0x2a, 
    0xe, 0x2a, 0x29e, 0x3, 0x2a, 0x3, 0x2a, 0x3, 0x2b, 0x3, 0x2b, 0x5, 0x2b, 
    0x2a5, 0xa, 0x2b, 0x3, 0x2b, 0x3, 0x2b, 0x3, 0x2c, 0x3, 0x2c, 0x5, 0x2c, 
    0x2ab, 0xa, 0x2c, 0x3, 0x2c, 0x3, 0x2c, 0x3, 0x2d, 0x3, 0x2d, 0x5, 0x2d, 
    0x2b1, 0xa, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2e, 0x3, 0x2e, 0x3, 0x2e, 
    0x3, 0x2f, 0x3, 0x2f, 0x3, 0x2f, 0x3, 0x2f, 0x3, 0x2f, 0x3, 0x2f, 0x3, 
    0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x5, 0x30, 0x2c3, 
    0xa, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x5, 0x30, 0x2c8, 0xa, 0x30, 
    0x3, 0x30, 0x5, 0x30, 0x2cb, 0xa, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 
    0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x5, 0x30, 0x2d5, 
    0xa, 0x30, 0x3, 0x30, 0x5, 0x30, 0x2d8, 0xa, 0x30, 0x3, 0x30, 0x3, 0x30, 
    0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 
    0x30, 0x3, 0x30, 0x3, 0x30, 0x5, 0x30, 0x2e5, 0xa, 0x30, 0x3, 0x30, 
    0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x5, 0x30, 0x2ed, 
    0xa, 0x30, 0x3, 0x31, 0x3, 0x31, 0x3, 0x31, 0x6, 0x31, 0x2f2, 0xa, 0x31, 
    0xd, 0x31, 0xe, 0x31, 0x2f3, 0x3, 0x31, 0x5, 0x31, 0x2f7, 0xa, 0x31, 
    0x3, 0x31, 0x7, 0x31, 0x2fa, 0xa, 0x31, 0xc, 0x31, 0xe, 0x31, 0x2fd, 
    0xb, 0x31, 0x3, 0x31, 0x5, 0x31, 0x300, 0xa, 0x31, 0x3, 0x32, 0x3, 0x32, 
    0x3, 0x32, 0x3, 0x32, 0x3, 0x32, 0x3, 0x32, 0x3, 0x32, 0x3, 0x33, 0x3, 
    0x33, 0x3, 0x33, 0x3, 0x34, 0x3, 0x34, 0x3, 0x34, 0x3, 0x34, 0x3, 0x35, 
    0x3, 0x35, 0x3, 0x35, 0x3, 0x35, 0x3, 0x36, 0x3, 0x36, 0x3, 0x36, 0x3, 
    0x36, 0x3, 0x36, 0x3, 0x36, 0x3, 0x36, 0x3, 0x36, 0x3, 0x36, 0x3, 0x36, 
    0x5, 0x36, 0x31e, 0xa, 0x36, 0x3, 0x37, 0x3, 0x37, 0x3, 0x37, 0x7, 0x37, 
    0x323, 0xa, 0x37, 0xc, 0x37, 0xe, 0x37, 0x326, 0xb, 0x37, 0x3, 0x38, 
    0x5, 0x38, 0x329, 0xa, 0x38, 0x3, 0x38, 0x3, 0x38, 0x7, 0x38, 0x32d, 
    0xa, 0x38, 0xc, 0x38, 0xe, 0x38, 0x330, 0xb, 0x38, 0x3, 0x39, 0x3, 0x39, 
    0x5, 0x39, 0x334, 0xa, 0x39, 0x3, 0x39, 0x5, 0x39, 0x337, 0xa, 0x39, 
    0x3, 0x39, 0x5, 0x39, 0x33a, 0xa, 0x39, 0x3, 0x39, 0x3, 0x39, 0x3, 0x3a, 
    0x3, 0x3a, 0x3, 0x3a, 0x5, 0x3a, 0x341, 0xa, 0x3a, 0x3, 0x3b, 0x3, 0x3b, 
    0x3, 0x3b, 0x3, 0x3b, 0x7, 0x3b, 0x347, 0xa, 0x3b, 0xc, 0x3b, 0xe, 0x3b, 
    0x34a, 0xb, 0x3b, 0x3, 0x3b, 0x3, 0x3b, 0x3, 0x3c, 0x3, 0x3c, 0x3, 0x3c, 
    0x3, 0x3c, 0x3, 0x3c, 0x3, 0x3c, 0x3, 0x3c, 0x3, 0x3c, 0x5, 0x3c, 0x356, 
    0xa, 0x3c, 0x3, 0x3d, 0x3, 0x3d, 0x3, 0x3d, 0x3, 0x3d, 0x3, 0x3e, 0x3, 
    0x3e, 0x3, 0x3e, 0x3, 0x3e, 0x7, 0x3e, 0x360, 0xa, 0x3e, 0xc, 0x3e, 
    0xe, 0x3e, 0x363, 0xb, 0x3e, 0x3, 0x3e, 0x3, 0x3e, 0x3, 0x3f, 0x3, 0x3f, 
    0x3, 0x3f, 0x3, 0x3f, 0x3, 0x3f, 0x7, 0x3f, 0x36c, 0xa, 0x3f, 0xc, 0x3f, 
    0xe, 0x3f, 0x36f, 0xb, 0x3f, 0x3, 0x3f, 0x3, 0x3f, 0x3, 0x3f, 0x3, 0x3f, 
    0x3, 0x3f, 0x3, 0x3f, 0x3, 0x3f, 0x7, 0x3f, 0x378, 0xa, 0x3f, 0xc, 0x3f, 
    0xe, 0x3f, 0x37b, 0xb, 0x3f, 0x3, 0x3f, 0x3, 0x3f, 0x3, 0x3f, 0x3, 0x3f, 
    0x5, 0x3f, 0x381, 0xa, 0x3f, 0x3, 0x3f, 0x3, 0x3f, 0x5, 0x3f, 0x385, 
    0xa, 0x3f, 0x3, 0x3f, 0x3, 0x3f, 0x5, 0x3f, 0x389, 0xa, 0x3f, 0x3, 0x3f, 
    0x3, 0x3f, 0x3, 0x3f, 0x3, 0x3f, 0x5, 0x3f, 0x38f, 0xa, 0x3f, 0x3, 0x3f, 
    0x3, 0x3f, 0x3, 0x3f, 0x3, 0x3f, 0x3, 0x3f, 0x3, 0x3f, 0x5, 0x3f, 0x397, 
    0xa, 0x3f, 0x3, 0x40, 0x3, 0x40, 0x3, 0x40, 0x7, 0x40, 0x39c, 0xa, 0x40, 
    0xc, 0x40, 0xe, 0x40, 0x39f, 0xb, 0x40, 0x3, 0x40, 0x5, 0x40, 0x3a2, 
    0xa, 0x40, 0x3, 0x41, 0x3, 0x41, 0x5, 0x41, 0x3a6, 0xa, 0x41, 0x3, 0x42, 
    0x3, 0x42, 0x3, 0x42, 0x3, 0x42, 0x3, 0x42, 0x3, 0x42, 0x3, 0x42, 0x3, 
    0x43, 0x3, 0x43, 0x3, 0x43, 0x3, 0x43, 0x5, 0x43, 0x3b3, 0xa, 0x43, 
    0x3, 0x43, 0x5, 0x43, 0x3b6, 0xa, 0x43, 0x3, 0x43, 0x3, 0x43, 0x3, 0x44, 
    0x3, 0x44, 0x3, 0x44, 0x5, 0x44, 0x3bd, 0xa, 0x44, 0x3, 0x44, 0x3, 0x44, 
    0x3, 0x45, 0x3, 0x45, 0x3, 0x45, 0x3, 0x45, 0x3, 0x46, 0x3, 0x46, 0x5, 
    0x46, 0x3c7, 0xa, 0x46, 0x3, 0x47, 0x3, 0x47, 0x5, 0x47, 0x3cb, 0xa, 
    0x47, 0x3, 0x48, 0x6, 0x48, 0x3ce, 0xa, 0x48, 0xd, 0x48, 0xe, 0x48, 
    0x3cf, 0x3, 0x49, 0x3, 0x49, 0x3, 0x49, 0x5, 0x49, 0x3d5, 0xa, 0x49, 
    0x3, 0x4a, 0x3, 0x4a, 0x3, 0x4a, 0x3, 0x4a, 0x3, 0x4b, 0x3, 0x4b, 0x3, 
    0x4b, 0x3, 0x4b, 0x3, 0x4b, 0x7, 0x4b, 0x3e0, 0xa, 0x4b, 0xc, 0x4b, 
    0xe, 0x4b, 0x3e3, 0xb, 0x4b, 0x3, 0x4b, 0x3, 0x4b, 0x3, 0x4c, 0x3, 0x4c, 
    0x3, 0x4c, 0x7, 0x4c, 0x3ea, 0xa, 0x4c, 0xc, 0x4c, 0xe, 0x4c, 0x3ed, 
    0xb, 0x4c, 0x3, 0x4d, 0x3, 0x4d, 0x3, 0x4d, 0x5, 0x4d, 0x3f2, 0xa, 0x4d, 
    0x3, 0x4d, 0x3, 0x4d, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 
    0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 
    0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 
    0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 
    0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 
    0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x5, 0x4e, 0x418, 0xa, 0x4e, 
    0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x5, 0x4e, 0x41d, 0xa, 0x4e, 0x3, 0x4e, 
    0x5, 0x4e, 0x420, 0xa, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 
    0x5, 0x4e, 0x426, 0xa, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 
    0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 
    0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 
    0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 
    0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x5, 0x4e, 0x443, 0xa, 0x4e, 
    0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x5, 0x4e, 0x44a, 
    0xa, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x5, 0x4e, 0x44e, 0xa, 0x4e, 0x3, 0x4e, 
    0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x5, 0x4e, 0x454, 0xa, 0x4e, 0x3, 0x4e, 
    0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 
    0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x5, 0x4e, 0x461, 0xa, 0x4e, 
    0x5, 0x4e, 0x463, 0xa, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 
    0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 
    0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 
    0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 
    0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 
    0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x5, 
    0x4e, 0x489, 0xa, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 
    0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 
    0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x7, 0x4e, 0x499, 0xa, 0x4e, 
    0xc, 0x4e, 0xe, 0x4e, 0x49c, 0xb, 0x4e, 0x3, 0x4f, 0x3, 0x4f, 0x3, 0x4f, 
    0x5, 0x4f, 0x4a1, 0xa, 0x4f, 0x3, 0x50, 0x3, 0x50, 0x3, 0x51, 0x3, 0x51, 
    0x3, 0x51, 0x3, 0x51, 0x5, 0x51, 0x4a9, 0xa, 0x51, 0x3, 0x52, 0x3, 0x52, 
    0x3, 0x52, 0x7, 0x52, 0x4ae, 0xa, 0x52, 0xc, 0x52, 0xe, 0x52, 0x4b1, 
    0xb, 0x52, 0x3, 0x52, 0x5, 0x52, 0x4b4, 0xa, 0x52, 0x3, 0x53, 0x3, 0x53, 
    0x3, 0x53, 0x5, 0x53, 0x4b9, 0xa, 0x53, 0x3, 0x53, 0x3, 0x53, 0x3, 0x53, 
    0x5, 0x53, 0x4be, 0xa, 0x53, 0x3, 0x53, 0x3, 0x53, 0x5, 0x53, 0x4c2, 
    0xa, 0x53, 0x3, 0x54, 0x3, 0x54, 0x3, 0x54, 0x3, 0x54, 0x3, 0x54, 0x7, 
    0x54, 0x4c9, 0xa, 0x54, 0xc, 0x54, 0xe, 0x54, 0x4cc, 0xb, 0x54, 0x3, 
    0x54, 0x3, 0x54, 0x3, 0x55, 0x5, 0x55, 0x4d1, 0xa, 0x55, 0x3, 0x55, 
    0x3, 0x55, 0x3, 0x56, 0x3, 0x56, 0x5, 0x56, 0x4d7, 0xa, 0x56, 0x3, 0x56, 
    0x5, 0x56, 0x4da, 0xa, 0x56, 0x3, 0x57, 0x3, 0x57, 0x5, 0x57, 0x4de, 
    0xa, 0x57, 0x3, 0x57, 0x5, 0x57, 0x4e1, 0xa, 0x57, 0x3, 0x57, 0x3, 0x57, 
    0x5, 0x57, 0x4e5, 0xa, 0x57, 0x3, 0x58, 0x3, 0x58, 0x3, 0x58, 0x7, 0x58, 
    0x4ea, 0xa, 0x58, 0xc, 0x58, 0xe, 0x58, 0x4ed, 0xb, 0x58, 0x3, 0x59, 
    0x5, 0x59, 0x4f0, 0xa, 0x59, 0x3, 0x59, 0x5, 0x59, 0x4f3, 0xa, 0x59, 
    0x3, 0x59, 0x3, 0x59, 0x3, 0x5a, 0x3, 0x5a, 0x3, 0x5a, 0x7, 0x5a, 0x4fa, 
    0xa, 0x5a, 0xc, 0x5a, 0xe, 0x5a, 0x4fd, 0xb, 0x5a, 0x3, 0x5b, 0x3, 0x5b, 
    0x3, 0x5b, 0x7, 0x5b, 0x502, 0xa, 0x5b, 0xc, 0x5b, 0xe, 0x5b, 0x505, 
    0xb, 0x5b, 0x3, 0x5c, 0x3, 0x5c, 0x3, 0x5c, 0x3, 0x5c, 0x7, 0x5c, 0x50b, 
    0xa, 0x5c, 0xc, 0x5c, 0xe, 0x5c, 0x50e, 0xb, 0x5c, 0x3, 0x5c, 0x5, 0x5c, 
    0x511, 0xa, 0x5c, 0x3, 0x5c, 0x3, 0x5c, 0x3, 0x5d, 0x5, 0x5d, 0x516, 
    0xa, 0x5d, 0x3, 0x5d, 0x3, 0x5d, 0x3, 0x5d, 0x5, 0x5d, 0x51b, 0xa, 0x5d, 
    0x3, 0x5e, 0x3, 0x5e, 0x3, 0x5e, 0x3, 0x5e, 0x3, 0x5e, 0x3, 0x5e, 0x5, 
    0x5e, 0x523, 0xa, 0x5e, 0x5, 0x5e, 0x525, 0xa, 0x5e, 0x3, 0x5e, 0x3, 
    0x5e, 0x3, 0x5e, 0x3, 0x5e, 0x5, 0x5e, 0x52b, 0xa, 0x5e, 0x5, 0x5e, 
    0x52d, 0xa, 0x5e, 0x3, 0x5e, 0x3, 0x5e, 0x3, 0x5e, 0x5, 0x5e, 0x532, 
    0xa, 0x5e, 0x3, 0x5f, 0x3, 0x5f, 0x3, 0x5f, 0x7, 0x5f, 0x537, 0xa, 0x5f, 
    0xc, 0x5f, 0xe, 0x5f, 0x53a, 0xb, 0x5f, 0x3, 0x60, 0x3, 0x60, 0x3, 0x60, 
    0x5, 0x60, 0x53f, 0xa, 0x60, 0x3, 0x61, 0x3, 0x61, 0x3, 0x61, 0x3, 0x61, 
    0x3, 0x61, 0x5, 0x61, 0x546, 0xa, 0x61, 0x3, 0x62, 0x3, 0x62, 0x3, 0x62, 
    0x3, 0x62, 0x5, 0x62, 0x54c, 0xa, 0x62, 0x3, 0x63, 0x3, 0x63, 0x3, 0x64, 
    0x3, 0x64, 0x3, 0x64, 0x3, 0x64, 0x3, 0x64, 0x3, 0x64, 0x5, 0x64, 0x556, 
    0xa, 0x64, 0x3, 0x64, 0x3, 0x64, 0x5, 0x64, 0x55a, 0xa, 0x64, 0x3, 0x64, 
    0x3, 0x64, 0x3, 0x64, 0x5, 0x64, 0x55f, 0xa, 0x64, 0x3, 0x65, 0x3, 0x65, 
    0x3, 0x66, 0x3, 0x66, 0x6, 0x66, 0x565, 0xa, 0x66, 0xd, 0x66, 0xe, 0x66, 
    0x566, 0x3, 0x66, 0x3, 0x66, 0x6, 0x66, 0x56b, 0xa, 0x66, 0xd, 0x66, 
    0xe, 0x66, 0x56c, 0x3, 0x66, 0x3, 0x66, 0x3, 0x66, 0x7, 0x66, 0x572, 
    0xa, 0x66, 0xc, 0x66, 0xe, 0x66, 0x575, 0xb, 0x66, 0x3, 0x66, 0x5, 0x66, 
    0x578, 0xa, 0x66, 0x3, 0x67, 0x3, 0x67, 0x5, 0x67, 0x57c, 0xa, 0x67, 
    0x3, 0x68, 0x3, 0x68, 0x3, 0x68, 0x7, 0x68, 0x581, 0xa, 0x68, 0xc, 0x68, 
    0xe, 0x68, 0x584, 0xb, 0x68, 0x3, 0x69, 0x3, 0x69, 0x3, 0x69, 0x3, 0x69, 
    0x3, 0x69, 0x3, 0x69, 0x5, 0x69, 0x58c, 0xa, 0x69, 0x3, 0x69, 0x7, 0x69, 
    0x58f, 0xa, 0x69, 0xc, 0x69, 0xe, 0x69, 0x592, 0xb, 0x69, 0x3, 0x6a, 
    0x3, 0x6a, 0x3, 0x6a, 0x5, 0x6a, 0x597, 0xa, 0x6a, 0x3, 0x6b, 0x3, 0x6b, 
    0x3, 0x6b, 0x3, 0x6c, 0x3, 0x6c, 0x3, 0x6c, 0x5, 0x6c, 0x59f, 0xa, 0x6c, 
    0x3, 0x6d, 0x5, 0x6d, 0x5a2, 0xa, 0x6d, 0x3, 0x6d, 0x3, 0x6d, 0x7, 0x6d, 
    0x5a6, 0xa, 0x6d, 0xc, 0x6d, 0xe, 0x6d, 0x5a9, 0xb, 0x6d, 0x3, 0x6e, 
    0x3, 0x6e, 0x3, 0x6e, 0x5, 0x6e, 0x5ae, 0xa, 0x6e, 0x3, 0x6e, 0x3, 0x6e, 
    0x3, 0x6e, 0x3, 0x6e, 0x5, 0x6e, 0x5b4, 0xa, 0x6e, 0x3, 0x6f, 0x3, 0x6f, 
    0x5, 0x6f, 0x5b8, 0xa, 0x6f, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 
    0x3, 0x70, 0x5, 0x70, 0x5bf, 0xa, 0x70, 0x3, 0x70, 0x7, 0x70, 0x5c2, 
    0xa, 0x70, 0xc, 0x70, 0xe, 0x70, 0x5c5, 0xb, 0x70, 0x3, 0x71, 0x7, 0x71, 
    0x5c8, 0xa, 0x71, 0xc, 0x71, 0xe, 0x71, 0x5cb, 0xb, 0x71, 0x3, 0x71, 
    0x3, 0x71, 0x3, 0x71, 0x3, 0x71, 0x3, 0x71, 0x3, 0x71, 0x5, 0x71, 0x5d3, 
    0xa, 0x71, 0x3, 0x71, 0x7, 0x71, 0x5d6, 0xa, 0x71, 0xc, 0x71, 0xe, 0x71, 
    0x5d9, 0xb, 0x71, 0x3, 0x72, 0x3, 0x72, 0x5, 0x72, 0x5dd, 0xa, 0x72, 
    0x3, 0x72, 0x3, 0x72, 0x3, 0x72, 0x3, 0x72, 0x3, 0x72, 0x5, 0x72, 0x5e4, 
    0xa, 0x72, 0x3, 0x73, 0x5, 0x73, 0x5e7, 0xa, 0x73, 0x3, 0x73, 0x3, 0x73, 
    0x5, 0x73, 0x5eb, 0xa, 0x73, 0x7, 0x73, 0x5ed, 0xa, 0x73, 0xc, 0x73, 
    0xe, 0x73, 0x5f0, 0xb, 0x73, 0x3, 0x74, 0x3, 0x74, 0x3, 0x74, 0x3, 0x74, 
    0x3, 0x74, 0x3, 0x74, 0x5, 0x74, 0x5f8, 0xa, 0x74, 0x3, 0x75, 0x3, 0x75, 
    0x3, 0x76, 0x3, 0x76, 0x3, 0x77, 0x3, 0x77, 0x3, 0x78, 0x3, 0x78, 0x3, 
    0x79, 0x3, 0x79, 0x3, 0x7a, 0x3, 0x7a, 0x3, 0x7b, 0x3, 0x7b, 0x3, 0x7b, 
    0x2, 0x3, 0x9a, 0x7c, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 
    0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 
    0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e, 0x40, 0x42, 
    0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 
    0x5c, 0x5e, 0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 
    0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 
    0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e, 0xa0, 0xa2, 
    0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 
    0xbc, 0xbe, 0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 
    0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde, 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 
    0xec, 0xee, 0xf0, 0xf2, 0xf4, 0x2, 0x1a, 0x4, 0x2, 0x17, 0x17, 0x30, 
    0x30, 0x4, 0x2, 0x15, 0x15, 0x56, 0x56, 0x3, 0x2, 0xaf, 0xb0, 0x3, 0x2, 
    0xa3, 0xa4, 0x4, 0x2, 0x9c, 0x9c, 0x9e, 0x9f, 0x3, 0x2, 0x7b, 0x7c, 
    0x3, 0x2, 0x36, 0x37, 0x3, 0x2, 0x4e, 0x4f, 0x3, 0x2, 0xa0, 0xa2, 0x4, 
    0x2, 0x9e, 0x9f, 0xa6, 0xa6, 0x3, 0x2, 0x92, 0x93, 0x4, 0x2, 0x81, 0x82, 
    0x98, 0x99, 0x3, 0x2, 0x7d, 0x80, 0x5, 0x2, 0x83, 0x85, 0x87, 0x8f, 
    0xb1, 0xb1, 0x3, 0x2, 0x9e, 0x9f, 0x4, 0x2, 0xb6, 0xb7, 0xb9, 0xba, 
    0x4, 0x2, 0x15, 0x15, 0x48, 0x48, 0x4, 0x2, 0xb, 0xb, 0x2b, 0x2b, 0x4, 
    0x2, 0xb, 0x77, 0xb5, 0xb5, 0x6, 0x2, 0xb, 0xb, 0x2b, 0x2b, 0x4b, 0x4d, 
    0x52, 0x52, 0x3, 0x2, 0x70, 0x77, 0x3, 0x2, 0x60, 0x6f, 0x9, 0x2, 0xc, 
    0xc, 0xf, 0xf, 0x1d, 0x1d, 0x3c, 0x3d, 0x47, 0x47, 0x50, 0x50, 0x53, 
    0x53, 0xb, 0x2, 0xc, 0xc, 0xe, 0xf, 0x1c, 0x1d, 0x2d, 0x2d, 0x3a, 0x3d, 
    0x47, 0x47, 0x50, 0x50, 0x53, 0x53, 0x59, 0x5b, 0x2, 0x698, 0x2, 0xf9, 
    0x3, 0x2, 0x2, 0x2, 0x4, 0x101, 0x3, 0x2, 0x2, 0x2, 0x6, 0x10c, 0x3, 
    0x2, 0x2, 0x2, 0x8, 0x10e, 0x3, 0x2, 0x2, 0x2, 0xa, 0x116, 0x3, 0x2, 
    0x2, 0x2, 0xc, 0x123, 0x3, 0x2, 0x2, 0x2, 0xe, 0x128, 0x3, 0x2, 0x2, 
    0x2, 0x10, 0x13e, 0x3, 0x2, 0x2, 0x2, 0x12, 0x140, 0x3, 0x2, 0x2, 0x2, 
    0x14, 0x14e, 0x3, 0x2, 0x2, 0x2, 0x16, 0x179, 0x3, 0x2, 0x2, 0x2, 0x18, 
    0x17b, 0x3, 0x2, 0x2, 0x2, 0x1a, 0x191, 0x3, 0x2, 0x2, 0x2, 0x1c, 0x193, 
    0x3, 0x2, 0x2, 0x2, 0x1e, 0x19b, 0x3, 0x2, 0x2, 0x2, 0x20, 0x1a3, 0x3, 
    0x2, 0x2, 0x2, 0x22, 0x1a6, 0x3, 0x2, 0x2, 0x2, 0x24, 0x1ad, 0x3, 0x2, 
    0x2, 0x2, 0x26, 0x1bb, 0x3, 0x2, 0x2, 0x2, 0x28, 0x1be, 0x3, 0x2, 0x2, 
    0x2, 0x2a, 0x1e0, 0x3, 0x2, 0x2, 0x2, 0x2c, 0x1e2, 0x3, 0x2, 0x2, 0x2, 
    0x2e, 0x1ea, 0x3, 0x2, 0x2, 0x2, 0x30, 0x1f2, 0x3, 0x2, 0x2, 0x2, 0x32, 
    0x1f9, 0x3, 0x2, 0x2, 0x2, 0x34, 0x1ff, 0x3, 0x2, 0x2, 0x2, 0x36, 0x21b, 
    0x3, 0x2, 0x2, 0x2, 0x38, 0x21d, 0x3, 0x2, 0x2, 0x2, 0x3a, 0x21f, 0x3, 
    0x2, 0x2, 0x2, 0x3c, 0x23f, 0x3, 0x2, 0x2, 0x2, 0x3e, 0x241, 0x3, 0x2, 
    0x2, 0x2, 0x40, 0x245, 0x3, 0x2, 0x2, 0x2, 0x42, 0x24a, 0x3, 0x2, 0x2, 
    0x2, 0x44, 0x24d, 0x3, 0x2, 0x2, 0x2, 0x46, 0x251, 0x3, 0x2, 0x2, 0x2, 
    0x48, 0x25b, 0x3, 0x2, 0x2, 0x2, 0x4a, 0x261, 0x3, 0x2, 0x2, 0x2, 0x4c, 
    0x277, 0x3, 0x2, 0x2, 0x2, 0x4e, 0x279, 0x3, 0x2, 0x2, 0x2, 0x50, 0x27b, 
    0x3, 0x2, 0x2, 0x2, 0x52, 0x29c, 0x3, 0x2, 0x2, 0x2, 0x54, 0x2a2, 0x3, 
    0x2, 0x2, 0x2, 0x56, 0x2a8, 0x3, 0x2, 0x2, 0x2, 0x58, 0x2ae, 0x3, 0x2, 
    0x2, 0x2, 0x5a, 0x2b4, 0x3, 0x2, 0x2, 0x2, 0x5c, 0x2b7, 0x3, 0x2, 0x2, 
    0x2, 0x5e, 0x2bd, 0x3, 0x2, 0x2, 0x2, 0x60, 0x2ee, 0x3, 0x2, 0x2, 0x2, 
    0x62, 0x301, 0x3, 0x2, 0x2, 0x2, 0x64, 0x308, 0x3, 0x2, 0x2, 0x2, 0x66, 
    0x30b, 0x3, 0x2, 0x2, 0x2, 0x68, 0x30f, 0x3, 0x2, 0x2, 0x2, 0x6a, 0x313, 
    0x3, 0x2, 0x2, 0x2, 0x6c, 0x31f, 0x3, 0x2, 0x2, 0x2, 0x6e, 0x328, 0x3, 
    0x2, 0x2, 0x2, 0x70, 0x331, 0x3, 0x2, 0x2, 0x2, 0x72, 0x340, 0x3, 0x2, 
    0x2, 0x2, 0x74, 0x342, 0x3, 0x2, 0x2, 0x2, 0x76, 0x355, 0x3, 0x2, 0x2, 
    0x2, 0x78, 0x357, 0x3, 0x2, 0x2, 0x2, 0x7a, 0x35b, 0x3, 0x2, 0x2, 0x2, 
    0x7c, 0x396, 0x3, 0x2, 0x2, 0x2, 0x7e, 0x3a1, 0x3, 0x2, 0x2, 0x2, 0x80, 
    0x3a5, 0x3, 0x2, 0x2, 0x2, 0x82, 0x3a7, 0x3, 0x2, 0x2, 0x2, 0x84, 0x3ae, 
    0x3, 0x2, 0x2, 0x2, 0x86, 0x3bc, 0x3, 0x2, 0x2, 0x2, 0x88, 0x3c0, 0x3, 
    0x2, 0x2, 0x2, 0x8a, 0x3c6, 0x3, 0x2, 0x2, 0x2, 0x8c, 0x3ca, 0x3, 0x2, 
    0x2, 0x2, 0x8e, 0x3cd, 0x3, 0x2, 0x2, 0x2, 0x90, 0x3d1, 0x3, 0x2, 0x2, 
    0x2, 0x92, 0x3d6, 0x3, 0x2, 0x2, 0x2, 0x94, 0x3da, 0x3, 0x2, 0x2, 0x2, 
    0x96, 0x3e6, 0x3, 0x2, 0x2, 0x2, 0x98, 0x3ee, 0x3, 0x2, 0x2, 0x2, 0x9a, 
    0x462, 0x3, 0x2, 0x2, 0x2, 0x9c, 0x49d, 0x3, 0x2, 0x2, 0x2, 0x9e, 0x4a2, 
    0x3, 0x2, 0x2, 0x2, 0xa0, 0x4a4, 0x3, 0x2, 0x2, 0x2, 0xa2, 0x4aa, 0x3, 
    0x2, 0x2, 0x2, 0xa4, 0x4c1, 0x3, 0x2, 0x2, 0x2, 0xa6, 0x4c3, 0x3, 0x2, 
    0x2, 0x2, 0xa8, 0x4d0, 0x3, 0x2, 0x2, 0x2, 0xaa, 0x4d9, 0x3, 0x2, 0x2, 
    0x2, 0xac, 0x4e4, 0x3, 0x2, 0x2, 0x2, 0xae, 0x4e6, 0x3, 0x2, 0x2, 0x2, 
    0xb0, 0x4ef, 0x3, 0x2, 0x2, 0x2, 0xb2, 0x4f6, 0x3, 0x2, 0x2, 0x2, 0xb4, 
    0x4fe, 0x3, 0x2, 0x2, 0x2, 0xb6, 0x506, 0x3, 0x2, 0x2, 0x2, 0xb8, 0x51a, 
    0x3, 0x2, 0x2, 0x2, 0xba, 0x531, 0x3, 0x2, 0x2, 0x2, 0xbc, 0x533, 0x3, 
    0x2, 0x2, 0x2, 0xbe, 0x53b, 0x3, 0x2, 0x2, 0x2, 0xc0, 0x545, 0x3, 0x2, 
    0x2, 0x2, 0xc2, 0x54b, 0x3, 0x2, 0x2, 0x2, 0xc4, 0x54d, 0x3, 0x2, 0x2, 
    0x2, 0xc6, 0x55e, 0x3, 0x2, 0x2, 0x2, 0xc8, 0x560, 0x3, 0x2, 0x2, 0x2, 
    0xca, 0x577, 0x3, 0x2, 0x2, 0x2, 0xcc, 0x57b, 0x3, 0x2, 0x2, 0x2, 0xce, 
    0x57d, 0x3, 0x2, 0x2, 0x2, 0xd0, 0x58b, 0x3, 0x2, 0x2, 0x2, 0xd2, 0x593, 
    0x3, 0x2, 0x2, 0x2, 0xd4, 0x598, 0x3, 0x2, 0x2, 0x2, 0xd6, 0x59e, 0x3, 
    0x2, 0x2, 0x2, 0xd8, 0x5a1, 0x3, 0x2, 0x2, 0x2, 0xda, 0x5b3, 0x3, 0x2, 
    0x2, 0x2, 0xdc, 0x5b7, 0x3, 0x2, 0x2, 0x2, 0xde, 0x5be, 0x3, 0x2, 0x2, 
    0x2, 0xe0, 0x5c9, 0x3, 0x2, 0x2, 0x2, 0xe2, 0x5e3, 0x3, 0x2, 0x2, 0x2, 
    0xe4, 0x5e6, 0x3, 0x2, 0x2, 0x2, 0xe6, 0x5f7, 0x3, 0x2, 0x2, 0x2, 0xe8, 
    0x5f9, 0x3, 0x2, 0x2, 0x2, 0xea, 0x5fb, 0x3, 0x2, 0x2, 0x2, 0xec, 0x5fd, 
    0x3, 0x2, 0x2, 0x2, 0xee, 0x5ff, 0x3, 0x2, 0x2, 0x2, 0xf0, 0x601, 0x3, 
    0x2, 0x2, 0x2, 0xf2, 0x603, 0x3, 0x2, 0x2, 0x2, 0xf4, 0x605, 0x3, 0x2, 
    0x2, 0x2, 0xf6, 0xf8, 0x5, 0x4, 0x3, 0x2, 0xf7, 0xf6, 0x3, 0x2, 0x2, 
    0x2, 0xf8, 0xfb, 0x3, 0x2, 0x2, 0x2, 0xf9, 0xf7, 0x3, 0x2, 0x2, 0x2, 
    0xf9, 0xfa, 0x3, 0x2, 0x2, 0x2, 0xfa, 0xfd, 0x3, 0x2, 0x2, 0x2, 0xfb, 
    0xf9, 0x3, 0x2, 0x2, 0x2, 0xfc, 0xfe, 0x5, 0x6, 0x4, 0x2, 0xfd, 0xfc, 
    0x3, 0x2, 0x2, 0x2, 0xfe, 0xff, 0x3, 0x2, 0x2, 0x2, 0xff, 0xfd, 0x3, 
    0x2, 0x2, 0x2, 0xff, 0x100, 0x3, 0x2, 0x2, 0x2, 0x100, 0x3, 0x3, 0x2, 
    0x2, 0x2, 0x101, 0x102, 0x7, 0x35, 0x2, 0x2, 0x102, 0x103, 0x7, 0x44, 
    0x2, 0x2, 0x103, 0x104, 0x5, 0xb2, 0x5a, 0x2, 0x104, 0x105, 0x7, 0xb0, 
    0x2, 0x2, 0x105, 0x5, 0x3, 0x2, 0x2, 0x2, 0x106, 0x10d, 0x5, 0x36, 0x1c, 
    0x2, 0x107, 0x10d, 0x5, 0x8, 0x5, 0x2, 0x108, 0x10d, 0x5, 0xe, 0x8, 
    0x2, 0x109, 0x10d, 0x5, 0x12, 0xa, 0x2, 0x10a, 0x10d, 0x5, 0x14, 0xb, 
    0x2, 0x10b, 0x10d, 0x5, 0x94, 0x4b, 0x2, 0x10c, 0x106, 0x3, 0x2, 0x2, 
    0x2, 0x10c, 0x107, 0x3, 0x2, 0x2, 0x2, 0x10c, 0x108, 0x3, 0x2, 0x2, 
    0x2, 0x10c, 0x109, 0x3, 0x2, 0x2, 0x2, 0x10c, 0x10a, 0x3, 0x2, 0x2, 
    0x2, 0x10c, 0x10b, 0x3, 0x2, 0x2, 0x2, 0x10d, 0x7, 0x3, 0x2, 0x2, 0x2, 
    0x10e, 0x110, 0x7, 0x5c, 0x2, 0x2, 0x10f, 0x111, 0x9, 0x2, 0x2, 0x2, 
    0x110, 0x10f, 0x3, 0x2, 0x2, 0x2, 0x110, 0x111, 0x3, 0x2, 0x2, 0x2, 
    0x111, 0x112, 0x3, 0x2, 0x2, 0x2, 0x112, 0x113, 0x5, 0xa, 0x6, 0x2, 
    0x113, 0x114, 0x7, 0xb0, 0x2, 0x2, 0x114, 0x9, 0x3, 0x2, 0x2, 0x2, 0x115, 
    0x117, 0x7, 0x96, 0x2, 0x2, 0x116, 0x115, 0x3, 0x2, 0x2, 0x2, 0x116, 
    0x117, 0x3, 0x2, 0x2, 0x2, 0x117, 0x118, 0x3, 0x2, 0x2, 0x2, 0x118, 
    0x120, 0x5, 0xc, 0x7, 0x2, 0x119, 0x11b, 0x7, 0xae, 0x2, 0x2, 0x11a, 
    0x11c, 0x7, 0x96, 0x2, 0x2, 0x11b, 0x11a, 0x3, 0x2, 0x2, 0x2, 0x11b, 
    0x11c, 0x3, 0x2, 0x2, 0x2, 0x11c, 0x11d, 0x3, 0x2, 0x2, 0x2, 0x11d, 
    0x11f, 0x5, 0xc, 0x7, 0x2, 0x11e, 0x119, 0x3, 0x2, 0x2, 0x2, 0x11f, 
    0x122, 0x3, 0x2, 0x2, 0x2, 0x120, 0x11e, 0x3, 0x2, 0x2, 0x2, 0x120, 
    0x121, 0x3, 0x2, 0x2, 0x2, 0x121, 0xb, 0x3, 0x2, 0x2, 0x2, 0x122, 0x120, 
    0x3, 0x2, 0x2, 0x2, 0x123, 0x126, 0x5, 0xb2, 0x5a, 0x2, 0x124, 0x125, 
    0x7, 0xd, 0x2, 0x2, 0x125, 0x127, 0x5, 0xea, 0x76, 0x2, 0x126, 0x124, 
    0x3, 0x2, 0x2, 0x2, 0x126, 0x127, 0x3, 0x2, 0x2, 0x2, 0x127, 0xd, 0x3, 
    0x2, 0x2, 0x2, 0x128, 0x137, 0x7, 0x44, 0x2, 0x2, 0x129, 0x12b, 0x5, 
    0xb2, 0x5a, 0x2, 0x12a, 0x129, 0x3, 0x2, 0x2, 0x2, 0x12a, 0x12b, 0x3, 
    0x2, 0x2, 0x2, 0x12b, 0x12c, 0x3, 0x2, 0x2, 0x2, 0x12c, 0x130, 0x7, 
    0xac, 0x2, 0x2, 0x12d, 0x12f, 0x5, 0x10, 0x9, 0x2, 0x12e, 0x12d, 0x3, 
    0x2, 0x2, 0x2, 0x12f, 0x132, 0x3, 0x2, 0x2, 0x2, 0x130, 0x12e, 0x3, 
    0x2, 0x2, 0x2, 0x130, 0x131, 0x3, 0x2, 0x2, 0x2, 0x131, 0x133, 0x3, 
    0x2, 0x2, 0x2, 0x132, 0x130, 0x3, 0x2, 0x2, 0x2, 0x133, 0x138, 0x7, 
    0xad, 0x2, 0x2, 0x134, 0x135, 0x5, 0xb2, 0x5a, 0x2, 0x135, 0x136, 0x7, 
    0xb0, 0x2, 0x2, 0x136, 0x138, 0x3, 0x2, 0x2, 0x2, 0x137, 0x12a, 0x3, 
    0x2, 0x2, 0x2, 0x137, 0x134, 0x3, 0x2, 0x2, 0x2, 0x138, 0xf, 0x3, 0x2, 
    0x2, 0x2, 0x139, 0x13f, 0x5, 0x36, 0x1c, 0x2, 0x13a, 0x13f, 0x5, 0x8, 
    0x5, 0x2, 0x13b, 0x13f, 0x5, 0x12, 0xa, 0x2, 0x13c, 0x13f, 0x5, 0x14, 
    0xb, 0x2, 0x13d, 0x13f, 0x5, 0x94, 0x4b, 0x2, 0x13e, 0x139, 0x3, 0x2, 
    0x2, 0x2, 0x13e, 0x13a, 0x3, 0x2, 0x2, 0x2, 0x13e, 0x13b, 0x3, 0x2, 
    0x2, 0x2, 0x13e, 0x13c, 0x3, 0x2, 0x2, 0x2, 0x13e, 0x13d, 0x3, 0x2, 
    0x2, 0x2, 0x13f, 0x11, 0x3, 0x2, 0x2, 0x2, 0x140, 0x141, 0x5, 0x26, 
    0x14, 0x2, 0x141, 0x143, 0x7, 0x30, 0x2, 0x2, 0x142, 0x144, 0x7, 0x9a, 
    0x2, 0x2, 0x143, 0x142, 0x3, 0x2, 0x2, 0x2, 0x143, 0x144, 0x3, 0x2, 
    0x2, 0x2, 0x144, 0x145, 0x3, 0x2, 0x2, 0x2, 0x145, 0x147, 0x5, 0xea, 
    0x76, 0x2, 0x146, 0x148, 0x5, 0x1a, 0xe, 0x2, 0x147, 0x146, 0x3, 0x2, 
    0x2, 0x2, 0x147, 0x148, 0x3, 0x2, 0x2, 0x2, 0x148, 0x149, 0x3, 0x2, 
    0x2, 0x2, 0x149, 0x14a, 0x7, 0xa8, 0x2, 0x2, 0x14a, 0x14b, 0x5, 0x6e, 
    0x38, 0x2, 0x14b, 0x14c, 0x7, 0xa9, 0x2, 0x2, 0x14c, 0x14d, 0x5, 0x3a, 
    0x1e, 0x2, 0x14d, 0x13, 0x3, 0x2, 0x2, 0x2, 0x14e, 0x150, 0x5, 0x26, 
    0x14, 0x2, 0x14f, 0x151, 0x7, 0x4b, 0x2, 0x2, 0x150, 0x14f, 0x3, 0x2, 
    0x2, 0x2, 0x150, 0x151, 0x3, 0x2, 0x2, 0x2, 0x151, 0x153, 0x3, 0x2, 
    0x2, 0x2, 0x152, 0x154, 0x5, 0xe8, 0x75, 0x2, 0x153, 0x152, 0x3, 0x2, 
    0x2, 0x2, 0x153, 0x154, 0x3, 0x2, 0x2, 0x2, 0x154, 0x156, 0x3, 0x2, 
    0x2, 0x2, 0x155, 0x157, 0x7, 0x49, 0x2, 0x2, 0x156, 0x155, 0x3, 0x2, 
    0x2, 0x2, 0x156, 0x157, 0x3, 0x2, 0x2, 0x2, 0x157, 0x16e, 0x3, 0x2, 
    0x2, 0x2, 0x158, 0x159, 0x5, 0x16, 0xc, 0x2, 0x159, 0x15b, 0x5, 0xea, 
    0x76, 0x2, 0x15a, 0x15c, 0x5, 0x1a, 0xe, 0x2, 0x15b, 0x15a, 0x3, 0x2, 
    0x2, 0x2, 0x15b, 0x15c, 0x3, 0x2, 0x2, 0x2, 0x15c, 0x15f, 0x3, 0x2, 
    0x2, 0x2, 0x15d, 0x15e, 0x7, 0x2a, 0x2, 0x2, 0x15e, 0x160, 0x5, 0xaa, 
    0x56, 0x2, 0x15f, 0x15d, 0x3, 0x2, 0x2, 0x2, 0x15f, 0x160, 0x3, 0x2, 
    0x2, 0x2, 0x160, 0x163, 0x3, 0x2, 0x2, 0x2, 0x161, 0x162, 0x7, 0x34, 
    0x2, 0x2, 0x162, 0x164, 0x5, 0x18, 0xd, 0x2, 0x163, 0x161, 0x3, 0x2, 
    0x2, 0x2, 0x163, 0x164, 0x3, 0x2, 0x2, 0x2, 0x164, 0x16f, 0x3, 0x2, 
    0x2, 0x2, 0x165, 0x166, 0x7, 0x3e, 0x2, 0x2, 0x166, 0x168, 0x5, 0xea, 
    0x76, 0x2, 0x167, 0x169, 0x5, 0x1a, 0xe, 0x2, 0x168, 0x167, 0x3, 0x2, 
    0x2, 0x2, 0x168, 0x169, 0x3, 0x2, 0x2, 0x2, 0x169, 0x16c, 0x3, 0x2, 
    0x2, 0x2, 0x16a, 0x16b, 0x7, 0x2a, 0x2, 0x2, 0x16b, 0x16d, 0x5, 0x18, 
    0xd, 0x2, 0x16c, 0x16a, 0x3, 0x2, 0x2, 0x2, 0x16c, 0x16d, 0x3, 0x2, 
    0x2, 0x2, 0x16d, 0x16f, 0x3, 0x2, 0x2, 0x2, 0x16e, 0x158, 0x3, 0x2, 
    0x2, 0x2, 0x16e, 0x165, 0x3, 0x2, 0x2, 0x2, 0x16f, 0x170, 0x3, 0x2, 
    0x2, 0x2, 0x170, 0x174, 0x7, 0xac, 0x2, 0x2, 0x171, 0x173, 0x5, 0x7c, 
    0x3f, 0x2, 0x172, 0x171, 0x3, 0x2, 0x2, 0x2, 0x173, 0x176, 0x3, 0x2, 
    0x2, 0x2, 0x174, 0x172, 0x3, 0x2, 0x2, 0x2, 0x174, 0x175, 0x3, 0x2, 
    0x2, 0x2, 0x175, 0x177, 0x3, 0x2, 0x2, 0x2, 0x176, 0x174, 0x3, 0x2, 
    0x2, 0x2, 0x177, 0x178, 0x7, 0xad, 0x2, 0x2, 0x178, 0x15, 0x3, 0x2, 
    0x2, 0x2, 0x179, 0x17a, 0x9, 0x3, 0x2, 0x2, 0x17a, 0x17, 0x3, 0x2, 0x2, 
    0x2, 0x17b, 0x180, 0x5, 0xaa, 0x56, 0x2, 0x17c, 0x17d, 0x7, 0xae, 0x2, 
    0x2, 0x17d, 0x17f, 0x5, 0xaa, 0x56, 0x2, 0x17e, 0x17c, 0x3, 0x2, 0x2, 
    0x2, 0x17f, 0x182, 0x3, 0x2, 0x2, 0x2, 0x180, 0x17e, 0x3, 0x2, 0x2, 
    0x2, 0x180, 0x181, 0x3, 0x2, 0x2, 0x2, 0x181, 0x19, 0x3, 0x2, 0x2, 0x2, 
    0x182, 0x180, 0x3, 0x2, 0x2, 0x2, 0x183, 0x184, 0x7, 0x78, 0x2, 0x2, 
    0x184, 0x185, 0x5, 0x1c, 0xf, 0x2, 0x185, 0x186, 0x7, 0x79, 0x2, 0x2, 
    0x186, 0x192, 0x3, 0x2, 0x2, 0x2, 0x187, 0x188, 0x7, 0x78, 0x2, 0x2, 
    0x188, 0x189, 0x5, 0x1e, 0x10, 0x2, 0x189, 0x18a, 0x7, 0x79, 0x2, 0x2, 
    0x18a, 0x192, 0x3, 0x2, 0x2, 0x2, 0x18b, 0x18c, 0x7, 0x78, 0x2, 0x2, 
    0x18c, 0x18d, 0x5, 0x1c, 0xf, 0x2, 0x18d, 0x18e, 0x7, 0xae, 0x2, 0x2, 
    0x18e, 0x18f, 0x5, 0x1e, 0x10, 0x2, 0x18f, 0x190, 0x7, 0x79, 0x2, 0x2, 
    0x190, 0x192, 0x3, 0x2, 0x2, 0x2, 0x191, 0x183, 0x3, 0x2, 0x2, 0x2, 
    0x191, 0x187, 0x3, 0x2, 0x2, 0x2, 0x191, 0x18b, 0x3, 0x2, 0x2, 0x2, 
    0x192, 0x1b, 0x3, 0x2, 0x2, 0x2, 0x193, 0x198, 0x5, 0x20, 0x11, 0x2, 
    0x194, 0x195, 0x7, 0xae, 0x2, 0x2, 0x195, 0x197, 0x5, 0x20, 0x11, 0x2, 
    0x196, 0x194, 0x3, 0x2, 0x2, 0x2, 0x197, 0x19a, 0x3, 0x2, 0x2, 0x2, 
    0x198, 0x196, 0x3, 0x2, 0x2, 0x2, 0x198, 0x199, 0x3, 0x2, 0x2, 0x2, 
    0x199, 0x1d, 0x3, 0x2, 0x2, 0x2, 0x19a, 0x198, 0x3, 0x2, 0x2, 0x2, 0x19b, 
    0x1a0, 0x5, 0x22, 0x12, 0x2, 0x19c, 0x19d, 0x7, 0xae, 0x2, 0x2, 0x19d, 
    0x19f, 0x5, 0x22, 0x12, 0x2, 0x19e, 0x19c, 0x3, 0x2, 0x2, 0x2, 0x19f, 
    0x1a2, 0x3, 0x2, 0x2, 0x2, 0x1a0, 0x19e, 0x3, 0x2, 0x2, 0x2, 0x1a0, 
    0x1a1, 0x3, 0x2, 0x2, 0x2, 0x1a1, 0x1f, 0x3, 0x2, 0x2, 0x2, 0x1a2, 0x1a0, 
    0x3, 0x2, 0x2, 0x2, 0x1a3, 0x1a4, 0x5, 0x26, 0x14, 0x2, 0x1a4, 0x1a5, 
    0x5, 0xea, 0x76, 0x2, 0x1a5, 0x21, 0x3, 0x2, 0x2, 0x2, 0x1a6, 0x1a7, 
    0x5, 0x26, 0x14, 0x2, 0x1a7, 0x1a8, 0x5, 0xea, 0x76, 0x2, 0x1a8, 0x1ab, 
    0x7, 0xb1, 0x2, 0x2, 0x1a9, 0x1ac, 0x5, 0xaa, 0x56, 0x2, 0x1aa, 0x1ac, 
    0x5, 0xf2, 0x7a, 0x2, 0x1ab, 0x1a9, 0x3, 0x2, 0x2, 0x2, 0x1ab, 0x1aa, 
    0x3, 0x2, 0x2, 0x2, 0x1ac, 0x23, 0x3, 0x2, 0x2, 0x2, 0x1ad, 0x1ae, 0x7, 
    0x78, 0x2, 0x2, 0x1ae, 0x1b3, 0x5, 0xac, 0x57, 0x2, 0x1af, 0x1b0, 0x7, 
    0xae, 0x2, 0x2, 0x1b0, 0x1b2, 0x5, 0xac, 0x57, 0x2, 0x1b1, 0x1af, 0x3, 
    0x2, 0x2, 0x2, 0x1b2, 0x1b5, 0x3, 0x2, 0x2, 0x2, 0x1b3, 0x1b1, 0x3, 
    0x2, 0x2, 0x2, 0x1b3, 0x1b4, 0x3, 0x2, 0x2, 0x2, 0x1b4, 0x1b6, 0x3, 
    0x2, 0x2, 0x2, 0x1b5, 0x1b3, 0x3, 0x2, 0x2, 0x2, 0x1b6, 0x1b7, 0x7, 
    0x79, 0x2, 0x2, 0x1b7, 0x25, 0x3, 0x2, 0x2, 0x2, 0x1b8, 0x1ba, 0x5, 
    0x28, 0x15, 0x2, 0x1b9, 0x1b8, 0x3, 0x2, 0x2, 0x2, 0x1ba, 0x1bd, 0x3, 
    0x2, 0x2, 0x2, 0x1bb, 0x1b9, 0x3, 0x2, 0x2, 0x2, 0x1bb, 0x1bc, 0x3, 
    0x2, 0x2, 0x2, 0x1bc, 0x27, 0x3, 0x2, 0x2, 0x2, 0x1bd, 0x1bb, 0x3, 0x2, 
    0x2, 0x2, 0x1be, 0x1c2, 0x7, 0xaa, 0x2, 0x2, 0x1bf, 0x1c0, 0x5, 0xea, 
    0x76, 0x2, 0x1c0, 0x1c1, 0x7, 0xaf, 0x2, 0x2, 0x1c1, 0x1c3, 0x3, 0x2, 
    0x2, 0x2, 0x1c2, 0x1bf, 0x3, 0x2, 0x2, 0x2, 0x1c2, 0x1c3, 0x3, 0x2, 
    0x2, 0x2, 0x1c3, 0x1c4, 0x3, 0x2, 0x2, 0x2, 0x1c4, 0x1c9, 0x5, 0x2a, 
    0x16, 0x2, 0x1c5, 0x1c6, 0x7, 0xae, 0x2, 0x2, 0x1c6, 0x1c8, 0x5, 0x2a, 
    0x16, 0x2, 0x1c7, 0x1c5, 0x3, 0x2, 0x2, 0x2, 0x1c8, 0x1cb, 0x3, 0x2, 
    0x2, 0x2, 0x1c9, 0x1c7, 0x3, 0x2, 0x2, 0x2, 0x1c9, 0x1ca, 0x3, 0x2, 
    0x2, 0x2, 0x1ca, 0x1cc, 0x3, 0x2, 0x2, 0x2, 0x1cb, 0x1c9, 0x3, 0x2, 
    0x2, 0x2, 0x1cc, 0x1cd, 0x7, 0xab, 0x2, 0x2, 0x1cd, 0x29, 0x3, 0x2, 
    0x2, 0x2, 0x1ce, 0x1e1, 0x5, 0xb0, 0x59, 0x2, 0x1cf, 0x1d0, 0x5, 0xb0, 
    0x59, 0x2, 0x1d0, 0x1d1, 0x7, 0xa8, 0x2, 0x2, 0x1d1, 0x1d2, 0x5, 0x2c, 
    0x17, 0x2, 0x1d2, 0x1d3, 0x7, 0xa9, 0x2, 0x2, 0x1d3, 0x1e1, 0x3, 0x2, 
    0x2, 0x2, 0x1d4, 0x1d5, 0x5, 0xb0, 0x59, 0x2, 0x1d5, 0x1d6, 0x7, 0xa8, 
    0x2, 0x2, 0x1d6, 0x1d7, 0x5, 0x2e, 0x18, 0x2, 0x1d7, 0x1d8, 0x7, 0xa9, 
    0x2, 0x2, 0x1d8, 0x1e1, 0x3, 0x2, 0x2, 0x2, 0x1d9, 0x1da, 0x5, 0xb0, 
    0x59, 0x2, 0x1da, 0x1db, 0x7, 0xa8, 0x2, 0x2, 0x1db, 0x1dc, 0x5, 0x2c, 
    0x17, 0x2, 0x1dc, 0x1dd, 0x7, 0xae, 0x2, 0x2, 0x1dd, 0x1de, 0x5, 0x2e, 
    0x18, 0x2, 0x1de, 0x1df, 0x7, 0xa9, 0x2, 0x2, 0x1df, 0x1e1, 0x3, 0x2, 
    0x2, 0x2, 0x1e0, 0x1ce, 0x3, 0x2, 0x2, 0x2, 0x1e0, 0x1cf, 0x3, 0x2, 
    0x2, 0x2, 0x1e0, 0x1d4, 0x3, 0x2, 0x2, 0x2, 0x1e0, 0x1d9, 0x3, 0x2, 
    0x2, 0x2, 0x1e1, 0x2b, 0x3, 0x2, 0x2, 0x2, 0x1e2, 0x1e7, 0x5, 0x9a, 
    0x4e, 0x2, 0x1e3, 0x1e4, 0x7, 0xae, 0x2, 0x2, 0x1e4, 0x1e6, 0x5, 0x9a, 
    0x4e, 0x2, 0x1e5, 0x1e3, 0x3, 0x2, 0x2, 0x2, 0x1e6, 0x1e9, 0x3, 0x2, 
    0x2, 0x2, 0x1e7, 0x1e5, 0x3, 0x2, 0x2, 0x2, 0x1e7, 0x1e8, 0x3, 0x2, 
    0x2, 0x2, 0x1e8, 0x2d, 0x3, 0x2, 0x2, 0x2, 0x1e9, 0x1e7, 0x3, 0x2, 0x2, 
    0x2, 0x1ea, 0x1ef, 0x5, 0x30, 0x19, 0x2, 0x1eb, 0x1ec, 0x7, 0xae, 0x2, 
    0x2, 0x1ec, 0x1ee, 0x5, 0x30, 0x19, 0x2, 0x1ed, 0x1eb, 0x3, 0x2, 0x2, 
    0x2, 0x1ee, 0x1f1, 0x3, 0x2, 0x2, 0x2, 0x1ef, 0x1ed, 0x3, 0x2, 0x2, 
    0x2, 0x1ef, 0x1f0, 0x3, 0x2, 0x2, 0x2, 0x1f0, 0x2f, 0x3, 0x2, 0x2, 0x2, 
    0x1f1, 0x1ef, 0x3, 0x2, 0x2, 0x2, 0x1f2, 0x1f3, 0x7, 0xb4, 0x2, 0x2, 
    0x1f3, 0x1f4, 0x7, 0x7a, 0x2, 0x2, 0x1f4, 0x1f5, 0x5, 0x9a, 0x4e, 0x2, 
    0x1f5, 0x31, 0x3, 0x2, 0x2, 0x2, 0x1f6, 0x1f8, 0x5, 0x34, 0x1b, 0x2, 
    0x1f7, 0x1f6, 0x3, 0x2, 0x2, 0x2, 0x1f8, 0x1fb, 0x3, 0x2, 0x2, 0x2, 
    0x1f9, 0x1f7, 0x3, 0x2, 0x2, 0x2, 0x1f9, 0x1fa, 0x3, 0x2, 0x2, 0x2, 
    0x1fa, 0x33, 0x3, 0x2, 0x2, 0x2, 0x1fb, 0x1f9, 0x3, 0x2, 0x2, 0x2, 0x1fc, 
    0x200, 0x5, 0x36, 0x1c, 0x2, 0x1fd, 0x200, 0x5, 0x12, 0xa, 0x2, 0x1fe, 
    0x200, 0x5, 0x14, 0xb, 0x2, 0x1ff, 0x1fc, 0x3, 0x2, 0x2, 0x2, 0x1ff, 
    0x1fd, 0x3, 0x2, 0x2, 0x2, 0x1ff, 0x1fe, 0x3, 0x2, 0x2, 0x2, 0x200, 
    0x35, 0x3, 0x2, 0x2, 0x2, 0x201, 0x202, 0x5, 0xea, 0x76, 0x2, 0x202, 
    0x203, 0x7, 0xaf, 0x2, 0x2, 0x203, 0x21c, 0x3, 0x2, 0x2, 0x2, 0x204, 
    0x21c, 0x5, 0x3a, 0x1e, 0x2, 0x205, 0x21c, 0x5, 0x3c, 0x1f, 0x2, 0x206, 
    0x21c, 0x5, 0x46, 0x24, 0x2, 0x207, 0x21c, 0x5, 0x48, 0x25, 0x2, 0x208, 
    0x21c, 0x5, 0x4a, 0x26, 0x2, 0x209, 0x21c, 0x5, 0x50, 0x29, 0x2, 0x20a, 
    0x21c, 0x5, 0x54, 0x2b, 0x2, 0x20b, 0x21c, 0x5, 0x56, 0x2c, 0x2, 0x20c, 
    0x21c, 0x5, 0x58, 0x2d, 0x2, 0x20d, 0x20e, 0x5, 0xa0, 0x51, 0x2, 0x20e, 
    0x20f, 0x7, 0xb0, 0x2, 0x2, 0x20f, 0x21c, 0x3, 0x2, 0x2, 0x2, 0x210, 
    0x21c, 0x5, 0x74, 0x3b, 0x2, 0x211, 0x21c, 0x5, 0x7a, 0x3e, 0x2, 0x212, 
    0x21c, 0x5, 0x78, 0x3d, 0x2, 0x213, 0x21c, 0x5, 0x5a, 0x2e, 0x2, 0x214, 
    0x21c, 0x5, 0x5c, 0x2f, 0x2, 0x215, 0x21c, 0x5, 0x5e, 0x30, 0x2, 0x216, 
    0x21c, 0x5, 0x60, 0x31, 0x2, 0x217, 0x21c, 0x5, 0x66, 0x34, 0x2, 0x218, 
    0x21c, 0x5, 0x68, 0x35, 0x2, 0x219, 0x21c, 0x5, 0x6a, 0x36, 0x2, 0x21a, 
    0x21c, 0x5, 0x38, 0x1d, 0x2, 0x21b, 0x201, 0x3, 0x2, 0x2, 0x2, 0x21b, 
    0x204, 0x3, 0x2, 0x2, 0x2, 0x21b, 0x205, 0x3, 0x2, 0x2, 0x2, 0x21b, 
    0x206, 0x3, 0x2, 0x2, 0x2, 0x21b, 0x207, 0x3, 0x2, 0x2, 0x2, 0x21b, 
    0x208, 0x3, 0x2, 0x2, 0x2, 0x21b, 0x209, 0x3, 0x2, 0x2, 0x2, 0x21b, 
    0x20a, 0x3, 0x2, 0x2, 0x2, 0x21b, 0x20b, 0x3, 0x2, 0x2, 0x2, 0x21b, 
    0x20c, 0x3, 0x2, 0x2, 0x2, 0x21b, 0x20d, 0x3, 0x2, 0x2, 0x2, 0x21b, 
    0x210, 0x3, 0x2, 0x2, 0x2, 0x21b, 0x211, 0x3, 0x2, 0x2, 0x2, 0x21b, 
    0x212, 0x3, 0x2, 0x2, 0x2, 0x21b, 0x213, 0x3, 0x2, 0x2, 0x2, 0x21b, 
    0x214, 0x3, 0x2, 0x2, 0x2, 0x21b, 0x215, 0x3, 0x2, 0x2, 0x2, 0x21b, 
    0x216, 0x3, 0x2, 0x2, 0x2, 0x21b, 0x217, 0x3, 0x2, 0x2, 0x2, 0x21b, 
    0x218, 0x3, 0x2, 0x2, 0x2, 0x21b, 0x219, 0x3, 0x2, 0x2, 0x2, 0x21b, 
    0x21a, 0x3, 0x2, 0x2, 0x2, 0x21c, 0x37, 0x3, 0x2, 0x2, 0x2, 0x21d, 0x21e, 
    0x7, 0xb0, 0x2, 0x2, 0x21e, 0x39, 0x3, 0x2, 0x2, 0x2, 0x21f, 0x220, 
    0x7, 0xac, 0x2, 0x2, 0x220, 0x221, 0x5, 0x32, 0x1a, 0x2, 0x221, 0x222, 
    0x7, 0xad, 0x2, 0x2, 0x222, 0x3b, 0x3, 0x2, 0x2, 0x2, 0x223, 0x224, 
    0x7, 0x33, 0x2, 0x2, 0x224, 0x225, 0x5, 0x98, 0x4d, 0x2, 0x225, 0x229, 
    0x5, 0x36, 0x1c, 0x2, 0x226, 0x228, 0x5, 0x3e, 0x20, 0x2, 0x227, 0x226, 
    0x3, 0x2, 0x2, 0x2, 0x228, 0x22b, 0x3, 0x2, 0x2, 0x2, 0x229, 0x227, 
    0x3, 0x2, 0x2, 0x2, 0x229, 0x22a, 0x3, 0x2, 0x2, 0x2, 0x22a, 0x22d, 
    0x3, 0x2, 0x2, 0x2, 0x22b, 0x229, 0x3, 0x2, 0x2, 0x2, 0x22c, 0x22e, 
    0x5, 0x42, 0x22, 0x2, 0x22d, 0x22c, 0x3, 0x2, 0x2, 0x2, 0x22d, 0x22e, 
    0x3, 0x2, 0x2, 0x2, 0x22e, 0x240, 0x3, 0x2, 0x2, 0x2, 0x22f, 0x230, 
    0x7, 0x33, 0x2, 0x2, 0x230, 0x231, 0x5, 0x98, 0x4d, 0x2, 0x231, 0x232, 
    0x7, 0xaf, 0x2, 0x2, 0x232, 0x236, 0x5, 0x32, 0x1a, 0x2, 0x233, 0x235, 
    0x5, 0x40, 0x21, 0x2, 0x234, 0x233, 0x3, 0x2, 0x2, 0x2, 0x235, 0x238, 
    0x3, 0x2, 0x2, 0x2, 0x236, 0x234, 0x3, 0x2, 0x2, 0x2, 0x236, 0x237, 
    0x3, 0x2, 0x2, 0x2, 0x237, 0x23a, 0x3, 0x2, 0x2, 0x2, 0x238, 0x236, 
    0x3, 0x2, 0x2, 0x2, 0x239, 0x23b, 0x5, 0x44, 0x23, 0x2, 0x23a, 0x239, 
    0x3, 0x2, 0x2, 0x2, 0x23a, 0x23b, 0x3, 0x2, 0x2, 0x2, 0x23b, 0x23c, 
    0x3, 0x2, 0x2, 0x2, 0x23c, 0x23d, 0x7, 0x25, 0x2, 0x2, 0x23d, 0x23e, 
    0x7, 0xb0, 0x2, 0x2, 0x23e, 0x240, 0x3, 0x2, 0x2, 0x2, 0x23f, 0x223, 
    0x3, 0x2, 0x2, 0x2, 0x23f, 0x22f, 0x3, 0x2, 0x2, 0x2, 0x240, 0x3d, 0x3, 
    0x2, 0x2, 0x2, 0x241, 0x242, 0x7, 0x20, 0x2, 0x2, 0x242, 0x243, 0x5, 
    0x98, 0x4d, 0x2, 0x243, 0x244, 0x5, 0x36, 0x1c, 0x2, 0x244, 0x3f, 0x3, 
    0x2, 0x2, 0x2, 0x245, 0x246, 0x7, 0x20, 0x2, 0x2, 0x246, 0x247, 0x5, 
    0x98, 0x4d, 0x2, 0x247, 0x248, 0x7, 0xaf, 0x2, 0x2, 0x248, 0x249, 0x5, 
    0x32, 0x1a, 0x2, 0x249, 0x41, 0x3, 0x2, 0x2, 0x2, 0x24a, 0x24b, 0x7, 
    0x1f, 0x2, 0x2, 0x24b, 0x24c, 0x5, 0x36, 0x1c, 0x2, 0x24c, 0x43, 0x3, 
    0x2, 0x2, 0x2, 0x24d, 0x24e, 0x7, 0x1f, 0x2, 0x2, 0x24e, 0x24f, 0x7, 
    0xaf, 0x2, 0x2, 0x24f, 0x250, 0x5, 0x32, 0x1a, 0x2, 0x250, 0x45, 0x3, 
    0x2, 0x2, 0x2, 0x251, 0x252, 0x7, 0x5e, 0x2, 0x2, 0x252, 0x259, 0x5, 
    0x98, 0x4d, 0x2, 0x253, 0x25a, 0x5, 0x36, 0x1c, 0x2, 0x254, 0x255, 0x7, 
    0xaf, 0x2, 0x2, 0x255, 0x256, 0x5, 0x32, 0x1a, 0x2, 0x256, 0x257, 0x7, 
    0x27, 0x2, 0x2, 0x257, 0x258, 0x7, 0xb0, 0x2, 0x2, 0x258, 0x25a, 0x3, 
    0x2, 0x2, 0x2, 0x259, 0x253, 0x3, 0x2, 0x2, 0x2, 0x259, 0x254, 0x3, 
    0x2, 0x2, 0x2, 0x25a, 0x47, 0x3, 0x2, 0x2, 0x2, 0x25b, 0x25c, 0x7, 0x1b, 
    0x2, 0x2, 0x25c, 0x25d, 0x5, 0x36, 0x1c, 0x2, 0x25d, 0x25e, 0x7, 0x5e, 
    0x2, 0x2, 0x25e, 0x25f, 0x5, 0x98, 0x4d, 0x2, 0x25f, 0x260, 0x7, 0xb0, 
    0x2, 0x2, 0x260, 0x49, 0x3, 0x2, 0x2, 0x2, 0x261, 0x262, 0x7, 0x2e, 
    0x2, 0x2, 0x262, 0x264, 0x7, 0xa8, 0x2, 0x2, 0x263, 0x265, 0x5, 0x4c, 
    0x27, 0x2, 0x264, 0x263, 0x3, 0x2, 0x2, 0x2, 0x264, 0x265, 0x3, 0x2, 
    0x2, 0x2, 0x265, 0x266, 0x3, 0x2, 0x2, 0x2, 0x266, 0x268, 0x7, 0xb0, 
    0x2, 0x2, 0x267, 0x269, 0x5, 0x96, 0x4c, 0x2, 0x268, 0x267, 0x3, 0x2, 
    0x2, 0x2, 0x268, 0x269, 0x3, 0x2, 0x2, 0x2, 0x269, 0x26a, 0x3, 0x2, 
    0x2, 0x2, 0x26a, 0x26c, 0x7, 0xb0, 0x2, 0x2, 0x26b, 0x26d, 0x5, 0x4e, 
    0x28, 0x2, 0x26c, 0x26b, 0x3, 0x2, 0x2, 0x2, 0x26c, 0x26d, 0x3, 0x2, 
    0x2, 0x2, 0x26d, 0x26e, 0x3, 0x2, 0x2, 0x2, 0x26e, 0x275, 0x7, 0xa9, 
    0x2, 0x2, 0x26f, 0x276, 0x5, 0x36, 0x1c, 0x2, 0x270, 0x271, 0x7, 0xaf, 
    0x2, 0x2, 0x271, 0x272, 0x5, 0x32, 0x1a, 0x2, 0x272, 0x273, 0x7, 0x23, 
    0x2, 0x2, 0x273, 0x274, 0x7, 0xb0, 0x2, 0x2, 0x274, 0x276, 0x3, 0x2, 
    0x2, 0x2, 0x275, 0x26f, 0x3, 0x2, 0x2, 0x2, 0x275, 0x270, 0x3, 0x2, 
    0x2, 0x2, 0x276, 0x4b, 0x3, 0x2, 0x2, 0x2, 0x277, 0x278, 0x5, 0x96, 
    0x4c, 0x2, 0x278, 0x4d, 0x3, 0x2, 0x2, 0x2, 0x279, 0x27a, 0x5, 0x96, 
    0x4c, 0x2, 0x27a, 0x4f, 0x3, 0x2, 0x2, 0x2, 0x27b, 0x27c, 0x7, 0x54, 
    0x2, 0x2, 0x27c, 0x294, 0x5, 0x98, 0x4d, 0x2, 0x27d, 0x27f, 0x7, 0xac, 
    0x2, 0x2, 0x27e, 0x280, 0x7, 0xb0, 0x2, 0x2, 0x27f, 0x27e, 0x3, 0x2, 
    0x2, 0x2, 0x27f, 0x280, 0x3, 0x2, 0x2, 0x2, 0x280, 0x284, 0x3, 0x2, 
    0x2, 0x2, 0x281, 0x283, 0x5, 0x52, 0x2a, 0x2, 0x282, 0x281, 0x3, 0x2, 
    0x2, 0x2, 0x283, 0x286, 0x3, 0x2, 0x2, 0x2, 0x284, 0x282, 0x3, 0x2, 
    0x2, 0x2, 0x284, 0x285, 0x3, 0x2, 0x2, 0x2, 0x285, 0x287, 0x3, 0x2, 
    0x2, 0x2, 0x286, 0x284, 0x3, 0x2, 0x2, 0x2, 0x287, 0x295, 0x7, 0xad, 
    0x2, 0x2, 0x288, 0x28a, 0x7, 0xaf, 0x2, 0x2, 0x289, 0x28b, 0x7, 0xb0, 
    0x2, 0x2, 0x28a, 0x289, 0x3, 0x2, 0x2, 0x2, 0x28a, 0x28b, 0x3, 0x2, 
    0x2, 0x2, 0x28b, 0x28f, 0x3, 0x2, 0x2, 0x2, 0x28c, 0x28e, 0x5, 0x52, 
    0x2a, 0x2, 0x28d, 0x28c, 0x3, 0x2, 0x2, 0x2, 0x28e, 0x291, 0x3, 0x2, 
    0x2, 0x2, 0x28f, 0x28d, 0x3, 0x2, 0x2, 0x2, 0x28f, 0x290, 0x3, 0x2, 
    0x2, 0x2, 0x290, 0x292, 0x3, 0x2, 0x2, 0x2, 0x291, 0x28f, 0x3, 0x2, 
    0x2, 0x2, 0x292, 0x293, 0x7, 0x26, 0x2, 0x2, 0x293, 0x295, 0x7, 0xb0, 
    0x2, 0x2, 0x294, 0x27d, 0x3, 0x2, 0x2, 0x2, 0x294, 0x288, 0x3, 0x2, 
    0x2, 0x2, 0x295, 0x51, 0x3, 0x2, 0x2, 0x2, 0x296, 0x297, 0x7, 0x13, 
    0x2, 0x2, 0x297, 0x29a, 0x5, 0x9a, 0x4e, 0x2, 0x298, 0x29a, 0x7, 0x1a, 
    0x2, 0x2, 0x299, 0x296, 0x3, 0x2, 0x2, 0x2, 0x299, 0x298, 0x3, 0x2, 
    0x2, 0x2, 0x29a, 0x29b, 0x3, 0x2, 0x2, 0x2, 0x29b, 0x29d, 0x9, 0x4, 
    0x2, 0x2, 0x29c, 0x299, 0x3, 0x2, 0x2, 0x2, 0x29d, 0x29e, 0x3, 0x2, 
    0x2, 0x2, 0x29e, 0x29c, 0x3, 0x2, 0x2, 0x2, 0x29e, 0x29f, 0x3, 0x2, 
    0x2, 0x2, 0x29f, 0x2a0, 0x3, 0x2, 0x2, 0x2, 0x2a0, 0x2a1, 0x5, 0x32, 
    0x1a, 0x2, 0x2a1, 0x53, 0x3, 0x2, 0x2, 0x2, 0x2a2, 0x2a4, 0x7, 0x11, 
    0x2, 0x2, 0x2a3, 0x2a5, 0x5, 0x9a, 0x4e, 0x2, 0x2a4, 0x2a3, 0x3, 0x2, 
    0x2, 0x2, 0x2a4, 0x2a5, 0x3, 0x2, 0x2, 0x2, 0x2a5, 0x2a6, 0x3, 0x2, 
    0x2, 0x2, 0x2a6, 0x2a7, 0x7, 0xb0, 0x2, 0x2, 0x2a7, 0x55, 0x3, 0x2, 
    0x2, 0x2, 0x2a8, 0x2aa, 0x7, 0x18, 0x2, 0x2, 0x2a9, 0x2ab, 0x5, 0x9a, 
    0x4e, 0x2, 0x2aa, 0x2a9, 0x3, 0x2, 0x2, 0x2, 0x2aa, 0x2ab, 0x3, 0x2, 
    0x2, 0x2, 0x2ab, 0x2ac, 0x3, 0x2, 0x2, 0x2, 0x2ac, 0x2ad, 0x7, 0xb0, 
    0x2, 0x2, 0x2ad, 0x57, 0x3, 0x2, 0x2, 0x2, 0x2ae, 0x2b0, 0x7, 0x51, 
    0x2, 0x2, 0x2af, 0x2b1, 0x5, 0x9a, 0x4e, 0x2, 0x2b0, 0x2af, 0x3, 0x2, 
    0x2, 0x2, 0x2b0, 0x2b1, 0x3, 0x2, 0x2, 0x2, 0x2b1, 0x2b2, 0x3, 0x2, 
    0x2, 0x2, 0x2b2, 0x2b3, 0x7, 0xb0, 0x2, 0x2, 0x2b3, 0x59, 0x3, 0x2, 
    0x2, 0x2, 0x2b4, 0x2b5, 0x5, 0x9a, 0x4e, 0x2, 0x2b5, 0x2b6, 0x7, 0xb0, 
    0x2, 0x2, 0x2b6, 0x5b, 0x3, 0x2, 0x2, 0x2, 0x2b7, 0x2b8, 0x7, 0x5b, 
    0x2, 0x2, 0x2b8, 0x2b9, 0x7, 0xa8, 0x2, 0x2, 0x2b9, 0x2ba, 0x5, 0xce, 
    0x68, 0x2, 0x2ba, 0x2bb, 0x7, 0xa9, 0x2, 0x2, 0x2bb, 0x2bc, 0x7, 0xb0, 
    0x2, 0x2, 0x2bc, 0x5d, 0x3, 0x2, 0x2, 0x2, 0x2bd, 0x2e4, 0x7, 0x2f, 
    0x2, 0x2, 0x2be, 0x2bf, 0x7, 0xa8, 0x2, 0x2, 0x2bf, 0x2c0, 0x5, 0xd0, 
    0x69, 0x2, 0x2c0, 0x2c2, 0x7, 0xd, 0x2, 0x2, 0x2c1, 0x2c3, 0x7, 0x9a, 
    0x2, 0x2, 0x2c2, 0x2c1, 0x3, 0x2, 0x2, 0x2, 0x2c2, 0x2c3, 0x3, 0x2, 
    0x2, 0x2, 0x2c3, 0x2c4, 0x3, 0x2, 0x2, 0x2, 0x2c4, 0x2ca, 0x5, 0xd0, 
    0x69, 0x2, 0x2c5, 0x2c7, 0x7, 0x7a, 0x2, 0x2, 0x2c6, 0x2c8, 0x7, 0x9a, 
    0x2, 0x2, 0x2c7, 0x2c6, 0x3, 0x2, 0x2, 0x2, 0x2c7, 0x2c8, 0x3, 0x2, 
    0x2, 0x2, 0x2c8, 0x2c9, 0x3, 0x2, 0x2, 0x2, 0x2c9, 0x2cb, 0x5, 0xd0, 
    0x69, 0x2, 0x2ca, 0x2c5, 0x3, 0x2, 0x2, 0x2, 0x2ca, 0x2cb, 0x3, 0x2, 
    0x2, 0x2, 0x2cb, 0x2cc, 0x3, 0x2, 0x2, 0x2, 0x2cc, 0x2cd, 0x7, 0xa9, 
    0x2, 0x2, 0x2cd, 0x2e5, 0x3, 0x2, 0x2, 0x2, 0x2ce, 0x2cf, 0x7, 0xa8, 
    0x2, 0x2, 0x2cf, 0x2d0, 0x5, 0x9a, 0x4e, 0x2, 0x2d0, 0x2d1, 0x7, 0xd, 
    0x2, 0x2, 0x2d1, 0x2d7, 0x5, 0xd0, 0x69, 0x2, 0x2d2, 0x2d4, 0x7, 0x7a, 
    0x2, 0x2, 0x2d3, 0x2d5, 0x7, 0x9a, 0x2, 0x2, 0x2d4, 0x2d3, 0x3, 0x2, 
    0x2, 0x2, 0x2d4, 0x2d5, 0x3, 0x2, 0x2, 0x2, 0x2d5, 0x2d6, 0x3, 0x2, 
    0x2, 0x2, 0x2d6, 0x2d8, 0x5, 0xd0, 0x69, 0x2, 0x2d7, 0x2d2, 0x3, 0x2, 
    0x2, 0x2, 0x2d7, 0x2d8, 0x3, 0x2, 0x2, 0x2, 0x2d8, 0x2d9, 0x3, 0x2, 
    0x2, 0x2, 0x2d9, 0x2da, 0x7, 0xa9, 0x2, 0x2, 0x2da, 0x2e5, 0x3, 0x2, 
    0x2, 0x2, 0x2db, 0x2dc, 0x7, 0xa8, 0x2, 0x2, 0x2dc, 0x2dd, 0x5, 0xd0, 
    0x69, 0x2, 0x2dd, 0x2de, 0x7, 0xd, 0x2, 0x2, 0x2de, 0x2df, 0x7, 0x40, 
    0x2, 0x2, 0x2df, 0x2e0, 0x7, 0xa8, 0x2, 0x2, 0x2e0, 0x2e1, 0x5, 0xe4, 
    0x73, 0x2, 0x2e1, 0x2e2, 0x7, 0xa9, 0x2, 0x2, 0x2e2, 0x2e3, 0x7, 0xa9, 
    0x2, 0x2, 0x2e3, 0x2e5, 0x3, 0x2, 0x2, 0x2, 0x2e4, 0x2be, 0x3, 0x2, 
    0x2, 0x2, 0x2e4, 0x2ce, 0x3, 0x2, 0x2, 0x2, 0x2e4, 0x2db, 0x3, 0x2, 
    0x2, 0x2, 0x2e5, 0x2ec, 0x3, 0x2, 0x2, 0x2, 0x2e6, 0x2ed, 0x5, 0x36, 
    0x1c, 0x2, 0x2e7, 0x2e8, 0x7, 0xaf, 0x2, 0x2, 0x2e8, 0x2e9, 0x5, 0x32, 
    0x1a, 0x2, 0x2e9, 0x2ea, 0x7, 0x24, 0x2, 0x2, 0x2ea, 0x2eb, 0x7, 0xb0, 
    0x2, 0x2, 0x2eb, 0x2ed, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2e6, 0x3, 0x2, 
    0x2, 0x2, 0x2ec, 0x2e7, 0x3, 0x2, 0x2, 0x2, 0x2ed, 0x5f, 0x3, 0x2, 0x2, 
    0x2, 0x2ee, 0x2ef, 0x7, 0x57, 0x2, 0x2, 0x2ef, 0x2ff, 0x5, 0x3a, 0x1e, 
    0x2, 0x2f0, 0x2f2, 0x5, 0x62, 0x32, 0x2, 0x2f1, 0x2f0, 0x3, 0x2, 0x2, 
    0x2, 0x2f2, 0x2f3, 0x3, 0x2, 0x2, 0x2, 0x2f3, 0x2f1, 0x3, 0x2, 0x2, 
    0x2, 0x2f3, 0x2f4, 0x3, 0x2, 0x2, 0x2, 0x2f4, 0x2f6, 0x3, 0x2, 0x2, 
    0x2, 0x2f5, 0x2f7, 0x5, 0x64, 0x33, 0x2, 0x2f6, 0x2f5, 0x3, 0x2, 0x2, 
    0x2, 0x2f6, 0x2f7, 0x3, 0x2, 0x2, 0x2, 0x2f7, 0x300, 0x3, 0x2, 0x2, 
    0x2, 0x2f8, 0x2fa, 0x5, 0x62, 0x32, 0x2, 0x2f9, 0x2f8, 0x3, 0x2, 0x2, 
    0x2, 0x2fa, 0x2fd, 0x3, 0x2, 0x2, 0x2, 0x2fb, 0x2f9, 0x3, 0x2, 0x2, 
    0x2, 0x2fb, 0x2fc, 0x3, 0x2, 0x2, 0x2, 0x2fc, 0x2fe, 0x3, 0x2, 0x2, 
    0x2, 0x2fd, 0x2fb, 0x3, 0x2, 0x2, 0x2, 0x2fe, 0x300, 0x5, 0x64, 0x33, 
    0x2, 0x2ff, 0x2f1, 0x3, 0x2, 0x2, 0x2, 0x2ff, 0x2fb, 0x3, 0x2, 0x2, 
    0x2, 0x300, 0x61, 0x3, 0x2, 0x2, 0x2, 0x301, 0x302, 0x7, 0x14, 0x2, 
    0x2, 0x302, 0x303, 0x7, 0xa8, 0x2, 0x2, 0x303, 0x304, 0x5, 0xaa, 0x56, 
    0x2, 0x304, 0x305, 0x7, 0xb4, 0x2, 0x2, 0x305, 0x306, 0x7, 0xa9, 0x2, 
    0x2, 0x306, 0x307, 0x5, 0x3a, 0x1e, 0x2, 0x307, 0x63, 0x3, 0x2, 0x2, 
    0x2, 0x308, 0x309, 0x7, 0x2c, 0x2, 0x2, 0x309, 0x30a, 0x5, 0x3a, 0x1e, 
    0x2, 0x30a, 0x65, 0x3, 0x2, 0x2, 0x2, 0x30b, 0x30c, 0x7, 0x55, 0x2, 
    0x2, 0x30c, 0x30d, 0x5, 0x9a, 0x4e, 0x2, 0x30d, 0x30e, 0x7, 0xb0, 0x2, 
    0x2, 0x30e, 0x67, 0x3, 0x2, 0x2, 0x2, 0x30f, 0x310, 0x7, 0x32, 0x2, 
    0x2, 0x310, 0x311, 0x5, 0xea, 0x76, 0x2, 0x311, 0x312, 0x7, 0xb0, 0x2, 
    0x2, 0x312, 0x69, 0x3, 0x2, 0x2, 0x2, 0x313, 0x314, 0x7, 0x19, 0x2, 
    0x2, 0x314, 0x315, 0x7, 0xa8, 0x2, 0x2, 0x315, 0x316, 0x5, 0x6c, 0x37, 
    0x2, 0x316, 0x31d, 0x7, 0xa9, 0x2, 0x2, 0x317, 0x31e, 0x5, 0x36, 0x1c, 
    0x2, 0x318, 0x319, 0x7, 0xaf, 0x2, 0x2, 0x319, 0x31a, 0x5, 0x32, 0x1a, 
    0x2, 0x31a, 0x31b, 0x7, 0x22, 0x2, 0x2, 0x31b, 0x31c, 0x7, 0xb0, 0x2, 
    0x2, 0x31c, 0x31e, 0x3, 0x2, 0x2, 0x2, 0x31d, 0x317, 0x3, 0x2, 0x2, 
    0x2, 0x31d, 0x318, 0x3, 0x2, 0x2, 0x2, 0x31e, 0x6b, 0x3, 0x2, 0x2, 0x2, 
    0x31f, 0x324, 0x5, 0x92, 0x4a, 0x2, 0x320, 0x321, 0x7, 0xae, 0x2, 0x2, 
    0x321, 0x323, 0x5, 0x92, 0x4a, 0x2, 0x322, 0x320, 0x3, 0x2, 0x2, 0x2, 
    0x323, 0x326, 0x3, 0x2, 0x2, 0x2, 0x324, 0x322, 0x3, 0x2, 0x2, 0x2, 
    0x324, 0x325, 0x3, 0x2, 0x2, 0x2, 0x325, 0x6d, 0x3, 0x2, 0x2, 0x2, 0x326, 
    0x324, 0x3, 0x2, 0x2, 0x2, 0x327, 0x329, 0x5, 0x70, 0x39, 0x2, 0x328, 
    0x327, 0x3, 0x2, 0x2, 0x2, 0x328, 0x329, 0x3, 0x2, 0x2, 0x2, 0x329, 
    0x32e, 0x3, 0x2, 0x2, 0x2, 0x32a, 0x32b, 0x7, 0xae, 0x2, 0x2, 0x32b, 
    0x32d, 0x5, 0x70, 0x39, 0x2, 0x32c, 0x32a, 0x3, 0x2, 0x2, 0x2, 0x32d, 
    0x330, 0x3, 0x2, 0x2, 0x2, 0x32e, 0x32c, 0x3, 0x2, 0x2, 0x2, 0x32e, 
    0x32f, 0x3, 0x2, 0x2, 0x2, 0x32f, 0x6f, 0x3, 0x2, 0x2, 0x2, 0x330, 0x32e, 
    0x3, 0x2, 0x2, 0x2, 0x331, 0x333, 0x5, 0x26, 0x14, 0x2, 0x332, 0x334, 
    0x5, 0x72, 0x3a, 0x2, 0x333, 0x332, 0x3, 0x2, 0x2, 0x2, 0x333, 0x334, 
    0x3, 0x2, 0x2, 0x2, 0x334, 0x336, 0x3, 0x2, 0x2, 0x2, 0x335, 0x337, 
    0x7, 0x9a, 0x2, 0x2, 0x336, 0x335, 0x3, 0x2, 0x2, 0x2, 0x336, 0x337, 
    0x3, 0x2, 0x2, 0x2, 0x337, 0x339, 0x3, 0x2, 0x2, 0x2, 0x338, 0x33a, 
    0x7, 0x97, 0x2, 0x2, 0x339, 0x338, 0x3, 0x2, 0x2, 0x2, 0x339, 0x33a, 
    0x3, 0x2, 0x2, 0x2, 0x33a, 0x33b, 0x3, 0x2, 0x2, 0x2, 0x33b, 0x33c, 
    0x5, 0x90, 0x49, 0x2, 0x33c, 0x71, 0x3, 0x2, 0x2, 0x2, 0x33d, 0x341, 
    0x5, 0xaa, 0x56, 0x2, 0x33e, 0x341, 0x7, 0x12, 0x2, 0x2, 0x33f, 0x341, 
    0x5, 0xf2, 0x7a, 0x2, 0x340, 0x33d, 0x3, 0x2, 0x2, 0x2, 0x340, 0x33e, 
    0x3, 0x2, 0x2, 0x2, 0x340, 0x33f, 0x3, 0x2, 0x2, 0x2, 0x341, 0x73, 0x3, 
    0x2, 0x2, 0x2, 0x342, 0x343, 0x7, 0x31, 0x2, 0x2, 0x343, 0x348, 0x5, 
    0x76, 0x3c, 0x2, 0x344, 0x345, 0x7, 0xae, 0x2, 0x2, 0x345, 0x347, 0x5, 
    0x76, 0x3c, 0x2, 0x346, 0x344, 0x3, 0x2, 0x2, 0x2, 0x347, 0x34a, 0x3, 
    0x2, 0x2, 0x2, 0x348, 0x346, 0x3, 0x2, 0x2, 0x2, 0x348, 0x349, 0x3, 
    0x2, 0x2, 0x2, 0x349, 0x34b, 0x3, 0x2, 0x2, 0x2, 0x34a, 0x348, 0x3, 
    0x2, 0x2, 0x2, 0x34b, 0x34c, 0x7, 0xb0, 0x2, 0x2, 0x34c, 0x75, 0x3, 
    0x2, 0x2, 0x2, 0x34d, 0x356, 0x7, 0xb4, 0x2, 0x2, 0x34e, 0x34f, 0x7, 
    0xa5, 0x2, 0x2, 0x34f, 0x356, 0x5, 0xd0, 0x69, 0x2, 0x350, 0x351, 0x7, 
    0xa5, 0x2, 0x2, 0x351, 0x352, 0x7, 0xac, 0x2, 0x2, 0x352, 0x353, 0x5, 
    0x9a, 0x4e, 0x2, 0x353, 0x354, 0x7, 0xad, 0x2, 0x2, 0x354, 0x356, 0x3, 
    0x2, 0x2, 0x2, 0x355, 0x34d, 0x3, 0x2, 0x2, 0x2, 0x355, 0x34e, 0x3, 
    0x2, 0x2, 0x2, 0x355, 0x350, 0x3, 0x2, 0x2, 0x2, 0x356, 0x77, 0x3, 0x2, 
    0x2, 0x2, 0x357, 0x358, 0x7, 0x1e, 0x2, 0x2, 0x358, 0x359, 0x5, 0x96, 
    0x4c, 0x2, 0x359, 0x35a, 0x7, 0xb0, 0x2, 0x2, 0x35a, 0x79, 0x3, 0x2, 
    0x2, 0x2, 0x35b, 0x35c, 0x7, 0x52, 0x2, 0x2, 0x35c, 0x361, 0x5, 0x90, 
    0x49, 0x2, 0x35d, 0x35e, 0x7, 0xae, 0x2, 0x2, 0x35e, 0x360, 0x5, 0x90, 
    0x49, 0x2, 0x35f, 0x35d, 0x3, 0x2, 0x2, 0x2, 0x360, 0x363, 0x3, 0x2, 
    0x2, 0x2, 0x361, 0x35f, 0x3, 0x2, 0x2, 0x2, 0x361, 0x362, 0x3, 0x2, 
    0x2, 0x2, 0x362, 0x364, 0x3, 0x2, 0x2, 0x2, 0x363, 0x361, 0x3, 0x2, 
    0x2, 0x2, 0x364, 0x365, 0x7, 0xb0, 0x2, 0x2, 0x365, 0x7b, 0x3, 0x2, 
    0x2, 0x2, 0x366, 0x367, 0x5, 0x26, 0x14, 0x2, 0x367, 0x368, 0x5, 0x8c, 
    0x47, 0x2, 0x368, 0x36d, 0x5, 0x90, 0x49, 0x2, 0x369, 0x36a, 0x7, 0xae, 
    0x2, 0x2, 0x36a, 0x36c, 0x5, 0x90, 0x49, 0x2, 0x36b, 0x369, 0x3, 0x2, 
    0x2, 0x2, 0x36c, 0x36f, 0x3, 0x2, 0x2, 0x2, 0x36d, 0x36b, 0x3, 0x2, 
    0x2, 0x2, 0x36d, 0x36e, 0x3, 0x2, 0x2, 0x2, 0x36e, 0x370, 0x3, 0x2, 
    0x2, 0x2, 0x36f, 0x36d, 0x3, 0x2, 0x2, 0x2, 0x370, 0x371, 0x7, 0xb0, 
    0x2, 0x2, 0x371, 0x397, 0x3, 0x2, 0x2, 0x2, 0x372, 0x373, 0x5, 0x26, 
    0x14, 0x2, 0x373, 0x374, 0x7, 0x17, 0x2, 0x2, 0x374, 0x379, 0x5, 0x92, 
    0x4a, 0x2, 0x375, 0x376, 0x7, 0xae, 0x2, 0x2, 0x376, 0x378, 0x5, 0x92, 
    0x4a, 0x2, 0x377, 0x375, 0x3, 0x2, 0x2, 0x2, 0x378, 0x37b, 0x3, 0x2, 
    0x2, 0x2, 0x379, 0x377, 0x3, 0x2, 0x2, 0x2, 0x379, 0x37a, 0x3, 0x2, 
    0x2, 0x2, 0x37a, 0x37c, 0x3, 0x2, 0x2, 0x2, 0x37b, 0x379, 0x3, 0x2, 
    0x2, 0x2, 0x37c, 0x37d, 0x7, 0xb0, 0x2, 0x2, 0x37d, 0x397, 0x3, 0x2, 
    0x2, 0x2, 0x37e, 0x380, 0x5, 0x26, 0x14, 0x2, 0x37f, 0x381, 0x5, 0x8e, 
    0x48, 0x2, 0x380, 0x37f, 0x3, 0x2, 0x2, 0x2, 0x380, 0x381, 0x3, 0x2, 
    0x2, 0x2, 0x381, 0x382, 0x3, 0x2, 0x2, 0x2, 0x382, 0x384, 0x7, 0x30, 
    0x2, 0x2, 0x383, 0x385, 0x7, 0x9a, 0x2, 0x2, 0x384, 0x383, 0x3, 0x2, 
    0x2, 0x2, 0x384, 0x385, 0x3, 0x2, 0x2, 0x2, 0x385, 0x386, 0x3, 0x2, 
    0x2, 0x2, 0x386, 0x388, 0x5, 0xea, 0x76, 0x2, 0x387, 0x389, 0x5, 0x1a, 
    0xe, 0x2, 0x388, 0x387, 0x3, 0x2, 0x2, 0x2, 0x388, 0x389, 0x3, 0x2, 
    0x2, 0x2, 0x389, 0x38a, 0x3, 0x2, 0x2, 0x2, 0x38a, 0x38b, 0x7, 0xa8, 
    0x2, 0x2, 0x38b, 0x38c, 0x5, 0x6e, 0x38, 0x2, 0x38c, 0x38e, 0x7, 0xa9, 
    0x2, 0x2, 0x38d, 0x38f, 0x5, 0x88, 0x45, 0x2, 0x38e, 0x38d, 0x3, 0x2, 
    0x2, 0x2, 0x38e, 0x38f, 0x3, 0x2, 0x2, 0x2, 0x38f, 0x390, 0x3, 0x2, 
    0x2, 0x2, 0x390, 0x391, 0x5, 0x8a, 0x46, 0x2, 0x391, 0x397, 0x3, 0x2, 
    0x2, 0x2, 0x392, 0x393, 0x7, 0x5c, 0x2, 0x2, 0x393, 0x394, 0x5, 0xb4, 
    0x5b, 0x2, 0x394, 0x395, 0x5, 0x7e, 0x40, 0x2, 0x395, 0x397, 0x3, 0x2, 
    0x2, 0x2, 0x396, 0x366, 0x3, 0x2, 0x2, 0x2, 0x396, 0x372, 0x3, 0x2, 
    0x2, 0x2, 0x396, 0x37e, 0x3, 0x2, 0x2, 0x2, 0x396, 0x392, 0x3, 0x2, 
    0x2, 0x2, 0x397, 0x7d, 0x3, 0x2, 0x2, 0x2, 0x398, 0x3a2, 0x7, 0xb0, 
    0x2, 0x2, 0x399, 0x39d, 0x7, 0xac, 0x2, 0x2, 0x39a, 0x39c, 0x5, 0x80, 
    0x41, 0x2, 0x39b, 0x39a, 0x3, 0x2, 0x2, 0x2, 0x39c, 0x39f, 0x3, 0x2, 
    0x2, 0x2, 0x39d, 0x39b, 0x3, 0x2, 0x2, 0x2, 0x39d, 0x39e, 0x3, 0x2, 
    0x2, 0x2, 0x39e, 0x3a0, 0x3, 0x2, 0x2, 0x2, 0x39f, 0x39d, 0x3, 0x2, 
    0x2, 0x2, 0x3a0, 0x3a2, 0x7, 0xad, 0x2, 0x2, 0x3a1, 0x398, 0x3, 0x2, 
    0x2, 0x2, 0x3a1, 0x399, 0x3, 0x2, 0x2, 0x2, 0x3a2, 0x7f, 0x3, 0x2, 0x2, 
    0x2, 0x3a3, 0x3a6, 0x5, 0x82, 0x42, 0x2, 0x3a4, 0x3a6, 0x5, 0x84, 0x43, 
    0x2, 0x3a5, 0x3a3, 0x3, 0x2, 0x2, 0x2, 0x3a5, 0x3a4, 0x3, 0x2, 0x2, 
    0x2, 0x3a6, 0x81, 0x3, 0x2, 0x2, 0x2, 0x3a7, 0x3a8, 0x5, 0xb0, 0x59, 
    0x2, 0x3a8, 0x3a9, 0x7, 0x94, 0x2, 0x2, 0x3a9, 0x3aa, 0x5, 0xea, 0x76, 
    0x2, 0x3aa, 0x3ab, 0x7, 0x39, 0x2, 0x2, 0x3ab, 0x3ac, 0x5, 0xb4, 0x5b, 
    0x2, 0x3ac, 0x3ad, 0x7, 0xb0, 0x2, 0x2, 0x3ad, 0x83, 0x3, 0x2, 0x2, 
    0x2, 0x3ae, 0x3af, 0x5, 0x86, 0x44, 0x2, 0x3af, 0x3b5, 0x7, 0xd, 0x2, 
    0x2, 0x3b0, 0x3b6, 0x5, 0xec, 0x77, 0x2, 0x3b1, 0x3b3, 0x5, 0xec, 0x77, 
    0x2, 0x3b2, 0x3b1, 0x3, 0x2, 0x2, 0x2, 0x3b2, 0x3b3, 0x3, 0x2, 0x2, 
    0x2, 0x3b3, 0x3b4, 0x3, 0x2, 0x2, 0x2, 0x3b4, 0x3b6, 0x5, 0xea, 0x76, 
    0x2, 0x3b5, 0x3b0, 0x3, 0x2, 0x2, 0x2, 0x3b5, 0x3b2, 0x3, 0x2, 0x2, 
    0x2, 0x3b6, 0x3b7, 0x3, 0x2, 0x2, 0x2, 0x3b7, 0x3b8, 0x7, 0xb0, 0x2, 
    0x2, 0x3b8, 0x85, 0x3, 0x2, 0x2, 0x2, 0x3b9, 0x3ba, 0x5, 0xb0, 0x59, 
    0x2, 0x3ba, 0x3bb, 0x7, 0x94, 0x2, 0x2, 0x3bb, 0x3bd, 0x3, 0x2, 0x2, 
    0x2, 0x3bc, 0x3b9, 0x3, 0x2, 0x2, 0x2, 0x3bc, 0x3bd, 0x3, 0x2, 0x2, 
    0x2, 0x3bd, 0x3be, 0x3, 0x2, 0x2, 0x2, 0x3be, 0x3bf, 0x5, 0xea, 0x76, 
    0x2, 0x3bf, 0x87, 0x3, 0x2, 0x2, 0x2, 0x3c0, 0x3c1, 0x7, 0xaf, 0x2, 
    0x2, 0x3c1, 0x3c2, 0x5, 0xea, 0x76, 0x2, 0x3c2, 0x3c3, 0x5, 0xb6, 0x5c, 
    0x2, 0x3c3, 0x89, 0x3, 0x2, 0x2, 0x2, 0x3c4, 0x3c7, 0x7, 0xb0, 0x2, 
    0x2, 0x3c5, 0x3c7, 0x5, 0x3a, 0x1e, 0x2, 0x3c6, 0x3c4, 0x3, 0x2, 0x2, 
    0x2, 0x3c6, 0x3c5, 0x3, 0x2, 0x2, 0x2, 0x3c7, 0x8b, 0x3, 0x2, 0x2, 0x2, 
    0x3c8, 0x3cb, 0x5, 0x8e, 0x48, 0x2, 0x3c9, 0x3cb, 0x7, 0x5d, 0x2, 0x2, 
    0x3ca, 0x3c8, 0x3, 0x2, 0x2, 0x2, 0x3ca, 0x3c9, 0x3, 0x2, 0x2, 0x2, 
    0x3cb, 0x8d, 0x3, 0x2, 0x2, 0x2, 0x3cc, 0x3ce, 0x5, 0xec, 0x77, 0x2, 
    0x3cd, 0x3cc, 0x3, 0x2, 0x2, 0x2, 0x3ce, 0x3cf, 0x3, 0x2, 0x2, 0x2, 
    0x3cf, 0x3cd, 0x3, 0x2, 0x2, 0x2, 0x3cf, 0x3d0, 0x3, 0x2, 0x2, 0x2, 
    0x3d0, 0x8f, 0x3, 0x2, 0x2, 0x2, 0x3d1, 0x3d4, 0x7, 0xb4, 0x2, 0x2, 
    0x3d2, 0x3d3, 0x7, 0xb1, 0x2, 0x2, 0x3d3, 0x3d5, 0x5, 0xba, 0x5e, 0x2, 
    0x3d4, 0x3d2, 0x3, 0x2, 0x2, 0x2, 0x3d4, 0x3d5, 0x3, 0x2, 0x2, 0x2, 
    0x3d5, 0x91, 0x3, 0x2, 0x2, 0x2, 0x3d6, 0x3d7, 0x5, 0xea, 0x76, 0x2, 
    0x3d7, 0x3d8, 0x7, 0xb1, 0x2, 0x2, 0x3d8, 0x3d9, 0x5, 0xba, 0x5e, 0x2, 
    0x3d9, 0x93, 0x3, 0x2, 0x2, 0x2, 0x3da, 0x3db, 0x5, 0x26, 0x14, 0x2, 
    0x3db, 0x3dc, 0x7, 0x17, 0x2, 0x2, 0x3dc, 0x3e1, 0x5, 0x92, 0x4a, 0x2, 
    0x3dd, 0x3de, 0x7, 0xae, 0x2, 0x2, 0x3de, 0x3e0, 0x5, 0x92, 0x4a, 0x2, 
    0x3df, 0x3dd, 0x3, 0x2, 0x2, 0x2, 0x3e0, 0x3e3, 0x3, 0x2, 0x2, 0x2, 
    0x3e1, 0x3df, 0x3, 0x2, 0x2, 0x2, 0x3e1, 0x3e2, 0x3, 0x2, 0x2, 0x2, 
    0x3e2, 0x3e4, 0x3, 0x2, 0x2, 0x2, 0x3e3, 0x3e1, 0x3, 0x2, 0x2, 0x2, 
    0x3e4, 0x3e5, 0x7, 0xb0, 0x2, 0x2, 0x3e5, 0x95, 0x3, 0x2, 0x2, 0x2, 
    0x3e6, 0x3eb, 0x5, 0x9a, 0x4e, 0x2, 0x3e7, 0x3e8, 0x7, 0xae, 0x2, 0x2, 
    0x3e8, 0x3ea, 0x5, 0x9a, 0x4e, 0x2, 0x3e9, 0x3e7, 0x3, 0x2, 0x2, 0x2, 
    0x3ea, 0x3ed, 0x3, 0x2, 0x2, 0x2, 0x3eb, 0x3e9, 0x3, 0x2, 0x2, 0x2, 
    0x3eb, 0x3ec, 0x3, 0x2, 0x2, 0x2, 0x3ec, 0x97, 0x3, 0x2, 0x2, 0x2, 0x3ed, 
    0x3eb, 0x3, 0x2, 0x2, 0x2, 0x3ee, 0x3f1, 0x7, 0xa8, 0x2, 0x2, 0x3ef, 
    0x3f2, 0x5, 0x9a, 0x4e, 0x2, 0x3f0, 0x3f2, 0x5, 0xa0, 0x51, 0x2, 0x3f1, 
    0x3ef, 0x3, 0x2, 0x2, 0x2, 0x3f1, 0x3f0, 0x3, 0x2, 0x2, 0x2, 0x3f2, 
    0x3f3, 0x3, 0x2, 0x2, 0x2, 0x3f3, 0x3f4, 0x7, 0xa9, 0x2, 0x2, 0x3f4, 
    0x99, 0x3, 0x2, 0x2, 0x2, 0x3f5, 0x3f6, 0x8, 0x4e, 0x1, 0x2, 0x3f6, 
    0x3f7, 0x7, 0x16, 0x2, 0x2, 0x3f7, 0x463, 0x5, 0x9a, 0x4e, 0x2d, 0x3f8, 
    0x463, 0x5, 0x9c, 0x4f, 0x2, 0x3f9, 0x3fa, 0x5, 0xc8, 0x65, 0x2, 0x3fa, 
    0x3fb, 0x7, 0xaa, 0x2, 0x2, 0x3fb, 0x3fc, 0x5, 0x9a, 0x4e, 0x2, 0x3fc, 
    0x3fd, 0x7, 0xab, 0x2, 0x2, 0x3fd, 0x463, 0x3, 0x2, 0x2, 0x2, 0x3fe, 
    0x3ff, 0x7, 0xa8, 0x2, 0x2, 0x3ff, 0x400, 0x5, 0xf4, 0x7b, 0x2, 0x400, 
    0x401, 0x7, 0xa9, 0x2, 0x2, 0x401, 0x402, 0x5, 0x9a, 0x4e, 0x2a, 0x402, 
    0x463, 0x3, 0x2, 0x2, 0x2, 0x403, 0x404, 0x9, 0x5, 0x2, 0x2, 0x404, 
    0x463, 0x5, 0x9a, 0x4e, 0x29, 0x405, 0x406, 0x9, 0x6, 0x2, 0x2, 0x406, 
    0x463, 0x5, 0x9a, 0x4e, 0x28, 0x407, 0x408, 0x9, 0x7, 0x2, 0x2, 0x408, 
    0x463, 0x5, 0xd0, 0x69, 0x2, 0x409, 0x40a, 0x5, 0xd0, 0x69, 0x2, 0x40a, 
    0x40b, 0x9, 0x7, 0x2, 0x2, 0x40b, 0x463, 0x3, 0x2, 0x2, 0x2, 0x40c, 
    0x40d, 0x7, 0x4a, 0x2, 0x2, 0x40d, 0x463, 0x5, 0x9a, 0x4e, 0x25, 0x40e, 
    0x463, 0x5, 0xd0, 0x69, 0x2, 0x40f, 0x463, 0x5, 0xc0, 0x61, 0x2, 0x410, 
    0x463, 0x5, 0xca, 0x66, 0x2, 0x411, 0x463, 0x7, 0xb5, 0x2, 0x2, 0x412, 
    0x463, 0x7, 0xbb, 0x2, 0x2, 0x413, 0x463, 0x5, 0x98, 0x4d, 0x2, 0x414, 
    0x415, 0x7, 0xc, 0x2, 0x2, 0x415, 0x417, 0x7, 0xa8, 0x2, 0x2, 0x416, 
    0x418, 0x5, 0xa2, 0x52, 0x2, 0x417, 0x416, 0x3, 0x2, 0x2, 0x2, 0x417, 
    0x418, 0x3, 0x2, 0x2, 0x2, 0x418, 0x419, 0x3, 0x2, 0x2, 0x2, 0x419, 
    0x420, 0x7, 0xa9, 0x2, 0x2, 0x41a, 0x41c, 0x7, 0xaa, 0x2, 0x2, 0x41b, 
    0x41d, 0x5, 0xa2, 0x52, 0x2, 0x41c, 0x41b, 0x3, 0x2, 0x2, 0x2, 0x41c, 
    0x41d, 0x3, 0x2, 0x2, 0x2, 0x41d, 0x41e, 0x3, 0x2, 0x2, 0x2, 0x41e, 
    0x420, 0x7, 0xab, 0x2, 0x2, 0x41f, 0x414, 0x3, 0x2, 0x2, 0x2, 0x41f, 
    0x41a, 0x3, 0x2, 0x2, 0x2, 0x420, 0x425, 0x3, 0x2, 0x2, 0x2, 0x421, 
    0x422, 0x7, 0xaa, 0x2, 0x2, 0x422, 0x423, 0x5, 0x9a, 0x4e, 0x2, 0x423, 
    0x424, 0x7, 0xab, 0x2, 0x2, 0x424, 0x426, 0x3, 0x2, 0x2, 0x2, 0x425, 
    0x421, 0x3, 0x2, 0x2, 0x2, 0x425, 0x426, 0x3, 0x2, 0x2, 0x2, 0x426, 
    0x463, 0x3, 0x2, 0x2, 0x2, 0x427, 0x463, 0x7, 0x5f, 0x2, 0x2, 0x428, 
    0x429, 0x7, 0x40, 0x2, 0x2, 0x429, 0x42a, 0x7, 0xa8, 0x2, 0x2, 0x42a, 
    0x42b, 0x5, 0xe4, 0x73, 0x2, 0x42b, 0x42c, 0x7, 0xa9, 0x2, 0x2, 0x42c, 
    0x42d, 0x7, 0xb1, 0x2, 0x2, 0x42d, 0x42e, 0x5, 0x9a, 0x4e, 0x1c, 0x42e, 
    0x463, 0x3, 0x2, 0x2, 0x2, 0x42f, 0x430, 0x7, 0x3f, 0x2, 0x2, 0x430, 
    0x431, 0x7, 0xa8, 0x2, 0x2, 0x431, 0x432, 0x5, 0xce, 0x68, 0x2, 0x432, 
    0x433, 0x7, 0xa9, 0x2, 0x2, 0x433, 0x463, 0x3, 0x2, 0x2, 0x2, 0x434, 
    0x435, 0x7, 0x21, 0x2, 0x2, 0x435, 0x436, 0x7, 0xa8, 0x2, 0x2, 0x436, 
    0x437, 0x5, 0xd0, 0x69, 0x2, 0x437, 0x438, 0x7, 0xa9, 0x2, 0x2, 0x438, 
    0x463, 0x3, 0x2, 0x2, 0x2, 0x439, 0x43a, 0x7, 0x28, 0x2, 0x2, 0x43a, 
    0x43b, 0x7, 0xa8, 0x2, 0x2, 0x43b, 0x43c, 0x5, 0x9a, 0x4e, 0x2, 0x43c, 
    0x43d, 0x7, 0xa9, 0x2, 0x2, 0x43d, 0x463, 0x3, 0x2, 0x2, 0x2, 0x43e, 
    0x442, 0x7, 0x29, 0x2, 0x2, 0x43f, 0x440, 0x7, 0xa8, 0x2, 0x2, 0x440, 
    0x443, 0x7, 0xa9, 0x2, 0x2, 0x441, 0x443, 0x5, 0x98, 0x4d, 0x2, 0x442, 
    0x43f, 0x3, 0x2, 0x2, 0x2, 0x442, 0x441, 0x3, 0x2, 0x2, 0x2, 0x442, 
    0x443, 0x3, 0x2, 0x2, 0x2, 0x443, 0x463, 0x3, 0x2, 0x2, 0x2, 0x444, 
    0x445, 0x9, 0x8, 0x2, 0x2, 0x445, 0x463, 0x5, 0x9a, 0x4e, 0x17, 0x446, 
    0x447, 0x9, 0x9, 0x2, 0x2, 0x447, 0x463, 0x5, 0x9a, 0x4e, 0x16, 0x448, 
    0x44a, 0x7, 0x52, 0x2, 0x2, 0x449, 0x448, 0x3, 0x2, 0x2, 0x2, 0x449, 
    0x44a, 0x3, 0x2, 0x2, 0x2, 0x44a, 0x44b, 0x3, 0x2, 0x2, 0x2, 0x44b, 
    0x44d, 0x7, 0x30, 0x2, 0x2, 0x44c, 0x44e, 0x7, 0x9a, 0x2, 0x2, 0x44d, 
    0x44c, 0x3, 0x2, 0x2, 0x2, 0x44d, 0x44e, 0x3, 0x2, 0x2, 0x2, 0x44e, 
    0x44f, 0x3, 0x2, 0x2, 0x2, 0x44f, 0x450, 0x7, 0xa8, 0x2, 0x2, 0x450, 
    0x451, 0x5, 0x6e, 0x38, 0x2, 0x451, 0x453, 0x7, 0xa9, 0x2, 0x2, 0x452, 
    0x454, 0x5, 0xa6, 0x54, 0x2, 0x453, 0x452, 0x3, 0x2, 0x2, 0x2, 0x453, 
    0x454, 0x3, 0x2, 0x2, 0x2, 0x454, 0x455, 0x3, 0x2, 0x2, 0x2, 0x455, 
    0x456, 0x5, 0x3a, 0x1e, 0x2, 0x456, 0x463, 0x3, 0x2, 0x2, 0x2, 0x457, 
    0x458, 0x5, 0xd0, 0x69, 0x2, 0x458, 0x459, 0x5, 0x9e, 0x50, 0x2, 0x459, 
    0x45a, 0x5, 0x9a, 0x4e, 0x7, 0x45a, 0x463, 0x3, 0x2, 0x2, 0x2, 0x45b, 
    0x45c, 0x5, 0xd0, 0x69, 0x2, 0x45c, 0x45d, 0x7, 0xb1, 0x2, 0x2, 0x45d, 
    0x460, 0x7, 0x9a, 0x2, 0x2, 0x45e, 0x461, 0x5, 0xd0, 0x69, 0x2, 0x45f, 
    0x461, 0x5, 0x9c, 0x4f, 0x2, 0x460, 0x45e, 0x3, 0x2, 0x2, 0x2, 0x460, 
    0x45f, 0x3, 0x2, 0x2, 0x2, 0x461, 0x463, 0x3, 0x2, 0x2, 0x2, 0x462, 
    0x3f5, 0x3, 0x2, 0x2, 0x2, 0x462, 0x3f8, 0x3, 0x2, 0x2, 0x2, 0x462, 
    0x3f9, 0x3, 0x2, 0x2, 0x2, 0x462, 0x3fe, 0x3, 0x2, 0x2, 0x2, 0x462, 
    0x403, 0x3, 0x2, 0x2, 0x2, 0x462, 0x405, 0x3, 0x2, 0x2, 0x2, 0x462, 
    0x407, 0x3, 0x2, 0x2, 0x2, 0x462, 0x409, 0x3, 0x2, 0x2, 0x2, 0x462, 
    0x40c, 0x3, 0x2, 0x2, 0x2, 0x462, 0x40e, 0x3, 0x2, 0x2, 0x2, 0x462, 
    0x40f, 0x3, 0x2, 0x2, 0x2, 0x462, 0x410, 0x3, 0x2, 0x2, 0x2, 0x462, 
    0x411, 0x3, 0x2, 0x2, 0x2, 0x462, 0x412, 0x3, 0x2, 0x2, 0x2, 0x462, 
    0x413, 0x3, 0x2, 0x2, 0x2, 0x462, 0x41f, 0x3, 0x2, 0x2, 0x2, 0x462, 
    0x427, 0x3, 0x2, 0x2, 0x2, 0x462, 0x428, 0x3, 0x2, 0x2, 0x2, 0x462, 
    0x42f, 0x3, 0x2, 0x2, 0x2, 0x462, 0x434, 0x3, 0x2, 0x2, 0x2, 0x462, 
    0x439, 0x3, 0x2, 0x2, 0x2, 0x462, 0x43e, 0x3, 0x2, 0x2, 0x2, 0x462, 
    0x444, 0x3, 0x2, 0x2, 0x2, 0x462, 0x446, 0x3, 0x2, 0x2, 0x2, 0x462, 
    0x449, 0x3, 0x2, 0x2, 0x2, 0x462, 0x457, 0x3, 0x2, 0x2, 0x2, 0x462, 
    0x45b, 0x3, 0x2, 0x2, 0x2, 0x463, 0x49a, 0x3, 0x2, 0x2, 0x2, 0x464, 
    0x465, 0xc, 0x14, 0x2, 0x2, 0x465, 0x466, 0x7, 0x86, 0x2, 0x2, 0x466, 
    0x499, 0x5, 0x9a, 0x4e, 0x14, 0x467, 0x468, 0xc, 0x12, 0x2, 0x2, 0x468, 
    0x469, 0x9, 0xa, 0x2, 0x2, 0x469, 0x499, 0x5, 0x9a, 0x4e, 0x13, 0x46a, 
    0x46b, 0xc, 0x11, 0x2, 0x2, 0x46b, 0x46c, 0x9, 0xb, 0x2, 0x2, 0x46c, 
    0x499, 0x5, 0x9a, 0x4e, 0x12, 0x46d, 0x46e, 0xc, 0x10, 0x2, 0x2, 0x46e, 
    0x46f, 0x9, 0xc, 0x2, 0x2, 0x46f, 0x499, 0x5, 0x9a, 0x4e, 0x11, 0x470, 
    0x471, 0xc, 0xf, 0x2, 0x2, 0x471, 0x472, 0x9, 0xd, 0x2, 0x2, 0x472, 
    0x499, 0x5, 0x9a, 0x4e, 0x10, 0x473, 0x474, 0xc, 0xe, 0x2, 0x2, 0x474, 
    0x475, 0x9, 0xe, 0x2, 0x2, 0x475, 0x499, 0x5, 0x9a, 0x4e, 0xf, 0x476, 
    0x477, 0xc, 0xd, 0x2, 0x2, 0x477, 0x478, 0x7, 0x9a, 0x2, 0x2, 0x478, 
    0x499, 0x5, 0x9a, 0x4e, 0xe, 0x479, 0x47a, 0xc, 0xc, 0x2, 0x2, 0x47a, 
    0x47b, 0x7, 0x9d, 0x2, 0x2, 0x47b, 0x499, 0x5, 0x9a, 0x4e, 0xd, 0x47c, 
    0x47d, 0xc, 0xb, 0x2, 0x2, 0x47d, 0x47e, 0x7, 0x9b, 0x2, 0x2, 0x47e, 
    0x499, 0x5, 0x9a, 0x4e, 0xc, 0x47f, 0x480, 0xc, 0xa, 0x2, 0x2, 0x480, 
    0x481, 0x7, 0x91, 0x2, 0x2, 0x481, 0x499, 0x5, 0x9a, 0x4e, 0xb, 0x482, 
    0x483, 0xc, 0x9, 0x2, 0x2, 0x483, 0x484, 0x7, 0x90, 0x2, 0x2, 0x484, 
    0x499, 0x5, 0x9a, 0x4e, 0xa, 0x485, 0x486, 0xc, 0x8, 0x2, 0x2, 0x486, 
    0x488, 0x7, 0xa7, 0x2, 0x2, 0x487, 0x489, 0x5, 0x9a, 0x4e, 0x2, 0x488, 
    0x487, 0x3, 0x2, 0x2, 0x2, 0x488, 0x489, 0x3, 0x2, 0x2, 0x2, 0x489, 
    0x48a, 0x3, 0x2, 0x2, 0x2, 0x48a, 0x48b, 0x7, 0xaf, 0x2, 0x2, 0x48b, 
    0x499, 0x5, 0x9a, 0x4e, 0x9, 0x48c, 0x48d, 0xc, 0x5, 0x2, 0x2, 0x48d, 
    0x48e, 0x7, 0x41, 0x2, 0x2, 0x48e, 0x499, 0x5, 0x9a, 0x4e, 0x6, 0x48f, 
    0x490, 0xc, 0x4, 0x2, 0x2, 0x490, 0x491, 0x7, 0x43, 0x2, 0x2, 0x491, 
    0x499, 0x5, 0x9a, 0x4e, 0x5, 0x492, 0x493, 0xc, 0x3, 0x2, 0x2, 0x493, 
    0x494, 0x7, 0x42, 0x2, 0x2, 0x494, 0x499, 0x5, 0x9a, 0x4e, 0x4, 0x495, 
    0x496, 0xc, 0x13, 0x2, 0x2, 0x496, 0x497, 0x7, 0x38, 0x2, 0x2, 0x497, 
    0x499, 0x5, 0xac, 0x57, 0x2, 0x498, 0x464, 0x3, 0x2, 0x2, 0x2, 0x498, 
    0x467, 0x3, 0x2, 0x2, 0x2, 0x498, 0x46a, 0x3, 0x2, 0x2, 0x2, 0x498, 
    0x46d, 0x3, 0x2, 0x2, 0x2, 0x498, 0x470, 0x3, 0x2, 0x2, 0x2, 0x498, 
    0x473, 0x3, 0x2, 0x2, 0x2, 0x498, 0x476, 0x3, 0x2, 0x2, 0x2, 0x498, 
    0x479, 0x3, 0x2, 0x2, 0x2, 0x498, 0x47c, 0x3, 0x2, 0x2, 0x2, 0x498, 
    0x47f, 0x3, 0x2, 0x2, 0x2, 0x498, 0x482, 0x3, 0x2, 0x2, 0x2, 0x498, 
    0x485, 0x3, 0x2, 0x2, 0x2, 0x498, 0x48c, 0x3, 0x2, 0x2, 0x2, 0x498, 
    0x48f, 0x3, 0x2, 0x2, 0x2, 0x498, 0x492, 0x3, 0x2, 0x2, 0x2, 0x498, 
    0x495, 0x3, 0x2, 0x2, 0x2, 0x499, 0x49c, 0x3, 0x2, 0x2, 0x2, 0x49a, 
    0x498, 0x3, 0x2, 0x2, 0x2, 0x49a, 0x49b, 0x3, 0x2, 0x2, 0x2, 0x49b, 
    0x9b, 0x3, 0x2, 0x2, 0x2, 0x49c, 0x49a, 0x3, 0x2, 0x2, 0x2, 0x49d, 0x49e, 
    0x7, 0x45, 0x2, 0x2, 0x49e, 0x4a0, 0x5, 0xac, 0x57, 0x2, 0x49f, 0x4a1, 
    0x5, 0xb6, 0x5c, 0x2, 0x4a0, 0x49f, 0x3, 0x2, 0x2, 0x2, 0x4a0, 0x4a1, 
    0x3, 0x2, 0x2, 0x2, 0x4a1, 0x9d, 0x3, 0x2, 0x2, 0x2, 0x4a2, 0x4a3, 0x9, 
    0xf, 0x2, 0x2, 0x4a3, 0x9f, 0x3, 0x2, 0x2, 0x2, 0x4a4, 0x4a5, 0x7, 0x5f, 
    0x2, 0x2, 0x4a5, 0x4a8, 0x5, 0x9a, 0x4e, 0x2, 0x4a6, 0x4a7, 0x7, 0x7a, 
    0x2, 0x2, 0x4a7, 0x4a9, 0x5, 0x9a, 0x4e, 0x2, 0x4a8, 0x4a6, 0x3, 0x2, 
    0x2, 0x2, 0x4a8, 0x4a9, 0x3, 0x2, 0x2, 0x2, 0x4a9, 0xa1, 0x3, 0x2, 0x2, 
    0x2, 0x4aa, 0x4af, 0x5, 0xa4, 0x53, 0x2, 0x4ab, 0x4ac, 0x7, 0xae, 0x2, 
    0x2, 0x4ac, 0x4ae, 0x5, 0xa4, 0x53, 0x2, 0x4ad, 0x4ab, 0x3, 0x2, 0x2, 
    0x2, 0x4ae, 0x4b1, 0x3, 0x2, 0x2, 0x2, 0x4af, 0x4ad, 0x3, 0x2, 0x2, 
    0x2, 0x4af, 0x4b0, 0x3, 0x2, 0x2, 0x2, 0x4b0, 0x4b3, 0x3, 0x2, 0x2, 
    0x2, 0x4b1, 0x4af, 0x3, 0x2, 0x2, 0x2, 0x4b2, 0x4b4, 0x7, 0xae, 0x2, 
    0x2, 0x4b3, 0x4b2, 0x3, 0x2, 0x2, 0x2, 0x4b3, 0x4b4, 0x3, 0x2, 0x2, 
    0x2, 0x4b4, 0xa3, 0x3, 0x2, 0x2, 0x2, 0x4b5, 0x4b8, 0x5, 0x9a, 0x4e, 
    0x2, 0x4b6, 0x4b7, 0x7, 0x7a, 0x2, 0x2, 0x4b7, 0x4b9, 0x5, 0x9a, 0x4e, 
    0x2, 0x4b8, 0x4b6, 0x3, 0x2, 0x2, 0x2, 0x4b8, 0x4b9, 0x3, 0x2, 0x2, 
    0x2, 0x4b9, 0x4c2, 0x3, 0x2, 0x2, 0x2, 0x4ba, 0x4bb, 0x5, 0x9a, 0x4e, 
    0x2, 0x4bb, 0x4bc, 0x7, 0x7a, 0x2, 0x2, 0x4bc, 0x4be, 0x3, 0x2, 0x2, 
    0x2, 0x4bd, 0x4ba, 0x3, 0x2, 0x2, 0x2, 0x4bd, 0x4be, 0x3, 0x2, 0x2, 
    0x2, 0x4be, 0x4bf, 0x3, 0x2, 0x2, 0x2, 0x4bf, 0x4c0, 0x7, 0x9a, 0x2, 
    0x2, 0x4c0, 0x4c2, 0x5, 0xd0, 0x69, 0x2, 0x4c1, 0x4b5, 0x3, 0x2, 0x2, 
    0x2, 0x4c1, 0x4bd, 0x3, 0x2, 0x2, 0x2, 0x4c2, 0xa5, 0x3, 0x2, 0x2, 0x2, 
    0x4c3, 0x4c4, 0x7, 0x5c, 0x2, 0x2, 0x4c4, 0x4c5, 0x7, 0xa8, 0x2, 0x2, 
    0x4c5, 0x4ca, 0x5, 0xa8, 0x55, 0x2, 0x4c6, 0x4c7, 0x7, 0xae, 0x2, 0x2, 
    0x4c7, 0x4c9, 0x5, 0xa8, 0x55, 0x2, 0x4c8, 0x4c6, 0x3, 0x2, 0x2, 0x2, 
    0x4c9, 0x4cc, 0x3, 0x2, 0x2, 0x2, 0x4ca, 0x4c8, 0x3, 0x2, 0x2, 0x2, 
    0x4ca, 0x4cb, 0x3, 0x2, 0x2, 0x2, 0x4cb, 0x4cd, 0x3, 0x2, 0x2, 0x2, 
    0x4cc, 0x4ca, 0x3, 0x2, 0x2, 0x2, 0x4cd, 0x4ce, 0x7, 0xa9, 0x2, 0x2, 
    0x4ce, 0xa7, 0x3, 0x2, 0x2, 0x2, 0x4cf, 0x4d1, 0x7, 0x9a, 0x2, 0x2, 
    0x4d0, 0x4cf, 0x3, 0x2, 0x2, 0x2, 0x4d0, 0x4d1, 0x3, 0x2, 0x2, 0x2, 
    0x4d1, 0x4d2, 0x3, 0x2, 0x2, 0x2, 0x4d2, 0x4d3, 0x7, 0xb4, 0x2, 0x2, 
    0x4d3, 0xa9, 0x3, 0x2, 0x2, 0x2, 0x4d4, 0x4d6, 0x5, 0xb0, 0x59, 0x2, 
    0x4d5, 0x4d7, 0x5, 0x24, 0x13, 0x2, 0x4d6, 0x4d5, 0x3, 0x2, 0x2, 0x2, 
    0x4d6, 0x4d7, 0x3, 0x2, 0x2, 0x2, 0x4d7, 0x4da, 0x3, 0x2, 0x2, 0x2, 
    0x4d8, 0x4da, 0x7, 0x52, 0x2, 0x2, 0x4d9, 0x4d4, 0x3, 0x2, 0x2, 0x2, 
    0x4d9, 0x4d8, 0x3, 0x2, 0x2, 0x2, 0x4da, 0xab, 0x3, 0x2, 0x2, 0x2, 0x4db, 
    0x4de, 0x5, 0xb0, 0x59, 0x2, 0x4dc, 0x4de, 0x5, 0xae, 0x58, 0x2, 0x4dd, 
    0x4db, 0x3, 0x2, 0x2, 0x2, 0x4dd, 0x4dc, 0x3, 0x2, 0x2, 0x2, 0x4de, 
    0x4e0, 0x3, 0x2, 0x2, 0x2, 0x4df, 0x4e1, 0x5, 0x24, 0x13, 0x2, 0x4e0, 
    0x4df, 0x3, 0x2, 0x2, 0x2, 0x4e0, 0x4e1, 0x3, 0x2, 0x2, 0x2, 0x4e1, 
    0x4e5, 0x3, 0x2, 0x2, 0x2, 0x4e2, 0x4e5, 0x5, 0xf2, 0x7a, 0x2, 0x4e3, 
    0x4e5, 0x7, 0x52, 0x2, 0x2, 0x4e4, 0x4dd, 0x3, 0x2, 0x2, 0x2, 0x4e4, 
    0x4e2, 0x3, 0x2, 0x2, 0x2, 0x4e4, 0x4e3, 0x3, 0x2, 0x2, 0x2, 0x4e5, 
    0xad, 0x3, 0x2, 0x2, 0x2, 0x4e6, 0x4eb, 0x5, 0xda, 0x6e, 0x2, 0x4e7, 
    0x4e8, 0x7, 0x95, 0x2, 0x2, 0x4e8, 0x4ea, 0x5, 0xdc, 0x6f, 0x2, 0x4e9, 
    0x4e7, 0x3, 0x2, 0x2, 0x2, 0x4ea, 0x4ed, 0x3, 0x2, 0x2, 0x2, 0x4eb, 
    0x4e9, 0x3, 0x2, 0x2, 0x2, 0x4eb, 0x4ec, 0x3, 0x2, 0x2, 0x2, 0x4ec, 
    0xaf, 0x3, 0x2, 0x2, 0x2, 0x4ed, 0x4eb, 0x3, 0x2, 0x2, 0x2, 0x4ee, 0x4f0, 
    0x7, 0x44, 0x2, 0x2, 0x4ef, 0x4ee, 0x3, 0x2, 0x2, 0x2, 0x4ef, 0x4f0, 
    0x3, 0x2, 0x2, 0x2, 0x4f0, 0x4f2, 0x3, 0x2, 0x2, 0x2, 0x4f1, 0x4f3, 
    0x7, 0x96, 0x2, 0x2, 0x4f2, 0x4f1, 0x3, 0x2, 0x2, 0x2, 0x4f2, 0x4f3, 
    0x3, 0x2, 0x2, 0x2, 0x4f3, 0x4f4, 0x3, 0x2, 0x2, 0x2, 0x4f4, 0x4f5, 
    0x5, 0xb2, 0x5a, 0x2, 0x4f5, 0xb1, 0x3, 0x2, 0x2, 0x2, 0x4f6, 0x4fb, 
    0x5, 0xea, 0x76, 0x2, 0x4f7, 0x4f8, 0x7, 0x96, 0x2, 0x2, 0x4f8, 0x4fa, 
    0x5, 0xea, 0x76, 0x2, 0x4f9, 0x4f7, 0x3, 0x2, 0x2, 0x2, 0x4fa, 0x4fd, 
    0x3, 0x2, 0x2, 0x2, 0x4fb, 0x4f9, 0x3, 0x2, 0x2, 0x2, 0x4fb, 0x4fc, 
    0x3, 0x2, 0x2, 0x2, 0x4fc, 0xb3, 0x3, 0x2, 0x2, 0x2, 0x4fd, 0x4fb, 0x3, 
    0x2, 0x2, 0x2, 0x4fe, 0x503, 0x5, 0xb0, 0x59, 0x2, 0x4ff, 0x500, 0x7, 
    0xae, 0x2, 0x2, 0x500, 0x502, 0x5, 0xb0, 0x59, 0x2, 0x501, 0x4ff, 0x3, 
    0x2, 0x2, 0x2, 0x502, 0x505, 0x3, 0x2, 0x2, 0x2, 0x503, 0x501, 0x3, 
    0x2, 0x2, 0x2, 0x503, 0x504, 0x3, 0x2, 0x2, 0x2, 0x504, 0xb5, 0x3, 0x2, 
    0x2, 0x2, 0x505, 0x503, 0x3, 0x2, 0x2, 0x2, 0x506, 0x510, 0x7, 0xa8, 
    0x2, 0x2, 0x507, 0x50c, 0x5, 0xb8, 0x5d, 0x2, 0x508, 0x509, 0x7, 0xae, 
    0x2, 0x2, 0x509, 0x50b, 0x5, 0xb8, 0x5d, 0x2, 0x50a, 0x508, 0x3, 0x2, 
    0x2, 0x2, 0x50b, 0x50e, 0x3, 0x2, 0x2, 0x2, 0x50c, 0x50a, 0x3, 0x2, 
    0x2, 0x2, 0x50c, 0x50d, 0x3, 0x2, 0x2, 0x2, 0x50d, 0x511, 0x3, 0x2, 
    0x2, 0x2, 0x50e, 0x50c, 0x3, 0x2, 0x2, 0x2, 0x50f, 0x511, 0x5, 0xa0, 
    0x51, 0x2, 0x510, 0x507, 0x3, 0x2, 0x2, 0x2, 0x510, 0x50f, 0x3, 0x2, 
    0x2, 0x2, 0x510, 0x511, 0x3, 0x2, 0x2, 0x2, 0x511, 0x512, 0x3, 0x2, 
    0x2, 0x2, 0x512, 0x513, 0x7, 0xa9, 0x2, 0x2, 0x513, 0xb7, 0x3, 0x2, 
    0x2, 0x2, 0x514, 0x516, 0x7, 0x97, 0x2, 0x2, 0x515, 0x514, 0x3, 0x2, 
    0x2, 0x2, 0x515, 0x516, 0x3, 0x2, 0x2, 0x2, 0x516, 0x517, 0x3, 0x2, 
    0x2, 0x2, 0x517, 0x51b, 0x5, 0x9a, 0x4e, 0x2, 0x518, 0x519, 0x7, 0x9a, 
    0x2, 0x2, 0x519, 0x51b, 0x5, 0xd0, 0x69, 0x2, 0x51a, 0x515, 0x3, 0x2, 
    0x2, 0x2, 0x51a, 0x518, 0x3, 0x2, 0x2, 0x2, 0x51b, 0xb9, 0x3, 0x2, 0x2, 
    0x2, 0x51c, 0x532, 0x5, 0xc0, 0x61, 0x2, 0x51d, 0x532, 0x5, 0xca, 0x66, 
    0x2, 0x51e, 0x51f, 0x7, 0xc, 0x2, 0x2, 0x51f, 0x524, 0x7, 0xa8, 0x2, 
    0x2, 0x520, 0x522, 0x5, 0xbc, 0x5f, 0x2, 0x521, 0x523, 0x7, 0xae, 0x2, 
    0x2, 0x522, 0x521, 0x3, 0x2, 0x2, 0x2, 0x522, 0x523, 0x3, 0x2, 0x2, 
    0x2, 0x523, 0x525, 0x3, 0x2, 0x2, 0x2, 0x524, 0x520, 0x3, 0x2, 0x2, 
    0x2, 0x524, 0x525, 0x3, 0x2, 0x2, 0x2, 0x525, 0x526, 0x3, 0x2, 0x2, 
    0x2, 0x526, 0x532, 0x7, 0xa9, 0x2, 0x2, 0x527, 0x52c, 0x7, 0xaa, 0x2, 
    0x2, 0x528, 0x52a, 0x5, 0xbc, 0x5f, 0x2, 0x529, 0x52b, 0x7, 0xae, 0x2, 
    0x2, 0x52a, 0x529, 0x3, 0x2, 0x2, 0x2, 0x52a, 0x52b, 0x3, 0x2, 0x2, 
    0x2, 0x52b, 0x52d, 0x3, 0x2, 0x2, 0x2, 0x52c, 0x528, 0x3, 0x2, 0x2, 
    0x2, 0x52c, 0x52d, 0x3, 0x2, 0x2, 0x2, 0x52d, 0x52e, 0x3, 0x2, 0x2, 
    0x2, 0x52e, 0x532, 0x7, 0xab, 0x2, 0x2, 0x52f, 0x530, 0x9, 0x10, 0x2, 
    0x2, 0x530, 0x532, 0x5, 0xba, 0x5e, 0x2, 0x531, 0x51c, 0x3, 0x2, 0x2, 
    0x2, 0x531, 0x51d, 0x3, 0x2, 0x2, 0x2, 0x531, 0x51e, 0x3, 0x2, 0x2, 
    0x2, 0x531, 0x527, 0x3, 0x2, 0x2, 0x2, 0x531, 0x52f, 0x3, 0x2, 0x2, 
    0x2, 0x532, 0xbb, 0x3, 0x2, 0x2, 0x2, 0x533, 0x538, 0x5, 0xbe, 0x60, 
    0x2, 0x534, 0x535, 0x7, 0xae, 0x2, 0x2, 0x535, 0x537, 0x5, 0xbe, 0x60, 
    0x2, 0x536, 0x534, 0x3, 0x2, 0x2, 0x2, 0x537, 0x53a, 0x3, 0x2, 0x2, 
    0x2, 0x538, 0x536, 0x3, 0x2, 0x2, 0x2, 0x538, 0x539, 0x3, 0x2, 0x2, 
    0x2, 0x539, 0xbd, 0x3, 0x2, 0x2, 0x2, 0x53a, 0x538, 0x3, 0x2, 0x2, 0x2, 
    0x53b, 0x53e, 0x5, 0xba, 0x5e, 0x2, 0x53c, 0x53d, 0x7, 0x7a, 0x2, 0x2, 
    0x53d, 0x53f, 0x5, 0xba, 0x5e, 0x2, 0x53e, 0x53c, 0x3, 0x2, 0x2, 0x2, 
    0x53e, 0x53f, 0x3, 0x2, 0x2, 0x2, 0x53f, 0xbf, 0x3, 0x2, 0x2, 0x2, 0x540, 
    0x546, 0x7, 0x46, 0x2, 0x2, 0x541, 0x546, 0x5, 0xc2, 0x62, 0x2, 0x542, 
    0x546, 0x5, 0xee, 0x78, 0x2, 0x543, 0x546, 0x5, 0xc6, 0x64, 0x2, 0x544, 
    0x546, 0x5, 0xb0, 0x59, 0x2, 0x545, 0x540, 0x3, 0x2, 0x2, 0x2, 0x545, 
    0x541, 0x3, 0x2, 0x2, 0x2, 0x545, 0x542, 0x3, 0x2, 0x2, 0x2, 0x545, 
    0x543, 0x3, 0x2, 0x2, 0x2, 0x545, 0x544, 0x3, 0x2, 0x2, 0x2, 0x546, 
    0xc1, 0x3, 0x2, 0x2, 0x2, 0x547, 0x54c, 0x7, 0xb8, 0x2, 0x2, 0x548, 
    0x54c, 0x7, 0x10, 0x2, 0x2, 0x549, 0x54c, 0x5, 0xc4, 0x63, 0x2, 0x54a, 
    0x54c, 0x5, 0xc8, 0x65, 0x2, 0x54b, 0x547, 0x3, 0x2, 0x2, 0x2, 0x54b, 
    0x548, 0x3, 0x2, 0x2, 0x2, 0x54b, 0x549, 0x3, 0x2, 0x2, 0x2, 0x54b, 
    0x54a, 0x3, 0x2, 0x2, 0x2, 0x54c, 0xc3, 0x3, 0x2, 0x2, 0x2, 0x54d, 0x54e, 
    0x9, 0x11, 0x2, 0x2, 0x54e, 0xc5, 0x3, 0x2, 0x2, 0x2, 0x54f, 0x550, 
    0x9, 0x12, 0x2, 0x2, 0x550, 0x555, 0x7, 0x94, 0x2, 0x2, 0x551, 0x556, 
    0x5, 0xea, 0x76, 0x2, 0x552, 0x556, 0x7, 0x64, 0x2, 0x2, 0x553, 0x556, 
    0x7, 0x60, 0x2, 0x2, 0x554, 0x556, 0x7, 0x61, 0x2, 0x2, 0x555, 0x551, 
    0x3, 0x2, 0x2, 0x2, 0x555, 0x552, 0x3, 0x2, 0x2, 0x2, 0x555, 0x553, 
    0x3, 0x2, 0x2, 0x2, 0x555, 0x554, 0x3, 0x2, 0x2, 0x2, 0x556, 0x55f, 
    0x3, 0x2, 0x2, 0x2, 0x557, 0x55a, 0x5, 0xaa, 0x56, 0x2, 0x558, 0x55a, 
    0x5, 0xe0, 0x71, 0x2, 0x559, 0x557, 0x3, 0x2, 0x2, 0x2, 0x559, 0x558, 
    0x3, 0x2, 0x2, 0x2, 0x55a, 0x55b, 0x3, 0x2, 0x2, 0x2, 0x55b, 0x55c, 
    0x7, 0x94, 0x2, 0x2, 0x55c, 0x55d, 0x5, 0xea, 0x76, 0x2, 0x55d, 0x55f, 
    0x3, 0x2, 0x2, 0x2, 0x55e, 0x54f, 0x3, 0x2, 0x2, 0x2, 0x55e, 0x559, 
    0x3, 0x2, 0x2, 0x2, 0x55f, 0xc7, 0x3, 0x2, 0x2, 0x2, 0x560, 0x561, 0x7, 
    0xb5, 0x2, 0x2, 0x561, 0xc9, 0x3, 0x2, 0x2, 0x2, 0x562, 0x564, 0x7, 
    0xbf, 0x2, 0x2, 0x563, 0x565, 0x7, 0xc6, 0x2, 0x2, 0x564, 0x563, 0x3, 
    0x2, 0x2, 0x2, 0x565, 0x566, 0x3, 0x2, 0x2, 0x2, 0x566, 0x564, 0x3, 
    0x2, 0x2, 0x2, 0x566, 0x567, 0x3, 0x2, 0x2, 0x2, 0x567, 0x578, 0x3, 
    0x2, 0x2, 0x2, 0x568, 0x56a, 0x7, 0xbe, 0x2, 0x2, 0x569, 0x56b, 0x7, 
    0xc6, 0x2, 0x2, 0x56a, 0x569, 0x3, 0x2, 0x2, 0x2, 0x56b, 0x56c, 0x3, 
    0x2, 0x2, 0x2, 0x56c, 0x56a, 0x3, 0x2, 0x2, 0x2, 0x56c, 0x56d, 0x3, 
    0x2, 0x2, 0x2, 0x56d, 0x578, 0x3, 0x2, 0x2, 0x2, 0x56e, 0x578, 0x7, 
    0xbc, 0x2, 0x2, 0x56f, 0x573, 0x7, 0xbd, 0x2, 0x2, 0x570, 0x572, 0x5, 
    0xcc, 0x67, 0x2, 0x571, 0x570, 0x3, 0x2, 0x2, 0x2, 0x572, 0x575, 0x3, 
    0x2, 0x2, 0x2, 0x573, 0x571, 0x3, 0x2, 0x2, 0x2, 0x573, 0x574, 0x3, 
    0x2, 0x2, 0x2, 0x574, 0x576, 0x3, 0x2, 0x2, 0x2, 0x575, 0x573, 0x3, 
    0x2, 0x2, 0x2, 0x576, 0x578, 0x7, 0xbd, 0x2, 0x2, 0x577, 0x562, 0x3, 
    0x2, 0x2, 0x2, 0x577, 0x568, 0x3, 0x2, 0x2, 0x2, 0x577, 0x56e, 0x3, 
    0x2, 0x2, 0x2, 0x577, 0x56f, 0x3, 0x2, 0x2, 0x2, 0x578, 0xcb, 0x3, 0x2, 
    0x2, 0x2, 0x579, 0x57c, 0x7, 0xc2, 0x2, 0x2, 0x57a, 0x57c, 0x5, 0xd0, 
    0x69, 0x2, 0x57b, 0x579, 0x3, 0x2, 0x2, 0x2, 0x57b, 0x57a, 0x3, 0x2, 
    0x2, 0x2, 0x57c, 0xcd, 0x3, 0x2, 0x2, 0x2, 0x57d, 0x582, 0x5, 0xd0, 
    0x69, 0x2, 0x57e, 0x57f, 0x7, 0xae, 0x2, 0x2, 0x57f, 0x581, 0x5, 0xd0, 
    0x69, 0x2, 0x580, 0x57e, 0x3, 0x2, 0x2, 0x2, 0x581, 0x584, 0x3, 0x2, 
    0x2, 0x2, 0x582, 0x580, 0x3, 0x2, 0x2, 0x2, 0x582, 0x583, 0x3, 0x2, 
    0x2, 0x2, 0x583, 0xcf, 0x3, 0x2, 0x2, 0x2, 0x584, 0x582, 0x3, 0x2, 0x2, 
    0x2, 0x585, 0x58c, 0x5, 0xda, 0x6e, 0x2, 0x586, 0x58c, 0x5, 0xd4, 0x6b, 
    0x2, 0x587, 0x588, 0x7, 0xa8, 0x2, 0x2, 0x588, 0x589, 0x5, 0x9c, 0x4f, 
    0x2, 0x589, 0x58a, 0x7, 0xa9, 0x2, 0x2, 0x58a, 0x58c, 0x3, 0x2, 0x2, 
    0x2, 0x58b, 0x585, 0x3, 0x2, 0x2, 0x2, 0x58b, 0x586, 0x3, 0x2, 0x2, 
    0x2, 0x58b, 0x587, 0x3, 0x2, 0x2, 0x2, 0x58c, 0x590, 0x3, 0x2, 0x2, 
    0x2, 0x58d, 0x58f, 0x5, 0xd2, 0x6a, 0x2, 0x58e, 0x58d, 0x3, 0x2, 0x2, 
    0x2, 0x58f, 0x592, 0x3, 0x2, 0x2, 0x2, 0x590, 0x58e, 0x3, 0x2, 0x2, 
    0x2, 0x590, 0x591, 0x3, 0x2, 0x2, 0x2, 0x591, 0xd1, 0x3, 0x2, 0x2, 0x2, 
    0x592, 0x590, 0x3, 0x2, 0x2, 0x2, 0x593, 0x594, 0x7, 0x95, 0x2, 0x2, 
    0x594, 0x596, 0x5, 0xdc, 0x6f, 0x2, 0x595, 0x597, 0x5, 0xd8, 0x6d, 0x2, 
    0x596, 0x595, 0x3, 0x2, 0x2, 0x2, 0x596, 0x597, 0x3, 0x2, 0x2, 0x2, 
    0x597, 0xd3, 0x3, 0x2, 0x2, 0x2, 0x598, 0x599, 0x5, 0xd6, 0x6c, 0x2, 
    0x599, 0x59a, 0x5, 0xd8, 0x6d, 0x2, 0x59a, 0xd5, 0x3, 0x2, 0x2, 0x2, 
    0x59b, 0x59f, 0x5, 0xb0, 0x59, 0x2, 0x59c, 0x59f, 0x5, 0xc6, 0x64, 0x2, 
    0x59d, 0x59f, 0x5, 0xda, 0x6e, 0x2, 0x59e, 0x59b, 0x3, 0x2, 0x2, 0x2, 
    0x59e, 0x59c, 0x3, 0x2, 0x2, 0x2, 0x59e, 0x59d, 0x3, 0x2, 0x2, 0x2, 
    0x59f, 0xd7, 0x3, 0x2, 0x2, 0x2, 0x5a0, 0x5a2, 0x5, 0x24, 0x13, 0x2, 
    0x5a1, 0x5a0, 0x3, 0x2, 0x2, 0x2, 0x5a1, 0x5a2, 0x3, 0x2, 0x2, 0x2, 
    0x5a2, 0x5a3, 0x3, 0x2, 0x2, 0x2, 0x5a3, 0x5a7, 0x5, 0xb6, 0x5c, 0x2, 
    0x5a4, 0x5a6, 0x5, 0xe2, 0x72, 0x2, 0x5a5, 0x5a4, 0x3, 0x2, 0x2, 0x2, 
    0x5a6, 0x5a9, 0x3, 0x2, 0x2, 0x2, 0x5a7, 0x5a5, 0x3, 0x2, 0x2, 0x2, 
    0x5a7, 0x5a8, 0x3, 0x2, 0x2, 0x2, 0x5a8, 0xd9, 0x3, 0x2, 0x2, 0x2, 0x5a9, 
    0x5a7, 0x3, 0x2, 0x2, 0x2, 0x5aa, 0x5ad, 0x5, 0xe0, 0x71, 0x2, 0x5ab, 
    0x5ac, 0x7, 0x94, 0x2, 0x2, 0x5ac, 0x5ae, 0x5, 0xe0, 0x71, 0x2, 0x5ad, 
    0x5ab, 0x3, 0x2, 0x2, 0x2, 0x5ad, 0x5ae, 0x3, 0x2, 0x2, 0x2, 0x5ae, 
    0x5b4, 0x3, 0x2, 0x2, 0x2, 0x5af, 0x5b0, 0x5, 0xaa, 0x56, 0x2, 0x5b0, 
    0x5b1, 0x7, 0x94, 0x2, 0x2, 0x5b1, 0x5b2, 0x5, 0xe0, 0x71, 0x2, 0x5b2, 
    0x5b4, 0x3, 0x2, 0x2, 0x2, 0x5b3, 0x5aa, 0x3, 0x2, 0x2, 0x2, 0x5b3, 
    0x5af, 0x3, 0x2, 0x2, 0x2, 0x5b4, 0xdb, 0x3, 0x2, 0x2, 0x2, 0x5b5, 0x5b8, 
    0x5, 0xde, 0x70, 0x2, 0x5b6, 0x5b8, 0x5, 0xe0, 0x71, 0x2, 0x5b7, 0x5b5, 
    0x3, 0x2, 0x2, 0x2, 0x5b7, 0x5b6, 0x3, 0x2, 0x2, 0x2, 0x5b8, 0xdd, 0x3, 
    0x2, 0x2, 0x2, 0x5b9, 0x5bf, 0x5, 0xea, 0x76, 0x2, 0x5ba, 0x5bb, 0x7, 
    0xac, 0x2, 0x2, 0x5bb, 0x5bc, 0x5, 0x9a, 0x4e, 0x2, 0x5bc, 0x5bd, 0x7, 
    0xad, 0x2, 0x2, 0x5bd, 0x5bf, 0x3, 0x2, 0x2, 0x2, 0x5be, 0x5b9, 0x3, 
    0x2, 0x2, 0x2, 0x5be, 0x5ba, 0x3, 0x2, 0x2, 0x2, 0x5bf, 0x5c3, 0x3, 
    0x2, 0x2, 0x2, 0x5c0, 0x5c2, 0x5, 0xe2, 0x72, 0x2, 0x5c1, 0x5c0, 0x3, 
    0x2, 0x2, 0x2, 0x5c2, 0x5c5, 0x3, 0x2, 0x2, 0x2, 0x5c3, 0x5c1, 0x3, 
    0x2, 0x2, 0x2, 0x5c3, 0x5c4, 0x3, 0x2, 0x2, 0x2, 0x5c4, 0xdf, 0x3, 0x2, 
    0x2, 0x2, 0x5c5, 0x5c3, 0x3, 0x2, 0x2, 0x2, 0x5c6, 0x5c8, 0x7, 0xa5, 
    0x2, 0x2, 0x5c7, 0x5c6, 0x3, 0x2, 0x2, 0x2, 0x5c8, 0x5cb, 0x3, 0x2, 
    0x2, 0x2, 0x5c9, 0x5c7, 0x3, 0x2, 0x2, 0x2, 0x5c9, 0x5ca, 0x3, 0x2, 
    0x2, 0x2, 0x5ca, 0x5d2, 0x3, 0x2, 0x2, 0x2, 0x5cb, 0x5c9, 0x3, 0x2, 
    0x2, 0x2, 0x5cc, 0x5d3, 0x7, 0xb4, 0x2, 0x2, 0x5cd, 0x5ce, 0x7, 0xa5, 
    0x2, 0x2, 0x5ce, 0x5cf, 0x7, 0xac, 0x2, 0x2, 0x5cf, 0x5d0, 0x5, 0x9a, 
    0x4e, 0x2, 0x5d0, 0x5d1, 0x7, 0xad, 0x2, 0x2, 0x5d1, 0x5d3, 0x3, 0x2, 
    0x2, 0x2, 0x5d2, 0x5cc, 0x3, 0x2, 0x2, 0x2, 0x5d2, 0x5cd, 0x3, 0x2, 
    0x2, 0x2, 0x5d3, 0x5d7, 0x3, 0x2, 0x2, 0x2, 0x5d4, 0x5d6, 0x5, 0xe2, 
    0x72, 0x2, 0x5d5, 0x5d4, 0x3, 0x2, 0x2, 0x2, 0x5d6, 0x5d9, 0x3, 0x2, 
    0x2, 0x2, 0x5d7, 0x5d5, 0x3, 0x2, 0x2, 0x2, 0x5d7, 0x5d8, 0x3, 0x2, 
    0x2, 0x2, 0x5d8, 0xe1, 0x3, 0x2, 0x2, 0x2, 0x5d9, 0x5d7, 0x3, 0x2, 0x2, 
    0x2, 0x5da, 0x5dc, 0x7, 0xaa, 0x2, 0x2, 0x5db, 0x5dd, 0x5, 0x9a, 0x4e, 
    0x2, 0x5dc, 0x5db, 0x3, 0x2, 0x2, 0x2, 0x5dc, 0x5dd, 0x3, 0x2, 0x2, 
    0x2, 0x5dd, 0x5de, 0x3, 0x2, 0x2, 0x2, 0x5de, 0x5e4, 0x7, 0xab, 0x2, 
    0x2, 0x5df, 0x5e0, 0x7, 0xac, 0x2, 0x2, 0x5e0, 0x5e1, 0x5, 0x9a, 0x4e, 
    0x2, 0x5e1, 0x5e2, 0x7, 0xad, 0x2, 0x2, 0x5e2, 0x5e4, 0x3, 0x2, 0x2, 
    0x2, 0x5e3, 0x5da, 0x3, 0x2, 0x2, 0x2, 0x5e3, 0x5df, 0x3, 0x2, 0x2, 
    0x2, 0x5e4, 0xe3, 0x3, 0x2, 0x2, 0x2, 0x5e5, 0x5e7, 0x5, 0xe6, 0x74, 
    0x2, 0x5e6, 0x5e5, 0x3, 0x2, 0x2, 0x2, 0x5e6, 0x5e7, 0x3, 0x2, 0x2, 
    0x2, 0x5e7, 0x5ee, 0x3, 0x2, 0x2, 0x2, 0x5e8, 0x5ea, 0x7, 0xae, 0x2, 
    0x2, 0x5e9, 0x5eb, 0x5, 0xe6, 0x74, 0x2, 0x5ea, 0x5e9, 0x3, 0x2, 0x2, 
    0x2, 0x5ea, 0x5eb, 0x3, 0x2, 0x2, 0x2, 0x5eb, 0x5ed, 0x3, 0x2, 0x2, 
    0x2, 0x5ec, 0x5e8, 0x3, 0x2, 0x2, 0x2, 0x5ed, 0x5f0, 0x3, 0x2, 0x2, 
    0x2, 0x5ee, 0x5ec, 0x3, 0x2, 0x2, 0x2, 0x5ee, 0x5ef, 0x3, 0x2, 0x2, 
    0x2, 0x5ef, 0xe5, 0x3, 0x2, 0x2, 0x2, 0x5f0, 0x5ee, 0x3, 0x2, 0x2, 0x2, 
    0x5f1, 0x5f8, 0x5, 0xd0, 0x69, 0x2, 0x5f2, 0x5f3, 0x7, 0x40, 0x2, 0x2, 
    0x5f3, 0x5f4, 0x7, 0xa8, 0x2, 0x2, 0x5f4, 0x5f5, 0x5, 0xe4, 0x73, 0x2, 
    0x5f5, 0x5f6, 0x7, 0xa9, 0x2, 0x2, 0x5f6, 0x5f8, 0x3, 0x2, 0x2, 0x2, 
    0x5f7, 0x5f1, 0x3, 0x2, 0x2, 0x2, 0x5f7, 0x5f2, 0x3, 0x2, 0x2, 0x2, 
    0x5f8, 0xe7, 0x3, 0x2, 0x2, 0x2, 0x5f9, 0x5fa, 0x9, 0x13, 0x2, 0x2, 
    0x5fa, 0xe9, 0x3, 0x2, 0x2, 0x2, 0x5fb, 0x5fc, 0x9, 0x14, 0x2, 0x2, 
    0x5fc, 0xeb, 0x3, 0x2, 0x2, 0x2, 0x5fd, 0x5fe, 0x9, 0x15, 0x2, 0x2, 
    0x5fe, 0xed, 0x3, 0x2, 0x2, 0x2, 0x5ff, 0x600, 0x9, 0x16, 0x2, 0x2, 
    0x600, 0xef, 0x3, 0x2, 0x2, 0x2, 0x601, 0x602, 0x9, 0x17, 0x2, 0x2, 
    0x602, 0xf1, 0x3, 0x2, 0x2, 0x2, 0x603, 0x604, 0x9, 0x18, 0x2, 0x2, 
    0x604, 0xf3, 0x3, 0x2, 0x2, 0x2, 0x605, 0x606, 0x9, 0x19, 0x2, 0x2, 
    0x606, 0xf5, 0x3, 0x2, 0x2, 0x2, 0xb1, 0xf9, 0xff, 0x10c, 0x110, 0x116, 
    0x11b, 0x120, 0x126, 0x12a, 0x130, 0x137, 0x13e, 0x143, 0x147, 0x150, 
    0x153, 0x156, 0x15b, 0x15f, 0x163, 0x168, 0x16c, 0x16e, 0x174, 0x180, 
    0x191, 0x198, 0x1a0, 0x1ab, 0x1b3, 0x1bb, 0x1c2, 0x1c9, 0x1e0, 0x1e7, 
    0x1ef, 0x1f9, 0x1ff, 0x21b, 0x229, 0x22d, 0x236, 0x23a, 0x23f, 0x259, 
    0x264, 0x268, 0x26c, 0x275, 0x27f, 0x284, 0x28a, 0x28f, 0x294, 0x299, 
    0x29e, 0x2a4, 0x2aa, 0x2b0, 0x2c2, 0x2c7, 0x2ca, 0x2d4, 0x2d7, 0x2e4, 
    0x2ec, 0x2f3, 0x2f6, 0x2fb, 0x2ff, 0x31d, 0x324, 0x328, 0x32e, 0x333, 
    0x336, 0x339, 0x340, 0x348, 0x355, 0x361, 0x36d, 0x379, 0x380, 0x384, 
    0x388, 0x38e, 0x396, 0x39d, 0x3a1, 0x3a5, 0x3b2, 0x3b5, 0x3bc, 0x3c6, 
    0x3ca, 0x3cf, 0x3d4, 0x3e1, 0x3eb, 0x3f1, 0x417, 0x41c, 0x41f, 0x425, 
    0x442, 0x449, 0x44d, 0x453, 0x460, 0x462, 0x488, 0x498, 0x49a, 0x4a0, 
    0x4a8, 0x4af, 0x4b3, 0x4b8, 0x4bd, 0x4c1, 0x4ca, 0x4d0, 0x4d6, 0x4d9, 
    0x4dd, 0x4e0, 0x4e4, 0x4eb, 0x4ef, 0x4f2, 0x4fb, 0x503, 0x50c, 0x510, 
    0x515, 0x51a, 0x522, 0x524, 0x52a, 0x52c, 0x531, 0x538, 0x53e, 0x545, 
    0x54b, 0x555, 0x559, 0x55e, 0x566, 0x56c, 0x573, 0x577, 0x57b, 0x582, 
    0x58b, 0x590, 0x596, 0x59e, 0x5a1, 0x5a7, 0x5ad, 0x5b3, 0x5b7, 0x5be, 
    0x5c3, 0x5c9, 0x5d2, 0x5d7, 0x5dc, 0x5e3, 0x5e6, 0x5ea, 0x5ee, 0x5f7, 
  };

  atn::ATNDeserializer deserializer;
  _atn = deserializer.deserialize(_serializedATN);

  size_t count = _atn.getNumberOfDecisions();
  _decisionToDFA.reserve(count);
  for (size_t i = 0; i < count; i++) { 
    _decisionToDFA.emplace_back(_atn.getDecisionState(i), i);
  }
}

PhpParser::Initializer PhpParser::_init;
