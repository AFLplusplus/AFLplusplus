
// Generated from C:\Users\xiang\Documents\GitHub\js_parser\ECMAScript.g4 by ANTLR 4.7


#include "ECMAScriptVisitor.h"

#include "ECMAScriptParser.h"


using namespace antlrcpp;
using namespace antlr4;

ECMAScriptParser::ECMAScriptParser(TokenStream *input) : Parser(input) {
  _interpreter = new atn::ParserATNSimulator(this, _atn, _decisionToDFA, _sharedContextCache);
}

ECMAScriptParser::~ECMAScriptParser() {
  delete _interpreter;
}

std::string ECMAScriptParser::getGrammarFileName() const {
  return "ECMAScript.g4";
}

const std::vector<std::string>& ECMAScriptParser::getRuleNames() const {
  return _ruleNames;
}

dfa::Vocabulary& ECMAScriptParser::getVocabulary() const {
  return _vocabulary;
}


//----------------- ProgramContext ------------------------------------------------------------------

ECMAScriptParser::ProgramContext::ProgramContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::ProgramContext::EOF() {
  return getToken(ECMAScriptParser::EOF, 0);
}

ECMAScriptParser::SourceElementsContext* ECMAScriptParser::ProgramContext::sourceElements() {
  return getRuleContext<ECMAScriptParser::SourceElementsContext>(0);
}


size_t ECMAScriptParser::ProgramContext::getRuleIndex() const {
  return ECMAScriptParser::RuleProgram;
}

antlrcpp::Any ECMAScriptParser::ProgramContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitProgram(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::ProgramContext* ECMAScriptParser::program() {
  ProgramContext *_localctx = _tracker.createInstance<ProgramContext>(_ctx, getState());
  enterRule(_localctx, 0, ECMAScriptParser::RuleProgram);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(111);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 0, _ctx)) {
    case 1: {
      setState(110);
      sourceElements();
      break;
    }

    }
    setState(113);
    match(ECMAScriptParser::EOF);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SourceElementsContext ------------------------------------------------------------------

ECMAScriptParser::SourceElementsContext::SourceElementsContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<ECMAScriptParser::SourceElementContext *> ECMAScriptParser::SourceElementsContext::sourceElement() {
  return getRuleContexts<ECMAScriptParser::SourceElementContext>();
}

ECMAScriptParser::SourceElementContext* ECMAScriptParser::SourceElementsContext::sourceElement(size_t i) {
  return getRuleContext<ECMAScriptParser::SourceElementContext>(i);
}


size_t ECMAScriptParser::SourceElementsContext::getRuleIndex() const {
  return ECMAScriptParser::RuleSourceElements;
}

antlrcpp::Any ECMAScriptParser::SourceElementsContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitSourceElements(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::SourceElementsContext* ECMAScriptParser::sourceElements() {
  SourceElementsContext *_localctx = _tracker.createInstance<SourceElementsContext>(_ctx, getState());
  enterRule(_localctx, 2, ECMAScriptParser::RuleSourceElements);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(116); 
    _errHandler->sync(this);
    alt = 1;
    do {
      switch (alt) {
        case 1: {
              setState(115);
              sourceElement();
              break;
            }

      default:
        throw NoViableAltException(this);
      }
      setState(118); 
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 1, _ctx);
    } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SourceElementContext ------------------------------------------------------------------

ECMAScriptParser::SourceElementContext::SourceElementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

ECMAScriptParser::StatementContext* ECMAScriptParser::SourceElementContext::statement() {
  return getRuleContext<ECMAScriptParser::StatementContext>(0);
}

ECMAScriptParser::FunctionDeclarationContext* ECMAScriptParser::SourceElementContext::functionDeclaration() {
  return getRuleContext<ECMAScriptParser::FunctionDeclarationContext>(0);
}


size_t ECMAScriptParser::SourceElementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleSourceElement;
}

antlrcpp::Any ECMAScriptParser::SourceElementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitSourceElement(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::SourceElementContext* ECMAScriptParser::sourceElement() {
  SourceElementContext *_localctx = _tracker.createInstance<SourceElementContext>(_ctx, getState());
  enterRule(_localctx, 4, ECMAScriptParser::RuleSourceElement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(122);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 2, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(120);
      statement();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(121);
      functionDeclaration();
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

ECMAScriptParser::StatementContext::StatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

ECMAScriptParser::BlockContext* ECMAScriptParser::StatementContext::block() {
  return getRuleContext<ECMAScriptParser::BlockContext>(0);
}

ECMAScriptParser::VariableStatementContext* ECMAScriptParser::StatementContext::variableStatement() {
  return getRuleContext<ECMAScriptParser::VariableStatementContext>(0);
}

ECMAScriptParser::EmptyStatementContext* ECMAScriptParser::StatementContext::emptyStatement() {
  return getRuleContext<ECMAScriptParser::EmptyStatementContext>(0);
}

ECMAScriptParser::ExpressionStatementContext* ECMAScriptParser::StatementContext::expressionStatement() {
  return getRuleContext<ECMAScriptParser::ExpressionStatementContext>(0);
}

ECMAScriptParser::IfStatementContext* ECMAScriptParser::StatementContext::ifStatement() {
  return getRuleContext<ECMAScriptParser::IfStatementContext>(0);
}

ECMAScriptParser::IterationStatementContext* ECMAScriptParser::StatementContext::iterationStatement() {
  return getRuleContext<ECMAScriptParser::IterationStatementContext>(0);
}

ECMAScriptParser::ContinueStatementContext* ECMAScriptParser::StatementContext::continueStatement() {
  return getRuleContext<ECMAScriptParser::ContinueStatementContext>(0);
}

ECMAScriptParser::BreakStatementContext* ECMAScriptParser::StatementContext::breakStatement() {
  return getRuleContext<ECMAScriptParser::BreakStatementContext>(0);
}

ECMAScriptParser::ReturnStatementContext* ECMAScriptParser::StatementContext::returnStatement() {
  return getRuleContext<ECMAScriptParser::ReturnStatementContext>(0);
}

ECMAScriptParser::WithStatementContext* ECMAScriptParser::StatementContext::withStatement() {
  return getRuleContext<ECMAScriptParser::WithStatementContext>(0);
}

ECMAScriptParser::LabelledStatementContext* ECMAScriptParser::StatementContext::labelledStatement() {
  return getRuleContext<ECMAScriptParser::LabelledStatementContext>(0);
}

ECMAScriptParser::SwitchStatementContext* ECMAScriptParser::StatementContext::switchStatement() {
  return getRuleContext<ECMAScriptParser::SwitchStatementContext>(0);
}

ECMAScriptParser::ThrowStatementContext* ECMAScriptParser::StatementContext::throwStatement() {
  return getRuleContext<ECMAScriptParser::ThrowStatementContext>(0);
}

ECMAScriptParser::TryStatementContext* ECMAScriptParser::StatementContext::tryStatement() {
  return getRuleContext<ECMAScriptParser::TryStatementContext>(0);
}

ECMAScriptParser::DebuggerStatementContext* ECMAScriptParser::StatementContext::debuggerStatement() {
  return getRuleContext<ECMAScriptParser::DebuggerStatementContext>(0);
}


size_t ECMAScriptParser::StatementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleStatement;
}

antlrcpp::Any ECMAScriptParser::StatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitStatement(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::StatementContext* ECMAScriptParser::statement() {
  StatementContext *_localctx = _tracker.createInstance<StatementContext>(_ctx, getState());
  enterRule(_localctx, 6, ECMAScriptParser::RuleStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(139);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 3, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(124);
      block();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(125);
      variableStatement();
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(126);
      emptyStatement();
      break;
    }

    case 4: {
      enterOuterAlt(_localctx, 4);
      setState(127);
      expressionStatement();
      break;
    }

    case 5: {
      enterOuterAlt(_localctx, 5);
      setState(128);
      ifStatement();
      break;
    }

    case 6: {
      enterOuterAlt(_localctx, 6);
      setState(129);
      iterationStatement();
      break;
    }

    case 7: {
      enterOuterAlt(_localctx, 7);
      setState(130);
      continueStatement();
      break;
    }

    case 8: {
      enterOuterAlt(_localctx, 8);
      setState(131);
      breakStatement();
      break;
    }

    case 9: {
      enterOuterAlt(_localctx, 9);
      setState(132);
      returnStatement();
      break;
    }

    case 10: {
      enterOuterAlt(_localctx, 10);
      setState(133);
      withStatement();
      break;
    }

    case 11: {
      enterOuterAlt(_localctx, 11);
      setState(134);
      labelledStatement();
      break;
    }

    case 12: {
      enterOuterAlt(_localctx, 12);
      setState(135);
      switchStatement();
      break;
    }

    case 13: {
      enterOuterAlt(_localctx, 13);
      setState(136);
      throwStatement();
      break;
    }

    case 14: {
      enterOuterAlt(_localctx, 14);
      setState(137);
      tryStatement();
      break;
    }

    case 15: {
      enterOuterAlt(_localctx, 15);
      setState(138);
      debuggerStatement();
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

//----------------- BlockContext ------------------------------------------------------------------

ECMAScriptParser::BlockContext::BlockContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

ECMAScriptParser::StatementListContext* ECMAScriptParser::BlockContext::statementList() {
  return getRuleContext<ECMAScriptParser::StatementListContext>(0);
}


size_t ECMAScriptParser::BlockContext::getRuleIndex() const {
  return ECMAScriptParser::RuleBlock;
}

antlrcpp::Any ECMAScriptParser::BlockContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitBlock(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::BlockContext* ECMAScriptParser::block() {
  BlockContext *_localctx = _tracker.createInstance<BlockContext>(_ctx, getState());
  enterRule(_localctx, 8, ECMAScriptParser::RuleBlock);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(141);
    match(ECMAScriptParser::OpenBrace);
    setState(143);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 4, _ctx)) {
    case 1: {
      setState(142);
      statementList();
      break;
    }

    }
    setState(145);
    match(ECMAScriptParser::CloseBrace);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- StatementListContext ------------------------------------------------------------------

ECMAScriptParser::StatementListContext::StatementListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<ECMAScriptParser::StatementContext *> ECMAScriptParser::StatementListContext::statement() {
  return getRuleContexts<ECMAScriptParser::StatementContext>();
}

ECMAScriptParser::StatementContext* ECMAScriptParser::StatementListContext::statement(size_t i) {
  return getRuleContext<ECMAScriptParser::StatementContext>(i);
}


size_t ECMAScriptParser::StatementListContext::getRuleIndex() const {
  return ECMAScriptParser::RuleStatementList;
}

antlrcpp::Any ECMAScriptParser::StatementListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitStatementList(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::StatementListContext* ECMAScriptParser::statementList() {
  StatementListContext *_localctx = _tracker.createInstance<StatementListContext>(_ctx, getState());
  enterRule(_localctx, 10, ECMAScriptParser::RuleStatementList);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(148); 
    _errHandler->sync(this);
    alt = 1;
    do {
      switch (alt) {
        case 1: {
              setState(147);
              statement();
              break;
            }

      default:
        throw NoViableAltException(this);
      }
      setState(150); 
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 5, _ctx);
    } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- VariableStatementContext ------------------------------------------------------------------

ECMAScriptParser::VariableStatementContext::VariableStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::VariableStatementContext::Var() {
  return getToken(ECMAScriptParser::Var, 0);
}

ECMAScriptParser::VariableDeclarationListContext* ECMAScriptParser::VariableStatementContext::variableDeclarationList() {
  return getRuleContext<ECMAScriptParser::VariableDeclarationListContext>(0);
}

ECMAScriptParser::EosContext* ECMAScriptParser::VariableStatementContext::eos() {
  return getRuleContext<ECMAScriptParser::EosContext>(0);
}

tree::TerminalNode* ECMAScriptParser::VariableStatementContext::Let() {
  return getToken(ECMAScriptParser::Let, 0);
}


size_t ECMAScriptParser::VariableStatementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleVariableStatement;
}

antlrcpp::Any ECMAScriptParser::VariableStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitVariableStatement(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::VariableStatementContext* ECMAScriptParser::variableStatement() {
  VariableStatementContext *_localctx = _tracker.createInstance<VariableStatementContext>(_ctx, getState());
  enterRule(_localctx, 12, ECMAScriptParser::RuleVariableStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(160);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case ECMAScriptParser::Var: {
        enterOuterAlt(_localctx, 1);
        setState(152);
        match(ECMAScriptParser::Var);
        setState(153);
        variableDeclarationList();
        setState(154);
        eos();
        break;
      }

      case ECMAScriptParser::Let: {
        enterOuterAlt(_localctx, 2);
        setState(156);
        match(ECMAScriptParser::Let);
        setState(157);
        variableDeclarationList();
        setState(158);
        eos();
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

//----------------- VariableDeclarationListContext ------------------------------------------------------------------

ECMAScriptParser::VariableDeclarationListContext::VariableDeclarationListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<ECMAScriptParser::VariableDeclarationContext *> ECMAScriptParser::VariableDeclarationListContext::variableDeclaration() {
  return getRuleContexts<ECMAScriptParser::VariableDeclarationContext>();
}

ECMAScriptParser::VariableDeclarationContext* ECMAScriptParser::VariableDeclarationListContext::variableDeclaration(size_t i) {
  return getRuleContext<ECMAScriptParser::VariableDeclarationContext>(i);
}


size_t ECMAScriptParser::VariableDeclarationListContext::getRuleIndex() const {
  return ECMAScriptParser::RuleVariableDeclarationList;
}

antlrcpp::Any ECMAScriptParser::VariableDeclarationListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitVariableDeclarationList(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::VariableDeclarationListContext* ECMAScriptParser::variableDeclarationList() {
  VariableDeclarationListContext *_localctx = _tracker.createInstance<VariableDeclarationListContext>(_ctx, getState());
  enterRule(_localctx, 14, ECMAScriptParser::RuleVariableDeclarationList);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(162);
    variableDeclaration();
    setState(167);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 7, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(163);
        match(ECMAScriptParser::Comma);
        setState(164);
        variableDeclaration(); 
      }
      setState(169);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 7, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- VariableDeclarationContext ------------------------------------------------------------------

ECMAScriptParser::VariableDeclarationContext::VariableDeclarationContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::VariableDeclarationContext::Identifier() {
  return getToken(ECMAScriptParser::Identifier, 0);
}

ECMAScriptParser::InitialiserContext* ECMAScriptParser::VariableDeclarationContext::initialiser() {
  return getRuleContext<ECMAScriptParser::InitialiserContext>(0);
}


size_t ECMAScriptParser::VariableDeclarationContext::getRuleIndex() const {
  return ECMAScriptParser::RuleVariableDeclaration;
}

antlrcpp::Any ECMAScriptParser::VariableDeclarationContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitVariableDeclaration(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::VariableDeclarationContext* ECMAScriptParser::variableDeclaration() {
  VariableDeclarationContext *_localctx = _tracker.createInstance<VariableDeclarationContext>(_ctx, getState());
  enterRule(_localctx, 16, ECMAScriptParser::RuleVariableDeclaration);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(170);
    match(ECMAScriptParser::Identifier);
    setState(172);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 8, _ctx)) {
    case 1: {
      setState(171);
      initialiser();
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

//----------------- InitialiserContext ------------------------------------------------------------------

ECMAScriptParser::InitialiserContext::InitialiserContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::InitialiserContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}


size_t ECMAScriptParser::InitialiserContext::getRuleIndex() const {
  return ECMAScriptParser::RuleInitialiser;
}

antlrcpp::Any ECMAScriptParser::InitialiserContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitInitialiser(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::InitialiserContext* ECMAScriptParser::initialiser() {
  InitialiserContext *_localctx = _tracker.createInstance<InitialiserContext>(_ctx, getState());
  enterRule(_localctx, 18, ECMAScriptParser::RuleInitialiser);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(174);
    match(ECMAScriptParser::Assign);
    setState(175);
    singleExpression(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- EmptyStatementContext ------------------------------------------------------------------

ECMAScriptParser::EmptyStatementContext::EmptyStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::EmptyStatementContext::SemiColon() {
  return getToken(ECMAScriptParser::SemiColon, 0);
}


size_t ECMAScriptParser::EmptyStatementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleEmptyStatement;
}

antlrcpp::Any ECMAScriptParser::EmptyStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitEmptyStatement(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::EmptyStatementContext* ECMAScriptParser::emptyStatement() {
  EmptyStatementContext *_localctx = _tracker.createInstance<EmptyStatementContext>(_ctx, getState());
  enterRule(_localctx, 20, ECMAScriptParser::RuleEmptyStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(177);
    match(ECMAScriptParser::SemiColon);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ExpressionStatementContext ------------------------------------------------------------------

ECMAScriptParser::ExpressionStatementContext::ExpressionStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::ExpressionStatementContext::expressionSequence() {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(0);
}

ECMAScriptParser::EosContext* ECMAScriptParser::ExpressionStatementContext::eos() {
  return getRuleContext<ECMAScriptParser::EosContext>(0);
}


size_t ECMAScriptParser::ExpressionStatementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleExpressionStatement;
}

antlrcpp::Any ECMAScriptParser::ExpressionStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitExpressionStatement(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::ExpressionStatementContext* ECMAScriptParser::expressionStatement() {
  ExpressionStatementContext *_localctx = _tracker.createInstance<ExpressionStatementContext>(_ctx, getState());
  enterRule(_localctx, 22, ECMAScriptParser::RuleExpressionStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(179);

    if (!((_input->LA(1) != OpenBrace) && (_input->LA(1) != Function))) throw FailedPredicateException(this, "(_input->LA(1) != OpenBrace) && (_input->LA(1) != Function)");
    setState(180);
    expressionSequence();
    setState(181);
    eos();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- IfStatementContext ------------------------------------------------------------------

ECMAScriptParser::IfStatementContext::IfStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::IfStatementContext::If() {
  return getToken(ECMAScriptParser::If, 0);
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::IfStatementContext::expressionSequence() {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(0);
}

std::vector<ECMAScriptParser::StatementContext *> ECMAScriptParser::IfStatementContext::statement() {
  return getRuleContexts<ECMAScriptParser::StatementContext>();
}

ECMAScriptParser::StatementContext* ECMAScriptParser::IfStatementContext::statement(size_t i) {
  return getRuleContext<ECMAScriptParser::StatementContext>(i);
}

tree::TerminalNode* ECMAScriptParser::IfStatementContext::Else() {
  return getToken(ECMAScriptParser::Else, 0);
}


size_t ECMAScriptParser::IfStatementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleIfStatement;
}

antlrcpp::Any ECMAScriptParser::IfStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitIfStatement(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::IfStatementContext* ECMAScriptParser::ifStatement() {
  IfStatementContext *_localctx = _tracker.createInstance<IfStatementContext>(_ctx, getState());
  enterRule(_localctx, 24, ECMAScriptParser::RuleIfStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(183);
    match(ECMAScriptParser::If);
    setState(184);
    match(ECMAScriptParser::OpenParen);
    setState(185);
    expressionSequence();
    setState(186);
    match(ECMAScriptParser::CloseParen);
    setState(187);
    statement();
    setState(190);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 9, _ctx)) {
    case 1: {
      setState(188);
      match(ECMAScriptParser::Else);
      setState(189);
      statement();
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

//----------------- IterationStatementContext ------------------------------------------------------------------

ECMAScriptParser::IterationStatementContext::IterationStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}


size_t ECMAScriptParser::IterationStatementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleIterationStatement;
}

void ECMAScriptParser::IterationStatementContext::copyFrom(IterationStatementContext *ctx) {
  ParserRuleContext::copyFrom(ctx);
}

//----------------- DoStatementContext ------------------------------------------------------------------

tree::TerminalNode* ECMAScriptParser::DoStatementContext::Do() {
  return getToken(ECMAScriptParser::Do, 0);
}

ECMAScriptParser::StatementContext* ECMAScriptParser::DoStatementContext::statement() {
  return getRuleContext<ECMAScriptParser::StatementContext>(0);
}

tree::TerminalNode* ECMAScriptParser::DoStatementContext::While() {
  return getToken(ECMAScriptParser::While, 0);
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::DoStatementContext::expressionSequence() {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(0);
}

ECMAScriptParser::EosContext* ECMAScriptParser::DoStatementContext::eos() {
  return getRuleContext<ECMAScriptParser::EosContext>(0);
}

ECMAScriptParser::DoStatementContext::DoStatementContext(IterationStatementContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::DoStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitDoStatement(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ForVarStatementContext ------------------------------------------------------------------

tree::TerminalNode* ECMAScriptParser::ForVarStatementContext::For() {
  return getToken(ECMAScriptParser::For, 0);
}

tree::TerminalNode* ECMAScriptParser::ForVarStatementContext::Var() {
  return getToken(ECMAScriptParser::Var, 0);
}

ECMAScriptParser::VariableDeclarationListContext* ECMAScriptParser::ForVarStatementContext::variableDeclarationList() {
  return getRuleContext<ECMAScriptParser::VariableDeclarationListContext>(0);
}

ECMAScriptParser::StatementContext* ECMAScriptParser::ForVarStatementContext::statement() {
  return getRuleContext<ECMAScriptParser::StatementContext>(0);
}

std::vector<ECMAScriptParser::ExpressionSequenceContext *> ECMAScriptParser::ForVarStatementContext::expressionSequence() {
  return getRuleContexts<ECMAScriptParser::ExpressionSequenceContext>();
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::ForVarStatementContext::expressionSequence(size_t i) {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(i);
}

ECMAScriptParser::ForVarStatementContext::ForVarStatementContext(IterationStatementContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::ForVarStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitForVarStatement(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ForVarInStatementContext ------------------------------------------------------------------

tree::TerminalNode* ECMAScriptParser::ForVarInStatementContext::For() {
  return getToken(ECMAScriptParser::For, 0);
}

tree::TerminalNode* ECMAScriptParser::ForVarInStatementContext::Var() {
  return getToken(ECMAScriptParser::Var, 0);
}

ECMAScriptParser::VariableDeclarationContext* ECMAScriptParser::ForVarInStatementContext::variableDeclaration() {
  return getRuleContext<ECMAScriptParser::VariableDeclarationContext>(0);
}

tree::TerminalNode* ECMAScriptParser::ForVarInStatementContext::In() {
  return getToken(ECMAScriptParser::In, 0);
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::ForVarInStatementContext::expressionSequence() {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(0);
}

ECMAScriptParser::StatementContext* ECMAScriptParser::ForVarInStatementContext::statement() {
  return getRuleContext<ECMAScriptParser::StatementContext>(0);
}

ECMAScriptParser::ForVarInStatementContext::ForVarInStatementContext(IterationStatementContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::ForVarInStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitForVarInStatement(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ForLetInStatementContext ------------------------------------------------------------------

tree::TerminalNode* ECMAScriptParser::ForLetInStatementContext::For() {
  return getToken(ECMAScriptParser::For, 0);
}

tree::TerminalNode* ECMAScriptParser::ForLetInStatementContext::Let() {
  return getToken(ECMAScriptParser::Let, 0);
}

ECMAScriptParser::VariableDeclarationContext* ECMAScriptParser::ForLetInStatementContext::variableDeclaration() {
  return getRuleContext<ECMAScriptParser::VariableDeclarationContext>(0);
}

tree::TerminalNode* ECMAScriptParser::ForLetInStatementContext::In() {
  return getToken(ECMAScriptParser::In, 0);
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::ForLetInStatementContext::expressionSequence() {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(0);
}

ECMAScriptParser::StatementContext* ECMAScriptParser::ForLetInStatementContext::statement() {
  return getRuleContext<ECMAScriptParser::StatementContext>(0);
}

ECMAScriptParser::ForLetInStatementContext::ForLetInStatementContext(IterationStatementContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::ForLetInStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitForLetInStatement(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ForLetStatementContext ------------------------------------------------------------------

tree::TerminalNode* ECMAScriptParser::ForLetStatementContext::For() {
  return getToken(ECMAScriptParser::For, 0);
}

tree::TerminalNode* ECMAScriptParser::ForLetStatementContext::Let() {
  return getToken(ECMAScriptParser::Let, 0);
}

ECMAScriptParser::VariableDeclarationListContext* ECMAScriptParser::ForLetStatementContext::variableDeclarationList() {
  return getRuleContext<ECMAScriptParser::VariableDeclarationListContext>(0);
}

ECMAScriptParser::StatementContext* ECMAScriptParser::ForLetStatementContext::statement() {
  return getRuleContext<ECMAScriptParser::StatementContext>(0);
}

std::vector<ECMAScriptParser::ExpressionSequenceContext *> ECMAScriptParser::ForLetStatementContext::expressionSequence() {
  return getRuleContexts<ECMAScriptParser::ExpressionSequenceContext>();
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::ForLetStatementContext::expressionSequence(size_t i) {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(i);
}

ECMAScriptParser::ForLetStatementContext::ForLetStatementContext(IterationStatementContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::ForLetStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitForLetStatement(this);
  else
    return visitor->visitChildren(this);
}
//----------------- WhileStatementContext ------------------------------------------------------------------

tree::TerminalNode* ECMAScriptParser::WhileStatementContext::While() {
  return getToken(ECMAScriptParser::While, 0);
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::WhileStatementContext::expressionSequence() {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(0);
}

ECMAScriptParser::StatementContext* ECMAScriptParser::WhileStatementContext::statement() {
  return getRuleContext<ECMAScriptParser::StatementContext>(0);
}

ECMAScriptParser::WhileStatementContext::WhileStatementContext(IterationStatementContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::WhileStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitWhileStatement(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ForStatementContext ------------------------------------------------------------------

tree::TerminalNode* ECMAScriptParser::ForStatementContext::For() {
  return getToken(ECMAScriptParser::For, 0);
}

ECMAScriptParser::StatementContext* ECMAScriptParser::ForStatementContext::statement() {
  return getRuleContext<ECMAScriptParser::StatementContext>(0);
}

std::vector<ECMAScriptParser::ExpressionSequenceContext *> ECMAScriptParser::ForStatementContext::expressionSequence() {
  return getRuleContexts<ECMAScriptParser::ExpressionSequenceContext>();
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::ForStatementContext::expressionSequence(size_t i) {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(i);
}

ECMAScriptParser::ForStatementContext::ForStatementContext(IterationStatementContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::ForStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitForStatement(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ForInStatementContext ------------------------------------------------------------------

tree::TerminalNode* ECMAScriptParser::ForInStatementContext::For() {
  return getToken(ECMAScriptParser::For, 0);
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::ForInStatementContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

tree::TerminalNode* ECMAScriptParser::ForInStatementContext::In() {
  return getToken(ECMAScriptParser::In, 0);
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::ForInStatementContext::expressionSequence() {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(0);
}

ECMAScriptParser::StatementContext* ECMAScriptParser::ForInStatementContext::statement() {
  return getRuleContext<ECMAScriptParser::StatementContext>(0);
}

ECMAScriptParser::ForInStatementContext::ForInStatementContext(IterationStatementContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::ForInStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitForInStatement(this);
  else
    return visitor->visitChildren(this);
}
ECMAScriptParser::IterationStatementContext* ECMAScriptParser::iterationStatement() {
  IterationStatementContext *_localctx = _tracker.createInstance<IterationStatementContext>(_ctx, getState());
  enterRule(_localctx, 26, ECMAScriptParser::RuleIterationStatement);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(277);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 17, _ctx)) {
    case 1: {
      _localctx = dynamic_cast<IterationStatementContext *>(_tracker.createInstance<ECMAScriptParser::DoStatementContext>(_localctx));
      enterOuterAlt(_localctx, 1);
      setState(192);
      match(ECMAScriptParser::Do);
      setState(193);
      statement();
      setState(194);
      match(ECMAScriptParser::While);
      setState(195);
      match(ECMAScriptParser::OpenParen);
      setState(196);
      expressionSequence();
      setState(197);
      match(ECMAScriptParser::CloseParen);
      setState(198);
      eos();
      break;
    }

    case 2: {
      _localctx = dynamic_cast<IterationStatementContext *>(_tracker.createInstance<ECMAScriptParser::WhileStatementContext>(_localctx));
      enterOuterAlt(_localctx, 2);
      setState(200);
      match(ECMAScriptParser::While);
      setState(201);
      match(ECMAScriptParser::OpenParen);
      setState(202);
      expressionSequence();
      setState(203);
      match(ECMAScriptParser::CloseParen);
      setState(204);
      statement();
      break;
    }

    case 3: {
      _localctx = dynamic_cast<IterationStatementContext *>(_tracker.createInstance<ECMAScriptParser::ForStatementContext>(_localctx));
      enterOuterAlt(_localctx, 3);
      setState(206);
      match(ECMAScriptParser::For);
      setState(207);
      match(ECMAScriptParser::OpenParen);
      setState(209);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << ECMAScriptParser::RegularExpressionLiteral)
        | (1ULL << ECMAScriptParser::OpenBracket)
        | (1ULL << ECMAScriptParser::OpenParen)
        | (1ULL << ECMAScriptParser::OpenBrace)
        | (1ULL << ECMAScriptParser::PlusPlus)
        | (1ULL << ECMAScriptParser::MinusMinus)
        | (1ULL << ECMAScriptParser::Plus)
        | (1ULL << ECMAScriptParser::Minus)
        | (1ULL << ECMAScriptParser::BitNot)
        | (1ULL << ECMAScriptParser::Not)
        | (1ULL << ECMAScriptParser::NullLiteral)
        | (1ULL << ECMAScriptParser::BooleanLiteral)
        | (1ULL << ECMAScriptParser::DecimalLiteral)
        | (1ULL << ECMAScriptParser::HexIntegerLiteral)
        | (1ULL << ECMAScriptParser::OctalIntegerLiteral)
        | (1ULL << ECMAScriptParser::Typeof)
        | (1ULL << ECMAScriptParser::New))) != 0) || ((((_la - 68) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 68)) & ((1ULL << (ECMAScriptParser::Void - 68))
        | (1ULL << (ECMAScriptParser::Function - 68))
        | (1ULL << (ECMAScriptParser::This - 68))
        | (1ULL << (ECMAScriptParser::Delete - 68))
        | (1ULL << (ECMAScriptParser::Identifier - 68))
        | (1ULL << (ECMAScriptParser::StringLiteral - 68)))) != 0)) {
        setState(208);
        expressionSequence();
      }
      setState(211);
      match(ECMAScriptParser::SemiColon);
      setState(213);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << ECMAScriptParser::RegularExpressionLiteral)
        | (1ULL << ECMAScriptParser::OpenBracket)
        | (1ULL << ECMAScriptParser::OpenParen)
        | (1ULL << ECMAScriptParser::OpenBrace)
        | (1ULL << ECMAScriptParser::PlusPlus)
        | (1ULL << ECMAScriptParser::MinusMinus)
        | (1ULL << ECMAScriptParser::Plus)
        | (1ULL << ECMAScriptParser::Minus)
        | (1ULL << ECMAScriptParser::BitNot)
        | (1ULL << ECMAScriptParser::Not)
        | (1ULL << ECMAScriptParser::NullLiteral)
        | (1ULL << ECMAScriptParser::BooleanLiteral)
        | (1ULL << ECMAScriptParser::DecimalLiteral)
        | (1ULL << ECMAScriptParser::HexIntegerLiteral)
        | (1ULL << ECMAScriptParser::OctalIntegerLiteral)
        | (1ULL << ECMAScriptParser::Typeof)
        | (1ULL << ECMAScriptParser::New))) != 0) || ((((_la - 68) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 68)) & ((1ULL << (ECMAScriptParser::Void - 68))
        | (1ULL << (ECMAScriptParser::Function - 68))
        | (1ULL << (ECMAScriptParser::This - 68))
        | (1ULL << (ECMAScriptParser::Delete - 68))
        | (1ULL << (ECMAScriptParser::Identifier - 68))
        | (1ULL << (ECMAScriptParser::StringLiteral - 68)))) != 0)) {
        setState(212);
        expressionSequence();
      }
      setState(215);
      match(ECMAScriptParser::SemiColon);
      setState(217);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << ECMAScriptParser::RegularExpressionLiteral)
        | (1ULL << ECMAScriptParser::OpenBracket)
        | (1ULL << ECMAScriptParser::OpenParen)
        | (1ULL << ECMAScriptParser::OpenBrace)
        | (1ULL << ECMAScriptParser::PlusPlus)
        | (1ULL << ECMAScriptParser::MinusMinus)
        | (1ULL << ECMAScriptParser::Plus)
        | (1ULL << ECMAScriptParser::Minus)
        | (1ULL << ECMAScriptParser::BitNot)
        | (1ULL << ECMAScriptParser::Not)
        | (1ULL << ECMAScriptParser::NullLiteral)
        | (1ULL << ECMAScriptParser::BooleanLiteral)
        | (1ULL << ECMAScriptParser::DecimalLiteral)
        | (1ULL << ECMAScriptParser::HexIntegerLiteral)
        | (1ULL << ECMAScriptParser::OctalIntegerLiteral)
        | (1ULL << ECMAScriptParser::Typeof)
        | (1ULL << ECMAScriptParser::New))) != 0) || ((((_la - 68) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 68)) & ((1ULL << (ECMAScriptParser::Void - 68))
        | (1ULL << (ECMAScriptParser::Function - 68))
        | (1ULL << (ECMAScriptParser::This - 68))
        | (1ULL << (ECMAScriptParser::Delete - 68))
        | (1ULL << (ECMAScriptParser::Identifier - 68))
        | (1ULL << (ECMAScriptParser::StringLiteral - 68)))) != 0)) {
        setState(216);
        expressionSequence();
      }
      setState(219);
      match(ECMAScriptParser::CloseParen);
      setState(220);
      statement();
      break;
    }

    case 4: {
      _localctx = dynamic_cast<IterationStatementContext *>(_tracker.createInstance<ECMAScriptParser::ForVarStatementContext>(_localctx));
      enterOuterAlt(_localctx, 4);
      setState(221);
      match(ECMAScriptParser::For);
      setState(222);
      match(ECMAScriptParser::OpenParen);
      setState(223);
      match(ECMAScriptParser::Var);
      setState(224);
      variableDeclarationList();
      setState(225);
      match(ECMAScriptParser::SemiColon);
      setState(227);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << ECMAScriptParser::RegularExpressionLiteral)
        | (1ULL << ECMAScriptParser::OpenBracket)
        | (1ULL << ECMAScriptParser::OpenParen)
        | (1ULL << ECMAScriptParser::OpenBrace)
        | (1ULL << ECMAScriptParser::PlusPlus)
        | (1ULL << ECMAScriptParser::MinusMinus)
        | (1ULL << ECMAScriptParser::Plus)
        | (1ULL << ECMAScriptParser::Minus)
        | (1ULL << ECMAScriptParser::BitNot)
        | (1ULL << ECMAScriptParser::Not)
        | (1ULL << ECMAScriptParser::NullLiteral)
        | (1ULL << ECMAScriptParser::BooleanLiteral)
        | (1ULL << ECMAScriptParser::DecimalLiteral)
        | (1ULL << ECMAScriptParser::HexIntegerLiteral)
        | (1ULL << ECMAScriptParser::OctalIntegerLiteral)
        | (1ULL << ECMAScriptParser::Typeof)
        | (1ULL << ECMAScriptParser::New))) != 0) || ((((_la - 68) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 68)) & ((1ULL << (ECMAScriptParser::Void - 68))
        | (1ULL << (ECMAScriptParser::Function - 68))
        | (1ULL << (ECMAScriptParser::This - 68))
        | (1ULL << (ECMAScriptParser::Delete - 68))
        | (1ULL << (ECMAScriptParser::Identifier - 68))
        | (1ULL << (ECMAScriptParser::StringLiteral - 68)))) != 0)) {
        setState(226);
        expressionSequence();
      }
      setState(229);
      match(ECMAScriptParser::SemiColon);
      setState(231);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << ECMAScriptParser::RegularExpressionLiteral)
        | (1ULL << ECMAScriptParser::OpenBracket)
        | (1ULL << ECMAScriptParser::OpenParen)
        | (1ULL << ECMAScriptParser::OpenBrace)
        | (1ULL << ECMAScriptParser::PlusPlus)
        | (1ULL << ECMAScriptParser::MinusMinus)
        | (1ULL << ECMAScriptParser::Plus)
        | (1ULL << ECMAScriptParser::Minus)
        | (1ULL << ECMAScriptParser::BitNot)
        | (1ULL << ECMAScriptParser::Not)
        | (1ULL << ECMAScriptParser::NullLiteral)
        | (1ULL << ECMAScriptParser::BooleanLiteral)
        | (1ULL << ECMAScriptParser::DecimalLiteral)
        | (1ULL << ECMAScriptParser::HexIntegerLiteral)
        | (1ULL << ECMAScriptParser::OctalIntegerLiteral)
        | (1ULL << ECMAScriptParser::Typeof)
        | (1ULL << ECMAScriptParser::New))) != 0) || ((((_la - 68) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 68)) & ((1ULL << (ECMAScriptParser::Void - 68))
        | (1ULL << (ECMAScriptParser::Function - 68))
        | (1ULL << (ECMAScriptParser::This - 68))
        | (1ULL << (ECMAScriptParser::Delete - 68))
        | (1ULL << (ECMAScriptParser::Identifier - 68))
        | (1ULL << (ECMAScriptParser::StringLiteral - 68)))) != 0)) {
        setState(230);
        expressionSequence();
      }
      setState(233);
      match(ECMAScriptParser::CloseParen);
      setState(234);
      statement();
      break;
    }

    case 5: {
      _localctx = dynamic_cast<IterationStatementContext *>(_tracker.createInstance<ECMAScriptParser::ForLetStatementContext>(_localctx));
      enterOuterAlt(_localctx, 5);
      setState(236);
      match(ECMAScriptParser::For);
      setState(237);
      match(ECMAScriptParser::OpenParen);
      setState(238);
      match(ECMAScriptParser::Let);
      setState(239);
      variableDeclarationList();
      setState(240);
      match(ECMAScriptParser::SemiColon);
      setState(242);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << ECMAScriptParser::RegularExpressionLiteral)
        | (1ULL << ECMAScriptParser::OpenBracket)
        | (1ULL << ECMAScriptParser::OpenParen)
        | (1ULL << ECMAScriptParser::OpenBrace)
        | (1ULL << ECMAScriptParser::PlusPlus)
        | (1ULL << ECMAScriptParser::MinusMinus)
        | (1ULL << ECMAScriptParser::Plus)
        | (1ULL << ECMAScriptParser::Minus)
        | (1ULL << ECMAScriptParser::BitNot)
        | (1ULL << ECMAScriptParser::Not)
        | (1ULL << ECMAScriptParser::NullLiteral)
        | (1ULL << ECMAScriptParser::BooleanLiteral)
        | (1ULL << ECMAScriptParser::DecimalLiteral)
        | (1ULL << ECMAScriptParser::HexIntegerLiteral)
        | (1ULL << ECMAScriptParser::OctalIntegerLiteral)
        | (1ULL << ECMAScriptParser::Typeof)
        | (1ULL << ECMAScriptParser::New))) != 0) || ((((_la - 68) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 68)) & ((1ULL << (ECMAScriptParser::Void - 68))
        | (1ULL << (ECMAScriptParser::Function - 68))
        | (1ULL << (ECMAScriptParser::This - 68))
        | (1ULL << (ECMAScriptParser::Delete - 68))
        | (1ULL << (ECMAScriptParser::Identifier - 68))
        | (1ULL << (ECMAScriptParser::StringLiteral - 68)))) != 0)) {
        setState(241);
        expressionSequence();
      }
      setState(244);
      match(ECMAScriptParser::SemiColon);
      setState(246);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << ECMAScriptParser::RegularExpressionLiteral)
        | (1ULL << ECMAScriptParser::OpenBracket)
        | (1ULL << ECMAScriptParser::OpenParen)
        | (1ULL << ECMAScriptParser::OpenBrace)
        | (1ULL << ECMAScriptParser::PlusPlus)
        | (1ULL << ECMAScriptParser::MinusMinus)
        | (1ULL << ECMAScriptParser::Plus)
        | (1ULL << ECMAScriptParser::Minus)
        | (1ULL << ECMAScriptParser::BitNot)
        | (1ULL << ECMAScriptParser::Not)
        | (1ULL << ECMAScriptParser::NullLiteral)
        | (1ULL << ECMAScriptParser::BooleanLiteral)
        | (1ULL << ECMAScriptParser::DecimalLiteral)
        | (1ULL << ECMAScriptParser::HexIntegerLiteral)
        | (1ULL << ECMAScriptParser::OctalIntegerLiteral)
        | (1ULL << ECMAScriptParser::Typeof)
        | (1ULL << ECMAScriptParser::New))) != 0) || ((((_la - 68) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 68)) & ((1ULL << (ECMAScriptParser::Void - 68))
        | (1ULL << (ECMAScriptParser::Function - 68))
        | (1ULL << (ECMAScriptParser::This - 68))
        | (1ULL << (ECMAScriptParser::Delete - 68))
        | (1ULL << (ECMAScriptParser::Identifier - 68))
        | (1ULL << (ECMAScriptParser::StringLiteral - 68)))) != 0)) {
        setState(245);
        expressionSequence();
      }
      setState(248);
      match(ECMAScriptParser::CloseParen);
      setState(249);
      statement();
      break;
    }

    case 6: {
      _localctx = dynamic_cast<IterationStatementContext *>(_tracker.createInstance<ECMAScriptParser::ForInStatementContext>(_localctx));
      enterOuterAlt(_localctx, 6);
      setState(251);
      match(ECMAScriptParser::For);
      setState(252);
      match(ECMAScriptParser::OpenParen);
      setState(253);
      singleExpression(0);
      setState(254);
      match(ECMAScriptParser::In);
      setState(255);
      expressionSequence();
      setState(256);
      match(ECMAScriptParser::CloseParen);
      setState(257);
      statement();
      break;
    }

    case 7: {
      _localctx = dynamic_cast<IterationStatementContext *>(_tracker.createInstance<ECMAScriptParser::ForVarInStatementContext>(_localctx));
      enterOuterAlt(_localctx, 7);
      setState(259);
      match(ECMAScriptParser::For);
      setState(260);
      match(ECMAScriptParser::OpenParen);
      setState(261);
      match(ECMAScriptParser::Var);
      setState(262);
      variableDeclaration();
      setState(263);
      match(ECMAScriptParser::In);
      setState(264);
      expressionSequence();
      setState(265);
      match(ECMAScriptParser::CloseParen);
      setState(266);
      statement();
      break;
    }

    case 8: {
      _localctx = dynamic_cast<IterationStatementContext *>(_tracker.createInstance<ECMAScriptParser::ForLetInStatementContext>(_localctx));
      enterOuterAlt(_localctx, 8);
      setState(268);
      match(ECMAScriptParser::For);
      setState(269);
      match(ECMAScriptParser::OpenParen);
      setState(270);
      match(ECMAScriptParser::Let);
      setState(271);
      variableDeclaration();
      setState(272);
      match(ECMAScriptParser::In);
      setState(273);
      expressionSequence();
      setState(274);
      match(ECMAScriptParser::CloseParen);
      setState(275);
      statement();
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

//----------------- ContinueStatementContext ------------------------------------------------------------------

ECMAScriptParser::ContinueStatementContext::ContinueStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::ContinueStatementContext::Continue() {
  return getToken(ECMAScriptParser::Continue, 0);
}

ECMAScriptParser::EosContext* ECMAScriptParser::ContinueStatementContext::eos() {
  return getRuleContext<ECMAScriptParser::EosContext>(0);
}

tree::TerminalNode* ECMAScriptParser::ContinueStatementContext::Identifier() {
  return getToken(ECMAScriptParser::Identifier, 0);
}


size_t ECMAScriptParser::ContinueStatementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleContinueStatement;
}

antlrcpp::Any ECMAScriptParser::ContinueStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitContinueStatement(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::ContinueStatementContext* ECMAScriptParser::continueStatement() {
  ContinueStatementContext *_localctx = _tracker.createInstance<ContinueStatementContext>(_ctx, getState());
  enterRule(_localctx, 28, ECMAScriptParser::RuleContinueStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(279);
    match(ECMAScriptParser::Continue);
    setState(282);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 18, _ctx)) {
    case 1: {
      setState(280);

      if (!(!here(LineTerminator))) throw FailedPredicateException(this, "!here(LineTerminator)");
      setState(281);
      match(ECMAScriptParser::Identifier);
      break;
    }

    }
    setState(284);
    eos();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- BreakStatementContext ------------------------------------------------------------------

ECMAScriptParser::BreakStatementContext::BreakStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::BreakStatementContext::Break() {
  return getToken(ECMAScriptParser::Break, 0);
}

ECMAScriptParser::EosContext* ECMAScriptParser::BreakStatementContext::eos() {
  return getRuleContext<ECMAScriptParser::EosContext>(0);
}

tree::TerminalNode* ECMAScriptParser::BreakStatementContext::Identifier() {
  return getToken(ECMAScriptParser::Identifier, 0);
}


size_t ECMAScriptParser::BreakStatementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleBreakStatement;
}

antlrcpp::Any ECMAScriptParser::BreakStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitBreakStatement(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::BreakStatementContext* ECMAScriptParser::breakStatement() {
  BreakStatementContext *_localctx = _tracker.createInstance<BreakStatementContext>(_ctx, getState());
  enterRule(_localctx, 30, ECMAScriptParser::RuleBreakStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(286);
    match(ECMAScriptParser::Break);
    setState(289);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 19, _ctx)) {
    case 1: {
      setState(287);

      if (!(!here(LineTerminator))) throw FailedPredicateException(this, "!here(LineTerminator)");
      setState(288);
      match(ECMAScriptParser::Identifier);
      break;
    }

    }
    setState(291);
    eos();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ReturnStatementContext ------------------------------------------------------------------

ECMAScriptParser::ReturnStatementContext::ReturnStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::ReturnStatementContext::Return() {
  return getToken(ECMAScriptParser::Return, 0);
}

ECMAScriptParser::EosContext* ECMAScriptParser::ReturnStatementContext::eos() {
  return getRuleContext<ECMAScriptParser::EosContext>(0);
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::ReturnStatementContext::expressionSequence() {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(0);
}


size_t ECMAScriptParser::ReturnStatementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleReturnStatement;
}

antlrcpp::Any ECMAScriptParser::ReturnStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitReturnStatement(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::ReturnStatementContext* ECMAScriptParser::returnStatement() {
  ReturnStatementContext *_localctx = _tracker.createInstance<ReturnStatementContext>(_ctx, getState());
  enterRule(_localctx, 32, ECMAScriptParser::RuleReturnStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(293);
    match(ECMAScriptParser::Return);
    setState(296);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 20, _ctx)) {
    case 1: {
      setState(294);

      if (!(!here(LineTerminator))) throw FailedPredicateException(this, "!here(LineTerminator)");
      setState(295);
      expressionSequence();
      break;
    }

    }
    setState(298);
    eos();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- WithStatementContext ------------------------------------------------------------------

ECMAScriptParser::WithStatementContext::WithStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::WithStatementContext::With() {
  return getToken(ECMAScriptParser::With, 0);
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::WithStatementContext::expressionSequence() {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(0);
}

ECMAScriptParser::StatementContext* ECMAScriptParser::WithStatementContext::statement() {
  return getRuleContext<ECMAScriptParser::StatementContext>(0);
}


size_t ECMAScriptParser::WithStatementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleWithStatement;
}

antlrcpp::Any ECMAScriptParser::WithStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitWithStatement(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::WithStatementContext* ECMAScriptParser::withStatement() {
  WithStatementContext *_localctx = _tracker.createInstance<WithStatementContext>(_ctx, getState());
  enterRule(_localctx, 34, ECMAScriptParser::RuleWithStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(300);
    match(ECMAScriptParser::With);
    setState(301);
    match(ECMAScriptParser::OpenParen);
    setState(302);
    expressionSequence();
    setState(303);
    match(ECMAScriptParser::CloseParen);
    setState(304);
    statement();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SwitchStatementContext ------------------------------------------------------------------

ECMAScriptParser::SwitchStatementContext::SwitchStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::SwitchStatementContext::Switch() {
  return getToken(ECMAScriptParser::Switch, 0);
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::SwitchStatementContext::expressionSequence() {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(0);
}

ECMAScriptParser::CaseBlockContext* ECMAScriptParser::SwitchStatementContext::caseBlock() {
  return getRuleContext<ECMAScriptParser::CaseBlockContext>(0);
}


size_t ECMAScriptParser::SwitchStatementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleSwitchStatement;
}

antlrcpp::Any ECMAScriptParser::SwitchStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitSwitchStatement(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::SwitchStatementContext* ECMAScriptParser::switchStatement() {
  SwitchStatementContext *_localctx = _tracker.createInstance<SwitchStatementContext>(_ctx, getState());
  enterRule(_localctx, 36, ECMAScriptParser::RuleSwitchStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(306);
    match(ECMAScriptParser::Switch);
    setState(307);
    match(ECMAScriptParser::OpenParen);
    setState(308);
    expressionSequence();
    setState(309);
    match(ECMAScriptParser::CloseParen);
    setState(310);
    caseBlock();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- CaseBlockContext ------------------------------------------------------------------

ECMAScriptParser::CaseBlockContext::CaseBlockContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<ECMAScriptParser::CaseClausesContext *> ECMAScriptParser::CaseBlockContext::caseClauses() {
  return getRuleContexts<ECMAScriptParser::CaseClausesContext>();
}

ECMAScriptParser::CaseClausesContext* ECMAScriptParser::CaseBlockContext::caseClauses(size_t i) {
  return getRuleContext<ECMAScriptParser::CaseClausesContext>(i);
}

ECMAScriptParser::DefaultClauseContext* ECMAScriptParser::CaseBlockContext::defaultClause() {
  return getRuleContext<ECMAScriptParser::DefaultClauseContext>(0);
}


size_t ECMAScriptParser::CaseBlockContext::getRuleIndex() const {
  return ECMAScriptParser::RuleCaseBlock;
}

antlrcpp::Any ECMAScriptParser::CaseBlockContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitCaseBlock(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::CaseBlockContext* ECMAScriptParser::caseBlock() {
  CaseBlockContext *_localctx = _tracker.createInstance<CaseBlockContext>(_ctx, getState());
  enterRule(_localctx, 38, ECMAScriptParser::RuleCaseBlock);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(312);
    match(ECMAScriptParser::OpenBrace);
    setState(314);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == ECMAScriptParser::Case) {
      setState(313);
      caseClauses();
    }
    setState(320);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == ECMAScriptParser::Default) {
      setState(316);
      defaultClause();
      setState(318);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == ECMAScriptParser::Case) {
        setState(317);
        caseClauses();
      }
    }
    setState(322);
    match(ECMAScriptParser::CloseBrace);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- CaseClausesContext ------------------------------------------------------------------

ECMAScriptParser::CaseClausesContext::CaseClausesContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<ECMAScriptParser::CaseClauseContext *> ECMAScriptParser::CaseClausesContext::caseClause() {
  return getRuleContexts<ECMAScriptParser::CaseClauseContext>();
}

ECMAScriptParser::CaseClauseContext* ECMAScriptParser::CaseClausesContext::caseClause(size_t i) {
  return getRuleContext<ECMAScriptParser::CaseClauseContext>(i);
}


size_t ECMAScriptParser::CaseClausesContext::getRuleIndex() const {
  return ECMAScriptParser::RuleCaseClauses;
}

antlrcpp::Any ECMAScriptParser::CaseClausesContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitCaseClauses(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::CaseClausesContext* ECMAScriptParser::caseClauses() {
  CaseClausesContext *_localctx = _tracker.createInstance<CaseClausesContext>(_ctx, getState());
  enterRule(_localctx, 40, ECMAScriptParser::RuleCaseClauses);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(325); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(324);
      caseClause();
      setState(327); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == ECMAScriptParser::Case);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- CaseClauseContext ------------------------------------------------------------------

ECMAScriptParser::CaseClauseContext::CaseClauseContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::CaseClauseContext::Case() {
  return getToken(ECMAScriptParser::Case, 0);
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::CaseClauseContext::expressionSequence() {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(0);
}

ECMAScriptParser::StatementListContext* ECMAScriptParser::CaseClauseContext::statementList() {
  return getRuleContext<ECMAScriptParser::StatementListContext>(0);
}


size_t ECMAScriptParser::CaseClauseContext::getRuleIndex() const {
  return ECMAScriptParser::RuleCaseClause;
}

antlrcpp::Any ECMAScriptParser::CaseClauseContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitCaseClause(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::CaseClauseContext* ECMAScriptParser::caseClause() {
  CaseClauseContext *_localctx = _tracker.createInstance<CaseClauseContext>(_ctx, getState());
  enterRule(_localctx, 42, ECMAScriptParser::RuleCaseClause);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(329);
    match(ECMAScriptParser::Case);
    setState(330);
    expressionSequence();
    setState(331);
    match(ECMAScriptParser::Colon);
    setState(333);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 25, _ctx)) {
    case 1: {
      setState(332);
      statementList();
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

//----------------- DefaultClauseContext ------------------------------------------------------------------

ECMAScriptParser::DefaultClauseContext::DefaultClauseContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::DefaultClauseContext::Default() {
  return getToken(ECMAScriptParser::Default, 0);
}

ECMAScriptParser::StatementListContext* ECMAScriptParser::DefaultClauseContext::statementList() {
  return getRuleContext<ECMAScriptParser::StatementListContext>(0);
}


size_t ECMAScriptParser::DefaultClauseContext::getRuleIndex() const {
  return ECMAScriptParser::RuleDefaultClause;
}

antlrcpp::Any ECMAScriptParser::DefaultClauseContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitDefaultClause(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::DefaultClauseContext* ECMAScriptParser::defaultClause() {
  DefaultClauseContext *_localctx = _tracker.createInstance<DefaultClauseContext>(_ctx, getState());
  enterRule(_localctx, 44, ECMAScriptParser::RuleDefaultClause);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(335);
    match(ECMAScriptParser::Default);
    setState(336);
    match(ECMAScriptParser::Colon);
    setState(338);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 26, _ctx)) {
    case 1: {
      setState(337);
      statementList();
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

//----------------- LabelledStatementContext ------------------------------------------------------------------

ECMAScriptParser::LabelledStatementContext::LabelledStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::LabelledStatementContext::Identifier() {
  return getToken(ECMAScriptParser::Identifier, 0);
}

ECMAScriptParser::StatementContext* ECMAScriptParser::LabelledStatementContext::statement() {
  return getRuleContext<ECMAScriptParser::StatementContext>(0);
}


size_t ECMAScriptParser::LabelledStatementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleLabelledStatement;
}

antlrcpp::Any ECMAScriptParser::LabelledStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitLabelledStatement(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::LabelledStatementContext* ECMAScriptParser::labelledStatement() {
  LabelledStatementContext *_localctx = _tracker.createInstance<LabelledStatementContext>(_ctx, getState());
  enterRule(_localctx, 46, ECMAScriptParser::RuleLabelledStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(340);
    match(ECMAScriptParser::Identifier);
    setState(341);
    match(ECMAScriptParser::Colon);
    setState(342);
    statement();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ThrowStatementContext ------------------------------------------------------------------

ECMAScriptParser::ThrowStatementContext::ThrowStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::ThrowStatementContext::Throw() {
  return getToken(ECMAScriptParser::Throw, 0);
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::ThrowStatementContext::expressionSequence() {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(0);
}

ECMAScriptParser::EosContext* ECMAScriptParser::ThrowStatementContext::eos() {
  return getRuleContext<ECMAScriptParser::EosContext>(0);
}


size_t ECMAScriptParser::ThrowStatementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleThrowStatement;
}

antlrcpp::Any ECMAScriptParser::ThrowStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitThrowStatement(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::ThrowStatementContext* ECMAScriptParser::throwStatement() {
  ThrowStatementContext *_localctx = _tracker.createInstance<ThrowStatementContext>(_ctx, getState());
  enterRule(_localctx, 48, ECMAScriptParser::RuleThrowStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(344);
    match(ECMAScriptParser::Throw);
    setState(345);

    if (!(!here(LineTerminator))) throw FailedPredicateException(this, "!here(LineTerminator)");
    setState(346);
    expressionSequence();
    setState(347);
    eos();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TryStatementContext ------------------------------------------------------------------

ECMAScriptParser::TryStatementContext::TryStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::TryStatementContext::Try() {
  return getToken(ECMAScriptParser::Try, 0);
}

ECMAScriptParser::BlockContext* ECMAScriptParser::TryStatementContext::block() {
  return getRuleContext<ECMAScriptParser::BlockContext>(0);
}

ECMAScriptParser::CatchProductionContext* ECMAScriptParser::TryStatementContext::catchProduction() {
  return getRuleContext<ECMAScriptParser::CatchProductionContext>(0);
}

ECMAScriptParser::FinallyProductionContext* ECMAScriptParser::TryStatementContext::finallyProduction() {
  return getRuleContext<ECMAScriptParser::FinallyProductionContext>(0);
}


size_t ECMAScriptParser::TryStatementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleTryStatement;
}

antlrcpp::Any ECMAScriptParser::TryStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitTryStatement(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::TryStatementContext* ECMAScriptParser::tryStatement() {
  TryStatementContext *_localctx = _tracker.createInstance<TryStatementContext>(_ctx, getState());
  enterRule(_localctx, 50, ECMAScriptParser::RuleTryStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(362);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 27, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(349);
      match(ECMAScriptParser::Try);
      setState(350);
      block();
      setState(351);
      catchProduction();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(353);
      match(ECMAScriptParser::Try);
      setState(354);
      block();
      setState(355);
      finallyProduction();
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(357);
      match(ECMAScriptParser::Try);
      setState(358);
      block();
      setState(359);
      catchProduction();
      setState(360);
      finallyProduction();
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

//----------------- CatchProductionContext ------------------------------------------------------------------

ECMAScriptParser::CatchProductionContext::CatchProductionContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::CatchProductionContext::Catch() {
  return getToken(ECMAScriptParser::Catch, 0);
}

tree::TerminalNode* ECMAScriptParser::CatchProductionContext::Identifier() {
  return getToken(ECMAScriptParser::Identifier, 0);
}

ECMAScriptParser::BlockContext* ECMAScriptParser::CatchProductionContext::block() {
  return getRuleContext<ECMAScriptParser::BlockContext>(0);
}


size_t ECMAScriptParser::CatchProductionContext::getRuleIndex() const {
  return ECMAScriptParser::RuleCatchProduction;
}

antlrcpp::Any ECMAScriptParser::CatchProductionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitCatchProduction(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::CatchProductionContext* ECMAScriptParser::catchProduction() {
  CatchProductionContext *_localctx = _tracker.createInstance<CatchProductionContext>(_ctx, getState());
  enterRule(_localctx, 52, ECMAScriptParser::RuleCatchProduction);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(364);
    match(ECMAScriptParser::Catch);
    setState(365);
    match(ECMAScriptParser::OpenParen);
    setState(366);
    match(ECMAScriptParser::Identifier);
    setState(367);
    match(ECMAScriptParser::CloseParen);
    setState(368);
    block();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- FinallyProductionContext ------------------------------------------------------------------

ECMAScriptParser::FinallyProductionContext::FinallyProductionContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::FinallyProductionContext::Finally() {
  return getToken(ECMAScriptParser::Finally, 0);
}

ECMAScriptParser::BlockContext* ECMAScriptParser::FinallyProductionContext::block() {
  return getRuleContext<ECMAScriptParser::BlockContext>(0);
}


size_t ECMAScriptParser::FinallyProductionContext::getRuleIndex() const {
  return ECMAScriptParser::RuleFinallyProduction;
}

antlrcpp::Any ECMAScriptParser::FinallyProductionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitFinallyProduction(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::FinallyProductionContext* ECMAScriptParser::finallyProduction() {
  FinallyProductionContext *_localctx = _tracker.createInstance<FinallyProductionContext>(_ctx, getState());
  enterRule(_localctx, 54, ECMAScriptParser::RuleFinallyProduction);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(370);
    match(ECMAScriptParser::Finally);
    setState(371);
    block();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- DebuggerStatementContext ------------------------------------------------------------------

ECMAScriptParser::DebuggerStatementContext::DebuggerStatementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::DebuggerStatementContext::Debugger() {
  return getToken(ECMAScriptParser::Debugger, 0);
}

ECMAScriptParser::EosContext* ECMAScriptParser::DebuggerStatementContext::eos() {
  return getRuleContext<ECMAScriptParser::EosContext>(0);
}


size_t ECMAScriptParser::DebuggerStatementContext::getRuleIndex() const {
  return ECMAScriptParser::RuleDebuggerStatement;
}

antlrcpp::Any ECMAScriptParser::DebuggerStatementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitDebuggerStatement(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::DebuggerStatementContext* ECMAScriptParser::debuggerStatement() {
  DebuggerStatementContext *_localctx = _tracker.createInstance<DebuggerStatementContext>(_ctx, getState());
  enterRule(_localctx, 56, ECMAScriptParser::RuleDebuggerStatement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(373);
    match(ECMAScriptParser::Debugger);
    setState(374);
    eos();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- FunctionDeclarationContext ------------------------------------------------------------------

ECMAScriptParser::FunctionDeclarationContext::FunctionDeclarationContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::FunctionDeclarationContext::Function() {
  return getToken(ECMAScriptParser::Function, 0);
}

tree::TerminalNode* ECMAScriptParser::FunctionDeclarationContext::Identifier() {
  return getToken(ECMAScriptParser::Identifier, 0);
}

ECMAScriptParser::FunctionBodyContext* ECMAScriptParser::FunctionDeclarationContext::functionBody() {
  return getRuleContext<ECMAScriptParser::FunctionBodyContext>(0);
}

ECMAScriptParser::FormalParameterListContext* ECMAScriptParser::FunctionDeclarationContext::formalParameterList() {
  return getRuleContext<ECMAScriptParser::FormalParameterListContext>(0);
}


size_t ECMAScriptParser::FunctionDeclarationContext::getRuleIndex() const {
  return ECMAScriptParser::RuleFunctionDeclaration;
}

antlrcpp::Any ECMAScriptParser::FunctionDeclarationContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitFunctionDeclaration(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::FunctionDeclarationContext* ECMAScriptParser::functionDeclaration() {
  FunctionDeclarationContext *_localctx = _tracker.createInstance<FunctionDeclarationContext>(_ctx, getState());
  enterRule(_localctx, 58, ECMAScriptParser::RuleFunctionDeclaration);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(376);
    match(ECMAScriptParser::Function);
    setState(377);
    match(ECMAScriptParser::Identifier);
    setState(378);
    match(ECMAScriptParser::OpenParen);
    setState(380);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == ECMAScriptParser::Identifier) {
      setState(379);
      formalParameterList();
    }
    setState(382);
    match(ECMAScriptParser::CloseParen);
    setState(383);
    match(ECMAScriptParser::OpenBrace);
    setState(384);
    functionBody();
    setState(385);
    match(ECMAScriptParser::CloseBrace);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- FormalParameterListContext ------------------------------------------------------------------

ECMAScriptParser::FormalParameterListContext::FormalParameterListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<tree::TerminalNode *> ECMAScriptParser::FormalParameterListContext::Identifier() {
  return getTokens(ECMAScriptParser::Identifier);
}

tree::TerminalNode* ECMAScriptParser::FormalParameterListContext::Identifier(size_t i) {
  return getToken(ECMAScriptParser::Identifier, i);
}


size_t ECMAScriptParser::FormalParameterListContext::getRuleIndex() const {
  return ECMAScriptParser::RuleFormalParameterList;
}

antlrcpp::Any ECMAScriptParser::FormalParameterListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitFormalParameterList(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::FormalParameterListContext* ECMAScriptParser::formalParameterList() {
  FormalParameterListContext *_localctx = _tracker.createInstance<FormalParameterListContext>(_ctx, getState());
  enterRule(_localctx, 60, ECMAScriptParser::RuleFormalParameterList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(387);
    match(ECMAScriptParser::Identifier);
    setState(392);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == ECMAScriptParser::Comma) {
      setState(388);
      match(ECMAScriptParser::Comma);
      setState(389);
      match(ECMAScriptParser::Identifier);
      setState(394);
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

//----------------- FunctionBodyContext ------------------------------------------------------------------

ECMAScriptParser::FunctionBodyContext::FunctionBodyContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

ECMAScriptParser::SourceElementsContext* ECMAScriptParser::FunctionBodyContext::sourceElements() {
  return getRuleContext<ECMAScriptParser::SourceElementsContext>(0);
}


size_t ECMAScriptParser::FunctionBodyContext::getRuleIndex() const {
  return ECMAScriptParser::RuleFunctionBody;
}

antlrcpp::Any ECMAScriptParser::FunctionBodyContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitFunctionBody(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::FunctionBodyContext* ECMAScriptParser::functionBody() {
  FunctionBodyContext *_localctx = _tracker.createInstance<FunctionBodyContext>(_ctx, getState());
  enterRule(_localctx, 62, ECMAScriptParser::RuleFunctionBody);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(396);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 30, _ctx)) {
    case 1: {
      setState(395);
      sourceElements();
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

//----------------- ArrayLiteralContext ------------------------------------------------------------------

ECMAScriptParser::ArrayLiteralContext::ArrayLiteralContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

ECMAScriptParser::ElementListContext* ECMAScriptParser::ArrayLiteralContext::elementList() {
  return getRuleContext<ECMAScriptParser::ElementListContext>(0);
}

ECMAScriptParser::ElisionContext* ECMAScriptParser::ArrayLiteralContext::elision() {
  return getRuleContext<ECMAScriptParser::ElisionContext>(0);
}


size_t ECMAScriptParser::ArrayLiteralContext::getRuleIndex() const {
  return ECMAScriptParser::RuleArrayLiteral;
}

antlrcpp::Any ECMAScriptParser::ArrayLiteralContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitArrayLiteral(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::ArrayLiteralContext* ECMAScriptParser::arrayLiteral() {
  ArrayLiteralContext *_localctx = _tracker.createInstance<ArrayLiteralContext>(_ctx, getState());
  enterRule(_localctx, 64, ECMAScriptParser::RuleArrayLiteral);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(398);
    match(ECMAScriptParser::OpenBracket);
    setState(400);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 31, _ctx)) {
    case 1: {
      setState(399);
      elementList();
      break;
    }

    }
    setState(403);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 32, _ctx)) {
    case 1: {
      setState(402);
      match(ECMAScriptParser::Comma);
      break;
    }

    }
    setState(406);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == ECMAScriptParser::Comma) {
      setState(405);
      elision();
    }
    setState(408);
    match(ECMAScriptParser::CloseBracket);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ElementListContext ------------------------------------------------------------------

ECMAScriptParser::ElementListContext::ElementListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::ElementListContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::ElementListContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

std::vector<ECMAScriptParser::ElisionContext *> ECMAScriptParser::ElementListContext::elision() {
  return getRuleContexts<ECMAScriptParser::ElisionContext>();
}

ECMAScriptParser::ElisionContext* ECMAScriptParser::ElementListContext::elision(size_t i) {
  return getRuleContext<ECMAScriptParser::ElisionContext>(i);
}


size_t ECMAScriptParser::ElementListContext::getRuleIndex() const {
  return ECMAScriptParser::RuleElementList;
}

antlrcpp::Any ECMAScriptParser::ElementListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitElementList(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::ElementListContext* ECMAScriptParser::elementList() {
  ElementListContext *_localctx = _tracker.createInstance<ElementListContext>(_ctx, getState());
  enterRule(_localctx, 66, ECMAScriptParser::RuleElementList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(411);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == ECMAScriptParser::Comma) {
      setState(410);
      elision();
    }
    setState(413);
    singleExpression(0);
    setState(421);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 36, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(414);
        match(ECMAScriptParser::Comma);
        setState(416);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == ECMAScriptParser::Comma) {
          setState(415);
          elision();
        }
        setState(418);
        singleExpression(0); 
      }
      setState(423);
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

//----------------- ElisionContext ------------------------------------------------------------------

ECMAScriptParser::ElisionContext::ElisionContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}


size_t ECMAScriptParser::ElisionContext::getRuleIndex() const {
  return ECMAScriptParser::RuleElision;
}

antlrcpp::Any ECMAScriptParser::ElisionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitElision(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::ElisionContext* ECMAScriptParser::elision() {
  ElisionContext *_localctx = _tracker.createInstance<ElisionContext>(_ctx, getState());
  enterRule(_localctx, 68, ECMAScriptParser::RuleElision);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(425); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(424);
      match(ECMAScriptParser::Comma);
      setState(427); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == ECMAScriptParser::Comma);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ObjectLiteralContext ------------------------------------------------------------------

ECMAScriptParser::ObjectLiteralContext::ObjectLiteralContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

ECMAScriptParser::PropertyNameAndValueListContext* ECMAScriptParser::ObjectLiteralContext::propertyNameAndValueList() {
  return getRuleContext<ECMAScriptParser::PropertyNameAndValueListContext>(0);
}


size_t ECMAScriptParser::ObjectLiteralContext::getRuleIndex() const {
  return ECMAScriptParser::RuleObjectLiteral;
}

antlrcpp::Any ECMAScriptParser::ObjectLiteralContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitObjectLiteral(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::ObjectLiteralContext* ECMAScriptParser::objectLiteral() {
  ObjectLiteralContext *_localctx = _tracker.createInstance<ObjectLiteralContext>(_ctx, getState());
  enterRule(_localctx, 70, ECMAScriptParser::RuleObjectLiteral);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(429);
    match(ECMAScriptParser::OpenBrace);
    setState(431);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 38, _ctx)) {
    case 1: {
      setState(430);
      propertyNameAndValueList();
      break;
    }

    }
    setState(434);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == ECMAScriptParser::Comma) {
      setState(433);
      match(ECMAScriptParser::Comma);
    }
    setState(436);
    match(ECMAScriptParser::CloseBrace);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- PropertyNameAndValueListContext ------------------------------------------------------------------

ECMAScriptParser::PropertyNameAndValueListContext::PropertyNameAndValueListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<ECMAScriptParser::PropertyAssignmentContext *> ECMAScriptParser::PropertyNameAndValueListContext::propertyAssignment() {
  return getRuleContexts<ECMAScriptParser::PropertyAssignmentContext>();
}

ECMAScriptParser::PropertyAssignmentContext* ECMAScriptParser::PropertyNameAndValueListContext::propertyAssignment(size_t i) {
  return getRuleContext<ECMAScriptParser::PropertyAssignmentContext>(i);
}


size_t ECMAScriptParser::PropertyNameAndValueListContext::getRuleIndex() const {
  return ECMAScriptParser::RulePropertyNameAndValueList;
}

antlrcpp::Any ECMAScriptParser::PropertyNameAndValueListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitPropertyNameAndValueList(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::PropertyNameAndValueListContext* ECMAScriptParser::propertyNameAndValueList() {
  PropertyNameAndValueListContext *_localctx = _tracker.createInstance<PropertyNameAndValueListContext>(_ctx, getState());
  enterRule(_localctx, 72, ECMAScriptParser::RulePropertyNameAndValueList);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(438);
    propertyAssignment();
    setState(443);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 40, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(439);
        match(ECMAScriptParser::Comma);
        setState(440);
        propertyAssignment(); 
      }
      setState(445);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 40, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- PropertyAssignmentContext ------------------------------------------------------------------

ECMAScriptParser::PropertyAssignmentContext::PropertyAssignmentContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}


size_t ECMAScriptParser::PropertyAssignmentContext::getRuleIndex() const {
  return ECMAScriptParser::RulePropertyAssignment;
}

void ECMAScriptParser::PropertyAssignmentContext::copyFrom(PropertyAssignmentContext *ctx) {
  ParserRuleContext::copyFrom(ctx);
}

//----------------- PropertyExpressionAssignmentContext ------------------------------------------------------------------

ECMAScriptParser::PropertyNameContext* ECMAScriptParser::PropertyExpressionAssignmentContext::propertyName() {
  return getRuleContext<ECMAScriptParser::PropertyNameContext>(0);
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::PropertyExpressionAssignmentContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::PropertyExpressionAssignmentContext::PropertyExpressionAssignmentContext(PropertyAssignmentContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::PropertyExpressionAssignmentContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitPropertyExpressionAssignment(this);
  else
    return visitor->visitChildren(this);
}
//----------------- PropertySetterContext ------------------------------------------------------------------

ECMAScriptParser::SetterContext* ECMAScriptParser::PropertySetterContext::setter() {
  return getRuleContext<ECMAScriptParser::SetterContext>(0);
}

ECMAScriptParser::PropertySetParameterListContext* ECMAScriptParser::PropertySetterContext::propertySetParameterList() {
  return getRuleContext<ECMAScriptParser::PropertySetParameterListContext>(0);
}

ECMAScriptParser::FunctionBodyContext* ECMAScriptParser::PropertySetterContext::functionBody() {
  return getRuleContext<ECMAScriptParser::FunctionBodyContext>(0);
}

ECMAScriptParser::PropertySetterContext::PropertySetterContext(PropertyAssignmentContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::PropertySetterContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitPropertySetter(this);
  else
    return visitor->visitChildren(this);
}
//----------------- PropertyGetterContext ------------------------------------------------------------------

ECMAScriptParser::GetterContext* ECMAScriptParser::PropertyGetterContext::getter() {
  return getRuleContext<ECMAScriptParser::GetterContext>(0);
}

ECMAScriptParser::FunctionBodyContext* ECMAScriptParser::PropertyGetterContext::functionBody() {
  return getRuleContext<ECMAScriptParser::FunctionBodyContext>(0);
}

ECMAScriptParser::PropertyGetterContext::PropertyGetterContext(PropertyAssignmentContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::PropertyGetterContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitPropertyGetter(this);
  else
    return visitor->visitChildren(this);
}
ECMAScriptParser::PropertyAssignmentContext* ECMAScriptParser::propertyAssignment() {
  PropertyAssignmentContext *_localctx = _tracker.createInstance<PropertyAssignmentContext>(_ctx, getState());
  enterRule(_localctx, 74, ECMAScriptParser::RulePropertyAssignment);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(465);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 41, _ctx)) {
    case 1: {
      _localctx = dynamic_cast<PropertyAssignmentContext *>(_tracker.createInstance<ECMAScriptParser::PropertyExpressionAssignmentContext>(_localctx));
      enterOuterAlt(_localctx, 1);
      setState(446);
      propertyName();
      setState(447);
      match(ECMAScriptParser::Colon);
      setState(448);
      singleExpression(0);
      break;
    }

    case 2: {
      _localctx = dynamic_cast<PropertyAssignmentContext *>(_tracker.createInstance<ECMAScriptParser::PropertyGetterContext>(_localctx));
      enterOuterAlt(_localctx, 2);
      setState(450);
      getter();
      setState(451);
      match(ECMAScriptParser::OpenParen);
      setState(452);
      match(ECMAScriptParser::CloseParen);
      setState(453);
      match(ECMAScriptParser::OpenBrace);
      setState(454);
      functionBody();
      setState(455);
      match(ECMAScriptParser::CloseBrace);
      break;
    }

    case 3: {
      _localctx = dynamic_cast<PropertyAssignmentContext *>(_tracker.createInstance<ECMAScriptParser::PropertySetterContext>(_localctx));
      enterOuterAlt(_localctx, 3);
      setState(457);
      setter();
      setState(458);
      match(ECMAScriptParser::OpenParen);
      setState(459);
      propertySetParameterList();
      setState(460);
      match(ECMAScriptParser::CloseParen);
      setState(461);
      match(ECMAScriptParser::OpenBrace);
      setState(462);
      functionBody();
      setState(463);
      match(ECMAScriptParser::CloseBrace);
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

//----------------- PropertyNameContext ------------------------------------------------------------------

ECMAScriptParser::PropertyNameContext::PropertyNameContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

ECMAScriptParser::IdentifierNameContext* ECMAScriptParser::PropertyNameContext::identifierName() {
  return getRuleContext<ECMAScriptParser::IdentifierNameContext>(0);
}

tree::TerminalNode* ECMAScriptParser::PropertyNameContext::StringLiteral() {
  return getToken(ECMAScriptParser::StringLiteral, 0);
}

ECMAScriptParser::NumericLiteralContext* ECMAScriptParser::PropertyNameContext::numericLiteral() {
  return getRuleContext<ECMAScriptParser::NumericLiteralContext>(0);
}


size_t ECMAScriptParser::PropertyNameContext::getRuleIndex() const {
  return ECMAScriptParser::RulePropertyName;
}

antlrcpp::Any ECMAScriptParser::PropertyNameContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitPropertyName(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::PropertyNameContext* ECMAScriptParser::propertyName() {
  PropertyNameContext *_localctx = _tracker.createInstance<PropertyNameContext>(_ctx, getState());
  enterRule(_localctx, 76, ECMAScriptParser::RulePropertyName);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(470);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case ECMAScriptParser::NullLiteral:
      case ECMAScriptParser::BooleanLiteral:
      case ECMAScriptParser::Break:
      case ECMAScriptParser::Do:
      case ECMAScriptParser::Instanceof:
      case ECMAScriptParser::Typeof:
      case ECMAScriptParser::Case:
      case ECMAScriptParser::Else:
      case ECMAScriptParser::New:
      case ECMAScriptParser::Var:
      case ECMAScriptParser::Let:
      case ECMAScriptParser::Catch:
      case ECMAScriptParser::Finally:
      case ECMAScriptParser::Return:
      case ECMAScriptParser::Void:
      case ECMAScriptParser::Continue:
      case ECMAScriptParser::For:
      case ECMAScriptParser::Switch:
      case ECMAScriptParser::While:
      case ECMAScriptParser::Debugger:
      case ECMAScriptParser::Function:
      case ECMAScriptParser::This:
      case ECMAScriptParser::With:
      case ECMAScriptParser::Default:
      case ECMAScriptParser::If:
      case ECMAScriptParser::Throw:
      case ECMAScriptParser::Delete:
      case ECMAScriptParser::In:
      case ECMAScriptParser::Try:
      case ECMAScriptParser::Class:
      case ECMAScriptParser::Enum:
      case ECMAScriptParser::Extends:
      case ECMAScriptParser::Super:
      case ECMAScriptParser::Const:
      case ECMAScriptParser::Export:
      case ECMAScriptParser::Import:
      case ECMAScriptParser::Implements:
      case ECMAScriptParser::Private:
      case ECMAScriptParser::Public:
      case ECMAScriptParser::Interface:
      case ECMAScriptParser::Package:
      case ECMAScriptParser::Protected:
      case ECMAScriptParser::Static:
      case ECMAScriptParser::Yield:
      case ECMAScriptParser::Identifier: {
        enterOuterAlt(_localctx, 1);
        setState(467);
        identifierName();
        break;
      }

      case ECMAScriptParser::StringLiteral: {
        enterOuterAlt(_localctx, 2);
        setState(468);
        match(ECMAScriptParser::StringLiteral);
        break;
      }

      case ECMAScriptParser::DecimalLiteral:
      case ECMAScriptParser::HexIntegerLiteral:
      case ECMAScriptParser::OctalIntegerLiteral: {
        enterOuterAlt(_localctx, 3);
        setState(469);
        numericLiteral();
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

//----------------- PropertySetParameterListContext ------------------------------------------------------------------

ECMAScriptParser::PropertySetParameterListContext::PropertySetParameterListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::PropertySetParameterListContext::Identifier() {
  return getToken(ECMAScriptParser::Identifier, 0);
}


size_t ECMAScriptParser::PropertySetParameterListContext::getRuleIndex() const {
  return ECMAScriptParser::RulePropertySetParameterList;
}

antlrcpp::Any ECMAScriptParser::PropertySetParameterListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitPropertySetParameterList(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::PropertySetParameterListContext* ECMAScriptParser::propertySetParameterList() {
  PropertySetParameterListContext *_localctx = _tracker.createInstance<PropertySetParameterListContext>(_ctx, getState());
  enterRule(_localctx, 78, ECMAScriptParser::RulePropertySetParameterList);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(472);
    match(ECMAScriptParser::Identifier);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ArgumentsContext ------------------------------------------------------------------

ECMAScriptParser::ArgumentsContext::ArgumentsContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

ECMAScriptParser::ArgumentListContext* ECMAScriptParser::ArgumentsContext::argumentList() {
  return getRuleContext<ECMAScriptParser::ArgumentListContext>(0);
}


size_t ECMAScriptParser::ArgumentsContext::getRuleIndex() const {
  return ECMAScriptParser::RuleArguments;
}

antlrcpp::Any ECMAScriptParser::ArgumentsContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitArguments(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::ArgumentsContext* ECMAScriptParser::arguments() {
  ArgumentsContext *_localctx = _tracker.createInstance<ArgumentsContext>(_ctx, getState());
  enterRule(_localctx, 80, ECMAScriptParser::RuleArguments);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(474);
    match(ECMAScriptParser::OpenParen);
    setState(476);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << ECMAScriptParser::RegularExpressionLiteral)
      | (1ULL << ECMAScriptParser::OpenBracket)
      | (1ULL << ECMAScriptParser::OpenParen)
      | (1ULL << ECMAScriptParser::OpenBrace)
      | (1ULL << ECMAScriptParser::PlusPlus)
      | (1ULL << ECMAScriptParser::MinusMinus)
      | (1ULL << ECMAScriptParser::Plus)
      | (1ULL << ECMAScriptParser::Minus)
      | (1ULL << ECMAScriptParser::BitNot)
      | (1ULL << ECMAScriptParser::Not)
      | (1ULL << ECMAScriptParser::NullLiteral)
      | (1ULL << ECMAScriptParser::BooleanLiteral)
      | (1ULL << ECMAScriptParser::DecimalLiteral)
      | (1ULL << ECMAScriptParser::HexIntegerLiteral)
      | (1ULL << ECMAScriptParser::OctalIntegerLiteral)
      | (1ULL << ECMAScriptParser::Typeof)
      | (1ULL << ECMAScriptParser::New))) != 0) || ((((_la - 68) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 68)) & ((1ULL << (ECMAScriptParser::Void - 68))
      | (1ULL << (ECMAScriptParser::Function - 68))
      | (1ULL << (ECMAScriptParser::This - 68))
      | (1ULL << (ECMAScriptParser::Delete - 68))
      | (1ULL << (ECMAScriptParser::Identifier - 68))
      | (1ULL << (ECMAScriptParser::StringLiteral - 68)))) != 0)) {
      setState(475);
      argumentList();
    }
    setState(478);
    match(ECMAScriptParser::CloseParen);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ArgumentListContext ------------------------------------------------------------------

ECMAScriptParser::ArgumentListContext::ArgumentListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::ArgumentListContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::ArgumentListContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}


size_t ECMAScriptParser::ArgumentListContext::getRuleIndex() const {
  return ECMAScriptParser::RuleArgumentList;
}

antlrcpp::Any ECMAScriptParser::ArgumentListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitArgumentList(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::ArgumentListContext* ECMAScriptParser::argumentList() {
  ArgumentListContext *_localctx = _tracker.createInstance<ArgumentListContext>(_ctx, getState());
  enterRule(_localctx, 82, ECMAScriptParser::RuleArgumentList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(480);
    singleExpression(0);
    setState(485);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == ECMAScriptParser::Comma) {
      setState(481);
      match(ECMAScriptParser::Comma);
      setState(482);
      singleExpression(0);
      setState(487);
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

//----------------- ExpressionSequenceContext ------------------------------------------------------------------

ECMAScriptParser::ExpressionSequenceContext::ExpressionSequenceContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::ExpressionSequenceContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::ExpressionSequenceContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}


size_t ECMAScriptParser::ExpressionSequenceContext::getRuleIndex() const {
  return ECMAScriptParser::RuleExpressionSequence;
}

antlrcpp::Any ECMAScriptParser::ExpressionSequenceContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitExpressionSequence(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::expressionSequence() {
  ExpressionSequenceContext *_localctx = _tracker.createInstance<ExpressionSequenceContext>(_ctx, getState());
  enterRule(_localctx, 84, ECMAScriptParser::RuleExpressionSequence);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(488);
    singleExpression(0);
    setState(493);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 45, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(489);
        match(ECMAScriptParser::Comma);
        setState(490);
        singleExpression(0); 
      }
      setState(495);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 45, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SingleExpressionContext ------------------------------------------------------------------

ECMAScriptParser::SingleExpressionContext::SingleExpressionContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}


size_t ECMAScriptParser::SingleExpressionContext::getRuleIndex() const {
  return ECMAScriptParser::RuleSingleExpression;
}

void ECMAScriptParser::SingleExpressionContext::copyFrom(SingleExpressionContext *ctx) {
  ParserRuleContext::copyFrom(ctx);
}

//----------------- TernaryExpressionContext ------------------------------------------------------------------

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::TernaryExpressionContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::TernaryExpressionContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

ECMAScriptParser::TernaryExpressionContext::TernaryExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::TernaryExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitTernaryExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- LogicalAndExpressionContext ------------------------------------------------------------------

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::LogicalAndExpressionContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::LogicalAndExpressionContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

ECMAScriptParser::LogicalAndExpressionContext::LogicalAndExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::LogicalAndExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitLogicalAndExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- PreIncrementExpressionContext ------------------------------------------------------------------

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::PreIncrementExpressionContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::PreIncrementExpressionContext::PreIncrementExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::PreIncrementExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitPreIncrementExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ObjectLiteralExpressionContext ------------------------------------------------------------------

ECMAScriptParser::ObjectLiteralContext* ECMAScriptParser::ObjectLiteralExpressionContext::objectLiteral() {
  return getRuleContext<ECMAScriptParser::ObjectLiteralContext>(0);
}

ECMAScriptParser::ObjectLiteralExpressionContext::ObjectLiteralExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::ObjectLiteralExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitObjectLiteralExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- InExpressionContext ------------------------------------------------------------------

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::InExpressionContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::InExpressionContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

tree::TerminalNode* ECMAScriptParser::InExpressionContext::In() {
  return getToken(ECMAScriptParser::In, 0);
}

ECMAScriptParser::InExpressionContext::InExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::InExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitInExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- LogicalOrExpressionContext ------------------------------------------------------------------

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::LogicalOrExpressionContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::LogicalOrExpressionContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

ECMAScriptParser::LogicalOrExpressionContext::LogicalOrExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::LogicalOrExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitLogicalOrExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- NotExpressionContext ------------------------------------------------------------------

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::NotExpressionContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::NotExpressionContext::NotExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::NotExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitNotExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- PreDecreaseExpressionContext ------------------------------------------------------------------

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::PreDecreaseExpressionContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::PreDecreaseExpressionContext::PreDecreaseExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::PreDecreaseExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitPreDecreaseExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ArgumentsExpressionContext ------------------------------------------------------------------

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::ArgumentsExpressionContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::ArgumentsContext* ECMAScriptParser::ArgumentsExpressionContext::arguments() {
  return getRuleContext<ECMAScriptParser::ArgumentsContext>(0);
}

ECMAScriptParser::ArgumentsExpressionContext::ArgumentsExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::ArgumentsExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitArgumentsExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ThisExpressionContext ------------------------------------------------------------------

tree::TerminalNode* ECMAScriptParser::ThisExpressionContext::This() {
  return getToken(ECMAScriptParser::This, 0);
}

ECMAScriptParser::ThisExpressionContext::ThisExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::ThisExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitThisExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- FunctionExpressionContext ------------------------------------------------------------------

tree::TerminalNode* ECMAScriptParser::FunctionExpressionContext::Function() {
  return getToken(ECMAScriptParser::Function, 0);
}

ECMAScriptParser::FunctionBodyContext* ECMAScriptParser::FunctionExpressionContext::functionBody() {
  return getRuleContext<ECMAScriptParser::FunctionBodyContext>(0);
}

tree::TerminalNode* ECMAScriptParser::FunctionExpressionContext::Identifier() {
  return getToken(ECMAScriptParser::Identifier, 0);
}

ECMAScriptParser::FormalParameterListContext* ECMAScriptParser::FunctionExpressionContext::formalParameterList() {
  return getRuleContext<ECMAScriptParser::FormalParameterListContext>(0);
}

ECMAScriptParser::FunctionExpressionContext::FunctionExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::FunctionExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitFunctionExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- UnaryMinusExpressionContext ------------------------------------------------------------------

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::UnaryMinusExpressionContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::UnaryMinusExpressionContext::UnaryMinusExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::UnaryMinusExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitUnaryMinusExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- AssignmentExpressionContext ------------------------------------------------------------------

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::AssignmentExpressionContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::AssignmentExpressionContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

ECMAScriptParser::AssignmentExpressionContext::AssignmentExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::AssignmentExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitAssignmentExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- PostDecreaseExpressionContext ------------------------------------------------------------------

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::PostDecreaseExpressionContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::PostDecreaseExpressionContext::PostDecreaseExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::PostDecreaseExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitPostDecreaseExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- TypeofExpressionContext ------------------------------------------------------------------

tree::TerminalNode* ECMAScriptParser::TypeofExpressionContext::Typeof() {
  return getToken(ECMAScriptParser::Typeof, 0);
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::TypeofExpressionContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::TypeofExpressionContext::TypeofExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::TypeofExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitTypeofExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- InstanceofExpressionContext ------------------------------------------------------------------

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::InstanceofExpressionContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::InstanceofExpressionContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

tree::TerminalNode* ECMAScriptParser::InstanceofExpressionContext::Instanceof() {
  return getToken(ECMAScriptParser::Instanceof, 0);
}

ECMAScriptParser::InstanceofExpressionContext::InstanceofExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::InstanceofExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitInstanceofExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- UnaryPlusExpressionContext ------------------------------------------------------------------

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::UnaryPlusExpressionContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::UnaryPlusExpressionContext::UnaryPlusExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::UnaryPlusExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitUnaryPlusExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- DeleteExpressionContext ------------------------------------------------------------------

tree::TerminalNode* ECMAScriptParser::DeleteExpressionContext::Delete() {
  return getToken(ECMAScriptParser::Delete, 0);
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::DeleteExpressionContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::DeleteExpressionContext::DeleteExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::DeleteExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitDeleteExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- EqualityExpressionContext ------------------------------------------------------------------

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::EqualityExpressionContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::EqualityExpressionContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

ECMAScriptParser::EqualityExpressionContext::EqualityExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::EqualityExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitEqualityExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- BitXOrExpressionContext ------------------------------------------------------------------

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::BitXOrExpressionContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::BitXOrExpressionContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

ECMAScriptParser::BitXOrExpressionContext::BitXOrExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::BitXOrExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitBitXOrExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- MultiplicativeExpressionContext ------------------------------------------------------------------

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::MultiplicativeExpressionContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::MultiplicativeExpressionContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

ECMAScriptParser::MultiplicativeExpressionContext::MultiplicativeExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::MultiplicativeExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitMultiplicativeExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- BitShiftExpressionContext ------------------------------------------------------------------

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::BitShiftExpressionContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::BitShiftExpressionContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

ECMAScriptParser::BitShiftExpressionContext::BitShiftExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::BitShiftExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitBitShiftExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ParenthesizedExpressionContext ------------------------------------------------------------------

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::ParenthesizedExpressionContext::expressionSequence() {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(0);
}

ECMAScriptParser::ParenthesizedExpressionContext::ParenthesizedExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::ParenthesizedExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitParenthesizedExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- AdditiveExpressionContext ------------------------------------------------------------------

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::AdditiveExpressionContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::AdditiveExpressionContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

ECMAScriptParser::AdditiveExpressionContext::AdditiveExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::AdditiveExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitAdditiveExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- RelationalExpressionContext ------------------------------------------------------------------

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::RelationalExpressionContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::RelationalExpressionContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

ECMAScriptParser::RelationalExpressionContext::RelationalExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::RelationalExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitRelationalExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- PostIncrementExpressionContext ------------------------------------------------------------------

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::PostIncrementExpressionContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::PostIncrementExpressionContext::PostIncrementExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::PostIncrementExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitPostIncrementExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- BitNotExpressionContext ------------------------------------------------------------------

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::BitNotExpressionContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::BitNotExpressionContext::BitNotExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::BitNotExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitBitNotExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- NewExpressionContext ------------------------------------------------------------------

tree::TerminalNode* ECMAScriptParser::NewExpressionContext::New() {
  return getToken(ECMAScriptParser::New, 0);
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::NewExpressionContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::ArgumentsContext* ECMAScriptParser::NewExpressionContext::arguments() {
  return getRuleContext<ECMAScriptParser::ArgumentsContext>(0);
}

ECMAScriptParser::NewExpressionContext::NewExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::NewExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitNewExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- LiteralExpressionContext ------------------------------------------------------------------

ECMAScriptParser::LiteralContext* ECMAScriptParser::LiteralExpressionContext::literal() {
  return getRuleContext<ECMAScriptParser::LiteralContext>(0);
}

ECMAScriptParser::LiteralExpressionContext::LiteralExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::LiteralExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitLiteralExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- ArrayLiteralExpressionContext ------------------------------------------------------------------

ECMAScriptParser::ArrayLiteralContext* ECMAScriptParser::ArrayLiteralExpressionContext::arrayLiteral() {
  return getRuleContext<ECMAScriptParser::ArrayLiteralContext>(0);
}

ECMAScriptParser::ArrayLiteralExpressionContext::ArrayLiteralExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::ArrayLiteralExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitArrayLiteralExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- MemberDotExpressionContext ------------------------------------------------------------------

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::MemberDotExpressionContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::IdentifierNameContext* ECMAScriptParser::MemberDotExpressionContext::identifierName() {
  return getRuleContext<ECMAScriptParser::IdentifierNameContext>(0);
}

ECMAScriptParser::MemberDotExpressionContext::MemberDotExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::MemberDotExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitMemberDotExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- MemberIndexExpressionContext ------------------------------------------------------------------

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::MemberIndexExpressionContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::ExpressionSequenceContext* ECMAScriptParser::MemberIndexExpressionContext::expressionSequence() {
  return getRuleContext<ECMAScriptParser::ExpressionSequenceContext>(0);
}

ECMAScriptParser::MemberIndexExpressionContext::MemberIndexExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::MemberIndexExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitMemberIndexExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- IdentifierExpressionContext ------------------------------------------------------------------

tree::TerminalNode* ECMAScriptParser::IdentifierExpressionContext::Identifier() {
  return getToken(ECMAScriptParser::Identifier, 0);
}

ECMAScriptParser::IdentifierExpressionContext::IdentifierExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::IdentifierExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitIdentifierExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- BitAndExpressionContext ------------------------------------------------------------------

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::BitAndExpressionContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::BitAndExpressionContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

ECMAScriptParser::BitAndExpressionContext::BitAndExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::BitAndExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitBitAndExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- BitOrExpressionContext ------------------------------------------------------------------

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::BitOrExpressionContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::BitOrExpressionContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

ECMAScriptParser::BitOrExpressionContext::BitOrExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::BitOrExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitBitOrExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- AssignmentOperatorExpressionContext ------------------------------------------------------------------

std::vector<ECMAScriptParser::SingleExpressionContext *> ECMAScriptParser::AssignmentOperatorExpressionContext::singleExpression() {
  return getRuleContexts<ECMAScriptParser::SingleExpressionContext>();
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::AssignmentOperatorExpressionContext::singleExpression(size_t i) {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(i);
}

ECMAScriptParser::AssignmentOperatorContext* ECMAScriptParser::AssignmentOperatorExpressionContext::assignmentOperator() {
  return getRuleContext<ECMAScriptParser::AssignmentOperatorContext>(0);
}

ECMAScriptParser::AssignmentOperatorExpressionContext::AssignmentOperatorExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::AssignmentOperatorExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitAssignmentOperatorExpression(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VoidExpressionContext ------------------------------------------------------------------

tree::TerminalNode* ECMAScriptParser::VoidExpressionContext::Void() {
  return getToken(ECMAScriptParser::Void, 0);
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::VoidExpressionContext::singleExpression() {
  return getRuleContext<ECMAScriptParser::SingleExpressionContext>(0);
}

ECMAScriptParser::VoidExpressionContext::VoidExpressionContext(SingleExpressionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any ECMAScriptParser::VoidExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitVoidExpression(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::singleExpression() {
   return singleExpression(0);
}

ECMAScriptParser::SingleExpressionContext* ECMAScriptParser::singleExpression(int precedence) {
  ParserRuleContext *parentContext = _ctx;
  size_t parentState = getState();
  ECMAScriptParser::SingleExpressionContext *_localctx = _tracker.createInstance<SingleExpressionContext>(_ctx, parentState);
  ECMAScriptParser::SingleExpressionContext *previousContext = _localctx;
  size_t startState = 86;
  enterRecursionRule(_localctx, 86, ECMAScriptParser::RuleSingleExpression, precedence);

    size_t _la = 0;

  auto onExit = finally([=] {
    unrollRecursionContexts(parentContext);
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(542);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case ECMAScriptParser::Function: {
        _localctx = _tracker.createInstance<FunctionExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;

        setState(497);
        match(ECMAScriptParser::Function);
        setState(499);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == ECMAScriptParser::Identifier) {
          setState(498);
          match(ECMAScriptParser::Identifier);
        }
        setState(501);
        match(ECMAScriptParser::OpenParen);
        setState(503);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == ECMAScriptParser::Identifier) {
          setState(502);
          formalParameterList();
        }
        setState(505);
        match(ECMAScriptParser::CloseParen);
        setState(506);
        match(ECMAScriptParser::OpenBrace);
        setState(507);
        functionBody();
        setState(508);
        match(ECMAScriptParser::CloseBrace);
        break;
      }

      case ECMAScriptParser::New: {
        _localctx = _tracker.createInstance<NewExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(510);
        match(ECMAScriptParser::New);
        setState(511);
        singleExpression(0);
        setState(513);
        _errHandler->sync(this);

        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 48, _ctx)) {
        case 1: {
          setState(512);
          arguments();
          break;
        }

        }
        break;
      }

      case ECMAScriptParser::Delete: {
        _localctx = _tracker.createInstance<DeleteExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(515);
        match(ECMAScriptParser::Delete);
        setState(516);
        singleExpression(30);
        break;
      }

      case ECMAScriptParser::Void: {
        _localctx = _tracker.createInstance<VoidExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(517);
        match(ECMAScriptParser::Void);
        setState(518);
        singleExpression(29);
        break;
      }

      case ECMAScriptParser::Typeof: {
        _localctx = _tracker.createInstance<TypeofExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(519);
        match(ECMAScriptParser::Typeof);
        setState(520);
        singleExpression(28);
        break;
      }

      case ECMAScriptParser::PlusPlus: {
        _localctx = _tracker.createInstance<PreIncrementExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(521);
        match(ECMAScriptParser::PlusPlus);
        setState(522);
        singleExpression(27);
        break;
      }

      case ECMAScriptParser::MinusMinus: {
        _localctx = _tracker.createInstance<PreDecreaseExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(523);
        match(ECMAScriptParser::MinusMinus);
        setState(524);
        singleExpression(26);
        break;
      }

      case ECMAScriptParser::Plus: {
        _localctx = _tracker.createInstance<UnaryPlusExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(525);
        match(ECMAScriptParser::Plus);
        setState(526);
        singleExpression(25);
        break;
      }

      case ECMAScriptParser::Minus: {
        _localctx = _tracker.createInstance<UnaryMinusExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(527);
        match(ECMAScriptParser::Minus);
        setState(528);
        singleExpression(24);
        break;
      }

      case ECMAScriptParser::BitNot: {
        _localctx = _tracker.createInstance<BitNotExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(529);
        match(ECMAScriptParser::BitNot);
        setState(530);
        singleExpression(23);
        break;
      }

      case ECMAScriptParser::Not: {
        _localctx = _tracker.createInstance<NotExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(531);
        match(ECMAScriptParser::Not);
        setState(532);
        singleExpression(22);
        break;
      }

      case ECMAScriptParser::This: {
        _localctx = _tracker.createInstance<ThisExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(533);
        match(ECMAScriptParser::This);
        break;
      }

      case ECMAScriptParser::Identifier: {
        _localctx = _tracker.createInstance<IdentifierExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(534);
        match(ECMAScriptParser::Identifier);
        break;
      }

      case ECMAScriptParser::RegularExpressionLiteral:
      case ECMAScriptParser::NullLiteral:
      case ECMAScriptParser::BooleanLiteral:
      case ECMAScriptParser::DecimalLiteral:
      case ECMAScriptParser::HexIntegerLiteral:
      case ECMAScriptParser::OctalIntegerLiteral:
      case ECMAScriptParser::StringLiteral: {
        _localctx = _tracker.createInstance<LiteralExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(535);
        literal();
        break;
      }

      case ECMAScriptParser::OpenBracket: {
        _localctx = _tracker.createInstance<ArrayLiteralExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(536);
        arrayLiteral();
        break;
      }

      case ECMAScriptParser::OpenBrace: {
        _localctx = _tracker.createInstance<ObjectLiteralExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(537);
        objectLiteral();
        break;
      }

      case ECMAScriptParser::OpenParen: {
        _localctx = _tracker.createInstance<ParenthesizedExpressionContext>(_localctx);
        _ctx = _localctx;
        previousContext = _localctx;
        setState(538);
        match(ECMAScriptParser::OpenParen);
        setState(539);
        expressionSequence();
        setState(540);
        match(ECMAScriptParser::CloseParen);
        break;
      }

    default:
      throw NoViableAltException(this);
    }
    _ctx->stop = _input->LT(-1);
    setState(611);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 51, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        if (!_parseListeners.empty())
          triggerExitRuleEvent();
        previousContext = _localctx;
        setState(609);
        _errHandler->sync(this);
        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 50, _ctx)) {
        case 1: {
          auto newContext = _tracker.createInstance<MultiplicativeExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(544);

          if (!(precpred(_ctx, 21))) throw FailedPredicateException(this, "precpred(_ctx, 21)");
          setState(545);
          _la = _input->LA(1);
          if (!((((_la & ~ 0x3fULL) == 0) &&
            ((1ULL << _la) & ((1ULL << ECMAScriptParser::Multiply)
            | (1ULL << ECMAScriptParser::Divide)
            | (1ULL << ECMAScriptParser::Modulus))) != 0))) {
          _errHandler->recoverInline(this);
          }
          else {
            _errHandler->reportMatch(this);
            consume();
          }
          setState(546);
          singleExpression(22);
          break;
        }

        case 2: {
          auto newContext = _tracker.createInstance<AdditiveExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(547);

          if (!(precpred(_ctx, 20))) throw FailedPredicateException(this, "precpred(_ctx, 20)");
          setState(548);
          _la = _input->LA(1);
          if (!(_la == ECMAScriptParser::Plus

          || _la == ECMAScriptParser::Minus)) {
          _errHandler->recoverInline(this);
          }
          else {
            _errHandler->reportMatch(this);
            consume();
          }
          setState(549);
          singleExpression(21);
          break;
        }

        case 3: {
          auto newContext = _tracker.createInstance<BitShiftExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(550);

          if (!(precpred(_ctx, 19))) throw FailedPredicateException(this, "precpred(_ctx, 19)");
          setState(551);
          _la = _input->LA(1);
          if (!((((_la & ~ 0x3fULL) == 0) &&
            ((1ULL << _la) & ((1ULL << ECMAScriptParser::RightShiftArithmetic)
            | (1ULL << ECMAScriptParser::LeftShiftArithmetic)
            | (1ULL << ECMAScriptParser::RightShiftLogical))) != 0))) {
          _errHandler->recoverInline(this);
          }
          else {
            _errHandler->reportMatch(this);
            consume();
          }
          setState(552);
          singleExpression(20);
          break;
        }

        case 4: {
          auto newContext = _tracker.createInstance<RelationalExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(553);

          if (!(precpred(_ctx, 18))) throw FailedPredicateException(this, "precpred(_ctx, 18)");
          setState(554);
          _la = _input->LA(1);
          if (!((((_la & ~ 0x3fULL) == 0) &&
            ((1ULL << _la) & ((1ULL << ECMAScriptParser::LessThan)
            | (1ULL << ECMAScriptParser::MoreThan)
            | (1ULL << ECMAScriptParser::LessThanEquals)
            | (1ULL << ECMAScriptParser::GreaterThanEquals))) != 0))) {
          _errHandler->recoverInline(this);
          }
          else {
            _errHandler->reportMatch(this);
            consume();
          }
          setState(555);
          singleExpression(19);
          break;
        }

        case 5: {
          auto newContext = _tracker.createInstance<InstanceofExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(556);

          if (!(precpred(_ctx, 17))) throw FailedPredicateException(this, "precpred(_ctx, 17)");
          setState(557);
          match(ECMAScriptParser::Instanceof);
          setState(558);
          singleExpression(18);
          break;
        }

        case 6: {
          auto newContext = _tracker.createInstance<InExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(559);

          if (!(precpred(_ctx, 16))) throw FailedPredicateException(this, "precpred(_ctx, 16)");
          setState(560);
          match(ECMAScriptParser::In);
          setState(561);
          singleExpression(17);
          break;
        }

        case 7: {
          auto newContext = _tracker.createInstance<EqualityExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(562);

          if (!(precpred(_ctx, 15))) throw FailedPredicateException(this, "precpred(_ctx, 15)");
          setState(563);
          _la = _input->LA(1);
          if (!((((_la & ~ 0x3fULL) == 0) &&
            ((1ULL << _la) & ((1ULL << ECMAScriptParser::Equals_)
            | (1ULL << ECMAScriptParser::NotEquals)
            | (1ULL << ECMAScriptParser::IdentityEquals)
            | (1ULL << ECMAScriptParser::IdentityNotEquals))) != 0))) {
          _errHandler->recoverInline(this);
          }
          else {
            _errHandler->reportMatch(this);
            consume();
          }
          setState(564);
          singleExpression(16);
          break;
        }

        case 8: {
          auto newContext = _tracker.createInstance<BitAndExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(565);

          if (!(precpred(_ctx, 14))) throw FailedPredicateException(this, "precpred(_ctx, 14)");
          setState(566);
          match(ECMAScriptParser::BitAnd);
          setState(567);
          singleExpression(15);
          break;
        }

        case 9: {
          auto newContext = _tracker.createInstance<BitXOrExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(568);

          if (!(precpred(_ctx, 13))) throw FailedPredicateException(this, "precpred(_ctx, 13)");
          setState(569);
          match(ECMAScriptParser::BitXOr);
          setState(570);
          singleExpression(14);
          break;
        }

        case 10: {
          auto newContext = _tracker.createInstance<BitOrExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(571);

          if (!(precpred(_ctx, 12))) throw FailedPredicateException(this, "precpred(_ctx, 12)");
          setState(572);
          match(ECMAScriptParser::BitOr);
          setState(573);
          singleExpression(13);
          break;
        }

        case 11: {
          auto newContext = _tracker.createInstance<LogicalAndExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(574);

          if (!(precpred(_ctx, 11))) throw FailedPredicateException(this, "precpred(_ctx, 11)");
          setState(575);
          match(ECMAScriptParser::And);
          setState(576);
          singleExpression(12);
          break;
        }

        case 12: {
          auto newContext = _tracker.createInstance<LogicalOrExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(577);

          if (!(precpred(_ctx, 10))) throw FailedPredicateException(this, "precpred(_ctx, 10)");
          setState(578);
          match(ECMAScriptParser::Or);
          setState(579);
          singleExpression(11);
          break;
        }

        case 13: {
          auto newContext = _tracker.createInstance<TernaryExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(580);

          if (!(precpred(_ctx, 9))) throw FailedPredicateException(this, "precpred(_ctx, 9)");
          setState(581);
          match(ECMAScriptParser::QuestionMark);
          setState(582);
          singleExpression(0);
          setState(583);
          match(ECMAScriptParser::Colon);
          setState(584);
          singleExpression(10);
          break;
        }

        case 14: {
          auto newContext = _tracker.createInstance<AssignmentExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(586);

          if (!(precpred(_ctx, 8))) throw FailedPredicateException(this, "precpred(_ctx, 8)");
          setState(587);
          match(ECMAScriptParser::Assign);
          setState(588);
          singleExpression(9);
          break;
        }

        case 15: {
          auto newContext = _tracker.createInstance<AssignmentOperatorExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(589);

          if (!(precpred(_ctx, 7))) throw FailedPredicateException(this, "precpred(_ctx, 7)");
          setState(590);
          assignmentOperator();
          setState(591);
          singleExpression(8);
          break;
        }

        case 16: {
          auto newContext = _tracker.createInstance<MemberIndexExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(593);

          if (!(precpred(_ctx, 36))) throw FailedPredicateException(this, "precpred(_ctx, 36)");
          setState(594);
          match(ECMAScriptParser::OpenBracket);
          setState(595);
          expressionSequence();
          setState(596);
          match(ECMAScriptParser::CloseBracket);
          break;
        }

        case 17: {
          auto newContext = _tracker.createInstance<MemberDotExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(598);

          if (!(precpred(_ctx, 35))) throw FailedPredicateException(this, "precpred(_ctx, 35)");
          setState(599);
          match(ECMAScriptParser::Dot);
          setState(600);
          identifierName();
          break;
        }

        case 18: {
          auto newContext = _tracker.createInstance<ArgumentsExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(601);

          if (!(precpred(_ctx, 34))) throw FailedPredicateException(this, "precpred(_ctx, 34)");
          setState(602);
          arguments();
          break;
        }

        case 19: {
          auto newContext = _tracker.createInstance<PostIncrementExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(603);

          if (!(precpred(_ctx, 32))) throw FailedPredicateException(this, "precpred(_ctx, 32)");
          setState(604);

          if (!(!here(LineTerminator))) throw FailedPredicateException(this, "!here(LineTerminator)");
          setState(605);
          match(ECMAScriptParser::PlusPlus);
          break;
        }

        case 20: {
          auto newContext = _tracker.createInstance<PostDecreaseExpressionContext>(_tracker.createInstance<SingleExpressionContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleSingleExpression);
          setState(606);

          if (!(precpred(_ctx, 31))) throw FailedPredicateException(this, "precpred(_ctx, 31)");
          setState(607);

          if (!(!here(LineTerminator))) throw FailedPredicateException(this, "!here(LineTerminator)");
          setState(608);
          match(ECMAScriptParser::MinusMinus);
          break;
        }

        } 
      }
      setState(613);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 51, _ctx);
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

ECMAScriptParser::AssignmentOperatorContext::AssignmentOperatorContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}


size_t ECMAScriptParser::AssignmentOperatorContext::getRuleIndex() const {
  return ECMAScriptParser::RuleAssignmentOperator;
}

antlrcpp::Any ECMAScriptParser::AssignmentOperatorContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitAssignmentOperator(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::AssignmentOperatorContext* ECMAScriptParser::assignmentOperator() {
  AssignmentOperatorContext *_localctx = _tracker.createInstance<AssignmentOperatorContext>(_ctx, getState());
  enterRule(_localctx, 88, ECMAScriptParser::RuleAssignmentOperator);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(614);
    _la = _input->LA(1);
    if (!((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << ECMAScriptParser::MultiplyAssign)
      | (1ULL << ECMAScriptParser::DivideAssign)
      | (1ULL << ECMAScriptParser::ModulusAssign)
      | (1ULL << ECMAScriptParser::PlusAssign)
      | (1ULL << ECMAScriptParser::MinusAssign)
      | (1ULL << ECMAScriptParser::LeftShiftArithmeticAssign)
      | (1ULL << ECMAScriptParser::RightShiftArithmeticAssign)
      | (1ULL << ECMAScriptParser::RightShiftLogicalAssign)
      | (1ULL << ECMAScriptParser::BitAndAssign)
      | (1ULL << ECMAScriptParser::BitXorAssign)
      | (1ULL << ECMAScriptParser::BitOrAssign))) != 0))) {
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

//----------------- LiteralContext ------------------------------------------------------------------

ECMAScriptParser::LiteralContext::LiteralContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::LiteralContext::NullLiteral() {
  return getToken(ECMAScriptParser::NullLiteral, 0);
}

tree::TerminalNode* ECMAScriptParser::LiteralContext::BooleanLiteral() {
  return getToken(ECMAScriptParser::BooleanLiteral, 0);
}

tree::TerminalNode* ECMAScriptParser::LiteralContext::StringLiteral() {
  return getToken(ECMAScriptParser::StringLiteral, 0);
}

tree::TerminalNode* ECMAScriptParser::LiteralContext::RegularExpressionLiteral() {
  return getToken(ECMAScriptParser::RegularExpressionLiteral, 0);
}

ECMAScriptParser::NumericLiteralContext* ECMAScriptParser::LiteralContext::numericLiteral() {
  return getRuleContext<ECMAScriptParser::NumericLiteralContext>(0);
}


size_t ECMAScriptParser::LiteralContext::getRuleIndex() const {
  return ECMAScriptParser::RuleLiteral;
}

antlrcpp::Any ECMAScriptParser::LiteralContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitLiteral(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::LiteralContext* ECMAScriptParser::literal() {
  LiteralContext *_localctx = _tracker.createInstance<LiteralContext>(_ctx, getState());
  enterRule(_localctx, 90, ECMAScriptParser::RuleLiteral);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(618);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case ECMAScriptParser::RegularExpressionLiteral:
      case ECMAScriptParser::NullLiteral:
      case ECMAScriptParser::BooleanLiteral:
      case ECMAScriptParser::StringLiteral: {
        enterOuterAlt(_localctx, 1);
        setState(616);
        _la = _input->LA(1);
        if (!((((_la & ~ 0x3fULL) == 0) &&
          ((1ULL << _la) & ((1ULL << ECMAScriptParser::RegularExpressionLiteral)
          | (1ULL << ECMAScriptParser::NullLiteral)
          | (1ULL << ECMAScriptParser::BooleanLiteral))) != 0) || _la == ECMAScriptParser::StringLiteral)) {
        _errHandler->recoverInline(this);
        }
        else {
          _errHandler->reportMatch(this);
          consume();
        }
        break;
      }

      case ECMAScriptParser::DecimalLiteral:
      case ECMAScriptParser::HexIntegerLiteral:
      case ECMAScriptParser::OctalIntegerLiteral: {
        enterOuterAlt(_localctx, 2);
        setState(617);
        numericLiteral();
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

//----------------- NumericLiteralContext ------------------------------------------------------------------

ECMAScriptParser::NumericLiteralContext::NumericLiteralContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::NumericLiteralContext::DecimalLiteral() {
  return getToken(ECMAScriptParser::DecimalLiteral, 0);
}

tree::TerminalNode* ECMAScriptParser::NumericLiteralContext::HexIntegerLiteral() {
  return getToken(ECMAScriptParser::HexIntegerLiteral, 0);
}

tree::TerminalNode* ECMAScriptParser::NumericLiteralContext::OctalIntegerLiteral() {
  return getToken(ECMAScriptParser::OctalIntegerLiteral, 0);
}


size_t ECMAScriptParser::NumericLiteralContext::getRuleIndex() const {
  return ECMAScriptParser::RuleNumericLiteral;
}

antlrcpp::Any ECMAScriptParser::NumericLiteralContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitNumericLiteral(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::NumericLiteralContext* ECMAScriptParser::numericLiteral() {
  NumericLiteralContext *_localctx = _tracker.createInstance<NumericLiteralContext>(_ctx, getState());
  enterRule(_localctx, 92, ECMAScriptParser::RuleNumericLiteral);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(620);
    _la = _input->LA(1);
    if (!((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << ECMAScriptParser::DecimalLiteral)
      | (1ULL << ECMAScriptParser::HexIntegerLiteral)
      | (1ULL << ECMAScriptParser::OctalIntegerLiteral))) != 0))) {
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

//----------------- IdentifierNameContext ------------------------------------------------------------------

ECMAScriptParser::IdentifierNameContext::IdentifierNameContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::IdentifierNameContext::Identifier() {
  return getToken(ECMAScriptParser::Identifier, 0);
}

ECMAScriptParser::ReservedWordContext* ECMAScriptParser::IdentifierNameContext::reservedWord() {
  return getRuleContext<ECMAScriptParser::ReservedWordContext>(0);
}


size_t ECMAScriptParser::IdentifierNameContext::getRuleIndex() const {
  return ECMAScriptParser::RuleIdentifierName;
}

antlrcpp::Any ECMAScriptParser::IdentifierNameContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitIdentifierName(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::IdentifierNameContext* ECMAScriptParser::identifierName() {
  IdentifierNameContext *_localctx = _tracker.createInstance<IdentifierNameContext>(_ctx, getState());
  enterRule(_localctx, 94, ECMAScriptParser::RuleIdentifierName);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(624);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case ECMAScriptParser::Identifier: {
        enterOuterAlt(_localctx, 1);
        setState(622);
        match(ECMAScriptParser::Identifier);
        break;
      }

      case ECMAScriptParser::NullLiteral:
      case ECMAScriptParser::BooleanLiteral:
      case ECMAScriptParser::Break:
      case ECMAScriptParser::Do:
      case ECMAScriptParser::Instanceof:
      case ECMAScriptParser::Typeof:
      case ECMAScriptParser::Case:
      case ECMAScriptParser::Else:
      case ECMAScriptParser::New:
      case ECMAScriptParser::Var:
      case ECMAScriptParser::Let:
      case ECMAScriptParser::Catch:
      case ECMAScriptParser::Finally:
      case ECMAScriptParser::Return:
      case ECMAScriptParser::Void:
      case ECMAScriptParser::Continue:
      case ECMAScriptParser::For:
      case ECMAScriptParser::Switch:
      case ECMAScriptParser::While:
      case ECMAScriptParser::Debugger:
      case ECMAScriptParser::Function:
      case ECMAScriptParser::This:
      case ECMAScriptParser::With:
      case ECMAScriptParser::Default:
      case ECMAScriptParser::If:
      case ECMAScriptParser::Throw:
      case ECMAScriptParser::Delete:
      case ECMAScriptParser::In:
      case ECMAScriptParser::Try:
      case ECMAScriptParser::Class:
      case ECMAScriptParser::Enum:
      case ECMAScriptParser::Extends:
      case ECMAScriptParser::Super:
      case ECMAScriptParser::Const:
      case ECMAScriptParser::Export:
      case ECMAScriptParser::Import:
      case ECMAScriptParser::Implements:
      case ECMAScriptParser::Private:
      case ECMAScriptParser::Public:
      case ECMAScriptParser::Interface:
      case ECMAScriptParser::Package:
      case ECMAScriptParser::Protected:
      case ECMAScriptParser::Static:
      case ECMAScriptParser::Yield: {
        enterOuterAlt(_localctx, 2);
        setState(623);
        reservedWord();
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

//----------------- ReservedWordContext ------------------------------------------------------------------

ECMAScriptParser::ReservedWordContext::ReservedWordContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

ECMAScriptParser::KeywordContext* ECMAScriptParser::ReservedWordContext::keyword() {
  return getRuleContext<ECMAScriptParser::KeywordContext>(0);
}

ECMAScriptParser::FutureReservedWordContext* ECMAScriptParser::ReservedWordContext::futureReservedWord() {
  return getRuleContext<ECMAScriptParser::FutureReservedWordContext>(0);
}

tree::TerminalNode* ECMAScriptParser::ReservedWordContext::NullLiteral() {
  return getToken(ECMAScriptParser::NullLiteral, 0);
}

tree::TerminalNode* ECMAScriptParser::ReservedWordContext::BooleanLiteral() {
  return getToken(ECMAScriptParser::BooleanLiteral, 0);
}


size_t ECMAScriptParser::ReservedWordContext::getRuleIndex() const {
  return ECMAScriptParser::RuleReservedWord;
}

antlrcpp::Any ECMAScriptParser::ReservedWordContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitReservedWord(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::ReservedWordContext* ECMAScriptParser::reservedWord() {
  ReservedWordContext *_localctx = _tracker.createInstance<ReservedWordContext>(_ctx, getState());
  enterRule(_localctx, 96, ECMAScriptParser::RuleReservedWord);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(629);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case ECMAScriptParser::Break:
      case ECMAScriptParser::Do:
      case ECMAScriptParser::Instanceof:
      case ECMAScriptParser::Typeof:
      case ECMAScriptParser::Case:
      case ECMAScriptParser::Else:
      case ECMAScriptParser::New:
      case ECMAScriptParser::Var:
      case ECMAScriptParser::Let:
      case ECMAScriptParser::Catch:
      case ECMAScriptParser::Finally:
      case ECMAScriptParser::Return:
      case ECMAScriptParser::Void:
      case ECMAScriptParser::Continue:
      case ECMAScriptParser::For:
      case ECMAScriptParser::Switch:
      case ECMAScriptParser::While:
      case ECMAScriptParser::Debugger:
      case ECMAScriptParser::Function:
      case ECMAScriptParser::This:
      case ECMAScriptParser::With:
      case ECMAScriptParser::Default:
      case ECMAScriptParser::If:
      case ECMAScriptParser::Throw:
      case ECMAScriptParser::Delete:
      case ECMAScriptParser::In:
      case ECMAScriptParser::Try: {
        enterOuterAlt(_localctx, 1);
        setState(626);
        keyword();
        break;
      }

      case ECMAScriptParser::Class:
      case ECMAScriptParser::Enum:
      case ECMAScriptParser::Extends:
      case ECMAScriptParser::Super:
      case ECMAScriptParser::Const:
      case ECMAScriptParser::Export:
      case ECMAScriptParser::Import:
      case ECMAScriptParser::Implements:
      case ECMAScriptParser::Private:
      case ECMAScriptParser::Public:
      case ECMAScriptParser::Interface:
      case ECMAScriptParser::Package:
      case ECMAScriptParser::Protected:
      case ECMAScriptParser::Static:
      case ECMAScriptParser::Yield: {
        enterOuterAlt(_localctx, 2);
        setState(627);
        futureReservedWord();
        break;
      }

      case ECMAScriptParser::NullLiteral:
      case ECMAScriptParser::BooleanLiteral: {
        enterOuterAlt(_localctx, 3);
        setState(628);
        _la = _input->LA(1);
        if (!(_la == ECMAScriptParser::NullLiteral

        || _la == ECMAScriptParser::BooleanLiteral)) {
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
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- KeywordContext ------------------------------------------------------------------

ECMAScriptParser::KeywordContext::KeywordContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Break() {
  return getToken(ECMAScriptParser::Break, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Do() {
  return getToken(ECMAScriptParser::Do, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Instanceof() {
  return getToken(ECMAScriptParser::Instanceof, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Typeof() {
  return getToken(ECMAScriptParser::Typeof, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Case() {
  return getToken(ECMAScriptParser::Case, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Else() {
  return getToken(ECMAScriptParser::Else, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::New() {
  return getToken(ECMAScriptParser::New, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Var() {
  return getToken(ECMAScriptParser::Var, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Let() {
  return getToken(ECMAScriptParser::Let, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Catch() {
  return getToken(ECMAScriptParser::Catch, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Finally() {
  return getToken(ECMAScriptParser::Finally, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Return() {
  return getToken(ECMAScriptParser::Return, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Void() {
  return getToken(ECMAScriptParser::Void, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Continue() {
  return getToken(ECMAScriptParser::Continue, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::For() {
  return getToken(ECMAScriptParser::For, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Switch() {
  return getToken(ECMAScriptParser::Switch, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::While() {
  return getToken(ECMAScriptParser::While, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Debugger() {
  return getToken(ECMAScriptParser::Debugger, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Function() {
  return getToken(ECMAScriptParser::Function, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::This() {
  return getToken(ECMAScriptParser::This, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::With() {
  return getToken(ECMAScriptParser::With, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Default() {
  return getToken(ECMAScriptParser::Default, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::If() {
  return getToken(ECMAScriptParser::If, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Throw() {
  return getToken(ECMAScriptParser::Throw, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Delete() {
  return getToken(ECMAScriptParser::Delete, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::In() {
  return getToken(ECMAScriptParser::In, 0);
}

tree::TerminalNode* ECMAScriptParser::KeywordContext::Try() {
  return getToken(ECMAScriptParser::Try, 0);
}


size_t ECMAScriptParser::KeywordContext::getRuleIndex() const {
  return ECMAScriptParser::RuleKeyword;
}

antlrcpp::Any ECMAScriptParser::KeywordContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitKeyword(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::KeywordContext* ECMAScriptParser::keyword() {
  KeywordContext *_localctx = _tracker.createInstance<KeywordContext>(_ctx, getState());
  enterRule(_localctx, 98, ECMAScriptParser::RuleKeyword);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(631);
    _la = _input->LA(1);
    if (!(((((_la - 56) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 56)) & ((1ULL << (ECMAScriptParser::Break - 56))
      | (1ULL << (ECMAScriptParser::Do - 56))
      | (1ULL << (ECMAScriptParser::Instanceof - 56))
      | (1ULL << (ECMAScriptParser::Typeof - 56))
      | (1ULL << (ECMAScriptParser::Case - 56))
      | (1ULL << (ECMAScriptParser::Else - 56))
      | (1ULL << (ECMAScriptParser::New - 56))
      | (1ULL << (ECMAScriptParser::Var - 56))
      | (1ULL << (ECMAScriptParser::Let - 56))
      | (1ULL << (ECMAScriptParser::Catch - 56))
      | (1ULL << (ECMAScriptParser::Finally - 56))
      | (1ULL << (ECMAScriptParser::Return - 56))
      | (1ULL << (ECMAScriptParser::Void - 56))
      | (1ULL << (ECMAScriptParser::Continue - 56))
      | (1ULL << (ECMAScriptParser::For - 56))
      | (1ULL << (ECMAScriptParser::Switch - 56))
      | (1ULL << (ECMAScriptParser::While - 56))
      | (1ULL << (ECMAScriptParser::Debugger - 56))
      | (1ULL << (ECMAScriptParser::Function - 56))
      | (1ULL << (ECMAScriptParser::This - 56))
      | (1ULL << (ECMAScriptParser::With - 56))
      | (1ULL << (ECMAScriptParser::Default - 56))
      | (1ULL << (ECMAScriptParser::If - 56))
      | (1ULL << (ECMAScriptParser::Throw - 56))
      | (1ULL << (ECMAScriptParser::Delete - 56))
      | (1ULL << (ECMAScriptParser::In - 56))
      | (1ULL << (ECMAScriptParser::Try - 56)))) != 0))) {
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

//----------------- FutureReservedWordContext ------------------------------------------------------------------

ECMAScriptParser::FutureReservedWordContext::FutureReservedWordContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::FutureReservedWordContext::Class() {
  return getToken(ECMAScriptParser::Class, 0);
}

tree::TerminalNode* ECMAScriptParser::FutureReservedWordContext::Enum() {
  return getToken(ECMAScriptParser::Enum, 0);
}

tree::TerminalNode* ECMAScriptParser::FutureReservedWordContext::Extends() {
  return getToken(ECMAScriptParser::Extends, 0);
}

tree::TerminalNode* ECMAScriptParser::FutureReservedWordContext::Super() {
  return getToken(ECMAScriptParser::Super, 0);
}

tree::TerminalNode* ECMAScriptParser::FutureReservedWordContext::Const() {
  return getToken(ECMAScriptParser::Const, 0);
}

tree::TerminalNode* ECMAScriptParser::FutureReservedWordContext::Export() {
  return getToken(ECMAScriptParser::Export, 0);
}

tree::TerminalNode* ECMAScriptParser::FutureReservedWordContext::Import() {
  return getToken(ECMAScriptParser::Import, 0);
}

tree::TerminalNode* ECMAScriptParser::FutureReservedWordContext::Implements() {
  return getToken(ECMAScriptParser::Implements, 0);
}

tree::TerminalNode* ECMAScriptParser::FutureReservedWordContext::Private() {
  return getToken(ECMAScriptParser::Private, 0);
}

tree::TerminalNode* ECMAScriptParser::FutureReservedWordContext::Public() {
  return getToken(ECMAScriptParser::Public, 0);
}

tree::TerminalNode* ECMAScriptParser::FutureReservedWordContext::Interface() {
  return getToken(ECMAScriptParser::Interface, 0);
}

tree::TerminalNode* ECMAScriptParser::FutureReservedWordContext::Package() {
  return getToken(ECMAScriptParser::Package, 0);
}

tree::TerminalNode* ECMAScriptParser::FutureReservedWordContext::Protected() {
  return getToken(ECMAScriptParser::Protected, 0);
}

tree::TerminalNode* ECMAScriptParser::FutureReservedWordContext::Static() {
  return getToken(ECMAScriptParser::Static, 0);
}

tree::TerminalNode* ECMAScriptParser::FutureReservedWordContext::Yield() {
  return getToken(ECMAScriptParser::Yield, 0);
}


size_t ECMAScriptParser::FutureReservedWordContext::getRuleIndex() const {
  return ECMAScriptParser::RuleFutureReservedWord;
}

antlrcpp::Any ECMAScriptParser::FutureReservedWordContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitFutureReservedWord(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::FutureReservedWordContext* ECMAScriptParser::futureReservedWord() {
  FutureReservedWordContext *_localctx = _tracker.createInstance<FutureReservedWordContext>(_ctx, getState());
  enterRule(_localctx, 100, ECMAScriptParser::RuleFutureReservedWord);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(633);
    _la = _input->LA(1);
    if (!(((((_la - 83) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 83)) & ((1ULL << (ECMAScriptParser::Class - 83))
      | (1ULL << (ECMAScriptParser::Enum - 83))
      | (1ULL << (ECMAScriptParser::Extends - 83))
      | (1ULL << (ECMAScriptParser::Super - 83))
      | (1ULL << (ECMAScriptParser::Const - 83))
      | (1ULL << (ECMAScriptParser::Export - 83))
      | (1ULL << (ECMAScriptParser::Import - 83))
      | (1ULL << (ECMAScriptParser::Implements - 83))
      | (1ULL << (ECMAScriptParser::Private - 83))
      | (1ULL << (ECMAScriptParser::Public - 83))
      | (1ULL << (ECMAScriptParser::Interface - 83))
      | (1ULL << (ECMAScriptParser::Package - 83))
      | (1ULL << (ECMAScriptParser::Protected - 83))
      | (1ULL << (ECMAScriptParser::Static - 83))
      | (1ULL << (ECMAScriptParser::Yield - 83)))) != 0))) {
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

//----------------- GetterContext ------------------------------------------------------------------

ECMAScriptParser::GetterContext::GetterContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::GetterContext::Identifier() {
  return getToken(ECMAScriptParser::Identifier, 0);
}

ECMAScriptParser::PropertyNameContext* ECMAScriptParser::GetterContext::propertyName() {
  return getRuleContext<ECMAScriptParser::PropertyNameContext>(0);
}


size_t ECMAScriptParser::GetterContext::getRuleIndex() const {
  return ECMAScriptParser::RuleGetter;
}

antlrcpp::Any ECMAScriptParser::GetterContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitGetter(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::GetterContext* ECMAScriptParser::getter() {
  GetterContext *_localctx = _tracker.createInstance<GetterContext>(_ctx, getState());
  enterRule(_localctx, 102, ECMAScriptParser::RuleGetter);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(635);

    if (_input->LT(1)->getText().compare("get")) throw FailedPredicateException(this, "_input->LT(1).Text.Equals(\"get\")");
    setState(636);
    match(ECMAScriptParser::Identifier);
    setState(637);
    propertyName();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SetterContext ------------------------------------------------------------------

ECMAScriptParser::SetterContext::SetterContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::SetterContext::Identifier() {
  return getToken(ECMAScriptParser::Identifier, 0);
}

ECMAScriptParser::PropertyNameContext* ECMAScriptParser::SetterContext::propertyName() {
  return getRuleContext<ECMAScriptParser::PropertyNameContext>(0);
}


size_t ECMAScriptParser::SetterContext::getRuleIndex() const {
  return ECMAScriptParser::RuleSetter;
}

antlrcpp::Any ECMAScriptParser::SetterContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitSetter(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::SetterContext* ECMAScriptParser::setter() {
  SetterContext *_localctx = _tracker.createInstance<SetterContext>(_ctx, getState());
  enterRule(_localctx, 104, ECMAScriptParser::RuleSetter);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(639);

    if (_input->LT(1)->getText().compare("set")) throw FailedPredicateException(this, "_input->LT(1)->getText().Equals(\"set\")");
    setState(640);
    match(ECMAScriptParser::Identifier);
    setState(641);
    propertyName();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- EosContext ------------------------------------------------------------------

ECMAScriptParser::EosContext::EosContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::EosContext::SemiColon() {
  return getToken(ECMAScriptParser::SemiColon, 0);
}

tree::TerminalNode* ECMAScriptParser::EosContext::EOF() {
  return getToken(ECMAScriptParser::EOF, 0);
}


size_t ECMAScriptParser::EosContext::getRuleIndex() const {
  return ECMAScriptParser::RuleEos;
}

antlrcpp::Any ECMAScriptParser::EosContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitEos(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::EosContext* ECMAScriptParser::eos() {
  EosContext *_localctx = _tracker.createInstance<EosContext>(_ctx, getState());
  enterRule(_localctx, 106, ECMAScriptParser::RuleEos);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(647);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 55, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(643);
      match(ECMAScriptParser::SemiColon);
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(644);
      match(ECMAScriptParser::EOF);
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(645);

      if (!(lineTerminatorAhead())) throw FailedPredicateException(this, "lineTerminatorAhead()");
      break;
    }

    case 4: {
      enterOuterAlt(_localctx, 4);
      setState(646);

      if (!(_input->LT(1)->getType() == CloseBrace)) throw FailedPredicateException(this, "_input->LT(1).Type == CloseBrace");
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

//----------------- EofContext ------------------------------------------------------------------

ECMAScriptParser::EofContext::EofContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* ECMAScriptParser::EofContext::EOF() {
  return getToken(ECMAScriptParser::EOF, 0);
}


size_t ECMAScriptParser::EofContext::getRuleIndex() const {
  return ECMAScriptParser::RuleEof;
}

antlrcpp::Any ECMAScriptParser::EofContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<ECMAScriptVisitor*>(visitor))
    return parserVisitor->visitEof(this);
  else
    return visitor->visitChildren(this);
}

ECMAScriptParser::EofContext* ECMAScriptParser::eof() {
  EofContext *_localctx = _tracker.createInstance<EofContext>(_ctx, getState());
  enterRule(_localctx, 108, ECMAScriptParser::RuleEof);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(649);
    match(ECMAScriptParser::EOF);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

bool ECMAScriptParser::sempred(RuleContext *context, size_t ruleIndex, size_t predicateIndex) {
  switch (ruleIndex) {
    case 11: return expressionStatementSempred(dynamic_cast<ExpressionStatementContext *>(context), predicateIndex);
    case 14: return continueStatementSempred(dynamic_cast<ContinueStatementContext *>(context), predicateIndex);
    case 15: return breakStatementSempred(dynamic_cast<BreakStatementContext *>(context), predicateIndex);
    case 16: return returnStatementSempred(dynamic_cast<ReturnStatementContext *>(context), predicateIndex);
    case 24: return throwStatementSempred(dynamic_cast<ThrowStatementContext *>(context), predicateIndex);
    case 43: return singleExpressionSempred(dynamic_cast<SingleExpressionContext *>(context), predicateIndex);
    case 51: return getterSempred(dynamic_cast<GetterContext *>(context), predicateIndex);
    case 52: return setterSempred(dynamic_cast<SetterContext *>(context), predicateIndex);
    case 53: return eosSempred(dynamic_cast<EosContext *>(context), predicateIndex);

  default:
    break;
  }
  return true;
}

bool ECMAScriptParser::expressionStatementSempred(ExpressionStatementContext *_localctx, size_t predicateIndex) {
  switch (predicateIndex) {
    case 0: return (_input->LA(1) != OpenBrace) && (_input->LA(1) != Function);

  default:
    break;
  }
  return true;
}

bool ECMAScriptParser::continueStatementSempred(ContinueStatementContext *_localctx, size_t predicateIndex) {
  switch (predicateIndex) {
    case 1: return !here(LineTerminator);

  default:
    break;
  }
  return true;
}

bool ECMAScriptParser::breakStatementSempred(BreakStatementContext *_localctx, size_t predicateIndex) {
  switch (predicateIndex) {
    case 2: return !here(LineTerminator);

  default:
    break;
  }
  return true;
}

bool ECMAScriptParser::returnStatementSempred(ReturnStatementContext *_localctx, size_t predicateIndex) {
  switch (predicateIndex) {
    case 3: return !here(LineTerminator);

  default:
    break;
  }
  return true;
}

bool ECMAScriptParser::throwStatementSempred(ThrowStatementContext *_localctx, size_t predicateIndex) {
  switch (predicateIndex) {
    case 4: return !here(LineTerminator);

  default:
    break;
  }
  return true;
}

bool ECMAScriptParser::singleExpressionSempred(SingleExpressionContext *_localctx, size_t predicateIndex) {
  switch (predicateIndex) {
    case 5: return precpred(_ctx, 21);
    case 6: return precpred(_ctx, 20);
    case 7: return precpred(_ctx, 19);
    case 8: return precpred(_ctx, 18);
    case 9: return precpred(_ctx, 17);
    case 10: return precpred(_ctx, 16);
    case 11: return precpred(_ctx, 15);
    case 12: return precpred(_ctx, 14);
    case 13: return precpred(_ctx, 13);
    case 14: return precpred(_ctx, 12);
    case 15: return precpred(_ctx, 11);
    case 16: return precpred(_ctx, 10);
    case 17: return precpred(_ctx, 9);
    case 18: return precpred(_ctx, 8);
    case 19: return precpred(_ctx, 7);
    case 20: return precpred(_ctx, 36);
    case 21: return precpred(_ctx, 35);
    case 22: return precpred(_ctx, 34);
    case 23: return precpred(_ctx, 32);
    case 24: return !here(LineTerminator);
    case 25: return precpred(_ctx, 31);
    case 26: return !here(LineTerminator);

  default:
    break;
  }
  return true;
}

bool ECMAScriptParser::getterSempred(GetterContext *_localctx, size_t predicateIndex) {
  switch (predicateIndex) {
    case 27: return !(_input->LT(1)->getText().compare("get"));

  default:
    break;
  }
  return true;
}

bool ECMAScriptParser::setterSempred(SetterContext *_localctx, size_t predicateIndex) {
  switch (predicateIndex) {
    case 28: return !(_input->LT(1)->getText().compare("set"));

  default:
    break;
  }
  return true;
}

bool ECMAScriptParser::eosSempred(EosContext *_localctx, size_t predicateIndex) {
  switch (predicateIndex) {
    case 29: return lineTerminatorAhead();
    case 30: return _input->LT(1)->getType() == CloseBrace;

  default:
    break;
  }
  return true;
}

// Static vars and initialization.
std::vector<dfa::DFA> ECMAScriptParser::_decisionToDFA;
atn::PredictionContextCache ECMAScriptParser::_sharedContextCache;

// We own the ATN which in turn owns the ATN states.
atn::ATN ECMAScriptParser::_atn;
std::vector<uint16_t> ECMAScriptParser::_serializedATN;

std::vector<std::string> ECMAScriptParser::_ruleNames = {
  "program", "sourceElements", "sourceElement", "statement", "block", "statementList", 
  "variableStatement", "variableDeclarationList", "variableDeclaration", 
  "initialiser", "emptyStatement", "expressionStatement", "ifStatement", 
  "iterationStatement", "continueStatement", "breakStatement", "returnStatement", 
  "withStatement", "switchStatement", "caseBlock", "caseClauses", "caseClause", 
  "defaultClause", "labelledStatement", "throwStatement", "tryStatement", 
  "catchProduction", "finallyProduction", "debuggerStatement", "functionDeclaration", 
  "formalParameterList", "functionBody", "arrayLiteral", "elementList", 
  "elision", "objectLiteral", "propertyNameAndValueList", "propertyAssignment", 
  "propertyName", "propertySetParameterList", "arguments", "argumentList", 
  "expressionSequence", "singleExpression", "assignmentOperator", "literal", 
  "numericLiteral", "identifierName", "reservedWord", "keyword", "futureReservedWord", 
  "getter", "setter", "eos", "eof"
};

std::vector<std::string> ECMAScriptParser::_literalNames = {
  "", "", "", "'['", "']'", "'('", "')'", "'{'", "'}'", "';'", "','", "'='", 
  "'?'", "':'", "'.'", "'++'", "'--'", "'+'", "'-'", "'~'", "'!'", "'*'", 
  "'/'", "'%'", "'>>'", "'<<'", "'>>>'", "'<'", "'>'", "'<='", "'>='", "'=='", 
  "'!='", "'==='", "'!=='", "'&'", "'^'", "'|'", "'&&'", "'||'", "'*='", 
  "'/='", "'%='", "'+='", "'-='", "'<<='", "'>>='", "'>>>='", "'&='", "'^='", 
  "'|='", "'null'", "", "", "", "", "'break'", "'do'", "'instanceof'", "'typeof'", 
  "'case'", "'else'", "'new'", "'var'", "'let'", "'catch'", "'finally'", 
  "'return'", "'void'", "'continue'", "'for'", "'switch'", "'while'", "'debugger'", 
  "'function'", "'this'", "'with'", "'default'", "'if'", "'throw'", "'delete'", 
  "'in'", "'try'", "'class'", "'enum'", "'extends'", "'super'", "'const'", 
  "'export'", "'import'", "'implements'", "'private'", "'public'", "'interface'", 
  "'package'", "'protected'", "'static'", "'yield'"
};

std::vector<std::string> ECMAScriptParser::_symbolicNames = {
  "", "RegularExpressionLiteral", "LineTerminator", "OpenBracket", "CloseBracket", 
  "OpenParen", "CloseParen", "OpenBrace", "CloseBrace", "SemiColon", "Comma", 
  "Assign", "QuestionMark", "Colon", "Dot", "PlusPlus", "MinusMinus", "Plus", 
  "Minus", "BitNot", "Not", "Multiply", "Divide", "Modulus", "RightShiftArithmetic", 
  "LeftShiftArithmetic", "RightShiftLogical", "LessThan", "MoreThan", "LessThanEquals", 
  "GreaterThanEquals", "Equals_", "NotEquals", "IdentityEquals", "IdentityNotEquals", 
  "BitAnd", "BitXOr", "BitOr", "And", "Or", "MultiplyAssign", "DivideAssign", 
  "ModulusAssign", "PlusAssign", "MinusAssign", "LeftShiftArithmeticAssign", 
  "RightShiftArithmeticAssign", "RightShiftLogicalAssign", "BitAndAssign", 
  "BitXorAssign", "BitOrAssign", "NullLiteral", "BooleanLiteral", "DecimalLiteral", 
  "HexIntegerLiteral", "OctalIntegerLiteral", "Break", "Do", "Instanceof", 
  "Typeof", "Case", "Else", "New", "Var", "Let", "Catch", "Finally", "Return", 
  "Void", "Continue", "For", "Switch", "While", "Debugger", "Function", 
  "This", "With", "Default", "If", "Throw", "Delete", "In", "Try", "Class", 
  "Enum", "Extends", "Super", "Const", "Export", "Import", "Implements", 
  "Private", "Public", "Interface", "Package", "Protected", "Static", "Yield", 
  "Identifier", "StringLiteral", "WhiteSpaces", "MultiLineComment", "SingleLineComment", 
  "HtmlComment", "UnexpectedCharacter"
};

dfa::Vocabulary ECMAScriptParser::_vocabulary(_literalNames, _symbolicNames);

std::vector<std::string> ECMAScriptParser::_tokenNames;

ECMAScriptParser::Initializer::Initializer() {
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
    0x3, 0x6a, 0x28e, 0x4, 0x2, 0x9, 0x2, 0x4, 0x3, 0x9, 0x3, 0x4, 0x4, 
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
    0x4, 0x36, 0x9, 0x36, 0x4, 0x37, 0x9, 0x37, 0x4, 0x38, 0x9, 0x38, 0x3, 
    0x2, 0x5, 0x2, 0x72, 0xa, 0x2, 0x3, 0x2, 0x3, 0x2, 0x3, 0x3, 0x6, 0x3, 
    0x77, 0xa, 0x3, 0xd, 0x3, 0xe, 0x3, 0x78, 0x3, 0x4, 0x3, 0x4, 0x5, 0x4, 
    0x7d, 0xa, 0x4, 0x3, 0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 
    0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 
    0x5, 0x3, 0x5, 0x3, 0x5, 0x5, 0x5, 0x8e, 0xa, 0x5, 0x3, 0x6, 0x3, 0x6, 
    0x5, 0x6, 0x92, 0xa, 0x6, 0x3, 0x6, 0x3, 0x6, 0x3, 0x7, 0x6, 0x7, 0x97, 
    0xa, 0x7, 0xd, 0x7, 0xe, 0x7, 0x98, 0x3, 0x8, 0x3, 0x8, 0x3, 0x8, 0x3, 
    0x8, 0x3, 0x8, 0x3, 0x8, 0x3, 0x8, 0x3, 0x8, 0x5, 0x8, 0xa3, 0xa, 0x8, 
    0x3, 0x9, 0x3, 0x9, 0x3, 0x9, 0x7, 0x9, 0xa8, 0xa, 0x9, 0xc, 0x9, 0xe, 
    0x9, 0xab, 0xb, 0x9, 0x3, 0xa, 0x3, 0xa, 0x5, 0xa, 0xaf, 0xa, 0xa, 0x3, 
    0xb, 0x3, 0xb, 0x3, 0xb, 0x3, 0xc, 0x3, 0xc, 0x3, 0xd, 0x3, 0xd, 0x3, 
    0xd, 0x3, 0xd, 0x3, 0xe, 0x3, 0xe, 0x3, 0xe, 0x3, 0xe, 0x3, 0xe, 0x3, 
    0xe, 0x3, 0xe, 0x5, 0xe, 0xc1, 0xa, 0xe, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 
    0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 
    0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 
    0x5, 0xf, 0xd4, 0xa, 0xf, 0x3, 0xf, 0x3, 0xf, 0x5, 0xf, 0xd8, 0xa, 0xf, 
    0x3, 0xf, 0x3, 0xf, 0x5, 0xf, 0xdc, 0xa, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 
    0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x5, 0xf, 0xe6, 
    0xa, 0xf, 0x3, 0xf, 0x3, 0xf, 0x5, 0xf, 0xea, 0xa, 0xf, 0x3, 0xf, 0x3, 
    0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 
    0xf, 0x5, 0xf, 0xf5, 0xa, 0xf, 0x3, 0xf, 0x3, 0xf, 0x5, 0xf, 0xf9, 0xa, 
    0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 
    0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 
    0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 
    0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 
    0xf, 0x3, 0xf, 0x5, 0xf, 0x118, 0xa, 0xf, 0x3, 0x10, 0x3, 0x10, 0x3, 
    0x10, 0x5, 0x10, 0x11d, 0xa, 0x10, 0x3, 0x10, 0x3, 0x10, 0x3, 0x11, 
    0x3, 0x11, 0x3, 0x11, 0x5, 0x11, 0x124, 0xa, 0x11, 0x3, 0x11, 0x3, 0x11, 
    0x3, 0x12, 0x3, 0x12, 0x3, 0x12, 0x5, 0x12, 0x12b, 0xa, 0x12, 0x3, 0x12, 
    0x3, 0x12, 0x3, 0x13, 0x3, 0x13, 0x3, 0x13, 0x3, 0x13, 0x3, 0x13, 0x3, 
    0x13, 0x3, 0x14, 0x3, 0x14, 0x3, 0x14, 0x3, 0x14, 0x3, 0x14, 0x3, 0x14, 
    0x3, 0x15, 0x3, 0x15, 0x5, 0x15, 0x13d, 0xa, 0x15, 0x3, 0x15, 0x3, 0x15, 
    0x5, 0x15, 0x141, 0xa, 0x15, 0x5, 0x15, 0x143, 0xa, 0x15, 0x3, 0x15, 
    0x3, 0x15, 0x3, 0x16, 0x6, 0x16, 0x148, 0xa, 0x16, 0xd, 0x16, 0xe, 0x16, 
    0x149, 0x3, 0x17, 0x3, 0x17, 0x3, 0x17, 0x3, 0x17, 0x5, 0x17, 0x150, 
    0xa, 0x17, 0x3, 0x18, 0x3, 0x18, 0x3, 0x18, 0x5, 0x18, 0x155, 0xa, 0x18, 
    0x3, 0x19, 0x3, 0x19, 0x3, 0x19, 0x3, 0x19, 0x3, 0x1a, 0x3, 0x1a, 0x3, 
    0x1a, 0x3, 0x1a, 0x3, 0x1a, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 
    0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 
    0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x5, 0x1b, 0x16d, 0xa, 0x1b, 0x3, 0x1c, 
    0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1d, 0x3, 
    0x1d, 0x3, 0x1d, 0x3, 0x1e, 0x3, 0x1e, 0x3, 0x1e, 0x3, 0x1f, 0x3, 0x1f, 
    0x3, 0x1f, 0x3, 0x1f, 0x5, 0x1f, 0x17f, 0xa, 0x1f, 0x3, 0x1f, 0x3, 0x1f, 
    0x3, 0x1f, 0x3, 0x1f, 0x3, 0x1f, 0x3, 0x20, 0x3, 0x20, 0x3, 0x20, 0x7, 
    0x20, 0x189, 0xa, 0x20, 0xc, 0x20, 0xe, 0x20, 0x18c, 0xb, 0x20, 0x3, 
    0x21, 0x5, 0x21, 0x18f, 0xa, 0x21, 0x3, 0x22, 0x3, 0x22, 0x5, 0x22, 
    0x193, 0xa, 0x22, 0x3, 0x22, 0x5, 0x22, 0x196, 0xa, 0x22, 0x3, 0x22, 
    0x5, 0x22, 0x199, 0xa, 0x22, 0x3, 0x22, 0x3, 0x22, 0x3, 0x23, 0x5, 0x23, 
    0x19e, 0xa, 0x23, 0x3, 0x23, 0x3, 0x23, 0x3, 0x23, 0x5, 0x23, 0x1a3, 
    0xa, 0x23, 0x3, 0x23, 0x7, 0x23, 0x1a6, 0xa, 0x23, 0xc, 0x23, 0xe, 0x23, 
    0x1a9, 0xb, 0x23, 0x3, 0x24, 0x6, 0x24, 0x1ac, 0xa, 0x24, 0xd, 0x24, 
    0xe, 0x24, 0x1ad, 0x3, 0x25, 0x3, 0x25, 0x5, 0x25, 0x1b2, 0xa, 0x25, 
    0x3, 0x25, 0x5, 0x25, 0x1b5, 0xa, 0x25, 0x3, 0x25, 0x3, 0x25, 0x3, 0x26, 
    0x3, 0x26, 0x3, 0x26, 0x7, 0x26, 0x1bc, 0xa, 0x26, 0xc, 0x26, 0xe, 0x26, 
    0x1bf, 0xb, 0x26, 0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 
    0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 0x3, 
    0x27, 0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 
    0x3, 0x27, 0x5, 0x27, 0x1d4, 0xa, 0x27, 0x3, 0x28, 0x3, 0x28, 0x3, 0x28, 
    0x5, 0x28, 0x1d9, 0xa, 0x28, 0x3, 0x29, 0x3, 0x29, 0x3, 0x2a, 0x3, 0x2a, 
    0x5, 0x2a, 0x1df, 0xa, 0x2a, 0x3, 0x2a, 0x3, 0x2a, 0x3, 0x2b, 0x3, 0x2b, 
    0x3, 0x2b, 0x7, 0x2b, 0x1e6, 0xa, 0x2b, 0xc, 0x2b, 0xe, 0x2b, 0x1e9, 
    0xb, 0x2b, 0x3, 0x2c, 0x3, 0x2c, 0x3, 0x2c, 0x7, 0x2c, 0x1ee, 0xa, 0x2c, 
    0xc, 0x2c, 0xe, 0x2c, 0x1f1, 0xb, 0x2c, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 
    0x5, 0x2d, 0x1f6, 0xa, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x5, 0x2d, 0x1fa, 
    0xa, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 
    0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x5, 0x2d, 0x204, 0xa, 0x2d, 0x3, 0x2d, 
    0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 
    0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 
    0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 
    0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 
    0x5, 0x2d, 0x221, 0xa, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 
    0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 
    0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 
    0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 
    0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 
    0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 
    0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 
    0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 
    0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 
    0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 
    0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x7, 0x2d, 0x264, 0xa, 0x2d, 0xc, 0x2d, 
    0xe, 0x2d, 0x267, 0xb, 0x2d, 0x3, 0x2e, 0x3, 0x2e, 0x3, 0x2f, 0x3, 0x2f, 
    0x5, 0x2f, 0x26d, 0xa, 0x2f, 0x3, 0x30, 0x3, 0x30, 0x3, 0x31, 0x3, 0x31, 
    0x5, 0x31, 0x273, 0xa, 0x31, 0x3, 0x32, 0x3, 0x32, 0x3, 0x32, 0x5, 0x32, 
    0x278, 0xa, 0x32, 0x3, 0x33, 0x3, 0x33, 0x3, 0x34, 0x3, 0x34, 0x3, 0x35, 
    0x3, 0x35, 0x3, 0x35, 0x3, 0x35, 0x3, 0x36, 0x3, 0x36, 0x3, 0x36, 0x3, 
    0x36, 0x3, 0x37, 0x3, 0x37, 0x3, 0x37, 0x3, 0x37, 0x5, 0x37, 0x28a, 
    0xa, 0x37, 0x3, 0x38, 0x3, 0x38, 0x3, 0x38, 0x2, 0x3, 0x58, 0x39, 0x2, 
    0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 
    0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 
    0x36, 0x38, 0x3a, 0x3c, 0x3e, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 
    0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e, 0x60, 0x62, 0x64, 
    0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x2, 0xd, 0x3, 0x2, 0x17, 0x19, 0x3, 0x2, 
    0x13, 0x14, 0x3, 0x2, 0x1a, 0x1c, 0x3, 0x2, 0x1d, 0x20, 0x3, 0x2, 0x21, 
    0x24, 0x3, 0x2, 0x2a, 0x34, 0x5, 0x2, 0x3, 0x3, 0x35, 0x36, 0x65, 0x65, 
    0x3, 0x2, 0x37, 0x39, 0x3, 0x2, 0x35, 0x36, 0x3, 0x2, 0x3a, 0x54, 0x3, 
    0x2, 0x55, 0x63, 0x2, 0x2c8, 0x2, 0x71, 0x3, 0x2, 0x2, 0x2, 0x4, 0x76, 
    0x3, 0x2, 0x2, 0x2, 0x6, 0x7c, 0x3, 0x2, 0x2, 0x2, 0x8, 0x8d, 0x3, 0x2, 
    0x2, 0x2, 0xa, 0x8f, 0x3, 0x2, 0x2, 0x2, 0xc, 0x96, 0x3, 0x2, 0x2, 0x2, 
    0xe, 0xa2, 0x3, 0x2, 0x2, 0x2, 0x10, 0xa4, 0x3, 0x2, 0x2, 0x2, 0x12, 
    0xac, 0x3, 0x2, 0x2, 0x2, 0x14, 0xb0, 0x3, 0x2, 0x2, 0x2, 0x16, 0xb3, 
    0x3, 0x2, 0x2, 0x2, 0x18, 0xb5, 0x3, 0x2, 0x2, 0x2, 0x1a, 0xb9, 0x3, 
    0x2, 0x2, 0x2, 0x1c, 0x117, 0x3, 0x2, 0x2, 0x2, 0x1e, 0x119, 0x3, 0x2, 
    0x2, 0x2, 0x20, 0x120, 0x3, 0x2, 0x2, 0x2, 0x22, 0x127, 0x3, 0x2, 0x2, 
    0x2, 0x24, 0x12e, 0x3, 0x2, 0x2, 0x2, 0x26, 0x134, 0x3, 0x2, 0x2, 0x2, 
    0x28, 0x13a, 0x3, 0x2, 0x2, 0x2, 0x2a, 0x147, 0x3, 0x2, 0x2, 0x2, 0x2c, 
    0x14b, 0x3, 0x2, 0x2, 0x2, 0x2e, 0x151, 0x3, 0x2, 0x2, 0x2, 0x30, 0x156, 
    0x3, 0x2, 0x2, 0x2, 0x32, 0x15a, 0x3, 0x2, 0x2, 0x2, 0x34, 0x16c, 0x3, 
    0x2, 0x2, 0x2, 0x36, 0x16e, 0x3, 0x2, 0x2, 0x2, 0x38, 0x174, 0x3, 0x2, 
    0x2, 0x2, 0x3a, 0x177, 0x3, 0x2, 0x2, 0x2, 0x3c, 0x17a, 0x3, 0x2, 0x2, 
    0x2, 0x3e, 0x185, 0x3, 0x2, 0x2, 0x2, 0x40, 0x18e, 0x3, 0x2, 0x2, 0x2, 
    0x42, 0x190, 0x3, 0x2, 0x2, 0x2, 0x44, 0x19d, 0x3, 0x2, 0x2, 0x2, 0x46, 
    0x1ab, 0x3, 0x2, 0x2, 0x2, 0x48, 0x1af, 0x3, 0x2, 0x2, 0x2, 0x4a, 0x1b8, 
    0x3, 0x2, 0x2, 0x2, 0x4c, 0x1d3, 0x3, 0x2, 0x2, 0x2, 0x4e, 0x1d8, 0x3, 
    0x2, 0x2, 0x2, 0x50, 0x1da, 0x3, 0x2, 0x2, 0x2, 0x52, 0x1dc, 0x3, 0x2, 
    0x2, 0x2, 0x54, 0x1e2, 0x3, 0x2, 0x2, 0x2, 0x56, 0x1ea, 0x3, 0x2, 0x2, 
    0x2, 0x58, 0x220, 0x3, 0x2, 0x2, 0x2, 0x5a, 0x268, 0x3, 0x2, 0x2, 0x2, 
    0x5c, 0x26c, 0x3, 0x2, 0x2, 0x2, 0x5e, 0x26e, 0x3, 0x2, 0x2, 0x2, 0x60, 
    0x272, 0x3, 0x2, 0x2, 0x2, 0x62, 0x277, 0x3, 0x2, 0x2, 0x2, 0x64, 0x279, 
    0x3, 0x2, 0x2, 0x2, 0x66, 0x27b, 0x3, 0x2, 0x2, 0x2, 0x68, 0x27d, 0x3, 
    0x2, 0x2, 0x2, 0x6a, 0x281, 0x3, 0x2, 0x2, 0x2, 0x6c, 0x289, 0x3, 0x2, 
    0x2, 0x2, 0x6e, 0x28b, 0x3, 0x2, 0x2, 0x2, 0x70, 0x72, 0x5, 0x4, 0x3, 
    0x2, 0x71, 0x70, 0x3, 0x2, 0x2, 0x2, 0x71, 0x72, 0x3, 0x2, 0x2, 0x2, 
    0x72, 0x73, 0x3, 0x2, 0x2, 0x2, 0x73, 0x74, 0x7, 0x2, 0x2, 0x3, 0x74, 
    0x3, 0x3, 0x2, 0x2, 0x2, 0x75, 0x77, 0x5, 0x6, 0x4, 0x2, 0x76, 0x75, 
    0x3, 0x2, 0x2, 0x2, 0x77, 0x78, 0x3, 0x2, 0x2, 0x2, 0x78, 0x76, 0x3, 
    0x2, 0x2, 0x2, 0x78, 0x79, 0x3, 0x2, 0x2, 0x2, 0x79, 0x5, 0x3, 0x2, 
    0x2, 0x2, 0x7a, 0x7d, 0x5, 0x8, 0x5, 0x2, 0x7b, 0x7d, 0x5, 0x3c, 0x1f, 
    0x2, 0x7c, 0x7a, 0x3, 0x2, 0x2, 0x2, 0x7c, 0x7b, 0x3, 0x2, 0x2, 0x2, 
    0x7d, 0x7, 0x3, 0x2, 0x2, 0x2, 0x7e, 0x8e, 0x5, 0xa, 0x6, 0x2, 0x7f, 
    0x8e, 0x5, 0xe, 0x8, 0x2, 0x80, 0x8e, 0x5, 0x16, 0xc, 0x2, 0x81, 0x8e, 
    0x5, 0x18, 0xd, 0x2, 0x82, 0x8e, 0x5, 0x1a, 0xe, 0x2, 0x83, 0x8e, 0x5, 
    0x1c, 0xf, 0x2, 0x84, 0x8e, 0x5, 0x1e, 0x10, 0x2, 0x85, 0x8e, 0x5, 0x20, 
    0x11, 0x2, 0x86, 0x8e, 0x5, 0x22, 0x12, 0x2, 0x87, 0x8e, 0x5, 0x24, 
    0x13, 0x2, 0x88, 0x8e, 0x5, 0x30, 0x19, 0x2, 0x89, 0x8e, 0x5, 0x26, 
    0x14, 0x2, 0x8a, 0x8e, 0x5, 0x32, 0x1a, 0x2, 0x8b, 0x8e, 0x5, 0x34, 
    0x1b, 0x2, 0x8c, 0x8e, 0x5, 0x3a, 0x1e, 0x2, 0x8d, 0x7e, 0x3, 0x2, 0x2, 
    0x2, 0x8d, 0x7f, 0x3, 0x2, 0x2, 0x2, 0x8d, 0x80, 0x3, 0x2, 0x2, 0x2, 
    0x8d, 0x81, 0x3, 0x2, 0x2, 0x2, 0x8d, 0x82, 0x3, 0x2, 0x2, 0x2, 0x8d, 
    0x83, 0x3, 0x2, 0x2, 0x2, 0x8d, 0x84, 0x3, 0x2, 0x2, 0x2, 0x8d, 0x85, 
    0x3, 0x2, 0x2, 0x2, 0x8d, 0x86, 0x3, 0x2, 0x2, 0x2, 0x8d, 0x87, 0x3, 
    0x2, 0x2, 0x2, 0x8d, 0x88, 0x3, 0x2, 0x2, 0x2, 0x8d, 0x89, 0x3, 0x2, 
    0x2, 0x2, 0x8d, 0x8a, 0x3, 0x2, 0x2, 0x2, 0x8d, 0x8b, 0x3, 0x2, 0x2, 
    0x2, 0x8d, 0x8c, 0x3, 0x2, 0x2, 0x2, 0x8e, 0x9, 0x3, 0x2, 0x2, 0x2, 
    0x8f, 0x91, 0x7, 0x9, 0x2, 0x2, 0x90, 0x92, 0x5, 0xc, 0x7, 0x2, 0x91, 
    0x90, 0x3, 0x2, 0x2, 0x2, 0x91, 0x92, 0x3, 0x2, 0x2, 0x2, 0x92, 0x93, 
    0x3, 0x2, 0x2, 0x2, 0x93, 0x94, 0x7, 0xa, 0x2, 0x2, 0x94, 0xb, 0x3, 
    0x2, 0x2, 0x2, 0x95, 0x97, 0x5, 0x8, 0x5, 0x2, 0x96, 0x95, 0x3, 0x2, 
    0x2, 0x2, 0x97, 0x98, 0x3, 0x2, 0x2, 0x2, 0x98, 0x96, 0x3, 0x2, 0x2, 
    0x2, 0x98, 0x99, 0x3, 0x2, 0x2, 0x2, 0x99, 0xd, 0x3, 0x2, 0x2, 0x2, 
    0x9a, 0x9b, 0x7, 0x41, 0x2, 0x2, 0x9b, 0x9c, 0x5, 0x10, 0x9, 0x2, 0x9c, 
    0x9d, 0x5, 0x6c, 0x37, 0x2, 0x9d, 0xa3, 0x3, 0x2, 0x2, 0x2, 0x9e, 0x9f, 
    0x7, 0x42, 0x2, 0x2, 0x9f, 0xa0, 0x5, 0x10, 0x9, 0x2, 0xa0, 0xa1, 0x5, 
    0x6c, 0x37, 0x2, 0xa1, 0xa3, 0x3, 0x2, 0x2, 0x2, 0xa2, 0x9a, 0x3, 0x2, 
    0x2, 0x2, 0xa2, 0x9e, 0x3, 0x2, 0x2, 0x2, 0xa3, 0xf, 0x3, 0x2, 0x2, 
    0x2, 0xa4, 0xa9, 0x5, 0x12, 0xa, 0x2, 0xa5, 0xa6, 0x7, 0xc, 0x2, 0x2, 
    0xa6, 0xa8, 0x5, 0x12, 0xa, 0x2, 0xa7, 0xa5, 0x3, 0x2, 0x2, 0x2, 0xa8, 
    0xab, 0x3, 0x2, 0x2, 0x2, 0xa9, 0xa7, 0x3, 0x2, 0x2, 0x2, 0xa9, 0xaa, 
    0x3, 0x2, 0x2, 0x2, 0xaa, 0x11, 0x3, 0x2, 0x2, 0x2, 0xab, 0xa9, 0x3, 
    0x2, 0x2, 0x2, 0xac, 0xae, 0x7, 0x64, 0x2, 0x2, 0xad, 0xaf, 0x5, 0x14, 
    0xb, 0x2, 0xae, 0xad, 0x3, 0x2, 0x2, 0x2, 0xae, 0xaf, 0x3, 0x2, 0x2, 
    0x2, 0xaf, 0x13, 0x3, 0x2, 0x2, 0x2, 0xb0, 0xb1, 0x7, 0xd, 0x2, 0x2, 
    0xb1, 0xb2, 0x5, 0x58, 0x2d, 0x2, 0xb2, 0x15, 0x3, 0x2, 0x2, 0x2, 0xb3, 
    0xb4, 0x7, 0xb, 0x2, 0x2, 0xb4, 0x17, 0x3, 0x2, 0x2, 0x2, 0xb5, 0xb6, 
    0x6, 0xd, 0x2, 0x2, 0xb6, 0xb7, 0x5, 0x56, 0x2c, 0x2, 0xb7, 0xb8, 0x5, 
    0x6c, 0x37, 0x2, 0xb8, 0x19, 0x3, 0x2, 0x2, 0x2, 0xb9, 0xba, 0x7, 0x50, 
    0x2, 0x2, 0xba, 0xbb, 0x7, 0x7, 0x2, 0x2, 0xbb, 0xbc, 0x5, 0x56, 0x2c, 
    0x2, 0xbc, 0xbd, 0x7, 0x8, 0x2, 0x2, 0xbd, 0xc0, 0x5, 0x8, 0x5, 0x2, 
    0xbe, 0xbf, 0x7, 0x3f, 0x2, 0x2, 0xbf, 0xc1, 0x5, 0x8, 0x5, 0x2, 0xc0, 
    0xbe, 0x3, 0x2, 0x2, 0x2, 0xc0, 0xc1, 0x3, 0x2, 0x2, 0x2, 0xc1, 0x1b, 
    0x3, 0x2, 0x2, 0x2, 0xc2, 0xc3, 0x7, 0x3b, 0x2, 0x2, 0xc3, 0xc4, 0x5, 
    0x8, 0x5, 0x2, 0xc4, 0xc5, 0x7, 0x4a, 0x2, 0x2, 0xc5, 0xc6, 0x7, 0x7, 
    0x2, 0x2, 0xc6, 0xc7, 0x5, 0x56, 0x2c, 0x2, 0xc7, 0xc8, 0x7, 0x8, 0x2, 
    0x2, 0xc8, 0xc9, 0x5, 0x6c, 0x37, 0x2, 0xc9, 0x118, 0x3, 0x2, 0x2, 0x2, 
    0xca, 0xcb, 0x7, 0x4a, 0x2, 0x2, 0xcb, 0xcc, 0x7, 0x7, 0x2, 0x2, 0xcc, 
    0xcd, 0x5, 0x56, 0x2c, 0x2, 0xcd, 0xce, 0x7, 0x8, 0x2, 0x2, 0xce, 0xcf, 
    0x5, 0x8, 0x5, 0x2, 0xcf, 0x118, 0x3, 0x2, 0x2, 0x2, 0xd0, 0xd1, 0x7, 
    0x48, 0x2, 0x2, 0xd1, 0xd3, 0x7, 0x7, 0x2, 0x2, 0xd2, 0xd4, 0x5, 0x56, 
    0x2c, 0x2, 0xd3, 0xd2, 0x3, 0x2, 0x2, 0x2, 0xd3, 0xd4, 0x3, 0x2, 0x2, 
    0x2, 0xd4, 0xd5, 0x3, 0x2, 0x2, 0x2, 0xd5, 0xd7, 0x7, 0xb, 0x2, 0x2, 
    0xd6, 0xd8, 0x5, 0x56, 0x2c, 0x2, 0xd7, 0xd6, 0x3, 0x2, 0x2, 0x2, 0xd7, 
    0xd8, 0x3, 0x2, 0x2, 0x2, 0xd8, 0xd9, 0x3, 0x2, 0x2, 0x2, 0xd9, 0xdb, 
    0x7, 0xb, 0x2, 0x2, 0xda, 0xdc, 0x5, 0x56, 0x2c, 0x2, 0xdb, 0xda, 0x3, 
    0x2, 0x2, 0x2, 0xdb, 0xdc, 0x3, 0x2, 0x2, 0x2, 0xdc, 0xdd, 0x3, 0x2, 
    0x2, 0x2, 0xdd, 0xde, 0x7, 0x8, 0x2, 0x2, 0xde, 0x118, 0x5, 0x8, 0x5, 
    0x2, 0xdf, 0xe0, 0x7, 0x48, 0x2, 0x2, 0xe0, 0xe1, 0x7, 0x7, 0x2, 0x2, 
    0xe1, 0xe2, 0x7, 0x41, 0x2, 0x2, 0xe2, 0xe3, 0x5, 0x10, 0x9, 0x2, 0xe3, 
    0xe5, 0x7, 0xb, 0x2, 0x2, 0xe4, 0xe6, 0x5, 0x56, 0x2c, 0x2, 0xe5, 0xe4, 
    0x3, 0x2, 0x2, 0x2, 0xe5, 0xe6, 0x3, 0x2, 0x2, 0x2, 0xe6, 0xe7, 0x3, 
    0x2, 0x2, 0x2, 0xe7, 0xe9, 0x7, 0xb, 0x2, 0x2, 0xe8, 0xea, 0x5, 0x56, 
    0x2c, 0x2, 0xe9, 0xe8, 0x3, 0x2, 0x2, 0x2, 0xe9, 0xea, 0x3, 0x2, 0x2, 
    0x2, 0xea, 0xeb, 0x3, 0x2, 0x2, 0x2, 0xeb, 0xec, 0x7, 0x8, 0x2, 0x2, 
    0xec, 0xed, 0x5, 0x8, 0x5, 0x2, 0xed, 0x118, 0x3, 0x2, 0x2, 0x2, 0xee, 
    0xef, 0x7, 0x48, 0x2, 0x2, 0xef, 0xf0, 0x7, 0x7, 0x2, 0x2, 0xf0, 0xf1, 
    0x7, 0x42, 0x2, 0x2, 0xf1, 0xf2, 0x5, 0x10, 0x9, 0x2, 0xf2, 0xf4, 0x7, 
    0xb, 0x2, 0x2, 0xf3, 0xf5, 0x5, 0x56, 0x2c, 0x2, 0xf4, 0xf3, 0x3, 0x2, 
    0x2, 0x2, 0xf4, 0xf5, 0x3, 0x2, 0x2, 0x2, 0xf5, 0xf6, 0x3, 0x2, 0x2, 
    0x2, 0xf6, 0xf8, 0x7, 0xb, 0x2, 0x2, 0xf7, 0xf9, 0x5, 0x56, 0x2c, 0x2, 
    0xf8, 0xf7, 0x3, 0x2, 0x2, 0x2, 0xf8, 0xf9, 0x3, 0x2, 0x2, 0x2, 0xf9, 
    0xfa, 0x3, 0x2, 0x2, 0x2, 0xfa, 0xfb, 0x7, 0x8, 0x2, 0x2, 0xfb, 0xfc, 
    0x5, 0x8, 0x5, 0x2, 0xfc, 0x118, 0x3, 0x2, 0x2, 0x2, 0xfd, 0xfe, 0x7, 
    0x48, 0x2, 0x2, 0xfe, 0xff, 0x7, 0x7, 0x2, 0x2, 0xff, 0x100, 0x5, 0x58, 
    0x2d, 0x2, 0x100, 0x101, 0x7, 0x53, 0x2, 0x2, 0x101, 0x102, 0x5, 0x56, 
    0x2c, 0x2, 0x102, 0x103, 0x7, 0x8, 0x2, 0x2, 0x103, 0x104, 0x5, 0x8, 
    0x5, 0x2, 0x104, 0x118, 0x3, 0x2, 0x2, 0x2, 0x105, 0x106, 0x7, 0x48, 
    0x2, 0x2, 0x106, 0x107, 0x7, 0x7, 0x2, 0x2, 0x107, 0x108, 0x7, 0x41, 
    0x2, 0x2, 0x108, 0x109, 0x5, 0x12, 0xa, 0x2, 0x109, 0x10a, 0x7, 0x53, 
    0x2, 0x2, 0x10a, 0x10b, 0x5, 0x56, 0x2c, 0x2, 0x10b, 0x10c, 0x7, 0x8, 
    0x2, 0x2, 0x10c, 0x10d, 0x5, 0x8, 0x5, 0x2, 0x10d, 0x118, 0x3, 0x2, 
    0x2, 0x2, 0x10e, 0x10f, 0x7, 0x48, 0x2, 0x2, 0x10f, 0x110, 0x7, 0x7, 
    0x2, 0x2, 0x110, 0x111, 0x7, 0x42, 0x2, 0x2, 0x111, 0x112, 0x5, 0x12, 
    0xa, 0x2, 0x112, 0x113, 0x7, 0x53, 0x2, 0x2, 0x113, 0x114, 0x5, 0x56, 
    0x2c, 0x2, 0x114, 0x115, 0x7, 0x8, 0x2, 0x2, 0x115, 0x116, 0x5, 0x8, 
    0x5, 0x2, 0x116, 0x118, 0x3, 0x2, 0x2, 0x2, 0x117, 0xc2, 0x3, 0x2, 0x2, 
    0x2, 0x117, 0xca, 0x3, 0x2, 0x2, 0x2, 0x117, 0xd0, 0x3, 0x2, 0x2, 0x2, 
    0x117, 0xdf, 0x3, 0x2, 0x2, 0x2, 0x117, 0xee, 0x3, 0x2, 0x2, 0x2, 0x117, 
    0xfd, 0x3, 0x2, 0x2, 0x2, 0x117, 0x105, 0x3, 0x2, 0x2, 0x2, 0x117, 0x10e, 
    0x3, 0x2, 0x2, 0x2, 0x118, 0x1d, 0x3, 0x2, 0x2, 0x2, 0x119, 0x11c, 0x7, 
    0x47, 0x2, 0x2, 0x11a, 0x11b, 0x6, 0x10, 0x3, 0x2, 0x11b, 0x11d, 0x7, 
    0x64, 0x2, 0x2, 0x11c, 0x11a, 0x3, 0x2, 0x2, 0x2, 0x11c, 0x11d, 0x3, 
    0x2, 0x2, 0x2, 0x11d, 0x11e, 0x3, 0x2, 0x2, 0x2, 0x11e, 0x11f, 0x5, 
    0x6c, 0x37, 0x2, 0x11f, 0x1f, 0x3, 0x2, 0x2, 0x2, 0x120, 0x123, 0x7, 
    0x3a, 0x2, 0x2, 0x121, 0x122, 0x6, 0x11, 0x4, 0x2, 0x122, 0x124, 0x7, 
    0x64, 0x2, 0x2, 0x123, 0x121, 0x3, 0x2, 0x2, 0x2, 0x123, 0x124, 0x3, 
    0x2, 0x2, 0x2, 0x124, 0x125, 0x3, 0x2, 0x2, 0x2, 0x125, 0x126, 0x5, 
    0x6c, 0x37, 0x2, 0x126, 0x21, 0x3, 0x2, 0x2, 0x2, 0x127, 0x12a, 0x7, 
    0x45, 0x2, 0x2, 0x128, 0x129, 0x6, 0x12, 0x5, 0x2, 0x129, 0x12b, 0x5, 
    0x56, 0x2c, 0x2, 0x12a, 0x128, 0x3, 0x2, 0x2, 0x2, 0x12a, 0x12b, 0x3, 
    0x2, 0x2, 0x2, 0x12b, 0x12c, 0x3, 0x2, 0x2, 0x2, 0x12c, 0x12d, 0x5, 
    0x6c, 0x37, 0x2, 0x12d, 0x23, 0x3, 0x2, 0x2, 0x2, 0x12e, 0x12f, 0x7, 
    0x4e, 0x2, 0x2, 0x12f, 0x130, 0x7, 0x7, 0x2, 0x2, 0x130, 0x131, 0x5, 
    0x56, 0x2c, 0x2, 0x131, 0x132, 0x7, 0x8, 0x2, 0x2, 0x132, 0x133, 0x5, 
    0x8, 0x5, 0x2, 0x133, 0x25, 0x3, 0x2, 0x2, 0x2, 0x134, 0x135, 0x7, 0x49, 
    0x2, 0x2, 0x135, 0x136, 0x7, 0x7, 0x2, 0x2, 0x136, 0x137, 0x5, 0x56, 
    0x2c, 0x2, 0x137, 0x138, 0x7, 0x8, 0x2, 0x2, 0x138, 0x139, 0x5, 0x28, 
    0x15, 0x2, 0x139, 0x27, 0x3, 0x2, 0x2, 0x2, 0x13a, 0x13c, 0x7, 0x9, 
    0x2, 0x2, 0x13b, 0x13d, 0x5, 0x2a, 0x16, 0x2, 0x13c, 0x13b, 0x3, 0x2, 
    0x2, 0x2, 0x13c, 0x13d, 0x3, 0x2, 0x2, 0x2, 0x13d, 0x142, 0x3, 0x2, 
    0x2, 0x2, 0x13e, 0x140, 0x5, 0x2e, 0x18, 0x2, 0x13f, 0x141, 0x5, 0x2a, 
    0x16, 0x2, 0x140, 0x13f, 0x3, 0x2, 0x2, 0x2, 0x140, 0x141, 0x3, 0x2, 
    0x2, 0x2, 0x141, 0x143, 0x3, 0x2, 0x2, 0x2, 0x142, 0x13e, 0x3, 0x2, 
    0x2, 0x2, 0x142, 0x143, 0x3, 0x2, 0x2, 0x2, 0x143, 0x144, 0x3, 0x2, 
    0x2, 0x2, 0x144, 0x145, 0x7, 0xa, 0x2, 0x2, 0x145, 0x29, 0x3, 0x2, 0x2, 
    0x2, 0x146, 0x148, 0x5, 0x2c, 0x17, 0x2, 0x147, 0x146, 0x3, 0x2, 0x2, 
    0x2, 0x148, 0x149, 0x3, 0x2, 0x2, 0x2, 0x149, 0x147, 0x3, 0x2, 0x2, 
    0x2, 0x149, 0x14a, 0x3, 0x2, 0x2, 0x2, 0x14a, 0x2b, 0x3, 0x2, 0x2, 0x2, 
    0x14b, 0x14c, 0x7, 0x3e, 0x2, 0x2, 0x14c, 0x14d, 0x5, 0x56, 0x2c, 0x2, 
    0x14d, 0x14f, 0x7, 0xf, 0x2, 0x2, 0x14e, 0x150, 0x5, 0xc, 0x7, 0x2, 
    0x14f, 0x14e, 0x3, 0x2, 0x2, 0x2, 0x14f, 0x150, 0x3, 0x2, 0x2, 0x2, 
    0x150, 0x2d, 0x3, 0x2, 0x2, 0x2, 0x151, 0x152, 0x7, 0x4f, 0x2, 0x2, 
    0x152, 0x154, 0x7, 0xf, 0x2, 0x2, 0x153, 0x155, 0x5, 0xc, 0x7, 0x2, 
    0x154, 0x153, 0x3, 0x2, 0x2, 0x2, 0x154, 0x155, 0x3, 0x2, 0x2, 0x2, 
    0x155, 0x2f, 0x3, 0x2, 0x2, 0x2, 0x156, 0x157, 0x7, 0x64, 0x2, 0x2, 
    0x157, 0x158, 0x7, 0xf, 0x2, 0x2, 0x158, 0x159, 0x5, 0x8, 0x5, 0x2, 
    0x159, 0x31, 0x3, 0x2, 0x2, 0x2, 0x15a, 0x15b, 0x7, 0x51, 0x2, 0x2, 
    0x15b, 0x15c, 0x6, 0x1a, 0x6, 0x2, 0x15c, 0x15d, 0x5, 0x56, 0x2c, 0x2, 
    0x15d, 0x15e, 0x5, 0x6c, 0x37, 0x2, 0x15e, 0x33, 0x3, 0x2, 0x2, 0x2, 
    0x15f, 0x160, 0x7, 0x54, 0x2, 0x2, 0x160, 0x161, 0x5, 0xa, 0x6, 0x2, 
    0x161, 0x162, 0x5, 0x36, 0x1c, 0x2, 0x162, 0x16d, 0x3, 0x2, 0x2, 0x2, 
    0x163, 0x164, 0x7, 0x54, 0x2, 0x2, 0x164, 0x165, 0x5, 0xa, 0x6, 0x2, 
    0x165, 0x166, 0x5, 0x38, 0x1d, 0x2, 0x166, 0x16d, 0x3, 0x2, 0x2, 0x2, 
    0x167, 0x168, 0x7, 0x54, 0x2, 0x2, 0x168, 0x169, 0x5, 0xa, 0x6, 0x2, 
    0x169, 0x16a, 0x5, 0x36, 0x1c, 0x2, 0x16a, 0x16b, 0x5, 0x38, 0x1d, 0x2, 
    0x16b, 0x16d, 0x3, 0x2, 0x2, 0x2, 0x16c, 0x15f, 0x3, 0x2, 0x2, 0x2, 
    0x16c, 0x163, 0x3, 0x2, 0x2, 0x2, 0x16c, 0x167, 0x3, 0x2, 0x2, 0x2, 
    0x16d, 0x35, 0x3, 0x2, 0x2, 0x2, 0x16e, 0x16f, 0x7, 0x43, 0x2, 0x2, 
    0x16f, 0x170, 0x7, 0x7, 0x2, 0x2, 0x170, 0x171, 0x7, 0x64, 0x2, 0x2, 
    0x171, 0x172, 0x7, 0x8, 0x2, 0x2, 0x172, 0x173, 0x5, 0xa, 0x6, 0x2, 
    0x173, 0x37, 0x3, 0x2, 0x2, 0x2, 0x174, 0x175, 0x7, 0x44, 0x2, 0x2, 
    0x175, 0x176, 0x5, 0xa, 0x6, 0x2, 0x176, 0x39, 0x3, 0x2, 0x2, 0x2, 0x177, 
    0x178, 0x7, 0x4b, 0x2, 0x2, 0x178, 0x179, 0x5, 0x6c, 0x37, 0x2, 0x179, 
    0x3b, 0x3, 0x2, 0x2, 0x2, 0x17a, 0x17b, 0x7, 0x4c, 0x2, 0x2, 0x17b, 
    0x17c, 0x7, 0x64, 0x2, 0x2, 0x17c, 0x17e, 0x7, 0x7, 0x2, 0x2, 0x17d, 
    0x17f, 0x5, 0x3e, 0x20, 0x2, 0x17e, 0x17d, 0x3, 0x2, 0x2, 0x2, 0x17e, 
    0x17f, 0x3, 0x2, 0x2, 0x2, 0x17f, 0x180, 0x3, 0x2, 0x2, 0x2, 0x180, 
    0x181, 0x7, 0x8, 0x2, 0x2, 0x181, 0x182, 0x7, 0x9, 0x2, 0x2, 0x182, 
    0x183, 0x5, 0x40, 0x21, 0x2, 0x183, 0x184, 0x7, 0xa, 0x2, 0x2, 0x184, 
    0x3d, 0x3, 0x2, 0x2, 0x2, 0x185, 0x18a, 0x7, 0x64, 0x2, 0x2, 0x186, 
    0x187, 0x7, 0xc, 0x2, 0x2, 0x187, 0x189, 0x7, 0x64, 0x2, 0x2, 0x188, 
    0x186, 0x3, 0x2, 0x2, 0x2, 0x189, 0x18c, 0x3, 0x2, 0x2, 0x2, 0x18a, 
    0x188, 0x3, 0x2, 0x2, 0x2, 0x18a, 0x18b, 0x3, 0x2, 0x2, 0x2, 0x18b, 
    0x3f, 0x3, 0x2, 0x2, 0x2, 0x18c, 0x18a, 0x3, 0x2, 0x2, 0x2, 0x18d, 0x18f, 
    0x5, 0x4, 0x3, 0x2, 0x18e, 0x18d, 0x3, 0x2, 0x2, 0x2, 0x18e, 0x18f, 
    0x3, 0x2, 0x2, 0x2, 0x18f, 0x41, 0x3, 0x2, 0x2, 0x2, 0x190, 0x192, 0x7, 
    0x5, 0x2, 0x2, 0x191, 0x193, 0x5, 0x44, 0x23, 0x2, 0x192, 0x191, 0x3, 
    0x2, 0x2, 0x2, 0x192, 0x193, 0x3, 0x2, 0x2, 0x2, 0x193, 0x195, 0x3, 
    0x2, 0x2, 0x2, 0x194, 0x196, 0x7, 0xc, 0x2, 0x2, 0x195, 0x194, 0x3, 
    0x2, 0x2, 0x2, 0x195, 0x196, 0x3, 0x2, 0x2, 0x2, 0x196, 0x198, 0x3, 
    0x2, 0x2, 0x2, 0x197, 0x199, 0x5, 0x46, 0x24, 0x2, 0x198, 0x197, 0x3, 
    0x2, 0x2, 0x2, 0x198, 0x199, 0x3, 0x2, 0x2, 0x2, 0x199, 0x19a, 0x3, 
    0x2, 0x2, 0x2, 0x19a, 0x19b, 0x7, 0x6, 0x2, 0x2, 0x19b, 0x43, 0x3, 0x2, 
    0x2, 0x2, 0x19c, 0x19e, 0x5, 0x46, 0x24, 0x2, 0x19d, 0x19c, 0x3, 0x2, 
    0x2, 0x2, 0x19d, 0x19e, 0x3, 0x2, 0x2, 0x2, 0x19e, 0x19f, 0x3, 0x2, 
    0x2, 0x2, 0x19f, 0x1a7, 0x5, 0x58, 0x2d, 0x2, 0x1a0, 0x1a2, 0x7, 0xc, 
    0x2, 0x2, 0x1a1, 0x1a3, 0x5, 0x46, 0x24, 0x2, 0x1a2, 0x1a1, 0x3, 0x2, 
    0x2, 0x2, 0x1a2, 0x1a3, 0x3, 0x2, 0x2, 0x2, 0x1a3, 0x1a4, 0x3, 0x2, 
    0x2, 0x2, 0x1a4, 0x1a6, 0x5, 0x58, 0x2d, 0x2, 0x1a5, 0x1a0, 0x3, 0x2, 
    0x2, 0x2, 0x1a6, 0x1a9, 0x3, 0x2, 0x2, 0x2, 0x1a7, 0x1a5, 0x3, 0x2, 
    0x2, 0x2, 0x1a7, 0x1a8, 0x3, 0x2, 0x2, 0x2, 0x1a8, 0x45, 0x3, 0x2, 0x2, 
    0x2, 0x1a9, 0x1a7, 0x3, 0x2, 0x2, 0x2, 0x1aa, 0x1ac, 0x7, 0xc, 0x2, 
    0x2, 0x1ab, 0x1aa, 0x3, 0x2, 0x2, 0x2, 0x1ac, 0x1ad, 0x3, 0x2, 0x2, 
    0x2, 0x1ad, 0x1ab, 0x3, 0x2, 0x2, 0x2, 0x1ad, 0x1ae, 0x3, 0x2, 0x2, 
    0x2, 0x1ae, 0x47, 0x3, 0x2, 0x2, 0x2, 0x1af, 0x1b1, 0x7, 0x9, 0x2, 0x2, 
    0x1b0, 0x1b2, 0x5, 0x4a, 0x26, 0x2, 0x1b1, 0x1b0, 0x3, 0x2, 0x2, 0x2, 
    0x1b1, 0x1b2, 0x3, 0x2, 0x2, 0x2, 0x1b2, 0x1b4, 0x3, 0x2, 0x2, 0x2, 
    0x1b3, 0x1b5, 0x7, 0xc, 0x2, 0x2, 0x1b4, 0x1b3, 0x3, 0x2, 0x2, 0x2, 
    0x1b4, 0x1b5, 0x3, 0x2, 0x2, 0x2, 0x1b5, 0x1b6, 0x3, 0x2, 0x2, 0x2, 
    0x1b6, 0x1b7, 0x7, 0xa, 0x2, 0x2, 0x1b7, 0x49, 0x3, 0x2, 0x2, 0x2, 0x1b8, 
    0x1bd, 0x5, 0x4c, 0x27, 0x2, 0x1b9, 0x1ba, 0x7, 0xc, 0x2, 0x2, 0x1ba, 
    0x1bc, 0x5, 0x4c, 0x27, 0x2, 0x1bb, 0x1b9, 0x3, 0x2, 0x2, 0x2, 0x1bc, 
    0x1bf, 0x3, 0x2, 0x2, 0x2, 0x1bd, 0x1bb, 0x3, 0x2, 0x2, 0x2, 0x1bd, 
    0x1be, 0x3, 0x2, 0x2, 0x2, 0x1be, 0x4b, 0x3, 0x2, 0x2, 0x2, 0x1bf, 0x1bd, 
    0x3, 0x2, 0x2, 0x2, 0x1c0, 0x1c1, 0x5, 0x4e, 0x28, 0x2, 0x1c1, 0x1c2, 
    0x7, 0xf, 0x2, 0x2, 0x1c2, 0x1c3, 0x5, 0x58, 0x2d, 0x2, 0x1c3, 0x1d4, 
    0x3, 0x2, 0x2, 0x2, 0x1c4, 0x1c5, 0x5, 0x68, 0x35, 0x2, 0x1c5, 0x1c6, 
    0x7, 0x7, 0x2, 0x2, 0x1c6, 0x1c7, 0x7, 0x8, 0x2, 0x2, 0x1c7, 0x1c8, 
    0x7, 0x9, 0x2, 0x2, 0x1c8, 0x1c9, 0x5, 0x40, 0x21, 0x2, 0x1c9, 0x1ca, 
    0x7, 0xa, 0x2, 0x2, 0x1ca, 0x1d4, 0x3, 0x2, 0x2, 0x2, 0x1cb, 0x1cc, 
    0x5, 0x6a, 0x36, 0x2, 0x1cc, 0x1cd, 0x7, 0x7, 0x2, 0x2, 0x1cd, 0x1ce, 
    0x5, 0x50, 0x29, 0x2, 0x1ce, 0x1cf, 0x7, 0x8, 0x2, 0x2, 0x1cf, 0x1d0, 
    0x7, 0x9, 0x2, 0x2, 0x1d0, 0x1d1, 0x5, 0x40, 0x21, 0x2, 0x1d1, 0x1d2, 
    0x7, 0xa, 0x2, 0x2, 0x1d2, 0x1d4, 0x3, 0x2, 0x2, 0x2, 0x1d3, 0x1c0, 
    0x3, 0x2, 0x2, 0x2, 0x1d3, 0x1c4, 0x3, 0x2, 0x2, 0x2, 0x1d3, 0x1cb, 
    0x3, 0x2, 0x2, 0x2, 0x1d4, 0x4d, 0x3, 0x2, 0x2, 0x2, 0x1d5, 0x1d9, 0x5, 
    0x60, 0x31, 0x2, 0x1d6, 0x1d9, 0x7, 0x65, 0x2, 0x2, 0x1d7, 0x1d9, 0x5, 
    0x5e, 0x30, 0x2, 0x1d8, 0x1d5, 0x3, 0x2, 0x2, 0x2, 0x1d8, 0x1d6, 0x3, 
    0x2, 0x2, 0x2, 0x1d8, 0x1d7, 0x3, 0x2, 0x2, 0x2, 0x1d9, 0x4f, 0x3, 0x2, 
    0x2, 0x2, 0x1da, 0x1db, 0x7, 0x64, 0x2, 0x2, 0x1db, 0x51, 0x3, 0x2, 
    0x2, 0x2, 0x1dc, 0x1de, 0x7, 0x7, 0x2, 0x2, 0x1dd, 0x1df, 0x5, 0x54, 
    0x2b, 0x2, 0x1de, 0x1dd, 0x3, 0x2, 0x2, 0x2, 0x1de, 0x1df, 0x3, 0x2, 
    0x2, 0x2, 0x1df, 0x1e0, 0x3, 0x2, 0x2, 0x2, 0x1e0, 0x1e1, 0x7, 0x8, 
    0x2, 0x2, 0x1e1, 0x53, 0x3, 0x2, 0x2, 0x2, 0x1e2, 0x1e7, 0x5, 0x58, 
    0x2d, 0x2, 0x1e3, 0x1e4, 0x7, 0xc, 0x2, 0x2, 0x1e4, 0x1e6, 0x5, 0x58, 
    0x2d, 0x2, 0x1e5, 0x1e3, 0x3, 0x2, 0x2, 0x2, 0x1e6, 0x1e9, 0x3, 0x2, 
    0x2, 0x2, 0x1e7, 0x1e5, 0x3, 0x2, 0x2, 0x2, 0x1e7, 0x1e8, 0x3, 0x2, 
    0x2, 0x2, 0x1e8, 0x55, 0x3, 0x2, 0x2, 0x2, 0x1e9, 0x1e7, 0x3, 0x2, 0x2, 
    0x2, 0x1ea, 0x1ef, 0x5, 0x58, 0x2d, 0x2, 0x1eb, 0x1ec, 0x7, 0xc, 0x2, 
    0x2, 0x1ec, 0x1ee, 0x5, 0x58, 0x2d, 0x2, 0x1ed, 0x1eb, 0x3, 0x2, 0x2, 
    0x2, 0x1ee, 0x1f1, 0x3, 0x2, 0x2, 0x2, 0x1ef, 0x1ed, 0x3, 0x2, 0x2, 
    0x2, 0x1ef, 0x1f0, 0x3, 0x2, 0x2, 0x2, 0x1f0, 0x57, 0x3, 0x2, 0x2, 0x2, 
    0x1f1, 0x1ef, 0x3, 0x2, 0x2, 0x2, 0x1f2, 0x1f3, 0x8, 0x2d, 0x1, 0x2, 
    0x1f3, 0x1f5, 0x7, 0x4c, 0x2, 0x2, 0x1f4, 0x1f6, 0x7, 0x64, 0x2, 0x2, 
    0x1f5, 0x1f4, 0x3, 0x2, 0x2, 0x2, 0x1f5, 0x1f6, 0x3, 0x2, 0x2, 0x2, 
    0x1f6, 0x1f7, 0x3, 0x2, 0x2, 0x2, 0x1f7, 0x1f9, 0x7, 0x7, 0x2, 0x2, 
    0x1f8, 0x1fa, 0x5, 0x3e, 0x20, 0x2, 0x1f9, 0x1f8, 0x3, 0x2, 0x2, 0x2, 
    0x1f9, 0x1fa, 0x3, 0x2, 0x2, 0x2, 0x1fa, 0x1fb, 0x3, 0x2, 0x2, 0x2, 
    0x1fb, 0x1fc, 0x7, 0x8, 0x2, 0x2, 0x1fc, 0x1fd, 0x7, 0x9, 0x2, 0x2, 
    0x1fd, 0x1fe, 0x5, 0x40, 0x21, 0x2, 0x1fe, 0x1ff, 0x7, 0xa, 0x2, 0x2, 
    0x1ff, 0x221, 0x3, 0x2, 0x2, 0x2, 0x200, 0x201, 0x7, 0x40, 0x2, 0x2, 
    0x201, 0x203, 0x5, 0x58, 0x2d, 0x2, 0x202, 0x204, 0x5, 0x52, 0x2a, 0x2, 
    0x203, 0x202, 0x3, 0x2, 0x2, 0x2, 0x203, 0x204, 0x3, 0x2, 0x2, 0x2, 
    0x204, 0x221, 0x3, 0x2, 0x2, 0x2, 0x205, 0x206, 0x7, 0x52, 0x2, 0x2, 
    0x206, 0x221, 0x5, 0x58, 0x2d, 0x20, 0x207, 0x208, 0x7, 0x46, 0x2, 0x2, 
    0x208, 0x221, 0x5, 0x58, 0x2d, 0x1f, 0x209, 0x20a, 0x7, 0x3d, 0x2, 0x2, 
    0x20a, 0x221, 0x5, 0x58, 0x2d, 0x1e, 0x20b, 0x20c, 0x7, 0x11, 0x2, 0x2, 
    0x20c, 0x221, 0x5, 0x58, 0x2d, 0x1d, 0x20d, 0x20e, 0x7, 0x12, 0x2, 0x2, 
    0x20e, 0x221, 0x5, 0x58, 0x2d, 0x1c, 0x20f, 0x210, 0x7, 0x13, 0x2, 0x2, 
    0x210, 0x221, 0x5, 0x58, 0x2d, 0x1b, 0x211, 0x212, 0x7, 0x14, 0x2, 0x2, 
    0x212, 0x221, 0x5, 0x58, 0x2d, 0x1a, 0x213, 0x214, 0x7, 0x15, 0x2, 0x2, 
    0x214, 0x221, 0x5, 0x58, 0x2d, 0x19, 0x215, 0x216, 0x7, 0x16, 0x2, 0x2, 
    0x216, 0x221, 0x5, 0x58, 0x2d, 0x18, 0x217, 0x221, 0x7, 0x4d, 0x2, 0x2, 
    0x218, 0x221, 0x7, 0x64, 0x2, 0x2, 0x219, 0x221, 0x5, 0x5c, 0x2f, 0x2, 
    0x21a, 0x221, 0x5, 0x42, 0x22, 0x2, 0x21b, 0x221, 0x5, 0x48, 0x25, 0x2, 
    0x21c, 0x21d, 0x7, 0x7, 0x2, 0x2, 0x21d, 0x21e, 0x5, 0x56, 0x2c, 0x2, 
    0x21e, 0x21f, 0x7, 0x8, 0x2, 0x2, 0x21f, 0x221, 0x3, 0x2, 0x2, 0x2, 
    0x220, 0x1f2, 0x3, 0x2, 0x2, 0x2, 0x220, 0x200, 0x3, 0x2, 0x2, 0x2, 
    0x220, 0x205, 0x3, 0x2, 0x2, 0x2, 0x220, 0x207, 0x3, 0x2, 0x2, 0x2, 
    0x220, 0x209, 0x3, 0x2, 0x2, 0x2, 0x220, 0x20b, 0x3, 0x2, 0x2, 0x2, 
    0x220, 0x20d, 0x3, 0x2, 0x2, 0x2, 0x220, 0x20f, 0x3, 0x2, 0x2, 0x2, 
    0x220, 0x211, 0x3, 0x2, 0x2, 0x2, 0x220, 0x213, 0x3, 0x2, 0x2, 0x2, 
    0x220, 0x215, 0x3, 0x2, 0x2, 0x2, 0x220, 0x217, 0x3, 0x2, 0x2, 0x2, 
    0x220, 0x218, 0x3, 0x2, 0x2, 0x2, 0x220, 0x219, 0x3, 0x2, 0x2, 0x2, 
    0x220, 0x21a, 0x3, 0x2, 0x2, 0x2, 0x220, 0x21b, 0x3, 0x2, 0x2, 0x2, 
    0x220, 0x21c, 0x3, 0x2, 0x2, 0x2, 0x221, 0x265, 0x3, 0x2, 0x2, 0x2, 
    0x222, 0x223, 0xc, 0x17, 0x2, 0x2, 0x223, 0x224, 0x9, 0x2, 0x2, 0x2, 
    0x224, 0x264, 0x5, 0x58, 0x2d, 0x18, 0x225, 0x226, 0xc, 0x16, 0x2, 0x2, 
    0x226, 0x227, 0x9, 0x3, 0x2, 0x2, 0x227, 0x264, 0x5, 0x58, 0x2d, 0x17, 
    0x228, 0x229, 0xc, 0x15, 0x2, 0x2, 0x229, 0x22a, 0x9, 0x4, 0x2, 0x2, 
    0x22a, 0x264, 0x5, 0x58, 0x2d, 0x16, 0x22b, 0x22c, 0xc, 0x14, 0x2, 0x2, 
    0x22c, 0x22d, 0x9, 0x5, 0x2, 0x2, 0x22d, 0x264, 0x5, 0x58, 0x2d, 0x15, 
    0x22e, 0x22f, 0xc, 0x13, 0x2, 0x2, 0x22f, 0x230, 0x7, 0x3c, 0x2, 0x2, 
    0x230, 0x264, 0x5, 0x58, 0x2d, 0x14, 0x231, 0x232, 0xc, 0x12, 0x2, 0x2, 
    0x232, 0x233, 0x7, 0x53, 0x2, 0x2, 0x233, 0x264, 0x5, 0x58, 0x2d, 0x13, 
    0x234, 0x235, 0xc, 0x11, 0x2, 0x2, 0x235, 0x236, 0x9, 0x6, 0x2, 0x2, 
    0x236, 0x264, 0x5, 0x58, 0x2d, 0x12, 0x237, 0x238, 0xc, 0x10, 0x2, 0x2, 
    0x238, 0x239, 0x7, 0x25, 0x2, 0x2, 0x239, 0x264, 0x5, 0x58, 0x2d, 0x11, 
    0x23a, 0x23b, 0xc, 0xf, 0x2, 0x2, 0x23b, 0x23c, 0x7, 0x26, 0x2, 0x2, 
    0x23c, 0x264, 0x5, 0x58, 0x2d, 0x10, 0x23d, 0x23e, 0xc, 0xe, 0x2, 0x2, 
    0x23e, 0x23f, 0x7, 0x27, 0x2, 0x2, 0x23f, 0x264, 0x5, 0x58, 0x2d, 0xf, 
    0x240, 0x241, 0xc, 0xd, 0x2, 0x2, 0x241, 0x242, 0x7, 0x28, 0x2, 0x2, 
    0x242, 0x264, 0x5, 0x58, 0x2d, 0xe, 0x243, 0x244, 0xc, 0xc, 0x2, 0x2, 
    0x244, 0x245, 0x7, 0x29, 0x2, 0x2, 0x245, 0x264, 0x5, 0x58, 0x2d, 0xd, 
    0x246, 0x247, 0xc, 0xb, 0x2, 0x2, 0x247, 0x248, 0x7, 0xe, 0x2, 0x2, 
    0x248, 0x249, 0x5, 0x58, 0x2d, 0x2, 0x249, 0x24a, 0x7, 0xf, 0x2, 0x2, 
    0x24a, 0x24b, 0x5, 0x58, 0x2d, 0xc, 0x24b, 0x264, 0x3, 0x2, 0x2, 0x2, 
    0x24c, 0x24d, 0xc, 0xa, 0x2, 0x2, 0x24d, 0x24e, 0x7, 0xd, 0x2, 0x2, 
    0x24e, 0x264, 0x5, 0x58, 0x2d, 0xb, 0x24f, 0x250, 0xc, 0x9, 0x2, 0x2, 
    0x250, 0x251, 0x5, 0x5a, 0x2e, 0x2, 0x251, 0x252, 0x5, 0x58, 0x2d, 0xa, 
    0x252, 0x264, 0x3, 0x2, 0x2, 0x2, 0x253, 0x254, 0xc, 0x26, 0x2, 0x2, 
    0x254, 0x255, 0x7, 0x5, 0x2, 0x2, 0x255, 0x256, 0x5, 0x56, 0x2c, 0x2, 
    0x256, 0x257, 0x7, 0x6, 0x2, 0x2, 0x257, 0x264, 0x3, 0x2, 0x2, 0x2, 
    0x258, 0x259, 0xc, 0x25, 0x2, 0x2, 0x259, 0x25a, 0x7, 0x10, 0x2, 0x2, 
    0x25a, 0x264, 0x5, 0x60, 0x31, 0x2, 0x25b, 0x25c, 0xc, 0x24, 0x2, 0x2, 
    0x25c, 0x264, 0x5, 0x52, 0x2a, 0x2, 0x25d, 0x25e, 0xc, 0x22, 0x2, 0x2, 
    0x25e, 0x25f, 0x6, 0x2d, 0x1a, 0x2, 0x25f, 0x264, 0x7, 0x11, 0x2, 0x2, 
    0x260, 0x261, 0xc, 0x21, 0x2, 0x2, 0x261, 0x262, 0x6, 0x2d, 0x1c, 0x2, 
    0x262, 0x264, 0x7, 0x12, 0x2, 0x2, 0x263, 0x222, 0x3, 0x2, 0x2, 0x2, 
    0x263, 0x225, 0x3, 0x2, 0x2, 0x2, 0x263, 0x228, 0x3, 0x2, 0x2, 0x2, 
    0x263, 0x22b, 0x3, 0x2, 0x2, 0x2, 0x263, 0x22e, 0x3, 0x2, 0x2, 0x2, 
    0x263, 0x231, 0x3, 0x2, 0x2, 0x2, 0x263, 0x234, 0x3, 0x2, 0x2, 0x2, 
    0x263, 0x237, 0x3, 0x2, 0x2, 0x2, 0x263, 0x23a, 0x3, 0x2, 0x2, 0x2, 
    0x263, 0x23d, 0x3, 0x2, 0x2, 0x2, 0x263, 0x240, 0x3, 0x2, 0x2, 0x2, 
    0x263, 0x243, 0x3, 0x2, 0x2, 0x2, 0x263, 0x246, 0x3, 0x2, 0x2, 0x2, 
    0x263, 0x24c, 0x3, 0x2, 0x2, 0x2, 0x263, 0x24f, 0x3, 0x2, 0x2, 0x2, 
    0x263, 0x253, 0x3, 0x2, 0x2, 0x2, 0x263, 0x258, 0x3, 0x2, 0x2, 0x2, 
    0x263, 0x25b, 0x3, 0x2, 0x2, 0x2, 0x263, 0x25d, 0x3, 0x2, 0x2, 0x2, 
    0x263, 0x260, 0x3, 0x2, 0x2, 0x2, 0x264, 0x267, 0x3, 0x2, 0x2, 0x2, 
    0x265, 0x263, 0x3, 0x2, 0x2, 0x2, 0x265, 0x266, 0x3, 0x2, 0x2, 0x2, 
    0x266, 0x59, 0x3, 0x2, 0x2, 0x2, 0x267, 0x265, 0x3, 0x2, 0x2, 0x2, 0x268, 
    0x269, 0x9, 0x7, 0x2, 0x2, 0x269, 0x5b, 0x3, 0x2, 0x2, 0x2, 0x26a, 0x26d, 
    0x9, 0x8, 0x2, 0x2, 0x26b, 0x26d, 0x5, 0x5e, 0x30, 0x2, 0x26c, 0x26a, 
    0x3, 0x2, 0x2, 0x2, 0x26c, 0x26b, 0x3, 0x2, 0x2, 0x2, 0x26d, 0x5d, 0x3, 
    0x2, 0x2, 0x2, 0x26e, 0x26f, 0x9, 0x9, 0x2, 0x2, 0x26f, 0x5f, 0x3, 0x2, 
    0x2, 0x2, 0x270, 0x273, 0x7, 0x64, 0x2, 0x2, 0x271, 0x273, 0x5, 0x62, 
    0x32, 0x2, 0x272, 0x270, 0x3, 0x2, 0x2, 0x2, 0x272, 0x271, 0x3, 0x2, 
    0x2, 0x2, 0x273, 0x61, 0x3, 0x2, 0x2, 0x2, 0x274, 0x278, 0x5, 0x64, 
    0x33, 0x2, 0x275, 0x278, 0x5, 0x66, 0x34, 0x2, 0x276, 0x278, 0x9, 0xa, 
    0x2, 0x2, 0x277, 0x274, 0x3, 0x2, 0x2, 0x2, 0x277, 0x275, 0x3, 0x2, 
    0x2, 0x2, 0x277, 0x276, 0x3, 0x2, 0x2, 0x2, 0x278, 0x63, 0x3, 0x2, 0x2, 
    0x2, 0x279, 0x27a, 0x9, 0xb, 0x2, 0x2, 0x27a, 0x65, 0x3, 0x2, 0x2, 0x2, 
    0x27b, 0x27c, 0x9, 0xc, 0x2, 0x2, 0x27c, 0x67, 0x3, 0x2, 0x2, 0x2, 0x27d, 
    0x27e, 0x6, 0x35, 0x1d, 0x2, 0x27e, 0x27f, 0x7, 0x64, 0x2, 0x2, 0x27f, 
    0x280, 0x5, 0x4e, 0x28, 0x2, 0x280, 0x69, 0x3, 0x2, 0x2, 0x2, 0x281, 
    0x282, 0x6, 0x36, 0x1e, 0x2, 0x282, 0x283, 0x7, 0x64, 0x2, 0x2, 0x283, 
    0x284, 0x5, 0x4e, 0x28, 0x2, 0x284, 0x6b, 0x3, 0x2, 0x2, 0x2, 0x285, 
    0x28a, 0x7, 0xb, 0x2, 0x2, 0x286, 0x28a, 0x7, 0x2, 0x2, 0x3, 0x287, 
    0x28a, 0x6, 0x37, 0x1f, 0x2, 0x288, 0x28a, 0x6, 0x37, 0x20, 0x2, 0x289, 
    0x285, 0x3, 0x2, 0x2, 0x2, 0x289, 0x286, 0x3, 0x2, 0x2, 0x2, 0x289, 
    0x287, 0x3, 0x2, 0x2, 0x2, 0x289, 0x288, 0x3, 0x2, 0x2, 0x2, 0x28a, 
    0x6d, 0x3, 0x2, 0x2, 0x2, 0x28b, 0x28c, 0x7, 0x2, 0x2, 0x3, 0x28c, 0x6f, 
    0x3, 0x2, 0x2, 0x2, 0x3a, 0x71, 0x78, 0x7c, 0x8d, 0x91, 0x98, 0xa2, 
    0xa9, 0xae, 0xc0, 0xd3, 0xd7, 0xdb, 0xe5, 0xe9, 0xf4, 0xf8, 0x117, 0x11c, 
    0x123, 0x12a, 0x13c, 0x140, 0x142, 0x149, 0x14f, 0x154, 0x16c, 0x17e, 
    0x18a, 0x18e, 0x192, 0x195, 0x198, 0x19d, 0x1a2, 0x1a7, 0x1ad, 0x1b1, 
    0x1b4, 0x1bd, 0x1d3, 0x1d8, 0x1de, 0x1e7, 0x1ef, 0x1f5, 0x1f9, 0x203, 
    0x220, 0x263, 0x265, 0x26c, 0x272, 0x277, 0x289, 
  };

  atn::ATNDeserializer deserializer;
  _atn = deserializer.deserialize(_serializedATN);

  size_t count = _atn.getNumberOfDecisions();
  _decisionToDFA.reserve(count);
  for (size_t i = 0; i < count; i++) { 
    _decisionToDFA.emplace_back(_atn.getDecisionState(i), i);
  }
}

ECMAScriptParser::Initializer ECMAScriptParser::_init;
