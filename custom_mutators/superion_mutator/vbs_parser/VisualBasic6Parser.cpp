
// Generated from C:\Users\xiang\Desktop\vbs_parser\VisualBasic6.g4 by ANTLR 4.7


#include "VisualBasic6Visitor.h"

#include "VisualBasic6Parser.h"


using namespace antlrcpp;
using namespace antlr4;

VisualBasic6Parser::VisualBasic6Parser(TokenStream *input) : Parser(input) {
  _interpreter = new atn::ParserATNSimulator(this, _atn, _decisionToDFA, _sharedContextCache);
}

VisualBasic6Parser::~VisualBasic6Parser() {
  delete _interpreter;
}

std::string VisualBasic6Parser::getGrammarFileName() const {
  return "VisualBasic6.g4";
}

const std::vector<std::string>& VisualBasic6Parser::getRuleNames() const {
  return _ruleNames;
}

dfa::Vocabulary& VisualBasic6Parser::getVocabulary() const {
  return _vocabulary;
}


//----------------- StartRuleContext ------------------------------------------------------------------

VisualBasic6Parser::StartRuleContext::StartRuleContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::ModuleContext* VisualBasic6Parser::StartRuleContext::module() {
  return getRuleContext<VisualBasic6Parser::ModuleContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::StartRuleContext::EOF() {
  return getToken(VisualBasic6Parser::EOF, 0);
}


size_t VisualBasic6Parser::StartRuleContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleStartRule;
}

antlrcpp::Any VisualBasic6Parser::StartRuleContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitStartRule(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::StartRuleContext* VisualBasic6Parser::startRule() {
  StartRuleContext *_localctx = _tracker.createInstance<StartRuleContext>(_ctx, getState());
  enterRule(_localctx, 0, VisualBasic6Parser::RuleStartRule);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(310);
    module();
    setState(311);
    match(VisualBasic6Parser::EOF);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ModuleContext ------------------------------------------------------------------

VisualBasic6Parser::ModuleContext::ModuleContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ModuleContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ModuleContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ModuleContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::ModuleContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::ModuleHeaderContext* VisualBasic6Parser::ModuleContext::moduleHeader() {
  return getRuleContext<VisualBasic6Parser::ModuleHeaderContext>(0);
}

VisualBasic6Parser::ModuleReferencesContext* VisualBasic6Parser::ModuleContext::moduleReferences() {
  return getRuleContext<VisualBasic6Parser::ModuleReferencesContext>(0);
}

VisualBasic6Parser::ControlPropertiesContext* VisualBasic6Parser::ModuleContext::controlProperties() {
  return getRuleContext<VisualBasic6Parser::ControlPropertiesContext>(0);
}

VisualBasic6Parser::ModuleConfigContext* VisualBasic6Parser::ModuleContext::moduleConfig() {
  return getRuleContext<VisualBasic6Parser::ModuleConfigContext>(0);
}

VisualBasic6Parser::ModuleAttributesContext* VisualBasic6Parser::ModuleContext::moduleAttributes() {
  return getRuleContext<VisualBasic6Parser::ModuleAttributesContext>(0);
}

VisualBasic6Parser::ModuleOptionsContext* VisualBasic6Parser::ModuleContext::moduleOptions() {
  return getRuleContext<VisualBasic6Parser::ModuleOptionsContext>(0);
}

VisualBasic6Parser::ModuleBodyContext* VisualBasic6Parser::ModuleContext::moduleBody() {
  return getRuleContext<VisualBasic6Parser::ModuleBodyContext>(0);
}


size_t VisualBasic6Parser::ModuleContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleModule;
}

antlrcpp::Any VisualBasic6Parser::ModuleContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitModule(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ModuleContext* VisualBasic6Parser::module() {
  ModuleContext *_localctx = _tracker.createInstance<ModuleContext>(_ctx, getState());
  enterRule(_localctx, 2, VisualBasic6Parser::RuleModule);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(314);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 0, _ctx)) {
    case 1: {
      setState(313);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(319);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 1, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(316);
        match(VisualBasic6Parser::NEWLINE); 
      }
      setState(321);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 1, _ctx);
    }
    setState(328);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 3, _ctx)) {
    case 1: {
      setState(322);
      moduleHeader();
      setState(324); 
      _errHandler->sync(this);
      alt = 1;
      do {
        switch (alt) {
          case 1: {
                setState(323);
                match(VisualBasic6Parser::NEWLINE);
                break;
              }

        default:
          throw NoViableAltException(this);
        }
        setState(326); 
        _errHandler->sync(this);
        alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 2, _ctx);
      } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
      break;
    }

    }
    setState(331);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 4, _ctx)) {
    case 1: {
      setState(330);
      moduleReferences();
      break;
    }

    }
    setState(336);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 5, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(333);
        match(VisualBasic6Parser::NEWLINE); 
      }
      setState(338);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 5, _ctx);
    }
    setState(340);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 6, _ctx)) {
    case 1: {
      setState(339);
      controlProperties();
      break;
    }

    }
    setState(345);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 7, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(342);
        match(VisualBasic6Parser::NEWLINE); 
      }
      setState(347);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 7, _ctx);
    }
    setState(349);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 8, _ctx)) {
    case 1: {
      setState(348);
      moduleConfig();
      break;
    }

    }
    setState(354);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 9, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(351);
        match(VisualBasic6Parser::NEWLINE); 
      }
      setState(356);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 9, _ctx);
    }
    setState(358);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 10, _ctx)) {
    case 1: {
      setState(357);
      moduleAttributes();
      break;
    }

    }
    setState(363);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 11, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(360);
        match(VisualBasic6Parser::NEWLINE); 
      }
      setState(365);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 11, _ctx);
    }
    setState(367);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 12, _ctx)) {
    case 1: {
      setState(366);
      moduleOptions();
      break;
    }

    }
    setState(372);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 13, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(369);
        match(VisualBasic6Parser::NEWLINE); 
      }
      setState(374);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 13, _ctx);
    }
    setState(376);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 14, _ctx)) {
    case 1: {
      setState(375);
      moduleBody();
      break;
    }

    }
    setState(381);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == VisualBasic6Parser::NEWLINE) {
      setState(378);
      match(VisualBasic6Parser::NEWLINE);
      setState(383);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
    setState(385);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(384);
      match(VisualBasic6Parser::WS);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ModuleReferencesContext ------------------------------------------------------------------

VisualBasic6Parser::ModuleReferencesContext::ModuleReferencesContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<VisualBasic6Parser::ModuleReferenceContext *> VisualBasic6Parser::ModuleReferencesContext::moduleReference() {
  return getRuleContexts<VisualBasic6Parser::ModuleReferenceContext>();
}

VisualBasic6Parser::ModuleReferenceContext* VisualBasic6Parser::ModuleReferencesContext::moduleReference(size_t i) {
  return getRuleContext<VisualBasic6Parser::ModuleReferenceContext>(i);
}


size_t VisualBasic6Parser::ModuleReferencesContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleModuleReferences;
}

antlrcpp::Any VisualBasic6Parser::ModuleReferencesContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitModuleReferences(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ModuleReferencesContext* VisualBasic6Parser::moduleReferences() {
  ModuleReferencesContext *_localctx = _tracker.createInstance<ModuleReferencesContext>(_ctx, getState());
  enterRule(_localctx, 4, VisualBasic6Parser::RuleModuleReferences);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(388); 
    _errHandler->sync(this);
    alt = 1;
    do {
      switch (alt) {
        case 1: {
              setState(387);
              moduleReference();
              break;
            }

      default:
        throw NoViableAltException(this);
      }
      setState(390); 
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 17, _ctx);
    } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ModuleReferenceContext ------------------------------------------------------------------

VisualBasic6Parser::ModuleReferenceContext::ModuleReferenceContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ModuleReferenceContext::OBJECT() {
  return getToken(VisualBasic6Parser::OBJECT, 0);
}

tree::TerminalNode* VisualBasic6Parser::ModuleReferenceContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

VisualBasic6Parser::ModuleReferenceValueContext* VisualBasic6Parser::ModuleReferenceContext::moduleReferenceValue() {
  return getRuleContext<VisualBasic6Parser::ModuleReferenceValueContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ModuleReferenceContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ModuleReferenceContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

tree::TerminalNode* VisualBasic6Parser::ModuleReferenceContext::SEMICOLON() {
  return getToken(VisualBasic6Parser::SEMICOLON, 0);
}

VisualBasic6Parser::ModuleReferenceComponentContext* VisualBasic6Parser::ModuleReferenceContext::moduleReferenceComponent() {
  return getRuleContext<VisualBasic6Parser::ModuleReferenceComponentContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ModuleReferenceContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::ModuleReferenceContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}


size_t VisualBasic6Parser::ModuleReferenceContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleModuleReference;
}

antlrcpp::Any VisualBasic6Parser::ModuleReferenceContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitModuleReference(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ModuleReferenceContext* VisualBasic6Parser::moduleReference() {
  ModuleReferenceContext *_localctx = _tracker.createInstance<ModuleReferenceContext>(_ctx, getState());
  enterRule(_localctx, 6, VisualBasic6Parser::RuleModuleReference);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(392);
    match(VisualBasic6Parser::OBJECT);
    setState(394);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(393);
      match(VisualBasic6Parser::WS);
    }
    setState(396);
    match(VisualBasic6Parser::EQ);
    setState(398);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(397);
      match(VisualBasic6Parser::WS);
    }
    setState(400);
    moduleReferenceValue();
    setState(406);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::SEMICOLON) {
      setState(401);
      match(VisualBasic6Parser::SEMICOLON);
      setState(403);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(402);
        match(VisualBasic6Parser::WS);
      }
      setState(405);
      moduleReferenceComponent();
    }
    setState(411);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 22, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(408);
        match(VisualBasic6Parser::NEWLINE); 
      }
      setState(413);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 22, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ModuleReferenceValueContext ------------------------------------------------------------------

VisualBasic6Parser::ModuleReferenceValueContext::ModuleReferenceValueContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ModuleReferenceValueContext::STRINGLITERAL() {
  return getToken(VisualBasic6Parser::STRINGLITERAL, 0);
}


size_t VisualBasic6Parser::ModuleReferenceValueContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleModuleReferenceValue;
}

antlrcpp::Any VisualBasic6Parser::ModuleReferenceValueContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitModuleReferenceValue(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ModuleReferenceValueContext* VisualBasic6Parser::moduleReferenceValue() {
  ModuleReferenceValueContext *_localctx = _tracker.createInstance<ModuleReferenceValueContext>(_ctx, getState());
  enterRule(_localctx, 8, VisualBasic6Parser::RuleModuleReferenceValue);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(414);
    match(VisualBasic6Parser::STRINGLITERAL);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ModuleReferenceComponentContext ------------------------------------------------------------------

VisualBasic6Parser::ModuleReferenceComponentContext::ModuleReferenceComponentContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ModuleReferenceComponentContext::STRINGLITERAL() {
  return getToken(VisualBasic6Parser::STRINGLITERAL, 0);
}


size_t VisualBasic6Parser::ModuleReferenceComponentContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleModuleReferenceComponent;
}

antlrcpp::Any VisualBasic6Parser::ModuleReferenceComponentContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitModuleReferenceComponent(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ModuleReferenceComponentContext* VisualBasic6Parser::moduleReferenceComponent() {
  ModuleReferenceComponentContext *_localctx = _tracker.createInstance<ModuleReferenceComponentContext>(_ctx, getState());
  enterRule(_localctx, 10, VisualBasic6Parser::RuleModuleReferenceComponent);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(416);
    match(VisualBasic6Parser::STRINGLITERAL);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ModuleHeaderContext ------------------------------------------------------------------

VisualBasic6Parser::ModuleHeaderContext::ModuleHeaderContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ModuleHeaderContext::VERSION() {
  return getToken(VisualBasic6Parser::VERSION, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ModuleHeaderContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ModuleHeaderContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

tree::TerminalNode* VisualBasic6Parser::ModuleHeaderContext::DOUBLELITERAL() {
  return getToken(VisualBasic6Parser::DOUBLELITERAL, 0);
}

tree::TerminalNode* VisualBasic6Parser::ModuleHeaderContext::CLASS() {
  return getToken(VisualBasic6Parser::CLASS, 0);
}


size_t VisualBasic6Parser::ModuleHeaderContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleModuleHeader;
}

antlrcpp::Any VisualBasic6Parser::ModuleHeaderContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitModuleHeader(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ModuleHeaderContext* VisualBasic6Parser::moduleHeader() {
  ModuleHeaderContext *_localctx = _tracker.createInstance<ModuleHeaderContext>(_ctx, getState());
  enterRule(_localctx, 12, VisualBasic6Parser::RuleModuleHeader);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(418);
    match(VisualBasic6Parser::VERSION);
    setState(419);
    match(VisualBasic6Parser::WS);
    setState(420);
    match(VisualBasic6Parser::DOUBLELITERAL);
    setState(423);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(421);
      match(VisualBasic6Parser::WS);
      setState(422);
      match(VisualBasic6Parser::CLASS);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ModuleConfigContext ------------------------------------------------------------------

VisualBasic6Parser::ModuleConfigContext::ModuleConfigContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ModuleConfigContext::BEGIN() {
  return getToken(VisualBasic6Parser::BEGIN, 0);
}

tree::TerminalNode* VisualBasic6Parser::ModuleConfigContext::END() {
  return getToken(VisualBasic6Parser::END, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ModuleConfigContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::ModuleConfigContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

std::vector<VisualBasic6Parser::ModuleConfigElementContext *> VisualBasic6Parser::ModuleConfigContext::moduleConfigElement() {
  return getRuleContexts<VisualBasic6Parser::ModuleConfigElementContext>();
}

VisualBasic6Parser::ModuleConfigElementContext* VisualBasic6Parser::ModuleConfigContext::moduleConfigElement(size_t i) {
  return getRuleContext<VisualBasic6Parser::ModuleConfigElementContext>(i);
}


size_t VisualBasic6Parser::ModuleConfigContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleModuleConfig;
}

antlrcpp::Any VisualBasic6Parser::ModuleConfigContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitModuleConfig(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ModuleConfigContext* VisualBasic6Parser::moduleConfig() {
  ModuleConfigContext *_localctx = _tracker.createInstance<ModuleConfigContext>(_ctx, getState());
  enterRule(_localctx, 14, VisualBasic6Parser::RuleModuleConfig);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(425);
    match(VisualBasic6Parser::BEGIN);
    setState(427); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(426);
      match(VisualBasic6Parser::NEWLINE);
      setState(429); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(432); 
    _errHandler->sync(this);
    alt = 1;
    do {
      switch (alt) {
        case 1: {
              setState(431);
              moduleConfigElement();
              break;
            }

      default:
        throw NoViableAltException(this);
      }
      setState(434); 
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 25, _ctx);
    } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
    setState(436);
    match(VisualBasic6Parser::END);
    setState(438); 
    _errHandler->sync(this);
    alt = 1;
    do {
      switch (alt) {
        case 1: {
              setState(437);
              match(VisualBasic6Parser::NEWLINE);
              break;
            }

      default:
        throw NoViableAltException(this);
      }
      setState(440); 
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 26, _ctx);
    } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ModuleConfigElementContext ------------------------------------------------------------------

VisualBasic6Parser::ModuleConfigElementContext::ModuleConfigElementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::ModuleConfigElementContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ModuleConfigElementContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

VisualBasic6Parser::LiteralContext* VisualBasic6Parser::ModuleConfigElementContext::literal() {
  return getRuleContext<VisualBasic6Parser::LiteralContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ModuleConfigElementContext::NEWLINE() {
  return getToken(VisualBasic6Parser::NEWLINE, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ModuleConfigElementContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ModuleConfigElementContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}


size_t VisualBasic6Parser::ModuleConfigElementContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleModuleConfigElement;
}

antlrcpp::Any VisualBasic6Parser::ModuleConfigElementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitModuleConfigElement(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ModuleConfigElementContext* VisualBasic6Parser::moduleConfigElement() {
  ModuleConfigElementContext *_localctx = _tracker.createInstance<ModuleConfigElementContext>(_ctx, getState());
  enterRule(_localctx, 16, VisualBasic6Parser::RuleModuleConfigElement);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(442);
    ambiguousIdentifier();
    setState(444);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(443);
      match(VisualBasic6Parser::WS);
    }
    setState(446);
    match(VisualBasic6Parser::EQ);
    setState(448);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(447);
      match(VisualBasic6Parser::WS);
    }
    setState(450);
    literal();
    setState(451);
    match(VisualBasic6Parser::NEWLINE);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ModuleAttributesContext ------------------------------------------------------------------

VisualBasic6Parser::ModuleAttributesContext::ModuleAttributesContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<VisualBasic6Parser::AttributeStmtContext *> VisualBasic6Parser::ModuleAttributesContext::attributeStmt() {
  return getRuleContexts<VisualBasic6Parser::AttributeStmtContext>();
}

VisualBasic6Parser::AttributeStmtContext* VisualBasic6Parser::ModuleAttributesContext::attributeStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::AttributeStmtContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ModuleAttributesContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::ModuleAttributesContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}


size_t VisualBasic6Parser::ModuleAttributesContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleModuleAttributes;
}

antlrcpp::Any VisualBasic6Parser::ModuleAttributesContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitModuleAttributes(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ModuleAttributesContext* VisualBasic6Parser::moduleAttributes() {
  ModuleAttributesContext *_localctx = _tracker.createInstance<ModuleAttributesContext>(_ctx, getState());
  enterRule(_localctx, 18, VisualBasic6Parser::RuleModuleAttributes);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(459); 
    _errHandler->sync(this);
    alt = 1;
    do {
      switch (alt) {
        case 1: {
              setState(453);
              attributeStmt();
              setState(455); 
              _errHandler->sync(this);
              alt = 1;
              do {
                switch (alt) {
                  case 1: {
                        setState(454);
                        match(VisualBasic6Parser::NEWLINE);
                        break;
                      }

                default:
                  throw NoViableAltException(this);
                }
                setState(457); 
                _errHandler->sync(this);
                alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 29, _ctx);
              } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
              break;
            }

      default:
        throw NoViableAltException(this);
      }
      setState(461); 
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 30, _ctx);
    } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ModuleOptionsContext ------------------------------------------------------------------

VisualBasic6Parser::ModuleOptionsContext::ModuleOptionsContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<VisualBasic6Parser::ModuleOptionContext *> VisualBasic6Parser::ModuleOptionsContext::moduleOption() {
  return getRuleContexts<VisualBasic6Parser::ModuleOptionContext>();
}

VisualBasic6Parser::ModuleOptionContext* VisualBasic6Parser::ModuleOptionsContext::moduleOption(size_t i) {
  return getRuleContext<VisualBasic6Parser::ModuleOptionContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ModuleOptionsContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::ModuleOptionsContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}


size_t VisualBasic6Parser::ModuleOptionsContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleModuleOptions;
}

antlrcpp::Any VisualBasic6Parser::ModuleOptionsContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitModuleOptions(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ModuleOptionsContext* VisualBasic6Parser::moduleOptions() {
  ModuleOptionsContext *_localctx = _tracker.createInstance<ModuleOptionsContext>(_ctx, getState());
  enterRule(_localctx, 20, VisualBasic6Parser::RuleModuleOptions);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(469); 
    _errHandler->sync(this);
    alt = 1;
    do {
      switch (alt) {
        case 1: {
              setState(463);
              moduleOption();
              setState(465); 
              _errHandler->sync(this);
              alt = 1;
              do {
                switch (alt) {
                  case 1: {
                        setState(464);
                        match(VisualBasic6Parser::NEWLINE);
                        break;
                      }

                default:
                  throw NoViableAltException(this);
                }
                setState(467); 
                _errHandler->sync(this);
                alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 31, _ctx);
              } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
              break;
            }

      default:
        throw NoViableAltException(this);
      }
      setState(471); 
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 32, _ctx);
    } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ModuleOptionContext ------------------------------------------------------------------

VisualBasic6Parser::ModuleOptionContext::ModuleOptionContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}


size_t VisualBasic6Parser::ModuleOptionContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleModuleOption;
}

void VisualBasic6Parser::ModuleOptionContext::copyFrom(ModuleOptionContext *ctx) {
  ParserRuleContext::copyFrom(ctx);
}

//----------------- OptionExplicitStmtContext ------------------------------------------------------------------

tree::TerminalNode* VisualBasic6Parser::OptionExplicitStmtContext::OPTION_EXPLICIT() {
  return getToken(VisualBasic6Parser::OPTION_EXPLICIT, 0);
}

VisualBasic6Parser::OptionExplicitStmtContext::OptionExplicitStmtContext(ModuleOptionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::OptionExplicitStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitOptionExplicitStmt(this);
  else
    return visitor->visitChildren(this);
}
//----------------- OptionBaseStmtContext ------------------------------------------------------------------

tree::TerminalNode* VisualBasic6Parser::OptionBaseStmtContext::OPTION_BASE() {
  return getToken(VisualBasic6Parser::OPTION_BASE, 0);
}

tree::TerminalNode* VisualBasic6Parser::OptionBaseStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

tree::TerminalNode* VisualBasic6Parser::OptionBaseStmtContext::INTEGERLITERAL() {
  return getToken(VisualBasic6Parser::INTEGERLITERAL, 0);
}

VisualBasic6Parser::OptionBaseStmtContext::OptionBaseStmtContext(ModuleOptionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::OptionBaseStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitOptionBaseStmt(this);
  else
    return visitor->visitChildren(this);
}
//----------------- OptionPrivateModuleStmtContext ------------------------------------------------------------------

tree::TerminalNode* VisualBasic6Parser::OptionPrivateModuleStmtContext::OPTION_PRIVATE_MODULE() {
  return getToken(VisualBasic6Parser::OPTION_PRIVATE_MODULE, 0);
}

VisualBasic6Parser::OptionPrivateModuleStmtContext::OptionPrivateModuleStmtContext(ModuleOptionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::OptionPrivateModuleStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitOptionPrivateModuleStmt(this);
  else
    return visitor->visitChildren(this);
}
//----------------- OptionCompareStmtContext ------------------------------------------------------------------

tree::TerminalNode* VisualBasic6Parser::OptionCompareStmtContext::OPTION_COMPARE() {
  return getToken(VisualBasic6Parser::OPTION_COMPARE, 0);
}

tree::TerminalNode* VisualBasic6Parser::OptionCompareStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

tree::TerminalNode* VisualBasic6Parser::OptionCompareStmtContext::BINARY() {
  return getToken(VisualBasic6Parser::BINARY, 0);
}

tree::TerminalNode* VisualBasic6Parser::OptionCompareStmtContext::TEXT() {
  return getToken(VisualBasic6Parser::TEXT, 0);
}

VisualBasic6Parser::OptionCompareStmtContext::OptionCompareStmtContext(ModuleOptionContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::OptionCompareStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitOptionCompareStmt(this);
  else
    return visitor->visitChildren(this);
}
VisualBasic6Parser::ModuleOptionContext* VisualBasic6Parser::moduleOption() {
  ModuleOptionContext *_localctx = _tracker.createInstance<ModuleOptionContext>(_ctx, getState());
  enterRule(_localctx, 22, VisualBasic6Parser::RuleModuleOption);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(481);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case VisualBasic6Parser::OPTION_BASE: {
        _localctx = dynamic_cast<ModuleOptionContext *>(_tracker.createInstance<VisualBasic6Parser::OptionBaseStmtContext>(_localctx));
        enterOuterAlt(_localctx, 1);
        setState(473);
        match(VisualBasic6Parser::OPTION_BASE);
        setState(474);
        match(VisualBasic6Parser::WS);
        setState(475);
        match(VisualBasic6Parser::INTEGERLITERAL);
        break;
      }

      case VisualBasic6Parser::OPTION_COMPARE: {
        _localctx = dynamic_cast<ModuleOptionContext *>(_tracker.createInstance<VisualBasic6Parser::OptionCompareStmtContext>(_localctx));
        enterOuterAlt(_localctx, 2);
        setState(476);
        match(VisualBasic6Parser::OPTION_COMPARE);
        setState(477);
        match(VisualBasic6Parser::WS);
        setState(478);
        _la = _input->LA(1);
        if (!(_la == VisualBasic6Parser::BINARY || _la == VisualBasic6Parser::TEXT)) {
        _errHandler->recoverInline(this);
        }
        else {
          _errHandler->reportMatch(this);
          consume();
        }
        break;
      }

      case VisualBasic6Parser::OPTION_EXPLICIT: {
        _localctx = dynamic_cast<ModuleOptionContext *>(_tracker.createInstance<VisualBasic6Parser::OptionExplicitStmtContext>(_localctx));
        enterOuterAlt(_localctx, 3);
        setState(479);
        match(VisualBasic6Parser::OPTION_EXPLICIT);
        break;
      }

      case VisualBasic6Parser::OPTION_PRIVATE_MODULE: {
        _localctx = dynamic_cast<ModuleOptionContext *>(_tracker.createInstance<VisualBasic6Parser::OptionPrivateModuleStmtContext>(_localctx));
        enterOuterAlt(_localctx, 4);
        setState(480);
        match(VisualBasic6Parser::OPTION_PRIVATE_MODULE);
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

//----------------- ModuleBodyContext ------------------------------------------------------------------

VisualBasic6Parser::ModuleBodyContext::ModuleBodyContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<VisualBasic6Parser::ModuleBodyElementContext *> VisualBasic6Parser::ModuleBodyContext::moduleBodyElement() {
  return getRuleContexts<VisualBasic6Parser::ModuleBodyElementContext>();
}

VisualBasic6Parser::ModuleBodyElementContext* VisualBasic6Parser::ModuleBodyContext::moduleBodyElement(size_t i) {
  return getRuleContext<VisualBasic6Parser::ModuleBodyElementContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ModuleBodyContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::ModuleBodyContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}


size_t VisualBasic6Parser::ModuleBodyContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleModuleBody;
}

antlrcpp::Any VisualBasic6Parser::ModuleBodyContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitModuleBody(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ModuleBodyContext* VisualBasic6Parser::moduleBody() {
  ModuleBodyContext *_localctx = _tracker.createInstance<ModuleBodyContext>(_ctx, getState());
  enterRule(_localctx, 24, VisualBasic6Parser::RuleModuleBody);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(483);
    moduleBodyElement();
    setState(492);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 35, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(485); 
        _errHandler->sync(this);
        _la = _input->LA(1);
        do {
          setState(484);
          match(VisualBasic6Parser::NEWLINE);
          setState(487); 
          _errHandler->sync(this);
          _la = _input->LA(1);
        } while (_la == VisualBasic6Parser::NEWLINE);
        setState(489);
        moduleBodyElement(); 
      }
      setState(494);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 35, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ModuleBodyElementContext ------------------------------------------------------------------

VisualBasic6Parser::ModuleBodyElementContext::ModuleBodyElementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::ModuleBlockContext* VisualBasic6Parser::ModuleBodyElementContext::moduleBlock() {
  return getRuleContext<VisualBasic6Parser::ModuleBlockContext>(0);
}

VisualBasic6Parser::ModuleOptionContext* VisualBasic6Parser::ModuleBodyElementContext::moduleOption() {
  return getRuleContext<VisualBasic6Parser::ModuleOptionContext>(0);
}

VisualBasic6Parser::DeclareStmtContext* VisualBasic6Parser::ModuleBodyElementContext::declareStmt() {
  return getRuleContext<VisualBasic6Parser::DeclareStmtContext>(0);
}

VisualBasic6Parser::EnumerationStmtContext* VisualBasic6Parser::ModuleBodyElementContext::enumerationStmt() {
  return getRuleContext<VisualBasic6Parser::EnumerationStmtContext>(0);
}

VisualBasic6Parser::EventStmtContext* VisualBasic6Parser::ModuleBodyElementContext::eventStmt() {
  return getRuleContext<VisualBasic6Parser::EventStmtContext>(0);
}

VisualBasic6Parser::FunctionStmtContext* VisualBasic6Parser::ModuleBodyElementContext::functionStmt() {
  return getRuleContext<VisualBasic6Parser::FunctionStmtContext>(0);
}

VisualBasic6Parser::MacroIfThenElseStmtContext* VisualBasic6Parser::ModuleBodyElementContext::macroIfThenElseStmt() {
  return getRuleContext<VisualBasic6Parser::MacroIfThenElseStmtContext>(0);
}

VisualBasic6Parser::PropertyGetStmtContext* VisualBasic6Parser::ModuleBodyElementContext::propertyGetStmt() {
  return getRuleContext<VisualBasic6Parser::PropertyGetStmtContext>(0);
}

VisualBasic6Parser::PropertySetStmtContext* VisualBasic6Parser::ModuleBodyElementContext::propertySetStmt() {
  return getRuleContext<VisualBasic6Parser::PropertySetStmtContext>(0);
}

VisualBasic6Parser::PropertyLetStmtContext* VisualBasic6Parser::ModuleBodyElementContext::propertyLetStmt() {
  return getRuleContext<VisualBasic6Parser::PropertyLetStmtContext>(0);
}

VisualBasic6Parser::SubStmtContext* VisualBasic6Parser::ModuleBodyElementContext::subStmt() {
  return getRuleContext<VisualBasic6Parser::SubStmtContext>(0);
}

VisualBasic6Parser::TypeStmtContext* VisualBasic6Parser::ModuleBodyElementContext::typeStmt() {
  return getRuleContext<VisualBasic6Parser::TypeStmtContext>(0);
}


size_t VisualBasic6Parser::ModuleBodyElementContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleModuleBodyElement;
}

antlrcpp::Any VisualBasic6Parser::ModuleBodyElementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitModuleBodyElement(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ModuleBodyElementContext* VisualBasic6Parser::moduleBodyElement() {
  ModuleBodyElementContext *_localctx = _tracker.createInstance<ModuleBodyElementContext>(_ctx, getState());
  enterRule(_localctx, 26, VisualBasic6Parser::RuleModuleBodyElement);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(507);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 36, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(495);
      moduleBlock();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(496);
      moduleOption();
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(497);
      declareStmt();
      break;
    }

    case 4: {
      enterOuterAlt(_localctx, 4);
      setState(498);
      enumerationStmt();
      break;
    }

    case 5: {
      enterOuterAlt(_localctx, 5);
      setState(499);
      eventStmt();
      break;
    }

    case 6: {
      enterOuterAlt(_localctx, 6);
      setState(500);
      functionStmt();
      break;
    }

    case 7: {
      enterOuterAlt(_localctx, 7);
      setState(501);
      macroIfThenElseStmt();
      break;
    }

    case 8: {
      enterOuterAlt(_localctx, 8);
      setState(502);
      propertyGetStmt();
      break;
    }

    case 9: {
      enterOuterAlt(_localctx, 9);
      setState(503);
      propertySetStmt();
      break;
    }

    case 10: {
      enterOuterAlt(_localctx, 10);
      setState(504);
      propertyLetStmt();
      break;
    }

    case 11: {
      enterOuterAlt(_localctx, 11);
      setState(505);
      subStmt();
      break;
    }

    case 12: {
      enterOuterAlt(_localctx, 12);
      setState(506);
      typeStmt();
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

//----------------- ControlPropertiesContext ------------------------------------------------------------------

VisualBasic6Parser::ControlPropertiesContext::ControlPropertiesContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ControlPropertiesContext::BEGIN() {
  return getToken(VisualBasic6Parser::BEGIN, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ControlPropertiesContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ControlPropertiesContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::Cp_ControlTypeContext* VisualBasic6Parser::ControlPropertiesContext::cp_ControlType() {
  return getRuleContext<VisualBasic6Parser::Cp_ControlTypeContext>(0);
}

VisualBasic6Parser::Cp_ControlIdentifierContext* VisualBasic6Parser::ControlPropertiesContext::cp_ControlIdentifier() {
  return getRuleContext<VisualBasic6Parser::Cp_ControlIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ControlPropertiesContext::END() {
  return getToken(VisualBasic6Parser::END, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ControlPropertiesContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::ControlPropertiesContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

std::vector<VisualBasic6Parser::Cp_PropertiesContext *> VisualBasic6Parser::ControlPropertiesContext::cp_Properties() {
  return getRuleContexts<VisualBasic6Parser::Cp_PropertiesContext>();
}

VisualBasic6Parser::Cp_PropertiesContext* VisualBasic6Parser::ControlPropertiesContext::cp_Properties(size_t i) {
  return getRuleContext<VisualBasic6Parser::Cp_PropertiesContext>(i);
}


size_t VisualBasic6Parser::ControlPropertiesContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleControlProperties;
}

antlrcpp::Any VisualBasic6Parser::ControlPropertiesContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitControlProperties(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ControlPropertiesContext* VisualBasic6Parser::controlProperties() {
  ControlPropertiesContext *_localctx = _tracker.createInstance<ControlPropertiesContext>(_ctx, getState());
  enterRule(_localctx, 28, VisualBasic6Parser::RuleControlProperties);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(510);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(509);
      match(VisualBasic6Parser::WS);
    }
    setState(512);
    match(VisualBasic6Parser::BEGIN);
    setState(513);
    match(VisualBasic6Parser::WS);
    setState(514);
    cp_ControlType();
    setState(515);
    match(VisualBasic6Parser::WS);
    setState(516);
    cp_ControlIdentifier();
    setState(518);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(517);
      match(VisualBasic6Parser::WS);
    }
    setState(521); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(520);
      match(VisualBasic6Parser::NEWLINE);
      setState(523); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(526); 
    _errHandler->sync(this);
    alt = 1;
    do {
      switch (alt) {
        case 1: {
              setState(525);
              cp_Properties();
              break;
            }

      default:
        throw NoViableAltException(this);
      }
      setState(528); 
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 40, _ctx);
    } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
    setState(530);
    match(VisualBasic6Parser::END);
    setState(534);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 41, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(531);
        match(VisualBasic6Parser::NEWLINE); 
      }
      setState(536);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 41, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- Cp_PropertiesContext ------------------------------------------------------------------

VisualBasic6Parser::Cp_PropertiesContext::Cp_PropertiesContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::Cp_SinglePropertyContext* VisualBasic6Parser::Cp_PropertiesContext::cp_SingleProperty() {
  return getRuleContext<VisualBasic6Parser::Cp_SinglePropertyContext>(0);
}

VisualBasic6Parser::Cp_NestedPropertyContext* VisualBasic6Parser::Cp_PropertiesContext::cp_NestedProperty() {
  return getRuleContext<VisualBasic6Parser::Cp_NestedPropertyContext>(0);
}

VisualBasic6Parser::ControlPropertiesContext* VisualBasic6Parser::Cp_PropertiesContext::controlProperties() {
  return getRuleContext<VisualBasic6Parser::ControlPropertiesContext>(0);
}


size_t VisualBasic6Parser::Cp_PropertiesContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleCp_Properties;
}

antlrcpp::Any VisualBasic6Parser::Cp_PropertiesContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitCp_Properties(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::Cp_PropertiesContext* VisualBasic6Parser::cp_Properties() {
  Cp_PropertiesContext *_localctx = _tracker.createInstance<Cp_PropertiesContext>(_ctx, getState());
  enterRule(_localctx, 30, VisualBasic6Parser::RuleCp_Properties);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(540);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 42, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(537);
      cp_SingleProperty();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(538);
      cp_NestedProperty();
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(539);
      controlProperties();
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

//----------------- Cp_SinglePropertyContext ------------------------------------------------------------------

VisualBasic6Parser::Cp_SinglePropertyContext::Cp_SinglePropertyContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::ImplicitCallStmt_InStmtContext* VisualBasic6Parser::Cp_SinglePropertyContext::implicitCallStmt_InStmt() {
  return getRuleContext<VisualBasic6Parser::ImplicitCallStmt_InStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::Cp_SinglePropertyContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

VisualBasic6Parser::Cp_PropertyValueContext* VisualBasic6Parser::Cp_SinglePropertyContext::cp_PropertyValue() {
  return getRuleContext<VisualBasic6Parser::Cp_PropertyValueContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::Cp_SinglePropertyContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::Cp_SinglePropertyContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

tree::TerminalNode* VisualBasic6Parser::Cp_SinglePropertyContext::FRX_OFFSET() {
  return getToken(VisualBasic6Parser::FRX_OFFSET, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::Cp_SinglePropertyContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::Cp_SinglePropertyContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}


size_t VisualBasic6Parser::Cp_SinglePropertyContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleCp_SingleProperty;
}

antlrcpp::Any VisualBasic6Parser::Cp_SinglePropertyContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitCp_SingleProperty(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::Cp_SinglePropertyContext* VisualBasic6Parser::cp_SingleProperty() {
  Cp_SinglePropertyContext *_localctx = _tracker.createInstance<Cp_SinglePropertyContext>(_ctx, getState());
  enterRule(_localctx, 32, VisualBasic6Parser::RuleCp_SingleProperty);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(543);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 43, _ctx)) {
    case 1: {
      setState(542);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(545);
    implicitCallStmt_InStmt();
    setState(547);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(546);
      match(VisualBasic6Parser::WS);
    }
    setState(549);
    match(VisualBasic6Parser::EQ);
    setState(551);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(550);
      match(VisualBasic6Parser::WS);
    }
    setState(554);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 46, _ctx)) {
    case 1: {
      setState(553);
      match(VisualBasic6Parser::DOLLAR);
      break;
    }

    }
    setState(556);
    cp_PropertyValue();
    setState(558);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::FRX_OFFSET) {
      setState(557);
      match(VisualBasic6Parser::FRX_OFFSET);
    }
    setState(561); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(560);
      match(VisualBasic6Parser::NEWLINE);
      setState(563); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- Cp_PropertyNameContext ------------------------------------------------------------------

VisualBasic6Parser::Cp_PropertyNameContext::Cp_PropertyNameContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<VisualBasic6Parser::AmbiguousIdentifierContext *> VisualBasic6Parser::Cp_PropertyNameContext::ambiguousIdentifier() {
  return getRuleContexts<VisualBasic6Parser::AmbiguousIdentifierContext>();
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::Cp_PropertyNameContext::ambiguousIdentifier(size_t i) {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::Cp_PropertyNameContext::OBJECT() {
  return getToken(VisualBasic6Parser::OBJECT, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::Cp_PropertyNameContext::DOT() {
  return getTokens(VisualBasic6Parser::DOT);
}

tree::TerminalNode* VisualBasic6Parser::Cp_PropertyNameContext::DOT(size_t i) {
  return getToken(VisualBasic6Parser::DOT, i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::Cp_PropertyNameContext::LPAREN() {
  return getTokens(VisualBasic6Parser::LPAREN);
}

tree::TerminalNode* VisualBasic6Parser::Cp_PropertyNameContext::LPAREN(size_t i) {
  return getToken(VisualBasic6Parser::LPAREN, i);
}

std::vector<VisualBasic6Parser::LiteralContext *> VisualBasic6Parser::Cp_PropertyNameContext::literal() {
  return getRuleContexts<VisualBasic6Parser::LiteralContext>();
}

VisualBasic6Parser::LiteralContext* VisualBasic6Parser::Cp_PropertyNameContext::literal(size_t i) {
  return getRuleContext<VisualBasic6Parser::LiteralContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::Cp_PropertyNameContext::RPAREN() {
  return getTokens(VisualBasic6Parser::RPAREN);
}

tree::TerminalNode* VisualBasic6Parser::Cp_PropertyNameContext::RPAREN(size_t i) {
  return getToken(VisualBasic6Parser::RPAREN, i);
}


size_t VisualBasic6Parser::Cp_PropertyNameContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleCp_PropertyName;
}

antlrcpp::Any VisualBasic6Parser::Cp_PropertyNameContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitCp_PropertyName(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::Cp_PropertyNameContext* VisualBasic6Parser::cp_PropertyName() {
  Cp_PropertyNameContext *_localctx = _tracker.createInstance<Cp_PropertyNameContext>(_ctx, getState());
  enterRule(_localctx, 34, VisualBasic6Parser::RuleCp_PropertyName);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(567);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 49, _ctx)) {
    case 1: {
      setState(565);
      match(VisualBasic6Parser::OBJECT);
      setState(566);
      match(VisualBasic6Parser::DOT);
      break;
    }

    }
    setState(569);
    ambiguousIdentifier();
    setState(574);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::LPAREN) {
      setState(570);
      match(VisualBasic6Parser::LPAREN);
      setState(571);
      literal();
      setState(572);
      match(VisualBasic6Parser::RPAREN);
    }
    setState(586);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == VisualBasic6Parser::DOT) {
      setState(576);
      match(VisualBasic6Parser::DOT);
      setState(577);
      ambiguousIdentifier();
      setState(582);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::LPAREN) {
        setState(578);
        match(VisualBasic6Parser::LPAREN);
        setState(579);
        literal();
        setState(580);
        match(VisualBasic6Parser::RPAREN);
      }
      setState(588);
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

//----------------- Cp_PropertyValueContext ------------------------------------------------------------------

VisualBasic6Parser::Cp_PropertyValueContext::Cp_PropertyValueContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::LiteralContext* VisualBasic6Parser::Cp_PropertyValueContext::literal() {
  return getRuleContext<VisualBasic6Parser::LiteralContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::Cp_PropertyValueContext::POW() {
  return getToken(VisualBasic6Parser::POW, 0);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::Cp_PropertyValueContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::Cp_PropertyValueContext::DOLLAR() {
  return getToken(VisualBasic6Parser::DOLLAR, 0);
}

tree::TerminalNode* VisualBasic6Parser::Cp_PropertyValueContext::LBRACE() {
  return getToken(VisualBasic6Parser::LBRACE, 0);
}

tree::TerminalNode* VisualBasic6Parser::Cp_PropertyValueContext::RBRACE() {
  return getToken(VisualBasic6Parser::RBRACE, 0);
}


size_t VisualBasic6Parser::Cp_PropertyValueContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleCp_PropertyValue;
}

antlrcpp::Any VisualBasic6Parser::Cp_PropertyValueContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitCp_PropertyValue(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::Cp_PropertyValueContext* VisualBasic6Parser::cp_PropertyValue() {
  Cp_PropertyValueContext *_localctx = _tracker.createInstance<Cp_PropertyValueContext>(_ctx, getState());
  enterRule(_localctx, 36, VisualBasic6Parser::RuleCp_PropertyValue);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(590);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::DOLLAR) {
      setState(589);
      match(VisualBasic6Parser::DOLLAR);
    }
    setState(599);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case VisualBasic6Parser::FALSE1:
      case VisualBasic6Parser::NOTHING:
      case VisualBasic6Parser::NULL1:
      case VisualBasic6Parser::TRUE1:
      case VisualBasic6Parser::STRINGLITERAL:
      case VisualBasic6Parser::DATELITERAL:
      case VisualBasic6Parser::COLORLITERAL:
      case VisualBasic6Parser::INTEGERLITERAL:
      case VisualBasic6Parser::DOUBLELITERAL:
      case VisualBasic6Parser::FILENUMBER:
      case VisualBasic6Parser::OCTALLITERAL: {
        setState(592);
        literal();
        break;
      }

      case VisualBasic6Parser::LBRACE: {
        setState(593);
        match(VisualBasic6Parser::LBRACE);
        setState(594);
        ambiguousIdentifier();
        setState(595);
        match(VisualBasic6Parser::RBRACE);
        break;
      }

      case VisualBasic6Parser::POW: {
        setState(597);
        match(VisualBasic6Parser::POW);
        setState(598);
        ambiguousIdentifier();
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

//----------------- Cp_NestedPropertyContext ------------------------------------------------------------------

VisualBasic6Parser::Cp_NestedPropertyContext::Cp_NestedPropertyContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::Cp_NestedPropertyContext::BEGINPROPERTY() {
  return getToken(VisualBasic6Parser::BEGINPROPERTY, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::Cp_NestedPropertyContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::Cp_NestedPropertyContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::Cp_NestedPropertyContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::Cp_NestedPropertyContext::ENDPROPERTY() {
  return getToken(VisualBasic6Parser::ENDPROPERTY, 0);
}

tree::TerminalNode* VisualBasic6Parser::Cp_NestedPropertyContext::LPAREN() {
  return getToken(VisualBasic6Parser::LPAREN, 0);
}

tree::TerminalNode* VisualBasic6Parser::Cp_NestedPropertyContext::INTEGERLITERAL() {
  return getToken(VisualBasic6Parser::INTEGERLITERAL, 0);
}

tree::TerminalNode* VisualBasic6Parser::Cp_NestedPropertyContext::RPAREN() {
  return getToken(VisualBasic6Parser::RPAREN, 0);
}

tree::TerminalNode* VisualBasic6Parser::Cp_NestedPropertyContext::GUID() {
  return getToken(VisualBasic6Parser::GUID, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::Cp_NestedPropertyContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::Cp_NestedPropertyContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

std::vector<VisualBasic6Parser::Cp_PropertiesContext *> VisualBasic6Parser::Cp_NestedPropertyContext::cp_Properties() {
  return getRuleContexts<VisualBasic6Parser::Cp_PropertiesContext>();
}

VisualBasic6Parser::Cp_PropertiesContext* VisualBasic6Parser::Cp_NestedPropertyContext::cp_Properties(size_t i) {
  return getRuleContext<VisualBasic6Parser::Cp_PropertiesContext>(i);
}


size_t VisualBasic6Parser::Cp_NestedPropertyContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleCp_NestedProperty;
}

antlrcpp::Any VisualBasic6Parser::Cp_NestedPropertyContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitCp_NestedProperty(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::Cp_NestedPropertyContext* VisualBasic6Parser::cp_NestedProperty() {
  Cp_NestedPropertyContext *_localctx = _tracker.createInstance<Cp_NestedPropertyContext>(_ctx, getState());
  enterRule(_localctx, 38, VisualBasic6Parser::RuleCp_NestedProperty);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(602);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(601);
      match(VisualBasic6Parser::WS);
    }
    setState(604);
    match(VisualBasic6Parser::BEGINPROPERTY);
    setState(605);
    match(VisualBasic6Parser::WS);
    setState(606);
    ambiguousIdentifier();
    setState(610);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::LPAREN) {
      setState(607);
      match(VisualBasic6Parser::LPAREN);
      setState(608);
      match(VisualBasic6Parser::INTEGERLITERAL);
      setState(609);
      match(VisualBasic6Parser::RPAREN);
    }
    setState(614);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(612);
      match(VisualBasic6Parser::WS);
      setState(613);
      match(VisualBasic6Parser::GUID);
    }
    setState(617); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(616);
      match(VisualBasic6Parser::NEWLINE);
      setState(619); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(626);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
      | (1ULL << VisualBasic6Parser::ADDRESSOF)
      | (1ULL << VisualBasic6Parser::ALIAS)
      | (1ULL << VisualBasic6Parser::AND)
      | (1ULL << VisualBasic6Parser::ATTRIBUTE)
      | (1ULL << VisualBasic6Parser::APPACTIVATE)
      | (1ULL << VisualBasic6Parser::APPEND)
      | (1ULL << VisualBasic6Parser::AS)
      | (1ULL << VisualBasic6Parser::BEEP)
      | (1ULL << VisualBasic6Parser::BEGIN)
      | (1ULL << VisualBasic6Parser::BEGINPROPERTY)
      | (1ULL << VisualBasic6Parser::BINARY)
      | (1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYVAL)
      | (1ULL << VisualBasic6Parser::BYREF)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::CALL)
      | (1ULL << VisualBasic6Parser::CASE)
      | (1ULL << VisualBasic6Parser::CHDIR)
      | (1ULL << VisualBasic6Parser::CHDRIVE)
      | (1ULL << VisualBasic6Parser::CLASS)
      | (1ULL << VisualBasic6Parser::CLOSE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::CONST)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DECLARE)
      | (1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR)
      | (1ULL << VisualBasic6Parser::DELETESETTING)
      | (1ULL << VisualBasic6Parser::DIM)
      | (1ULL << VisualBasic6Parser::DO)
      | (1ULL << VisualBasic6Parser::DOUBLE)
      | (1ULL << VisualBasic6Parser::EACH)
      | (1ULL << VisualBasic6Parser::ELSE)
      | (1ULL << VisualBasic6Parser::ELSEIF)
      | (1ULL << VisualBasic6Parser::END)
      | (1ULL << VisualBasic6Parser::ENUM)
      | (1ULL << VisualBasic6Parser::EQV)
      | (1ULL << VisualBasic6Parser::ERASE)
      | (1ULL << VisualBasic6Parser::ERROR)
      | (1ULL << VisualBasic6Parser::EVENT))) != 0) || ((((_la - 66) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 66)) & ((1ULL << (VisualBasic6Parser::FALSE1 - 66))
      | (1ULL << (VisualBasic6Parser::FILECOPY - 66))
      | (1ULL << (VisualBasic6Parser::FRIEND - 66))
      | (1ULL << (VisualBasic6Parser::FOR - 66))
      | (1ULL << (VisualBasic6Parser::FUNCTION - 66))
      | (1ULL << (VisualBasic6Parser::GET - 66))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 66))
      | (1ULL << (VisualBasic6Parser::GOSUB - 66))
      | (1ULL << (VisualBasic6Parser::GOTO - 66))
      | (1ULL << (VisualBasic6Parser::IF - 66))
      | (1ULL << (VisualBasic6Parser::IMP - 66))
      | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 66))
      | (1ULL << (VisualBasic6Parser::IN - 66))
      | (1ULL << (VisualBasic6Parser::INPUT - 66))
      | (1ULL << (VisualBasic6Parser::IS - 66))
      | (1ULL << (VisualBasic6Parser::INTEGER - 66))
      | (1ULL << (VisualBasic6Parser::KILL - 66))
      | (1ULL << (VisualBasic6Parser::LOAD - 66))
      | (1ULL << (VisualBasic6Parser::LOCK - 66))
      | (1ULL << (VisualBasic6Parser::LONG - 66))
      | (1ULL << (VisualBasic6Parser::LOOP - 66))
      | (1ULL << (VisualBasic6Parser::LEN - 66))
      | (1ULL << (VisualBasic6Parser::LET - 66))
      | (1ULL << (VisualBasic6Parser::LIB - 66))
      | (1ULL << (VisualBasic6Parser::LIKE - 66))
      | (1ULL << (VisualBasic6Parser::LSET - 66))
      | (1ULL << (VisualBasic6Parser::ME - 66))
      | (1ULL << (VisualBasic6Parser::MID - 66))
      | (1ULL << (VisualBasic6Parser::MKDIR - 66))
      | (1ULL << (VisualBasic6Parser::MOD - 66))
      | (1ULL << (VisualBasic6Parser::NAME - 66))
      | (1ULL << (VisualBasic6Parser::NEXT - 66))
      | (1ULL << (VisualBasic6Parser::NEW - 66))
      | (1ULL << (VisualBasic6Parser::NOT - 66))
      | (1ULL << (VisualBasic6Parser::NOTHING - 66))
      | (1ULL << (VisualBasic6Parser::NULL1 - 66))
      | (1ULL << (VisualBasic6Parser::OBJECT - 66))
      | (1ULL << (VisualBasic6Parser::ON - 66))
      | (1ULL << (VisualBasic6Parser::OPEN - 66))
      | (1ULL << (VisualBasic6Parser::OPTIONAL - 66))
      | (1ULL << (VisualBasic6Parser::OR - 66))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 66))
      | (1ULL << (VisualBasic6Parser::PARAMARRAY - 66))
      | (1ULL << (VisualBasic6Parser::PRESERVE - 66))
      | (1ULL << (VisualBasic6Parser::PRINT - 66))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 66))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 66)))) != 0) || ((((_la - 130) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 130)) & ((1ULL << (VisualBasic6Parser::PUT - 130))
      | (1ULL << (VisualBasic6Parser::RANDOM - 130))
      | (1ULL << (VisualBasic6Parser::RANDOMIZE - 130))
      | (1ULL << (VisualBasic6Parser::RAISEEVENT - 130))
      | (1ULL << (VisualBasic6Parser::READ - 130))
      | (1ULL << (VisualBasic6Parser::REDIM - 130))
      | (1ULL << (VisualBasic6Parser::REM - 130))
      | (1ULL << (VisualBasic6Parser::RESET - 130))
      | (1ULL << (VisualBasic6Parser::RESUME - 130))
      | (1ULL << (VisualBasic6Parser::RETURN - 130))
      | (1ULL << (VisualBasic6Parser::RMDIR - 130))
      | (1ULL << (VisualBasic6Parser::RSET - 130))
      | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 130))
      | (1ULL << (VisualBasic6Parser::SAVESETTING - 130))
      | (1ULL << (VisualBasic6Parser::SEEK - 130))
      | (1ULL << (VisualBasic6Parser::SELECT - 130))
      | (1ULL << (VisualBasic6Parser::SENDKEYS - 130))
      | (1ULL << (VisualBasic6Parser::SET - 130))
      | (1ULL << (VisualBasic6Parser::SETATTR - 130))
      | (1ULL << (VisualBasic6Parser::SHARED - 130))
      | (1ULL << (VisualBasic6Parser::SINGLE - 130))
      | (1ULL << (VisualBasic6Parser::SPC - 130))
      | (1ULL << (VisualBasic6Parser::STATIC - 130))
      | (1ULL << (VisualBasic6Parser::STEP - 130))
      | (1ULL << (VisualBasic6Parser::STOP - 130))
      | (1ULL << (VisualBasic6Parser::STRING - 130))
      | (1ULL << (VisualBasic6Parser::SUB - 130))
      | (1ULL << (VisualBasic6Parser::TAB - 130))
      | (1ULL << (VisualBasic6Parser::TEXT - 130))
      | (1ULL << (VisualBasic6Parser::THEN - 130))
      | (1ULL << (VisualBasic6Parser::TIME - 130))
      | (1ULL << (VisualBasic6Parser::TO - 130))
      | (1ULL << (VisualBasic6Parser::TRUE1 - 130))
      | (1ULL << (VisualBasic6Parser::TYPE - 130))
      | (1ULL << (VisualBasic6Parser::TYPEOF - 130))
      | (1ULL << (VisualBasic6Parser::UNLOAD - 130))
      | (1ULL << (VisualBasic6Parser::UNLOCK - 130))
      | (1ULL << (VisualBasic6Parser::UNTIL - 130))
      | (1ULL << (VisualBasic6Parser::VARIANT - 130))
      | (1ULL << (VisualBasic6Parser::VERSION - 130))
      | (1ULL << (VisualBasic6Parser::WEND - 130))
      | (1ULL << (VisualBasic6Parser::WHILE - 130))
      | (1ULL << (VisualBasic6Parser::WIDTH - 130))
      | (1ULL << (VisualBasic6Parser::WITH - 130))
      | (1ULL << (VisualBasic6Parser::WITHEVENTS - 130))
      | (1ULL << (VisualBasic6Parser::WRITE - 130))
      | (1ULL << (VisualBasic6Parser::XOR - 130))
      | (1ULL << (VisualBasic6Parser::DOT - 130))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 130)))) != 0) || ((((_la - 206) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 206)) & ((1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 206))
      | (1ULL << (VisualBasic6Parser::IDENTIFIER - 206))
      | (1ULL << (VisualBasic6Parser::WS - 206)))) != 0)) {
      setState(622); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(621);
        cp_Properties();
        setState(624); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
        | (1ULL << VisualBasic6Parser::ADDRESSOF)
        | (1ULL << VisualBasic6Parser::ALIAS)
        | (1ULL << VisualBasic6Parser::AND)
        | (1ULL << VisualBasic6Parser::ATTRIBUTE)
        | (1ULL << VisualBasic6Parser::APPACTIVATE)
        | (1ULL << VisualBasic6Parser::APPEND)
        | (1ULL << VisualBasic6Parser::AS)
        | (1ULL << VisualBasic6Parser::BEEP)
        | (1ULL << VisualBasic6Parser::BEGIN)
        | (1ULL << VisualBasic6Parser::BEGINPROPERTY)
        | (1ULL << VisualBasic6Parser::BINARY)
        | (1ULL << VisualBasic6Parser::BOOLEAN)
        | (1ULL << VisualBasic6Parser::BYVAL)
        | (1ULL << VisualBasic6Parser::BYREF)
        | (1ULL << VisualBasic6Parser::BYTE)
        | (1ULL << VisualBasic6Parser::CALL)
        | (1ULL << VisualBasic6Parser::CASE)
        | (1ULL << VisualBasic6Parser::CHDIR)
        | (1ULL << VisualBasic6Parser::CHDRIVE)
        | (1ULL << VisualBasic6Parser::CLASS)
        | (1ULL << VisualBasic6Parser::CLOSE)
        | (1ULL << VisualBasic6Parser::COLLECTION)
        | (1ULL << VisualBasic6Parser::CONST)
        | (1ULL << VisualBasic6Parser::DATE)
        | (1ULL << VisualBasic6Parser::DECLARE)
        | (1ULL << VisualBasic6Parser::DEFBOOL)
        | (1ULL << VisualBasic6Parser::DEFBYTE)
        | (1ULL << VisualBasic6Parser::DEFDATE)
        | (1ULL << VisualBasic6Parser::DEFDBL)
        | (1ULL << VisualBasic6Parser::DEFDEC)
        | (1ULL << VisualBasic6Parser::DEFCUR)
        | (1ULL << VisualBasic6Parser::DEFINT)
        | (1ULL << VisualBasic6Parser::DEFLNG)
        | (1ULL << VisualBasic6Parser::DEFOBJ)
        | (1ULL << VisualBasic6Parser::DEFSNG)
        | (1ULL << VisualBasic6Parser::DEFSTR)
        | (1ULL << VisualBasic6Parser::DEFVAR)
        | (1ULL << VisualBasic6Parser::DELETESETTING)
        | (1ULL << VisualBasic6Parser::DIM)
        | (1ULL << VisualBasic6Parser::DO)
        | (1ULL << VisualBasic6Parser::DOUBLE)
        | (1ULL << VisualBasic6Parser::EACH)
        | (1ULL << VisualBasic6Parser::ELSE)
        | (1ULL << VisualBasic6Parser::ELSEIF)
        | (1ULL << VisualBasic6Parser::END)
        | (1ULL << VisualBasic6Parser::ENUM)
        | (1ULL << VisualBasic6Parser::EQV)
        | (1ULL << VisualBasic6Parser::ERASE)
        | (1ULL << VisualBasic6Parser::ERROR)
        | (1ULL << VisualBasic6Parser::EVENT))) != 0) || ((((_la - 66) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 66)) & ((1ULL << (VisualBasic6Parser::FALSE1 - 66))
        | (1ULL << (VisualBasic6Parser::FILECOPY - 66))
        | (1ULL << (VisualBasic6Parser::FRIEND - 66))
        | (1ULL << (VisualBasic6Parser::FOR - 66))
        | (1ULL << (VisualBasic6Parser::FUNCTION - 66))
        | (1ULL << (VisualBasic6Parser::GET - 66))
        | (1ULL << (VisualBasic6Parser::GLOBAL - 66))
        | (1ULL << (VisualBasic6Parser::GOSUB - 66))
        | (1ULL << (VisualBasic6Parser::GOTO - 66))
        | (1ULL << (VisualBasic6Parser::IF - 66))
        | (1ULL << (VisualBasic6Parser::IMP - 66))
        | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 66))
        | (1ULL << (VisualBasic6Parser::IN - 66))
        | (1ULL << (VisualBasic6Parser::INPUT - 66))
        | (1ULL << (VisualBasic6Parser::IS - 66))
        | (1ULL << (VisualBasic6Parser::INTEGER - 66))
        | (1ULL << (VisualBasic6Parser::KILL - 66))
        | (1ULL << (VisualBasic6Parser::LOAD - 66))
        | (1ULL << (VisualBasic6Parser::LOCK - 66))
        | (1ULL << (VisualBasic6Parser::LONG - 66))
        | (1ULL << (VisualBasic6Parser::LOOP - 66))
        | (1ULL << (VisualBasic6Parser::LEN - 66))
        | (1ULL << (VisualBasic6Parser::LET - 66))
        | (1ULL << (VisualBasic6Parser::LIB - 66))
        | (1ULL << (VisualBasic6Parser::LIKE - 66))
        | (1ULL << (VisualBasic6Parser::LSET - 66))
        | (1ULL << (VisualBasic6Parser::ME - 66))
        | (1ULL << (VisualBasic6Parser::MID - 66))
        | (1ULL << (VisualBasic6Parser::MKDIR - 66))
        | (1ULL << (VisualBasic6Parser::MOD - 66))
        | (1ULL << (VisualBasic6Parser::NAME - 66))
        | (1ULL << (VisualBasic6Parser::NEXT - 66))
        | (1ULL << (VisualBasic6Parser::NEW - 66))
        | (1ULL << (VisualBasic6Parser::NOT - 66))
        | (1ULL << (VisualBasic6Parser::NOTHING - 66))
        | (1ULL << (VisualBasic6Parser::NULL1 - 66))
        | (1ULL << (VisualBasic6Parser::OBJECT - 66))
        | (1ULL << (VisualBasic6Parser::ON - 66))
        | (1ULL << (VisualBasic6Parser::OPEN - 66))
        | (1ULL << (VisualBasic6Parser::OPTIONAL - 66))
        | (1ULL << (VisualBasic6Parser::OR - 66))
        | (1ULL << (VisualBasic6Parser::OUTPUT - 66))
        | (1ULL << (VisualBasic6Parser::PARAMARRAY - 66))
        | (1ULL << (VisualBasic6Parser::PRESERVE - 66))
        | (1ULL << (VisualBasic6Parser::PRINT - 66))
        | (1ULL << (VisualBasic6Parser::PRIVATE - 66))
        | (1ULL << (VisualBasic6Parser::PUBLIC - 66)))) != 0) || ((((_la - 130) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 130)) & ((1ULL << (VisualBasic6Parser::PUT - 130))
        | (1ULL << (VisualBasic6Parser::RANDOM - 130))
        | (1ULL << (VisualBasic6Parser::RANDOMIZE - 130))
        | (1ULL << (VisualBasic6Parser::RAISEEVENT - 130))
        | (1ULL << (VisualBasic6Parser::READ - 130))
        | (1ULL << (VisualBasic6Parser::REDIM - 130))
        | (1ULL << (VisualBasic6Parser::REM - 130))
        | (1ULL << (VisualBasic6Parser::RESET - 130))
        | (1ULL << (VisualBasic6Parser::RESUME - 130))
        | (1ULL << (VisualBasic6Parser::RETURN - 130))
        | (1ULL << (VisualBasic6Parser::RMDIR - 130))
        | (1ULL << (VisualBasic6Parser::RSET - 130))
        | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 130))
        | (1ULL << (VisualBasic6Parser::SAVESETTING - 130))
        | (1ULL << (VisualBasic6Parser::SEEK - 130))
        | (1ULL << (VisualBasic6Parser::SELECT - 130))
        | (1ULL << (VisualBasic6Parser::SENDKEYS - 130))
        | (1ULL << (VisualBasic6Parser::SET - 130))
        | (1ULL << (VisualBasic6Parser::SETATTR - 130))
        | (1ULL << (VisualBasic6Parser::SHARED - 130))
        | (1ULL << (VisualBasic6Parser::SINGLE - 130))
        | (1ULL << (VisualBasic6Parser::SPC - 130))
        | (1ULL << (VisualBasic6Parser::STATIC - 130))
        | (1ULL << (VisualBasic6Parser::STEP - 130))
        | (1ULL << (VisualBasic6Parser::STOP - 130))
        | (1ULL << (VisualBasic6Parser::STRING - 130))
        | (1ULL << (VisualBasic6Parser::SUB - 130))
        | (1ULL << (VisualBasic6Parser::TAB - 130))
        | (1ULL << (VisualBasic6Parser::TEXT - 130))
        | (1ULL << (VisualBasic6Parser::THEN - 130))
        | (1ULL << (VisualBasic6Parser::TIME - 130))
        | (1ULL << (VisualBasic6Parser::TO - 130))
        | (1ULL << (VisualBasic6Parser::TRUE1 - 130))
        | (1ULL << (VisualBasic6Parser::TYPE - 130))
        | (1ULL << (VisualBasic6Parser::TYPEOF - 130))
        | (1ULL << (VisualBasic6Parser::UNLOAD - 130))
        | (1ULL << (VisualBasic6Parser::UNLOCK - 130))
        | (1ULL << (VisualBasic6Parser::UNTIL - 130))
        | (1ULL << (VisualBasic6Parser::VARIANT - 130))
        | (1ULL << (VisualBasic6Parser::VERSION - 130))
        | (1ULL << (VisualBasic6Parser::WEND - 130))
        | (1ULL << (VisualBasic6Parser::WHILE - 130))
        | (1ULL << (VisualBasic6Parser::WIDTH - 130))
        | (1ULL << (VisualBasic6Parser::WITH - 130))
        | (1ULL << (VisualBasic6Parser::WITHEVENTS - 130))
        | (1ULL << (VisualBasic6Parser::WRITE - 130))
        | (1ULL << (VisualBasic6Parser::XOR - 130))
        | (1ULL << (VisualBasic6Parser::DOT - 130))
        | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 130)))) != 0) || ((((_la - 206) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 206)) & ((1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 206))
        | (1ULL << (VisualBasic6Parser::IDENTIFIER - 206))
        | (1ULL << (VisualBasic6Parser::WS - 206)))) != 0));
    }
    setState(628);
    match(VisualBasic6Parser::ENDPROPERTY);
    setState(630); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(629);
      match(VisualBasic6Parser::NEWLINE);
      setState(632); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- Cp_ControlTypeContext ------------------------------------------------------------------

VisualBasic6Parser::Cp_ControlTypeContext::Cp_ControlTypeContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::ComplexTypeContext* VisualBasic6Parser::Cp_ControlTypeContext::complexType() {
  return getRuleContext<VisualBasic6Parser::ComplexTypeContext>(0);
}


size_t VisualBasic6Parser::Cp_ControlTypeContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleCp_ControlType;
}

antlrcpp::Any VisualBasic6Parser::Cp_ControlTypeContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitCp_ControlType(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::Cp_ControlTypeContext* VisualBasic6Parser::cp_ControlType() {
  Cp_ControlTypeContext *_localctx = _tracker.createInstance<Cp_ControlTypeContext>(_ctx, getState());
  enterRule(_localctx, 40, VisualBasic6Parser::RuleCp_ControlType);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(634);
    complexType();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- Cp_ControlIdentifierContext ------------------------------------------------------------------

VisualBasic6Parser::Cp_ControlIdentifierContext::Cp_ControlIdentifierContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::Cp_ControlIdentifierContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}


size_t VisualBasic6Parser::Cp_ControlIdentifierContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleCp_ControlIdentifier;
}

antlrcpp::Any VisualBasic6Parser::Cp_ControlIdentifierContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitCp_ControlIdentifier(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::Cp_ControlIdentifierContext* VisualBasic6Parser::cp_ControlIdentifier() {
  Cp_ControlIdentifierContext *_localctx = _tracker.createInstance<Cp_ControlIdentifierContext>(_ctx, getState());
  enterRule(_localctx, 42, VisualBasic6Parser::RuleCp_ControlIdentifier);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(636);
    ambiguousIdentifier();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ModuleBlockContext ------------------------------------------------------------------

VisualBasic6Parser::ModuleBlockContext::ModuleBlockContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::ModuleBlockContext::block() {
  return getRuleContext<VisualBasic6Parser::BlockContext>(0);
}


size_t VisualBasic6Parser::ModuleBlockContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleModuleBlock;
}

antlrcpp::Any VisualBasic6Parser::ModuleBlockContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitModuleBlock(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ModuleBlockContext* VisualBasic6Parser::moduleBlock() {
  ModuleBlockContext *_localctx = _tracker.createInstance<ModuleBlockContext>(_ctx, getState());
  enterRule(_localctx, 44, VisualBasic6Parser::RuleModuleBlock);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(638);
    block();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- AttributeStmtContext ------------------------------------------------------------------

VisualBasic6Parser::AttributeStmtContext::AttributeStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::AttributeStmtContext::ATTRIBUTE() {
  return getToken(VisualBasic6Parser::ATTRIBUTE, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::AttributeStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::AttributeStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::ImplicitCallStmt_InStmtContext* VisualBasic6Parser::AttributeStmtContext::implicitCallStmt_InStmt() {
  return getRuleContext<VisualBasic6Parser::ImplicitCallStmt_InStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::AttributeStmtContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

std::vector<VisualBasic6Parser::LiteralContext *> VisualBasic6Parser::AttributeStmtContext::literal() {
  return getRuleContexts<VisualBasic6Parser::LiteralContext>();
}

VisualBasic6Parser::LiteralContext* VisualBasic6Parser::AttributeStmtContext::literal(size_t i) {
  return getRuleContext<VisualBasic6Parser::LiteralContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::AttributeStmtContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::AttributeStmtContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}


size_t VisualBasic6Parser::AttributeStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleAttributeStmt;
}

antlrcpp::Any VisualBasic6Parser::AttributeStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitAttributeStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::AttributeStmtContext* VisualBasic6Parser::attributeStmt() {
  AttributeStmtContext *_localctx = _tracker.createInstance<AttributeStmtContext>(_ctx, getState());
  enterRule(_localctx, 46, VisualBasic6Parser::RuleAttributeStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(640);
    match(VisualBasic6Parser::ATTRIBUTE);
    setState(641);
    match(VisualBasic6Parser::WS);
    setState(642);
    implicitCallStmt_InStmt();
    setState(644);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(643);
      match(VisualBasic6Parser::WS);
    }
    setState(646);
    match(VisualBasic6Parser::EQ);
    setState(648);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(647);
      match(VisualBasic6Parser::WS);
    }
    setState(650);
    literal();
    setState(661);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 66, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(652);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(651);
          match(VisualBasic6Parser::WS);
        }
        setState(654);
        match(VisualBasic6Parser::COMMA);
        setState(656);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(655);
          match(VisualBasic6Parser::WS);
        }
        setState(658);
        literal(); 
      }
      setState(663);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 66, _ctx);
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

VisualBasic6Parser::BlockContext::BlockContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<VisualBasic6Parser::BlockStmtContext *> VisualBasic6Parser::BlockContext::blockStmt() {
  return getRuleContexts<VisualBasic6Parser::BlockStmtContext>();
}

VisualBasic6Parser::BlockStmtContext* VisualBasic6Parser::BlockContext::blockStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::BlockStmtContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::BlockContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::BlockContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::BlockContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::BlockContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}


size_t VisualBasic6Parser::BlockContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleBlock;
}

antlrcpp::Any VisualBasic6Parser::BlockContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitBlock(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::block() {
  BlockContext *_localctx = _tracker.createInstance<BlockContext>(_ctx, getState());
  enterRule(_localctx, 48, VisualBasic6Parser::RuleBlock);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(664);
    blockStmt();
    setState(676);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 69, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(666); 
        _errHandler->sync(this);
        _la = _input->LA(1);
        do {
          setState(665);
          match(VisualBasic6Parser::NEWLINE);
          setState(668); 
          _errHandler->sync(this);
          _la = _input->LA(1);
        } while (_la == VisualBasic6Parser::NEWLINE);
        setState(671);
        _errHandler->sync(this);

        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 68, _ctx)) {
        case 1: {
          setState(670);
          match(VisualBasic6Parser::WS);
          break;
        }

        }
        setState(673);
        blockStmt(); 
      }
      setState(678);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 69, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- BlockStmtContext ------------------------------------------------------------------

VisualBasic6Parser::BlockStmtContext::BlockStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::AppActivateStmtContext* VisualBasic6Parser::BlockStmtContext::appActivateStmt() {
  return getRuleContext<VisualBasic6Parser::AppActivateStmtContext>(0);
}

VisualBasic6Parser::AttributeStmtContext* VisualBasic6Parser::BlockStmtContext::attributeStmt() {
  return getRuleContext<VisualBasic6Parser::AttributeStmtContext>(0);
}

VisualBasic6Parser::BeepStmtContext* VisualBasic6Parser::BlockStmtContext::beepStmt() {
  return getRuleContext<VisualBasic6Parser::BeepStmtContext>(0);
}

VisualBasic6Parser::ChDirStmtContext* VisualBasic6Parser::BlockStmtContext::chDirStmt() {
  return getRuleContext<VisualBasic6Parser::ChDirStmtContext>(0);
}

VisualBasic6Parser::ChDriveStmtContext* VisualBasic6Parser::BlockStmtContext::chDriveStmt() {
  return getRuleContext<VisualBasic6Parser::ChDriveStmtContext>(0);
}

VisualBasic6Parser::CloseStmtContext* VisualBasic6Parser::BlockStmtContext::closeStmt() {
  return getRuleContext<VisualBasic6Parser::CloseStmtContext>(0);
}

VisualBasic6Parser::ConstStmtContext* VisualBasic6Parser::BlockStmtContext::constStmt() {
  return getRuleContext<VisualBasic6Parser::ConstStmtContext>(0);
}

VisualBasic6Parser::DateStmtContext* VisualBasic6Parser::BlockStmtContext::dateStmt() {
  return getRuleContext<VisualBasic6Parser::DateStmtContext>(0);
}

VisualBasic6Parser::DeleteSettingStmtContext* VisualBasic6Parser::BlockStmtContext::deleteSettingStmt() {
  return getRuleContext<VisualBasic6Parser::DeleteSettingStmtContext>(0);
}

VisualBasic6Parser::DeftypeStmtContext* VisualBasic6Parser::BlockStmtContext::deftypeStmt() {
  return getRuleContext<VisualBasic6Parser::DeftypeStmtContext>(0);
}

VisualBasic6Parser::DoLoopStmtContext* VisualBasic6Parser::BlockStmtContext::doLoopStmt() {
  return getRuleContext<VisualBasic6Parser::DoLoopStmtContext>(0);
}

VisualBasic6Parser::EndStmtContext* VisualBasic6Parser::BlockStmtContext::endStmt() {
  return getRuleContext<VisualBasic6Parser::EndStmtContext>(0);
}

VisualBasic6Parser::EraseStmtContext* VisualBasic6Parser::BlockStmtContext::eraseStmt() {
  return getRuleContext<VisualBasic6Parser::EraseStmtContext>(0);
}

VisualBasic6Parser::ErrorStmtContext* VisualBasic6Parser::BlockStmtContext::errorStmt() {
  return getRuleContext<VisualBasic6Parser::ErrorStmtContext>(0);
}

VisualBasic6Parser::ExitStmtContext* VisualBasic6Parser::BlockStmtContext::exitStmt() {
  return getRuleContext<VisualBasic6Parser::ExitStmtContext>(0);
}

VisualBasic6Parser::ExplicitCallStmtContext* VisualBasic6Parser::BlockStmtContext::explicitCallStmt() {
  return getRuleContext<VisualBasic6Parser::ExplicitCallStmtContext>(0);
}

VisualBasic6Parser::FilecopyStmtContext* VisualBasic6Parser::BlockStmtContext::filecopyStmt() {
  return getRuleContext<VisualBasic6Parser::FilecopyStmtContext>(0);
}

VisualBasic6Parser::ForEachStmtContext* VisualBasic6Parser::BlockStmtContext::forEachStmt() {
  return getRuleContext<VisualBasic6Parser::ForEachStmtContext>(0);
}

VisualBasic6Parser::ForNextStmtContext* VisualBasic6Parser::BlockStmtContext::forNextStmt() {
  return getRuleContext<VisualBasic6Parser::ForNextStmtContext>(0);
}

VisualBasic6Parser::GetStmtContext* VisualBasic6Parser::BlockStmtContext::getStmt() {
  return getRuleContext<VisualBasic6Parser::GetStmtContext>(0);
}

VisualBasic6Parser::GoSubStmtContext* VisualBasic6Parser::BlockStmtContext::goSubStmt() {
  return getRuleContext<VisualBasic6Parser::GoSubStmtContext>(0);
}

VisualBasic6Parser::GoToStmtContext* VisualBasic6Parser::BlockStmtContext::goToStmt() {
  return getRuleContext<VisualBasic6Parser::GoToStmtContext>(0);
}

VisualBasic6Parser::IfThenElseStmtContext* VisualBasic6Parser::BlockStmtContext::ifThenElseStmt() {
  return getRuleContext<VisualBasic6Parser::IfThenElseStmtContext>(0);
}

VisualBasic6Parser::ImplementsStmtContext* VisualBasic6Parser::BlockStmtContext::implementsStmt() {
  return getRuleContext<VisualBasic6Parser::ImplementsStmtContext>(0);
}

VisualBasic6Parser::InputStmtContext* VisualBasic6Parser::BlockStmtContext::inputStmt() {
  return getRuleContext<VisualBasic6Parser::InputStmtContext>(0);
}

VisualBasic6Parser::KillStmtContext* VisualBasic6Parser::BlockStmtContext::killStmt() {
  return getRuleContext<VisualBasic6Parser::KillStmtContext>(0);
}

VisualBasic6Parser::LetStmtContext* VisualBasic6Parser::BlockStmtContext::letStmt() {
  return getRuleContext<VisualBasic6Parser::LetStmtContext>(0);
}

VisualBasic6Parser::LineInputStmtContext* VisualBasic6Parser::BlockStmtContext::lineInputStmt() {
  return getRuleContext<VisualBasic6Parser::LineInputStmtContext>(0);
}

VisualBasic6Parser::LineLabelContext* VisualBasic6Parser::BlockStmtContext::lineLabel() {
  return getRuleContext<VisualBasic6Parser::LineLabelContext>(0);
}

VisualBasic6Parser::LoadStmtContext* VisualBasic6Parser::BlockStmtContext::loadStmt() {
  return getRuleContext<VisualBasic6Parser::LoadStmtContext>(0);
}

VisualBasic6Parser::LockStmtContext* VisualBasic6Parser::BlockStmtContext::lockStmt() {
  return getRuleContext<VisualBasic6Parser::LockStmtContext>(0);
}

VisualBasic6Parser::LsetStmtContext* VisualBasic6Parser::BlockStmtContext::lsetStmt() {
  return getRuleContext<VisualBasic6Parser::LsetStmtContext>(0);
}

VisualBasic6Parser::MacroIfThenElseStmtContext* VisualBasic6Parser::BlockStmtContext::macroIfThenElseStmt() {
  return getRuleContext<VisualBasic6Parser::MacroIfThenElseStmtContext>(0);
}

VisualBasic6Parser::MidStmtContext* VisualBasic6Parser::BlockStmtContext::midStmt() {
  return getRuleContext<VisualBasic6Parser::MidStmtContext>(0);
}

VisualBasic6Parser::MkdirStmtContext* VisualBasic6Parser::BlockStmtContext::mkdirStmt() {
  return getRuleContext<VisualBasic6Parser::MkdirStmtContext>(0);
}

VisualBasic6Parser::NameStmtContext* VisualBasic6Parser::BlockStmtContext::nameStmt() {
  return getRuleContext<VisualBasic6Parser::NameStmtContext>(0);
}

VisualBasic6Parser::OnErrorStmtContext* VisualBasic6Parser::BlockStmtContext::onErrorStmt() {
  return getRuleContext<VisualBasic6Parser::OnErrorStmtContext>(0);
}

VisualBasic6Parser::OnGoToStmtContext* VisualBasic6Parser::BlockStmtContext::onGoToStmt() {
  return getRuleContext<VisualBasic6Parser::OnGoToStmtContext>(0);
}

VisualBasic6Parser::OnGoSubStmtContext* VisualBasic6Parser::BlockStmtContext::onGoSubStmt() {
  return getRuleContext<VisualBasic6Parser::OnGoSubStmtContext>(0);
}

VisualBasic6Parser::OpenStmtContext* VisualBasic6Parser::BlockStmtContext::openStmt() {
  return getRuleContext<VisualBasic6Parser::OpenStmtContext>(0);
}

VisualBasic6Parser::PrintStmtContext* VisualBasic6Parser::BlockStmtContext::printStmt() {
  return getRuleContext<VisualBasic6Parser::PrintStmtContext>(0);
}

VisualBasic6Parser::PutStmtContext* VisualBasic6Parser::BlockStmtContext::putStmt() {
  return getRuleContext<VisualBasic6Parser::PutStmtContext>(0);
}

VisualBasic6Parser::RaiseEventStmtContext* VisualBasic6Parser::BlockStmtContext::raiseEventStmt() {
  return getRuleContext<VisualBasic6Parser::RaiseEventStmtContext>(0);
}

VisualBasic6Parser::RandomizeStmtContext* VisualBasic6Parser::BlockStmtContext::randomizeStmt() {
  return getRuleContext<VisualBasic6Parser::RandomizeStmtContext>(0);
}

VisualBasic6Parser::RedimStmtContext* VisualBasic6Parser::BlockStmtContext::redimStmt() {
  return getRuleContext<VisualBasic6Parser::RedimStmtContext>(0);
}

VisualBasic6Parser::ResetStmtContext* VisualBasic6Parser::BlockStmtContext::resetStmt() {
  return getRuleContext<VisualBasic6Parser::ResetStmtContext>(0);
}

VisualBasic6Parser::ResumeStmtContext* VisualBasic6Parser::BlockStmtContext::resumeStmt() {
  return getRuleContext<VisualBasic6Parser::ResumeStmtContext>(0);
}

VisualBasic6Parser::ReturnStmtContext* VisualBasic6Parser::BlockStmtContext::returnStmt() {
  return getRuleContext<VisualBasic6Parser::ReturnStmtContext>(0);
}

VisualBasic6Parser::RmdirStmtContext* VisualBasic6Parser::BlockStmtContext::rmdirStmt() {
  return getRuleContext<VisualBasic6Parser::RmdirStmtContext>(0);
}

VisualBasic6Parser::RsetStmtContext* VisualBasic6Parser::BlockStmtContext::rsetStmt() {
  return getRuleContext<VisualBasic6Parser::RsetStmtContext>(0);
}

VisualBasic6Parser::SavepictureStmtContext* VisualBasic6Parser::BlockStmtContext::savepictureStmt() {
  return getRuleContext<VisualBasic6Parser::SavepictureStmtContext>(0);
}

VisualBasic6Parser::SaveSettingStmtContext* VisualBasic6Parser::BlockStmtContext::saveSettingStmt() {
  return getRuleContext<VisualBasic6Parser::SaveSettingStmtContext>(0);
}

VisualBasic6Parser::SeekStmtContext* VisualBasic6Parser::BlockStmtContext::seekStmt() {
  return getRuleContext<VisualBasic6Parser::SeekStmtContext>(0);
}

VisualBasic6Parser::SelectCaseStmtContext* VisualBasic6Parser::BlockStmtContext::selectCaseStmt() {
  return getRuleContext<VisualBasic6Parser::SelectCaseStmtContext>(0);
}

VisualBasic6Parser::SendkeysStmtContext* VisualBasic6Parser::BlockStmtContext::sendkeysStmt() {
  return getRuleContext<VisualBasic6Parser::SendkeysStmtContext>(0);
}

VisualBasic6Parser::SetattrStmtContext* VisualBasic6Parser::BlockStmtContext::setattrStmt() {
  return getRuleContext<VisualBasic6Parser::SetattrStmtContext>(0);
}

VisualBasic6Parser::SetStmtContext* VisualBasic6Parser::BlockStmtContext::setStmt() {
  return getRuleContext<VisualBasic6Parser::SetStmtContext>(0);
}

VisualBasic6Parser::StopStmtContext* VisualBasic6Parser::BlockStmtContext::stopStmt() {
  return getRuleContext<VisualBasic6Parser::StopStmtContext>(0);
}

VisualBasic6Parser::TimeStmtContext* VisualBasic6Parser::BlockStmtContext::timeStmt() {
  return getRuleContext<VisualBasic6Parser::TimeStmtContext>(0);
}

VisualBasic6Parser::UnloadStmtContext* VisualBasic6Parser::BlockStmtContext::unloadStmt() {
  return getRuleContext<VisualBasic6Parser::UnloadStmtContext>(0);
}

VisualBasic6Parser::UnlockStmtContext* VisualBasic6Parser::BlockStmtContext::unlockStmt() {
  return getRuleContext<VisualBasic6Parser::UnlockStmtContext>(0);
}

VisualBasic6Parser::VariableStmtContext* VisualBasic6Parser::BlockStmtContext::variableStmt() {
  return getRuleContext<VisualBasic6Parser::VariableStmtContext>(0);
}

VisualBasic6Parser::WhileWendStmtContext* VisualBasic6Parser::BlockStmtContext::whileWendStmt() {
  return getRuleContext<VisualBasic6Parser::WhileWendStmtContext>(0);
}

VisualBasic6Parser::WidthStmtContext* VisualBasic6Parser::BlockStmtContext::widthStmt() {
  return getRuleContext<VisualBasic6Parser::WidthStmtContext>(0);
}

VisualBasic6Parser::WithStmtContext* VisualBasic6Parser::BlockStmtContext::withStmt() {
  return getRuleContext<VisualBasic6Parser::WithStmtContext>(0);
}

VisualBasic6Parser::WriteStmtContext* VisualBasic6Parser::BlockStmtContext::writeStmt() {
  return getRuleContext<VisualBasic6Parser::WriteStmtContext>(0);
}

VisualBasic6Parser::ImplicitCallStmt_InBlockContext* VisualBasic6Parser::BlockStmtContext::implicitCallStmt_InBlock() {
  return getRuleContext<VisualBasic6Parser::ImplicitCallStmt_InBlockContext>(0);
}


size_t VisualBasic6Parser::BlockStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleBlockStmt;
}

antlrcpp::Any VisualBasic6Parser::BlockStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitBlockStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::BlockStmtContext* VisualBasic6Parser::blockStmt() {
  BlockStmtContext *_localctx = _tracker.createInstance<BlockStmtContext>(_ctx, getState());
  enterRule(_localctx, 50, VisualBasic6Parser::RuleBlockStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(746);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 70, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(679);
      appActivateStmt();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(680);
      attributeStmt();
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(681);
      beepStmt();
      break;
    }

    case 4: {
      enterOuterAlt(_localctx, 4);
      setState(682);
      chDirStmt();
      break;
    }

    case 5: {
      enterOuterAlt(_localctx, 5);
      setState(683);
      chDriveStmt();
      break;
    }

    case 6: {
      enterOuterAlt(_localctx, 6);
      setState(684);
      closeStmt();
      break;
    }

    case 7: {
      enterOuterAlt(_localctx, 7);
      setState(685);
      constStmt();
      break;
    }

    case 8: {
      enterOuterAlt(_localctx, 8);
      setState(686);
      dateStmt();
      break;
    }

    case 9: {
      enterOuterAlt(_localctx, 9);
      setState(687);
      deleteSettingStmt();
      break;
    }

    case 10: {
      enterOuterAlt(_localctx, 10);
      setState(688);
      deftypeStmt();
      break;
    }

    case 11: {
      enterOuterAlt(_localctx, 11);
      setState(689);
      doLoopStmt();
      break;
    }

    case 12: {
      enterOuterAlt(_localctx, 12);
      setState(690);
      endStmt();
      break;
    }

    case 13: {
      enterOuterAlt(_localctx, 13);
      setState(691);
      eraseStmt();
      break;
    }

    case 14: {
      enterOuterAlt(_localctx, 14);
      setState(692);
      errorStmt();
      break;
    }

    case 15: {
      enterOuterAlt(_localctx, 15);
      setState(693);
      exitStmt();
      break;
    }

    case 16: {
      enterOuterAlt(_localctx, 16);
      setState(694);
      explicitCallStmt();
      break;
    }

    case 17: {
      enterOuterAlt(_localctx, 17);
      setState(695);
      filecopyStmt();
      break;
    }

    case 18: {
      enterOuterAlt(_localctx, 18);
      setState(696);
      forEachStmt();
      break;
    }

    case 19: {
      enterOuterAlt(_localctx, 19);
      setState(697);
      forNextStmt();
      break;
    }

    case 20: {
      enterOuterAlt(_localctx, 20);
      setState(698);
      getStmt();
      break;
    }

    case 21: {
      enterOuterAlt(_localctx, 21);
      setState(699);
      goSubStmt();
      break;
    }

    case 22: {
      enterOuterAlt(_localctx, 22);
      setState(700);
      goToStmt();
      break;
    }

    case 23: {
      enterOuterAlt(_localctx, 23);
      setState(701);
      ifThenElseStmt();
      break;
    }

    case 24: {
      enterOuterAlt(_localctx, 24);
      setState(702);
      implementsStmt();
      break;
    }

    case 25: {
      enterOuterAlt(_localctx, 25);
      setState(703);
      inputStmt();
      break;
    }

    case 26: {
      enterOuterAlt(_localctx, 26);
      setState(704);
      killStmt();
      break;
    }

    case 27: {
      enterOuterAlt(_localctx, 27);
      setState(705);
      letStmt();
      break;
    }

    case 28: {
      enterOuterAlt(_localctx, 28);
      setState(706);
      lineInputStmt();
      break;
    }

    case 29: {
      enterOuterAlt(_localctx, 29);
      setState(707);
      lineLabel();
      break;
    }

    case 30: {
      enterOuterAlt(_localctx, 30);
      setState(708);
      loadStmt();
      break;
    }

    case 31: {
      enterOuterAlt(_localctx, 31);
      setState(709);
      lockStmt();
      break;
    }

    case 32: {
      enterOuterAlt(_localctx, 32);
      setState(710);
      lsetStmt();
      break;
    }

    case 33: {
      enterOuterAlt(_localctx, 33);
      setState(711);
      macroIfThenElseStmt();
      break;
    }

    case 34: {
      enterOuterAlt(_localctx, 34);
      setState(712);
      midStmt();
      break;
    }

    case 35: {
      enterOuterAlt(_localctx, 35);
      setState(713);
      mkdirStmt();
      break;
    }

    case 36: {
      enterOuterAlt(_localctx, 36);
      setState(714);
      nameStmt();
      break;
    }

    case 37: {
      enterOuterAlt(_localctx, 37);
      setState(715);
      onErrorStmt();
      break;
    }

    case 38: {
      enterOuterAlt(_localctx, 38);
      setState(716);
      onGoToStmt();
      break;
    }

    case 39: {
      enterOuterAlt(_localctx, 39);
      setState(717);
      onGoSubStmt();
      break;
    }

    case 40: {
      enterOuterAlt(_localctx, 40);
      setState(718);
      openStmt();
      break;
    }

    case 41: {
      enterOuterAlt(_localctx, 41);
      setState(719);
      printStmt();
      break;
    }

    case 42: {
      enterOuterAlt(_localctx, 42);
      setState(720);
      putStmt();
      break;
    }

    case 43: {
      enterOuterAlt(_localctx, 43);
      setState(721);
      raiseEventStmt();
      break;
    }

    case 44: {
      enterOuterAlt(_localctx, 44);
      setState(722);
      randomizeStmt();
      break;
    }

    case 45: {
      enterOuterAlt(_localctx, 45);
      setState(723);
      redimStmt();
      break;
    }

    case 46: {
      enterOuterAlt(_localctx, 46);
      setState(724);
      resetStmt();
      break;
    }

    case 47: {
      enterOuterAlt(_localctx, 47);
      setState(725);
      resumeStmt();
      break;
    }

    case 48: {
      enterOuterAlt(_localctx, 48);
      setState(726);
      returnStmt();
      break;
    }

    case 49: {
      enterOuterAlt(_localctx, 49);
      setState(727);
      rmdirStmt();
      break;
    }

    case 50: {
      enterOuterAlt(_localctx, 50);
      setState(728);
      rsetStmt();
      break;
    }

    case 51: {
      enterOuterAlt(_localctx, 51);
      setState(729);
      savepictureStmt();
      break;
    }

    case 52: {
      enterOuterAlt(_localctx, 52);
      setState(730);
      saveSettingStmt();
      break;
    }

    case 53: {
      enterOuterAlt(_localctx, 53);
      setState(731);
      seekStmt();
      break;
    }

    case 54: {
      enterOuterAlt(_localctx, 54);
      setState(732);
      selectCaseStmt();
      break;
    }

    case 55: {
      enterOuterAlt(_localctx, 55);
      setState(733);
      sendkeysStmt();
      break;
    }

    case 56: {
      enterOuterAlt(_localctx, 56);
      setState(734);
      setattrStmt();
      break;
    }

    case 57: {
      enterOuterAlt(_localctx, 57);
      setState(735);
      setStmt();
      break;
    }

    case 58: {
      enterOuterAlt(_localctx, 58);
      setState(736);
      stopStmt();
      break;
    }

    case 59: {
      enterOuterAlt(_localctx, 59);
      setState(737);
      timeStmt();
      break;
    }

    case 60: {
      enterOuterAlt(_localctx, 60);
      setState(738);
      unloadStmt();
      break;
    }

    case 61: {
      enterOuterAlt(_localctx, 61);
      setState(739);
      unlockStmt();
      break;
    }

    case 62: {
      enterOuterAlt(_localctx, 62);
      setState(740);
      variableStmt();
      break;
    }

    case 63: {
      enterOuterAlt(_localctx, 63);
      setState(741);
      whileWendStmt();
      break;
    }

    case 64: {
      enterOuterAlt(_localctx, 64);
      setState(742);
      widthStmt();
      break;
    }

    case 65: {
      enterOuterAlt(_localctx, 65);
      setState(743);
      withStmt();
      break;
    }

    case 66: {
      enterOuterAlt(_localctx, 66);
      setState(744);
      writeStmt();
      break;
    }

    case 67: {
      enterOuterAlt(_localctx, 67);
      setState(745);
      implicitCallStmt_InBlock();
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

//----------------- AppActivateStmtContext ------------------------------------------------------------------

VisualBasic6Parser::AppActivateStmtContext::AppActivateStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::AppActivateStmtContext::APPACTIVATE() {
  return getToken(VisualBasic6Parser::APPACTIVATE, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::AppActivateStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::AppActivateStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::AppActivateStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::AppActivateStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::AppActivateStmtContext::COMMA() {
  return getToken(VisualBasic6Parser::COMMA, 0);
}


size_t VisualBasic6Parser::AppActivateStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleAppActivateStmt;
}

antlrcpp::Any VisualBasic6Parser::AppActivateStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitAppActivateStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::AppActivateStmtContext* VisualBasic6Parser::appActivateStmt() {
  AppActivateStmtContext *_localctx = _tracker.createInstance<AppActivateStmtContext>(_ctx, getState());
  enterRule(_localctx, 52, VisualBasic6Parser::RuleAppActivateStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(748);
    match(VisualBasic6Parser::APPACTIVATE);
    setState(749);
    match(VisualBasic6Parser::WS);
    setState(750);
    valueStmt(0);
    setState(759);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 73, _ctx)) {
    case 1: {
      setState(752);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(751);
        match(VisualBasic6Parser::WS);
      }
      setState(754);
      match(VisualBasic6Parser::COMMA);
      setState(756);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 72, _ctx)) {
      case 1: {
        setState(755);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(758);
      valueStmt(0);
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

//----------------- BeepStmtContext ------------------------------------------------------------------

VisualBasic6Parser::BeepStmtContext::BeepStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::BeepStmtContext::BEEP() {
  return getToken(VisualBasic6Parser::BEEP, 0);
}


size_t VisualBasic6Parser::BeepStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleBeepStmt;
}

antlrcpp::Any VisualBasic6Parser::BeepStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitBeepStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::BeepStmtContext* VisualBasic6Parser::beepStmt() {
  BeepStmtContext *_localctx = _tracker.createInstance<BeepStmtContext>(_ctx, getState());
  enterRule(_localctx, 54, VisualBasic6Parser::RuleBeepStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(761);
    match(VisualBasic6Parser::BEEP);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ChDirStmtContext ------------------------------------------------------------------

VisualBasic6Parser::ChDirStmtContext::ChDirStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ChDirStmtContext::CHDIR() {
  return getToken(VisualBasic6Parser::CHDIR, 0);
}

tree::TerminalNode* VisualBasic6Parser::ChDirStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::ChDirStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::ChDirStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleChDirStmt;
}

antlrcpp::Any VisualBasic6Parser::ChDirStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitChDirStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ChDirStmtContext* VisualBasic6Parser::chDirStmt() {
  ChDirStmtContext *_localctx = _tracker.createInstance<ChDirStmtContext>(_ctx, getState());
  enterRule(_localctx, 56, VisualBasic6Parser::RuleChDirStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(763);
    match(VisualBasic6Parser::CHDIR);
    setState(764);
    match(VisualBasic6Parser::WS);
    setState(765);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ChDriveStmtContext ------------------------------------------------------------------

VisualBasic6Parser::ChDriveStmtContext::ChDriveStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ChDriveStmtContext::CHDRIVE() {
  return getToken(VisualBasic6Parser::CHDRIVE, 0);
}

tree::TerminalNode* VisualBasic6Parser::ChDriveStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::ChDriveStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::ChDriveStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleChDriveStmt;
}

antlrcpp::Any VisualBasic6Parser::ChDriveStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitChDriveStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ChDriveStmtContext* VisualBasic6Parser::chDriveStmt() {
  ChDriveStmtContext *_localctx = _tracker.createInstance<ChDriveStmtContext>(_ctx, getState());
  enterRule(_localctx, 58, VisualBasic6Parser::RuleChDriveStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(767);
    match(VisualBasic6Parser::CHDRIVE);
    setState(768);
    match(VisualBasic6Parser::WS);
    setState(769);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- CloseStmtContext ------------------------------------------------------------------

VisualBasic6Parser::CloseStmtContext::CloseStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::CloseStmtContext::CLOSE() {
  return getToken(VisualBasic6Parser::CLOSE, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::CloseStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::CloseStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::CloseStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::CloseStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::CloseStmtContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::CloseStmtContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}


size_t VisualBasic6Parser::CloseStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleCloseStmt;
}

antlrcpp::Any VisualBasic6Parser::CloseStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitCloseStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::CloseStmtContext* VisualBasic6Parser::closeStmt() {
  CloseStmtContext *_localctx = _tracker.createInstance<CloseStmtContext>(_ctx, getState());
  enterRule(_localctx, 60, VisualBasic6Parser::RuleCloseStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(771);
    match(VisualBasic6Parser::CLOSE);
    setState(787);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 77, _ctx)) {
    case 1: {
      setState(772);
      match(VisualBasic6Parser::WS);
      setState(773);
      valueStmt(0);
      setState(784);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 76, _ctx);
      while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
        if (alt == 1) {
          setState(775);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(774);
            match(VisualBasic6Parser::WS);
          }
          setState(777);
          match(VisualBasic6Parser::COMMA);
          setState(779);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 75, _ctx)) {
          case 1: {
            setState(778);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(781);
          valueStmt(0); 
        }
        setState(786);
        _errHandler->sync(this);
        alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 76, _ctx);
      }
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

//----------------- ConstStmtContext ------------------------------------------------------------------

VisualBasic6Parser::ConstStmtContext::ConstStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ConstStmtContext::CONST() {
  return getToken(VisualBasic6Parser::CONST, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ConstStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ConstStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ConstSubStmtContext *> VisualBasic6Parser::ConstStmtContext::constSubStmt() {
  return getRuleContexts<VisualBasic6Parser::ConstSubStmtContext>();
}

VisualBasic6Parser::ConstSubStmtContext* VisualBasic6Parser::ConstStmtContext::constSubStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ConstSubStmtContext>(i);
}

VisualBasic6Parser::PublicPrivateGlobalVisibilityContext* VisualBasic6Parser::ConstStmtContext::publicPrivateGlobalVisibility() {
  return getRuleContext<VisualBasic6Parser::PublicPrivateGlobalVisibilityContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ConstStmtContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::ConstStmtContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}


size_t VisualBasic6Parser::ConstStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleConstStmt;
}

antlrcpp::Any VisualBasic6Parser::ConstStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitConstStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ConstStmtContext* VisualBasic6Parser::constStmt() {
  ConstStmtContext *_localctx = _tracker.createInstance<ConstStmtContext>(_ctx, getState());
  enterRule(_localctx, 62, VisualBasic6Parser::RuleConstStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(792);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 72) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 72)) & ((1ULL << (VisualBasic6Parser::GLOBAL - 72))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 72))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 72)))) != 0)) {
      setState(789);
      publicPrivateGlobalVisibility();
      setState(790);
      match(VisualBasic6Parser::WS);
    }
    setState(794);
    match(VisualBasic6Parser::CONST);
    setState(795);
    match(VisualBasic6Parser::WS);
    setState(796);
    constSubStmt();
    setState(807);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 81, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(798);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(797);
          match(VisualBasic6Parser::WS);
        }
        setState(800);
        match(VisualBasic6Parser::COMMA);
        setState(802);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(801);
          match(VisualBasic6Parser::WS);
        }
        setState(804);
        constSubStmt(); 
      }
      setState(809);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 81, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ConstSubStmtContext ------------------------------------------------------------------

VisualBasic6Parser::ConstSubStmtContext::ConstSubStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::ConstSubStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ConstSubStmtContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::ConstSubStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

VisualBasic6Parser::TypeHintContext* VisualBasic6Parser::ConstSubStmtContext::typeHint() {
  return getRuleContext<VisualBasic6Parser::TypeHintContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ConstSubStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ConstSubStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AsTypeClauseContext* VisualBasic6Parser::ConstSubStmtContext::asTypeClause() {
  return getRuleContext<VisualBasic6Parser::AsTypeClauseContext>(0);
}


size_t VisualBasic6Parser::ConstSubStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleConstSubStmt;
}

antlrcpp::Any VisualBasic6Parser::ConstSubStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitConstSubStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ConstSubStmtContext* VisualBasic6Parser::constSubStmt() {
  ConstSubStmtContext *_localctx = _tracker.createInstance<ConstSubStmtContext>(_ctx, getState());
  enterRule(_localctx, 64, VisualBasic6Parser::RuleConstSubStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(810);
    ambiguousIdentifier();
    setState(812);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 178) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 178)) & ((1ULL << (VisualBasic6Parser::AMPERSAND - 178))
      | (1ULL << (VisualBasic6Parser::AT - 178))
      | (1ULL << (VisualBasic6Parser::DOLLAR - 178))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 178))
      | (1ULL << (VisualBasic6Parser::HASH - 178))
      | (1ULL << (VisualBasic6Parser::PERCENT - 178)))) != 0)) {
      setState(811);
      typeHint();
    }
    setState(816);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 83, _ctx)) {
    case 1: {
      setState(814);
      match(VisualBasic6Parser::WS);
      setState(815);
      asTypeClause();
      break;
    }

    }
    setState(819);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(818);
      match(VisualBasic6Parser::WS);
    }
    setState(821);
    match(VisualBasic6Parser::EQ);
    setState(823);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 85, _ctx)) {
    case 1: {
      setState(822);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(825);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- DateStmtContext ------------------------------------------------------------------

VisualBasic6Parser::DateStmtContext::DateStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::DateStmtContext::DATE() {
  return getToken(VisualBasic6Parser::DATE, 0);
}

tree::TerminalNode* VisualBasic6Parser::DateStmtContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::DateStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::DateStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::DateStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}


size_t VisualBasic6Parser::DateStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleDateStmt;
}

antlrcpp::Any VisualBasic6Parser::DateStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitDateStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::DateStmtContext* VisualBasic6Parser::dateStmt() {
  DateStmtContext *_localctx = _tracker.createInstance<DateStmtContext>(_ctx, getState());
  enterRule(_localctx, 66, VisualBasic6Parser::RuleDateStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(827);
    match(VisualBasic6Parser::DATE);
    setState(829);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(828);
      match(VisualBasic6Parser::WS);
    }
    setState(831);
    match(VisualBasic6Parser::EQ);
    setState(833);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 87, _ctx)) {
    case 1: {
      setState(832);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(835);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- DeclareStmtContext ------------------------------------------------------------------

VisualBasic6Parser::DeclareStmtContext::DeclareStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::DeclareStmtContext::DECLARE() {
  return getToken(VisualBasic6Parser::DECLARE, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::DeclareStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::DeclareStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::DeclareStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::DeclareStmtContext::LIB() {
  return getToken(VisualBasic6Parser::LIB, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::DeclareStmtContext::STRINGLITERAL() {
  return getTokens(VisualBasic6Parser::STRINGLITERAL);
}

tree::TerminalNode* VisualBasic6Parser::DeclareStmtContext::STRINGLITERAL(size_t i) {
  return getToken(VisualBasic6Parser::STRINGLITERAL, i);
}

tree::TerminalNode* VisualBasic6Parser::DeclareStmtContext::FUNCTION() {
  return getToken(VisualBasic6Parser::FUNCTION, 0);
}

tree::TerminalNode* VisualBasic6Parser::DeclareStmtContext::SUB() {
  return getToken(VisualBasic6Parser::SUB, 0);
}

VisualBasic6Parser::VisibilityContext* VisualBasic6Parser::DeclareStmtContext::visibility() {
  return getRuleContext<VisualBasic6Parser::VisibilityContext>(0);
}

std::vector<VisualBasic6Parser::TypeHintContext *> VisualBasic6Parser::DeclareStmtContext::typeHint() {
  return getRuleContexts<VisualBasic6Parser::TypeHintContext>();
}

VisualBasic6Parser::TypeHintContext* VisualBasic6Parser::DeclareStmtContext::typeHint(size_t i) {
  return getRuleContext<VisualBasic6Parser::TypeHintContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::DeclareStmtContext::ALIAS() {
  return getToken(VisualBasic6Parser::ALIAS, 0);
}

VisualBasic6Parser::ArgListContext* VisualBasic6Parser::DeclareStmtContext::argList() {
  return getRuleContext<VisualBasic6Parser::ArgListContext>(0);
}

VisualBasic6Parser::AsTypeClauseContext* VisualBasic6Parser::DeclareStmtContext::asTypeClause() {
  return getRuleContext<VisualBasic6Parser::AsTypeClauseContext>(0);
}


size_t VisualBasic6Parser::DeclareStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleDeclareStmt;
}

antlrcpp::Any VisualBasic6Parser::DeclareStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitDeclareStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::DeclareStmtContext* VisualBasic6Parser::declareStmt() {
  DeclareStmtContext *_localctx = _tracker.createInstance<DeclareStmtContext>(_ctx, getState());
  enterRule(_localctx, 68, VisualBasic6Parser::RuleDeclareStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(840);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 68) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 68)) & ((1ULL << (VisualBasic6Parser::FRIEND - 68))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 68))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 68))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 68)))) != 0)) {
      setState(837);
      visibility();
      setState(838);
      match(VisualBasic6Parser::WS);
    }
    setState(842);
    match(VisualBasic6Parser::DECLARE);
    setState(843);
    match(VisualBasic6Parser::WS);
    setState(849);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case VisualBasic6Parser::FUNCTION: {
        setState(844);
        match(VisualBasic6Parser::FUNCTION);
        setState(846);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (((((_la - 178) & ~ 0x3fULL) == 0) &&
          ((1ULL << (_la - 178)) & ((1ULL << (VisualBasic6Parser::AMPERSAND - 178))
          | (1ULL << (VisualBasic6Parser::AT - 178))
          | (1ULL << (VisualBasic6Parser::DOLLAR - 178))
          | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 178))
          | (1ULL << (VisualBasic6Parser::HASH - 178))
          | (1ULL << (VisualBasic6Parser::PERCENT - 178)))) != 0)) {
          setState(845);
          typeHint();
        }
        break;
      }

      case VisualBasic6Parser::SUB: {
        setState(848);
        match(VisualBasic6Parser::SUB);
        break;
      }

    default:
      throw NoViableAltException(this);
    }
    setState(851);
    match(VisualBasic6Parser::WS);
    setState(852);
    ambiguousIdentifier();
    setState(854);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 178) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 178)) & ((1ULL << (VisualBasic6Parser::AMPERSAND - 178))
      | (1ULL << (VisualBasic6Parser::AT - 178))
      | (1ULL << (VisualBasic6Parser::DOLLAR - 178))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 178))
      | (1ULL << (VisualBasic6Parser::HASH - 178))
      | (1ULL << (VisualBasic6Parser::PERCENT - 178)))) != 0)) {
      setState(853);
      typeHint();
    }
    setState(856);
    match(VisualBasic6Parser::WS);
    setState(857);
    match(VisualBasic6Parser::LIB);
    setState(858);
    match(VisualBasic6Parser::WS);
    setState(859);
    match(VisualBasic6Parser::STRINGLITERAL);
    setState(864);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 92, _ctx)) {
    case 1: {
      setState(860);
      match(VisualBasic6Parser::WS);
      setState(861);
      match(VisualBasic6Parser::ALIAS);
      setState(862);
      match(VisualBasic6Parser::WS);
      setState(863);
      match(VisualBasic6Parser::STRINGLITERAL);
      break;
    }

    }
    setState(870);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 94, _ctx)) {
    case 1: {
      setState(867);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(866);
        match(VisualBasic6Parser::WS);
      }
      setState(869);
      argList();
      break;
    }

    }
    setState(874);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 95, _ctx)) {
    case 1: {
      setState(872);
      match(VisualBasic6Parser::WS);
      setState(873);
      asTypeClause();
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

//----------------- DeftypeStmtContext ------------------------------------------------------------------

VisualBasic6Parser::DeftypeStmtContext::DeftypeStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::DeftypeStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::DeftypeStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::LetterrangeContext *> VisualBasic6Parser::DeftypeStmtContext::letterrange() {
  return getRuleContexts<VisualBasic6Parser::LetterrangeContext>();
}

VisualBasic6Parser::LetterrangeContext* VisualBasic6Parser::DeftypeStmtContext::letterrange(size_t i) {
  return getRuleContext<VisualBasic6Parser::LetterrangeContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::DeftypeStmtContext::DEFBOOL() {
  return getToken(VisualBasic6Parser::DEFBOOL, 0);
}

tree::TerminalNode* VisualBasic6Parser::DeftypeStmtContext::DEFBYTE() {
  return getToken(VisualBasic6Parser::DEFBYTE, 0);
}

tree::TerminalNode* VisualBasic6Parser::DeftypeStmtContext::DEFINT() {
  return getToken(VisualBasic6Parser::DEFINT, 0);
}

tree::TerminalNode* VisualBasic6Parser::DeftypeStmtContext::DEFLNG() {
  return getToken(VisualBasic6Parser::DEFLNG, 0);
}

tree::TerminalNode* VisualBasic6Parser::DeftypeStmtContext::DEFCUR() {
  return getToken(VisualBasic6Parser::DEFCUR, 0);
}

tree::TerminalNode* VisualBasic6Parser::DeftypeStmtContext::DEFSNG() {
  return getToken(VisualBasic6Parser::DEFSNG, 0);
}

tree::TerminalNode* VisualBasic6Parser::DeftypeStmtContext::DEFDBL() {
  return getToken(VisualBasic6Parser::DEFDBL, 0);
}

tree::TerminalNode* VisualBasic6Parser::DeftypeStmtContext::DEFDEC() {
  return getToken(VisualBasic6Parser::DEFDEC, 0);
}

tree::TerminalNode* VisualBasic6Parser::DeftypeStmtContext::DEFDATE() {
  return getToken(VisualBasic6Parser::DEFDATE, 0);
}

tree::TerminalNode* VisualBasic6Parser::DeftypeStmtContext::DEFSTR() {
  return getToken(VisualBasic6Parser::DEFSTR, 0);
}

tree::TerminalNode* VisualBasic6Parser::DeftypeStmtContext::DEFOBJ() {
  return getToken(VisualBasic6Parser::DEFOBJ, 0);
}

tree::TerminalNode* VisualBasic6Parser::DeftypeStmtContext::DEFVAR() {
  return getToken(VisualBasic6Parser::DEFVAR, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::DeftypeStmtContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::DeftypeStmtContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}


size_t VisualBasic6Parser::DeftypeStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleDeftypeStmt;
}

antlrcpp::Any VisualBasic6Parser::DeftypeStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitDeftypeStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::DeftypeStmtContext* VisualBasic6Parser::deftypeStmt() {
  DeftypeStmtContext *_localctx = _tracker.createInstance<DeftypeStmtContext>(_ctx, getState());
  enterRule(_localctx, 70, VisualBasic6Parser::RuleDeftypeStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(876);
    _la = _input->LA(1);
    if (!((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR))) != 0))) {
    _errHandler->recoverInline(this);
    }
    else {
      _errHandler->reportMatch(this);
      consume();
    }
    setState(877);
    match(VisualBasic6Parser::WS);
    setState(878);
    letterrange();
    setState(889);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 98, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(880);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(879);
          match(VisualBasic6Parser::WS);
        }
        setState(882);
        match(VisualBasic6Parser::COMMA);
        setState(884);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(883);
          match(VisualBasic6Parser::WS);
        }
        setState(886);
        letterrange(); 
      }
      setState(891);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 98, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- DeleteSettingStmtContext ------------------------------------------------------------------

VisualBasic6Parser::DeleteSettingStmtContext::DeleteSettingStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::DeleteSettingStmtContext::DELETESETTING() {
  return getToken(VisualBasic6Parser::DELETESETTING, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::DeleteSettingStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::DeleteSettingStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::DeleteSettingStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::DeleteSettingStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::DeleteSettingStmtContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::DeleteSettingStmtContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}


size_t VisualBasic6Parser::DeleteSettingStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleDeleteSettingStmt;
}

antlrcpp::Any VisualBasic6Parser::DeleteSettingStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitDeleteSettingStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::DeleteSettingStmtContext* VisualBasic6Parser::deleteSettingStmt() {
  DeleteSettingStmtContext *_localctx = _tracker.createInstance<DeleteSettingStmtContext>(_ctx, getState());
  enterRule(_localctx, 72, VisualBasic6Parser::RuleDeleteSettingStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(892);
    match(VisualBasic6Parser::DELETESETTING);
    setState(893);
    match(VisualBasic6Parser::WS);
    setState(894);
    valueStmt(0);
    setState(896);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(895);
      match(VisualBasic6Parser::WS);
    }
    setState(898);
    match(VisualBasic6Parser::COMMA);
    setState(900);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 100, _ctx)) {
    case 1: {
      setState(899);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(902);
    valueStmt(0);
    setState(911);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 103, _ctx)) {
    case 1: {
      setState(904);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(903);
        match(VisualBasic6Parser::WS);
      }
      setState(906);
      match(VisualBasic6Parser::COMMA);
      setState(908);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 102, _ctx)) {
      case 1: {
        setState(907);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(910);
      valueStmt(0);
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

//----------------- DoLoopStmtContext ------------------------------------------------------------------

VisualBasic6Parser::DoLoopStmtContext::DoLoopStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::DoLoopStmtContext::DO() {
  return getToken(VisualBasic6Parser::DO, 0);
}

tree::TerminalNode* VisualBasic6Parser::DoLoopStmtContext::LOOP() {
  return getToken(VisualBasic6Parser::LOOP, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::DoLoopStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::DoLoopStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::DoLoopStmtContext::block() {
  return getRuleContext<VisualBasic6Parser::BlockContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::DoLoopStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::DoLoopStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::DoLoopStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::DoLoopStmtContext::WHILE() {
  return getToken(VisualBasic6Parser::WHILE, 0);
}

tree::TerminalNode* VisualBasic6Parser::DoLoopStmtContext::UNTIL() {
  return getToken(VisualBasic6Parser::UNTIL, 0);
}


size_t VisualBasic6Parser::DoLoopStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleDoLoopStmt;
}

antlrcpp::Any VisualBasic6Parser::DoLoopStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitDoLoopStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::DoLoopStmtContext* VisualBasic6Parser::doLoopStmt() {
  DoLoopStmtContext *_localctx = _tracker.createInstance<DoLoopStmtContext>(_ctx, getState());
  enterRule(_localctx, 74, VisualBasic6Parser::RuleDoLoopStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(966);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 112, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(913);
      match(VisualBasic6Parser::DO);
      setState(915); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(914);
        match(VisualBasic6Parser::NEWLINE);
        setState(917); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
      setState(925);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 106, _ctx)) {
      case 1: {
        setState(919);
        block();
        setState(921); 
        _errHandler->sync(this);
        _la = _input->LA(1);
        do {
          setState(920);
          match(VisualBasic6Parser::NEWLINE);
          setState(923); 
          _errHandler->sync(this);
          _la = _input->LA(1);
        } while (_la == VisualBasic6Parser::NEWLINE);
        break;
      }

      }
      setState(927);
      match(VisualBasic6Parser::LOOP);
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(928);
      match(VisualBasic6Parser::DO);
      setState(929);
      match(VisualBasic6Parser::WS);
      setState(930);
      _la = _input->LA(1);
      if (!(_la == VisualBasic6Parser::UNTIL

      || _la == VisualBasic6Parser::WHILE)) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      setState(931);
      match(VisualBasic6Parser::WS);
      setState(932);
      valueStmt(0);
      setState(934); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(933);
        match(VisualBasic6Parser::NEWLINE);
        setState(936); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
      setState(944);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 109, _ctx)) {
      case 1: {
        setState(938);
        block();
        setState(940); 
        _errHandler->sync(this);
        _la = _input->LA(1);
        do {
          setState(939);
          match(VisualBasic6Parser::NEWLINE);
          setState(942); 
          _errHandler->sync(this);
          _la = _input->LA(1);
        } while (_la == VisualBasic6Parser::NEWLINE);
        break;
      }

      }
      setState(946);
      match(VisualBasic6Parser::LOOP);
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(948);
      match(VisualBasic6Parser::DO);
      setState(950); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(949);
        match(VisualBasic6Parser::NEWLINE);
        setState(952); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);

      setState(954);
      block();
      setState(956); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(955);
        match(VisualBasic6Parser::NEWLINE);
        setState(958); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
      setState(960);
      match(VisualBasic6Parser::LOOP);
      setState(961);
      match(VisualBasic6Parser::WS);
      setState(962);
      _la = _input->LA(1);
      if (!(_la == VisualBasic6Parser::UNTIL

      || _la == VisualBasic6Parser::WHILE)) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      setState(963);
      match(VisualBasic6Parser::WS);
      setState(964);
      valueStmt(0);
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

//----------------- EndStmtContext ------------------------------------------------------------------

VisualBasic6Parser::EndStmtContext::EndStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::EndStmtContext::END() {
  return getToken(VisualBasic6Parser::END, 0);
}


size_t VisualBasic6Parser::EndStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleEndStmt;
}

antlrcpp::Any VisualBasic6Parser::EndStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitEndStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::EndStmtContext* VisualBasic6Parser::endStmt() {
  EndStmtContext *_localctx = _tracker.createInstance<EndStmtContext>(_ctx, getState());
  enterRule(_localctx, 76, VisualBasic6Parser::RuleEndStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(968);
    match(VisualBasic6Parser::END);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- EnumerationStmtContext ------------------------------------------------------------------

VisualBasic6Parser::EnumerationStmtContext::EnumerationStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::EnumerationStmtContext::ENUM() {
  return getToken(VisualBasic6Parser::ENUM, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::EnumerationStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::EnumerationStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::EnumerationStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::EnumerationStmtContext::END_ENUM() {
  return getToken(VisualBasic6Parser::END_ENUM, 0);
}

VisualBasic6Parser::PublicPrivateVisibilityContext* VisualBasic6Parser::EnumerationStmtContext::publicPrivateVisibility() {
  return getRuleContext<VisualBasic6Parser::PublicPrivateVisibilityContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::EnumerationStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::EnumerationStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

std::vector<VisualBasic6Parser::EnumerationStmt_ConstantContext *> VisualBasic6Parser::EnumerationStmtContext::enumerationStmt_Constant() {
  return getRuleContexts<VisualBasic6Parser::EnumerationStmt_ConstantContext>();
}

VisualBasic6Parser::EnumerationStmt_ConstantContext* VisualBasic6Parser::EnumerationStmtContext::enumerationStmt_Constant(size_t i) {
  return getRuleContext<VisualBasic6Parser::EnumerationStmt_ConstantContext>(i);
}


size_t VisualBasic6Parser::EnumerationStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleEnumerationStmt;
}

antlrcpp::Any VisualBasic6Parser::EnumerationStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitEnumerationStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::EnumerationStmtContext* VisualBasic6Parser::enumerationStmt() {
  EnumerationStmtContext *_localctx = _tracker.createInstance<EnumerationStmtContext>(_ctx, getState());
  enterRule(_localctx, 78, VisualBasic6Parser::RuleEnumerationStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(973);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::PRIVATE

    || _la == VisualBasic6Parser::PUBLIC) {
      setState(970);
      publicPrivateVisibility();
      setState(971);
      match(VisualBasic6Parser::WS);
    }
    setState(975);
    match(VisualBasic6Parser::ENUM);
    setState(976);
    match(VisualBasic6Parser::WS);
    setState(977);
    ambiguousIdentifier();
    setState(979); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(978);
      match(VisualBasic6Parser::NEWLINE);
      setState(981); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(986);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
      | (1ULL << VisualBasic6Parser::ADDRESSOF)
      | (1ULL << VisualBasic6Parser::ALIAS)
      | (1ULL << VisualBasic6Parser::AND)
      | (1ULL << VisualBasic6Parser::ATTRIBUTE)
      | (1ULL << VisualBasic6Parser::APPACTIVATE)
      | (1ULL << VisualBasic6Parser::APPEND)
      | (1ULL << VisualBasic6Parser::AS)
      | (1ULL << VisualBasic6Parser::BEEP)
      | (1ULL << VisualBasic6Parser::BEGIN)
      | (1ULL << VisualBasic6Parser::BINARY)
      | (1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYVAL)
      | (1ULL << VisualBasic6Parser::BYREF)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::CALL)
      | (1ULL << VisualBasic6Parser::CASE)
      | (1ULL << VisualBasic6Parser::CHDIR)
      | (1ULL << VisualBasic6Parser::CHDRIVE)
      | (1ULL << VisualBasic6Parser::CLASS)
      | (1ULL << VisualBasic6Parser::CLOSE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::CONST)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DECLARE)
      | (1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR)
      | (1ULL << VisualBasic6Parser::DELETESETTING)
      | (1ULL << VisualBasic6Parser::DIM)
      | (1ULL << VisualBasic6Parser::DO)
      | (1ULL << VisualBasic6Parser::DOUBLE)
      | (1ULL << VisualBasic6Parser::EACH)
      | (1ULL << VisualBasic6Parser::ELSE)
      | (1ULL << VisualBasic6Parser::ELSEIF)
      | (1ULL << VisualBasic6Parser::END)
      | (1ULL << VisualBasic6Parser::ENUM)
      | (1ULL << VisualBasic6Parser::EQV)
      | (1ULL << VisualBasic6Parser::ERASE)
      | (1ULL << VisualBasic6Parser::ERROR)
      | (1ULL << VisualBasic6Parser::EVENT))) != 0) || ((((_la - 66) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 66)) & ((1ULL << (VisualBasic6Parser::FALSE1 - 66))
      | (1ULL << (VisualBasic6Parser::FILECOPY - 66))
      | (1ULL << (VisualBasic6Parser::FRIEND - 66))
      | (1ULL << (VisualBasic6Parser::FOR - 66))
      | (1ULL << (VisualBasic6Parser::FUNCTION - 66))
      | (1ULL << (VisualBasic6Parser::GET - 66))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 66))
      | (1ULL << (VisualBasic6Parser::GOSUB - 66))
      | (1ULL << (VisualBasic6Parser::GOTO - 66))
      | (1ULL << (VisualBasic6Parser::IF - 66))
      | (1ULL << (VisualBasic6Parser::IMP - 66))
      | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 66))
      | (1ULL << (VisualBasic6Parser::IN - 66))
      | (1ULL << (VisualBasic6Parser::INPUT - 66))
      | (1ULL << (VisualBasic6Parser::IS - 66))
      | (1ULL << (VisualBasic6Parser::INTEGER - 66))
      | (1ULL << (VisualBasic6Parser::KILL - 66))
      | (1ULL << (VisualBasic6Parser::LOAD - 66))
      | (1ULL << (VisualBasic6Parser::LOCK - 66))
      | (1ULL << (VisualBasic6Parser::LONG - 66))
      | (1ULL << (VisualBasic6Parser::LOOP - 66))
      | (1ULL << (VisualBasic6Parser::LEN - 66))
      | (1ULL << (VisualBasic6Parser::LET - 66))
      | (1ULL << (VisualBasic6Parser::LIB - 66))
      | (1ULL << (VisualBasic6Parser::LIKE - 66))
      | (1ULL << (VisualBasic6Parser::LSET - 66))
      | (1ULL << (VisualBasic6Parser::ME - 66))
      | (1ULL << (VisualBasic6Parser::MID - 66))
      | (1ULL << (VisualBasic6Parser::MKDIR - 66))
      | (1ULL << (VisualBasic6Parser::MOD - 66))
      | (1ULL << (VisualBasic6Parser::NAME - 66))
      | (1ULL << (VisualBasic6Parser::NEXT - 66))
      | (1ULL << (VisualBasic6Parser::NEW - 66))
      | (1ULL << (VisualBasic6Parser::NOT - 66))
      | (1ULL << (VisualBasic6Parser::NOTHING - 66))
      | (1ULL << (VisualBasic6Parser::NULL1 - 66))
      | (1ULL << (VisualBasic6Parser::OBJECT - 66))
      | (1ULL << (VisualBasic6Parser::ON - 66))
      | (1ULL << (VisualBasic6Parser::OPEN - 66))
      | (1ULL << (VisualBasic6Parser::OPTIONAL - 66))
      | (1ULL << (VisualBasic6Parser::OR - 66))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 66))
      | (1ULL << (VisualBasic6Parser::PARAMARRAY - 66))
      | (1ULL << (VisualBasic6Parser::PRESERVE - 66))
      | (1ULL << (VisualBasic6Parser::PRINT - 66))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 66))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 66)))) != 0) || ((((_la - 130) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 130)) & ((1ULL << (VisualBasic6Parser::PUT - 130))
      | (1ULL << (VisualBasic6Parser::RANDOM - 130))
      | (1ULL << (VisualBasic6Parser::RANDOMIZE - 130))
      | (1ULL << (VisualBasic6Parser::RAISEEVENT - 130))
      | (1ULL << (VisualBasic6Parser::READ - 130))
      | (1ULL << (VisualBasic6Parser::REDIM - 130))
      | (1ULL << (VisualBasic6Parser::REM - 130))
      | (1ULL << (VisualBasic6Parser::RESET - 130))
      | (1ULL << (VisualBasic6Parser::RESUME - 130))
      | (1ULL << (VisualBasic6Parser::RETURN - 130))
      | (1ULL << (VisualBasic6Parser::RMDIR - 130))
      | (1ULL << (VisualBasic6Parser::RSET - 130))
      | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 130))
      | (1ULL << (VisualBasic6Parser::SAVESETTING - 130))
      | (1ULL << (VisualBasic6Parser::SEEK - 130))
      | (1ULL << (VisualBasic6Parser::SELECT - 130))
      | (1ULL << (VisualBasic6Parser::SENDKEYS - 130))
      | (1ULL << (VisualBasic6Parser::SET - 130))
      | (1ULL << (VisualBasic6Parser::SETATTR - 130))
      | (1ULL << (VisualBasic6Parser::SHARED - 130))
      | (1ULL << (VisualBasic6Parser::SINGLE - 130))
      | (1ULL << (VisualBasic6Parser::SPC - 130))
      | (1ULL << (VisualBasic6Parser::STATIC - 130))
      | (1ULL << (VisualBasic6Parser::STEP - 130))
      | (1ULL << (VisualBasic6Parser::STOP - 130))
      | (1ULL << (VisualBasic6Parser::STRING - 130))
      | (1ULL << (VisualBasic6Parser::SUB - 130))
      | (1ULL << (VisualBasic6Parser::TAB - 130))
      | (1ULL << (VisualBasic6Parser::TEXT - 130))
      | (1ULL << (VisualBasic6Parser::THEN - 130))
      | (1ULL << (VisualBasic6Parser::TIME - 130))
      | (1ULL << (VisualBasic6Parser::TO - 130))
      | (1ULL << (VisualBasic6Parser::TRUE1 - 130))
      | (1ULL << (VisualBasic6Parser::TYPE - 130))
      | (1ULL << (VisualBasic6Parser::TYPEOF - 130))
      | (1ULL << (VisualBasic6Parser::UNLOAD - 130))
      | (1ULL << (VisualBasic6Parser::UNLOCK - 130))
      | (1ULL << (VisualBasic6Parser::UNTIL - 130))
      | (1ULL << (VisualBasic6Parser::VARIANT - 130))
      | (1ULL << (VisualBasic6Parser::VERSION - 130))
      | (1ULL << (VisualBasic6Parser::WEND - 130))
      | (1ULL << (VisualBasic6Parser::WHILE - 130))
      | (1ULL << (VisualBasic6Parser::WIDTH - 130))
      | (1ULL << (VisualBasic6Parser::WITH - 130))
      | (1ULL << (VisualBasic6Parser::WITHEVENTS - 130))
      | (1ULL << (VisualBasic6Parser::WRITE - 130))
      | (1ULL << (VisualBasic6Parser::XOR - 130)))) != 0) || _la == VisualBasic6Parser::L_SQUARE_BRACKET

    || _la == VisualBasic6Parser::IDENTIFIER) {
      setState(983);
      enumerationStmt_Constant();
      setState(988);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
    setState(989);
    match(VisualBasic6Parser::END_ENUM);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- EnumerationStmt_ConstantContext ------------------------------------------------------------------

VisualBasic6Parser::EnumerationStmt_ConstantContext::EnumerationStmt_ConstantContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::EnumerationStmt_ConstantContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::EnumerationStmt_ConstantContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::EnumerationStmt_ConstantContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::EnumerationStmt_ConstantContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::EnumerationStmt_ConstantContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::EnumerationStmt_ConstantContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::EnumerationStmt_ConstantContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}


size_t VisualBasic6Parser::EnumerationStmt_ConstantContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleEnumerationStmt_Constant;
}

antlrcpp::Any VisualBasic6Parser::EnumerationStmt_ConstantContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitEnumerationStmt_Constant(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::EnumerationStmt_ConstantContext* VisualBasic6Parser::enumerationStmt_Constant() {
  EnumerationStmt_ConstantContext *_localctx = _tracker.createInstance<EnumerationStmt_ConstantContext>(_ctx, getState());
  enterRule(_localctx, 80, VisualBasic6Parser::RuleEnumerationStmt_Constant);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(991);
    ambiguousIdentifier();
    setState(1000);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::EQ

    || _la == VisualBasic6Parser::WS) {
      setState(993);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(992);
        match(VisualBasic6Parser::WS);
      }
      setState(995);
      match(VisualBasic6Parser::EQ);
      setState(997);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 117, _ctx)) {
      case 1: {
        setState(996);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(999);
      valueStmt(0);
    }
    setState(1003); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(1002);
      match(VisualBasic6Parser::NEWLINE);
      setState(1005); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- EraseStmtContext ------------------------------------------------------------------

VisualBasic6Parser::EraseStmtContext::EraseStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::EraseStmtContext::ERASE() {
  return getToken(VisualBasic6Parser::ERASE, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::EraseStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::EraseStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::EraseStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::EraseStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::EraseStmtContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::EraseStmtContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}


size_t VisualBasic6Parser::EraseStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleEraseStmt;
}

antlrcpp::Any VisualBasic6Parser::EraseStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitEraseStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::EraseStmtContext* VisualBasic6Parser::eraseStmt() {
  EraseStmtContext *_localctx = _tracker.createInstance<EraseStmtContext>(_ctx, getState());
  enterRule(_localctx, 82, VisualBasic6Parser::RuleEraseStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(1007);
    match(VisualBasic6Parser::ERASE);
    setState(1008);
    match(VisualBasic6Parser::WS);
    setState(1009);
    valueStmt(0);
    setState(1020);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 122, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(1011);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(1010);
          match(VisualBasic6Parser::WS);
        }
        setState(1013);
        match(VisualBasic6Parser::COMMA);
        setState(1015);
        _errHandler->sync(this);

        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 121, _ctx)) {
        case 1: {
          setState(1014);
          match(VisualBasic6Parser::WS);
          break;
        }

        }
        setState(1017);
        valueStmt(0); 
      }
      setState(1022);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 122, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ErrorStmtContext ------------------------------------------------------------------

VisualBasic6Parser::ErrorStmtContext::ErrorStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ErrorStmtContext::ERROR() {
  return getToken(VisualBasic6Parser::ERROR, 0);
}

tree::TerminalNode* VisualBasic6Parser::ErrorStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::ErrorStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::ErrorStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleErrorStmt;
}

antlrcpp::Any VisualBasic6Parser::ErrorStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitErrorStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ErrorStmtContext* VisualBasic6Parser::errorStmt() {
  ErrorStmtContext *_localctx = _tracker.createInstance<ErrorStmtContext>(_ctx, getState());
  enterRule(_localctx, 84, VisualBasic6Parser::RuleErrorStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1023);
    match(VisualBasic6Parser::ERROR);
    setState(1024);
    match(VisualBasic6Parser::WS);
    setState(1025);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- EventStmtContext ------------------------------------------------------------------

VisualBasic6Parser::EventStmtContext::EventStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::EventStmtContext::EVENT() {
  return getToken(VisualBasic6Parser::EVENT, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::EventStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::EventStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::EventStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

VisualBasic6Parser::ArgListContext* VisualBasic6Parser::EventStmtContext::argList() {
  return getRuleContext<VisualBasic6Parser::ArgListContext>(0);
}

VisualBasic6Parser::VisibilityContext* VisualBasic6Parser::EventStmtContext::visibility() {
  return getRuleContext<VisualBasic6Parser::VisibilityContext>(0);
}


size_t VisualBasic6Parser::EventStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleEventStmt;
}

antlrcpp::Any VisualBasic6Parser::EventStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitEventStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::EventStmtContext* VisualBasic6Parser::eventStmt() {
  EventStmtContext *_localctx = _tracker.createInstance<EventStmtContext>(_ctx, getState());
  enterRule(_localctx, 86, VisualBasic6Parser::RuleEventStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1030);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 68) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 68)) & ((1ULL << (VisualBasic6Parser::FRIEND - 68))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 68))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 68))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 68)))) != 0)) {
      setState(1027);
      visibility();
      setState(1028);
      match(VisualBasic6Parser::WS);
    }
    setState(1032);
    match(VisualBasic6Parser::EVENT);
    setState(1033);
    match(VisualBasic6Parser::WS);
    setState(1034);
    ambiguousIdentifier();
    setState(1036);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1035);
      match(VisualBasic6Parser::WS);
    }
    setState(1038);
    argList();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ExitStmtContext ------------------------------------------------------------------

VisualBasic6Parser::ExitStmtContext::ExitStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ExitStmtContext::EXIT_DO() {
  return getToken(VisualBasic6Parser::EXIT_DO, 0);
}

tree::TerminalNode* VisualBasic6Parser::ExitStmtContext::EXIT_FOR() {
  return getToken(VisualBasic6Parser::EXIT_FOR, 0);
}

tree::TerminalNode* VisualBasic6Parser::ExitStmtContext::EXIT_FUNCTION() {
  return getToken(VisualBasic6Parser::EXIT_FUNCTION, 0);
}

tree::TerminalNode* VisualBasic6Parser::ExitStmtContext::EXIT_PROPERTY() {
  return getToken(VisualBasic6Parser::EXIT_PROPERTY, 0);
}

tree::TerminalNode* VisualBasic6Parser::ExitStmtContext::EXIT_SUB() {
  return getToken(VisualBasic6Parser::EXIT_SUB, 0);
}


size_t VisualBasic6Parser::ExitStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleExitStmt;
}

antlrcpp::Any VisualBasic6Parser::ExitStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitExitStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ExitStmtContext* VisualBasic6Parser::exitStmt() {
  ExitStmtContext *_localctx = _tracker.createInstance<ExitStmtContext>(_ctx, getState());
  enterRule(_localctx, 88, VisualBasic6Parser::RuleExitStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1040);
    _la = _input->LA(1);
    if (!(((((_la - 61) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 61)) & ((1ULL << (VisualBasic6Parser::EXIT_DO - 61))
      | (1ULL << (VisualBasic6Parser::EXIT_FOR - 61))
      | (1ULL << (VisualBasic6Parser::EXIT_FUNCTION - 61))
      | (1ULL << (VisualBasic6Parser::EXIT_PROPERTY - 61))
      | (1ULL << (VisualBasic6Parser::EXIT_SUB - 61)))) != 0))) {
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

//----------------- FilecopyStmtContext ------------------------------------------------------------------

VisualBasic6Parser::FilecopyStmtContext::FilecopyStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::FilecopyStmtContext::FILECOPY() {
  return getToken(VisualBasic6Parser::FILECOPY, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::FilecopyStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::FilecopyStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::FilecopyStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::FilecopyStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::FilecopyStmtContext::COMMA() {
  return getToken(VisualBasic6Parser::COMMA, 0);
}


size_t VisualBasic6Parser::FilecopyStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleFilecopyStmt;
}

antlrcpp::Any VisualBasic6Parser::FilecopyStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitFilecopyStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::FilecopyStmtContext* VisualBasic6Parser::filecopyStmt() {
  FilecopyStmtContext *_localctx = _tracker.createInstance<FilecopyStmtContext>(_ctx, getState());
  enterRule(_localctx, 90, VisualBasic6Parser::RuleFilecopyStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1042);
    match(VisualBasic6Parser::FILECOPY);
    setState(1043);
    match(VisualBasic6Parser::WS);
    setState(1044);
    valueStmt(0);
    setState(1046);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1045);
      match(VisualBasic6Parser::WS);
    }
    setState(1048);
    match(VisualBasic6Parser::COMMA);
    setState(1050);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 126, _ctx)) {
    case 1: {
      setState(1049);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1052);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ForEachStmtContext ------------------------------------------------------------------

VisualBasic6Parser::ForEachStmtContext::ForEachStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ForEachStmtContext::FOR() {
  return getToken(VisualBasic6Parser::FOR, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ForEachStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ForEachStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

tree::TerminalNode* VisualBasic6Parser::ForEachStmtContext::EACH() {
  return getToken(VisualBasic6Parser::EACH, 0);
}

std::vector<VisualBasic6Parser::AmbiguousIdentifierContext *> VisualBasic6Parser::ForEachStmtContext::ambiguousIdentifier() {
  return getRuleContexts<VisualBasic6Parser::AmbiguousIdentifierContext>();
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::ForEachStmtContext::ambiguousIdentifier(size_t i) {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::ForEachStmtContext::IN() {
  return getToken(VisualBasic6Parser::IN, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::ForEachStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ForEachStmtContext::NEXT() {
  return getToken(VisualBasic6Parser::NEXT, 0);
}

VisualBasic6Parser::TypeHintContext* VisualBasic6Parser::ForEachStmtContext::typeHint() {
  return getRuleContext<VisualBasic6Parser::TypeHintContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ForEachStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::ForEachStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::ForEachStmtContext::block() {
  return getRuleContext<VisualBasic6Parser::BlockContext>(0);
}


size_t VisualBasic6Parser::ForEachStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleForEachStmt;
}

antlrcpp::Any VisualBasic6Parser::ForEachStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitForEachStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ForEachStmtContext* VisualBasic6Parser::forEachStmt() {
  ForEachStmtContext *_localctx = _tracker.createInstance<ForEachStmtContext>(_ctx, getState());
  enterRule(_localctx, 92, VisualBasic6Parser::RuleForEachStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1054);
    match(VisualBasic6Parser::FOR);
    setState(1055);
    match(VisualBasic6Parser::WS);
    setState(1056);
    match(VisualBasic6Parser::EACH);
    setState(1057);
    match(VisualBasic6Parser::WS);
    setState(1058);
    ambiguousIdentifier();
    setState(1060);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 178) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 178)) & ((1ULL << (VisualBasic6Parser::AMPERSAND - 178))
      | (1ULL << (VisualBasic6Parser::AT - 178))
      | (1ULL << (VisualBasic6Parser::DOLLAR - 178))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 178))
      | (1ULL << (VisualBasic6Parser::HASH - 178))
      | (1ULL << (VisualBasic6Parser::PERCENT - 178)))) != 0)) {
      setState(1059);
      typeHint();
    }
    setState(1062);
    match(VisualBasic6Parser::WS);
    setState(1063);
    match(VisualBasic6Parser::IN);
    setState(1064);
    match(VisualBasic6Parser::WS);
    setState(1065);
    valueStmt(0);
    setState(1067); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(1066);
      match(VisualBasic6Parser::NEWLINE);
      setState(1069); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(1077);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 130, _ctx)) {
    case 1: {
      setState(1071);
      block();
      setState(1073); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(1072);
        match(VisualBasic6Parser::NEWLINE);
        setState(1075); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
      break;
    }

    }
    setState(1079);
    match(VisualBasic6Parser::NEXT);
    setState(1082);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 131, _ctx)) {
    case 1: {
      setState(1080);
      match(VisualBasic6Parser::WS);
      setState(1081);
      ambiguousIdentifier();
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

//----------------- ForNextStmtContext ------------------------------------------------------------------

VisualBasic6Parser::ForNextStmtContext::ForNextStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ForNextStmtContext::FOR() {
  return getToken(VisualBasic6Parser::FOR, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ForNextStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ForNextStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext* VisualBasic6Parser::ForNextStmtContext::iCS_S_VariableOrProcedureCall() {
  return getRuleContext<VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ForNextStmtContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::ForNextStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::ForNextStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::ForNextStmtContext::TO() {
  return getToken(VisualBasic6Parser::TO, 0);
}

tree::TerminalNode* VisualBasic6Parser::ForNextStmtContext::NEXT() {
  return getToken(VisualBasic6Parser::NEXT, 0);
}

std::vector<VisualBasic6Parser::TypeHintContext *> VisualBasic6Parser::ForNextStmtContext::typeHint() {
  return getRuleContexts<VisualBasic6Parser::TypeHintContext>();
}

VisualBasic6Parser::TypeHintContext* VisualBasic6Parser::ForNextStmtContext::typeHint(size_t i) {
  return getRuleContext<VisualBasic6Parser::TypeHintContext>(i);
}

VisualBasic6Parser::AsTypeClauseContext* VisualBasic6Parser::ForNextStmtContext::asTypeClause() {
  return getRuleContext<VisualBasic6Parser::AsTypeClauseContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ForNextStmtContext::STEP() {
  return getToken(VisualBasic6Parser::STEP, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ForNextStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::ForNextStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::ForNextStmtContext::block() {
  return getRuleContext<VisualBasic6Parser::BlockContext>(0);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::ForNextStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}


size_t VisualBasic6Parser::ForNextStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleForNextStmt;
}

antlrcpp::Any VisualBasic6Parser::ForNextStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitForNextStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ForNextStmtContext* VisualBasic6Parser::forNextStmt() {
  ForNextStmtContext *_localctx = _tracker.createInstance<ForNextStmtContext>(_ctx, getState());
  enterRule(_localctx, 94, VisualBasic6Parser::RuleForNextStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1084);
    match(VisualBasic6Parser::FOR);
    setState(1085);
    match(VisualBasic6Parser::WS);
    setState(1086);
    iCS_S_VariableOrProcedureCall();
    setState(1088);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 178) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 178)) & ((1ULL << (VisualBasic6Parser::AMPERSAND - 178))
      | (1ULL << (VisualBasic6Parser::AT - 178))
      | (1ULL << (VisualBasic6Parser::DOLLAR - 178))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 178))
      | (1ULL << (VisualBasic6Parser::HASH - 178))
      | (1ULL << (VisualBasic6Parser::PERCENT - 178)))) != 0)) {
      setState(1087);
      typeHint();
    }
    setState(1092);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 133, _ctx)) {
    case 1: {
      setState(1090);
      match(VisualBasic6Parser::WS);
      setState(1091);
      asTypeClause();
      break;
    }

    }
    setState(1095);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1094);
      match(VisualBasic6Parser::WS);
    }
    setState(1097);
    match(VisualBasic6Parser::EQ);
    setState(1099);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 135, _ctx)) {
    case 1: {
      setState(1098);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1101);
    valueStmt(0);
    setState(1102);
    match(VisualBasic6Parser::WS);
    setState(1103);
    match(VisualBasic6Parser::TO);
    setState(1104);
    match(VisualBasic6Parser::WS);
    setState(1105);
    valueStmt(0);
    setState(1110);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1106);
      match(VisualBasic6Parser::WS);
      setState(1107);
      match(VisualBasic6Parser::STEP);
      setState(1108);
      match(VisualBasic6Parser::WS);
      setState(1109);
      valueStmt(0);
    }
    setState(1113); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(1112);
      match(VisualBasic6Parser::NEWLINE);
      setState(1115); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(1123);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 139, _ctx)) {
    case 1: {
      setState(1117);
      block();
      setState(1119); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(1118);
        match(VisualBasic6Parser::NEWLINE);
        setState(1121); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
      break;
    }

    }
    setState(1125);
    match(VisualBasic6Parser::NEXT);
    setState(1131);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 141, _ctx)) {
    case 1: {
      setState(1126);
      match(VisualBasic6Parser::WS);
      setState(1127);
      ambiguousIdentifier();
      setState(1129);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 140, _ctx)) {
      case 1: {
        setState(1128);
        typeHint();
        break;
      }

      }
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

//----------------- FunctionStmtContext ------------------------------------------------------------------

VisualBasic6Parser::FunctionStmtContext::FunctionStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::FunctionStmtContext::FUNCTION() {
  return getToken(VisualBasic6Parser::FUNCTION, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::FunctionStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::FunctionStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::FunctionStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::FunctionStmtContext::END_FUNCTION() {
  return getToken(VisualBasic6Parser::END_FUNCTION, 0);
}

VisualBasic6Parser::VisibilityContext* VisualBasic6Parser::FunctionStmtContext::visibility() {
  return getRuleContext<VisualBasic6Parser::VisibilityContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::FunctionStmtContext::STATIC() {
  return getToken(VisualBasic6Parser::STATIC, 0);
}

VisualBasic6Parser::ArgListContext* VisualBasic6Parser::FunctionStmtContext::argList() {
  return getRuleContext<VisualBasic6Parser::ArgListContext>(0);
}

VisualBasic6Parser::AsTypeClauseContext* VisualBasic6Parser::FunctionStmtContext::asTypeClause() {
  return getRuleContext<VisualBasic6Parser::AsTypeClauseContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::FunctionStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::FunctionStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::FunctionStmtContext::block() {
  return getRuleContext<VisualBasic6Parser::BlockContext>(0);
}


size_t VisualBasic6Parser::FunctionStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleFunctionStmt;
}

antlrcpp::Any VisualBasic6Parser::FunctionStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitFunctionStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::FunctionStmtContext* VisualBasic6Parser::functionStmt() {
  FunctionStmtContext *_localctx = _tracker.createInstance<FunctionStmtContext>(_ctx, getState());
  enterRule(_localctx, 96, VisualBasic6Parser::RuleFunctionStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1136);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 68) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 68)) & ((1ULL << (VisualBasic6Parser::FRIEND - 68))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 68))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 68))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 68)))) != 0)) {
      setState(1133);
      visibility();
      setState(1134);
      match(VisualBasic6Parser::WS);
    }
    setState(1140);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::STATIC) {
      setState(1138);
      match(VisualBasic6Parser::STATIC);
      setState(1139);
      match(VisualBasic6Parser::WS);
    }
    setState(1142);
    match(VisualBasic6Parser::FUNCTION);
    setState(1143);
    match(VisualBasic6Parser::WS);
    setState(1144);
    ambiguousIdentifier();
    setState(1149);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 145, _ctx)) {
    case 1: {
      setState(1146);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(1145);
        match(VisualBasic6Parser::WS);
      }
      setState(1148);
      argList();
      break;
    }

    }
    setState(1153);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1151);
      match(VisualBasic6Parser::WS);
      setState(1152);
      asTypeClause();
    }
    setState(1156); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(1155);
      match(VisualBasic6Parser::NEWLINE);
      setState(1158); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(1166);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
      | (1ULL << VisualBasic6Parser::ADDRESSOF)
      | (1ULL << VisualBasic6Parser::ALIAS)
      | (1ULL << VisualBasic6Parser::AND)
      | (1ULL << VisualBasic6Parser::ATTRIBUTE)
      | (1ULL << VisualBasic6Parser::APPACTIVATE)
      | (1ULL << VisualBasic6Parser::APPEND)
      | (1ULL << VisualBasic6Parser::AS)
      | (1ULL << VisualBasic6Parser::BEEP)
      | (1ULL << VisualBasic6Parser::BEGIN)
      | (1ULL << VisualBasic6Parser::BINARY)
      | (1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYVAL)
      | (1ULL << VisualBasic6Parser::BYREF)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::CALL)
      | (1ULL << VisualBasic6Parser::CASE)
      | (1ULL << VisualBasic6Parser::CHDIR)
      | (1ULL << VisualBasic6Parser::CHDRIVE)
      | (1ULL << VisualBasic6Parser::CLASS)
      | (1ULL << VisualBasic6Parser::CLOSE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::CONST)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DECLARE)
      | (1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR)
      | (1ULL << VisualBasic6Parser::DELETESETTING)
      | (1ULL << VisualBasic6Parser::DIM)
      | (1ULL << VisualBasic6Parser::DO)
      | (1ULL << VisualBasic6Parser::DOUBLE)
      | (1ULL << VisualBasic6Parser::EACH)
      | (1ULL << VisualBasic6Parser::ELSE)
      | (1ULL << VisualBasic6Parser::ELSEIF)
      | (1ULL << VisualBasic6Parser::END)
      | (1ULL << VisualBasic6Parser::ENUM)
      | (1ULL << VisualBasic6Parser::EQV)
      | (1ULL << VisualBasic6Parser::ERASE)
      | (1ULL << VisualBasic6Parser::ERROR)
      | (1ULL << VisualBasic6Parser::EVENT)
      | (1ULL << VisualBasic6Parser::EXIT_DO)
      | (1ULL << VisualBasic6Parser::EXIT_FOR)
      | (1ULL << VisualBasic6Parser::EXIT_FUNCTION))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (VisualBasic6Parser::EXIT_PROPERTY - 64))
      | (1ULL << (VisualBasic6Parser::EXIT_SUB - 64))
      | (1ULL << (VisualBasic6Parser::FALSE1 - 64))
      | (1ULL << (VisualBasic6Parser::FILECOPY - 64))
      | (1ULL << (VisualBasic6Parser::FRIEND - 64))
      | (1ULL << (VisualBasic6Parser::FOR - 64))
      | (1ULL << (VisualBasic6Parser::FUNCTION - 64))
      | (1ULL << (VisualBasic6Parser::GET - 64))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 64))
      | (1ULL << (VisualBasic6Parser::GOSUB - 64))
      | (1ULL << (VisualBasic6Parser::GOTO - 64))
      | (1ULL << (VisualBasic6Parser::IF - 64))
      | (1ULL << (VisualBasic6Parser::IMP - 64))
      | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 64))
      | (1ULL << (VisualBasic6Parser::IN - 64))
      | (1ULL << (VisualBasic6Parser::INPUT - 64))
      | (1ULL << (VisualBasic6Parser::IS - 64))
      | (1ULL << (VisualBasic6Parser::INTEGER - 64))
      | (1ULL << (VisualBasic6Parser::KILL - 64))
      | (1ULL << (VisualBasic6Parser::LOAD - 64))
      | (1ULL << (VisualBasic6Parser::LOCK - 64))
      | (1ULL << (VisualBasic6Parser::LONG - 64))
      | (1ULL << (VisualBasic6Parser::LOOP - 64))
      | (1ULL << (VisualBasic6Parser::LEN - 64))
      | (1ULL << (VisualBasic6Parser::LET - 64))
      | (1ULL << (VisualBasic6Parser::LIB - 64))
      | (1ULL << (VisualBasic6Parser::LIKE - 64))
      | (1ULL << (VisualBasic6Parser::LINE_INPUT - 64))
      | (1ULL << (VisualBasic6Parser::LSET - 64))
      | (1ULL << (VisualBasic6Parser::MACRO_IF - 64))
      | (1ULL << (VisualBasic6Parser::ME - 64))
      | (1ULL << (VisualBasic6Parser::MID - 64))
      | (1ULL << (VisualBasic6Parser::MKDIR - 64))
      | (1ULL << (VisualBasic6Parser::MOD - 64))
      | (1ULL << (VisualBasic6Parser::NAME - 64))
      | (1ULL << (VisualBasic6Parser::NEXT - 64))
      | (1ULL << (VisualBasic6Parser::NEW - 64))
      | (1ULL << (VisualBasic6Parser::NOT - 64))
      | (1ULL << (VisualBasic6Parser::NOTHING - 64))
      | (1ULL << (VisualBasic6Parser::NULL1 - 64))
      | (1ULL << (VisualBasic6Parser::OBJECT - 64))
      | (1ULL << (VisualBasic6Parser::ON - 64))
      | (1ULL << (VisualBasic6Parser::ON_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::ON_LOCAL_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::OPEN - 64))
      | (1ULL << (VisualBasic6Parser::OPTIONAL - 64))
      | (1ULL << (VisualBasic6Parser::OR - 64))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 64))
      | (1ULL << (VisualBasic6Parser::PARAMARRAY - 64))
      | (1ULL << (VisualBasic6Parser::PRESERVE - 64))
      | (1ULL << (VisualBasic6Parser::PRINT - 64))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 64)))) != 0) || ((((_la - 129) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 129)) & ((1ULL << (VisualBasic6Parser::PUBLIC - 129))
      | (1ULL << (VisualBasic6Parser::PUT - 129))
      | (1ULL << (VisualBasic6Parser::RANDOM - 129))
      | (1ULL << (VisualBasic6Parser::RANDOMIZE - 129))
      | (1ULL << (VisualBasic6Parser::RAISEEVENT - 129))
      | (1ULL << (VisualBasic6Parser::READ - 129))
      | (1ULL << (VisualBasic6Parser::REDIM - 129))
      | (1ULL << (VisualBasic6Parser::REM - 129))
      | (1ULL << (VisualBasic6Parser::RESET - 129))
      | (1ULL << (VisualBasic6Parser::RESUME - 129))
      | (1ULL << (VisualBasic6Parser::RETURN - 129))
      | (1ULL << (VisualBasic6Parser::RMDIR - 129))
      | (1ULL << (VisualBasic6Parser::RSET - 129))
      | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 129))
      | (1ULL << (VisualBasic6Parser::SAVESETTING - 129))
      | (1ULL << (VisualBasic6Parser::SEEK - 129))
      | (1ULL << (VisualBasic6Parser::SELECT - 129))
      | (1ULL << (VisualBasic6Parser::SENDKEYS - 129))
      | (1ULL << (VisualBasic6Parser::SET - 129))
      | (1ULL << (VisualBasic6Parser::SETATTR - 129))
      | (1ULL << (VisualBasic6Parser::SHARED - 129))
      | (1ULL << (VisualBasic6Parser::SINGLE - 129))
      | (1ULL << (VisualBasic6Parser::SPC - 129))
      | (1ULL << (VisualBasic6Parser::STATIC - 129))
      | (1ULL << (VisualBasic6Parser::STEP - 129))
      | (1ULL << (VisualBasic6Parser::STOP - 129))
      | (1ULL << (VisualBasic6Parser::STRING - 129))
      | (1ULL << (VisualBasic6Parser::SUB - 129))
      | (1ULL << (VisualBasic6Parser::TAB - 129))
      | (1ULL << (VisualBasic6Parser::TEXT - 129))
      | (1ULL << (VisualBasic6Parser::THEN - 129))
      | (1ULL << (VisualBasic6Parser::TIME - 129))
      | (1ULL << (VisualBasic6Parser::TO - 129))
      | (1ULL << (VisualBasic6Parser::TRUE1 - 129))
      | (1ULL << (VisualBasic6Parser::TYPE - 129))
      | (1ULL << (VisualBasic6Parser::TYPEOF - 129))
      | (1ULL << (VisualBasic6Parser::UNLOAD - 129))
      | (1ULL << (VisualBasic6Parser::UNLOCK - 129))
      | (1ULL << (VisualBasic6Parser::UNTIL - 129))
      | (1ULL << (VisualBasic6Parser::VARIANT - 129))
      | (1ULL << (VisualBasic6Parser::VERSION - 129))
      | (1ULL << (VisualBasic6Parser::WEND - 129))
      | (1ULL << (VisualBasic6Parser::WHILE - 129))
      | (1ULL << (VisualBasic6Parser::WIDTH - 129))
      | (1ULL << (VisualBasic6Parser::WITH - 129))
      | (1ULL << (VisualBasic6Parser::WITHEVENTS - 129))
      | (1ULL << (VisualBasic6Parser::WRITE - 129))
      | (1ULL << (VisualBasic6Parser::XOR - 129))
      | (1ULL << (VisualBasic6Parser::DOT - 129))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 129)))) != 0) || ((((_la - 206) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 206)) & ((1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 206))
      | (1ULL << (VisualBasic6Parser::IDENTIFIER - 206))
      | (1ULL << (VisualBasic6Parser::WS - 206)))) != 0)) {
      setState(1160);
      block();
      setState(1162); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(1161);
        match(VisualBasic6Parser::NEWLINE);
        setState(1164); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
    }
    setState(1168);
    match(VisualBasic6Parser::END_FUNCTION);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- GetStmtContext ------------------------------------------------------------------

VisualBasic6Parser::GetStmtContext::GetStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::GetStmtContext::GET() {
  return getToken(VisualBasic6Parser::GET, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::GetStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::GetStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::GetStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::GetStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::GetStmtContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::GetStmtContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}


size_t VisualBasic6Parser::GetStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleGetStmt;
}

antlrcpp::Any VisualBasic6Parser::GetStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitGetStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::GetStmtContext* VisualBasic6Parser::getStmt() {
  GetStmtContext *_localctx = _tracker.createInstance<GetStmtContext>(_ctx, getState());
  enterRule(_localctx, 98, VisualBasic6Parser::RuleGetStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1170);
    match(VisualBasic6Parser::GET);
    setState(1171);
    match(VisualBasic6Parser::WS);
    setState(1172);
    valueStmt(0);
    setState(1174);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1173);
      match(VisualBasic6Parser::WS);
    }
    setState(1176);
    match(VisualBasic6Parser::COMMA);
    setState(1178);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 151, _ctx)) {
    case 1: {
      setState(1177);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1181);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 152, _ctx)) {
    case 1: {
      setState(1180);
      valueStmt(0);
      break;
    }

    }
    setState(1184);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1183);
      match(VisualBasic6Parser::WS);
    }
    setState(1186);
    match(VisualBasic6Parser::COMMA);
    setState(1188);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 154, _ctx)) {
    case 1: {
      setState(1187);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1190);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- GoSubStmtContext ------------------------------------------------------------------

VisualBasic6Parser::GoSubStmtContext::GoSubStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::GoSubStmtContext::GOSUB() {
  return getToken(VisualBasic6Parser::GOSUB, 0);
}

tree::TerminalNode* VisualBasic6Parser::GoSubStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::GoSubStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::GoSubStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleGoSubStmt;
}

antlrcpp::Any VisualBasic6Parser::GoSubStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitGoSubStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::GoSubStmtContext* VisualBasic6Parser::goSubStmt() {
  GoSubStmtContext *_localctx = _tracker.createInstance<GoSubStmtContext>(_ctx, getState());
  enterRule(_localctx, 100, VisualBasic6Parser::RuleGoSubStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1192);
    match(VisualBasic6Parser::GOSUB);
    setState(1193);
    match(VisualBasic6Parser::WS);
    setState(1194);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- GoToStmtContext ------------------------------------------------------------------

VisualBasic6Parser::GoToStmtContext::GoToStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::GoToStmtContext::GOTO() {
  return getToken(VisualBasic6Parser::GOTO, 0);
}

tree::TerminalNode* VisualBasic6Parser::GoToStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::GoToStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::GoToStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleGoToStmt;
}

antlrcpp::Any VisualBasic6Parser::GoToStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitGoToStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::GoToStmtContext* VisualBasic6Parser::goToStmt() {
  GoToStmtContext *_localctx = _tracker.createInstance<GoToStmtContext>(_ctx, getState());
  enterRule(_localctx, 102, VisualBasic6Parser::RuleGoToStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1196);
    match(VisualBasic6Parser::GOTO);
    setState(1197);
    match(VisualBasic6Parser::WS);
    setState(1198);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- IfThenElseStmtContext ------------------------------------------------------------------

VisualBasic6Parser::IfThenElseStmtContext::IfThenElseStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}


size_t VisualBasic6Parser::IfThenElseStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleIfThenElseStmt;
}

void VisualBasic6Parser::IfThenElseStmtContext::copyFrom(IfThenElseStmtContext *ctx) {
  ParserRuleContext::copyFrom(ctx);
}

//----------------- BlockIfThenElseContext ------------------------------------------------------------------

VisualBasic6Parser::IfBlockStmtContext* VisualBasic6Parser::BlockIfThenElseContext::ifBlockStmt() {
  return getRuleContext<VisualBasic6Parser::IfBlockStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::BlockIfThenElseContext::END_IF() {
  return getToken(VisualBasic6Parser::END_IF, 0);
}

std::vector<VisualBasic6Parser::IfElseIfBlockStmtContext *> VisualBasic6Parser::BlockIfThenElseContext::ifElseIfBlockStmt() {
  return getRuleContexts<VisualBasic6Parser::IfElseIfBlockStmtContext>();
}

VisualBasic6Parser::IfElseIfBlockStmtContext* VisualBasic6Parser::BlockIfThenElseContext::ifElseIfBlockStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::IfElseIfBlockStmtContext>(i);
}

VisualBasic6Parser::IfElseBlockStmtContext* VisualBasic6Parser::BlockIfThenElseContext::ifElseBlockStmt() {
  return getRuleContext<VisualBasic6Parser::IfElseBlockStmtContext>(0);
}

VisualBasic6Parser::BlockIfThenElseContext::BlockIfThenElseContext(IfThenElseStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::BlockIfThenElseContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitBlockIfThenElse(this);
  else
    return visitor->visitChildren(this);
}
//----------------- InlineIfThenElseContext ------------------------------------------------------------------

tree::TerminalNode* VisualBasic6Parser::InlineIfThenElseContext::IF() {
  return getToken(VisualBasic6Parser::IF, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::InlineIfThenElseContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::InlineIfThenElseContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::IfConditionStmtContext* VisualBasic6Parser::InlineIfThenElseContext::ifConditionStmt() {
  return getRuleContext<VisualBasic6Parser::IfConditionStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::InlineIfThenElseContext::THEN() {
  return getToken(VisualBasic6Parser::THEN, 0);
}

std::vector<VisualBasic6Parser::BlockStmtContext *> VisualBasic6Parser::InlineIfThenElseContext::blockStmt() {
  return getRuleContexts<VisualBasic6Parser::BlockStmtContext>();
}

VisualBasic6Parser::BlockStmtContext* VisualBasic6Parser::InlineIfThenElseContext::blockStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::BlockStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::InlineIfThenElseContext::ELSE() {
  return getToken(VisualBasic6Parser::ELSE, 0);
}

VisualBasic6Parser::InlineIfThenElseContext::InlineIfThenElseContext(IfThenElseStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::InlineIfThenElseContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitInlineIfThenElse(this);
  else
    return visitor->visitChildren(this);
}
VisualBasic6Parser::IfThenElseStmtContext* VisualBasic6Parser::ifThenElseStmt() {
  IfThenElseStmtContext *_localctx = _tracker.createInstance<IfThenElseStmtContext>(_ctx, getState());
  enterRule(_localctx, 104, VisualBasic6Parser::RuleIfThenElseStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1225);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 158, _ctx)) {
    case 1: {
      _localctx = dynamic_cast<IfThenElseStmtContext *>(_tracker.createInstance<VisualBasic6Parser::InlineIfThenElseContext>(_localctx));
      enterOuterAlt(_localctx, 1);
      setState(1200);
      match(VisualBasic6Parser::IF);
      setState(1201);
      match(VisualBasic6Parser::WS);
      setState(1202);
      ifConditionStmt();
      setState(1203);
      match(VisualBasic6Parser::WS);
      setState(1204);
      match(VisualBasic6Parser::THEN);
      setState(1205);
      match(VisualBasic6Parser::WS);
      setState(1206);
      blockStmt();
      setState(1211);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 155, _ctx)) {
      case 1: {
        setState(1207);
        match(VisualBasic6Parser::WS);
        setState(1208);
        match(VisualBasic6Parser::ELSE);
        setState(1209);
        match(VisualBasic6Parser::WS);
        setState(1210);
        blockStmt();
        break;
      }

      }
      break;
    }

    case 2: {
      _localctx = dynamic_cast<IfThenElseStmtContext *>(_tracker.createInstance<VisualBasic6Parser::BlockIfThenElseContext>(_localctx));
      enterOuterAlt(_localctx, 2);
      setState(1213);
      ifBlockStmt();
      setState(1217);
      _errHandler->sync(this);
      _la = _input->LA(1);
      while (_la == VisualBasic6Parser::ELSEIF) {
        setState(1214);
        ifElseIfBlockStmt();
        setState(1219);
        _errHandler->sync(this);
        _la = _input->LA(1);
      }
      setState(1221);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::ELSE) {
        setState(1220);
        ifElseBlockStmt();
      }
      setState(1223);
      match(VisualBasic6Parser::END_IF);
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

//----------------- IfBlockStmtContext ------------------------------------------------------------------

VisualBasic6Parser::IfBlockStmtContext::IfBlockStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::IfBlockStmtContext::IF() {
  return getToken(VisualBasic6Parser::IF, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::IfBlockStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::IfBlockStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::IfConditionStmtContext* VisualBasic6Parser::IfBlockStmtContext::ifConditionStmt() {
  return getRuleContext<VisualBasic6Parser::IfConditionStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::IfBlockStmtContext::THEN() {
  return getToken(VisualBasic6Parser::THEN, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::IfBlockStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::IfBlockStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::IfBlockStmtContext::block() {
  return getRuleContext<VisualBasic6Parser::BlockContext>(0);
}


size_t VisualBasic6Parser::IfBlockStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleIfBlockStmt;
}

antlrcpp::Any VisualBasic6Parser::IfBlockStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitIfBlockStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::IfBlockStmtContext* VisualBasic6Parser::ifBlockStmt() {
  IfBlockStmtContext *_localctx = _tracker.createInstance<IfBlockStmtContext>(_ctx, getState());
  enterRule(_localctx, 106, VisualBasic6Parser::RuleIfBlockStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1227);
    match(VisualBasic6Parser::IF);
    setState(1228);
    match(VisualBasic6Parser::WS);
    setState(1229);
    ifConditionStmt();
    setState(1230);
    match(VisualBasic6Parser::WS);
    setState(1231);
    match(VisualBasic6Parser::THEN);
    setState(1233); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(1232);
      match(VisualBasic6Parser::NEWLINE);
      setState(1235); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(1243);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 161, _ctx)) {
    case 1: {
      setState(1237);
      block();
      setState(1239); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(1238);
        match(VisualBasic6Parser::NEWLINE);
        setState(1241); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
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

//----------------- IfConditionStmtContext ------------------------------------------------------------------

VisualBasic6Parser::IfConditionStmtContext::IfConditionStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::IfConditionStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::IfConditionStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleIfConditionStmt;
}

antlrcpp::Any VisualBasic6Parser::IfConditionStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitIfConditionStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::IfConditionStmtContext* VisualBasic6Parser::ifConditionStmt() {
  IfConditionStmtContext *_localctx = _tracker.createInstance<IfConditionStmtContext>(_ctx, getState());
  enterRule(_localctx, 108, VisualBasic6Parser::RuleIfConditionStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1245);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- IfElseIfBlockStmtContext ------------------------------------------------------------------

VisualBasic6Parser::IfElseIfBlockStmtContext::IfElseIfBlockStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::IfElseIfBlockStmtContext::ELSEIF() {
  return getToken(VisualBasic6Parser::ELSEIF, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::IfElseIfBlockStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::IfElseIfBlockStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::IfConditionStmtContext* VisualBasic6Parser::IfElseIfBlockStmtContext::ifConditionStmt() {
  return getRuleContext<VisualBasic6Parser::IfConditionStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::IfElseIfBlockStmtContext::THEN() {
  return getToken(VisualBasic6Parser::THEN, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::IfElseIfBlockStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::IfElseIfBlockStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::IfElseIfBlockStmtContext::block() {
  return getRuleContext<VisualBasic6Parser::BlockContext>(0);
}


size_t VisualBasic6Parser::IfElseIfBlockStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleIfElseIfBlockStmt;
}

antlrcpp::Any VisualBasic6Parser::IfElseIfBlockStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitIfElseIfBlockStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::IfElseIfBlockStmtContext* VisualBasic6Parser::ifElseIfBlockStmt() {
  IfElseIfBlockStmtContext *_localctx = _tracker.createInstance<IfElseIfBlockStmtContext>(_ctx, getState());
  enterRule(_localctx, 110, VisualBasic6Parser::RuleIfElseIfBlockStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1247);
    match(VisualBasic6Parser::ELSEIF);
    setState(1248);
    match(VisualBasic6Parser::WS);
    setState(1249);
    ifConditionStmt();
    setState(1250);
    match(VisualBasic6Parser::WS);
    setState(1251);
    match(VisualBasic6Parser::THEN);
    setState(1253); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(1252);
      match(VisualBasic6Parser::NEWLINE);
      setState(1255); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(1263);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 164, _ctx)) {
    case 1: {
      setState(1257);
      block();
      setState(1259); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(1258);
        match(VisualBasic6Parser::NEWLINE);
        setState(1261); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
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

//----------------- IfElseBlockStmtContext ------------------------------------------------------------------

VisualBasic6Parser::IfElseBlockStmtContext::IfElseBlockStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::IfElseBlockStmtContext::ELSE() {
  return getToken(VisualBasic6Parser::ELSE, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::IfElseBlockStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::IfElseBlockStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::IfElseBlockStmtContext::block() {
  return getRuleContext<VisualBasic6Parser::BlockContext>(0);
}


size_t VisualBasic6Parser::IfElseBlockStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleIfElseBlockStmt;
}

antlrcpp::Any VisualBasic6Parser::IfElseBlockStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitIfElseBlockStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::IfElseBlockStmtContext* VisualBasic6Parser::ifElseBlockStmt() {
  IfElseBlockStmtContext *_localctx = _tracker.createInstance<IfElseBlockStmtContext>(_ctx, getState());
  enterRule(_localctx, 112, VisualBasic6Parser::RuleIfElseBlockStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1265);
    match(VisualBasic6Parser::ELSE);
    setState(1267); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(1266);
      match(VisualBasic6Parser::NEWLINE);
      setState(1269); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(1277);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
      | (1ULL << VisualBasic6Parser::ADDRESSOF)
      | (1ULL << VisualBasic6Parser::ALIAS)
      | (1ULL << VisualBasic6Parser::AND)
      | (1ULL << VisualBasic6Parser::ATTRIBUTE)
      | (1ULL << VisualBasic6Parser::APPACTIVATE)
      | (1ULL << VisualBasic6Parser::APPEND)
      | (1ULL << VisualBasic6Parser::AS)
      | (1ULL << VisualBasic6Parser::BEEP)
      | (1ULL << VisualBasic6Parser::BEGIN)
      | (1ULL << VisualBasic6Parser::BINARY)
      | (1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYVAL)
      | (1ULL << VisualBasic6Parser::BYREF)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::CALL)
      | (1ULL << VisualBasic6Parser::CASE)
      | (1ULL << VisualBasic6Parser::CHDIR)
      | (1ULL << VisualBasic6Parser::CHDRIVE)
      | (1ULL << VisualBasic6Parser::CLASS)
      | (1ULL << VisualBasic6Parser::CLOSE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::CONST)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DECLARE)
      | (1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR)
      | (1ULL << VisualBasic6Parser::DELETESETTING)
      | (1ULL << VisualBasic6Parser::DIM)
      | (1ULL << VisualBasic6Parser::DO)
      | (1ULL << VisualBasic6Parser::DOUBLE)
      | (1ULL << VisualBasic6Parser::EACH)
      | (1ULL << VisualBasic6Parser::ELSE)
      | (1ULL << VisualBasic6Parser::ELSEIF)
      | (1ULL << VisualBasic6Parser::END)
      | (1ULL << VisualBasic6Parser::ENUM)
      | (1ULL << VisualBasic6Parser::EQV)
      | (1ULL << VisualBasic6Parser::ERASE)
      | (1ULL << VisualBasic6Parser::ERROR)
      | (1ULL << VisualBasic6Parser::EVENT)
      | (1ULL << VisualBasic6Parser::EXIT_DO)
      | (1ULL << VisualBasic6Parser::EXIT_FOR)
      | (1ULL << VisualBasic6Parser::EXIT_FUNCTION))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (VisualBasic6Parser::EXIT_PROPERTY - 64))
      | (1ULL << (VisualBasic6Parser::EXIT_SUB - 64))
      | (1ULL << (VisualBasic6Parser::FALSE1 - 64))
      | (1ULL << (VisualBasic6Parser::FILECOPY - 64))
      | (1ULL << (VisualBasic6Parser::FRIEND - 64))
      | (1ULL << (VisualBasic6Parser::FOR - 64))
      | (1ULL << (VisualBasic6Parser::FUNCTION - 64))
      | (1ULL << (VisualBasic6Parser::GET - 64))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 64))
      | (1ULL << (VisualBasic6Parser::GOSUB - 64))
      | (1ULL << (VisualBasic6Parser::GOTO - 64))
      | (1ULL << (VisualBasic6Parser::IF - 64))
      | (1ULL << (VisualBasic6Parser::IMP - 64))
      | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 64))
      | (1ULL << (VisualBasic6Parser::IN - 64))
      | (1ULL << (VisualBasic6Parser::INPUT - 64))
      | (1ULL << (VisualBasic6Parser::IS - 64))
      | (1ULL << (VisualBasic6Parser::INTEGER - 64))
      | (1ULL << (VisualBasic6Parser::KILL - 64))
      | (1ULL << (VisualBasic6Parser::LOAD - 64))
      | (1ULL << (VisualBasic6Parser::LOCK - 64))
      | (1ULL << (VisualBasic6Parser::LONG - 64))
      | (1ULL << (VisualBasic6Parser::LOOP - 64))
      | (1ULL << (VisualBasic6Parser::LEN - 64))
      | (1ULL << (VisualBasic6Parser::LET - 64))
      | (1ULL << (VisualBasic6Parser::LIB - 64))
      | (1ULL << (VisualBasic6Parser::LIKE - 64))
      | (1ULL << (VisualBasic6Parser::LINE_INPUT - 64))
      | (1ULL << (VisualBasic6Parser::LSET - 64))
      | (1ULL << (VisualBasic6Parser::MACRO_IF - 64))
      | (1ULL << (VisualBasic6Parser::ME - 64))
      | (1ULL << (VisualBasic6Parser::MID - 64))
      | (1ULL << (VisualBasic6Parser::MKDIR - 64))
      | (1ULL << (VisualBasic6Parser::MOD - 64))
      | (1ULL << (VisualBasic6Parser::NAME - 64))
      | (1ULL << (VisualBasic6Parser::NEXT - 64))
      | (1ULL << (VisualBasic6Parser::NEW - 64))
      | (1ULL << (VisualBasic6Parser::NOT - 64))
      | (1ULL << (VisualBasic6Parser::NOTHING - 64))
      | (1ULL << (VisualBasic6Parser::NULL1 - 64))
      | (1ULL << (VisualBasic6Parser::OBJECT - 64))
      | (1ULL << (VisualBasic6Parser::ON - 64))
      | (1ULL << (VisualBasic6Parser::ON_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::ON_LOCAL_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::OPEN - 64))
      | (1ULL << (VisualBasic6Parser::OPTIONAL - 64))
      | (1ULL << (VisualBasic6Parser::OR - 64))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 64))
      | (1ULL << (VisualBasic6Parser::PARAMARRAY - 64))
      | (1ULL << (VisualBasic6Parser::PRESERVE - 64))
      | (1ULL << (VisualBasic6Parser::PRINT - 64))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 64)))) != 0) || ((((_la - 129) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 129)) & ((1ULL << (VisualBasic6Parser::PUBLIC - 129))
      | (1ULL << (VisualBasic6Parser::PUT - 129))
      | (1ULL << (VisualBasic6Parser::RANDOM - 129))
      | (1ULL << (VisualBasic6Parser::RANDOMIZE - 129))
      | (1ULL << (VisualBasic6Parser::RAISEEVENT - 129))
      | (1ULL << (VisualBasic6Parser::READ - 129))
      | (1ULL << (VisualBasic6Parser::REDIM - 129))
      | (1ULL << (VisualBasic6Parser::REM - 129))
      | (1ULL << (VisualBasic6Parser::RESET - 129))
      | (1ULL << (VisualBasic6Parser::RESUME - 129))
      | (1ULL << (VisualBasic6Parser::RETURN - 129))
      | (1ULL << (VisualBasic6Parser::RMDIR - 129))
      | (1ULL << (VisualBasic6Parser::RSET - 129))
      | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 129))
      | (1ULL << (VisualBasic6Parser::SAVESETTING - 129))
      | (1ULL << (VisualBasic6Parser::SEEK - 129))
      | (1ULL << (VisualBasic6Parser::SELECT - 129))
      | (1ULL << (VisualBasic6Parser::SENDKEYS - 129))
      | (1ULL << (VisualBasic6Parser::SET - 129))
      | (1ULL << (VisualBasic6Parser::SETATTR - 129))
      | (1ULL << (VisualBasic6Parser::SHARED - 129))
      | (1ULL << (VisualBasic6Parser::SINGLE - 129))
      | (1ULL << (VisualBasic6Parser::SPC - 129))
      | (1ULL << (VisualBasic6Parser::STATIC - 129))
      | (1ULL << (VisualBasic6Parser::STEP - 129))
      | (1ULL << (VisualBasic6Parser::STOP - 129))
      | (1ULL << (VisualBasic6Parser::STRING - 129))
      | (1ULL << (VisualBasic6Parser::SUB - 129))
      | (1ULL << (VisualBasic6Parser::TAB - 129))
      | (1ULL << (VisualBasic6Parser::TEXT - 129))
      | (1ULL << (VisualBasic6Parser::THEN - 129))
      | (1ULL << (VisualBasic6Parser::TIME - 129))
      | (1ULL << (VisualBasic6Parser::TO - 129))
      | (1ULL << (VisualBasic6Parser::TRUE1 - 129))
      | (1ULL << (VisualBasic6Parser::TYPE - 129))
      | (1ULL << (VisualBasic6Parser::TYPEOF - 129))
      | (1ULL << (VisualBasic6Parser::UNLOAD - 129))
      | (1ULL << (VisualBasic6Parser::UNLOCK - 129))
      | (1ULL << (VisualBasic6Parser::UNTIL - 129))
      | (1ULL << (VisualBasic6Parser::VARIANT - 129))
      | (1ULL << (VisualBasic6Parser::VERSION - 129))
      | (1ULL << (VisualBasic6Parser::WEND - 129))
      | (1ULL << (VisualBasic6Parser::WHILE - 129))
      | (1ULL << (VisualBasic6Parser::WIDTH - 129))
      | (1ULL << (VisualBasic6Parser::WITH - 129))
      | (1ULL << (VisualBasic6Parser::WITHEVENTS - 129))
      | (1ULL << (VisualBasic6Parser::WRITE - 129))
      | (1ULL << (VisualBasic6Parser::XOR - 129))
      | (1ULL << (VisualBasic6Parser::DOT - 129))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 129)))) != 0) || ((((_la - 206) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 206)) & ((1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 206))
      | (1ULL << (VisualBasic6Parser::IDENTIFIER - 206))
      | (1ULL << (VisualBasic6Parser::WS - 206)))) != 0)) {
      setState(1271);
      block();
      setState(1273); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(1272);
        match(VisualBasic6Parser::NEWLINE);
        setState(1275); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ImplementsStmtContext ------------------------------------------------------------------

VisualBasic6Parser::ImplementsStmtContext::ImplementsStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ImplementsStmtContext::IMPLEMENTS() {
  return getToken(VisualBasic6Parser::IMPLEMENTS, 0);
}

tree::TerminalNode* VisualBasic6Parser::ImplementsStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::ImplementsStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}


size_t VisualBasic6Parser::ImplementsStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleImplementsStmt;
}

antlrcpp::Any VisualBasic6Parser::ImplementsStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitImplementsStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ImplementsStmtContext* VisualBasic6Parser::implementsStmt() {
  ImplementsStmtContext *_localctx = _tracker.createInstance<ImplementsStmtContext>(_ctx, getState());
  enterRule(_localctx, 114, VisualBasic6Parser::RuleImplementsStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1279);
    match(VisualBasic6Parser::IMPLEMENTS);
    setState(1280);
    match(VisualBasic6Parser::WS);
    setState(1281);
    ambiguousIdentifier();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- InputStmtContext ------------------------------------------------------------------

VisualBasic6Parser::InputStmtContext::InputStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::InputStmtContext::INPUT() {
  return getToken(VisualBasic6Parser::INPUT, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::InputStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::InputStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::InputStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::InputStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::InputStmtContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::InputStmtContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}


size_t VisualBasic6Parser::InputStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleInputStmt;
}

antlrcpp::Any VisualBasic6Parser::InputStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitInputStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::InputStmtContext* VisualBasic6Parser::inputStmt() {
  InputStmtContext *_localctx = _tracker.createInstance<InputStmtContext>(_ctx, getState());
  enterRule(_localctx, 116, VisualBasic6Parser::RuleInputStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(1283);
    match(VisualBasic6Parser::INPUT);
    setState(1284);
    match(VisualBasic6Parser::WS);
    setState(1285);
    valueStmt(0);
    setState(1294); 
    _errHandler->sync(this);
    alt = 1;
    do {
      switch (alt) {
        case 1: {
              setState(1287);
              _errHandler->sync(this);

              _la = _input->LA(1);
              if (_la == VisualBasic6Parser::WS) {
                setState(1286);
                match(VisualBasic6Parser::WS);
              }
              setState(1289);
              match(VisualBasic6Parser::COMMA);
              setState(1291);
              _errHandler->sync(this);

              switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 169, _ctx)) {
              case 1: {
                setState(1290);
                match(VisualBasic6Parser::WS);
                break;
              }

              }
              setState(1293);
              valueStmt(0);
              break;
            }

      default:
        throw NoViableAltException(this);
      }
      setState(1296); 
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 170, _ctx);
    } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- KillStmtContext ------------------------------------------------------------------

VisualBasic6Parser::KillStmtContext::KillStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::KillStmtContext::KILL() {
  return getToken(VisualBasic6Parser::KILL, 0);
}

tree::TerminalNode* VisualBasic6Parser::KillStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::KillStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::KillStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleKillStmt;
}

antlrcpp::Any VisualBasic6Parser::KillStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitKillStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::KillStmtContext* VisualBasic6Parser::killStmt() {
  KillStmtContext *_localctx = _tracker.createInstance<KillStmtContext>(_ctx, getState());
  enterRule(_localctx, 118, VisualBasic6Parser::RuleKillStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1298);
    match(VisualBasic6Parser::KILL);
    setState(1299);
    match(VisualBasic6Parser::WS);
    setState(1300);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- LetStmtContext ------------------------------------------------------------------

VisualBasic6Parser::LetStmtContext::LetStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::ImplicitCallStmt_InStmtContext* VisualBasic6Parser::LetStmtContext::implicitCallStmt_InStmt() {
  return getRuleContext<VisualBasic6Parser::ImplicitCallStmt_InStmtContext>(0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::LetStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::LetStmtContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

tree::TerminalNode* VisualBasic6Parser::LetStmtContext::PLUS_EQ() {
  return getToken(VisualBasic6Parser::PLUS_EQ, 0);
}

tree::TerminalNode* VisualBasic6Parser::LetStmtContext::MINUS_EQ() {
  return getToken(VisualBasic6Parser::MINUS_EQ, 0);
}

tree::TerminalNode* VisualBasic6Parser::LetStmtContext::LET() {
  return getToken(VisualBasic6Parser::LET, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::LetStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::LetStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}


size_t VisualBasic6Parser::LetStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleLetStmt;
}

antlrcpp::Any VisualBasic6Parser::LetStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitLetStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::LetStmtContext* VisualBasic6Parser::letStmt() {
  LetStmtContext *_localctx = _tracker.createInstance<LetStmtContext>(_ctx, getState());
  enterRule(_localctx, 120, VisualBasic6Parser::RuleLetStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1304);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 171, _ctx)) {
    case 1: {
      setState(1302);
      match(VisualBasic6Parser::LET);
      setState(1303);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1306);
    implicitCallStmt_InStmt();
    setState(1308);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1307);
      match(VisualBasic6Parser::WS);
    }
    setState(1310);
    _la = _input->LA(1);
    if (!(((((_la - 186) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 186)) & ((1ULL << (VisualBasic6Parser::EQ - 186))
      | (1ULL << (VisualBasic6Parser::MINUS_EQ - 186))
      | (1ULL << (VisualBasic6Parser::PLUS_EQ - 186)))) != 0))) {
    _errHandler->recoverInline(this);
    }
    else {
      _errHandler->reportMatch(this);
      consume();
    }
    setState(1312);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 173, _ctx)) {
    case 1: {
      setState(1311);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1314);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- LineInputStmtContext ------------------------------------------------------------------

VisualBasic6Parser::LineInputStmtContext::LineInputStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::LineInputStmtContext::LINE_INPUT() {
  return getToken(VisualBasic6Parser::LINE_INPUT, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::LineInputStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::LineInputStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::LineInputStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::LineInputStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::LineInputStmtContext::COMMA() {
  return getToken(VisualBasic6Parser::COMMA, 0);
}


size_t VisualBasic6Parser::LineInputStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleLineInputStmt;
}

antlrcpp::Any VisualBasic6Parser::LineInputStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitLineInputStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::LineInputStmtContext* VisualBasic6Parser::lineInputStmt() {
  LineInputStmtContext *_localctx = _tracker.createInstance<LineInputStmtContext>(_ctx, getState());
  enterRule(_localctx, 122, VisualBasic6Parser::RuleLineInputStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1316);
    match(VisualBasic6Parser::LINE_INPUT);
    setState(1317);
    match(VisualBasic6Parser::WS);
    setState(1318);
    valueStmt(0);
    setState(1320);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1319);
      match(VisualBasic6Parser::WS);
    }
    setState(1322);
    match(VisualBasic6Parser::COMMA);
    setState(1324);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 175, _ctx)) {
    case 1: {
      setState(1323);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1326);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- LoadStmtContext ------------------------------------------------------------------

VisualBasic6Parser::LoadStmtContext::LoadStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::LoadStmtContext::LOAD() {
  return getToken(VisualBasic6Parser::LOAD, 0);
}

tree::TerminalNode* VisualBasic6Parser::LoadStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::LoadStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::LoadStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleLoadStmt;
}

antlrcpp::Any VisualBasic6Parser::LoadStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitLoadStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::LoadStmtContext* VisualBasic6Parser::loadStmt() {
  LoadStmtContext *_localctx = _tracker.createInstance<LoadStmtContext>(_ctx, getState());
  enterRule(_localctx, 124, VisualBasic6Parser::RuleLoadStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1328);
    match(VisualBasic6Parser::LOAD);
    setState(1329);
    match(VisualBasic6Parser::WS);
    setState(1330);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- LockStmtContext ------------------------------------------------------------------

VisualBasic6Parser::LockStmtContext::LockStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::LockStmtContext::LOCK() {
  return getToken(VisualBasic6Parser::LOCK, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::LockStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::LockStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::LockStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::LockStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::LockStmtContext::COMMA() {
  return getToken(VisualBasic6Parser::COMMA, 0);
}

tree::TerminalNode* VisualBasic6Parser::LockStmtContext::TO() {
  return getToken(VisualBasic6Parser::TO, 0);
}


size_t VisualBasic6Parser::LockStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleLockStmt;
}

antlrcpp::Any VisualBasic6Parser::LockStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitLockStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::LockStmtContext* VisualBasic6Parser::lockStmt() {
  LockStmtContext *_localctx = _tracker.createInstance<LockStmtContext>(_ctx, getState());
  enterRule(_localctx, 126, VisualBasic6Parser::RuleLockStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1332);
    match(VisualBasic6Parser::LOCK);
    setState(1333);
    match(VisualBasic6Parser::WS);
    setState(1334);
    valueStmt(0);
    setState(1349);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 179, _ctx)) {
    case 1: {
      setState(1336);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(1335);
        match(VisualBasic6Parser::WS);
      }
      setState(1338);
      match(VisualBasic6Parser::COMMA);
      setState(1340);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 177, _ctx)) {
      case 1: {
        setState(1339);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(1342);
      valueStmt(0);
      setState(1347);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 178, _ctx)) {
      case 1: {
        setState(1343);
        match(VisualBasic6Parser::WS);
        setState(1344);
        match(VisualBasic6Parser::TO);
        setState(1345);
        match(VisualBasic6Parser::WS);
        setState(1346);
        valueStmt(0);
        break;
      }

      }
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

//----------------- LsetStmtContext ------------------------------------------------------------------

VisualBasic6Parser::LsetStmtContext::LsetStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::LsetStmtContext::LSET() {
  return getToken(VisualBasic6Parser::LSET, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::LsetStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::LsetStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::ImplicitCallStmt_InStmtContext* VisualBasic6Parser::LsetStmtContext::implicitCallStmt_InStmt() {
  return getRuleContext<VisualBasic6Parser::ImplicitCallStmt_InStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::LsetStmtContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::LsetStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::LsetStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleLsetStmt;
}

antlrcpp::Any VisualBasic6Parser::LsetStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitLsetStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::LsetStmtContext* VisualBasic6Parser::lsetStmt() {
  LsetStmtContext *_localctx = _tracker.createInstance<LsetStmtContext>(_ctx, getState());
  enterRule(_localctx, 128, VisualBasic6Parser::RuleLsetStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1351);
    match(VisualBasic6Parser::LSET);
    setState(1352);
    match(VisualBasic6Parser::WS);
    setState(1353);
    implicitCallStmt_InStmt();
    setState(1355);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1354);
      match(VisualBasic6Parser::WS);
    }
    setState(1357);
    match(VisualBasic6Parser::EQ);
    setState(1359);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 181, _ctx)) {
    case 1: {
      setState(1358);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1361);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- MacroIfThenElseStmtContext ------------------------------------------------------------------

VisualBasic6Parser::MacroIfThenElseStmtContext::MacroIfThenElseStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::MacroIfBlockStmtContext* VisualBasic6Parser::MacroIfThenElseStmtContext::macroIfBlockStmt() {
  return getRuleContext<VisualBasic6Parser::MacroIfBlockStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::MacroIfThenElseStmtContext::MACRO_END_IF() {
  return getToken(VisualBasic6Parser::MACRO_END_IF, 0);
}

std::vector<VisualBasic6Parser::MacroElseIfBlockStmtContext *> VisualBasic6Parser::MacroIfThenElseStmtContext::macroElseIfBlockStmt() {
  return getRuleContexts<VisualBasic6Parser::MacroElseIfBlockStmtContext>();
}

VisualBasic6Parser::MacroElseIfBlockStmtContext* VisualBasic6Parser::MacroIfThenElseStmtContext::macroElseIfBlockStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::MacroElseIfBlockStmtContext>(i);
}

VisualBasic6Parser::MacroElseBlockStmtContext* VisualBasic6Parser::MacroIfThenElseStmtContext::macroElseBlockStmt() {
  return getRuleContext<VisualBasic6Parser::MacroElseBlockStmtContext>(0);
}


size_t VisualBasic6Parser::MacroIfThenElseStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleMacroIfThenElseStmt;
}

antlrcpp::Any VisualBasic6Parser::MacroIfThenElseStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitMacroIfThenElseStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::MacroIfThenElseStmtContext* VisualBasic6Parser::macroIfThenElseStmt() {
  MacroIfThenElseStmtContext *_localctx = _tracker.createInstance<MacroIfThenElseStmtContext>(_ctx, getState());
  enterRule(_localctx, 130, VisualBasic6Parser::RuleMacroIfThenElseStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1363);
    macroIfBlockStmt();
    setState(1367);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == VisualBasic6Parser::MACRO_ELSEIF) {
      setState(1364);
      macroElseIfBlockStmt();
      setState(1369);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
    setState(1371);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::MACRO_ELSE) {
      setState(1370);
      macroElseBlockStmt();
    }
    setState(1373);
    match(VisualBasic6Parser::MACRO_END_IF);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- MacroIfBlockStmtContext ------------------------------------------------------------------

VisualBasic6Parser::MacroIfBlockStmtContext::MacroIfBlockStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::MacroIfBlockStmtContext::MACRO_IF() {
  return getToken(VisualBasic6Parser::MACRO_IF, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::MacroIfBlockStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::MacroIfBlockStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::IfConditionStmtContext* VisualBasic6Parser::MacroIfBlockStmtContext::ifConditionStmt() {
  return getRuleContext<VisualBasic6Parser::IfConditionStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::MacroIfBlockStmtContext::THEN() {
  return getToken(VisualBasic6Parser::THEN, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::MacroIfBlockStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::MacroIfBlockStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::ModuleBodyContext* VisualBasic6Parser::MacroIfBlockStmtContext::moduleBody() {
  return getRuleContext<VisualBasic6Parser::ModuleBodyContext>(0);
}


size_t VisualBasic6Parser::MacroIfBlockStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleMacroIfBlockStmt;
}

antlrcpp::Any VisualBasic6Parser::MacroIfBlockStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitMacroIfBlockStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::MacroIfBlockStmtContext* VisualBasic6Parser::macroIfBlockStmt() {
  MacroIfBlockStmtContext *_localctx = _tracker.createInstance<MacroIfBlockStmtContext>(_ctx, getState());
  enterRule(_localctx, 132, VisualBasic6Parser::RuleMacroIfBlockStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1375);
    match(VisualBasic6Parser::MACRO_IF);
    setState(1376);
    match(VisualBasic6Parser::WS);
    setState(1377);
    ifConditionStmt();
    setState(1378);
    match(VisualBasic6Parser::WS);
    setState(1379);
    match(VisualBasic6Parser::THEN);
    setState(1381); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(1380);
      match(VisualBasic6Parser::NEWLINE);
      setState(1383); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(1391);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
      | (1ULL << VisualBasic6Parser::ADDRESSOF)
      | (1ULL << VisualBasic6Parser::ALIAS)
      | (1ULL << VisualBasic6Parser::AND)
      | (1ULL << VisualBasic6Parser::ATTRIBUTE)
      | (1ULL << VisualBasic6Parser::APPACTIVATE)
      | (1ULL << VisualBasic6Parser::APPEND)
      | (1ULL << VisualBasic6Parser::AS)
      | (1ULL << VisualBasic6Parser::BEEP)
      | (1ULL << VisualBasic6Parser::BEGIN)
      | (1ULL << VisualBasic6Parser::BINARY)
      | (1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYVAL)
      | (1ULL << VisualBasic6Parser::BYREF)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::CALL)
      | (1ULL << VisualBasic6Parser::CASE)
      | (1ULL << VisualBasic6Parser::CHDIR)
      | (1ULL << VisualBasic6Parser::CHDRIVE)
      | (1ULL << VisualBasic6Parser::CLASS)
      | (1ULL << VisualBasic6Parser::CLOSE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::CONST)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DECLARE)
      | (1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR)
      | (1ULL << VisualBasic6Parser::DELETESETTING)
      | (1ULL << VisualBasic6Parser::DIM)
      | (1ULL << VisualBasic6Parser::DO)
      | (1ULL << VisualBasic6Parser::DOUBLE)
      | (1ULL << VisualBasic6Parser::EACH)
      | (1ULL << VisualBasic6Parser::ELSE)
      | (1ULL << VisualBasic6Parser::ELSEIF)
      | (1ULL << VisualBasic6Parser::END)
      | (1ULL << VisualBasic6Parser::ENUM)
      | (1ULL << VisualBasic6Parser::EQV)
      | (1ULL << VisualBasic6Parser::ERASE)
      | (1ULL << VisualBasic6Parser::ERROR)
      | (1ULL << VisualBasic6Parser::EVENT)
      | (1ULL << VisualBasic6Parser::EXIT_DO)
      | (1ULL << VisualBasic6Parser::EXIT_FOR)
      | (1ULL << VisualBasic6Parser::EXIT_FUNCTION))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (VisualBasic6Parser::EXIT_PROPERTY - 64))
      | (1ULL << (VisualBasic6Parser::EXIT_SUB - 64))
      | (1ULL << (VisualBasic6Parser::FALSE1 - 64))
      | (1ULL << (VisualBasic6Parser::FILECOPY - 64))
      | (1ULL << (VisualBasic6Parser::FRIEND - 64))
      | (1ULL << (VisualBasic6Parser::FOR - 64))
      | (1ULL << (VisualBasic6Parser::FUNCTION - 64))
      | (1ULL << (VisualBasic6Parser::GET - 64))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 64))
      | (1ULL << (VisualBasic6Parser::GOSUB - 64))
      | (1ULL << (VisualBasic6Parser::GOTO - 64))
      | (1ULL << (VisualBasic6Parser::IF - 64))
      | (1ULL << (VisualBasic6Parser::IMP - 64))
      | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 64))
      | (1ULL << (VisualBasic6Parser::IN - 64))
      | (1ULL << (VisualBasic6Parser::INPUT - 64))
      | (1ULL << (VisualBasic6Parser::IS - 64))
      | (1ULL << (VisualBasic6Parser::INTEGER - 64))
      | (1ULL << (VisualBasic6Parser::KILL - 64))
      | (1ULL << (VisualBasic6Parser::LOAD - 64))
      | (1ULL << (VisualBasic6Parser::LOCK - 64))
      | (1ULL << (VisualBasic6Parser::LONG - 64))
      | (1ULL << (VisualBasic6Parser::LOOP - 64))
      | (1ULL << (VisualBasic6Parser::LEN - 64))
      | (1ULL << (VisualBasic6Parser::LET - 64))
      | (1ULL << (VisualBasic6Parser::LIB - 64))
      | (1ULL << (VisualBasic6Parser::LIKE - 64))
      | (1ULL << (VisualBasic6Parser::LINE_INPUT - 64))
      | (1ULL << (VisualBasic6Parser::LSET - 64))
      | (1ULL << (VisualBasic6Parser::MACRO_IF - 64))
      | (1ULL << (VisualBasic6Parser::ME - 64))
      | (1ULL << (VisualBasic6Parser::MID - 64))
      | (1ULL << (VisualBasic6Parser::MKDIR - 64))
      | (1ULL << (VisualBasic6Parser::MOD - 64))
      | (1ULL << (VisualBasic6Parser::NAME - 64))
      | (1ULL << (VisualBasic6Parser::NEXT - 64))
      | (1ULL << (VisualBasic6Parser::NEW - 64))
      | (1ULL << (VisualBasic6Parser::NOT - 64))
      | (1ULL << (VisualBasic6Parser::NOTHING - 64))
      | (1ULL << (VisualBasic6Parser::NULL1 - 64))
      | (1ULL << (VisualBasic6Parser::OBJECT - 64))
      | (1ULL << (VisualBasic6Parser::ON - 64))
      | (1ULL << (VisualBasic6Parser::ON_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::ON_LOCAL_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::OPEN - 64))
      | (1ULL << (VisualBasic6Parser::OPTIONAL - 64))
      | (1ULL << (VisualBasic6Parser::OPTION_BASE - 64))
      | (1ULL << (VisualBasic6Parser::OPTION_EXPLICIT - 64))
      | (1ULL << (VisualBasic6Parser::OPTION_COMPARE - 64))
      | (1ULL << (VisualBasic6Parser::OPTION_PRIVATE_MODULE - 64))
      | (1ULL << (VisualBasic6Parser::OR - 64))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 64))
      | (1ULL << (VisualBasic6Parser::PARAMARRAY - 64))
      | (1ULL << (VisualBasic6Parser::PRESERVE - 64))
      | (1ULL << (VisualBasic6Parser::PRINT - 64))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 64))
      | (1ULL << (VisualBasic6Parser::PROPERTY_GET - 64))
      | (1ULL << (VisualBasic6Parser::PROPERTY_LET - 64)))) != 0) || ((((_la - 128) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 128)) & ((1ULL << (VisualBasic6Parser::PROPERTY_SET - 128))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 128))
      | (1ULL << (VisualBasic6Parser::PUT - 128))
      | (1ULL << (VisualBasic6Parser::RANDOM - 128))
      | (1ULL << (VisualBasic6Parser::RANDOMIZE - 128))
      | (1ULL << (VisualBasic6Parser::RAISEEVENT - 128))
      | (1ULL << (VisualBasic6Parser::READ - 128))
      | (1ULL << (VisualBasic6Parser::REDIM - 128))
      | (1ULL << (VisualBasic6Parser::REM - 128))
      | (1ULL << (VisualBasic6Parser::RESET - 128))
      | (1ULL << (VisualBasic6Parser::RESUME - 128))
      | (1ULL << (VisualBasic6Parser::RETURN - 128))
      | (1ULL << (VisualBasic6Parser::RMDIR - 128))
      | (1ULL << (VisualBasic6Parser::RSET - 128))
      | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 128))
      | (1ULL << (VisualBasic6Parser::SAVESETTING - 128))
      | (1ULL << (VisualBasic6Parser::SEEK - 128))
      | (1ULL << (VisualBasic6Parser::SELECT - 128))
      | (1ULL << (VisualBasic6Parser::SENDKEYS - 128))
      | (1ULL << (VisualBasic6Parser::SET - 128))
      | (1ULL << (VisualBasic6Parser::SETATTR - 128))
      | (1ULL << (VisualBasic6Parser::SHARED - 128))
      | (1ULL << (VisualBasic6Parser::SINGLE - 128))
      | (1ULL << (VisualBasic6Parser::SPC - 128))
      | (1ULL << (VisualBasic6Parser::STATIC - 128))
      | (1ULL << (VisualBasic6Parser::STEP - 128))
      | (1ULL << (VisualBasic6Parser::STOP - 128))
      | (1ULL << (VisualBasic6Parser::STRING - 128))
      | (1ULL << (VisualBasic6Parser::SUB - 128))
      | (1ULL << (VisualBasic6Parser::TAB - 128))
      | (1ULL << (VisualBasic6Parser::TEXT - 128))
      | (1ULL << (VisualBasic6Parser::THEN - 128))
      | (1ULL << (VisualBasic6Parser::TIME - 128))
      | (1ULL << (VisualBasic6Parser::TO - 128))
      | (1ULL << (VisualBasic6Parser::TRUE1 - 128))
      | (1ULL << (VisualBasic6Parser::TYPE - 128))
      | (1ULL << (VisualBasic6Parser::TYPEOF - 128))
      | (1ULL << (VisualBasic6Parser::UNLOAD - 128))
      | (1ULL << (VisualBasic6Parser::UNLOCK - 128))
      | (1ULL << (VisualBasic6Parser::UNTIL - 128))
      | (1ULL << (VisualBasic6Parser::VARIANT - 128))
      | (1ULL << (VisualBasic6Parser::VERSION - 128))
      | (1ULL << (VisualBasic6Parser::WEND - 128))
      | (1ULL << (VisualBasic6Parser::WHILE - 128))
      | (1ULL << (VisualBasic6Parser::WIDTH - 128))
      | (1ULL << (VisualBasic6Parser::WITH - 128))
      | (1ULL << (VisualBasic6Parser::WITHEVENTS - 128))
      | (1ULL << (VisualBasic6Parser::WRITE - 128))
      | (1ULL << (VisualBasic6Parser::XOR - 128))
      | (1ULL << (VisualBasic6Parser::DOT - 128))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 128)))) != 0) || ((((_la - 206) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 206)) & ((1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 206))
      | (1ULL << (VisualBasic6Parser::IDENTIFIER - 206))
      | (1ULL << (VisualBasic6Parser::WS - 206)))) != 0)) {
      setState(1385);
      moduleBody();
      setState(1387); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(1386);
        match(VisualBasic6Parser::NEWLINE);
        setState(1389); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- MacroElseIfBlockStmtContext ------------------------------------------------------------------

VisualBasic6Parser::MacroElseIfBlockStmtContext::MacroElseIfBlockStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::MacroElseIfBlockStmtContext::MACRO_ELSEIF() {
  return getToken(VisualBasic6Parser::MACRO_ELSEIF, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::MacroElseIfBlockStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::MacroElseIfBlockStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::IfConditionStmtContext* VisualBasic6Parser::MacroElseIfBlockStmtContext::ifConditionStmt() {
  return getRuleContext<VisualBasic6Parser::IfConditionStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::MacroElseIfBlockStmtContext::THEN() {
  return getToken(VisualBasic6Parser::THEN, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::MacroElseIfBlockStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::MacroElseIfBlockStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::ModuleBodyContext* VisualBasic6Parser::MacroElseIfBlockStmtContext::moduleBody() {
  return getRuleContext<VisualBasic6Parser::ModuleBodyContext>(0);
}


size_t VisualBasic6Parser::MacroElseIfBlockStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleMacroElseIfBlockStmt;
}

antlrcpp::Any VisualBasic6Parser::MacroElseIfBlockStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitMacroElseIfBlockStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::MacroElseIfBlockStmtContext* VisualBasic6Parser::macroElseIfBlockStmt() {
  MacroElseIfBlockStmtContext *_localctx = _tracker.createInstance<MacroElseIfBlockStmtContext>(_ctx, getState());
  enterRule(_localctx, 134, VisualBasic6Parser::RuleMacroElseIfBlockStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1393);
    match(VisualBasic6Parser::MACRO_ELSEIF);
    setState(1394);
    match(VisualBasic6Parser::WS);
    setState(1395);
    ifConditionStmt();
    setState(1396);
    match(VisualBasic6Parser::WS);
    setState(1397);
    match(VisualBasic6Parser::THEN);
    setState(1399); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(1398);
      match(VisualBasic6Parser::NEWLINE);
      setState(1401); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(1409);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
      | (1ULL << VisualBasic6Parser::ADDRESSOF)
      | (1ULL << VisualBasic6Parser::ALIAS)
      | (1ULL << VisualBasic6Parser::AND)
      | (1ULL << VisualBasic6Parser::ATTRIBUTE)
      | (1ULL << VisualBasic6Parser::APPACTIVATE)
      | (1ULL << VisualBasic6Parser::APPEND)
      | (1ULL << VisualBasic6Parser::AS)
      | (1ULL << VisualBasic6Parser::BEEP)
      | (1ULL << VisualBasic6Parser::BEGIN)
      | (1ULL << VisualBasic6Parser::BINARY)
      | (1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYVAL)
      | (1ULL << VisualBasic6Parser::BYREF)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::CALL)
      | (1ULL << VisualBasic6Parser::CASE)
      | (1ULL << VisualBasic6Parser::CHDIR)
      | (1ULL << VisualBasic6Parser::CHDRIVE)
      | (1ULL << VisualBasic6Parser::CLASS)
      | (1ULL << VisualBasic6Parser::CLOSE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::CONST)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DECLARE)
      | (1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR)
      | (1ULL << VisualBasic6Parser::DELETESETTING)
      | (1ULL << VisualBasic6Parser::DIM)
      | (1ULL << VisualBasic6Parser::DO)
      | (1ULL << VisualBasic6Parser::DOUBLE)
      | (1ULL << VisualBasic6Parser::EACH)
      | (1ULL << VisualBasic6Parser::ELSE)
      | (1ULL << VisualBasic6Parser::ELSEIF)
      | (1ULL << VisualBasic6Parser::END)
      | (1ULL << VisualBasic6Parser::ENUM)
      | (1ULL << VisualBasic6Parser::EQV)
      | (1ULL << VisualBasic6Parser::ERASE)
      | (1ULL << VisualBasic6Parser::ERROR)
      | (1ULL << VisualBasic6Parser::EVENT)
      | (1ULL << VisualBasic6Parser::EXIT_DO)
      | (1ULL << VisualBasic6Parser::EXIT_FOR)
      | (1ULL << VisualBasic6Parser::EXIT_FUNCTION))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (VisualBasic6Parser::EXIT_PROPERTY - 64))
      | (1ULL << (VisualBasic6Parser::EXIT_SUB - 64))
      | (1ULL << (VisualBasic6Parser::FALSE1 - 64))
      | (1ULL << (VisualBasic6Parser::FILECOPY - 64))
      | (1ULL << (VisualBasic6Parser::FRIEND - 64))
      | (1ULL << (VisualBasic6Parser::FOR - 64))
      | (1ULL << (VisualBasic6Parser::FUNCTION - 64))
      | (1ULL << (VisualBasic6Parser::GET - 64))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 64))
      | (1ULL << (VisualBasic6Parser::GOSUB - 64))
      | (1ULL << (VisualBasic6Parser::GOTO - 64))
      | (1ULL << (VisualBasic6Parser::IF - 64))
      | (1ULL << (VisualBasic6Parser::IMP - 64))
      | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 64))
      | (1ULL << (VisualBasic6Parser::IN - 64))
      | (1ULL << (VisualBasic6Parser::INPUT - 64))
      | (1ULL << (VisualBasic6Parser::IS - 64))
      | (1ULL << (VisualBasic6Parser::INTEGER - 64))
      | (1ULL << (VisualBasic6Parser::KILL - 64))
      | (1ULL << (VisualBasic6Parser::LOAD - 64))
      | (1ULL << (VisualBasic6Parser::LOCK - 64))
      | (1ULL << (VisualBasic6Parser::LONG - 64))
      | (1ULL << (VisualBasic6Parser::LOOP - 64))
      | (1ULL << (VisualBasic6Parser::LEN - 64))
      | (1ULL << (VisualBasic6Parser::LET - 64))
      | (1ULL << (VisualBasic6Parser::LIB - 64))
      | (1ULL << (VisualBasic6Parser::LIKE - 64))
      | (1ULL << (VisualBasic6Parser::LINE_INPUT - 64))
      | (1ULL << (VisualBasic6Parser::LSET - 64))
      | (1ULL << (VisualBasic6Parser::MACRO_IF - 64))
      | (1ULL << (VisualBasic6Parser::ME - 64))
      | (1ULL << (VisualBasic6Parser::MID - 64))
      | (1ULL << (VisualBasic6Parser::MKDIR - 64))
      | (1ULL << (VisualBasic6Parser::MOD - 64))
      | (1ULL << (VisualBasic6Parser::NAME - 64))
      | (1ULL << (VisualBasic6Parser::NEXT - 64))
      | (1ULL << (VisualBasic6Parser::NEW - 64))
      | (1ULL << (VisualBasic6Parser::NOT - 64))
      | (1ULL << (VisualBasic6Parser::NOTHING - 64))
      | (1ULL << (VisualBasic6Parser::NULL1 - 64))
      | (1ULL << (VisualBasic6Parser::OBJECT - 64))
      | (1ULL << (VisualBasic6Parser::ON - 64))
      | (1ULL << (VisualBasic6Parser::ON_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::ON_LOCAL_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::OPEN - 64))
      | (1ULL << (VisualBasic6Parser::OPTIONAL - 64))
      | (1ULL << (VisualBasic6Parser::OPTION_BASE - 64))
      | (1ULL << (VisualBasic6Parser::OPTION_EXPLICIT - 64))
      | (1ULL << (VisualBasic6Parser::OPTION_COMPARE - 64))
      | (1ULL << (VisualBasic6Parser::OPTION_PRIVATE_MODULE - 64))
      | (1ULL << (VisualBasic6Parser::OR - 64))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 64))
      | (1ULL << (VisualBasic6Parser::PARAMARRAY - 64))
      | (1ULL << (VisualBasic6Parser::PRESERVE - 64))
      | (1ULL << (VisualBasic6Parser::PRINT - 64))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 64))
      | (1ULL << (VisualBasic6Parser::PROPERTY_GET - 64))
      | (1ULL << (VisualBasic6Parser::PROPERTY_LET - 64)))) != 0) || ((((_la - 128) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 128)) & ((1ULL << (VisualBasic6Parser::PROPERTY_SET - 128))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 128))
      | (1ULL << (VisualBasic6Parser::PUT - 128))
      | (1ULL << (VisualBasic6Parser::RANDOM - 128))
      | (1ULL << (VisualBasic6Parser::RANDOMIZE - 128))
      | (1ULL << (VisualBasic6Parser::RAISEEVENT - 128))
      | (1ULL << (VisualBasic6Parser::READ - 128))
      | (1ULL << (VisualBasic6Parser::REDIM - 128))
      | (1ULL << (VisualBasic6Parser::REM - 128))
      | (1ULL << (VisualBasic6Parser::RESET - 128))
      | (1ULL << (VisualBasic6Parser::RESUME - 128))
      | (1ULL << (VisualBasic6Parser::RETURN - 128))
      | (1ULL << (VisualBasic6Parser::RMDIR - 128))
      | (1ULL << (VisualBasic6Parser::RSET - 128))
      | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 128))
      | (1ULL << (VisualBasic6Parser::SAVESETTING - 128))
      | (1ULL << (VisualBasic6Parser::SEEK - 128))
      | (1ULL << (VisualBasic6Parser::SELECT - 128))
      | (1ULL << (VisualBasic6Parser::SENDKEYS - 128))
      | (1ULL << (VisualBasic6Parser::SET - 128))
      | (1ULL << (VisualBasic6Parser::SETATTR - 128))
      | (1ULL << (VisualBasic6Parser::SHARED - 128))
      | (1ULL << (VisualBasic6Parser::SINGLE - 128))
      | (1ULL << (VisualBasic6Parser::SPC - 128))
      | (1ULL << (VisualBasic6Parser::STATIC - 128))
      | (1ULL << (VisualBasic6Parser::STEP - 128))
      | (1ULL << (VisualBasic6Parser::STOP - 128))
      | (1ULL << (VisualBasic6Parser::STRING - 128))
      | (1ULL << (VisualBasic6Parser::SUB - 128))
      | (1ULL << (VisualBasic6Parser::TAB - 128))
      | (1ULL << (VisualBasic6Parser::TEXT - 128))
      | (1ULL << (VisualBasic6Parser::THEN - 128))
      | (1ULL << (VisualBasic6Parser::TIME - 128))
      | (1ULL << (VisualBasic6Parser::TO - 128))
      | (1ULL << (VisualBasic6Parser::TRUE1 - 128))
      | (1ULL << (VisualBasic6Parser::TYPE - 128))
      | (1ULL << (VisualBasic6Parser::TYPEOF - 128))
      | (1ULL << (VisualBasic6Parser::UNLOAD - 128))
      | (1ULL << (VisualBasic6Parser::UNLOCK - 128))
      | (1ULL << (VisualBasic6Parser::UNTIL - 128))
      | (1ULL << (VisualBasic6Parser::VARIANT - 128))
      | (1ULL << (VisualBasic6Parser::VERSION - 128))
      | (1ULL << (VisualBasic6Parser::WEND - 128))
      | (1ULL << (VisualBasic6Parser::WHILE - 128))
      | (1ULL << (VisualBasic6Parser::WIDTH - 128))
      | (1ULL << (VisualBasic6Parser::WITH - 128))
      | (1ULL << (VisualBasic6Parser::WITHEVENTS - 128))
      | (1ULL << (VisualBasic6Parser::WRITE - 128))
      | (1ULL << (VisualBasic6Parser::XOR - 128))
      | (1ULL << (VisualBasic6Parser::DOT - 128))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 128)))) != 0) || ((((_la - 206) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 206)) & ((1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 206))
      | (1ULL << (VisualBasic6Parser::IDENTIFIER - 206))
      | (1ULL << (VisualBasic6Parser::WS - 206)))) != 0)) {
      setState(1403);
      moduleBody();
      setState(1405); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(1404);
        match(VisualBasic6Parser::NEWLINE);
        setState(1407); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- MacroElseBlockStmtContext ------------------------------------------------------------------

VisualBasic6Parser::MacroElseBlockStmtContext::MacroElseBlockStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::MacroElseBlockStmtContext::MACRO_ELSE() {
  return getToken(VisualBasic6Parser::MACRO_ELSE, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::MacroElseBlockStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::MacroElseBlockStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::ModuleBodyContext* VisualBasic6Parser::MacroElseBlockStmtContext::moduleBody() {
  return getRuleContext<VisualBasic6Parser::ModuleBodyContext>(0);
}


size_t VisualBasic6Parser::MacroElseBlockStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleMacroElseBlockStmt;
}

antlrcpp::Any VisualBasic6Parser::MacroElseBlockStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitMacroElseBlockStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::MacroElseBlockStmtContext* VisualBasic6Parser::macroElseBlockStmt() {
  MacroElseBlockStmtContext *_localctx = _tracker.createInstance<MacroElseBlockStmtContext>(_ctx, getState());
  enterRule(_localctx, 136, VisualBasic6Parser::RuleMacroElseBlockStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1411);
    match(VisualBasic6Parser::MACRO_ELSE);
    setState(1413); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(1412);
      match(VisualBasic6Parser::NEWLINE);
      setState(1415); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(1423);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
      | (1ULL << VisualBasic6Parser::ADDRESSOF)
      | (1ULL << VisualBasic6Parser::ALIAS)
      | (1ULL << VisualBasic6Parser::AND)
      | (1ULL << VisualBasic6Parser::ATTRIBUTE)
      | (1ULL << VisualBasic6Parser::APPACTIVATE)
      | (1ULL << VisualBasic6Parser::APPEND)
      | (1ULL << VisualBasic6Parser::AS)
      | (1ULL << VisualBasic6Parser::BEEP)
      | (1ULL << VisualBasic6Parser::BEGIN)
      | (1ULL << VisualBasic6Parser::BINARY)
      | (1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYVAL)
      | (1ULL << VisualBasic6Parser::BYREF)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::CALL)
      | (1ULL << VisualBasic6Parser::CASE)
      | (1ULL << VisualBasic6Parser::CHDIR)
      | (1ULL << VisualBasic6Parser::CHDRIVE)
      | (1ULL << VisualBasic6Parser::CLASS)
      | (1ULL << VisualBasic6Parser::CLOSE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::CONST)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DECLARE)
      | (1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR)
      | (1ULL << VisualBasic6Parser::DELETESETTING)
      | (1ULL << VisualBasic6Parser::DIM)
      | (1ULL << VisualBasic6Parser::DO)
      | (1ULL << VisualBasic6Parser::DOUBLE)
      | (1ULL << VisualBasic6Parser::EACH)
      | (1ULL << VisualBasic6Parser::ELSE)
      | (1ULL << VisualBasic6Parser::ELSEIF)
      | (1ULL << VisualBasic6Parser::END)
      | (1ULL << VisualBasic6Parser::ENUM)
      | (1ULL << VisualBasic6Parser::EQV)
      | (1ULL << VisualBasic6Parser::ERASE)
      | (1ULL << VisualBasic6Parser::ERROR)
      | (1ULL << VisualBasic6Parser::EVENT)
      | (1ULL << VisualBasic6Parser::EXIT_DO)
      | (1ULL << VisualBasic6Parser::EXIT_FOR)
      | (1ULL << VisualBasic6Parser::EXIT_FUNCTION))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (VisualBasic6Parser::EXIT_PROPERTY - 64))
      | (1ULL << (VisualBasic6Parser::EXIT_SUB - 64))
      | (1ULL << (VisualBasic6Parser::FALSE1 - 64))
      | (1ULL << (VisualBasic6Parser::FILECOPY - 64))
      | (1ULL << (VisualBasic6Parser::FRIEND - 64))
      | (1ULL << (VisualBasic6Parser::FOR - 64))
      | (1ULL << (VisualBasic6Parser::FUNCTION - 64))
      | (1ULL << (VisualBasic6Parser::GET - 64))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 64))
      | (1ULL << (VisualBasic6Parser::GOSUB - 64))
      | (1ULL << (VisualBasic6Parser::GOTO - 64))
      | (1ULL << (VisualBasic6Parser::IF - 64))
      | (1ULL << (VisualBasic6Parser::IMP - 64))
      | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 64))
      | (1ULL << (VisualBasic6Parser::IN - 64))
      | (1ULL << (VisualBasic6Parser::INPUT - 64))
      | (1ULL << (VisualBasic6Parser::IS - 64))
      | (1ULL << (VisualBasic6Parser::INTEGER - 64))
      | (1ULL << (VisualBasic6Parser::KILL - 64))
      | (1ULL << (VisualBasic6Parser::LOAD - 64))
      | (1ULL << (VisualBasic6Parser::LOCK - 64))
      | (1ULL << (VisualBasic6Parser::LONG - 64))
      | (1ULL << (VisualBasic6Parser::LOOP - 64))
      | (1ULL << (VisualBasic6Parser::LEN - 64))
      | (1ULL << (VisualBasic6Parser::LET - 64))
      | (1ULL << (VisualBasic6Parser::LIB - 64))
      | (1ULL << (VisualBasic6Parser::LIKE - 64))
      | (1ULL << (VisualBasic6Parser::LINE_INPUT - 64))
      | (1ULL << (VisualBasic6Parser::LSET - 64))
      | (1ULL << (VisualBasic6Parser::MACRO_IF - 64))
      | (1ULL << (VisualBasic6Parser::ME - 64))
      | (1ULL << (VisualBasic6Parser::MID - 64))
      | (1ULL << (VisualBasic6Parser::MKDIR - 64))
      | (1ULL << (VisualBasic6Parser::MOD - 64))
      | (1ULL << (VisualBasic6Parser::NAME - 64))
      | (1ULL << (VisualBasic6Parser::NEXT - 64))
      | (1ULL << (VisualBasic6Parser::NEW - 64))
      | (1ULL << (VisualBasic6Parser::NOT - 64))
      | (1ULL << (VisualBasic6Parser::NOTHING - 64))
      | (1ULL << (VisualBasic6Parser::NULL1 - 64))
      | (1ULL << (VisualBasic6Parser::OBJECT - 64))
      | (1ULL << (VisualBasic6Parser::ON - 64))
      | (1ULL << (VisualBasic6Parser::ON_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::ON_LOCAL_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::OPEN - 64))
      | (1ULL << (VisualBasic6Parser::OPTIONAL - 64))
      | (1ULL << (VisualBasic6Parser::OPTION_BASE - 64))
      | (1ULL << (VisualBasic6Parser::OPTION_EXPLICIT - 64))
      | (1ULL << (VisualBasic6Parser::OPTION_COMPARE - 64))
      | (1ULL << (VisualBasic6Parser::OPTION_PRIVATE_MODULE - 64))
      | (1ULL << (VisualBasic6Parser::OR - 64))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 64))
      | (1ULL << (VisualBasic6Parser::PARAMARRAY - 64))
      | (1ULL << (VisualBasic6Parser::PRESERVE - 64))
      | (1ULL << (VisualBasic6Parser::PRINT - 64))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 64))
      | (1ULL << (VisualBasic6Parser::PROPERTY_GET - 64))
      | (1ULL << (VisualBasic6Parser::PROPERTY_LET - 64)))) != 0) || ((((_la - 128) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 128)) & ((1ULL << (VisualBasic6Parser::PROPERTY_SET - 128))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 128))
      | (1ULL << (VisualBasic6Parser::PUT - 128))
      | (1ULL << (VisualBasic6Parser::RANDOM - 128))
      | (1ULL << (VisualBasic6Parser::RANDOMIZE - 128))
      | (1ULL << (VisualBasic6Parser::RAISEEVENT - 128))
      | (1ULL << (VisualBasic6Parser::READ - 128))
      | (1ULL << (VisualBasic6Parser::REDIM - 128))
      | (1ULL << (VisualBasic6Parser::REM - 128))
      | (1ULL << (VisualBasic6Parser::RESET - 128))
      | (1ULL << (VisualBasic6Parser::RESUME - 128))
      | (1ULL << (VisualBasic6Parser::RETURN - 128))
      | (1ULL << (VisualBasic6Parser::RMDIR - 128))
      | (1ULL << (VisualBasic6Parser::RSET - 128))
      | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 128))
      | (1ULL << (VisualBasic6Parser::SAVESETTING - 128))
      | (1ULL << (VisualBasic6Parser::SEEK - 128))
      | (1ULL << (VisualBasic6Parser::SELECT - 128))
      | (1ULL << (VisualBasic6Parser::SENDKEYS - 128))
      | (1ULL << (VisualBasic6Parser::SET - 128))
      | (1ULL << (VisualBasic6Parser::SETATTR - 128))
      | (1ULL << (VisualBasic6Parser::SHARED - 128))
      | (1ULL << (VisualBasic6Parser::SINGLE - 128))
      | (1ULL << (VisualBasic6Parser::SPC - 128))
      | (1ULL << (VisualBasic6Parser::STATIC - 128))
      | (1ULL << (VisualBasic6Parser::STEP - 128))
      | (1ULL << (VisualBasic6Parser::STOP - 128))
      | (1ULL << (VisualBasic6Parser::STRING - 128))
      | (1ULL << (VisualBasic6Parser::SUB - 128))
      | (1ULL << (VisualBasic6Parser::TAB - 128))
      | (1ULL << (VisualBasic6Parser::TEXT - 128))
      | (1ULL << (VisualBasic6Parser::THEN - 128))
      | (1ULL << (VisualBasic6Parser::TIME - 128))
      | (1ULL << (VisualBasic6Parser::TO - 128))
      | (1ULL << (VisualBasic6Parser::TRUE1 - 128))
      | (1ULL << (VisualBasic6Parser::TYPE - 128))
      | (1ULL << (VisualBasic6Parser::TYPEOF - 128))
      | (1ULL << (VisualBasic6Parser::UNLOAD - 128))
      | (1ULL << (VisualBasic6Parser::UNLOCK - 128))
      | (1ULL << (VisualBasic6Parser::UNTIL - 128))
      | (1ULL << (VisualBasic6Parser::VARIANT - 128))
      | (1ULL << (VisualBasic6Parser::VERSION - 128))
      | (1ULL << (VisualBasic6Parser::WEND - 128))
      | (1ULL << (VisualBasic6Parser::WHILE - 128))
      | (1ULL << (VisualBasic6Parser::WIDTH - 128))
      | (1ULL << (VisualBasic6Parser::WITH - 128))
      | (1ULL << (VisualBasic6Parser::WITHEVENTS - 128))
      | (1ULL << (VisualBasic6Parser::WRITE - 128))
      | (1ULL << (VisualBasic6Parser::XOR - 128))
      | (1ULL << (VisualBasic6Parser::DOT - 128))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 128)))) != 0) || ((((_la - 206) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 206)) & ((1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 206))
      | (1ULL << (VisualBasic6Parser::IDENTIFIER - 206))
      | (1ULL << (VisualBasic6Parser::WS - 206)))) != 0)) {
      setState(1417);
      moduleBody();
      setState(1419); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(1418);
        match(VisualBasic6Parser::NEWLINE);
        setState(1421); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- MidStmtContext ------------------------------------------------------------------

VisualBasic6Parser::MidStmtContext::MidStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::MidStmtContext::MID() {
  return getToken(VisualBasic6Parser::MID, 0);
}

tree::TerminalNode* VisualBasic6Parser::MidStmtContext::LPAREN() {
  return getToken(VisualBasic6Parser::LPAREN, 0);
}

VisualBasic6Parser::ArgsCallContext* VisualBasic6Parser::MidStmtContext::argsCall() {
  return getRuleContext<VisualBasic6Parser::ArgsCallContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::MidStmtContext::RPAREN() {
  return getToken(VisualBasic6Parser::RPAREN, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::MidStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::MidStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}


size_t VisualBasic6Parser::MidStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleMidStmt;
}

antlrcpp::Any VisualBasic6Parser::MidStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitMidStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::MidStmtContext* VisualBasic6Parser::midStmt() {
  MidStmtContext *_localctx = _tracker.createInstance<MidStmtContext>(_ctx, getState());
  enterRule(_localctx, 138, VisualBasic6Parser::RuleMidStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1425);
    match(VisualBasic6Parser::MID);
    setState(1427);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1426);
      match(VisualBasic6Parser::WS);
    }
    setState(1429);
    match(VisualBasic6Parser::LPAREN);
    setState(1431);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 194, _ctx)) {
    case 1: {
      setState(1430);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1433);
    argsCall();
    setState(1435);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1434);
      match(VisualBasic6Parser::WS);
    }
    setState(1437);
    match(VisualBasic6Parser::RPAREN);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- MkdirStmtContext ------------------------------------------------------------------

VisualBasic6Parser::MkdirStmtContext::MkdirStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::MkdirStmtContext::MKDIR() {
  return getToken(VisualBasic6Parser::MKDIR, 0);
}

tree::TerminalNode* VisualBasic6Parser::MkdirStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::MkdirStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::MkdirStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleMkdirStmt;
}

antlrcpp::Any VisualBasic6Parser::MkdirStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitMkdirStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::MkdirStmtContext* VisualBasic6Parser::mkdirStmt() {
  MkdirStmtContext *_localctx = _tracker.createInstance<MkdirStmtContext>(_ctx, getState());
  enterRule(_localctx, 140, VisualBasic6Parser::RuleMkdirStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1439);
    match(VisualBasic6Parser::MKDIR);
    setState(1440);
    match(VisualBasic6Parser::WS);
    setState(1441);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- NameStmtContext ------------------------------------------------------------------

VisualBasic6Parser::NameStmtContext::NameStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::NameStmtContext::NAME() {
  return getToken(VisualBasic6Parser::NAME, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::NameStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::NameStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::NameStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::NameStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::NameStmtContext::AS() {
  return getToken(VisualBasic6Parser::AS, 0);
}


size_t VisualBasic6Parser::NameStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleNameStmt;
}

antlrcpp::Any VisualBasic6Parser::NameStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitNameStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::NameStmtContext* VisualBasic6Parser::nameStmt() {
  NameStmtContext *_localctx = _tracker.createInstance<NameStmtContext>(_ctx, getState());
  enterRule(_localctx, 142, VisualBasic6Parser::RuleNameStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1443);
    match(VisualBasic6Parser::NAME);
    setState(1444);
    match(VisualBasic6Parser::WS);
    setState(1445);
    valueStmt(0);
    setState(1446);
    match(VisualBasic6Parser::WS);
    setState(1447);
    match(VisualBasic6Parser::AS);
    setState(1448);
    match(VisualBasic6Parser::WS);
    setState(1449);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- OnErrorStmtContext ------------------------------------------------------------------

VisualBasic6Parser::OnErrorStmtContext::OnErrorStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::OnErrorStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::OnErrorStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

tree::TerminalNode* VisualBasic6Parser::OnErrorStmtContext::ON_ERROR() {
  return getToken(VisualBasic6Parser::ON_ERROR, 0);
}

tree::TerminalNode* VisualBasic6Parser::OnErrorStmtContext::ON_LOCAL_ERROR() {
  return getToken(VisualBasic6Parser::ON_LOCAL_ERROR, 0);
}

tree::TerminalNode* VisualBasic6Parser::OnErrorStmtContext::GOTO() {
  return getToken(VisualBasic6Parser::GOTO, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::OnErrorStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::OnErrorStmtContext::RESUME() {
  return getToken(VisualBasic6Parser::RESUME, 0);
}

tree::TerminalNode* VisualBasic6Parser::OnErrorStmtContext::NEXT() {
  return getToken(VisualBasic6Parser::NEXT, 0);
}

tree::TerminalNode* VisualBasic6Parser::OnErrorStmtContext::COLON() {
  return getToken(VisualBasic6Parser::COLON, 0);
}


size_t VisualBasic6Parser::OnErrorStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleOnErrorStmt;
}

antlrcpp::Any VisualBasic6Parser::OnErrorStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitOnErrorStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::OnErrorStmtContext* VisualBasic6Parser::onErrorStmt() {
  OnErrorStmtContext *_localctx = _tracker.createInstance<OnErrorStmtContext>(_ctx, getState());
  enterRule(_localctx, 144, VisualBasic6Parser::RuleOnErrorStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1451);
    _la = _input->LA(1);
    if (!(_la == VisualBasic6Parser::ON_ERROR

    || _la == VisualBasic6Parser::ON_LOCAL_ERROR)) {
    _errHandler->recoverInline(this);
    }
    else {
      _errHandler->reportMatch(this);
      consume();
    }
    setState(1452);
    match(VisualBasic6Parser::WS);
    setState(1462);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case VisualBasic6Parser::GOTO: {
        setState(1453);
        match(VisualBasic6Parser::GOTO);
        setState(1454);
        match(VisualBasic6Parser::WS);
        setState(1455);
        valueStmt(0);
        setState(1457);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::COLON) {
          setState(1456);
          match(VisualBasic6Parser::COLON);
        }
        break;
      }

      case VisualBasic6Parser::RESUME: {
        setState(1459);
        match(VisualBasic6Parser::RESUME);
        setState(1460);
        match(VisualBasic6Parser::WS);
        setState(1461);
        match(VisualBasic6Parser::NEXT);
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

//----------------- OnGoToStmtContext ------------------------------------------------------------------

VisualBasic6Parser::OnGoToStmtContext::OnGoToStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::OnGoToStmtContext::ON() {
  return getToken(VisualBasic6Parser::ON, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::OnGoToStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::OnGoToStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::OnGoToStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::OnGoToStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::OnGoToStmtContext::GOTO() {
  return getToken(VisualBasic6Parser::GOTO, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::OnGoToStmtContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::OnGoToStmtContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}


size_t VisualBasic6Parser::OnGoToStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleOnGoToStmt;
}

antlrcpp::Any VisualBasic6Parser::OnGoToStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitOnGoToStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::OnGoToStmtContext* VisualBasic6Parser::onGoToStmt() {
  OnGoToStmtContext *_localctx = _tracker.createInstance<OnGoToStmtContext>(_ctx, getState());
  enterRule(_localctx, 146, VisualBasic6Parser::RuleOnGoToStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(1464);
    match(VisualBasic6Parser::ON);
    setState(1465);
    match(VisualBasic6Parser::WS);
    setState(1466);
    valueStmt(0);
    setState(1467);
    match(VisualBasic6Parser::WS);
    setState(1468);
    match(VisualBasic6Parser::GOTO);
    setState(1469);
    match(VisualBasic6Parser::WS);
    setState(1470);
    valueStmt(0);
    setState(1481);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 200, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(1472);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(1471);
          match(VisualBasic6Parser::WS);
        }
        setState(1474);
        match(VisualBasic6Parser::COMMA);
        setState(1476);
        _errHandler->sync(this);

        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 199, _ctx)) {
        case 1: {
          setState(1475);
          match(VisualBasic6Parser::WS);
          break;
        }

        }
        setState(1478);
        valueStmt(0); 
      }
      setState(1483);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 200, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- OnGoSubStmtContext ------------------------------------------------------------------

VisualBasic6Parser::OnGoSubStmtContext::OnGoSubStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::OnGoSubStmtContext::ON() {
  return getToken(VisualBasic6Parser::ON, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::OnGoSubStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::OnGoSubStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::OnGoSubStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::OnGoSubStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::OnGoSubStmtContext::GOSUB() {
  return getToken(VisualBasic6Parser::GOSUB, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::OnGoSubStmtContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::OnGoSubStmtContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}


size_t VisualBasic6Parser::OnGoSubStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleOnGoSubStmt;
}

antlrcpp::Any VisualBasic6Parser::OnGoSubStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitOnGoSubStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::OnGoSubStmtContext* VisualBasic6Parser::onGoSubStmt() {
  OnGoSubStmtContext *_localctx = _tracker.createInstance<OnGoSubStmtContext>(_ctx, getState());
  enterRule(_localctx, 148, VisualBasic6Parser::RuleOnGoSubStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(1484);
    match(VisualBasic6Parser::ON);
    setState(1485);
    match(VisualBasic6Parser::WS);
    setState(1486);
    valueStmt(0);
    setState(1487);
    match(VisualBasic6Parser::WS);
    setState(1488);
    match(VisualBasic6Parser::GOSUB);
    setState(1489);
    match(VisualBasic6Parser::WS);
    setState(1490);
    valueStmt(0);
    setState(1501);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 203, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(1492);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(1491);
          match(VisualBasic6Parser::WS);
        }
        setState(1494);
        match(VisualBasic6Parser::COMMA);
        setState(1496);
        _errHandler->sync(this);

        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 202, _ctx)) {
        case 1: {
          setState(1495);
          match(VisualBasic6Parser::WS);
          break;
        }

        }
        setState(1498);
        valueStmt(0); 
      }
      setState(1503);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 203, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- OpenStmtContext ------------------------------------------------------------------

VisualBasic6Parser::OpenStmtContext::OpenStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::OPEN() {
  return getToken(VisualBasic6Parser::OPEN, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::OpenStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::OpenStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::OpenStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::FOR() {
  return getToken(VisualBasic6Parser::FOR, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::AS() {
  return getToken(VisualBasic6Parser::AS, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::APPEND() {
  return getToken(VisualBasic6Parser::APPEND, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::BINARY() {
  return getToken(VisualBasic6Parser::BINARY, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::INPUT() {
  return getToken(VisualBasic6Parser::INPUT, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::OUTPUT() {
  return getToken(VisualBasic6Parser::OUTPUT, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::RANDOM() {
  return getToken(VisualBasic6Parser::RANDOM, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::ACCESS() {
  return getToken(VisualBasic6Parser::ACCESS, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::LEN() {
  return getToken(VisualBasic6Parser::LEN, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::READ() {
  return getToken(VisualBasic6Parser::READ, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::WRITE() {
  return getToken(VisualBasic6Parser::WRITE, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::READ_WRITE() {
  return getToken(VisualBasic6Parser::READ_WRITE, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::SHARED() {
  return getToken(VisualBasic6Parser::SHARED, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::LOCK_READ() {
  return getToken(VisualBasic6Parser::LOCK_READ, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::LOCK_WRITE() {
  return getToken(VisualBasic6Parser::LOCK_WRITE, 0);
}

tree::TerminalNode* VisualBasic6Parser::OpenStmtContext::LOCK_READ_WRITE() {
  return getToken(VisualBasic6Parser::LOCK_READ_WRITE, 0);
}


size_t VisualBasic6Parser::OpenStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleOpenStmt;
}

antlrcpp::Any VisualBasic6Parser::OpenStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitOpenStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::OpenStmtContext* VisualBasic6Parser::openStmt() {
  OpenStmtContext *_localctx = _tracker.createInstance<OpenStmtContext>(_ctx, getState());
  enterRule(_localctx, 150, VisualBasic6Parser::RuleOpenStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1504);
    match(VisualBasic6Parser::OPEN);
    setState(1505);
    match(VisualBasic6Parser::WS);
    setState(1506);
    valueStmt(0);
    setState(1507);
    match(VisualBasic6Parser::WS);
    setState(1508);
    match(VisualBasic6Parser::FOR);
    setState(1509);
    match(VisualBasic6Parser::WS);
    setState(1510);
    _la = _input->LA(1);
    if (!(_la == VisualBasic6Parser::APPEND

    || _la == VisualBasic6Parser::BINARY || ((((_la - 79) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 79)) & ((1ULL << (VisualBasic6Parser::INPUT - 79))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 79))
      | (1ULL << (VisualBasic6Parser::RANDOM - 79)))) != 0))) {
    _errHandler->recoverInline(this);
    }
    else {
      _errHandler->reportMatch(this);
      consume();
    }
    setState(1515);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 204, _ctx)) {
    case 1: {
      setState(1511);
      match(VisualBasic6Parser::WS);
      setState(1512);
      match(VisualBasic6Parser::ACCESS);
      setState(1513);
      match(VisualBasic6Parser::WS);
      setState(1514);
      _la = _input->LA(1);
      if (!(((((_la - 134) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 134)) & ((1ULL << (VisualBasic6Parser::READ - 134))
        | (1ULL << (VisualBasic6Parser::READ_WRITE - 134))
        | (1ULL << (VisualBasic6Parser::WRITE - 134)))) != 0))) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      break;
    }

    }
    setState(1519);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 205, _ctx)) {
    case 1: {
      setState(1517);
      match(VisualBasic6Parser::WS);
      setState(1518);
      _la = _input->LA(1);
      if (!(((((_la - 92) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 92)) & ((1ULL << (VisualBasic6Parser::LOCK_READ - 92))
        | (1ULL << (VisualBasic6Parser::LOCK_WRITE - 92))
        | (1ULL << (VisualBasic6Parser::LOCK_READ_WRITE - 92))
        | (1ULL << (VisualBasic6Parser::SHARED - 92)))) != 0))) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      break;
    }

    }
    setState(1521);
    match(VisualBasic6Parser::WS);
    setState(1522);
    match(VisualBasic6Parser::AS);
    setState(1523);
    match(VisualBasic6Parser::WS);
    setState(1524);
    valueStmt(0);
    setState(1535);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 208, _ctx)) {
    case 1: {
      setState(1525);
      match(VisualBasic6Parser::WS);
      setState(1526);
      match(VisualBasic6Parser::LEN);
      setState(1528);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(1527);
        match(VisualBasic6Parser::WS);
      }
      setState(1530);
      match(VisualBasic6Parser::EQ);
      setState(1532);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 207, _ctx)) {
      case 1: {
        setState(1531);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(1534);
      valueStmt(0);
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

//----------------- OutputListContext ------------------------------------------------------------------

VisualBasic6Parser::OutputListContext::OutputListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<VisualBasic6Parser::OutputList_ExpressionContext *> VisualBasic6Parser::OutputListContext::outputList_Expression() {
  return getRuleContexts<VisualBasic6Parser::OutputList_ExpressionContext>();
}

VisualBasic6Parser::OutputList_ExpressionContext* VisualBasic6Parser::OutputListContext::outputList_Expression(size_t i) {
  return getRuleContext<VisualBasic6Parser::OutputList_ExpressionContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::OutputListContext::SEMICOLON() {
  return getTokens(VisualBasic6Parser::SEMICOLON);
}

tree::TerminalNode* VisualBasic6Parser::OutputListContext::SEMICOLON(size_t i) {
  return getToken(VisualBasic6Parser::SEMICOLON, i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::OutputListContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::OutputListContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::OutputListContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::OutputListContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}


size_t VisualBasic6Parser::OutputListContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleOutputList;
}

antlrcpp::Any VisualBasic6Parser::OutputListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitOutputList(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::OutputListContext* VisualBasic6Parser::outputList() {
  OutputListContext *_localctx = _tracker.createInstance<OutputListContext>(_ctx, getState());
  enterRule(_localctx, 152, VisualBasic6Parser::RuleOutputList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    setState(1570);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 218, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(1537);
      outputList_Expression();
      setState(1550);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 212, _ctx);
      while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
        if (alt == 1) {
          setState(1539);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(1538);
            match(VisualBasic6Parser::WS);
          }
          setState(1541);
          _la = _input->LA(1);
          if (!(_la == VisualBasic6Parser::COMMA

          || _la == VisualBasic6Parser::SEMICOLON)) {
          _errHandler->recoverInline(this);
          }
          else {
            _errHandler->reportMatch(this);
            consume();
          }
          setState(1543);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 210, _ctx)) {
          case 1: {
            setState(1542);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(1546);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 211, _ctx)) {
          case 1: {
            setState(1545);
            outputList_Expression();
            break;
          }

          } 
        }
        setState(1552);
        _errHandler->sync(this);
        alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 212, _ctx);
      }
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(1554);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 213, _ctx)) {
      case 1: {
        setState(1553);
        outputList_Expression();
        break;
      }

      }
      setState(1566); 
      _errHandler->sync(this);
      alt = 1;
      do {
        switch (alt) {
          case 1: {
                setState(1557);
                _errHandler->sync(this);

                _la = _input->LA(1);
                if (_la == VisualBasic6Parser::WS) {
                  setState(1556);
                  match(VisualBasic6Parser::WS);
                }
                setState(1559);
                _la = _input->LA(1);
                if (!(_la == VisualBasic6Parser::COMMA

                || _la == VisualBasic6Parser::SEMICOLON)) {
                _errHandler->recoverInline(this);
                }
                else {
                  _errHandler->reportMatch(this);
                  consume();
                }
                setState(1561);
                _errHandler->sync(this);

                switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 215, _ctx)) {
                case 1: {
                  setState(1560);
                  match(VisualBasic6Parser::WS);
                  break;
                }

                }
                setState(1564);
                _errHandler->sync(this);

                switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 216, _ctx)) {
                case 1: {
                  setState(1563);
                  outputList_Expression();
                  break;
                }

                }
                break;
              }

        default:
          throw NoViableAltException(this);
        }
        setState(1568); 
        _errHandler->sync(this);
        alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 217, _ctx);
      } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
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

//----------------- OutputList_ExpressionContext ------------------------------------------------------------------

VisualBasic6Parser::OutputList_ExpressionContext::OutputList_ExpressionContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::OutputList_ExpressionContext::SPC() {
  return getToken(VisualBasic6Parser::SPC, 0);
}

tree::TerminalNode* VisualBasic6Parser::OutputList_ExpressionContext::TAB() {
  return getToken(VisualBasic6Parser::TAB, 0);
}

tree::TerminalNode* VisualBasic6Parser::OutputList_ExpressionContext::LPAREN() {
  return getToken(VisualBasic6Parser::LPAREN, 0);
}

VisualBasic6Parser::ArgsCallContext* VisualBasic6Parser::OutputList_ExpressionContext::argsCall() {
  return getRuleContext<VisualBasic6Parser::ArgsCallContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::OutputList_ExpressionContext::RPAREN() {
  return getToken(VisualBasic6Parser::RPAREN, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::OutputList_ExpressionContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::OutputList_ExpressionContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::OutputList_ExpressionContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::OutputList_ExpressionContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleOutputList_Expression;
}

antlrcpp::Any VisualBasic6Parser::OutputList_ExpressionContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitOutputList_Expression(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::OutputList_ExpressionContext* VisualBasic6Parser::outputList_Expression() {
  OutputList_ExpressionContext *_localctx = _tracker.createInstance<OutputList_ExpressionContext>(_ctx, getState());
  enterRule(_localctx, 154, VisualBasic6Parser::RuleOutputList_Expression);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1589);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 223, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(1572);
      _la = _input->LA(1);
      if (!(_la == VisualBasic6Parser::SPC

      || _la == VisualBasic6Parser::TAB)) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      setState(1586);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 222, _ctx)) {
      case 1: {
        setState(1574);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(1573);
          match(VisualBasic6Parser::WS);
        }
        setState(1576);
        match(VisualBasic6Parser::LPAREN);
        setState(1578);
        _errHandler->sync(this);

        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 220, _ctx)) {
        case 1: {
          setState(1577);
          match(VisualBasic6Parser::WS);
          break;
        }

        }
        setState(1580);
        argsCall();
        setState(1582);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(1581);
          match(VisualBasic6Parser::WS);
        }
        setState(1584);
        match(VisualBasic6Parser::RPAREN);
        break;
      }

      }
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(1588);
      valueStmt(0);
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

//----------------- PrintStmtContext ------------------------------------------------------------------

VisualBasic6Parser::PrintStmtContext::PrintStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::PrintStmtContext::PRINT() {
  return getToken(VisualBasic6Parser::PRINT, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::PrintStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::PrintStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::PrintStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::PrintStmtContext::COMMA() {
  return getToken(VisualBasic6Parser::COMMA, 0);
}

VisualBasic6Parser::OutputListContext* VisualBasic6Parser::PrintStmtContext::outputList() {
  return getRuleContext<VisualBasic6Parser::OutputListContext>(0);
}


size_t VisualBasic6Parser::PrintStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RulePrintStmt;
}

antlrcpp::Any VisualBasic6Parser::PrintStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitPrintStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::PrintStmtContext* VisualBasic6Parser::printStmt() {
  PrintStmtContext *_localctx = _tracker.createInstance<PrintStmtContext>(_ctx, getState());
  enterRule(_localctx, 156, VisualBasic6Parser::RulePrintStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1591);
    match(VisualBasic6Parser::PRINT);
    setState(1592);
    match(VisualBasic6Parser::WS);
    setState(1593);
    valueStmt(0);
    setState(1595);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1594);
      match(VisualBasic6Parser::WS);
    }
    setState(1597);
    match(VisualBasic6Parser::COMMA);
    setState(1602);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 226, _ctx)) {
    case 1: {
      setState(1599);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 225, _ctx)) {
      case 1: {
        setState(1598);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(1601);
      outputList();
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

//----------------- PropertyGetStmtContext ------------------------------------------------------------------

VisualBasic6Parser::PropertyGetStmtContext::PropertyGetStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::PropertyGetStmtContext::PROPERTY_GET() {
  return getToken(VisualBasic6Parser::PROPERTY_GET, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::PropertyGetStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::PropertyGetStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::PropertyGetStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::PropertyGetStmtContext::END_PROPERTY() {
  return getToken(VisualBasic6Parser::END_PROPERTY, 0);
}

VisualBasic6Parser::VisibilityContext* VisualBasic6Parser::PropertyGetStmtContext::visibility() {
  return getRuleContext<VisualBasic6Parser::VisibilityContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::PropertyGetStmtContext::STATIC() {
  return getToken(VisualBasic6Parser::STATIC, 0);
}

VisualBasic6Parser::TypeHintContext* VisualBasic6Parser::PropertyGetStmtContext::typeHint() {
  return getRuleContext<VisualBasic6Parser::TypeHintContext>(0);
}

VisualBasic6Parser::ArgListContext* VisualBasic6Parser::PropertyGetStmtContext::argList() {
  return getRuleContext<VisualBasic6Parser::ArgListContext>(0);
}

VisualBasic6Parser::AsTypeClauseContext* VisualBasic6Parser::PropertyGetStmtContext::asTypeClause() {
  return getRuleContext<VisualBasic6Parser::AsTypeClauseContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::PropertyGetStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::PropertyGetStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::PropertyGetStmtContext::block() {
  return getRuleContext<VisualBasic6Parser::BlockContext>(0);
}


size_t VisualBasic6Parser::PropertyGetStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RulePropertyGetStmt;
}

antlrcpp::Any VisualBasic6Parser::PropertyGetStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitPropertyGetStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::PropertyGetStmtContext* VisualBasic6Parser::propertyGetStmt() {
  PropertyGetStmtContext *_localctx = _tracker.createInstance<PropertyGetStmtContext>(_ctx, getState());
  enterRule(_localctx, 158, VisualBasic6Parser::RulePropertyGetStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1607);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 68) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 68)) & ((1ULL << (VisualBasic6Parser::FRIEND - 68))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 68))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 68))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 68)))) != 0)) {
      setState(1604);
      visibility();
      setState(1605);
      match(VisualBasic6Parser::WS);
    }
    setState(1611);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::STATIC) {
      setState(1609);
      match(VisualBasic6Parser::STATIC);
      setState(1610);
      match(VisualBasic6Parser::WS);
    }
    setState(1613);
    match(VisualBasic6Parser::PROPERTY_GET);
    setState(1614);
    match(VisualBasic6Parser::WS);
    setState(1615);
    ambiguousIdentifier();
    setState(1617);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 178) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 178)) & ((1ULL << (VisualBasic6Parser::AMPERSAND - 178))
      | (1ULL << (VisualBasic6Parser::AT - 178))
      | (1ULL << (VisualBasic6Parser::DOLLAR - 178))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 178))
      | (1ULL << (VisualBasic6Parser::HASH - 178))
      | (1ULL << (VisualBasic6Parser::PERCENT - 178)))) != 0)) {
      setState(1616);
      typeHint();
    }
    setState(1623);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 231, _ctx)) {
    case 1: {
      setState(1620);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(1619);
        match(VisualBasic6Parser::WS);
      }
      setState(1622);
      argList();
      break;
    }

    }
    setState(1627);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1625);
      match(VisualBasic6Parser::WS);
      setState(1626);
      asTypeClause();
    }
    setState(1630); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(1629);
      match(VisualBasic6Parser::NEWLINE);
      setState(1632); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(1640);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
      | (1ULL << VisualBasic6Parser::ADDRESSOF)
      | (1ULL << VisualBasic6Parser::ALIAS)
      | (1ULL << VisualBasic6Parser::AND)
      | (1ULL << VisualBasic6Parser::ATTRIBUTE)
      | (1ULL << VisualBasic6Parser::APPACTIVATE)
      | (1ULL << VisualBasic6Parser::APPEND)
      | (1ULL << VisualBasic6Parser::AS)
      | (1ULL << VisualBasic6Parser::BEEP)
      | (1ULL << VisualBasic6Parser::BEGIN)
      | (1ULL << VisualBasic6Parser::BINARY)
      | (1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYVAL)
      | (1ULL << VisualBasic6Parser::BYREF)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::CALL)
      | (1ULL << VisualBasic6Parser::CASE)
      | (1ULL << VisualBasic6Parser::CHDIR)
      | (1ULL << VisualBasic6Parser::CHDRIVE)
      | (1ULL << VisualBasic6Parser::CLASS)
      | (1ULL << VisualBasic6Parser::CLOSE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::CONST)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DECLARE)
      | (1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR)
      | (1ULL << VisualBasic6Parser::DELETESETTING)
      | (1ULL << VisualBasic6Parser::DIM)
      | (1ULL << VisualBasic6Parser::DO)
      | (1ULL << VisualBasic6Parser::DOUBLE)
      | (1ULL << VisualBasic6Parser::EACH)
      | (1ULL << VisualBasic6Parser::ELSE)
      | (1ULL << VisualBasic6Parser::ELSEIF)
      | (1ULL << VisualBasic6Parser::END)
      | (1ULL << VisualBasic6Parser::ENUM)
      | (1ULL << VisualBasic6Parser::EQV)
      | (1ULL << VisualBasic6Parser::ERASE)
      | (1ULL << VisualBasic6Parser::ERROR)
      | (1ULL << VisualBasic6Parser::EVENT)
      | (1ULL << VisualBasic6Parser::EXIT_DO)
      | (1ULL << VisualBasic6Parser::EXIT_FOR)
      | (1ULL << VisualBasic6Parser::EXIT_FUNCTION))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (VisualBasic6Parser::EXIT_PROPERTY - 64))
      | (1ULL << (VisualBasic6Parser::EXIT_SUB - 64))
      | (1ULL << (VisualBasic6Parser::FALSE1 - 64))
      | (1ULL << (VisualBasic6Parser::FILECOPY - 64))
      | (1ULL << (VisualBasic6Parser::FRIEND - 64))
      | (1ULL << (VisualBasic6Parser::FOR - 64))
      | (1ULL << (VisualBasic6Parser::FUNCTION - 64))
      | (1ULL << (VisualBasic6Parser::GET - 64))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 64))
      | (1ULL << (VisualBasic6Parser::GOSUB - 64))
      | (1ULL << (VisualBasic6Parser::GOTO - 64))
      | (1ULL << (VisualBasic6Parser::IF - 64))
      | (1ULL << (VisualBasic6Parser::IMP - 64))
      | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 64))
      | (1ULL << (VisualBasic6Parser::IN - 64))
      | (1ULL << (VisualBasic6Parser::INPUT - 64))
      | (1ULL << (VisualBasic6Parser::IS - 64))
      | (1ULL << (VisualBasic6Parser::INTEGER - 64))
      | (1ULL << (VisualBasic6Parser::KILL - 64))
      | (1ULL << (VisualBasic6Parser::LOAD - 64))
      | (1ULL << (VisualBasic6Parser::LOCK - 64))
      | (1ULL << (VisualBasic6Parser::LONG - 64))
      | (1ULL << (VisualBasic6Parser::LOOP - 64))
      | (1ULL << (VisualBasic6Parser::LEN - 64))
      | (1ULL << (VisualBasic6Parser::LET - 64))
      | (1ULL << (VisualBasic6Parser::LIB - 64))
      | (1ULL << (VisualBasic6Parser::LIKE - 64))
      | (1ULL << (VisualBasic6Parser::LINE_INPUT - 64))
      | (1ULL << (VisualBasic6Parser::LSET - 64))
      | (1ULL << (VisualBasic6Parser::MACRO_IF - 64))
      | (1ULL << (VisualBasic6Parser::ME - 64))
      | (1ULL << (VisualBasic6Parser::MID - 64))
      | (1ULL << (VisualBasic6Parser::MKDIR - 64))
      | (1ULL << (VisualBasic6Parser::MOD - 64))
      | (1ULL << (VisualBasic6Parser::NAME - 64))
      | (1ULL << (VisualBasic6Parser::NEXT - 64))
      | (1ULL << (VisualBasic6Parser::NEW - 64))
      | (1ULL << (VisualBasic6Parser::NOT - 64))
      | (1ULL << (VisualBasic6Parser::NOTHING - 64))
      | (1ULL << (VisualBasic6Parser::NULL1 - 64))
      | (1ULL << (VisualBasic6Parser::OBJECT - 64))
      | (1ULL << (VisualBasic6Parser::ON - 64))
      | (1ULL << (VisualBasic6Parser::ON_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::ON_LOCAL_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::OPEN - 64))
      | (1ULL << (VisualBasic6Parser::OPTIONAL - 64))
      | (1ULL << (VisualBasic6Parser::OR - 64))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 64))
      | (1ULL << (VisualBasic6Parser::PARAMARRAY - 64))
      | (1ULL << (VisualBasic6Parser::PRESERVE - 64))
      | (1ULL << (VisualBasic6Parser::PRINT - 64))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 64)))) != 0) || ((((_la - 129) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 129)) & ((1ULL << (VisualBasic6Parser::PUBLIC - 129))
      | (1ULL << (VisualBasic6Parser::PUT - 129))
      | (1ULL << (VisualBasic6Parser::RANDOM - 129))
      | (1ULL << (VisualBasic6Parser::RANDOMIZE - 129))
      | (1ULL << (VisualBasic6Parser::RAISEEVENT - 129))
      | (1ULL << (VisualBasic6Parser::READ - 129))
      | (1ULL << (VisualBasic6Parser::REDIM - 129))
      | (1ULL << (VisualBasic6Parser::REM - 129))
      | (1ULL << (VisualBasic6Parser::RESET - 129))
      | (1ULL << (VisualBasic6Parser::RESUME - 129))
      | (1ULL << (VisualBasic6Parser::RETURN - 129))
      | (1ULL << (VisualBasic6Parser::RMDIR - 129))
      | (1ULL << (VisualBasic6Parser::RSET - 129))
      | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 129))
      | (1ULL << (VisualBasic6Parser::SAVESETTING - 129))
      | (1ULL << (VisualBasic6Parser::SEEK - 129))
      | (1ULL << (VisualBasic6Parser::SELECT - 129))
      | (1ULL << (VisualBasic6Parser::SENDKEYS - 129))
      | (1ULL << (VisualBasic6Parser::SET - 129))
      | (1ULL << (VisualBasic6Parser::SETATTR - 129))
      | (1ULL << (VisualBasic6Parser::SHARED - 129))
      | (1ULL << (VisualBasic6Parser::SINGLE - 129))
      | (1ULL << (VisualBasic6Parser::SPC - 129))
      | (1ULL << (VisualBasic6Parser::STATIC - 129))
      | (1ULL << (VisualBasic6Parser::STEP - 129))
      | (1ULL << (VisualBasic6Parser::STOP - 129))
      | (1ULL << (VisualBasic6Parser::STRING - 129))
      | (1ULL << (VisualBasic6Parser::SUB - 129))
      | (1ULL << (VisualBasic6Parser::TAB - 129))
      | (1ULL << (VisualBasic6Parser::TEXT - 129))
      | (1ULL << (VisualBasic6Parser::THEN - 129))
      | (1ULL << (VisualBasic6Parser::TIME - 129))
      | (1ULL << (VisualBasic6Parser::TO - 129))
      | (1ULL << (VisualBasic6Parser::TRUE1 - 129))
      | (1ULL << (VisualBasic6Parser::TYPE - 129))
      | (1ULL << (VisualBasic6Parser::TYPEOF - 129))
      | (1ULL << (VisualBasic6Parser::UNLOAD - 129))
      | (1ULL << (VisualBasic6Parser::UNLOCK - 129))
      | (1ULL << (VisualBasic6Parser::UNTIL - 129))
      | (1ULL << (VisualBasic6Parser::VARIANT - 129))
      | (1ULL << (VisualBasic6Parser::VERSION - 129))
      | (1ULL << (VisualBasic6Parser::WEND - 129))
      | (1ULL << (VisualBasic6Parser::WHILE - 129))
      | (1ULL << (VisualBasic6Parser::WIDTH - 129))
      | (1ULL << (VisualBasic6Parser::WITH - 129))
      | (1ULL << (VisualBasic6Parser::WITHEVENTS - 129))
      | (1ULL << (VisualBasic6Parser::WRITE - 129))
      | (1ULL << (VisualBasic6Parser::XOR - 129))
      | (1ULL << (VisualBasic6Parser::DOT - 129))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 129)))) != 0) || ((((_la - 206) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 206)) & ((1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 206))
      | (1ULL << (VisualBasic6Parser::IDENTIFIER - 206))
      | (1ULL << (VisualBasic6Parser::WS - 206)))) != 0)) {
      setState(1634);
      block();
      setState(1636); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(1635);
        match(VisualBasic6Parser::NEWLINE);
        setState(1638); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
    }
    setState(1642);
    match(VisualBasic6Parser::END_PROPERTY);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- PropertySetStmtContext ------------------------------------------------------------------

VisualBasic6Parser::PropertySetStmtContext::PropertySetStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::PropertySetStmtContext::PROPERTY_SET() {
  return getToken(VisualBasic6Parser::PROPERTY_SET, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::PropertySetStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::PropertySetStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::PropertySetStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::PropertySetStmtContext::END_PROPERTY() {
  return getToken(VisualBasic6Parser::END_PROPERTY, 0);
}

VisualBasic6Parser::VisibilityContext* VisualBasic6Parser::PropertySetStmtContext::visibility() {
  return getRuleContext<VisualBasic6Parser::VisibilityContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::PropertySetStmtContext::STATIC() {
  return getToken(VisualBasic6Parser::STATIC, 0);
}

VisualBasic6Parser::ArgListContext* VisualBasic6Parser::PropertySetStmtContext::argList() {
  return getRuleContext<VisualBasic6Parser::ArgListContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::PropertySetStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::PropertySetStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::PropertySetStmtContext::block() {
  return getRuleContext<VisualBasic6Parser::BlockContext>(0);
}


size_t VisualBasic6Parser::PropertySetStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RulePropertySetStmt;
}

antlrcpp::Any VisualBasic6Parser::PropertySetStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitPropertySetStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::PropertySetStmtContext* VisualBasic6Parser::propertySetStmt() {
  PropertySetStmtContext *_localctx = _tracker.createInstance<PropertySetStmtContext>(_ctx, getState());
  enterRule(_localctx, 160, VisualBasic6Parser::RulePropertySetStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1647);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 68) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 68)) & ((1ULL << (VisualBasic6Parser::FRIEND - 68))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 68))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 68))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 68)))) != 0)) {
      setState(1644);
      visibility();
      setState(1645);
      match(VisualBasic6Parser::WS);
    }
    setState(1651);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::STATIC) {
      setState(1649);
      match(VisualBasic6Parser::STATIC);
      setState(1650);
      match(VisualBasic6Parser::WS);
    }
    setState(1653);
    match(VisualBasic6Parser::PROPERTY_SET);
    setState(1654);
    match(VisualBasic6Parser::WS);
    setState(1655);
    ambiguousIdentifier();
    setState(1660);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::LPAREN

    || _la == VisualBasic6Parser::WS) {
      setState(1657);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(1656);
        match(VisualBasic6Parser::WS);
      }
      setState(1659);
      argList();
    }
    setState(1663); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(1662);
      match(VisualBasic6Parser::NEWLINE);
      setState(1665); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(1673);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
      | (1ULL << VisualBasic6Parser::ADDRESSOF)
      | (1ULL << VisualBasic6Parser::ALIAS)
      | (1ULL << VisualBasic6Parser::AND)
      | (1ULL << VisualBasic6Parser::ATTRIBUTE)
      | (1ULL << VisualBasic6Parser::APPACTIVATE)
      | (1ULL << VisualBasic6Parser::APPEND)
      | (1ULL << VisualBasic6Parser::AS)
      | (1ULL << VisualBasic6Parser::BEEP)
      | (1ULL << VisualBasic6Parser::BEGIN)
      | (1ULL << VisualBasic6Parser::BINARY)
      | (1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYVAL)
      | (1ULL << VisualBasic6Parser::BYREF)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::CALL)
      | (1ULL << VisualBasic6Parser::CASE)
      | (1ULL << VisualBasic6Parser::CHDIR)
      | (1ULL << VisualBasic6Parser::CHDRIVE)
      | (1ULL << VisualBasic6Parser::CLASS)
      | (1ULL << VisualBasic6Parser::CLOSE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::CONST)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DECLARE)
      | (1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR)
      | (1ULL << VisualBasic6Parser::DELETESETTING)
      | (1ULL << VisualBasic6Parser::DIM)
      | (1ULL << VisualBasic6Parser::DO)
      | (1ULL << VisualBasic6Parser::DOUBLE)
      | (1ULL << VisualBasic6Parser::EACH)
      | (1ULL << VisualBasic6Parser::ELSE)
      | (1ULL << VisualBasic6Parser::ELSEIF)
      | (1ULL << VisualBasic6Parser::END)
      | (1ULL << VisualBasic6Parser::ENUM)
      | (1ULL << VisualBasic6Parser::EQV)
      | (1ULL << VisualBasic6Parser::ERASE)
      | (1ULL << VisualBasic6Parser::ERROR)
      | (1ULL << VisualBasic6Parser::EVENT)
      | (1ULL << VisualBasic6Parser::EXIT_DO)
      | (1ULL << VisualBasic6Parser::EXIT_FOR)
      | (1ULL << VisualBasic6Parser::EXIT_FUNCTION))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (VisualBasic6Parser::EXIT_PROPERTY - 64))
      | (1ULL << (VisualBasic6Parser::EXIT_SUB - 64))
      | (1ULL << (VisualBasic6Parser::FALSE1 - 64))
      | (1ULL << (VisualBasic6Parser::FILECOPY - 64))
      | (1ULL << (VisualBasic6Parser::FRIEND - 64))
      | (1ULL << (VisualBasic6Parser::FOR - 64))
      | (1ULL << (VisualBasic6Parser::FUNCTION - 64))
      | (1ULL << (VisualBasic6Parser::GET - 64))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 64))
      | (1ULL << (VisualBasic6Parser::GOSUB - 64))
      | (1ULL << (VisualBasic6Parser::GOTO - 64))
      | (1ULL << (VisualBasic6Parser::IF - 64))
      | (1ULL << (VisualBasic6Parser::IMP - 64))
      | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 64))
      | (1ULL << (VisualBasic6Parser::IN - 64))
      | (1ULL << (VisualBasic6Parser::INPUT - 64))
      | (1ULL << (VisualBasic6Parser::IS - 64))
      | (1ULL << (VisualBasic6Parser::INTEGER - 64))
      | (1ULL << (VisualBasic6Parser::KILL - 64))
      | (1ULL << (VisualBasic6Parser::LOAD - 64))
      | (1ULL << (VisualBasic6Parser::LOCK - 64))
      | (1ULL << (VisualBasic6Parser::LONG - 64))
      | (1ULL << (VisualBasic6Parser::LOOP - 64))
      | (1ULL << (VisualBasic6Parser::LEN - 64))
      | (1ULL << (VisualBasic6Parser::LET - 64))
      | (1ULL << (VisualBasic6Parser::LIB - 64))
      | (1ULL << (VisualBasic6Parser::LIKE - 64))
      | (1ULL << (VisualBasic6Parser::LINE_INPUT - 64))
      | (1ULL << (VisualBasic6Parser::LSET - 64))
      | (1ULL << (VisualBasic6Parser::MACRO_IF - 64))
      | (1ULL << (VisualBasic6Parser::ME - 64))
      | (1ULL << (VisualBasic6Parser::MID - 64))
      | (1ULL << (VisualBasic6Parser::MKDIR - 64))
      | (1ULL << (VisualBasic6Parser::MOD - 64))
      | (1ULL << (VisualBasic6Parser::NAME - 64))
      | (1ULL << (VisualBasic6Parser::NEXT - 64))
      | (1ULL << (VisualBasic6Parser::NEW - 64))
      | (1ULL << (VisualBasic6Parser::NOT - 64))
      | (1ULL << (VisualBasic6Parser::NOTHING - 64))
      | (1ULL << (VisualBasic6Parser::NULL1 - 64))
      | (1ULL << (VisualBasic6Parser::OBJECT - 64))
      | (1ULL << (VisualBasic6Parser::ON - 64))
      | (1ULL << (VisualBasic6Parser::ON_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::ON_LOCAL_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::OPEN - 64))
      | (1ULL << (VisualBasic6Parser::OPTIONAL - 64))
      | (1ULL << (VisualBasic6Parser::OR - 64))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 64))
      | (1ULL << (VisualBasic6Parser::PARAMARRAY - 64))
      | (1ULL << (VisualBasic6Parser::PRESERVE - 64))
      | (1ULL << (VisualBasic6Parser::PRINT - 64))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 64)))) != 0) || ((((_la - 129) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 129)) & ((1ULL << (VisualBasic6Parser::PUBLIC - 129))
      | (1ULL << (VisualBasic6Parser::PUT - 129))
      | (1ULL << (VisualBasic6Parser::RANDOM - 129))
      | (1ULL << (VisualBasic6Parser::RANDOMIZE - 129))
      | (1ULL << (VisualBasic6Parser::RAISEEVENT - 129))
      | (1ULL << (VisualBasic6Parser::READ - 129))
      | (1ULL << (VisualBasic6Parser::REDIM - 129))
      | (1ULL << (VisualBasic6Parser::REM - 129))
      | (1ULL << (VisualBasic6Parser::RESET - 129))
      | (1ULL << (VisualBasic6Parser::RESUME - 129))
      | (1ULL << (VisualBasic6Parser::RETURN - 129))
      | (1ULL << (VisualBasic6Parser::RMDIR - 129))
      | (1ULL << (VisualBasic6Parser::RSET - 129))
      | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 129))
      | (1ULL << (VisualBasic6Parser::SAVESETTING - 129))
      | (1ULL << (VisualBasic6Parser::SEEK - 129))
      | (1ULL << (VisualBasic6Parser::SELECT - 129))
      | (1ULL << (VisualBasic6Parser::SENDKEYS - 129))
      | (1ULL << (VisualBasic6Parser::SET - 129))
      | (1ULL << (VisualBasic6Parser::SETATTR - 129))
      | (1ULL << (VisualBasic6Parser::SHARED - 129))
      | (1ULL << (VisualBasic6Parser::SINGLE - 129))
      | (1ULL << (VisualBasic6Parser::SPC - 129))
      | (1ULL << (VisualBasic6Parser::STATIC - 129))
      | (1ULL << (VisualBasic6Parser::STEP - 129))
      | (1ULL << (VisualBasic6Parser::STOP - 129))
      | (1ULL << (VisualBasic6Parser::STRING - 129))
      | (1ULL << (VisualBasic6Parser::SUB - 129))
      | (1ULL << (VisualBasic6Parser::TAB - 129))
      | (1ULL << (VisualBasic6Parser::TEXT - 129))
      | (1ULL << (VisualBasic6Parser::THEN - 129))
      | (1ULL << (VisualBasic6Parser::TIME - 129))
      | (1ULL << (VisualBasic6Parser::TO - 129))
      | (1ULL << (VisualBasic6Parser::TRUE1 - 129))
      | (1ULL << (VisualBasic6Parser::TYPE - 129))
      | (1ULL << (VisualBasic6Parser::TYPEOF - 129))
      | (1ULL << (VisualBasic6Parser::UNLOAD - 129))
      | (1ULL << (VisualBasic6Parser::UNLOCK - 129))
      | (1ULL << (VisualBasic6Parser::UNTIL - 129))
      | (1ULL << (VisualBasic6Parser::VARIANT - 129))
      | (1ULL << (VisualBasic6Parser::VERSION - 129))
      | (1ULL << (VisualBasic6Parser::WEND - 129))
      | (1ULL << (VisualBasic6Parser::WHILE - 129))
      | (1ULL << (VisualBasic6Parser::WIDTH - 129))
      | (1ULL << (VisualBasic6Parser::WITH - 129))
      | (1ULL << (VisualBasic6Parser::WITHEVENTS - 129))
      | (1ULL << (VisualBasic6Parser::WRITE - 129))
      | (1ULL << (VisualBasic6Parser::XOR - 129))
      | (1ULL << (VisualBasic6Parser::DOT - 129))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 129)))) != 0) || ((((_la - 206) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 206)) & ((1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 206))
      | (1ULL << (VisualBasic6Parser::IDENTIFIER - 206))
      | (1ULL << (VisualBasic6Parser::WS - 206)))) != 0)) {
      setState(1667);
      block();
      setState(1669); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(1668);
        match(VisualBasic6Parser::NEWLINE);
        setState(1671); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
    }
    setState(1675);
    match(VisualBasic6Parser::END_PROPERTY);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- PropertyLetStmtContext ------------------------------------------------------------------

VisualBasic6Parser::PropertyLetStmtContext::PropertyLetStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::PropertyLetStmtContext::PROPERTY_LET() {
  return getToken(VisualBasic6Parser::PROPERTY_LET, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::PropertyLetStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::PropertyLetStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::PropertyLetStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::PropertyLetStmtContext::END_PROPERTY() {
  return getToken(VisualBasic6Parser::END_PROPERTY, 0);
}

VisualBasic6Parser::VisibilityContext* VisualBasic6Parser::PropertyLetStmtContext::visibility() {
  return getRuleContext<VisualBasic6Parser::VisibilityContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::PropertyLetStmtContext::STATIC() {
  return getToken(VisualBasic6Parser::STATIC, 0);
}

VisualBasic6Parser::ArgListContext* VisualBasic6Parser::PropertyLetStmtContext::argList() {
  return getRuleContext<VisualBasic6Parser::ArgListContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::PropertyLetStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::PropertyLetStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::PropertyLetStmtContext::block() {
  return getRuleContext<VisualBasic6Parser::BlockContext>(0);
}


size_t VisualBasic6Parser::PropertyLetStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RulePropertyLetStmt;
}

antlrcpp::Any VisualBasic6Parser::PropertyLetStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitPropertyLetStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::PropertyLetStmtContext* VisualBasic6Parser::propertyLetStmt() {
  PropertyLetStmtContext *_localctx = _tracker.createInstance<PropertyLetStmtContext>(_ctx, getState());
  enterRule(_localctx, 162, VisualBasic6Parser::RulePropertyLetStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1680);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 68) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 68)) & ((1ULL << (VisualBasic6Parser::FRIEND - 68))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 68))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 68))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 68)))) != 0)) {
      setState(1677);
      visibility();
      setState(1678);
      match(VisualBasic6Parser::WS);
    }
    setState(1684);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::STATIC) {
      setState(1682);
      match(VisualBasic6Parser::STATIC);
      setState(1683);
      match(VisualBasic6Parser::WS);
    }
    setState(1686);
    match(VisualBasic6Parser::PROPERTY_LET);
    setState(1687);
    match(VisualBasic6Parser::WS);
    setState(1688);
    ambiguousIdentifier();
    setState(1693);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::LPAREN

    || _la == VisualBasic6Parser::WS) {
      setState(1690);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(1689);
        match(VisualBasic6Parser::WS);
      }
      setState(1692);
      argList();
    }
    setState(1696); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(1695);
      match(VisualBasic6Parser::NEWLINE);
      setState(1698); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(1706);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
      | (1ULL << VisualBasic6Parser::ADDRESSOF)
      | (1ULL << VisualBasic6Parser::ALIAS)
      | (1ULL << VisualBasic6Parser::AND)
      | (1ULL << VisualBasic6Parser::ATTRIBUTE)
      | (1ULL << VisualBasic6Parser::APPACTIVATE)
      | (1ULL << VisualBasic6Parser::APPEND)
      | (1ULL << VisualBasic6Parser::AS)
      | (1ULL << VisualBasic6Parser::BEEP)
      | (1ULL << VisualBasic6Parser::BEGIN)
      | (1ULL << VisualBasic6Parser::BINARY)
      | (1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYVAL)
      | (1ULL << VisualBasic6Parser::BYREF)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::CALL)
      | (1ULL << VisualBasic6Parser::CASE)
      | (1ULL << VisualBasic6Parser::CHDIR)
      | (1ULL << VisualBasic6Parser::CHDRIVE)
      | (1ULL << VisualBasic6Parser::CLASS)
      | (1ULL << VisualBasic6Parser::CLOSE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::CONST)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DECLARE)
      | (1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR)
      | (1ULL << VisualBasic6Parser::DELETESETTING)
      | (1ULL << VisualBasic6Parser::DIM)
      | (1ULL << VisualBasic6Parser::DO)
      | (1ULL << VisualBasic6Parser::DOUBLE)
      | (1ULL << VisualBasic6Parser::EACH)
      | (1ULL << VisualBasic6Parser::ELSE)
      | (1ULL << VisualBasic6Parser::ELSEIF)
      | (1ULL << VisualBasic6Parser::END)
      | (1ULL << VisualBasic6Parser::ENUM)
      | (1ULL << VisualBasic6Parser::EQV)
      | (1ULL << VisualBasic6Parser::ERASE)
      | (1ULL << VisualBasic6Parser::ERROR)
      | (1ULL << VisualBasic6Parser::EVENT)
      | (1ULL << VisualBasic6Parser::EXIT_DO)
      | (1ULL << VisualBasic6Parser::EXIT_FOR)
      | (1ULL << VisualBasic6Parser::EXIT_FUNCTION))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (VisualBasic6Parser::EXIT_PROPERTY - 64))
      | (1ULL << (VisualBasic6Parser::EXIT_SUB - 64))
      | (1ULL << (VisualBasic6Parser::FALSE1 - 64))
      | (1ULL << (VisualBasic6Parser::FILECOPY - 64))
      | (1ULL << (VisualBasic6Parser::FRIEND - 64))
      | (1ULL << (VisualBasic6Parser::FOR - 64))
      | (1ULL << (VisualBasic6Parser::FUNCTION - 64))
      | (1ULL << (VisualBasic6Parser::GET - 64))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 64))
      | (1ULL << (VisualBasic6Parser::GOSUB - 64))
      | (1ULL << (VisualBasic6Parser::GOTO - 64))
      | (1ULL << (VisualBasic6Parser::IF - 64))
      | (1ULL << (VisualBasic6Parser::IMP - 64))
      | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 64))
      | (1ULL << (VisualBasic6Parser::IN - 64))
      | (1ULL << (VisualBasic6Parser::INPUT - 64))
      | (1ULL << (VisualBasic6Parser::IS - 64))
      | (1ULL << (VisualBasic6Parser::INTEGER - 64))
      | (1ULL << (VisualBasic6Parser::KILL - 64))
      | (1ULL << (VisualBasic6Parser::LOAD - 64))
      | (1ULL << (VisualBasic6Parser::LOCK - 64))
      | (1ULL << (VisualBasic6Parser::LONG - 64))
      | (1ULL << (VisualBasic6Parser::LOOP - 64))
      | (1ULL << (VisualBasic6Parser::LEN - 64))
      | (1ULL << (VisualBasic6Parser::LET - 64))
      | (1ULL << (VisualBasic6Parser::LIB - 64))
      | (1ULL << (VisualBasic6Parser::LIKE - 64))
      | (1ULL << (VisualBasic6Parser::LINE_INPUT - 64))
      | (1ULL << (VisualBasic6Parser::LSET - 64))
      | (1ULL << (VisualBasic6Parser::MACRO_IF - 64))
      | (1ULL << (VisualBasic6Parser::ME - 64))
      | (1ULL << (VisualBasic6Parser::MID - 64))
      | (1ULL << (VisualBasic6Parser::MKDIR - 64))
      | (1ULL << (VisualBasic6Parser::MOD - 64))
      | (1ULL << (VisualBasic6Parser::NAME - 64))
      | (1ULL << (VisualBasic6Parser::NEXT - 64))
      | (1ULL << (VisualBasic6Parser::NEW - 64))
      | (1ULL << (VisualBasic6Parser::NOT - 64))
      | (1ULL << (VisualBasic6Parser::NOTHING - 64))
      | (1ULL << (VisualBasic6Parser::NULL1 - 64))
      | (1ULL << (VisualBasic6Parser::OBJECT - 64))
      | (1ULL << (VisualBasic6Parser::ON - 64))
      | (1ULL << (VisualBasic6Parser::ON_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::ON_LOCAL_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::OPEN - 64))
      | (1ULL << (VisualBasic6Parser::OPTIONAL - 64))
      | (1ULL << (VisualBasic6Parser::OR - 64))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 64))
      | (1ULL << (VisualBasic6Parser::PARAMARRAY - 64))
      | (1ULL << (VisualBasic6Parser::PRESERVE - 64))
      | (1ULL << (VisualBasic6Parser::PRINT - 64))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 64)))) != 0) || ((((_la - 129) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 129)) & ((1ULL << (VisualBasic6Parser::PUBLIC - 129))
      | (1ULL << (VisualBasic6Parser::PUT - 129))
      | (1ULL << (VisualBasic6Parser::RANDOM - 129))
      | (1ULL << (VisualBasic6Parser::RANDOMIZE - 129))
      | (1ULL << (VisualBasic6Parser::RAISEEVENT - 129))
      | (1ULL << (VisualBasic6Parser::READ - 129))
      | (1ULL << (VisualBasic6Parser::REDIM - 129))
      | (1ULL << (VisualBasic6Parser::REM - 129))
      | (1ULL << (VisualBasic6Parser::RESET - 129))
      | (1ULL << (VisualBasic6Parser::RESUME - 129))
      | (1ULL << (VisualBasic6Parser::RETURN - 129))
      | (1ULL << (VisualBasic6Parser::RMDIR - 129))
      | (1ULL << (VisualBasic6Parser::RSET - 129))
      | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 129))
      | (1ULL << (VisualBasic6Parser::SAVESETTING - 129))
      | (1ULL << (VisualBasic6Parser::SEEK - 129))
      | (1ULL << (VisualBasic6Parser::SELECT - 129))
      | (1ULL << (VisualBasic6Parser::SENDKEYS - 129))
      | (1ULL << (VisualBasic6Parser::SET - 129))
      | (1ULL << (VisualBasic6Parser::SETATTR - 129))
      | (1ULL << (VisualBasic6Parser::SHARED - 129))
      | (1ULL << (VisualBasic6Parser::SINGLE - 129))
      | (1ULL << (VisualBasic6Parser::SPC - 129))
      | (1ULL << (VisualBasic6Parser::STATIC - 129))
      | (1ULL << (VisualBasic6Parser::STEP - 129))
      | (1ULL << (VisualBasic6Parser::STOP - 129))
      | (1ULL << (VisualBasic6Parser::STRING - 129))
      | (1ULL << (VisualBasic6Parser::SUB - 129))
      | (1ULL << (VisualBasic6Parser::TAB - 129))
      | (1ULL << (VisualBasic6Parser::TEXT - 129))
      | (1ULL << (VisualBasic6Parser::THEN - 129))
      | (1ULL << (VisualBasic6Parser::TIME - 129))
      | (1ULL << (VisualBasic6Parser::TO - 129))
      | (1ULL << (VisualBasic6Parser::TRUE1 - 129))
      | (1ULL << (VisualBasic6Parser::TYPE - 129))
      | (1ULL << (VisualBasic6Parser::TYPEOF - 129))
      | (1ULL << (VisualBasic6Parser::UNLOAD - 129))
      | (1ULL << (VisualBasic6Parser::UNLOCK - 129))
      | (1ULL << (VisualBasic6Parser::UNTIL - 129))
      | (1ULL << (VisualBasic6Parser::VARIANT - 129))
      | (1ULL << (VisualBasic6Parser::VERSION - 129))
      | (1ULL << (VisualBasic6Parser::WEND - 129))
      | (1ULL << (VisualBasic6Parser::WHILE - 129))
      | (1ULL << (VisualBasic6Parser::WIDTH - 129))
      | (1ULL << (VisualBasic6Parser::WITH - 129))
      | (1ULL << (VisualBasic6Parser::WITHEVENTS - 129))
      | (1ULL << (VisualBasic6Parser::WRITE - 129))
      | (1ULL << (VisualBasic6Parser::XOR - 129))
      | (1ULL << (VisualBasic6Parser::DOT - 129))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 129)))) != 0) || ((((_la - 206) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 206)) & ((1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 206))
      | (1ULL << (VisualBasic6Parser::IDENTIFIER - 206))
      | (1ULL << (VisualBasic6Parser::WS - 206)))) != 0)) {
      setState(1700);
      block();
      setState(1702); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(1701);
        match(VisualBasic6Parser::NEWLINE);
        setState(1704); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
    }
    setState(1708);
    match(VisualBasic6Parser::END_PROPERTY);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- PutStmtContext ------------------------------------------------------------------

VisualBasic6Parser::PutStmtContext::PutStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::PutStmtContext::PUT() {
  return getToken(VisualBasic6Parser::PUT, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::PutStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::PutStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::PutStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::PutStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::PutStmtContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::PutStmtContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}


size_t VisualBasic6Parser::PutStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RulePutStmt;
}

antlrcpp::Any VisualBasic6Parser::PutStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitPutStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::PutStmtContext* VisualBasic6Parser::putStmt() {
  PutStmtContext *_localctx = _tracker.createInstance<PutStmtContext>(_ctx, getState());
  enterRule(_localctx, 164, VisualBasic6Parser::RulePutStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1710);
    match(VisualBasic6Parser::PUT);
    setState(1711);
    match(VisualBasic6Parser::WS);
    setState(1712);
    valueStmt(0);
    setState(1714);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1713);
      match(VisualBasic6Parser::WS);
    }
    setState(1716);
    match(VisualBasic6Parser::COMMA);
    setState(1718);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 251, _ctx)) {
    case 1: {
      setState(1717);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1721);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 252, _ctx)) {
    case 1: {
      setState(1720);
      valueStmt(0);
      break;
    }

    }
    setState(1724);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1723);
      match(VisualBasic6Parser::WS);
    }
    setState(1726);
    match(VisualBasic6Parser::COMMA);
    setState(1728);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 254, _ctx)) {
    case 1: {
      setState(1727);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1730);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- RaiseEventStmtContext ------------------------------------------------------------------

VisualBasic6Parser::RaiseEventStmtContext::RaiseEventStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::RaiseEventStmtContext::RAISEEVENT() {
  return getToken(VisualBasic6Parser::RAISEEVENT, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::RaiseEventStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::RaiseEventStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::RaiseEventStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::RaiseEventStmtContext::LPAREN() {
  return getToken(VisualBasic6Parser::LPAREN, 0);
}

tree::TerminalNode* VisualBasic6Parser::RaiseEventStmtContext::RPAREN() {
  return getToken(VisualBasic6Parser::RPAREN, 0);
}

VisualBasic6Parser::ArgsCallContext* VisualBasic6Parser::RaiseEventStmtContext::argsCall() {
  return getRuleContext<VisualBasic6Parser::ArgsCallContext>(0);
}


size_t VisualBasic6Parser::RaiseEventStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleRaiseEventStmt;
}

antlrcpp::Any VisualBasic6Parser::RaiseEventStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitRaiseEventStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::RaiseEventStmtContext* VisualBasic6Parser::raiseEventStmt() {
  RaiseEventStmtContext *_localctx = _tracker.createInstance<RaiseEventStmtContext>(_ctx, getState());
  enterRule(_localctx, 166, VisualBasic6Parser::RuleRaiseEventStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1732);
    match(VisualBasic6Parser::RAISEEVENT);
    setState(1733);
    match(VisualBasic6Parser::WS);
    setState(1734);
    ambiguousIdentifier();
    setState(1749);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 259, _ctx)) {
    case 1: {
      setState(1736);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(1735);
        match(VisualBasic6Parser::WS);
      }
      setState(1738);
      match(VisualBasic6Parser::LPAREN);
      setState(1740);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 256, _ctx)) {
      case 1: {
        setState(1739);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(1746);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
        | (1ULL << VisualBasic6Parser::ADDRESSOF)
        | (1ULL << VisualBasic6Parser::ALIAS)
        | (1ULL << VisualBasic6Parser::AND)
        | (1ULL << VisualBasic6Parser::ATTRIBUTE)
        | (1ULL << VisualBasic6Parser::APPACTIVATE)
        | (1ULL << VisualBasic6Parser::APPEND)
        | (1ULL << VisualBasic6Parser::AS)
        | (1ULL << VisualBasic6Parser::BEEP)
        | (1ULL << VisualBasic6Parser::BEGIN)
        | (1ULL << VisualBasic6Parser::BINARY)
        | (1ULL << VisualBasic6Parser::BOOLEAN)
        | (1ULL << VisualBasic6Parser::BYVAL)
        | (1ULL << VisualBasic6Parser::BYREF)
        | (1ULL << VisualBasic6Parser::BYTE)
        | (1ULL << VisualBasic6Parser::CALL)
        | (1ULL << VisualBasic6Parser::CASE)
        | (1ULL << VisualBasic6Parser::CHDIR)
        | (1ULL << VisualBasic6Parser::CHDRIVE)
        | (1ULL << VisualBasic6Parser::CLASS)
        | (1ULL << VisualBasic6Parser::CLOSE)
        | (1ULL << VisualBasic6Parser::COLLECTION)
        | (1ULL << VisualBasic6Parser::CONST)
        | (1ULL << VisualBasic6Parser::DATE)
        | (1ULL << VisualBasic6Parser::DECLARE)
        | (1ULL << VisualBasic6Parser::DEFBOOL)
        | (1ULL << VisualBasic6Parser::DEFBYTE)
        | (1ULL << VisualBasic6Parser::DEFDATE)
        | (1ULL << VisualBasic6Parser::DEFDBL)
        | (1ULL << VisualBasic6Parser::DEFDEC)
        | (1ULL << VisualBasic6Parser::DEFCUR)
        | (1ULL << VisualBasic6Parser::DEFINT)
        | (1ULL << VisualBasic6Parser::DEFLNG)
        | (1ULL << VisualBasic6Parser::DEFOBJ)
        | (1ULL << VisualBasic6Parser::DEFSNG)
        | (1ULL << VisualBasic6Parser::DEFSTR)
        | (1ULL << VisualBasic6Parser::DEFVAR)
        | (1ULL << VisualBasic6Parser::DELETESETTING)
        | (1ULL << VisualBasic6Parser::DIM)
        | (1ULL << VisualBasic6Parser::DO)
        | (1ULL << VisualBasic6Parser::DOUBLE)
        | (1ULL << VisualBasic6Parser::EACH)
        | (1ULL << VisualBasic6Parser::ELSE)
        | (1ULL << VisualBasic6Parser::ELSEIF)
        | (1ULL << VisualBasic6Parser::END)
        | (1ULL << VisualBasic6Parser::ENUM)
        | (1ULL << VisualBasic6Parser::EQV)
        | (1ULL << VisualBasic6Parser::ERASE)
        | (1ULL << VisualBasic6Parser::ERROR)
        | (1ULL << VisualBasic6Parser::EVENT))) != 0) || ((((_la - 66) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 66)) & ((1ULL << (VisualBasic6Parser::FALSE1 - 66))
        | (1ULL << (VisualBasic6Parser::FILECOPY - 66))
        | (1ULL << (VisualBasic6Parser::FRIEND - 66))
        | (1ULL << (VisualBasic6Parser::FOR - 66))
        | (1ULL << (VisualBasic6Parser::FUNCTION - 66))
        | (1ULL << (VisualBasic6Parser::GET - 66))
        | (1ULL << (VisualBasic6Parser::GLOBAL - 66))
        | (1ULL << (VisualBasic6Parser::GOSUB - 66))
        | (1ULL << (VisualBasic6Parser::GOTO - 66))
        | (1ULL << (VisualBasic6Parser::IF - 66))
        | (1ULL << (VisualBasic6Parser::IMP - 66))
        | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 66))
        | (1ULL << (VisualBasic6Parser::IN - 66))
        | (1ULL << (VisualBasic6Parser::INPUT - 66))
        | (1ULL << (VisualBasic6Parser::IS - 66))
        | (1ULL << (VisualBasic6Parser::INTEGER - 66))
        | (1ULL << (VisualBasic6Parser::KILL - 66))
        | (1ULL << (VisualBasic6Parser::LOAD - 66))
        | (1ULL << (VisualBasic6Parser::LOCK - 66))
        | (1ULL << (VisualBasic6Parser::LONG - 66))
        | (1ULL << (VisualBasic6Parser::LOOP - 66))
        | (1ULL << (VisualBasic6Parser::LEN - 66))
        | (1ULL << (VisualBasic6Parser::LET - 66))
        | (1ULL << (VisualBasic6Parser::LIB - 66))
        | (1ULL << (VisualBasic6Parser::LIKE - 66))
        | (1ULL << (VisualBasic6Parser::LSET - 66))
        | (1ULL << (VisualBasic6Parser::ME - 66))
        | (1ULL << (VisualBasic6Parser::MID - 66))
        | (1ULL << (VisualBasic6Parser::MKDIR - 66))
        | (1ULL << (VisualBasic6Parser::MOD - 66))
        | (1ULL << (VisualBasic6Parser::NAME - 66))
        | (1ULL << (VisualBasic6Parser::NEXT - 66))
        | (1ULL << (VisualBasic6Parser::NEW - 66))
        | (1ULL << (VisualBasic6Parser::NOT - 66))
        | (1ULL << (VisualBasic6Parser::NOTHING - 66))
        | (1ULL << (VisualBasic6Parser::NULL1 - 66))
        | (1ULL << (VisualBasic6Parser::OBJECT - 66))
        | (1ULL << (VisualBasic6Parser::ON - 66))
        | (1ULL << (VisualBasic6Parser::OPEN - 66))
        | (1ULL << (VisualBasic6Parser::OPTIONAL - 66))
        | (1ULL << (VisualBasic6Parser::OR - 66))
        | (1ULL << (VisualBasic6Parser::OUTPUT - 66))
        | (1ULL << (VisualBasic6Parser::PARAMARRAY - 66))
        | (1ULL << (VisualBasic6Parser::PRESERVE - 66))
        | (1ULL << (VisualBasic6Parser::PRINT - 66))
        | (1ULL << (VisualBasic6Parser::PRIVATE - 66))
        | (1ULL << (VisualBasic6Parser::PUBLIC - 66)))) != 0) || ((((_la - 130) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 130)) & ((1ULL << (VisualBasic6Parser::PUT - 130))
        | (1ULL << (VisualBasic6Parser::RANDOM - 130))
        | (1ULL << (VisualBasic6Parser::RANDOMIZE - 130))
        | (1ULL << (VisualBasic6Parser::RAISEEVENT - 130))
        | (1ULL << (VisualBasic6Parser::READ - 130))
        | (1ULL << (VisualBasic6Parser::REDIM - 130))
        | (1ULL << (VisualBasic6Parser::REM - 130))
        | (1ULL << (VisualBasic6Parser::RESET - 130))
        | (1ULL << (VisualBasic6Parser::RESUME - 130))
        | (1ULL << (VisualBasic6Parser::RETURN - 130))
        | (1ULL << (VisualBasic6Parser::RMDIR - 130))
        | (1ULL << (VisualBasic6Parser::RSET - 130))
        | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 130))
        | (1ULL << (VisualBasic6Parser::SAVESETTING - 130))
        | (1ULL << (VisualBasic6Parser::SEEK - 130))
        | (1ULL << (VisualBasic6Parser::SELECT - 130))
        | (1ULL << (VisualBasic6Parser::SENDKEYS - 130))
        | (1ULL << (VisualBasic6Parser::SET - 130))
        | (1ULL << (VisualBasic6Parser::SETATTR - 130))
        | (1ULL << (VisualBasic6Parser::SHARED - 130))
        | (1ULL << (VisualBasic6Parser::SINGLE - 130))
        | (1ULL << (VisualBasic6Parser::SPC - 130))
        | (1ULL << (VisualBasic6Parser::STATIC - 130))
        | (1ULL << (VisualBasic6Parser::STEP - 130))
        | (1ULL << (VisualBasic6Parser::STOP - 130))
        | (1ULL << (VisualBasic6Parser::STRING - 130))
        | (1ULL << (VisualBasic6Parser::SUB - 130))
        | (1ULL << (VisualBasic6Parser::TAB - 130))
        | (1ULL << (VisualBasic6Parser::TEXT - 130))
        | (1ULL << (VisualBasic6Parser::THEN - 130))
        | (1ULL << (VisualBasic6Parser::TIME - 130))
        | (1ULL << (VisualBasic6Parser::TO - 130))
        | (1ULL << (VisualBasic6Parser::TRUE1 - 130))
        | (1ULL << (VisualBasic6Parser::TYPE - 130))
        | (1ULL << (VisualBasic6Parser::TYPEOF - 130))
        | (1ULL << (VisualBasic6Parser::UNLOAD - 130))
        | (1ULL << (VisualBasic6Parser::UNLOCK - 130))
        | (1ULL << (VisualBasic6Parser::UNTIL - 130))
        | (1ULL << (VisualBasic6Parser::VARIANT - 130))
        | (1ULL << (VisualBasic6Parser::VERSION - 130))
        | (1ULL << (VisualBasic6Parser::WEND - 130))
        | (1ULL << (VisualBasic6Parser::WHILE - 130))
        | (1ULL << (VisualBasic6Parser::WIDTH - 130))
        | (1ULL << (VisualBasic6Parser::WITH - 130))
        | (1ULL << (VisualBasic6Parser::WITHEVENTS - 130))
        | (1ULL << (VisualBasic6Parser::WRITE - 130))
        | (1ULL << (VisualBasic6Parser::XOR - 130))
        | (1ULL << (VisualBasic6Parser::COMMA - 130))
        | (1ULL << (VisualBasic6Parser::DOT - 130))
        | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 130))
        | (1ULL << (VisualBasic6Parser::LPAREN - 130)))) != 0) || ((((_la - 195) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 195)) & ((1ULL << (VisualBasic6Parser::MINUS - 195))
        | (1ULL << (VisualBasic6Parser::PLUS - 195))
        | (1ULL << (VisualBasic6Parser::SEMICOLON - 195))
        | (1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 195))
        | (1ULL << (VisualBasic6Parser::STRINGLITERAL - 195))
        | (1ULL << (VisualBasic6Parser::DATELITERAL - 195))
        | (1ULL << (VisualBasic6Parser::COLORLITERAL - 195))
        | (1ULL << (VisualBasic6Parser::INTEGERLITERAL - 195))
        | (1ULL << (VisualBasic6Parser::DOUBLELITERAL - 195))
        | (1ULL << (VisualBasic6Parser::FILENUMBER - 195))
        | (1ULL << (VisualBasic6Parser::OCTALLITERAL - 195))
        | (1ULL << (VisualBasic6Parser::IDENTIFIER - 195))
        | (1ULL << (VisualBasic6Parser::WS - 195)))) != 0)) {
        setState(1742);
        argsCall();
        setState(1744);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(1743);
          match(VisualBasic6Parser::WS);
        }
      }
      setState(1748);
      match(VisualBasic6Parser::RPAREN);
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

//----------------- RandomizeStmtContext ------------------------------------------------------------------

VisualBasic6Parser::RandomizeStmtContext::RandomizeStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::RandomizeStmtContext::RANDOMIZE() {
  return getToken(VisualBasic6Parser::RANDOMIZE, 0);
}

tree::TerminalNode* VisualBasic6Parser::RandomizeStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::RandomizeStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::RandomizeStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleRandomizeStmt;
}

antlrcpp::Any VisualBasic6Parser::RandomizeStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitRandomizeStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::RandomizeStmtContext* VisualBasic6Parser::randomizeStmt() {
  RandomizeStmtContext *_localctx = _tracker.createInstance<RandomizeStmtContext>(_ctx, getState());
  enterRule(_localctx, 168, VisualBasic6Parser::RuleRandomizeStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1751);
    match(VisualBasic6Parser::RANDOMIZE);
    setState(1754);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 260, _ctx)) {
    case 1: {
      setState(1752);
      match(VisualBasic6Parser::WS);
      setState(1753);
      valueStmt(0);
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

//----------------- RedimStmtContext ------------------------------------------------------------------

VisualBasic6Parser::RedimStmtContext::RedimStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::RedimStmtContext::REDIM() {
  return getToken(VisualBasic6Parser::REDIM, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::RedimStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::RedimStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::RedimSubStmtContext *> VisualBasic6Parser::RedimStmtContext::redimSubStmt() {
  return getRuleContexts<VisualBasic6Parser::RedimSubStmtContext>();
}

VisualBasic6Parser::RedimSubStmtContext* VisualBasic6Parser::RedimStmtContext::redimSubStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::RedimSubStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::RedimStmtContext::PRESERVE() {
  return getToken(VisualBasic6Parser::PRESERVE, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::RedimStmtContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::RedimStmtContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}


size_t VisualBasic6Parser::RedimStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleRedimStmt;
}

antlrcpp::Any VisualBasic6Parser::RedimStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitRedimStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::RedimStmtContext* VisualBasic6Parser::redimStmt() {
  RedimStmtContext *_localctx = _tracker.createInstance<RedimStmtContext>(_ctx, getState());
  enterRule(_localctx, 170, VisualBasic6Parser::RuleRedimStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(1756);
    match(VisualBasic6Parser::REDIM);
    setState(1757);
    match(VisualBasic6Parser::WS);
    setState(1760);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 261, _ctx)) {
    case 1: {
      setState(1758);
      match(VisualBasic6Parser::PRESERVE);
      setState(1759);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1762);
    redimSubStmt();
    setState(1773);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 264, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(1764);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(1763);
          match(VisualBasic6Parser::WS);
        }
        setState(1766);
        match(VisualBasic6Parser::COMMA);
        setState(1768);
        _errHandler->sync(this);

        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 263, _ctx)) {
        case 1: {
          setState(1767);
          match(VisualBasic6Parser::WS);
          break;
        }

        }
        setState(1770);
        redimSubStmt(); 
      }
      setState(1775);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 264, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- RedimSubStmtContext ------------------------------------------------------------------

VisualBasic6Parser::RedimSubStmtContext::RedimSubStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::ImplicitCallStmt_InStmtContext* VisualBasic6Parser::RedimSubStmtContext::implicitCallStmt_InStmt() {
  return getRuleContext<VisualBasic6Parser::ImplicitCallStmt_InStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::RedimSubStmtContext::LPAREN() {
  return getToken(VisualBasic6Parser::LPAREN, 0);
}

VisualBasic6Parser::SubscriptsContext* VisualBasic6Parser::RedimSubStmtContext::subscripts() {
  return getRuleContext<VisualBasic6Parser::SubscriptsContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::RedimSubStmtContext::RPAREN() {
  return getToken(VisualBasic6Parser::RPAREN, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::RedimSubStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::RedimSubStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AsTypeClauseContext* VisualBasic6Parser::RedimSubStmtContext::asTypeClause() {
  return getRuleContext<VisualBasic6Parser::AsTypeClauseContext>(0);
}


size_t VisualBasic6Parser::RedimSubStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleRedimSubStmt;
}

antlrcpp::Any VisualBasic6Parser::RedimSubStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitRedimSubStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::RedimSubStmtContext* VisualBasic6Parser::redimSubStmt() {
  RedimSubStmtContext *_localctx = _tracker.createInstance<RedimSubStmtContext>(_ctx, getState());
  enterRule(_localctx, 172, VisualBasic6Parser::RuleRedimSubStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1776);
    implicitCallStmt_InStmt();
    setState(1778);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1777);
      match(VisualBasic6Parser::WS);
    }
    setState(1780);
    match(VisualBasic6Parser::LPAREN);
    setState(1782);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 266, _ctx)) {
    case 1: {
      setState(1781);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1784);
    subscripts();
    setState(1786);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1785);
      match(VisualBasic6Parser::WS);
    }
    setState(1788);
    match(VisualBasic6Parser::RPAREN);
    setState(1791);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 268, _ctx)) {
    case 1: {
      setState(1789);
      match(VisualBasic6Parser::WS);
      setState(1790);
      asTypeClause();
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

//----------------- ResetStmtContext ------------------------------------------------------------------

VisualBasic6Parser::ResetStmtContext::ResetStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ResetStmtContext::RESET() {
  return getToken(VisualBasic6Parser::RESET, 0);
}


size_t VisualBasic6Parser::ResetStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleResetStmt;
}

antlrcpp::Any VisualBasic6Parser::ResetStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitResetStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ResetStmtContext* VisualBasic6Parser::resetStmt() {
  ResetStmtContext *_localctx = _tracker.createInstance<ResetStmtContext>(_ctx, getState());
  enterRule(_localctx, 174, VisualBasic6Parser::RuleResetStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1793);
    match(VisualBasic6Parser::RESET);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ResumeStmtContext ------------------------------------------------------------------

VisualBasic6Parser::ResumeStmtContext::ResumeStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ResumeStmtContext::RESUME() {
  return getToken(VisualBasic6Parser::RESUME, 0);
}

tree::TerminalNode* VisualBasic6Parser::ResumeStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

tree::TerminalNode* VisualBasic6Parser::ResumeStmtContext::NEXT() {
  return getToken(VisualBasic6Parser::NEXT, 0);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::ResumeStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}


size_t VisualBasic6Parser::ResumeStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleResumeStmt;
}

antlrcpp::Any VisualBasic6Parser::ResumeStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitResumeStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ResumeStmtContext* VisualBasic6Parser::resumeStmt() {
  ResumeStmtContext *_localctx = _tracker.createInstance<ResumeStmtContext>(_ctx, getState());
  enterRule(_localctx, 176, VisualBasic6Parser::RuleResumeStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1795);
    match(VisualBasic6Parser::RESUME);
    setState(1801);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 270, _ctx)) {
    case 1: {
      setState(1796);
      match(VisualBasic6Parser::WS);
      setState(1799);
      _errHandler->sync(this);
      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 269, _ctx)) {
      case 1: {
        setState(1797);
        match(VisualBasic6Parser::NEXT);
        break;
      }

      case 2: {
        setState(1798);
        ambiguousIdentifier();
        break;
      }

      }
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

//----------------- ReturnStmtContext ------------------------------------------------------------------

VisualBasic6Parser::ReturnStmtContext::ReturnStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ReturnStmtContext::RETURN() {
  return getToken(VisualBasic6Parser::RETURN, 0);
}


size_t VisualBasic6Parser::ReturnStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleReturnStmt;
}

antlrcpp::Any VisualBasic6Parser::ReturnStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitReturnStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ReturnStmtContext* VisualBasic6Parser::returnStmt() {
  ReturnStmtContext *_localctx = _tracker.createInstance<ReturnStmtContext>(_ctx, getState());
  enterRule(_localctx, 178, VisualBasic6Parser::RuleReturnStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1803);
    match(VisualBasic6Parser::RETURN);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- RmdirStmtContext ------------------------------------------------------------------

VisualBasic6Parser::RmdirStmtContext::RmdirStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::RmdirStmtContext::RMDIR() {
  return getToken(VisualBasic6Parser::RMDIR, 0);
}

tree::TerminalNode* VisualBasic6Parser::RmdirStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::RmdirStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::RmdirStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleRmdirStmt;
}

antlrcpp::Any VisualBasic6Parser::RmdirStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitRmdirStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::RmdirStmtContext* VisualBasic6Parser::rmdirStmt() {
  RmdirStmtContext *_localctx = _tracker.createInstance<RmdirStmtContext>(_ctx, getState());
  enterRule(_localctx, 180, VisualBasic6Parser::RuleRmdirStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1805);
    match(VisualBasic6Parser::RMDIR);
    setState(1806);
    match(VisualBasic6Parser::WS);
    setState(1807);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- RsetStmtContext ------------------------------------------------------------------

VisualBasic6Parser::RsetStmtContext::RsetStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::RsetStmtContext::RSET() {
  return getToken(VisualBasic6Parser::RSET, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::RsetStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::RsetStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::ImplicitCallStmt_InStmtContext* VisualBasic6Parser::RsetStmtContext::implicitCallStmt_InStmt() {
  return getRuleContext<VisualBasic6Parser::ImplicitCallStmt_InStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::RsetStmtContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::RsetStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::RsetStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleRsetStmt;
}

antlrcpp::Any VisualBasic6Parser::RsetStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitRsetStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::RsetStmtContext* VisualBasic6Parser::rsetStmt() {
  RsetStmtContext *_localctx = _tracker.createInstance<RsetStmtContext>(_ctx, getState());
  enterRule(_localctx, 182, VisualBasic6Parser::RuleRsetStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1809);
    match(VisualBasic6Parser::RSET);
    setState(1810);
    match(VisualBasic6Parser::WS);
    setState(1811);
    implicitCallStmt_InStmt();
    setState(1813);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1812);
      match(VisualBasic6Parser::WS);
    }
    setState(1815);
    match(VisualBasic6Parser::EQ);
    setState(1817);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 272, _ctx)) {
    case 1: {
      setState(1816);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1819);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SavepictureStmtContext ------------------------------------------------------------------

VisualBasic6Parser::SavepictureStmtContext::SavepictureStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::SavepictureStmtContext::SAVEPICTURE() {
  return getToken(VisualBasic6Parser::SAVEPICTURE, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SavepictureStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::SavepictureStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::SavepictureStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::SavepictureStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::SavepictureStmtContext::COMMA() {
  return getToken(VisualBasic6Parser::COMMA, 0);
}


size_t VisualBasic6Parser::SavepictureStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleSavepictureStmt;
}

antlrcpp::Any VisualBasic6Parser::SavepictureStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitSavepictureStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::SavepictureStmtContext* VisualBasic6Parser::savepictureStmt() {
  SavepictureStmtContext *_localctx = _tracker.createInstance<SavepictureStmtContext>(_ctx, getState());
  enterRule(_localctx, 184, VisualBasic6Parser::RuleSavepictureStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1821);
    match(VisualBasic6Parser::SAVEPICTURE);
    setState(1822);
    match(VisualBasic6Parser::WS);
    setState(1823);
    valueStmt(0);
    setState(1825);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1824);
      match(VisualBasic6Parser::WS);
    }
    setState(1827);
    match(VisualBasic6Parser::COMMA);
    setState(1829);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 274, _ctx)) {
    case 1: {
      setState(1828);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1831);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SaveSettingStmtContext ------------------------------------------------------------------

VisualBasic6Parser::SaveSettingStmtContext::SaveSettingStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::SaveSettingStmtContext::SAVESETTING() {
  return getToken(VisualBasic6Parser::SAVESETTING, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SaveSettingStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::SaveSettingStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::SaveSettingStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::SaveSettingStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SaveSettingStmtContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::SaveSettingStmtContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}


size_t VisualBasic6Parser::SaveSettingStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleSaveSettingStmt;
}

antlrcpp::Any VisualBasic6Parser::SaveSettingStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitSaveSettingStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::SaveSettingStmtContext* VisualBasic6Parser::saveSettingStmt() {
  SaveSettingStmtContext *_localctx = _tracker.createInstance<SaveSettingStmtContext>(_ctx, getState());
  enterRule(_localctx, 186, VisualBasic6Parser::RuleSaveSettingStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1833);
    match(VisualBasic6Parser::SAVESETTING);
    setState(1834);
    match(VisualBasic6Parser::WS);
    setState(1835);
    valueStmt(0);
    setState(1837);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1836);
      match(VisualBasic6Parser::WS);
    }
    setState(1839);
    match(VisualBasic6Parser::COMMA);
    setState(1841);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 276, _ctx)) {
    case 1: {
      setState(1840);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1843);
    valueStmt(0);
    setState(1845);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1844);
      match(VisualBasic6Parser::WS);
    }
    setState(1847);
    match(VisualBasic6Parser::COMMA);
    setState(1849);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 278, _ctx)) {
    case 1: {
      setState(1848);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1851);
    valueStmt(0);
    setState(1853);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1852);
      match(VisualBasic6Parser::WS);
    }
    setState(1855);
    match(VisualBasic6Parser::COMMA);
    setState(1857);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 280, _ctx)) {
    case 1: {
      setState(1856);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1859);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SeekStmtContext ------------------------------------------------------------------

VisualBasic6Parser::SeekStmtContext::SeekStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::SeekStmtContext::SEEK() {
  return getToken(VisualBasic6Parser::SEEK, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SeekStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::SeekStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::SeekStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::SeekStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::SeekStmtContext::COMMA() {
  return getToken(VisualBasic6Parser::COMMA, 0);
}


size_t VisualBasic6Parser::SeekStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleSeekStmt;
}

antlrcpp::Any VisualBasic6Parser::SeekStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitSeekStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::SeekStmtContext* VisualBasic6Parser::seekStmt() {
  SeekStmtContext *_localctx = _tracker.createInstance<SeekStmtContext>(_ctx, getState());
  enterRule(_localctx, 188, VisualBasic6Parser::RuleSeekStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1861);
    match(VisualBasic6Parser::SEEK);
    setState(1862);
    match(VisualBasic6Parser::WS);
    setState(1863);
    valueStmt(0);
    setState(1865);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1864);
      match(VisualBasic6Parser::WS);
    }
    setState(1867);
    match(VisualBasic6Parser::COMMA);
    setState(1869);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 282, _ctx)) {
    case 1: {
      setState(1868);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1871);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SelectCaseStmtContext ------------------------------------------------------------------

VisualBasic6Parser::SelectCaseStmtContext::SelectCaseStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::SelectCaseStmtContext::SELECT() {
  return getToken(VisualBasic6Parser::SELECT, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SelectCaseStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::SelectCaseStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

tree::TerminalNode* VisualBasic6Parser::SelectCaseStmtContext::CASE() {
  return getToken(VisualBasic6Parser::CASE, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::SelectCaseStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::SelectCaseStmtContext::END_SELECT() {
  return getToken(VisualBasic6Parser::END_SELECT, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SelectCaseStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::SelectCaseStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

std::vector<VisualBasic6Parser::SC_CaseContext *> VisualBasic6Parser::SelectCaseStmtContext::sC_Case() {
  return getRuleContexts<VisualBasic6Parser::SC_CaseContext>();
}

VisualBasic6Parser::SC_CaseContext* VisualBasic6Parser::SelectCaseStmtContext::sC_Case(size_t i) {
  return getRuleContext<VisualBasic6Parser::SC_CaseContext>(i);
}


size_t VisualBasic6Parser::SelectCaseStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleSelectCaseStmt;
}

antlrcpp::Any VisualBasic6Parser::SelectCaseStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitSelectCaseStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::SelectCaseStmtContext* VisualBasic6Parser::selectCaseStmt() {
  SelectCaseStmtContext *_localctx = _tracker.createInstance<SelectCaseStmtContext>(_ctx, getState());
  enterRule(_localctx, 190, VisualBasic6Parser::RuleSelectCaseStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1873);
    match(VisualBasic6Parser::SELECT);
    setState(1874);
    match(VisualBasic6Parser::WS);
    setState(1875);
    match(VisualBasic6Parser::CASE);
    setState(1876);
    match(VisualBasic6Parser::WS);
    setState(1877);
    valueStmt(0);
    setState(1879); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(1878);
      match(VisualBasic6Parser::NEWLINE);
      setState(1881); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(1886);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == VisualBasic6Parser::CASE) {
      setState(1883);
      sC_Case();
      setState(1888);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
    setState(1890);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1889);
      match(VisualBasic6Parser::WS);
    }
    setState(1892);
    match(VisualBasic6Parser::END_SELECT);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SC_CaseContext ------------------------------------------------------------------

VisualBasic6Parser::SC_CaseContext::SC_CaseContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::SC_CaseContext::CASE() {
  return getToken(VisualBasic6Parser::CASE, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SC_CaseContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::SC_CaseContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::SC_CondContext* VisualBasic6Parser::SC_CaseContext::sC_Cond() {
  return getRuleContext<VisualBasic6Parser::SC_CondContext>(0);
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::SC_CaseContext::block() {
  return getRuleContext<VisualBasic6Parser::BlockContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::SC_CaseContext::COLON() {
  return getToken(VisualBasic6Parser::COLON, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SC_CaseContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::SC_CaseContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}


size_t VisualBasic6Parser::SC_CaseContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleSC_Case;
}

antlrcpp::Any VisualBasic6Parser::SC_CaseContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitSC_Case(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::SC_CaseContext* VisualBasic6Parser::sC_Case() {
  SC_CaseContext *_localctx = _tracker.createInstance<SC_CaseContext>(_ctx, getState());
  enterRule(_localctx, 192, VisualBasic6Parser::RuleSC_Case);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1894);
    match(VisualBasic6Parser::CASE);
    setState(1895);
    match(VisualBasic6Parser::WS);
    setState(1896);
    sC_Cond();
    setState(1898);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 286, _ctx)) {
    case 1: {
      setState(1897);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1914);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 290, _ctx)) {
    case 1: {
      setState(1901);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::COLON) {
        setState(1900);
        match(VisualBasic6Parser::COLON);
      }
      setState(1906);
      _errHandler->sync(this);
      _la = _input->LA(1);
      while (_la == VisualBasic6Parser::NEWLINE) {
        setState(1903);
        match(VisualBasic6Parser::NEWLINE);
        setState(1908);
        _errHandler->sync(this);
        _la = _input->LA(1);
      }
      break;
    }

    case 2: {
      setState(1910); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(1909);
        match(VisualBasic6Parser::NEWLINE);
        setState(1912); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
      break;
    }

    }
    setState(1922);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 292, _ctx)) {
    case 1: {
      setState(1916);
      block();
      setState(1918); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(1917);
        match(VisualBasic6Parser::NEWLINE);
        setState(1920); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
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

//----------------- SC_CondContext ------------------------------------------------------------------

VisualBasic6Parser::SC_CondContext::SC_CondContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}


size_t VisualBasic6Parser::SC_CondContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleSC_Cond;
}

void VisualBasic6Parser::SC_CondContext::copyFrom(SC_CondContext *ctx) {
  ParserRuleContext::copyFrom(ctx);
}

//----------------- CaseCondExprContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::SC_CondExprContext *> VisualBasic6Parser::CaseCondExprContext::sC_CondExpr() {
  return getRuleContexts<VisualBasic6Parser::SC_CondExprContext>();
}

VisualBasic6Parser::SC_CondExprContext* VisualBasic6Parser::CaseCondExprContext::sC_CondExpr(size_t i) {
  return getRuleContext<VisualBasic6Parser::SC_CondExprContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::CaseCondExprContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::CaseCondExprContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::CaseCondExprContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::CaseCondExprContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::CaseCondExprContext::CaseCondExprContext(SC_CondContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::CaseCondExprContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitCaseCondExpr(this);
  else
    return visitor->visitChildren(this);
}
//----------------- CaseCondElseContext ------------------------------------------------------------------

tree::TerminalNode* VisualBasic6Parser::CaseCondElseContext::ELSE() {
  return getToken(VisualBasic6Parser::ELSE, 0);
}

VisualBasic6Parser::CaseCondElseContext::CaseCondElseContext(SC_CondContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::CaseCondElseContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitCaseCondElse(this);
  else
    return visitor->visitChildren(this);
}
VisualBasic6Parser::SC_CondContext* VisualBasic6Parser::sC_Cond() {
  SC_CondContext *_localctx = _tracker.createInstance<SC_CondContext>(_ctx, getState());
  enterRule(_localctx, 194, VisualBasic6Parser::RuleSC_Cond);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    setState(1939);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 296, _ctx)) {
    case 1: {
      _localctx = dynamic_cast<SC_CondContext *>(_tracker.createInstance<VisualBasic6Parser::CaseCondElseContext>(_localctx));
      enterOuterAlt(_localctx, 1);
      setState(1924);
      match(VisualBasic6Parser::ELSE);
      break;
    }

    case 2: {
      _localctx = dynamic_cast<SC_CondContext *>(_tracker.createInstance<VisualBasic6Parser::CaseCondExprContext>(_localctx));
      enterOuterAlt(_localctx, 2);
      setState(1925);
      sC_CondExpr();
      setState(1936);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 295, _ctx);
      while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
        if (alt == 1) {
          setState(1927);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(1926);
            match(VisualBasic6Parser::WS);
          }
          setState(1929);
          match(VisualBasic6Parser::COMMA);
          setState(1931);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 294, _ctx)) {
          case 1: {
            setState(1930);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(1933);
          sC_CondExpr(); 
        }
        setState(1938);
        _errHandler->sync(this);
        alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 295, _ctx);
      }
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

//----------------- SC_CondExprContext ------------------------------------------------------------------

VisualBasic6Parser::SC_CondExprContext::SC_CondExprContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}


size_t VisualBasic6Parser::SC_CondExprContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleSC_CondExpr;
}

void VisualBasic6Parser::SC_CondExprContext::copyFrom(SC_CondExprContext *ctx) {
  ParserRuleContext::copyFrom(ctx);
}

//----------------- CaseCondExprValueContext ------------------------------------------------------------------

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::CaseCondExprValueContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

VisualBasic6Parser::CaseCondExprValueContext::CaseCondExprValueContext(SC_CondExprContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::CaseCondExprValueContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitCaseCondExprValue(this);
  else
    return visitor->visitChildren(this);
}
//----------------- CaseCondExprIsContext ------------------------------------------------------------------

tree::TerminalNode* VisualBasic6Parser::CaseCondExprIsContext::IS() {
  return getToken(VisualBasic6Parser::IS, 0);
}

VisualBasic6Parser::ComparisonOperatorContext* VisualBasic6Parser::CaseCondExprIsContext::comparisonOperator() {
  return getRuleContext<VisualBasic6Parser::ComparisonOperatorContext>(0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::CaseCondExprIsContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::CaseCondExprIsContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::CaseCondExprIsContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::CaseCondExprIsContext::CaseCondExprIsContext(SC_CondExprContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::CaseCondExprIsContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitCaseCondExprIs(this);
  else
    return visitor->visitChildren(this);
}
//----------------- CaseCondExprToContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::CaseCondExprToContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::CaseCondExprToContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::CaseCondExprToContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::CaseCondExprToContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

tree::TerminalNode* VisualBasic6Parser::CaseCondExprToContext::TO() {
  return getToken(VisualBasic6Parser::TO, 0);
}

VisualBasic6Parser::CaseCondExprToContext::CaseCondExprToContext(SC_CondExprContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::CaseCondExprToContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitCaseCondExprTo(this);
  else
    return visitor->visitChildren(this);
}
VisualBasic6Parser::SC_CondExprContext* VisualBasic6Parser::sC_CondExpr() {
  SC_CondExprContext *_localctx = _tracker.createInstance<SC_CondExprContext>(_ctx, getState());
  enterRule(_localctx, 196, VisualBasic6Parser::RuleSC_CondExpr);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(1958);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 299, _ctx)) {
    case 1: {
      _localctx = dynamic_cast<SC_CondExprContext *>(_tracker.createInstance<VisualBasic6Parser::CaseCondExprIsContext>(_localctx));
      enterOuterAlt(_localctx, 1);
      setState(1941);
      match(VisualBasic6Parser::IS);
      setState(1943);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(1942);
        match(VisualBasic6Parser::WS);
      }
      setState(1945);
      comparisonOperator();
      setState(1947);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 298, _ctx)) {
      case 1: {
        setState(1946);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(1949);
      valueStmt(0);
      break;
    }

    case 2: {
      _localctx = dynamic_cast<SC_CondExprContext *>(_tracker.createInstance<VisualBasic6Parser::CaseCondExprValueContext>(_localctx));
      enterOuterAlt(_localctx, 2);
      setState(1951);
      valueStmt(0);
      break;
    }

    case 3: {
      _localctx = dynamic_cast<SC_CondExprContext *>(_tracker.createInstance<VisualBasic6Parser::CaseCondExprToContext>(_localctx));
      enterOuterAlt(_localctx, 3);
      setState(1952);
      valueStmt(0);
      setState(1953);
      match(VisualBasic6Parser::WS);
      setState(1954);
      match(VisualBasic6Parser::TO);
      setState(1955);
      match(VisualBasic6Parser::WS);
      setState(1956);
      valueStmt(0);
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

//----------------- SendkeysStmtContext ------------------------------------------------------------------

VisualBasic6Parser::SendkeysStmtContext::SendkeysStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::SendkeysStmtContext::SENDKEYS() {
  return getToken(VisualBasic6Parser::SENDKEYS, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SendkeysStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::SendkeysStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::SendkeysStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::SendkeysStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::SendkeysStmtContext::COMMA() {
  return getToken(VisualBasic6Parser::COMMA, 0);
}


size_t VisualBasic6Parser::SendkeysStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleSendkeysStmt;
}

antlrcpp::Any VisualBasic6Parser::SendkeysStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitSendkeysStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::SendkeysStmtContext* VisualBasic6Parser::sendkeysStmt() {
  SendkeysStmtContext *_localctx = _tracker.createInstance<SendkeysStmtContext>(_ctx, getState());
  enterRule(_localctx, 198, VisualBasic6Parser::RuleSendkeysStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1960);
    match(VisualBasic6Parser::SENDKEYS);
    setState(1961);
    match(VisualBasic6Parser::WS);
    setState(1962);
    valueStmt(0);
    setState(1971);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 302, _ctx)) {
    case 1: {
      setState(1964);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(1963);
        match(VisualBasic6Parser::WS);
      }
      setState(1966);
      match(VisualBasic6Parser::COMMA);
      setState(1968);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 301, _ctx)) {
      case 1: {
        setState(1967);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(1970);
      valueStmt(0);
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

//----------------- SetattrStmtContext ------------------------------------------------------------------

VisualBasic6Parser::SetattrStmtContext::SetattrStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::SetattrStmtContext::SETATTR() {
  return getToken(VisualBasic6Parser::SETATTR, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SetattrStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::SetattrStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::SetattrStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::SetattrStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::SetattrStmtContext::COMMA() {
  return getToken(VisualBasic6Parser::COMMA, 0);
}


size_t VisualBasic6Parser::SetattrStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleSetattrStmt;
}

antlrcpp::Any VisualBasic6Parser::SetattrStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitSetattrStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::SetattrStmtContext* VisualBasic6Parser::setattrStmt() {
  SetattrStmtContext *_localctx = _tracker.createInstance<SetattrStmtContext>(_ctx, getState());
  enterRule(_localctx, 200, VisualBasic6Parser::RuleSetattrStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1973);
    match(VisualBasic6Parser::SETATTR);
    setState(1974);
    match(VisualBasic6Parser::WS);
    setState(1975);
    valueStmt(0);
    setState(1977);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1976);
      match(VisualBasic6Parser::WS);
    }
    setState(1979);
    match(VisualBasic6Parser::COMMA);
    setState(1981);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 304, _ctx)) {
    case 1: {
      setState(1980);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1983);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SetStmtContext ------------------------------------------------------------------

VisualBasic6Parser::SetStmtContext::SetStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::SetStmtContext::SET() {
  return getToken(VisualBasic6Parser::SET, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SetStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::SetStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::ImplicitCallStmt_InStmtContext* VisualBasic6Parser::SetStmtContext::implicitCallStmt_InStmt() {
  return getRuleContext<VisualBasic6Parser::ImplicitCallStmt_InStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::SetStmtContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::SetStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::SetStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleSetStmt;
}

antlrcpp::Any VisualBasic6Parser::SetStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitSetStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::SetStmtContext* VisualBasic6Parser::setStmt() {
  SetStmtContext *_localctx = _tracker.createInstance<SetStmtContext>(_ctx, getState());
  enterRule(_localctx, 202, VisualBasic6Parser::RuleSetStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1985);
    match(VisualBasic6Parser::SET);
    setState(1986);
    match(VisualBasic6Parser::WS);
    setState(1987);
    implicitCallStmt_InStmt();
    setState(1989);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(1988);
      match(VisualBasic6Parser::WS);
    }
    setState(1991);
    match(VisualBasic6Parser::EQ);
    setState(1993);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 306, _ctx)) {
    case 1: {
      setState(1992);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(1995);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- StopStmtContext ------------------------------------------------------------------

VisualBasic6Parser::StopStmtContext::StopStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::StopStmtContext::STOP() {
  return getToken(VisualBasic6Parser::STOP, 0);
}


size_t VisualBasic6Parser::StopStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleStopStmt;
}

antlrcpp::Any VisualBasic6Parser::StopStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitStopStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::StopStmtContext* VisualBasic6Parser::stopStmt() {
  StopStmtContext *_localctx = _tracker.createInstance<StopStmtContext>(_ctx, getState());
  enterRule(_localctx, 204, VisualBasic6Parser::RuleStopStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(1997);
    match(VisualBasic6Parser::STOP);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SubStmtContext ------------------------------------------------------------------

VisualBasic6Parser::SubStmtContext::SubStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::SubStmtContext::SUB() {
  return getToken(VisualBasic6Parser::SUB, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SubStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::SubStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::SubStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::SubStmtContext::END_SUB() {
  return getToken(VisualBasic6Parser::END_SUB, 0);
}

VisualBasic6Parser::VisibilityContext* VisualBasic6Parser::SubStmtContext::visibility() {
  return getRuleContext<VisualBasic6Parser::VisibilityContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::SubStmtContext::STATIC() {
  return getToken(VisualBasic6Parser::STATIC, 0);
}

VisualBasic6Parser::ArgListContext* VisualBasic6Parser::SubStmtContext::argList() {
  return getRuleContext<VisualBasic6Parser::ArgListContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SubStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::SubStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::SubStmtContext::block() {
  return getRuleContext<VisualBasic6Parser::BlockContext>(0);
}


size_t VisualBasic6Parser::SubStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleSubStmt;
}

antlrcpp::Any VisualBasic6Parser::SubStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitSubStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::SubStmtContext* VisualBasic6Parser::subStmt() {
  SubStmtContext *_localctx = _tracker.createInstance<SubStmtContext>(_ctx, getState());
  enterRule(_localctx, 206, VisualBasic6Parser::RuleSubStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2002);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 68) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 68)) & ((1ULL << (VisualBasic6Parser::FRIEND - 68))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 68))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 68))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 68)))) != 0)) {
      setState(1999);
      visibility();
      setState(2000);
      match(VisualBasic6Parser::WS);
    }
    setState(2006);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::STATIC) {
      setState(2004);
      match(VisualBasic6Parser::STATIC);
      setState(2005);
      match(VisualBasic6Parser::WS);
    }
    setState(2008);
    match(VisualBasic6Parser::SUB);
    setState(2009);
    match(VisualBasic6Parser::WS);
    setState(2010);
    ambiguousIdentifier();
    setState(2015);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::LPAREN

    || _la == VisualBasic6Parser::WS) {
      setState(2012);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2011);
        match(VisualBasic6Parser::WS);
      }
      setState(2014);
      argList();
    }
    setState(2018); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(2017);
      match(VisualBasic6Parser::NEWLINE);
      setState(2020); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(2028);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
      | (1ULL << VisualBasic6Parser::ADDRESSOF)
      | (1ULL << VisualBasic6Parser::ALIAS)
      | (1ULL << VisualBasic6Parser::AND)
      | (1ULL << VisualBasic6Parser::ATTRIBUTE)
      | (1ULL << VisualBasic6Parser::APPACTIVATE)
      | (1ULL << VisualBasic6Parser::APPEND)
      | (1ULL << VisualBasic6Parser::AS)
      | (1ULL << VisualBasic6Parser::BEEP)
      | (1ULL << VisualBasic6Parser::BEGIN)
      | (1ULL << VisualBasic6Parser::BINARY)
      | (1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYVAL)
      | (1ULL << VisualBasic6Parser::BYREF)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::CALL)
      | (1ULL << VisualBasic6Parser::CASE)
      | (1ULL << VisualBasic6Parser::CHDIR)
      | (1ULL << VisualBasic6Parser::CHDRIVE)
      | (1ULL << VisualBasic6Parser::CLASS)
      | (1ULL << VisualBasic6Parser::CLOSE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::CONST)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DECLARE)
      | (1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR)
      | (1ULL << VisualBasic6Parser::DELETESETTING)
      | (1ULL << VisualBasic6Parser::DIM)
      | (1ULL << VisualBasic6Parser::DO)
      | (1ULL << VisualBasic6Parser::DOUBLE)
      | (1ULL << VisualBasic6Parser::EACH)
      | (1ULL << VisualBasic6Parser::ELSE)
      | (1ULL << VisualBasic6Parser::ELSEIF)
      | (1ULL << VisualBasic6Parser::END)
      | (1ULL << VisualBasic6Parser::ENUM)
      | (1ULL << VisualBasic6Parser::EQV)
      | (1ULL << VisualBasic6Parser::ERASE)
      | (1ULL << VisualBasic6Parser::ERROR)
      | (1ULL << VisualBasic6Parser::EVENT)
      | (1ULL << VisualBasic6Parser::EXIT_DO)
      | (1ULL << VisualBasic6Parser::EXIT_FOR)
      | (1ULL << VisualBasic6Parser::EXIT_FUNCTION))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (VisualBasic6Parser::EXIT_PROPERTY - 64))
      | (1ULL << (VisualBasic6Parser::EXIT_SUB - 64))
      | (1ULL << (VisualBasic6Parser::FALSE1 - 64))
      | (1ULL << (VisualBasic6Parser::FILECOPY - 64))
      | (1ULL << (VisualBasic6Parser::FRIEND - 64))
      | (1ULL << (VisualBasic6Parser::FOR - 64))
      | (1ULL << (VisualBasic6Parser::FUNCTION - 64))
      | (1ULL << (VisualBasic6Parser::GET - 64))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 64))
      | (1ULL << (VisualBasic6Parser::GOSUB - 64))
      | (1ULL << (VisualBasic6Parser::GOTO - 64))
      | (1ULL << (VisualBasic6Parser::IF - 64))
      | (1ULL << (VisualBasic6Parser::IMP - 64))
      | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 64))
      | (1ULL << (VisualBasic6Parser::IN - 64))
      | (1ULL << (VisualBasic6Parser::INPUT - 64))
      | (1ULL << (VisualBasic6Parser::IS - 64))
      | (1ULL << (VisualBasic6Parser::INTEGER - 64))
      | (1ULL << (VisualBasic6Parser::KILL - 64))
      | (1ULL << (VisualBasic6Parser::LOAD - 64))
      | (1ULL << (VisualBasic6Parser::LOCK - 64))
      | (1ULL << (VisualBasic6Parser::LONG - 64))
      | (1ULL << (VisualBasic6Parser::LOOP - 64))
      | (1ULL << (VisualBasic6Parser::LEN - 64))
      | (1ULL << (VisualBasic6Parser::LET - 64))
      | (1ULL << (VisualBasic6Parser::LIB - 64))
      | (1ULL << (VisualBasic6Parser::LIKE - 64))
      | (1ULL << (VisualBasic6Parser::LINE_INPUT - 64))
      | (1ULL << (VisualBasic6Parser::LSET - 64))
      | (1ULL << (VisualBasic6Parser::MACRO_IF - 64))
      | (1ULL << (VisualBasic6Parser::ME - 64))
      | (1ULL << (VisualBasic6Parser::MID - 64))
      | (1ULL << (VisualBasic6Parser::MKDIR - 64))
      | (1ULL << (VisualBasic6Parser::MOD - 64))
      | (1ULL << (VisualBasic6Parser::NAME - 64))
      | (1ULL << (VisualBasic6Parser::NEXT - 64))
      | (1ULL << (VisualBasic6Parser::NEW - 64))
      | (1ULL << (VisualBasic6Parser::NOT - 64))
      | (1ULL << (VisualBasic6Parser::NOTHING - 64))
      | (1ULL << (VisualBasic6Parser::NULL1 - 64))
      | (1ULL << (VisualBasic6Parser::OBJECT - 64))
      | (1ULL << (VisualBasic6Parser::ON - 64))
      | (1ULL << (VisualBasic6Parser::ON_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::ON_LOCAL_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::OPEN - 64))
      | (1ULL << (VisualBasic6Parser::OPTIONAL - 64))
      | (1ULL << (VisualBasic6Parser::OR - 64))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 64))
      | (1ULL << (VisualBasic6Parser::PARAMARRAY - 64))
      | (1ULL << (VisualBasic6Parser::PRESERVE - 64))
      | (1ULL << (VisualBasic6Parser::PRINT - 64))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 64)))) != 0) || ((((_la - 129) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 129)) & ((1ULL << (VisualBasic6Parser::PUBLIC - 129))
      | (1ULL << (VisualBasic6Parser::PUT - 129))
      | (1ULL << (VisualBasic6Parser::RANDOM - 129))
      | (1ULL << (VisualBasic6Parser::RANDOMIZE - 129))
      | (1ULL << (VisualBasic6Parser::RAISEEVENT - 129))
      | (1ULL << (VisualBasic6Parser::READ - 129))
      | (1ULL << (VisualBasic6Parser::REDIM - 129))
      | (1ULL << (VisualBasic6Parser::REM - 129))
      | (1ULL << (VisualBasic6Parser::RESET - 129))
      | (1ULL << (VisualBasic6Parser::RESUME - 129))
      | (1ULL << (VisualBasic6Parser::RETURN - 129))
      | (1ULL << (VisualBasic6Parser::RMDIR - 129))
      | (1ULL << (VisualBasic6Parser::RSET - 129))
      | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 129))
      | (1ULL << (VisualBasic6Parser::SAVESETTING - 129))
      | (1ULL << (VisualBasic6Parser::SEEK - 129))
      | (1ULL << (VisualBasic6Parser::SELECT - 129))
      | (1ULL << (VisualBasic6Parser::SENDKEYS - 129))
      | (1ULL << (VisualBasic6Parser::SET - 129))
      | (1ULL << (VisualBasic6Parser::SETATTR - 129))
      | (1ULL << (VisualBasic6Parser::SHARED - 129))
      | (1ULL << (VisualBasic6Parser::SINGLE - 129))
      | (1ULL << (VisualBasic6Parser::SPC - 129))
      | (1ULL << (VisualBasic6Parser::STATIC - 129))
      | (1ULL << (VisualBasic6Parser::STEP - 129))
      | (1ULL << (VisualBasic6Parser::STOP - 129))
      | (1ULL << (VisualBasic6Parser::STRING - 129))
      | (1ULL << (VisualBasic6Parser::SUB - 129))
      | (1ULL << (VisualBasic6Parser::TAB - 129))
      | (1ULL << (VisualBasic6Parser::TEXT - 129))
      | (1ULL << (VisualBasic6Parser::THEN - 129))
      | (1ULL << (VisualBasic6Parser::TIME - 129))
      | (1ULL << (VisualBasic6Parser::TO - 129))
      | (1ULL << (VisualBasic6Parser::TRUE1 - 129))
      | (1ULL << (VisualBasic6Parser::TYPE - 129))
      | (1ULL << (VisualBasic6Parser::TYPEOF - 129))
      | (1ULL << (VisualBasic6Parser::UNLOAD - 129))
      | (1ULL << (VisualBasic6Parser::UNLOCK - 129))
      | (1ULL << (VisualBasic6Parser::UNTIL - 129))
      | (1ULL << (VisualBasic6Parser::VARIANT - 129))
      | (1ULL << (VisualBasic6Parser::VERSION - 129))
      | (1ULL << (VisualBasic6Parser::WEND - 129))
      | (1ULL << (VisualBasic6Parser::WHILE - 129))
      | (1ULL << (VisualBasic6Parser::WIDTH - 129))
      | (1ULL << (VisualBasic6Parser::WITH - 129))
      | (1ULL << (VisualBasic6Parser::WITHEVENTS - 129))
      | (1ULL << (VisualBasic6Parser::WRITE - 129))
      | (1ULL << (VisualBasic6Parser::XOR - 129))
      | (1ULL << (VisualBasic6Parser::DOT - 129))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 129)))) != 0) || ((((_la - 206) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 206)) & ((1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 206))
      | (1ULL << (VisualBasic6Parser::IDENTIFIER - 206))
      | (1ULL << (VisualBasic6Parser::WS - 206)))) != 0)) {
      setState(2022);
      block();
      setState(2024); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(2023);
        match(VisualBasic6Parser::NEWLINE);
        setState(2026); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
    }
    setState(2030);
    match(VisualBasic6Parser::END_SUB);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TimeStmtContext ------------------------------------------------------------------

VisualBasic6Parser::TimeStmtContext::TimeStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::TimeStmtContext::TIME() {
  return getToken(VisualBasic6Parser::TIME, 0);
}

tree::TerminalNode* VisualBasic6Parser::TimeStmtContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::TimeStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::TimeStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::TimeStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}


size_t VisualBasic6Parser::TimeStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleTimeStmt;
}

antlrcpp::Any VisualBasic6Parser::TimeStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitTimeStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::TimeStmtContext* VisualBasic6Parser::timeStmt() {
  TimeStmtContext *_localctx = _tracker.createInstance<TimeStmtContext>(_ctx, getState());
  enterRule(_localctx, 208, VisualBasic6Parser::RuleTimeStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2032);
    match(VisualBasic6Parser::TIME);
    setState(2034);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(2033);
      match(VisualBasic6Parser::WS);
    }
    setState(2036);
    match(VisualBasic6Parser::EQ);
    setState(2038);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 315, _ctx)) {
    case 1: {
      setState(2037);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(2040);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TypeStmtContext ------------------------------------------------------------------

VisualBasic6Parser::TypeStmtContext::TypeStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::TypeStmtContext::TYPE() {
  return getToken(VisualBasic6Parser::TYPE, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::TypeStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::TypeStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::TypeStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::TypeStmtContext::END_TYPE() {
  return getToken(VisualBasic6Parser::END_TYPE, 0);
}

VisualBasic6Parser::VisibilityContext* VisualBasic6Parser::TypeStmtContext::visibility() {
  return getRuleContext<VisualBasic6Parser::VisibilityContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::TypeStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::TypeStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

std::vector<VisualBasic6Parser::TypeStmt_ElementContext *> VisualBasic6Parser::TypeStmtContext::typeStmt_Element() {
  return getRuleContexts<VisualBasic6Parser::TypeStmt_ElementContext>();
}

VisualBasic6Parser::TypeStmt_ElementContext* VisualBasic6Parser::TypeStmtContext::typeStmt_Element(size_t i) {
  return getRuleContext<VisualBasic6Parser::TypeStmt_ElementContext>(i);
}


size_t VisualBasic6Parser::TypeStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleTypeStmt;
}

antlrcpp::Any VisualBasic6Parser::TypeStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitTypeStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::TypeStmtContext* VisualBasic6Parser::typeStmt() {
  TypeStmtContext *_localctx = _tracker.createInstance<TypeStmtContext>(_ctx, getState());
  enterRule(_localctx, 210, VisualBasic6Parser::RuleTypeStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2045);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 68) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 68)) & ((1ULL << (VisualBasic6Parser::FRIEND - 68))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 68))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 68))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 68)))) != 0)) {
      setState(2042);
      visibility();
      setState(2043);
      match(VisualBasic6Parser::WS);
    }
    setState(2047);
    match(VisualBasic6Parser::TYPE);
    setState(2048);
    match(VisualBasic6Parser::WS);
    setState(2049);
    ambiguousIdentifier();
    setState(2051); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(2050);
      match(VisualBasic6Parser::NEWLINE);
      setState(2053); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(2058);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
      | (1ULL << VisualBasic6Parser::ADDRESSOF)
      | (1ULL << VisualBasic6Parser::ALIAS)
      | (1ULL << VisualBasic6Parser::AND)
      | (1ULL << VisualBasic6Parser::ATTRIBUTE)
      | (1ULL << VisualBasic6Parser::APPACTIVATE)
      | (1ULL << VisualBasic6Parser::APPEND)
      | (1ULL << VisualBasic6Parser::AS)
      | (1ULL << VisualBasic6Parser::BEEP)
      | (1ULL << VisualBasic6Parser::BEGIN)
      | (1ULL << VisualBasic6Parser::BINARY)
      | (1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYVAL)
      | (1ULL << VisualBasic6Parser::BYREF)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::CALL)
      | (1ULL << VisualBasic6Parser::CASE)
      | (1ULL << VisualBasic6Parser::CHDIR)
      | (1ULL << VisualBasic6Parser::CHDRIVE)
      | (1ULL << VisualBasic6Parser::CLASS)
      | (1ULL << VisualBasic6Parser::CLOSE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::CONST)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DECLARE)
      | (1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR)
      | (1ULL << VisualBasic6Parser::DELETESETTING)
      | (1ULL << VisualBasic6Parser::DIM)
      | (1ULL << VisualBasic6Parser::DO)
      | (1ULL << VisualBasic6Parser::DOUBLE)
      | (1ULL << VisualBasic6Parser::EACH)
      | (1ULL << VisualBasic6Parser::ELSE)
      | (1ULL << VisualBasic6Parser::ELSEIF)
      | (1ULL << VisualBasic6Parser::END)
      | (1ULL << VisualBasic6Parser::ENUM)
      | (1ULL << VisualBasic6Parser::EQV)
      | (1ULL << VisualBasic6Parser::ERASE)
      | (1ULL << VisualBasic6Parser::ERROR)
      | (1ULL << VisualBasic6Parser::EVENT))) != 0) || ((((_la - 66) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 66)) & ((1ULL << (VisualBasic6Parser::FALSE1 - 66))
      | (1ULL << (VisualBasic6Parser::FILECOPY - 66))
      | (1ULL << (VisualBasic6Parser::FRIEND - 66))
      | (1ULL << (VisualBasic6Parser::FOR - 66))
      | (1ULL << (VisualBasic6Parser::FUNCTION - 66))
      | (1ULL << (VisualBasic6Parser::GET - 66))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 66))
      | (1ULL << (VisualBasic6Parser::GOSUB - 66))
      | (1ULL << (VisualBasic6Parser::GOTO - 66))
      | (1ULL << (VisualBasic6Parser::IF - 66))
      | (1ULL << (VisualBasic6Parser::IMP - 66))
      | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 66))
      | (1ULL << (VisualBasic6Parser::IN - 66))
      | (1ULL << (VisualBasic6Parser::INPUT - 66))
      | (1ULL << (VisualBasic6Parser::IS - 66))
      | (1ULL << (VisualBasic6Parser::INTEGER - 66))
      | (1ULL << (VisualBasic6Parser::KILL - 66))
      | (1ULL << (VisualBasic6Parser::LOAD - 66))
      | (1ULL << (VisualBasic6Parser::LOCK - 66))
      | (1ULL << (VisualBasic6Parser::LONG - 66))
      | (1ULL << (VisualBasic6Parser::LOOP - 66))
      | (1ULL << (VisualBasic6Parser::LEN - 66))
      | (1ULL << (VisualBasic6Parser::LET - 66))
      | (1ULL << (VisualBasic6Parser::LIB - 66))
      | (1ULL << (VisualBasic6Parser::LIKE - 66))
      | (1ULL << (VisualBasic6Parser::LSET - 66))
      | (1ULL << (VisualBasic6Parser::ME - 66))
      | (1ULL << (VisualBasic6Parser::MID - 66))
      | (1ULL << (VisualBasic6Parser::MKDIR - 66))
      | (1ULL << (VisualBasic6Parser::MOD - 66))
      | (1ULL << (VisualBasic6Parser::NAME - 66))
      | (1ULL << (VisualBasic6Parser::NEXT - 66))
      | (1ULL << (VisualBasic6Parser::NEW - 66))
      | (1ULL << (VisualBasic6Parser::NOT - 66))
      | (1ULL << (VisualBasic6Parser::NOTHING - 66))
      | (1ULL << (VisualBasic6Parser::NULL1 - 66))
      | (1ULL << (VisualBasic6Parser::OBJECT - 66))
      | (1ULL << (VisualBasic6Parser::ON - 66))
      | (1ULL << (VisualBasic6Parser::OPEN - 66))
      | (1ULL << (VisualBasic6Parser::OPTIONAL - 66))
      | (1ULL << (VisualBasic6Parser::OR - 66))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 66))
      | (1ULL << (VisualBasic6Parser::PARAMARRAY - 66))
      | (1ULL << (VisualBasic6Parser::PRESERVE - 66))
      | (1ULL << (VisualBasic6Parser::PRINT - 66))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 66))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 66)))) != 0) || ((((_la - 130) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 130)) & ((1ULL << (VisualBasic6Parser::PUT - 130))
      | (1ULL << (VisualBasic6Parser::RANDOM - 130))
      | (1ULL << (VisualBasic6Parser::RANDOMIZE - 130))
      | (1ULL << (VisualBasic6Parser::RAISEEVENT - 130))
      | (1ULL << (VisualBasic6Parser::READ - 130))
      | (1ULL << (VisualBasic6Parser::REDIM - 130))
      | (1ULL << (VisualBasic6Parser::REM - 130))
      | (1ULL << (VisualBasic6Parser::RESET - 130))
      | (1ULL << (VisualBasic6Parser::RESUME - 130))
      | (1ULL << (VisualBasic6Parser::RETURN - 130))
      | (1ULL << (VisualBasic6Parser::RMDIR - 130))
      | (1ULL << (VisualBasic6Parser::RSET - 130))
      | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 130))
      | (1ULL << (VisualBasic6Parser::SAVESETTING - 130))
      | (1ULL << (VisualBasic6Parser::SEEK - 130))
      | (1ULL << (VisualBasic6Parser::SELECT - 130))
      | (1ULL << (VisualBasic6Parser::SENDKEYS - 130))
      | (1ULL << (VisualBasic6Parser::SET - 130))
      | (1ULL << (VisualBasic6Parser::SETATTR - 130))
      | (1ULL << (VisualBasic6Parser::SHARED - 130))
      | (1ULL << (VisualBasic6Parser::SINGLE - 130))
      | (1ULL << (VisualBasic6Parser::SPC - 130))
      | (1ULL << (VisualBasic6Parser::STATIC - 130))
      | (1ULL << (VisualBasic6Parser::STEP - 130))
      | (1ULL << (VisualBasic6Parser::STOP - 130))
      | (1ULL << (VisualBasic6Parser::STRING - 130))
      | (1ULL << (VisualBasic6Parser::SUB - 130))
      | (1ULL << (VisualBasic6Parser::TAB - 130))
      | (1ULL << (VisualBasic6Parser::TEXT - 130))
      | (1ULL << (VisualBasic6Parser::THEN - 130))
      | (1ULL << (VisualBasic6Parser::TIME - 130))
      | (1ULL << (VisualBasic6Parser::TO - 130))
      | (1ULL << (VisualBasic6Parser::TRUE1 - 130))
      | (1ULL << (VisualBasic6Parser::TYPE - 130))
      | (1ULL << (VisualBasic6Parser::TYPEOF - 130))
      | (1ULL << (VisualBasic6Parser::UNLOAD - 130))
      | (1ULL << (VisualBasic6Parser::UNLOCK - 130))
      | (1ULL << (VisualBasic6Parser::UNTIL - 130))
      | (1ULL << (VisualBasic6Parser::VARIANT - 130))
      | (1ULL << (VisualBasic6Parser::VERSION - 130))
      | (1ULL << (VisualBasic6Parser::WEND - 130))
      | (1ULL << (VisualBasic6Parser::WHILE - 130))
      | (1ULL << (VisualBasic6Parser::WIDTH - 130))
      | (1ULL << (VisualBasic6Parser::WITH - 130))
      | (1ULL << (VisualBasic6Parser::WITHEVENTS - 130))
      | (1ULL << (VisualBasic6Parser::WRITE - 130))
      | (1ULL << (VisualBasic6Parser::XOR - 130)))) != 0) || _la == VisualBasic6Parser::L_SQUARE_BRACKET

    || _la == VisualBasic6Parser::IDENTIFIER) {
      setState(2055);
      typeStmt_Element();
      setState(2060);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
    setState(2061);
    match(VisualBasic6Parser::END_TYPE);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TypeStmt_ElementContext ------------------------------------------------------------------

VisualBasic6Parser::TypeStmt_ElementContext::TypeStmt_ElementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::TypeStmt_ElementContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::TypeStmt_ElementContext::LPAREN() {
  return getToken(VisualBasic6Parser::LPAREN, 0);
}

tree::TerminalNode* VisualBasic6Parser::TypeStmt_ElementContext::RPAREN() {
  return getToken(VisualBasic6Parser::RPAREN, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::TypeStmt_ElementContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::TypeStmt_ElementContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AsTypeClauseContext* VisualBasic6Parser::TypeStmt_ElementContext::asTypeClause() {
  return getRuleContext<VisualBasic6Parser::AsTypeClauseContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::TypeStmt_ElementContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::TypeStmt_ElementContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::SubscriptsContext* VisualBasic6Parser::TypeStmt_ElementContext::subscripts() {
  return getRuleContext<VisualBasic6Parser::SubscriptsContext>(0);
}


size_t VisualBasic6Parser::TypeStmt_ElementContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleTypeStmt_Element;
}

antlrcpp::Any VisualBasic6Parser::TypeStmt_ElementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitTypeStmt_Element(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::TypeStmt_ElementContext* VisualBasic6Parser::typeStmt_Element() {
  TypeStmt_ElementContext *_localctx = _tracker.createInstance<TypeStmt_ElementContext>(_ctx, getState());
  enterRule(_localctx, 212, VisualBasic6Parser::RuleTypeStmt_Element);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2063);
    ambiguousIdentifier();
    setState(2078);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 323, _ctx)) {
    case 1: {
      setState(2065);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2064);
        match(VisualBasic6Parser::WS);
      }
      setState(2067);
      match(VisualBasic6Parser::LPAREN);
      setState(2072);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 321, _ctx)) {
      case 1: {
        setState(2069);
        _errHandler->sync(this);

        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 320, _ctx)) {
        case 1: {
          setState(2068);
          match(VisualBasic6Parser::WS);
          break;
        }

        }
        setState(2071);
        subscripts();
        break;
      }

      }
      setState(2075);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2074);
        match(VisualBasic6Parser::WS);
      }
      setState(2077);
      match(VisualBasic6Parser::RPAREN);
      break;
    }

    }
    setState(2082);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(2080);
      match(VisualBasic6Parser::WS);
      setState(2081);
      asTypeClause();
    }
    setState(2085); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(2084);
      match(VisualBasic6Parser::NEWLINE);
      setState(2087); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- TypeOfStmtContext ------------------------------------------------------------------

VisualBasic6Parser::TypeOfStmtContext::TypeOfStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::TypeOfStmtContext::TYPEOF() {
  return getToken(VisualBasic6Parser::TYPEOF, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::TypeOfStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::TypeOfStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::TypeOfStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::TypeOfStmtContext::IS() {
  return getToken(VisualBasic6Parser::IS, 0);
}

VisualBasic6Parser::TypeContext* VisualBasic6Parser::TypeOfStmtContext::type() {
  return getRuleContext<VisualBasic6Parser::TypeContext>(0);
}


size_t VisualBasic6Parser::TypeOfStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleTypeOfStmt;
}

antlrcpp::Any VisualBasic6Parser::TypeOfStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitTypeOfStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::TypeOfStmtContext* VisualBasic6Parser::typeOfStmt() {
  TypeOfStmtContext *_localctx = _tracker.createInstance<TypeOfStmtContext>(_ctx, getState());
  enterRule(_localctx, 214, VisualBasic6Parser::RuleTypeOfStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2089);
    match(VisualBasic6Parser::TYPEOF);
    setState(2090);
    match(VisualBasic6Parser::WS);
    setState(2091);
    valueStmt(0);
    setState(2096);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 326, _ctx)) {
    case 1: {
      setState(2092);
      match(VisualBasic6Parser::WS);
      setState(2093);
      match(VisualBasic6Parser::IS);
      setState(2094);
      match(VisualBasic6Parser::WS);
      setState(2095);
      type();
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

//----------------- UnloadStmtContext ------------------------------------------------------------------

VisualBasic6Parser::UnloadStmtContext::UnloadStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::UnloadStmtContext::UNLOAD() {
  return getToken(VisualBasic6Parser::UNLOAD, 0);
}

tree::TerminalNode* VisualBasic6Parser::UnloadStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::UnloadStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}


size_t VisualBasic6Parser::UnloadStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleUnloadStmt;
}

antlrcpp::Any VisualBasic6Parser::UnloadStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitUnloadStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::UnloadStmtContext* VisualBasic6Parser::unloadStmt() {
  UnloadStmtContext *_localctx = _tracker.createInstance<UnloadStmtContext>(_ctx, getState());
  enterRule(_localctx, 216, VisualBasic6Parser::RuleUnloadStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2098);
    match(VisualBasic6Parser::UNLOAD);
    setState(2099);
    match(VisualBasic6Parser::WS);
    setState(2100);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- UnlockStmtContext ------------------------------------------------------------------

VisualBasic6Parser::UnlockStmtContext::UnlockStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::UnlockStmtContext::UNLOCK() {
  return getToken(VisualBasic6Parser::UNLOCK, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::UnlockStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::UnlockStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::UnlockStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::UnlockStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::UnlockStmtContext::COMMA() {
  return getToken(VisualBasic6Parser::COMMA, 0);
}

tree::TerminalNode* VisualBasic6Parser::UnlockStmtContext::TO() {
  return getToken(VisualBasic6Parser::TO, 0);
}


size_t VisualBasic6Parser::UnlockStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleUnlockStmt;
}

antlrcpp::Any VisualBasic6Parser::UnlockStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitUnlockStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::UnlockStmtContext* VisualBasic6Parser::unlockStmt() {
  UnlockStmtContext *_localctx = _tracker.createInstance<UnlockStmtContext>(_ctx, getState());
  enterRule(_localctx, 218, VisualBasic6Parser::RuleUnlockStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2102);
    match(VisualBasic6Parser::UNLOCK);
    setState(2103);
    match(VisualBasic6Parser::WS);
    setState(2104);
    valueStmt(0);
    setState(2119);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 330, _ctx)) {
    case 1: {
      setState(2106);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2105);
        match(VisualBasic6Parser::WS);
      }
      setState(2108);
      match(VisualBasic6Parser::COMMA);
      setState(2110);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 328, _ctx)) {
      case 1: {
        setState(2109);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(2112);
      valueStmt(0);
      setState(2117);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 329, _ctx)) {
      case 1: {
        setState(2113);
        match(VisualBasic6Parser::WS);
        setState(2114);
        match(VisualBasic6Parser::TO);
        setState(2115);
        match(VisualBasic6Parser::WS);
        setState(2116);
        valueStmt(0);
        break;
      }

      }
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

//----------------- ValueStmtContext ------------------------------------------------------------------

VisualBasic6Parser::ValueStmtContext::ValueStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}


size_t VisualBasic6Parser::ValueStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleValueStmt;
}

void VisualBasic6Parser::ValueStmtContext::copyFrom(ValueStmtContext *ctx) {
  ParserRuleContext::copyFrom(ctx);
}

//----------------- VsStructContext ------------------------------------------------------------------

tree::TerminalNode* VisualBasic6Parser::VsStructContext::LPAREN() {
  return getToken(VisualBasic6Parser::LPAREN, 0);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsStructContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsStructContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsStructContext::RPAREN() {
  return getToken(VisualBasic6Parser::RPAREN, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsStructContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsStructContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsStructContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::VsStructContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}

VisualBasic6Parser::VsStructContext::VsStructContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsStructContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsStruct(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsAddContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsAddContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsAddContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsAddContext::PLUS() {
  return getToken(VisualBasic6Parser::PLUS, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsAddContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsAddContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsAddContext::VsAddContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsAddContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsAdd(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsLtContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsLtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsLtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsLtContext::LT() {
  return getToken(VisualBasic6Parser::LT, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsLtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsLtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsLtContext::VsLtContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsLtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsLt(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsAddressOfContext ------------------------------------------------------------------

tree::TerminalNode* VisualBasic6Parser::VsAddressOfContext::ADDRESSOF() {
  return getToken(VisualBasic6Parser::ADDRESSOF, 0);
}

tree::TerminalNode* VisualBasic6Parser::VsAddressOfContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsAddressOfContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

VisualBasic6Parser::VsAddressOfContext::VsAddressOfContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsAddressOfContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsAddressOf(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsNewContext ------------------------------------------------------------------

tree::TerminalNode* VisualBasic6Parser::VsNewContext::NEW() {
  return getToken(VisualBasic6Parser::NEW, 0);
}

tree::TerminalNode* VisualBasic6Parser::VsNewContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsNewContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

VisualBasic6Parser::VsNewContext::VsNewContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsNewContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsNew(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsMultContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsMultContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsMultContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsMultContext::MULT() {
  return getToken(VisualBasic6Parser::MULT, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsMultContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsMultContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsMultContext::VsMultContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsMultContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsMult(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsNegationContext ------------------------------------------------------------------

tree::TerminalNode* VisualBasic6Parser::VsNegationContext::MINUS() {
  return getToken(VisualBasic6Parser::MINUS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsNegationContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::VsNegationContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::VsNegationContext::VsNegationContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsNegationContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsNegation(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsAssignContext ------------------------------------------------------------------

VisualBasic6Parser::ImplicitCallStmt_InStmtContext* VisualBasic6Parser::VsAssignContext::implicitCallStmt_InStmt() {
  return getRuleContext<VisualBasic6Parser::ImplicitCallStmt_InStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::VsAssignContext::ASSIGN() {
  return getToken(VisualBasic6Parser::ASSIGN, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsAssignContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsAssignContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsAssignContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsAssignContext::VsAssignContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsAssignContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsAssign(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsDivContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsDivContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsDivContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsDivContext::DIV() {
  return getToken(VisualBasic6Parser::DIV, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsDivContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsDivContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsDivContext::VsDivContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsDivContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsDiv(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsLikeContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsLikeContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsLikeContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsLikeContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsLikeContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

tree::TerminalNode* VisualBasic6Parser::VsLikeContext::LIKE() {
  return getToken(VisualBasic6Parser::LIKE, 0);
}

VisualBasic6Parser::VsLikeContext::VsLikeContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsLikeContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsLike(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsPlusContext ------------------------------------------------------------------

tree::TerminalNode* VisualBasic6Parser::VsPlusContext::PLUS() {
  return getToken(VisualBasic6Parser::PLUS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsPlusContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::VsPlusContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::VsPlusContext::VsPlusContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsPlusContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsPlus(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsNotContext ------------------------------------------------------------------

tree::TerminalNode* VisualBasic6Parser::VsNotContext::NOT() {
  return getToken(VisualBasic6Parser::NOT, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsNotContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsNotContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsNotContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::VsNotContext::LPAREN() {
  return getToken(VisualBasic6Parser::LPAREN, 0);
}

tree::TerminalNode* VisualBasic6Parser::VsNotContext::RPAREN() {
  return getToken(VisualBasic6Parser::RPAREN, 0);
}

VisualBasic6Parser::VsNotContext::VsNotContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsNotContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsNot(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsGeqContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsGeqContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsGeqContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsGeqContext::GEQ() {
  return getToken(VisualBasic6Parser::GEQ, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsGeqContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsGeqContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsGeqContext::VsGeqContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsGeqContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsGeq(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsTypeOfContext ------------------------------------------------------------------

VisualBasic6Parser::TypeOfStmtContext* VisualBasic6Parser::VsTypeOfContext::typeOfStmt() {
  return getRuleContext<VisualBasic6Parser::TypeOfStmtContext>(0);
}

VisualBasic6Parser::VsTypeOfContext::VsTypeOfContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsTypeOfContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsTypeOf(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsICSContext ------------------------------------------------------------------

VisualBasic6Parser::ImplicitCallStmt_InStmtContext* VisualBasic6Parser::VsICSContext::implicitCallStmt_InStmt() {
  return getRuleContext<VisualBasic6Parser::ImplicitCallStmt_InStmtContext>(0);
}

VisualBasic6Parser::VsICSContext::VsICSContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsICSContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsICS(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsNeqContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsNeqContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsNeqContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsNeqContext::NEQ() {
  return getToken(VisualBasic6Parser::NEQ, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsNeqContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsNeqContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsNeqContext::VsNeqContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsNeqContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsNeq(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsXorContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsXorContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsXorContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsXorContext::XOR() {
  return getToken(VisualBasic6Parser::XOR, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsXorContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsXorContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsXorContext::VsXorContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsXorContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsXor(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsAndContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsAndContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsAndContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsAndContext::AND() {
  return getToken(VisualBasic6Parser::AND, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsAndContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsAndContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsAndContext::VsAndContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsAndContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsAnd(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsPowContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsPowContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsPowContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsPowContext::POW() {
  return getToken(VisualBasic6Parser::POW, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsPowContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsPowContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsPowContext::VsPowContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsPowContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsPow(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsLeqContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsLeqContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsLeqContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsLeqContext::LEQ() {
  return getToken(VisualBasic6Parser::LEQ, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsLeqContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsLeqContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsLeqContext::VsLeqContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsLeqContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsLeq(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsIsContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsIsContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsIsContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsIsContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsIsContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

tree::TerminalNode* VisualBasic6Parser::VsIsContext::IS() {
  return getToken(VisualBasic6Parser::IS, 0);
}

VisualBasic6Parser::VsIsContext::VsIsContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsIsContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsIs(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsModContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsModContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsModContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsModContext::MOD() {
  return getToken(VisualBasic6Parser::MOD, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsModContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsModContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsModContext::VsModContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsModContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsMod(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsAmpContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsAmpContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsAmpContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsAmpContext::AMPERSAND() {
  return getToken(VisualBasic6Parser::AMPERSAND, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsAmpContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsAmpContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsAmpContext::VsAmpContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsAmpContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsAmp(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsOrContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsOrContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsOrContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsOrContext::OR() {
  return getToken(VisualBasic6Parser::OR, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsOrContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsOrContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsOrContext::VsOrContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsOrContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsOr(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsMinusContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsMinusContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsMinusContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsMinusContext::MINUS() {
  return getToken(VisualBasic6Parser::MINUS, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsMinusContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsMinusContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsMinusContext::VsMinusContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsMinusContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsMinus(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsLiteralContext ------------------------------------------------------------------

VisualBasic6Parser::LiteralContext* VisualBasic6Parser::VsLiteralContext::literal() {
  return getRuleContext<VisualBasic6Parser::LiteralContext>(0);
}

VisualBasic6Parser::VsLiteralContext::VsLiteralContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsLiteralContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsLiteral(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsEqvContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsEqvContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsEqvContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsEqvContext::EQV() {
  return getToken(VisualBasic6Parser::EQV, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsEqvContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsEqvContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsEqvContext::VsEqvContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsEqvContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsEqv(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsImpContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsImpContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsImpContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsImpContext::IMP() {
  return getToken(VisualBasic6Parser::IMP, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsImpContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsImpContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsImpContext::VsImpContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsImpContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsImp(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsGtContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsGtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsGtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsGtContext::GT() {
  return getToken(VisualBasic6Parser::GT, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsGtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsGtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsGtContext::VsGtContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsGtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsGt(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsEqContext ------------------------------------------------------------------

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::VsEqContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::VsEqContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::VsEqContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VsEqContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VsEqContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VsEqContext::VsEqContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsEqContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsEq(this);
  else
    return visitor->visitChildren(this);
}
//----------------- VsMidContext ------------------------------------------------------------------

VisualBasic6Parser::MidStmtContext* VisualBasic6Parser::VsMidContext::midStmt() {
  return getRuleContext<VisualBasic6Parser::MidStmtContext>(0);
}

VisualBasic6Parser::VsMidContext::VsMidContext(ValueStmtContext *ctx) { copyFrom(ctx); }

antlrcpp::Any VisualBasic6Parser::VsMidContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVsMid(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::valueStmt() {
   return valueStmt(0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::valueStmt(int precedence) {
  ParserRuleContext *parentContext = _ctx;
  size_t parentState = getState();
  VisualBasic6Parser::ValueStmtContext *_localctx = _tracker.createInstance<ValueStmtContext>(_ctx, parentState);
  VisualBasic6Parser::ValueStmtContext *previousContext = _localctx;
  size_t startState = 220;
  enterRecursionRule(_localctx, 220, VisualBasic6Parser::RuleValueStmt, precedence);

    size_t _la = 0;

  auto onExit = finally([=] {
    unrollRecursionContexts(parentContext);
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(2190);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 343, _ctx)) {
    case 1: {
      _localctx = _tracker.createInstance<VsLiteralContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;

      setState(2122);
      literal();
      break;
    }

    case 2: {
      _localctx = _tracker.createInstance<VsStructContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(2123);
      match(VisualBasic6Parser::LPAREN);
      setState(2125);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 331, _ctx)) {
      case 1: {
        setState(2124);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(2127);
      valueStmt(0);
      setState(2138);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 334, _ctx);
      while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
        if (alt == 1) {
          setState(2129);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2128);
            match(VisualBasic6Parser::WS);
          }
          setState(2131);
          match(VisualBasic6Parser::COMMA);
          setState(2133);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 333, _ctx)) {
          case 1: {
            setState(2132);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2135);
          valueStmt(0); 
        }
        setState(2140);
        _errHandler->sync(this);
        alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 334, _ctx);
      }
      setState(2142);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2141);
        match(VisualBasic6Parser::WS);
      }
      setState(2144);
      match(VisualBasic6Parser::RPAREN);
      break;
    }

    case 3: {
      _localctx = _tracker.createInstance<VsNewContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(2146);
      match(VisualBasic6Parser::NEW);
      setState(2147);
      match(VisualBasic6Parser::WS);
      setState(2148);
      valueStmt(29);
      break;
    }

    case 4: {
      _localctx = _tracker.createInstance<VsTypeOfContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(2149);
      typeOfStmt();
      break;
    }

    case 5: {
      _localctx = _tracker.createInstance<VsAddressOfContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(2150);
      match(VisualBasic6Parser::ADDRESSOF);
      setState(2151);
      match(VisualBasic6Parser::WS);
      setState(2152);
      valueStmt(27);
      break;
    }

    case 6: {
      _localctx = _tracker.createInstance<VsAssignContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(2153);
      implicitCallStmt_InStmt();
      setState(2155);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2154);
        match(VisualBasic6Parser::WS);
      }
      setState(2157);
      match(VisualBasic6Parser::ASSIGN);
      setState(2159);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 337, _ctx)) {
      case 1: {
        setState(2158);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(2161);
      valueStmt(26);
      break;
    }

    case 7: {
      _localctx = _tracker.createInstance<VsNegationContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(2163);
      match(VisualBasic6Parser::MINUS);
      setState(2165);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 338, _ctx)) {
      case 1: {
        setState(2164);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(2167);
      valueStmt(24);
      break;
    }

    case 8: {
      _localctx = _tracker.createInstance<VsPlusContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(2168);
      match(VisualBasic6Parser::PLUS);
      setState(2170);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 339, _ctx)) {
      case 1: {
        setState(2169);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(2172);
      valueStmt(23);
      break;
    }

    case 9: {
      _localctx = _tracker.createInstance<VsNotContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(2173);
      match(VisualBasic6Parser::NOT);
      setState(2186);
      _errHandler->sync(this);
      switch (_input->LA(1)) {
        case VisualBasic6Parser::WS: {
          setState(2174);
          match(VisualBasic6Parser::WS);
          setState(2175);
          valueStmt(0);
          break;
        }

        case VisualBasic6Parser::LPAREN: {
          setState(2176);
          match(VisualBasic6Parser::LPAREN);
          setState(2178);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 340, _ctx)) {
          case 1: {
            setState(2177);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2180);
          valueStmt(0);
          setState(2182);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2181);
            match(VisualBasic6Parser::WS);
          }
          setState(2184);
          match(VisualBasic6Parser::RPAREN);
          break;
        }

      default:
        throw NoViableAltException(this);
      }
      break;
    }

    case 10: {
      _localctx = _tracker.createInstance<VsICSContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(2188);
      implicitCallStmt_InStmt();
      break;
    }

    case 11: {
      _localctx = _tracker.createInstance<VsMidContext>(_localctx);
      _ctx = _localctx;
      previousContext = _localctx;
      setState(2189);
      midStmt();
      break;
    }

    }
    _ctx->stop = _input->LT(-1);
    setState(2366);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 381, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        if (!_parseListeners.empty())
          triggerExitRuleEvent();
        previousContext = _localctx;
        setState(2364);
        _errHandler->sync(this);
        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 380, _ctx)) {
        case 1: {
          auto newContext = _tracker.createInstance<VsPowContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2192);

          if (!(precpred(_ctx, 25))) throw FailedPredicateException(this, "precpred(_ctx, 25)");
          setState(2194);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2193);
            match(VisualBasic6Parser::WS);
          }
          setState(2196);
          match(VisualBasic6Parser::POW);
          setState(2198);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 345, _ctx)) {
          case 1: {
            setState(2197);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2200);
          valueStmt(26);
          break;
        }

        case 2: {
          auto newContext = _tracker.createInstance<VsDivContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2201);

          if (!(precpred(_ctx, 22))) throw FailedPredicateException(this, "precpred(_ctx, 22)");
          setState(2203);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2202);
            match(VisualBasic6Parser::WS);
          }
          setState(2205);
          match(VisualBasic6Parser::DIV);
          setState(2207);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 347, _ctx)) {
          case 1: {
            setState(2206);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2209);
          valueStmt(23);
          break;
        }

        case 3: {
          auto newContext = _tracker.createInstance<VsMultContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2210);

          if (!(precpred(_ctx, 21))) throw FailedPredicateException(this, "precpred(_ctx, 21)");
          setState(2212);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2211);
            match(VisualBasic6Parser::WS);
          }
          setState(2214);
          match(VisualBasic6Parser::MULT);
          setState(2216);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 349, _ctx)) {
          case 1: {
            setState(2215);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2218);
          valueStmt(22);
          break;
        }

        case 4: {
          auto newContext = _tracker.createInstance<VsModContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2219);

          if (!(precpred(_ctx, 20))) throw FailedPredicateException(this, "precpred(_ctx, 20)");
          setState(2221);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2220);
            match(VisualBasic6Parser::WS);
          }
          setState(2223);
          match(VisualBasic6Parser::MOD);
          setState(2225);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 351, _ctx)) {
          case 1: {
            setState(2224);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2227);
          valueStmt(21);
          break;
        }

        case 5: {
          auto newContext = _tracker.createInstance<VsAddContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2228);

          if (!(precpred(_ctx, 19))) throw FailedPredicateException(this, "precpred(_ctx, 19)");
          setState(2230);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2229);
            match(VisualBasic6Parser::WS);
          }
          setState(2232);
          match(VisualBasic6Parser::PLUS);
          setState(2234);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 353, _ctx)) {
          case 1: {
            setState(2233);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2236);
          valueStmt(20);
          break;
        }

        case 6: {
          auto newContext = _tracker.createInstance<VsMinusContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2237);

          if (!(precpred(_ctx, 18))) throw FailedPredicateException(this, "precpred(_ctx, 18)");
          setState(2239);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2238);
            match(VisualBasic6Parser::WS);
          }
          setState(2241);
          match(VisualBasic6Parser::MINUS);
          setState(2243);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 355, _ctx)) {
          case 1: {
            setState(2242);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2245);
          valueStmt(19);
          break;
        }

        case 7: {
          auto newContext = _tracker.createInstance<VsAmpContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2246);

          if (!(precpred(_ctx, 17))) throw FailedPredicateException(this, "precpred(_ctx, 17)");
          setState(2248);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2247);
            match(VisualBasic6Parser::WS);
          }
          setState(2250);
          match(VisualBasic6Parser::AMPERSAND);
          setState(2252);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 357, _ctx)) {
          case 1: {
            setState(2251);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2254);
          valueStmt(18);
          break;
        }

        case 8: {
          auto newContext = _tracker.createInstance<VsEqContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2255);

          if (!(precpred(_ctx, 16))) throw FailedPredicateException(this, "precpred(_ctx, 16)");
          setState(2257);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2256);
            match(VisualBasic6Parser::WS);
          }
          setState(2259);
          match(VisualBasic6Parser::EQ);
          setState(2261);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 359, _ctx)) {
          case 1: {
            setState(2260);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2263);
          valueStmt(17);
          break;
        }

        case 9: {
          auto newContext = _tracker.createInstance<VsNeqContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2264);

          if (!(precpred(_ctx, 15))) throw FailedPredicateException(this, "precpred(_ctx, 15)");
          setState(2266);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2265);
            match(VisualBasic6Parser::WS);
          }
          setState(2268);
          match(VisualBasic6Parser::NEQ);
          setState(2270);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 361, _ctx)) {
          case 1: {
            setState(2269);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2272);
          valueStmt(16);
          break;
        }

        case 10: {
          auto newContext = _tracker.createInstance<VsLtContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2273);

          if (!(precpred(_ctx, 14))) throw FailedPredicateException(this, "precpred(_ctx, 14)");
          setState(2275);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2274);
            match(VisualBasic6Parser::WS);
          }
          setState(2277);
          match(VisualBasic6Parser::LT);
          setState(2279);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 363, _ctx)) {
          case 1: {
            setState(2278);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2281);
          valueStmt(15);
          break;
        }

        case 11: {
          auto newContext = _tracker.createInstance<VsGtContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2282);

          if (!(precpred(_ctx, 13))) throw FailedPredicateException(this, "precpred(_ctx, 13)");
          setState(2284);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2283);
            match(VisualBasic6Parser::WS);
          }
          setState(2286);
          match(VisualBasic6Parser::GT);
          setState(2288);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 365, _ctx)) {
          case 1: {
            setState(2287);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2290);
          valueStmt(14);
          break;
        }

        case 12: {
          auto newContext = _tracker.createInstance<VsLeqContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2291);

          if (!(precpred(_ctx, 12))) throw FailedPredicateException(this, "precpred(_ctx, 12)");
          setState(2293);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2292);
            match(VisualBasic6Parser::WS);
          }
          setState(2295);
          match(VisualBasic6Parser::LEQ);
          setState(2297);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 367, _ctx)) {
          case 1: {
            setState(2296);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2299);
          valueStmt(13);
          break;
        }

        case 13: {
          auto newContext = _tracker.createInstance<VsGeqContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2300);

          if (!(precpred(_ctx, 11))) throw FailedPredicateException(this, "precpred(_ctx, 11)");
          setState(2302);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2301);
            match(VisualBasic6Parser::WS);
          }
          setState(2304);
          match(VisualBasic6Parser::GEQ);
          setState(2306);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 369, _ctx)) {
          case 1: {
            setState(2305);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2308);
          valueStmt(12);
          break;
        }

        case 14: {
          auto newContext = _tracker.createInstance<VsLikeContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2309);

          if (!(precpred(_ctx, 10))) throw FailedPredicateException(this, "precpred(_ctx, 10)");
          setState(2310);
          match(VisualBasic6Parser::WS);
          setState(2311);
          match(VisualBasic6Parser::LIKE);
          setState(2312);
          match(VisualBasic6Parser::WS);
          setState(2313);
          valueStmt(11);
          break;
        }

        case 15: {
          auto newContext = _tracker.createInstance<VsIsContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2314);

          if (!(precpred(_ctx, 9))) throw FailedPredicateException(this, "precpred(_ctx, 9)");
          setState(2315);
          match(VisualBasic6Parser::WS);
          setState(2316);
          match(VisualBasic6Parser::IS);
          setState(2317);
          match(VisualBasic6Parser::WS);
          setState(2318);
          valueStmt(10);
          break;
        }

        case 16: {
          auto newContext = _tracker.createInstance<VsAndContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2319);

          if (!(precpred(_ctx, 7))) throw FailedPredicateException(this, "precpred(_ctx, 7)");
          setState(2321);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2320);
            match(VisualBasic6Parser::WS);
          }
          setState(2323);
          match(VisualBasic6Parser::AND);
          setState(2325);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 371, _ctx)) {
          case 1: {
            setState(2324);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2327);
          valueStmt(8);
          break;
        }

        case 17: {
          auto newContext = _tracker.createInstance<VsOrContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2328);

          if (!(precpred(_ctx, 6))) throw FailedPredicateException(this, "precpred(_ctx, 6)");
          setState(2330);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2329);
            match(VisualBasic6Parser::WS);
          }
          setState(2332);
          match(VisualBasic6Parser::OR);
          setState(2334);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 373, _ctx)) {
          case 1: {
            setState(2333);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2336);
          valueStmt(7);
          break;
        }

        case 18: {
          auto newContext = _tracker.createInstance<VsXorContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2337);

          if (!(precpred(_ctx, 5))) throw FailedPredicateException(this, "precpred(_ctx, 5)");
          setState(2339);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2338);
            match(VisualBasic6Parser::WS);
          }
          setState(2341);
          match(VisualBasic6Parser::XOR);
          setState(2343);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 375, _ctx)) {
          case 1: {
            setState(2342);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2345);
          valueStmt(6);
          break;
        }

        case 19: {
          auto newContext = _tracker.createInstance<VsEqvContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2346);

          if (!(precpred(_ctx, 4))) throw FailedPredicateException(this, "precpred(_ctx, 4)");
          setState(2348);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2347);
            match(VisualBasic6Parser::WS);
          }
          setState(2350);
          match(VisualBasic6Parser::EQV);
          setState(2352);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 377, _ctx)) {
          case 1: {
            setState(2351);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2354);
          valueStmt(5);
          break;
        }

        case 20: {
          auto newContext = _tracker.createInstance<VsImpContext>(_tracker.createInstance<ValueStmtContext>(parentContext, parentState));
          _localctx = newContext;
          pushNewRecursionContext(newContext, startState, RuleValueStmt);
          setState(2355);

          if (!(precpred(_ctx, 3))) throw FailedPredicateException(this, "precpred(_ctx, 3)");
          setState(2357);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2356);
            match(VisualBasic6Parser::WS);
          }
          setState(2359);
          match(VisualBasic6Parser::IMP);
          setState(2361);
          _errHandler->sync(this);

          switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 379, _ctx)) {
          case 1: {
            setState(2360);
            match(VisualBasic6Parser::WS);
            break;
          }

          }
          setState(2363);
          valueStmt(4);
          break;
        }

        } 
      }
      setState(2368);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 381, _ctx);
    }
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }
  return _localctx;
}

//----------------- VariableStmtContext ------------------------------------------------------------------

VisualBasic6Parser::VariableStmtContext::VariableStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VariableStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VariableStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::VariableListStmtContext* VisualBasic6Parser::VariableStmtContext::variableListStmt() {
  return getRuleContext<VisualBasic6Parser::VariableListStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::VariableStmtContext::DIM() {
  return getToken(VisualBasic6Parser::DIM, 0);
}

tree::TerminalNode* VisualBasic6Parser::VariableStmtContext::STATIC() {
  return getToken(VisualBasic6Parser::STATIC, 0);
}

VisualBasic6Parser::VisibilityContext* VisualBasic6Parser::VariableStmtContext::visibility() {
  return getRuleContext<VisualBasic6Parser::VisibilityContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::VariableStmtContext::WITHEVENTS() {
  return getToken(VisualBasic6Parser::WITHEVENTS, 0);
}


size_t VisualBasic6Parser::VariableStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleVariableStmt;
}

antlrcpp::Any VisualBasic6Parser::VariableStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVariableStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::VariableStmtContext* VisualBasic6Parser::variableStmt() {
  VariableStmtContext *_localctx = _tracker.createInstance<VariableStmtContext>(_ctx, getState());
  enterRule(_localctx, 222, VisualBasic6Parser::RuleVariableStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2372);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case VisualBasic6Parser::DIM: {
        setState(2369);
        match(VisualBasic6Parser::DIM);
        break;
      }

      case VisualBasic6Parser::STATIC: {
        setState(2370);
        match(VisualBasic6Parser::STATIC);
        break;
      }

      case VisualBasic6Parser::FRIEND:
      case VisualBasic6Parser::GLOBAL:
      case VisualBasic6Parser::PRIVATE:
      case VisualBasic6Parser::PUBLIC: {
        setState(2371);
        visibility();
        break;
      }

    default:
      throw NoViableAltException(this);
    }
    setState(2374);
    match(VisualBasic6Parser::WS);
    setState(2377);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 383, _ctx)) {
    case 1: {
      setState(2375);
      match(VisualBasic6Parser::WITHEVENTS);
      setState(2376);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(2379);
    variableListStmt();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- VariableListStmtContext ------------------------------------------------------------------

VisualBasic6Parser::VariableListStmtContext::VariableListStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<VisualBasic6Parser::VariableSubStmtContext *> VisualBasic6Parser::VariableListStmtContext::variableSubStmt() {
  return getRuleContexts<VisualBasic6Parser::VariableSubStmtContext>();
}

VisualBasic6Parser::VariableSubStmtContext* VisualBasic6Parser::VariableListStmtContext::variableSubStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::VariableSubStmtContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VariableListStmtContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::VariableListStmtContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VariableListStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VariableListStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}


size_t VisualBasic6Parser::VariableListStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleVariableListStmt;
}

antlrcpp::Any VisualBasic6Parser::VariableListStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVariableListStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::VariableListStmtContext* VisualBasic6Parser::variableListStmt() {
  VariableListStmtContext *_localctx = _tracker.createInstance<VariableListStmtContext>(_ctx, getState());
  enterRule(_localctx, 224, VisualBasic6Parser::RuleVariableListStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(2381);
    variableSubStmt();
    setState(2392);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 386, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(2383);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(2382);
          match(VisualBasic6Parser::WS);
        }
        setState(2385);
        match(VisualBasic6Parser::COMMA);
        setState(2387);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(2386);
          match(VisualBasic6Parser::WS);
        }
        setState(2389);
        variableSubStmt(); 
      }
      setState(2394);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 386, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- VariableSubStmtContext ------------------------------------------------------------------

VisualBasic6Parser::VariableSubStmtContext::VariableSubStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::VariableSubStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

VisualBasic6Parser::TypeHintContext* VisualBasic6Parser::VariableSubStmtContext::typeHint() {
  return getRuleContext<VisualBasic6Parser::TypeHintContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::VariableSubStmtContext::LPAREN() {
  return getToken(VisualBasic6Parser::LPAREN, 0);
}

tree::TerminalNode* VisualBasic6Parser::VariableSubStmtContext::RPAREN() {
  return getToken(VisualBasic6Parser::RPAREN, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::VariableSubStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::VariableSubStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AsTypeClauseContext* VisualBasic6Parser::VariableSubStmtContext::asTypeClause() {
  return getRuleContext<VisualBasic6Parser::AsTypeClauseContext>(0);
}

VisualBasic6Parser::SubscriptsContext* VisualBasic6Parser::VariableSubStmtContext::subscripts() {
  return getRuleContext<VisualBasic6Parser::SubscriptsContext>(0);
}


size_t VisualBasic6Parser::VariableSubStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleVariableSubStmt;
}

antlrcpp::Any VisualBasic6Parser::VariableSubStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVariableSubStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::VariableSubStmtContext* VisualBasic6Parser::variableSubStmt() {
  VariableSubStmtContext *_localctx = _tracker.createInstance<VariableSubStmtContext>(_ctx, getState());
  enterRule(_localctx, 226, VisualBasic6Parser::RuleVariableSubStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2395);
    ambiguousIdentifier();
    setState(2397);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 387, _ctx)) {
    case 1: {
      setState(2396);
      typeHint();
      break;
    }

    }
    setState(2416);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 393, _ctx)) {
    case 1: {
      setState(2400);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2399);
        match(VisualBasic6Parser::WS);
      }
      setState(2402);
      match(VisualBasic6Parser::LPAREN);
      setState(2404);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 389, _ctx)) {
      case 1: {
        setState(2403);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(2410);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if ((((_la & ~ 0x3fULL) == 0) &&
        ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
        | (1ULL << VisualBasic6Parser::ADDRESSOF)
        | (1ULL << VisualBasic6Parser::ALIAS)
        | (1ULL << VisualBasic6Parser::AND)
        | (1ULL << VisualBasic6Parser::ATTRIBUTE)
        | (1ULL << VisualBasic6Parser::APPACTIVATE)
        | (1ULL << VisualBasic6Parser::APPEND)
        | (1ULL << VisualBasic6Parser::AS)
        | (1ULL << VisualBasic6Parser::BEEP)
        | (1ULL << VisualBasic6Parser::BEGIN)
        | (1ULL << VisualBasic6Parser::BINARY)
        | (1ULL << VisualBasic6Parser::BOOLEAN)
        | (1ULL << VisualBasic6Parser::BYVAL)
        | (1ULL << VisualBasic6Parser::BYREF)
        | (1ULL << VisualBasic6Parser::BYTE)
        | (1ULL << VisualBasic6Parser::CALL)
        | (1ULL << VisualBasic6Parser::CASE)
        | (1ULL << VisualBasic6Parser::CHDIR)
        | (1ULL << VisualBasic6Parser::CHDRIVE)
        | (1ULL << VisualBasic6Parser::CLASS)
        | (1ULL << VisualBasic6Parser::CLOSE)
        | (1ULL << VisualBasic6Parser::COLLECTION)
        | (1ULL << VisualBasic6Parser::CONST)
        | (1ULL << VisualBasic6Parser::DATE)
        | (1ULL << VisualBasic6Parser::DECLARE)
        | (1ULL << VisualBasic6Parser::DEFBOOL)
        | (1ULL << VisualBasic6Parser::DEFBYTE)
        | (1ULL << VisualBasic6Parser::DEFDATE)
        | (1ULL << VisualBasic6Parser::DEFDBL)
        | (1ULL << VisualBasic6Parser::DEFDEC)
        | (1ULL << VisualBasic6Parser::DEFCUR)
        | (1ULL << VisualBasic6Parser::DEFINT)
        | (1ULL << VisualBasic6Parser::DEFLNG)
        | (1ULL << VisualBasic6Parser::DEFOBJ)
        | (1ULL << VisualBasic6Parser::DEFSNG)
        | (1ULL << VisualBasic6Parser::DEFSTR)
        | (1ULL << VisualBasic6Parser::DEFVAR)
        | (1ULL << VisualBasic6Parser::DELETESETTING)
        | (1ULL << VisualBasic6Parser::DIM)
        | (1ULL << VisualBasic6Parser::DO)
        | (1ULL << VisualBasic6Parser::DOUBLE)
        | (1ULL << VisualBasic6Parser::EACH)
        | (1ULL << VisualBasic6Parser::ELSE)
        | (1ULL << VisualBasic6Parser::ELSEIF)
        | (1ULL << VisualBasic6Parser::END)
        | (1ULL << VisualBasic6Parser::ENUM)
        | (1ULL << VisualBasic6Parser::EQV)
        | (1ULL << VisualBasic6Parser::ERASE)
        | (1ULL << VisualBasic6Parser::ERROR)
        | (1ULL << VisualBasic6Parser::EVENT))) != 0) || ((((_la - 66) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 66)) & ((1ULL << (VisualBasic6Parser::FALSE1 - 66))
        | (1ULL << (VisualBasic6Parser::FILECOPY - 66))
        | (1ULL << (VisualBasic6Parser::FRIEND - 66))
        | (1ULL << (VisualBasic6Parser::FOR - 66))
        | (1ULL << (VisualBasic6Parser::FUNCTION - 66))
        | (1ULL << (VisualBasic6Parser::GET - 66))
        | (1ULL << (VisualBasic6Parser::GLOBAL - 66))
        | (1ULL << (VisualBasic6Parser::GOSUB - 66))
        | (1ULL << (VisualBasic6Parser::GOTO - 66))
        | (1ULL << (VisualBasic6Parser::IF - 66))
        | (1ULL << (VisualBasic6Parser::IMP - 66))
        | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 66))
        | (1ULL << (VisualBasic6Parser::IN - 66))
        | (1ULL << (VisualBasic6Parser::INPUT - 66))
        | (1ULL << (VisualBasic6Parser::IS - 66))
        | (1ULL << (VisualBasic6Parser::INTEGER - 66))
        | (1ULL << (VisualBasic6Parser::KILL - 66))
        | (1ULL << (VisualBasic6Parser::LOAD - 66))
        | (1ULL << (VisualBasic6Parser::LOCK - 66))
        | (1ULL << (VisualBasic6Parser::LONG - 66))
        | (1ULL << (VisualBasic6Parser::LOOP - 66))
        | (1ULL << (VisualBasic6Parser::LEN - 66))
        | (1ULL << (VisualBasic6Parser::LET - 66))
        | (1ULL << (VisualBasic6Parser::LIB - 66))
        | (1ULL << (VisualBasic6Parser::LIKE - 66))
        | (1ULL << (VisualBasic6Parser::LSET - 66))
        | (1ULL << (VisualBasic6Parser::ME - 66))
        | (1ULL << (VisualBasic6Parser::MID - 66))
        | (1ULL << (VisualBasic6Parser::MKDIR - 66))
        | (1ULL << (VisualBasic6Parser::MOD - 66))
        | (1ULL << (VisualBasic6Parser::NAME - 66))
        | (1ULL << (VisualBasic6Parser::NEXT - 66))
        | (1ULL << (VisualBasic6Parser::NEW - 66))
        | (1ULL << (VisualBasic6Parser::NOT - 66))
        | (1ULL << (VisualBasic6Parser::NOTHING - 66))
        | (1ULL << (VisualBasic6Parser::NULL1 - 66))
        | (1ULL << (VisualBasic6Parser::OBJECT - 66))
        | (1ULL << (VisualBasic6Parser::ON - 66))
        | (1ULL << (VisualBasic6Parser::OPEN - 66))
        | (1ULL << (VisualBasic6Parser::OPTIONAL - 66))
        | (1ULL << (VisualBasic6Parser::OR - 66))
        | (1ULL << (VisualBasic6Parser::OUTPUT - 66))
        | (1ULL << (VisualBasic6Parser::PARAMARRAY - 66))
        | (1ULL << (VisualBasic6Parser::PRESERVE - 66))
        | (1ULL << (VisualBasic6Parser::PRINT - 66))
        | (1ULL << (VisualBasic6Parser::PRIVATE - 66))
        | (1ULL << (VisualBasic6Parser::PUBLIC - 66)))) != 0) || ((((_la - 130) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 130)) & ((1ULL << (VisualBasic6Parser::PUT - 130))
        | (1ULL << (VisualBasic6Parser::RANDOM - 130))
        | (1ULL << (VisualBasic6Parser::RANDOMIZE - 130))
        | (1ULL << (VisualBasic6Parser::RAISEEVENT - 130))
        | (1ULL << (VisualBasic6Parser::READ - 130))
        | (1ULL << (VisualBasic6Parser::REDIM - 130))
        | (1ULL << (VisualBasic6Parser::REM - 130))
        | (1ULL << (VisualBasic6Parser::RESET - 130))
        | (1ULL << (VisualBasic6Parser::RESUME - 130))
        | (1ULL << (VisualBasic6Parser::RETURN - 130))
        | (1ULL << (VisualBasic6Parser::RMDIR - 130))
        | (1ULL << (VisualBasic6Parser::RSET - 130))
        | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 130))
        | (1ULL << (VisualBasic6Parser::SAVESETTING - 130))
        | (1ULL << (VisualBasic6Parser::SEEK - 130))
        | (1ULL << (VisualBasic6Parser::SELECT - 130))
        | (1ULL << (VisualBasic6Parser::SENDKEYS - 130))
        | (1ULL << (VisualBasic6Parser::SET - 130))
        | (1ULL << (VisualBasic6Parser::SETATTR - 130))
        | (1ULL << (VisualBasic6Parser::SHARED - 130))
        | (1ULL << (VisualBasic6Parser::SINGLE - 130))
        | (1ULL << (VisualBasic6Parser::SPC - 130))
        | (1ULL << (VisualBasic6Parser::STATIC - 130))
        | (1ULL << (VisualBasic6Parser::STEP - 130))
        | (1ULL << (VisualBasic6Parser::STOP - 130))
        | (1ULL << (VisualBasic6Parser::STRING - 130))
        | (1ULL << (VisualBasic6Parser::SUB - 130))
        | (1ULL << (VisualBasic6Parser::TAB - 130))
        | (1ULL << (VisualBasic6Parser::TEXT - 130))
        | (1ULL << (VisualBasic6Parser::THEN - 130))
        | (1ULL << (VisualBasic6Parser::TIME - 130))
        | (1ULL << (VisualBasic6Parser::TO - 130))
        | (1ULL << (VisualBasic6Parser::TRUE1 - 130))
        | (1ULL << (VisualBasic6Parser::TYPE - 130))
        | (1ULL << (VisualBasic6Parser::TYPEOF - 130))
        | (1ULL << (VisualBasic6Parser::UNLOAD - 130))
        | (1ULL << (VisualBasic6Parser::UNLOCK - 130))
        | (1ULL << (VisualBasic6Parser::UNTIL - 130))
        | (1ULL << (VisualBasic6Parser::VARIANT - 130))
        | (1ULL << (VisualBasic6Parser::VERSION - 130))
        | (1ULL << (VisualBasic6Parser::WEND - 130))
        | (1ULL << (VisualBasic6Parser::WHILE - 130))
        | (1ULL << (VisualBasic6Parser::WIDTH - 130))
        | (1ULL << (VisualBasic6Parser::WITH - 130))
        | (1ULL << (VisualBasic6Parser::WITHEVENTS - 130))
        | (1ULL << (VisualBasic6Parser::WRITE - 130))
        | (1ULL << (VisualBasic6Parser::XOR - 130))
        | (1ULL << (VisualBasic6Parser::DOT - 130))
        | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 130))
        | (1ULL << (VisualBasic6Parser::LPAREN - 130)))) != 0) || ((((_la - 195) & ~ 0x3fULL) == 0) &&
        ((1ULL << (_la - 195)) & ((1ULL << (VisualBasic6Parser::MINUS - 195))
        | (1ULL << (VisualBasic6Parser::PLUS - 195))
        | (1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 195))
        | (1ULL << (VisualBasic6Parser::STRINGLITERAL - 195))
        | (1ULL << (VisualBasic6Parser::DATELITERAL - 195))
        | (1ULL << (VisualBasic6Parser::COLORLITERAL - 195))
        | (1ULL << (VisualBasic6Parser::INTEGERLITERAL - 195))
        | (1ULL << (VisualBasic6Parser::DOUBLELITERAL - 195))
        | (1ULL << (VisualBasic6Parser::FILENUMBER - 195))
        | (1ULL << (VisualBasic6Parser::OCTALLITERAL - 195))
        | (1ULL << (VisualBasic6Parser::IDENTIFIER - 195))
        | (1ULL << (VisualBasic6Parser::WS - 195)))) != 0)) {
        setState(2406);
        subscripts();
        setState(2408);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(2407);
          match(VisualBasic6Parser::WS);
        }
      }
      setState(2412);
      match(VisualBasic6Parser::RPAREN);
      setState(2414);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 392, _ctx)) {
      case 1: {
        setState(2413);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      break;
    }

    }
    setState(2420);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 394, _ctx)) {
    case 1: {
      setState(2418);
      match(VisualBasic6Parser::WS);
      setState(2419);
      asTypeClause();
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

//----------------- WhileWendStmtContext ------------------------------------------------------------------

VisualBasic6Parser::WhileWendStmtContext::WhileWendStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::WhileWendStmtContext::WHILE() {
  return getToken(VisualBasic6Parser::WHILE, 0);
}

tree::TerminalNode* VisualBasic6Parser::WhileWendStmtContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::WhileWendStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::WhileWendStmtContext::WEND() {
  return getToken(VisualBasic6Parser::WEND, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::WhileWendStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::WhileWendStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

std::vector<VisualBasic6Parser::BlockContext *> VisualBasic6Parser::WhileWendStmtContext::block() {
  return getRuleContexts<VisualBasic6Parser::BlockContext>();
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::WhileWendStmtContext::block(size_t i) {
  return getRuleContext<VisualBasic6Parser::BlockContext>(i);
}


size_t VisualBasic6Parser::WhileWendStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleWhileWendStmt;
}

antlrcpp::Any VisualBasic6Parser::WhileWendStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitWhileWendStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::WhileWendStmtContext* VisualBasic6Parser::whileWendStmt() {
  WhileWendStmtContext *_localctx = _tracker.createInstance<WhileWendStmtContext>(_ctx, getState());
  enterRule(_localctx, 228, VisualBasic6Parser::RuleWhileWendStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(2422);
    match(VisualBasic6Parser::WHILE);
    setState(2423);
    match(VisualBasic6Parser::WS);
    setState(2424);
    valueStmt(0);
    setState(2426); 
    _errHandler->sync(this);
    alt = 1;
    do {
      switch (alt) {
        case 1: {
              setState(2425);
              match(VisualBasic6Parser::NEWLINE);
              break;
            }

      default:
        throw NoViableAltException(this);
      }
      setState(2428); 
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 395, _ctx);
    } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
    setState(2433);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 396, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(2430);
        block(); 
      }
      setState(2435);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 396, _ctx);
    }
    setState(2439);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == VisualBasic6Parser::NEWLINE) {
      setState(2436);
      match(VisualBasic6Parser::NEWLINE);
      setState(2441);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
    setState(2442);
    match(VisualBasic6Parser::WEND);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- WidthStmtContext ------------------------------------------------------------------

VisualBasic6Parser::WidthStmtContext::WidthStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::WidthStmtContext::WIDTH() {
  return getToken(VisualBasic6Parser::WIDTH, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::WidthStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::WidthStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::WidthStmtContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::WidthStmtContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::WidthStmtContext::COMMA() {
  return getToken(VisualBasic6Parser::COMMA, 0);
}


size_t VisualBasic6Parser::WidthStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleWidthStmt;
}

antlrcpp::Any VisualBasic6Parser::WidthStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitWidthStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::WidthStmtContext* VisualBasic6Parser::widthStmt() {
  WidthStmtContext *_localctx = _tracker.createInstance<WidthStmtContext>(_ctx, getState());
  enterRule(_localctx, 230, VisualBasic6Parser::RuleWidthStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2444);
    match(VisualBasic6Parser::WIDTH);
    setState(2445);
    match(VisualBasic6Parser::WS);
    setState(2446);
    valueStmt(0);
    setState(2448);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(2447);
      match(VisualBasic6Parser::WS);
    }
    setState(2450);
    match(VisualBasic6Parser::COMMA);
    setState(2452);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 399, _ctx)) {
    case 1: {
      setState(2451);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(2454);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- WithStmtContext ------------------------------------------------------------------

VisualBasic6Parser::WithStmtContext::WithStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::WithStmtContext::WITH() {
  return getToken(VisualBasic6Parser::WITH, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::WithStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::WithStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::ImplicitCallStmt_InStmtContext* VisualBasic6Parser::WithStmtContext::implicitCallStmt_InStmt() {
  return getRuleContext<VisualBasic6Parser::ImplicitCallStmt_InStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::WithStmtContext::END_WITH() {
  return getToken(VisualBasic6Parser::END_WITH, 0);
}

tree::TerminalNode* VisualBasic6Parser::WithStmtContext::NEW() {
  return getToken(VisualBasic6Parser::NEW, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::WithStmtContext::NEWLINE() {
  return getTokens(VisualBasic6Parser::NEWLINE);
}

tree::TerminalNode* VisualBasic6Parser::WithStmtContext::NEWLINE(size_t i) {
  return getToken(VisualBasic6Parser::NEWLINE, i);
}

VisualBasic6Parser::BlockContext* VisualBasic6Parser::WithStmtContext::block() {
  return getRuleContext<VisualBasic6Parser::BlockContext>(0);
}


size_t VisualBasic6Parser::WithStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleWithStmt;
}

antlrcpp::Any VisualBasic6Parser::WithStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitWithStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::WithStmtContext* VisualBasic6Parser::withStmt() {
  WithStmtContext *_localctx = _tracker.createInstance<WithStmtContext>(_ctx, getState());
  enterRule(_localctx, 232, VisualBasic6Parser::RuleWithStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2456);
    match(VisualBasic6Parser::WITH);
    setState(2457);
    match(VisualBasic6Parser::WS);
    setState(2460);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 400, _ctx)) {
    case 1: {
      setState(2458);
      match(VisualBasic6Parser::NEW);
      setState(2459);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(2462);
    implicitCallStmt_InStmt();
    setState(2464); 
    _errHandler->sync(this);
    _la = _input->LA(1);
    do {
      setState(2463);
      match(VisualBasic6Parser::NEWLINE);
      setState(2466); 
      _errHandler->sync(this);
      _la = _input->LA(1);
    } while (_la == VisualBasic6Parser::NEWLINE);
    setState(2474);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
      | (1ULL << VisualBasic6Parser::ADDRESSOF)
      | (1ULL << VisualBasic6Parser::ALIAS)
      | (1ULL << VisualBasic6Parser::AND)
      | (1ULL << VisualBasic6Parser::ATTRIBUTE)
      | (1ULL << VisualBasic6Parser::APPACTIVATE)
      | (1ULL << VisualBasic6Parser::APPEND)
      | (1ULL << VisualBasic6Parser::AS)
      | (1ULL << VisualBasic6Parser::BEEP)
      | (1ULL << VisualBasic6Parser::BEGIN)
      | (1ULL << VisualBasic6Parser::BINARY)
      | (1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYVAL)
      | (1ULL << VisualBasic6Parser::BYREF)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::CALL)
      | (1ULL << VisualBasic6Parser::CASE)
      | (1ULL << VisualBasic6Parser::CHDIR)
      | (1ULL << VisualBasic6Parser::CHDRIVE)
      | (1ULL << VisualBasic6Parser::CLASS)
      | (1ULL << VisualBasic6Parser::CLOSE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::CONST)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DECLARE)
      | (1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR)
      | (1ULL << VisualBasic6Parser::DELETESETTING)
      | (1ULL << VisualBasic6Parser::DIM)
      | (1ULL << VisualBasic6Parser::DO)
      | (1ULL << VisualBasic6Parser::DOUBLE)
      | (1ULL << VisualBasic6Parser::EACH)
      | (1ULL << VisualBasic6Parser::ELSE)
      | (1ULL << VisualBasic6Parser::ELSEIF)
      | (1ULL << VisualBasic6Parser::END)
      | (1ULL << VisualBasic6Parser::ENUM)
      | (1ULL << VisualBasic6Parser::EQV)
      | (1ULL << VisualBasic6Parser::ERASE)
      | (1ULL << VisualBasic6Parser::ERROR)
      | (1ULL << VisualBasic6Parser::EVENT)
      | (1ULL << VisualBasic6Parser::EXIT_DO)
      | (1ULL << VisualBasic6Parser::EXIT_FOR)
      | (1ULL << VisualBasic6Parser::EXIT_FUNCTION))) != 0) || ((((_la - 64) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 64)) & ((1ULL << (VisualBasic6Parser::EXIT_PROPERTY - 64))
      | (1ULL << (VisualBasic6Parser::EXIT_SUB - 64))
      | (1ULL << (VisualBasic6Parser::FALSE1 - 64))
      | (1ULL << (VisualBasic6Parser::FILECOPY - 64))
      | (1ULL << (VisualBasic6Parser::FRIEND - 64))
      | (1ULL << (VisualBasic6Parser::FOR - 64))
      | (1ULL << (VisualBasic6Parser::FUNCTION - 64))
      | (1ULL << (VisualBasic6Parser::GET - 64))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 64))
      | (1ULL << (VisualBasic6Parser::GOSUB - 64))
      | (1ULL << (VisualBasic6Parser::GOTO - 64))
      | (1ULL << (VisualBasic6Parser::IF - 64))
      | (1ULL << (VisualBasic6Parser::IMP - 64))
      | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 64))
      | (1ULL << (VisualBasic6Parser::IN - 64))
      | (1ULL << (VisualBasic6Parser::INPUT - 64))
      | (1ULL << (VisualBasic6Parser::IS - 64))
      | (1ULL << (VisualBasic6Parser::INTEGER - 64))
      | (1ULL << (VisualBasic6Parser::KILL - 64))
      | (1ULL << (VisualBasic6Parser::LOAD - 64))
      | (1ULL << (VisualBasic6Parser::LOCK - 64))
      | (1ULL << (VisualBasic6Parser::LONG - 64))
      | (1ULL << (VisualBasic6Parser::LOOP - 64))
      | (1ULL << (VisualBasic6Parser::LEN - 64))
      | (1ULL << (VisualBasic6Parser::LET - 64))
      | (1ULL << (VisualBasic6Parser::LIB - 64))
      | (1ULL << (VisualBasic6Parser::LIKE - 64))
      | (1ULL << (VisualBasic6Parser::LINE_INPUT - 64))
      | (1ULL << (VisualBasic6Parser::LSET - 64))
      | (1ULL << (VisualBasic6Parser::MACRO_IF - 64))
      | (1ULL << (VisualBasic6Parser::ME - 64))
      | (1ULL << (VisualBasic6Parser::MID - 64))
      | (1ULL << (VisualBasic6Parser::MKDIR - 64))
      | (1ULL << (VisualBasic6Parser::MOD - 64))
      | (1ULL << (VisualBasic6Parser::NAME - 64))
      | (1ULL << (VisualBasic6Parser::NEXT - 64))
      | (1ULL << (VisualBasic6Parser::NEW - 64))
      | (1ULL << (VisualBasic6Parser::NOT - 64))
      | (1ULL << (VisualBasic6Parser::NOTHING - 64))
      | (1ULL << (VisualBasic6Parser::NULL1 - 64))
      | (1ULL << (VisualBasic6Parser::OBJECT - 64))
      | (1ULL << (VisualBasic6Parser::ON - 64))
      | (1ULL << (VisualBasic6Parser::ON_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::ON_LOCAL_ERROR - 64))
      | (1ULL << (VisualBasic6Parser::OPEN - 64))
      | (1ULL << (VisualBasic6Parser::OPTIONAL - 64))
      | (1ULL << (VisualBasic6Parser::OR - 64))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 64))
      | (1ULL << (VisualBasic6Parser::PARAMARRAY - 64))
      | (1ULL << (VisualBasic6Parser::PRESERVE - 64))
      | (1ULL << (VisualBasic6Parser::PRINT - 64))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 64)))) != 0) || ((((_la - 129) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 129)) & ((1ULL << (VisualBasic6Parser::PUBLIC - 129))
      | (1ULL << (VisualBasic6Parser::PUT - 129))
      | (1ULL << (VisualBasic6Parser::RANDOM - 129))
      | (1ULL << (VisualBasic6Parser::RANDOMIZE - 129))
      | (1ULL << (VisualBasic6Parser::RAISEEVENT - 129))
      | (1ULL << (VisualBasic6Parser::READ - 129))
      | (1ULL << (VisualBasic6Parser::REDIM - 129))
      | (1ULL << (VisualBasic6Parser::REM - 129))
      | (1ULL << (VisualBasic6Parser::RESET - 129))
      | (1ULL << (VisualBasic6Parser::RESUME - 129))
      | (1ULL << (VisualBasic6Parser::RETURN - 129))
      | (1ULL << (VisualBasic6Parser::RMDIR - 129))
      | (1ULL << (VisualBasic6Parser::RSET - 129))
      | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 129))
      | (1ULL << (VisualBasic6Parser::SAVESETTING - 129))
      | (1ULL << (VisualBasic6Parser::SEEK - 129))
      | (1ULL << (VisualBasic6Parser::SELECT - 129))
      | (1ULL << (VisualBasic6Parser::SENDKEYS - 129))
      | (1ULL << (VisualBasic6Parser::SET - 129))
      | (1ULL << (VisualBasic6Parser::SETATTR - 129))
      | (1ULL << (VisualBasic6Parser::SHARED - 129))
      | (1ULL << (VisualBasic6Parser::SINGLE - 129))
      | (1ULL << (VisualBasic6Parser::SPC - 129))
      | (1ULL << (VisualBasic6Parser::STATIC - 129))
      | (1ULL << (VisualBasic6Parser::STEP - 129))
      | (1ULL << (VisualBasic6Parser::STOP - 129))
      | (1ULL << (VisualBasic6Parser::STRING - 129))
      | (1ULL << (VisualBasic6Parser::SUB - 129))
      | (1ULL << (VisualBasic6Parser::TAB - 129))
      | (1ULL << (VisualBasic6Parser::TEXT - 129))
      | (1ULL << (VisualBasic6Parser::THEN - 129))
      | (1ULL << (VisualBasic6Parser::TIME - 129))
      | (1ULL << (VisualBasic6Parser::TO - 129))
      | (1ULL << (VisualBasic6Parser::TRUE1 - 129))
      | (1ULL << (VisualBasic6Parser::TYPE - 129))
      | (1ULL << (VisualBasic6Parser::TYPEOF - 129))
      | (1ULL << (VisualBasic6Parser::UNLOAD - 129))
      | (1ULL << (VisualBasic6Parser::UNLOCK - 129))
      | (1ULL << (VisualBasic6Parser::UNTIL - 129))
      | (1ULL << (VisualBasic6Parser::VARIANT - 129))
      | (1ULL << (VisualBasic6Parser::VERSION - 129))
      | (1ULL << (VisualBasic6Parser::WEND - 129))
      | (1ULL << (VisualBasic6Parser::WHILE - 129))
      | (1ULL << (VisualBasic6Parser::WIDTH - 129))
      | (1ULL << (VisualBasic6Parser::WITH - 129))
      | (1ULL << (VisualBasic6Parser::WITHEVENTS - 129))
      | (1ULL << (VisualBasic6Parser::WRITE - 129))
      | (1ULL << (VisualBasic6Parser::XOR - 129))
      | (1ULL << (VisualBasic6Parser::DOT - 129))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 129)))) != 0) || ((((_la - 206) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 206)) & ((1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 206))
      | (1ULL << (VisualBasic6Parser::IDENTIFIER - 206))
      | (1ULL << (VisualBasic6Parser::WS - 206)))) != 0)) {
      setState(2468);
      block();
      setState(2470); 
      _errHandler->sync(this);
      _la = _input->LA(1);
      do {
        setState(2469);
        match(VisualBasic6Parser::NEWLINE);
        setState(2472); 
        _errHandler->sync(this);
        _la = _input->LA(1);
      } while (_la == VisualBasic6Parser::NEWLINE);
    }
    setState(2476);
    match(VisualBasic6Parser::END_WITH);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- WriteStmtContext ------------------------------------------------------------------

VisualBasic6Parser::WriteStmtContext::WriteStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::WriteStmtContext::WRITE() {
  return getToken(VisualBasic6Parser::WRITE, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::WriteStmtContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::WriteStmtContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::WriteStmtContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::WriteStmtContext::COMMA() {
  return getToken(VisualBasic6Parser::COMMA, 0);
}

VisualBasic6Parser::OutputListContext* VisualBasic6Parser::WriteStmtContext::outputList() {
  return getRuleContext<VisualBasic6Parser::OutputListContext>(0);
}


size_t VisualBasic6Parser::WriteStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleWriteStmt;
}

antlrcpp::Any VisualBasic6Parser::WriteStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitWriteStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::WriteStmtContext* VisualBasic6Parser::writeStmt() {
  WriteStmtContext *_localctx = _tracker.createInstance<WriteStmtContext>(_ctx, getState());
  enterRule(_localctx, 234, VisualBasic6Parser::RuleWriteStmt);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2478);
    match(VisualBasic6Parser::WRITE);
    setState(2479);
    match(VisualBasic6Parser::WS);
    setState(2480);
    valueStmt(0);
    setState(2482);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(2481);
      match(VisualBasic6Parser::WS);
    }
    setState(2484);
    match(VisualBasic6Parser::COMMA);
    setState(2489);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 406, _ctx)) {
    case 1: {
      setState(2486);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 405, _ctx)) {
      case 1: {
        setState(2485);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(2488);
      outputList();
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

//----------------- ExplicitCallStmtContext ------------------------------------------------------------------

VisualBasic6Parser::ExplicitCallStmtContext::ExplicitCallStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::ECS_ProcedureCallContext* VisualBasic6Parser::ExplicitCallStmtContext::eCS_ProcedureCall() {
  return getRuleContext<VisualBasic6Parser::ECS_ProcedureCallContext>(0);
}

VisualBasic6Parser::ECS_MemberProcedureCallContext* VisualBasic6Parser::ExplicitCallStmtContext::eCS_MemberProcedureCall() {
  return getRuleContext<VisualBasic6Parser::ECS_MemberProcedureCallContext>(0);
}


size_t VisualBasic6Parser::ExplicitCallStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleExplicitCallStmt;
}

antlrcpp::Any VisualBasic6Parser::ExplicitCallStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitExplicitCallStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ExplicitCallStmtContext* VisualBasic6Parser::explicitCallStmt() {
  ExplicitCallStmtContext *_localctx = _tracker.createInstance<ExplicitCallStmtContext>(_ctx, getState());
  enterRule(_localctx, 236, VisualBasic6Parser::RuleExplicitCallStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(2493);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 407, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(2491);
      eCS_ProcedureCall();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(2492);
      eCS_MemberProcedureCall();
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

//----------------- ECS_ProcedureCallContext ------------------------------------------------------------------

VisualBasic6Parser::ECS_ProcedureCallContext::ECS_ProcedureCallContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ECS_ProcedureCallContext::CALL() {
  return getToken(VisualBasic6Parser::CALL, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ECS_ProcedureCallContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ECS_ProcedureCallContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::ECS_ProcedureCallContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

VisualBasic6Parser::TypeHintContext* VisualBasic6Parser::ECS_ProcedureCallContext::typeHint() {
  return getRuleContext<VisualBasic6Parser::TypeHintContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ECS_ProcedureCallContext::LPAREN() {
  return getToken(VisualBasic6Parser::LPAREN, 0);
}

VisualBasic6Parser::ArgsCallContext* VisualBasic6Parser::ECS_ProcedureCallContext::argsCall() {
  return getRuleContext<VisualBasic6Parser::ArgsCallContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ECS_ProcedureCallContext::RPAREN() {
  return getToken(VisualBasic6Parser::RPAREN, 0);
}


size_t VisualBasic6Parser::ECS_ProcedureCallContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleECS_ProcedureCall;
}

antlrcpp::Any VisualBasic6Parser::ECS_ProcedureCallContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitECS_ProcedureCall(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ECS_ProcedureCallContext* VisualBasic6Parser::eCS_ProcedureCall() {
  ECS_ProcedureCallContext *_localctx = _tracker.createInstance<ECS_ProcedureCallContext>(_ctx, getState());
  enterRule(_localctx, 238, VisualBasic6Parser::RuleECS_ProcedureCall);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2495);
    match(VisualBasic6Parser::CALL);
    setState(2496);
    match(VisualBasic6Parser::WS);
    setState(2497);
    ambiguousIdentifier();
    setState(2499);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 408, _ctx)) {
    case 1: {
      setState(2498);
      typeHint();
      break;
    }

    }
    setState(2514);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 412, _ctx)) {
    case 1: {
      setState(2502);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2501);
        match(VisualBasic6Parser::WS);
      }
      setState(2504);
      match(VisualBasic6Parser::LPAREN);
      setState(2506);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 410, _ctx)) {
      case 1: {
        setState(2505);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(2508);
      argsCall();
      setState(2510);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2509);
        match(VisualBasic6Parser::WS);
      }
      setState(2512);
      match(VisualBasic6Parser::RPAREN);
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

//----------------- ECS_MemberProcedureCallContext ------------------------------------------------------------------

VisualBasic6Parser::ECS_MemberProcedureCallContext::ECS_MemberProcedureCallContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ECS_MemberProcedureCallContext::CALL() {
  return getToken(VisualBasic6Parser::CALL, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ECS_MemberProcedureCallContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ECS_MemberProcedureCallContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

tree::TerminalNode* VisualBasic6Parser::ECS_MemberProcedureCallContext::DOT() {
  return getToken(VisualBasic6Parser::DOT, 0);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::ECS_MemberProcedureCallContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

VisualBasic6Parser::ImplicitCallStmt_InStmtContext* VisualBasic6Parser::ECS_MemberProcedureCallContext::implicitCallStmt_InStmt() {
  return getRuleContext<VisualBasic6Parser::ImplicitCallStmt_InStmtContext>(0);
}

VisualBasic6Parser::TypeHintContext* VisualBasic6Parser::ECS_MemberProcedureCallContext::typeHint() {
  return getRuleContext<VisualBasic6Parser::TypeHintContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ECS_MemberProcedureCallContext::LPAREN() {
  return getToken(VisualBasic6Parser::LPAREN, 0);
}

VisualBasic6Parser::ArgsCallContext* VisualBasic6Parser::ECS_MemberProcedureCallContext::argsCall() {
  return getRuleContext<VisualBasic6Parser::ArgsCallContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ECS_MemberProcedureCallContext::RPAREN() {
  return getToken(VisualBasic6Parser::RPAREN, 0);
}


size_t VisualBasic6Parser::ECS_MemberProcedureCallContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleECS_MemberProcedureCall;
}

antlrcpp::Any VisualBasic6Parser::ECS_MemberProcedureCallContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitECS_MemberProcedureCall(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ECS_MemberProcedureCallContext* VisualBasic6Parser::eCS_MemberProcedureCall() {
  ECS_MemberProcedureCallContext *_localctx = _tracker.createInstance<ECS_MemberProcedureCallContext>(_ctx, getState());
  enterRule(_localctx, 240, VisualBasic6Parser::RuleECS_MemberProcedureCall);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2516);
    match(VisualBasic6Parser::CALL);
    setState(2517);
    match(VisualBasic6Parser::WS);
    setState(2519);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 413, _ctx)) {
    case 1: {
      setState(2518);
      implicitCallStmt_InStmt();
      break;
    }

    }
    setState(2521);
    match(VisualBasic6Parser::DOT);
    setState(2523);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(2522);
      match(VisualBasic6Parser::WS);
    }
    setState(2525);
    ambiguousIdentifier();
    setState(2527);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 415, _ctx)) {
    case 1: {
      setState(2526);
      typeHint();
      break;
    }

    }
    setState(2542);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 419, _ctx)) {
    case 1: {
      setState(2530);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2529);
        match(VisualBasic6Parser::WS);
      }
      setState(2532);
      match(VisualBasic6Parser::LPAREN);
      setState(2534);
      _errHandler->sync(this);

      switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 417, _ctx)) {
      case 1: {
        setState(2533);
        match(VisualBasic6Parser::WS);
        break;
      }

      }
      setState(2536);
      argsCall();
      setState(2538);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2537);
        match(VisualBasic6Parser::WS);
      }
      setState(2540);
      match(VisualBasic6Parser::RPAREN);
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

//----------------- ImplicitCallStmt_InBlockContext ------------------------------------------------------------------

VisualBasic6Parser::ImplicitCallStmt_InBlockContext::ImplicitCallStmt_InBlockContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::ICS_B_ProcedureCallContext* VisualBasic6Parser::ImplicitCallStmt_InBlockContext::iCS_B_ProcedureCall() {
  return getRuleContext<VisualBasic6Parser::ICS_B_ProcedureCallContext>(0);
}

VisualBasic6Parser::ICS_B_MemberProcedureCallContext* VisualBasic6Parser::ImplicitCallStmt_InBlockContext::iCS_B_MemberProcedureCall() {
  return getRuleContext<VisualBasic6Parser::ICS_B_MemberProcedureCallContext>(0);
}


size_t VisualBasic6Parser::ImplicitCallStmt_InBlockContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleImplicitCallStmt_InBlock;
}

antlrcpp::Any VisualBasic6Parser::ImplicitCallStmt_InBlockContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitImplicitCallStmt_InBlock(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ImplicitCallStmt_InBlockContext* VisualBasic6Parser::implicitCallStmt_InBlock() {
  ImplicitCallStmt_InBlockContext *_localctx = _tracker.createInstance<ImplicitCallStmt_InBlockContext>(_ctx, getState());
  enterRule(_localctx, 242, VisualBasic6Parser::RuleImplicitCallStmt_InBlock);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(2546);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 420, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(2544);
      iCS_B_ProcedureCall();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(2545);
      iCS_B_MemberProcedureCall();
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

//----------------- ICS_B_ProcedureCallContext ------------------------------------------------------------------

VisualBasic6Parser::ICS_B_ProcedureCallContext::ICS_B_ProcedureCallContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::CertainIdentifierContext* VisualBasic6Parser::ICS_B_ProcedureCallContext::certainIdentifier() {
  return getRuleContext<VisualBasic6Parser::CertainIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ICS_B_ProcedureCallContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ArgsCallContext* VisualBasic6Parser::ICS_B_ProcedureCallContext::argsCall() {
  return getRuleContext<VisualBasic6Parser::ArgsCallContext>(0);
}


size_t VisualBasic6Parser::ICS_B_ProcedureCallContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleICS_B_ProcedureCall;
}

antlrcpp::Any VisualBasic6Parser::ICS_B_ProcedureCallContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitICS_B_ProcedureCall(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ICS_B_ProcedureCallContext* VisualBasic6Parser::iCS_B_ProcedureCall() {
  ICS_B_ProcedureCallContext *_localctx = _tracker.createInstance<ICS_B_ProcedureCallContext>(_ctx, getState());
  enterRule(_localctx, 244, VisualBasic6Parser::RuleICS_B_ProcedureCall);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2548);
    certainIdentifier();
    setState(2551);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 421, _ctx)) {
    case 1: {
      setState(2549);
      match(VisualBasic6Parser::WS);
      setState(2550);
      argsCall();
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

//----------------- ICS_B_MemberProcedureCallContext ------------------------------------------------------------------

VisualBasic6Parser::ICS_B_MemberProcedureCallContext::ICS_B_MemberProcedureCallContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ICS_B_MemberProcedureCallContext::DOT() {
  return getToken(VisualBasic6Parser::DOT, 0);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::ICS_B_MemberProcedureCallContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

VisualBasic6Parser::ImplicitCallStmt_InStmtContext* VisualBasic6Parser::ICS_B_MemberProcedureCallContext::implicitCallStmt_InStmt() {
  return getRuleContext<VisualBasic6Parser::ImplicitCallStmt_InStmtContext>(0);
}

VisualBasic6Parser::TypeHintContext* VisualBasic6Parser::ICS_B_MemberProcedureCallContext::typeHint() {
  return getRuleContext<VisualBasic6Parser::TypeHintContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ICS_B_MemberProcedureCallContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

VisualBasic6Parser::ArgsCallContext* VisualBasic6Parser::ICS_B_MemberProcedureCallContext::argsCall() {
  return getRuleContext<VisualBasic6Parser::ArgsCallContext>(0);
}

VisualBasic6Parser::DictionaryCallStmtContext* VisualBasic6Parser::ICS_B_MemberProcedureCallContext::dictionaryCallStmt() {
  return getRuleContext<VisualBasic6Parser::DictionaryCallStmtContext>(0);
}


size_t VisualBasic6Parser::ICS_B_MemberProcedureCallContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleICS_B_MemberProcedureCall;
}

antlrcpp::Any VisualBasic6Parser::ICS_B_MemberProcedureCallContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitICS_B_MemberProcedureCall(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ICS_B_MemberProcedureCallContext* VisualBasic6Parser::iCS_B_MemberProcedureCall() {
  ICS_B_MemberProcedureCallContext *_localctx = _tracker.createInstance<ICS_B_MemberProcedureCallContext>(_ctx, getState());
  enterRule(_localctx, 246, VisualBasic6Parser::RuleICS_B_MemberProcedureCall);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2554);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 422, _ctx)) {
    case 1: {
      setState(2553);
      implicitCallStmt_InStmt();
      break;
    }

    }
    setState(2556);
    match(VisualBasic6Parser::DOT);
    setState(2557);
    ambiguousIdentifier();
    setState(2559);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 423, _ctx)) {
    case 1: {
      setState(2558);
      typeHint();
      break;
    }

    }
    setState(2563);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 424, _ctx)) {
    case 1: {
      setState(2561);
      match(VisualBasic6Parser::WS);
      setState(2562);
      argsCall();
      break;
    }

    }
    setState(2566);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 425, _ctx)) {
    case 1: {
      setState(2565);
      dictionaryCallStmt();
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

//----------------- ImplicitCallStmt_InStmtContext ------------------------------------------------------------------

VisualBasic6Parser::ImplicitCallStmt_InStmtContext::ImplicitCallStmt_InStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::ICS_S_MembersCallContext* VisualBasic6Parser::ImplicitCallStmt_InStmtContext::iCS_S_MembersCall() {
  return getRuleContext<VisualBasic6Parser::ICS_S_MembersCallContext>(0);
}

VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext* VisualBasic6Parser::ImplicitCallStmt_InStmtContext::iCS_S_VariableOrProcedureCall() {
  return getRuleContext<VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext>(0);
}

VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext* VisualBasic6Parser::ImplicitCallStmt_InStmtContext::iCS_S_ProcedureOrArrayCall() {
  return getRuleContext<VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext>(0);
}

VisualBasic6Parser::ICS_S_DictionaryCallContext* VisualBasic6Parser::ImplicitCallStmt_InStmtContext::iCS_S_DictionaryCall() {
  return getRuleContext<VisualBasic6Parser::ICS_S_DictionaryCallContext>(0);
}


size_t VisualBasic6Parser::ImplicitCallStmt_InStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleImplicitCallStmt_InStmt;
}

antlrcpp::Any VisualBasic6Parser::ImplicitCallStmt_InStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitImplicitCallStmt_InStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ImplicitCallStmt_InStmtContext* VisualBasic6Parser::implicitCallStmt_InStmt() {
  ImplicitCallStmt_InStmtContext *_localctx = _tracker.createInstance<ImplicitCallStmt_InStmtContext>(_ctx, getState());
  enterRule(_localctx, 248, VisualBasic6Parser::RuleImplicitCallStmt_InStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(2572);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 426, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(2568);
      iCS_S_MembersCall();
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(2569);
      iCS_S_VariableOrProcedureCall();
      break;
    }

    case 3: {
      enterOuterAlt(_localctx, 3);
      setState(2570);
      iCS_S_ProcedureOrArrayCall();
      break;
    }

    case 4: {
      enterOuterAlt(_localctx, 4);
      setState(2571);
      iCS_S_DictionaryCall();
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

//----------------- ICS_S_VariableOrProcedureCallContext ------------------------------------------------------------------

VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext::ICS_S_VariableOrProcedureCallContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

VisualBasic6Parser::TypeHintContext* VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext::typeHint() {
  return getRuleContext<VisualBasic6Parser::TypeHintContext>(0);
}

VisualBasic6Parser::DictionaryCallStmtContext* VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext::dictionaryCallStmt() {
  return getRuleContext<VisualBasic6Parser::DictionaryCallStmtContext>(0);
}


size_t VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleICS_S_VariableOrProcedureCall;
}

antlrcpp::Any VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitICS_S_VariableOrProcedureCall(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext* VisualBasic6Parser::iCS_S_VariableOrProcedureCall() {
  ICS_S_VariableOrProcedureCallContext *_localctx = _tracker.createInstance<ICS_S_VariableOrProcedureCallContext>(_ctx, getState());
  enterRule(_localctx, 250, VisualBasic6Parser::RuleICS_S_VariableOrProcedureCall);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2574);
    ambiguousIdentifier();
    setState(2576);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 427, _ctx)) {
    case 1: {
      setState(2575);
      typeHint();
      break;
    }

    }
    setState(2579);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 428, _ctx)) {
    case 1: {
      setState(2578);
      dictionaryCallStmt();
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

//----------------- ICS_S_ProcedureOrArrayCallContext ------------------------------------------------------------------

VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::ICS_S_ProcedureOrArrayCallContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

VisualBasic6Parser::BaseTypeContext* VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::baseType() {
  return getRuleContext<VisualBasic6Parser::BaseTypeContext>(0);
}

VisualBasic6Parser::ICS_S_NestedProcedureCallContext* VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::iCS_S_NestedProcedureCall() {
  return getRuleContext<VisualBasic6Parser::ICS_S_NestedProcedureCallContext>(0);
}

VisualBasic6Parser::TypeHintContext* VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::typeHint() {
  return getRuleContext<VisualBasic6Parser::TypeHintContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::LPAREN() {
  return getTokens(VisualBasic6Parser::LPAREN);
}

tree::TerminalNode* VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::LPAREN(size_t i) {
  return getToken(VisualBasic6Parser::LPAREN, i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::RPAREN() {
  return getTokens(VisualBasic6Parser::RPAREN);
}

tree::TerminalNode* VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::RPAREN(size_t i) {
  return getToken(VisualBasic6Parser::RPAREN, i);
}

VisualBasic6Parser::DictionaryCallStmtContext* VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::dictionaryCallStmt() {
  return getRuleContext<VisualBasic6Parser::DictionaryCallStmtContext>(0);
}

std::vector<VisualBasic6Parser::ArgsCallContext *> VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::argsCall() {
  return getRuleContexts<VisualBasic6Parser::ArgsCallContext>();
}

VisualBasic6Parser::ArgsCallContext* VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::argsCall(size_t i) {
  return getRuleContext<VisualBasic6Parser::ArgsCallContext>(i);
}


size_t VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleICS_S_ProcedureOrArrayCall;
}

antlrcpp::Any VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitICS_S_ProcedureOrArrayCall(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext* VisualBasic6Parser::iCS_S_ProcedureOrArrayCall() {
  ICS_S_ProcedureOrArrayCallContext *_localctx = _tracker.createInstance<ICS_S_ProcedureOrArrayCallContext>(_ctx, getState());
  enterRule(_localctx, 252, VisualBasic6Parser::RuleICS_S_ProcedureOrArrayCall);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(2584);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 429, _ctx)) {
    case 1: {
      setState(2581);
      ambiguousIdentifier();
      break;
    }

    case 2: {
      setState(2582);
      baseType();
      break;
    }

    case 3: {
      setState(2583);
      iCS_S_NestedProcedureCall();
      break;
    }

    }
    setState(2587);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 178) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 178)) & ((1ULL << (VisualBasic6Parser::AMPERSAND - 178))
      | (1ULL << (VisualBasic6Parser::AT - 178))
      | (1ULL << (VisualBasic6Parser::DOLLAR - 178))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 178))
      | (1ULL << (VisualBasic6Parser::HASH - 178))
      | (1ULL << (VisualBasic6Parser::PERCENT - 178)))) != 0)) {
      setState(2586);
      typeHint();
    }
    setState(2590);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(2589);
      match(VisualBasic6Parser::WS);
    }
    setState(2603); 
    _errHandler->sync(this);
    alt = 1;
    do {
      switch (alt) {
        case 1: {
              setState(2592);
              match(VisualBasic6Parser::LPAREN);
              setState(2594);
              _errHandler->sync(this);

              switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 432, _ctx)) {
              case 1: {
                setState(2593);
                match(VisualBasic6Parser::WS);
                break;
              }

              }
              setState(2600);
              _errHandler->sync(this);

              _la = _input->LA(1);
              if ((((_la & ~ 0x3fULL) == 0) &&
                ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
                | (1ULL << VisualBasic6Parser::ADDRESSOF)
                | (1ULL << VisualBasic6Parser::ALIAS)
                | (1ULL << VisualBasic6Parser::AND)
                | (1ULL << VisualBasic6Parser::ATTRIBUTE)
                | (1ULL << VisualBasic6Parser::APPACTIVATE)
                | (1ULL << VisualBasic6Parser::APPEND)
                | (1ULL << VisualBasic6Parser::AS)
                | (1ULL << VisualBasic6Parser::BEEP)
                | (1ULL << VisualBasic6Parser::BEGIN)
                | (1ULL << VisualBasic6Parser::BINARY)
                | (1ULL << VisualBasic6Parser::BOOLEAN)
                | (1ULL << VisualBasic6Parser::BYVAL)
                | (1ULL << VisualBasic6Parser::BYREF)
                | (1ULL << VisualBasic6Parser::BYTE)
                | (1ULL << VisualBasic6Parser::CALL)
                | (1ULL << VisualBasic6Parser::CASE)
                | (1ULL << VisualBasic6Parser::CHDIR)
                | (1ULL << VisualBasic6Parser::CHDRIVE)
                | (1ULL << VisualBasic6Parser::CLASS)
                | (1ULL << VisualBasic6Parser::CLOSE)
                | (1ULL << VisualBasic6Parser::COLLECTION)
                | (1ULL << VisualBasic6Parser::CONST)
                | (1ULL << VisualBasic6Parser::DATE)
                | (1ULL << VisualBasic6Parser::DECLARE)
                | (1ULL << VisualBasic6Parser::DEFBOOL)
                | (1ULL << VisualBasic6Parser::DEFBYTE)
                | (1ULL << VisualBasic6Parser::DEFDATE)
                | (1ULL << VisualBasic6Parser::DEFDBL)
                | (1ULL << VisualBasic6Parser::DEFDEC)
                | (1ULL << VisualBasic6Parser::DEFCUR)
                | (1ULL << VisualBasic6Parser::DEFINT)
                | (1ULL << VisualBasic6Parser::DEFLNG)
                | (1ULL << VisualBasic6Parser::DEFOBJ)
                | (1ULL << VisualBasic6Parser::DEFSNG)
                | (1ULL << VisualBasic6Parser::DEFSTR)
                | (1ULL << VisualBasic6Parser::DEFVAR)
                | (1ULL << VisualBasic6Parser::DELETESETTING)
                | (1ULL << VisualBasic6Parser::DIM)
                | (1ULL << VisualBasic6Parser::DO)
                | (1ULL << VisualBasic6Parser::DOUBLE)
                | (1ULL << VisualBasic6Parser::EACH)
                | (1ULL << VisualBasic6Parser::ELSE)
                | (1ULL << VisualBasic6Parser::ELSEIF)
                | (1ULL << VisualBasic6Parser::END)
                | (1ULL << VisualBasic6Parser::ENUM)
                | (1ULL << VisualBasic6Parser::EQV)
                | (1ULL << VisualBasic6Parser::ERASE)
                | (1ULL << VisualBasic6Parser::ERROR)
                | (1ULL << VisualBasic6Parser::EVENT))) != 0) || ((((_la - 66) & ~ 0x3fULL) == 0) &&
                ((1ULL << (_la - 66)) & ((1ULL << (VisualBasic6Parser::FALSE1 - 66))
                | (1ULL << (VisualBasic6Parser::FILECOPY - 66))
                | (1ULL << (VisualBasic6Parser::FRIEND - 66))
                | (1ULL << (VisualBasic6Parser::FOR - 66))
                | (1ULL << (VisualBasic6Parser::FUNCTION - 66))
                | (1ULL << (VisualBasic6Parser::GET - 66))
                | (1ULL << (VisualBasic6Parser::GLOBAL - 66))
                | (1ULL << (VisualBasic6Parser::GOSUB - 66))
                | (1ULL << (VisualBasic6Parser::GOTO - 66))
                | (1ULL << (VisualBasic6Parser::IF - 66))
                | (1ULL << (VisualBasic6Parser::IMP - 66))
                | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 66))
                | (1ULL << (VisualBasic6Parser::IN - 66))
                | (1ULL << (VisualBasic6Parser::INPUT - 66))
                | (1ULL << (VisualBasic6Parser::IS - 66))
                | (1ULL << (VisualBasic6Parser::INTEGER - 66))
                | (1ULL << (VisualBasic6Parser::KILL - 66))
                | (1ULL << (VisualBasic6Parser::LOAD - 66))
                | (1ULL << (VisualBasic6Parser::LOCK - 66))
                | (1ULL << (VisualBasic6Parser::LONG - 66))
                | (1ULL << (VisualBasic6Parser::LOOP - 66))
                | (1ULL << (VisualBasic6Parser::LEN - 66))
                | (1ULL << (VisualBasic6Parser::LET - 66))
                | (1ULL << (VisualBasic6Parser::LIB - 66))
                | (1ULL << (VisualBasic6Parser::LIKE - 66))
                | (1ULL << (VisualBasic6Parser::LSET - 66))
                | (1ULL << (VisualBasic6Parser::ME - 66))
                | (1ULL << (VisualBasic6Parser::MID - 66))
                | (1ULL << (VisualBasic6Parser::MKDIR - 66))
                | (1ULL << (VisualBasic6Parser::MOD - 66))
                | (1ULL << (VisualBasic6Parser::NAME - 66))
                | (1ULL << (VisualBasic6Parser::NEXT - 66))
                | (1ULL << (VisualBasic6Parser::NEW - 66))
                | (1ULL << (VisualBasic6Parser::NOT - 66))
                | (1ULL << (VisualBasic6Parser::NOTHING - 66))
                | (1ULL << (VisualBasic6Parser::NULL1 - 66))
                | (1ULL << (VisualBasic6Parser::OBJECT - 66))
                | (1ULL << (VisualBasic6Parser::ON - 66))
                | (1ULL << (VisualBasic6Parser::OPEN - 66))
                | (1ULL << (VisualBasic6Parser::OPTIONAL - 66))
                | (1ULL << (VisualBasic6Parser::OR - 66))
                | (1ULL << (VisualBasic6Parser::OUTPUT - 66))
                | (1ULL << (VisualBasic6Parser::PARAMARRAY - 66))
                | (1ULL << (VisualBasic6Parser::PRESERVE - 66))
                | (1ULL << (VisualBasic6Parser::PRINT - 66))
                | (1ULL << (VisualBasic6Parser::PRIVATE - 66))
                | (1ULL << (VisualBasic6Parser::PUBLIC - 66)))) != 0) || ((((_la - 130) & ~ 0x3fULL) == 0) &&
                ((1ULL << (_la - 130)) & ((1ULL << (VisualBasic6Parser::PUT - 130))
                | (1ULL << (VisualBasic6Parser::RANDOM - 130))
                | (1ULL << (VisualBasic6Parser::RANDOMIZE - 130))
                | (1ULL << (VisualBasic6Parser::RAISEEVENT - 130))
                | (1ULL << (VisualBasic6Parser::READ - 130))
                | (1ULL << (VisualBasic6Parser::REDIM - 130))
                | (1ULL << (VisualBasic6Parser::REM - 130))
                | (1ULL << (VisualBasic6Parser::RESET - 130))
                | (1ULL << (VisualBasic6Parser::RESUME - 130))
                | (1ULL << (VisualBasic6Parser::RETURN - 130))
                | (1ULL << (VisualBasic6Parser::RMDIR - 130))
                | (1ULL << (VisualBasic6Parser::RSET - 130))
                | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 130))
                | (1ULL << (VisualBasic6Parser::SAVESETTING - 130))
                | (1ULL << (VisualBasic6Parser::SEEK - 130))
                | (1ULL << (VisualBasic6Parser::SELECT - 130))
                | (1ULL << (VisualBasic6Parser::SENDKEYS - 130))
                | (1ULL << (VisualBasic6Parser::SET - 130))
                | (1ULL << (VisualBasic6Parser::SETATTR - 130))
                | (1ULL << (VisualBasic6Parser::SHARED - 130))
                | (1ULL << (VisualBasic6Parser::SINGLE - 130))
                | (1ULL << (VisualBasic6Parser::SPC - 130))
                | (1ULL << (VisualBasic6Parser::STATIC - 130))
                | (1ULL << (VisualBasic6Parser::STEP - 130))
                | (1ULL << (VisualBasic6Parser::STOP - 130))
                | (1ULL << (VisualBasic6Parser::STRING - 130))
                | (1ULL << (VisualBasic6Parser::SUB - 130))
                | (1ULL << (VisualBasic6Parser::TAB - 130))
                | (1ULL << (VisualBasic6Parser::TEXT - 130))
                | (1ULL << (VisualBasic6Parser::THEN - 130))
                | (1ULL << (VisualBasic6Parser::TIME - 130))
                | (1ULL << (VisualBasic6Parser::TO - 130))
                | (1ULL << (VisualBasic6Parser::TRUE1 - 130))
                | (1ULL << (VisualBasic6Parser::TYPE - 130))
                | (1ULL << (VisualBasic6Parser::TYPEOF - 130))
                | (1ULL << (VisualBasic6Parser::UNLOAD - 130))
                | (1ULL << (VisualBasic6Parser::UNLOCK - 130))
                | (1ULL << (VisualBasic6Parser::UNTIL - 130))
                | (1ULL << (VisualBasic6Parser::VARIANT - 130))
                | (1ULL << (VisualBasic6Parser::VERSION - 130))
                | (1ULL << (VisualBasic6Parser::WEND - 130))
                | (1ULL << (VisualBasic6Parser::WHILE - 130))
                | (1ULL << (VisualBasic6Parser::WIDTH - 130))
                | (1ULL << (VisualBasic6Parser::WITH - 130))
                | (1ULL << (VisualBasic6Parser::WITHEVENTS - 130))
                | (1ULL << (VisualBasic6Parser::WRITE - 130))
                | (1ULL << (VisualBasic6Parser::XOR - 130))
                | (1ULL << (VisualBasic6Parser::COMMA - 130))
                | (1ULL << (VisualBasic6Parser::DOT - 130))
                | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 130))
                | (1ULL << (VisualBasic6Parser::LPAREN - 130)))) != 0) || ((((_la - 195) & ~ 0x3fULL) == 0) &&
                ((1ULL << (_la - 195)) & ((1ULL << (VisualBasic6Parser::MINUS - 195))
                | (1ULL << (VisualBasic6Parser::PLUS - 195))
                | (1ULL << (VisualBasic6Parser::SEMICOLON - 195))
                | (1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 195))
                | (1ULL << (VisualBasic6Parser::STRINGLITERAL - 195))
                | (1ULL << (VisualBasic6Parser::DATELITERAL - 195))
                | (1ULL << (VisualBasic6Parser::COLORLITERAL - 195))
                | (1ULL << (VisualBasic6Parser::INTEGERLITERAL - 195))
                | (1ULL << (VisualBasic6Parser::DOUBLELITERAL - 195))
                | (1ULL << (VisualBasic6Parser::FILENUMBER - 195))
                | (1ULL << (VisualBasic6Parser::OCTALLITERAL - 195))
                | (1ULL << (VisualBasic6Parser::IDENTIFIER - 195))
                | (1ULL << (VisualBasic6Parser::WS - 195)))) != 0)) {
                setState(2596);
                argsCall();
                setState(2598);
                _errHandler->sync(this);

                _la = _input->LA(1);
                if (_la == VisualBasic6Parser::WS) {
                  setState(2597);
                  match(VisualBasic6Parser::WS);
                }
              }
              setState(2602);
              match(VisualBasic6Parser::RPAREN);
              break;
            }

      default:
        throw NoViableAltException(this);
      }
      setState(2605); 
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 435, _ctx);
    } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
    setState(2608);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 436, _ctx)) {
    case 1: {
      setState(2607);
      dictionaryCallStmt();
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

//----------------- ICS_S_NestedProcedureCallContext ------------------------------------------------------------------

VisualBasic6Parser::ICS_S_NestedProcedureCallContext::ICS_S_NestedProcedureCallContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::ICS_S_NestedProcedureCallContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ICS_S_NestedProcedureCallContext::LPAREN() {
  return getToken(VisualBasic6Parser::LPAREN, 0);
}

tree::TerminalNode* VisualBasic6Parser::ICS_S_NestedProcedureCallContext::RPAREN() {
  return getToken(VisualBasic6Parser::RPAREN, 0);
}

VisualBasic6Parser::TypeHintContext* VisualBasic6Parser::ICS_S_NestedProcedureCallContext::typeHint() {
  return getRuleContext<VisualBasic6Parser::TypeHintContext>(0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ICS_S_NestedProcedureCallContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ICS_S_NestedProcedureCallContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::ArgsCallContext* VisualBasic6Parser::ICS_S_NestedProcedureCallContext::argsCall() {
  return getRuleContext<VisualBasic6Parser::ArgsCallContext>(0);
}


size_t VisualBasic6Parser::ICS_S_NestedProcedureCallContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleICS_S_NestedProcedureCall;
}

antlrcpp::Any VisualBasic6Parser::ICS_S_NestedProcedureCallContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitICS_S_NestedProcedureCall(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ICS_S_NestedProcedureCallContext* VisualBasic6Parser::iCS_S_NestedProcedureCall() {
  ICS_S_NestedProcedureCallContext *_localctx = _tracker.createInstance<ICS_S_NestedProcedureCallContext>(_ctx, getState());
  enterRule(_localctx, 254, VisualBasic6Parser::RuleICS_S_NestedProcedureCall);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2610);
    ambiguousIdentifier();
    setState(2612);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 178) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 178)) & ((1ULL << (VisualBasic6Parser::AMPERSAND - 178))
      | (1ULL << (VisualBasic6Parser::AT - 178))
      | (1ULL << (VisualBasic6Parser::DOLLAR - 178))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 178))
      | (1ULL << (VisualBasic6Parser::HASH - 178))
      | (1ULL << (VisualBasic6Parser::PERCENT - 178)))) != 0)) {
      setState(2611);
      typeHint();
    }
    setState(2615);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(2614);
      match(VisualBasic6Parser::WS);
    }
    setState(2617);
    match(VisualBasic6Parser::LPAREN);
    setState(2619);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 439, _ctx)) {
    case 1: {
      setState(2618);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(2625);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
      | (1ULL << VisualBasic6Parser::ADDRESSOF)
      | (1ULL << VisualBasic6Parser::ALIAS)
      | (1ULL << VisualBasic6Parser::AND)
      | (1ULL << VisualBasic6Parser::ATTRIBUTE)
      | (1ULL << VisualBasic6Parser::APPACTIVATE)
      | (1ULL << VisualBasic6Parser::APPEND)
      | (1ULL << VisualBasic6Parser::AS)
      | (1ULL << VisualBasic6Parser::BEEP)
      | (1ULL << VisualBasic6Parser::BEGIN)
      | (1ULL << VisualBasic6Parser::BINARY)
      | (1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYVAL)
      | (1ULL << VisualBasic6Parser::BYREF)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::CALL)
      | (1ULL << VisualBasic6Parser::CASE)
      | (1ULL << VisualBasic6Parser::CHDIR)
      | (1ULL << VisualBasic6Parser::CHDRIVE)
      | (1ULL << VisualBasic6Parser::CLASS)
      | (1ULL << VisualBasic6Parser::CLOSE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::CONST)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DECLARE)
      | (1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR)
      | (1ULL << VisualBasic6Parser::DELETESETTING)
      | (1ULL << VisualBasic6Parser::DIM)
      | (1ULL << VisualBasic6Parser::DO)
      | (1ULL << VisualBasic6Parser::DOUBLE)
      | (1ULL << VisualBasic6Parser::EACH)
      | (1ULL << VisualBasic6Parser::ELSE)
      | (1ULL << VisualBasic6Parser::ELSEIF)
      | (1ULL << VisualBasic6Parser::END)
      | (1ULL << VisualBasic6Parser::ENUM)
      | (1ULL << VisualBasic6Parser::EQV)
      | (1ULL << VisualBasic6Parser::ERASE)
      | (1ULL << VisualBasic6Parser::ERROR)
      | (1ULL << VisualBasic6Parser::EVENT))) != 0) || ((((_la - 66) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 66)) & ((1ULL << (VisualBasic6Parser::FALSE1 - 66))
      | (1ULL << (VisualBasic6Parser::FILECOPY - 66))
      | (1ULL << (VisualBasic6Parser::FRIEND - 66))
      | (1ULL << (VisualBasic6Parser::FOR - 66))
      | (1ULL << (VisualBasic6Parser::FUNCTION - 66))
      | (1ULL << (VisualBasic6Parser::GET - 66))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 66))
      | (1ULL << (VisualBasic6Parser::GOSUB - 66))
      | (1ULL << (VisualBasic6Parser::GOTO - 66))
      | (1ULL << (VisualBasic6Parser::IF - 66))
      | (1ULL << (VisualBasic6Parser::IMP - 66))
      | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 66))
      | (1ULL << (VisualBasic6Parser::IN - 66))
      | (1ULL << (VisualBasic6Parser::INPUT - 66))
      | (1ULL << (VisualBasic6Parser::IS - 66))
      | (1ULL << (VisualBasic6Parser::INTEGER - 66))
      | (1ULL << (VisualBasic6Parser::KILL - 66))
      | (1ULL << (VisualBasic6Parser::LOAD - 66))
      | (1ULL << (VisualBasic6Parser::LOCK - 66))
      | (1ULL << (VisualBasic6Parser::LONG - 66))
      | (1ULL << (VisualBasic6Parser::LOOP - 66))
      | (1ULL << (VisualBasic6Parser::LEN - 66))
      | (1ULL << (VisualBasic6Parser::LET - 66))
      | (1ULL << (VisualBasic6Parser::LIB - 66))
      | (1ULL << (VisualBasic6Parser::LIKE - 66))
      | (1ULL << (VisualBasic6Parser::LSET - 66))
      | (1ULL << (VisualBasic6Parser::ME - 66))
      | (1ULL << (VisualBasic6Parser::MID - 66))
      | (1ULL << (VisualBasic6Parser::MKDIR - 66))
      | (1ULL << (VisualBasic6Parser::MOD - 66))
      | (1ULL << (VisualBasic6Parser::NAME - 66))
      | (1ULL << (VisualBasic6Parser::NEXT - 66))
      | (1ULL << (VisualBasic6Parser::NEW - 66))
      | (1ULL << (VisualBasic6Parser::NOT - 66))
      | (1ULL << (VisualBasic6Parser::NOTHING - 66))
      | (1ULL << (VisualBasic6Parser::NULL1 - 66))
      | (1ULL << (VisualBasic6Parser::OBJECT - 66))
      | (1ULL << (VisualBasic6Parser::ON - 66))
      | (1ULL << (VisualBasic6Parser::OPEN - 66))
      | (1ULL << (VisualBasic6Parser::OPTIONAL - 66))
      | (1ULL << (VisualBasic6Parser::OR - 66))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 66))
      | (1ULL << (VisualBasic6Parser::PARAMARRAY - 66))
      | (1ULL << (VisualBasic6Parser::PRESERVE - 66))
      | (1ULL << (VisualBasic6Parser::PRINT - 66))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 66))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 66)))) != 0) || ((((_la - 130) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 130)) & ((1ULL << (VisualBasic6Parser::PUT - 130))
      | (1ULL << (VisualBasic6Parser::RANDOM - 130))
      | (1ULL << (VisualBasic6Parser::RANDOMIZE - 130))
      | (1ULL << (VisualBasic6Parser::RAISEEVENT - 130))
      | (1ULL << (VisualBasic6Parser::READ - 130))
      | (1ULL << (VisualBasic6Parser::REDIM - 130))
      | (1ULL << (VisualBasic6Parser::REM - 130))
      | (1ULL << (VisualBasic6Parser::RESET - 130))
      | (1ULL << (VisualBasic6Parser::RESUME - 130))
      | (1ULL << (VisualBasic6Parser::RETURN - 130))
      | (1ULL << (VisualBasic6Parser::RMDIR - 130))
      | (1ULL << (VisualBasic6Parser::RSET - 130))
      | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 130))
      | (1ULL << (VisualBasic6Parser::SAVESETTING - 130))
      | (1ULL << (VisualBasic6Parser::SEEK - 130))
      | (1ULL << (VisualBasic6Parser::SELECT - 130))
      | (1ULL << (VisualBasic6Parser::SENDKEYS - 130))
      | (1ULL << (VisualBasic6Parser::SET - 130))
      | (1ULL << (VisualBasic6Parser::SETATTR - 130))
      | (1ULL << (VisualBasic6Parser::SHARED - 130))
      | (1ULL << (VisualBasic6Parser::SINGLE - 130))
      | (1ULL << (VisualBasic6Parser::SPC - 130))
      | (1ULL << (VisualBasic6Parser::STATIC - 130))
      | (1ULL << (VisualBasic6Parser::STEP - 130))
      | (1ULL << (VisualBasic6Parser::STOP - 130))
      | (1ULL << (VisualBasic6Parser::STRING - 130))
      | (1ULL << (VisualBasic6Parser::SUB - 130))
      | (1ULL << (VisualBasic6Parser::TAB - 130))
      | (1ULL << (VisualBasic6Parser::TEXT - 130))
      | (1ULL << (VisualBasic6Parser::THEN - 130))
      | (1ULL << (VisualBasic6Parser::TIME - 130))
      | (1ULL << (VisualBasic6Parser::TO - 130))
      | (1ULL << (VisualBasic6Parser::TRUE1 - 130))
      | (1ULL << (VisualBasic6Parser::TYPE - 130))
      | (1ULL << (VisualBasic6Parser::TYPEOF - 130))
      | (1ULL << (VisualBasic6Parser::UNLOAD - 130))
      | (1ULL << (VisualBasic6Parser::UNLOCK - 130))
      | (1ULL << (VisualBasic6Parser::UNTIL - 130))
      | (1ULL << (VisualBasic6Parser::VARIANT - 130))
      | (1ULL << (VisualBasic6Parser::VERSION - 130))
      | (1ULL << (VisualBasic6Parser::WEND - 130))
      | (1ULL << (VisualBasic6Parser::WHILE - 130))
      | (1ULL << (VisualBasic6Parser::WIDTH - 130))
      | (1ULL << (VisualBasic6Parser::WITH - 130))
      | (1ULL << (VisualBasic6Parser::WITHEVENTS - 130))
      | (1ULL << (VisualBasic6Parser::WRITE - 130))
      | (1ULL << (VisualBasic6Parser::XOR - 130))
      | (1ULL << (VisualBasic6Parser::COMMA - 130))
      | (1ULL << (VisualBasic6Parser::DOT - 130))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 130))
      | (1ULL << (VisualBasic6Parser::LPAREN - 130)))) != 0) || ((((_la - 195) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 195)) & ((1ULL << (VisualBasic6Parser::MINUS - 195))
      | (1ULL << (VisualBasic6Parser::PLUS - 195))
      | (1ULL << (VisualBasic6Parser::SEMICOLON - 195))
      | (1ULL << (VisualBasic6Parser::L_SQUARE_BRACKET - 195))
      | (1ULL << (VisualBasic6Parser::STRINGLITERAL - 195))
      | (1ULL << (VisualBasic6Parser::DATELITERAL - 195))
      | (1ULL << (VisualBasic6Parser::COLORLITERAL - 195))
      | (1ULL << (VisualBasic6Parser::INTEGERLITERAL - 195))
      | (1ULL << (VisualBasic6Parser::DOUBLELITERAL - 195))
      | (1ULL << (VisualBasic6Parser::FILENUMBER - 195))
      | (1ULL << (VisualBasic6Parser::OCTALLITERAL - 195))
      | (1ULL << (VisualBasic6Parser::IDENTIFIER - 195))
      | (1ULL << (VisualBasic6Parser::WS - 195)))) != 0)) {
      setState(2621);
      argsCall();
      setState(2623);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2622);
        match(VisualBasic6Parser::WS);
      }
    }
    setState(2627);
    match(VisualBasic6Parser::RPAREN);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ICS_S_MembersCallContext ------------------------------------------------------------------

VisualBasic6Parser::ICS_S_MembersCallContext::ICS_S_MembersCallContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext* VisualBasic6Parser::ICS_S_MembersCallContext::iCS_S_VariableOrProcedureCall() {
  return getRuleContext<VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext>(0);
}

VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext* VisualBasic6Parser::ICS_S_MembersCallContext::iCS_S_ProcedureOrArrayCall() {
  return getRuleContext<VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext>(0);
}

std::vector<VisualBasic6Parser::ICS_S_MemberCallContext *> VisualBasic6Parser::ICS_S_MembersCallContext::iCS_S_MemberCall() {
  return getRuleContexts<VisualBasic6Parser::ICS_S_MemberCallContext>();
}

VisualBasic6Parser::ICS_S_MemberCallContext* VisualBasic6Parser::ICS_S_MembersCallContext::iCS_S_MemberCall(size_t i) {
  return getRuleContext<VisualBasic6Parser::ICS_S_MemberCallContext>(i);
}

VisualBasic6Parser::DictionaryCallStmtContext* VisualBasic6Parser::ICS_S_MembersCallContext::dictionaryCallStmt() {
  return getRuleContext<VisualBasic6Parser::DictionaryCallStmtContext>(0);
}


size_t VisualBasic6Parser::ICS_S_MembersCallContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleICS_S_MembersCall;
}

antlrcpp::Any VisualBasic6Parser::ICS_S_MembersCallContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitICS_S_MembersCall(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ICS_S_MembersCallContext* VisualBasic6Parser::iCS_S_MembersCall() {
  ICS_S_MembersCallContext *_localctx = _tracker.createInstance<ICS_S_MembersCallContext>(_ctx, getState());
  enterRule(_localctx, 256, VisualBasic6Parser::RuleICS_S_MembersCall);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(2631);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 442, _ctx)) {
    case 1: {
      setState(2629);
      iCS_S_VariableOrProcedureCall();
      break;
    }

    case 2: {
      setState(2630);
      iCS_S_ProcedureOrArrayCall();
      break;
    }

    }
    setState(2634); 
    _errHandler->sync(this);
    alt = 1;
    do {
      switch (alt) {
        case 1: {
              setState(2633);
              iCS_S_MemberCall();
              break;
            }

      default:
        throw NoViableAltException(this);
      }
      setState(2636); 
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 443, _ctx);
    } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
    setState(2639);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 444, _ctx)) {
    case 1: {
      setState(2638);
      dictionaryCallStmt();
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

//----------------- ICS_S_MemberCallContext ------------------------------------------------------------------

VisualBasic6Parser::ICS_S_MemberCallContext::ICS_S_MemberCallContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ICS_S_MemberCallContext::DOT() {
  return getToken(VisualBasic6Parser::DOT, 0);
}

VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext* VisualBasic6Parser::ICS_S_MemberCallContext::iCS_S_VariableOrProcedureCall() {
  return getRuleContext<VisualBasic6Parser::ICS_S_VariableOrProcedureCallContext>(0);
}

VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext* VisualBasic6Parser::ICS_S_MemberCallContext::iCS_S_ProcedureOrArrayCall() {
  return getRuleContext<VisualBasic6Parser::ICS_S_ProcedureOrArrayCallContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ICS_S_MemberCallContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}


size_t VisualBasic6Parser::ICS_S_MemberCallContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleICS_S_MemberCall;
}

antlrcpp::Any VisualBasic6Parser::ICS_S_MemberCallContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitICS_S_MemberCall(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ICS_S_MemberCallContext* VisualBasic6Parser::iCS_S_MemberCall() {
  ICS_S_MemberCallContext *_localctx = _tracker.createInstance<ICS_S_MemberCallContext>(_ctx, getState());
  enterRule(_localctx, 258, VisualBasic6Parser::RuleICS_S_MemberCall);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2642);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(2641);
      match(VisualBasic6Parser::WS);
    }
    setState(2644);
    match(VisualBasic6Parser::DOT);
    setState(2647);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 446, _ctx)) {
    case 1: {
      setState(2645);
      iCS_S_VariableOrProcedureCall();
      break;
    }

    case 2: {
      setState(2646);
      iCS_S_ProcedureOrArrayCall();
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

//----------------- ICS_S_DictionaryCallContext ------------------------------------------------------------------

VisualBasic6Parser::ICS_S_DictionaryCallContext::ICS_S_DictionaryCallContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::DictionaryCallStmtContext* VisualBasic6Parser::ICS_S_DictionaryCallContext::dictionaryCallStmt() {
  return getRuleContext<VisualBasic6Parser::DictionaryCallStmtContext>(0);
}


size_t VisualBasic6Parser::ICS_S_DictionaryCallContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleICS_S_DictionaryCall;
}

antlrcpp::Any VisualBasic6Parser::ICS_S_DictionaryCallContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitICS_S_DictionaryCall(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ICS_S_DictionaryCallContext* VisualBasic6Parser::iCS_S_DictionaryCall() {
  ICS_S_DictionaryCallContext *_localctx = _tracker.createInstance<ICS_S_DictionaryCallContext>(_ctx, getState());
  enterRule(_localctx, 260, VisualBasic6Parser::RuleICS_S_DictionaryCall);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2649);
    dictionaryCallStmt();
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ArgsCallContext ------------------------------------------------------------------

VisualBasic6Parser::ArgsCallContext::ArgsCallContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<VisualBasic6Parser::ArgCallContext *> VisualBasic6Parser::ArgsCallContext::argCall() {
  return getRuleContexts<VisualBasic6Parser::ArgCallContext>();
}

VisualBasic6Parser::ArgCallContext* VisualBasic6Parser::ArgsCallContext::argCall(size_t i) {
  return getRuleContext<VisualBasic6Parser::ArgCallContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ArgsCallContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::ArgsCallContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ArgsCallContext::SEMICOLON() {
  return getTokens(VisualBasic6Parser::SEMICOLON);
}

tree::TerminalNode* VisualBasic6Parser::ArgsCallContext::SEMICOLON(size_t i) {
  return getToken(VisualBasic6Parser::SEMICOLON, i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ArgsCallContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ArgsCallContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}


size_t VisualBasic6Parser::ArgsCallContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleArgsCall;
}

antlrcpp::Any VisualBasic6Parser::ArgsCallContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitArgsCall(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ArgsCallContext* VisualBasic6Parser::argsCall() {
  ArgsCallContext *_localctx = _tracker.createInstance<ArgsCallContext>(_ctx, getState());
  enterRule(_localctx, 262, VisualBasic6Parser::RuleArgsCall);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(2663);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 450, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(2652);
        _errHandler->sync(this);

        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 447, _ctx)) {
        case 1: {
          setState(2651);
          argCall();
          break;
        }

        }
        setState(2655);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(2654);
          match(VisualBasic6Parser::WS);
        }
        setState(2657);
        _la = _input->LA(1);
        if (!(_la == VisualBasic6Parser::COMMA

        || _la == VisualBasic6Parser::SEMICOLON)) {
        _errHandler->recoverInline(this);
        }
        else {
          _errHandler->reportMatch(this);
          consume();
        }
        setState(2659);
        _errHandler->sync(this);

        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 449, _ctx)) {
        case 1: {
          setState(2658);
          match(VisualBasic6Parser::WS);
          break;
        }

        } 
      }
      setState(2665);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 450, _ctx);
    }
    setState(2666);
    argCall();
    setState(2679);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 454, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(2668);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(2667);
          match(VisualBasic6Parser::WS);
        }
        setState(2670);
        _la = _input->LA(1);
        if (!(_la == VisualBasic6Parser::COMMA

        || _la == VisualBasic6Parser::SEMICOLON)) {
        _errHandler->recoverInline(this);
        }
        else {
          _errHandler->reportMatch(this);
          consume();
        }
        setState(2672);
        _errHandler->sync(this);

        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 452, _ctx)) {
        case 1: {
          setState(2671);
          match(VisualBasic6Parser::WS);
          break;
        }

        }
        setState(2675);
        _errHandler->sync(this);

        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 453, _ctx)) {
        case 1: {
          setState(2674);
          argCall();
          break;
        }

        } 
      }
      setState(2681);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 454, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ArgCallContext ------------------------------------------------------------------

VisualBasic6Parser::ArgCallContext::ArgCallContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::ArgCallContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ArgCallContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}

tree::TerminalNode* VisualBasic6Parser::ArgCallContext::BYVAL() {
  return getToken(VisualBasic6Parser::BYVAL, 0);
}

tree::TerminalNode* VisualBasic6Parser::ArgCallContext::BYREF() {
  return getToken(VisualBasic6Parser::BYREF, 0);
}

tree::TerminalNode* VisualBasic6Parser::ArgCallContext::PARAMARRAY() {
  return getToken(VisualBasic6Parser::PARAMARRAY, 0);
}


size_t VisualBasic6Parser::ArgCallContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleArgCall;
}

antlrcpp::Any VisualBasic6Parser::ArgCallContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitArgCall(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ArgCallContext* VisualBasic6Parser::argCall() {
  ArgCallContext *_localctx = _tracker.createInstance<ArgCallContext>(_ctx, getState());
  enterRule(_localctx, 264, VisualBasic6Parser::RuleArgCall);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2684);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 455, _ctx)) {
    case 1: {
      setState(2682);
      _la = _input->LA(1);
      if (!(_la == VisualBasic6Parser::BYVAL

      || _la == VisualBasic6Parser::BYREF || _la == VisualBasic6Parser::PARAMARRAY)) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      setState(2683);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(2686);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- DictionaryCallStmtContext ------------------------------------------------------------------

VisualBasic6Parser::DictionaryCallStmtContext::DictionaryCallStmtContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::DictionaryCallStmtContext::EXCLAMATIONMARK() {
  return getToken(VisualBasic6Parser::EXCLAMATIONMARK, 0);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::DictionaryCallStmtContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

VisualBasic6Parser::TypeHintContext* VisualBasic6Parser::DictionaryCallStmtContext::typeHint() {
  return getRuleContext<VisualBasic6Parser::TypeHintContext>(0);
}


size_t VisualBasic6Parser::DictionaryCallStmtContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleDictionaryCallStmt;
}

antlrcpp::Any VisualBasic6Parser::DictionaryCallStmtContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitDictionaryCallStmt(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::DictionaryCallStmtContext* VisualBasic6Parser::dictionaryCallStmt() {
  DictionaryCallStmtContext *_localctx = _tracker.createInstance<DictionaryCallStmtContext>(_ctx, getState());
  enterRule(_localctx, 266, VisualBasic6Parser::RuleDictionaryCallStmt);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2688);
    match(VisualBasic6Parser::EXCLAMATIONMARK);
    setState(2689);
    ambiguousIdentifier();
    setState(2691);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 456, _ctx)) {
    case 1: {
      setState(2690);
      typeHint();
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

//----------------- ArgListContext ------------------------------------------------------------------

VisualBasic6Parser::ArgListContext::ArgListContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ArgListContext::LPAREN() {
  return getToken(VisualBasic6Parser::LPAREN, 0);
}

tree::TerminalNode* VisualBasic6Parser::ArgListContext::RPAREN() {
  return getToken(VisualBasic6Parser::RPAREN, 0);
}

std::vector<VisualBasic6Parser::ArgContext *> VisualBasic6Parser::ArgListContext::arg() {
  return getRuleContexts<VisualBasic6Parser::ArgContext>();
}

VisualBasic6Parser::ArgContext* VisualBasic6Parser::ArgListContext::arg(size_t i) {
  return getRuleContext<VisualBasic6Parser::ArgContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ArgListContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ArgListContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ArgListContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::ArgListContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}


size_t VisualBasic6Parser::ArgListContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleArgList;
}

antlrcpp::Any VisualBasic6Parser::ArgListContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitArgList(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ArgListContext* VisualBasic6Parser::argList() {
  ArgListContext *_localctx = _tracker.createInstance<ArgListContext>(_ctx, getState());
  enterRule(_localctx, 268, VisualBasic6Parser::RuleArgList);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(2693);
    match(VisualBasic6Parser::LPAREN);
    setState(2711);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 461, _ctx)) {
    case 1: {
      setState(2695);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2694);
        match(VisualBasic6Parser::WS);
      }
      setState(2697);
      arg();
      setState(2708);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 460, _ctx);
      while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
        if (alt == 1) {
          setState(2699);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2698);
            match(VisualBasic6Parser::WS);
          }
          setState(2701);
          match(VisualBasic6Parser::COMMA);
          setState(2703);
          _errHandler->sync(this);

          _la = _input->LA(1);
          if (_la == VisualBasic6Parser::WS) {
            setState(2702);
            match(VisualBasic6Parser::WS);
          }
          setState(2705);
          arg(); 
        }
        setState(2710);
        _errHandler->sync(this);
        alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 460, _ctx);
      }
      break;
    }

    }
    setState(2714);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(2713);
      match(VisualBasic6Parser::WS);
    }
    setState(2716);
    match(VisualBasic6Parser::RPAREN);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ArgContext ------------------------------------------------------------------

VisualBasic6Parser::ArgContext::ArgContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::ArgContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ArgContext::OPTIONAL() {
  return getToken(VisualBasic6Parser::OPTIONAL, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ArgContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::ArgContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

tree::TerminalNode* VisualBasic6Parser::ArgContext::PARAMARRAY() {
  return getToken(VisualBasic6Parser::PARAMARRAY, 0);
}

VisualBasic6Parser::TypeHintContext* VisualBasic6Parser::ArgContext::typeHint() {
  return getRuleContext<VisualBasic6Parser::TypeHintContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ArgContext::LPAREN() {
  return getToken(VisualBasic6Parser::LPAREN, 0);
}

tree::TerminalNode* VisualBasic6Parser::ArgContext::RPAREN() {
  return getToken(VisualBasic6Parser::RPAREN, 0);
}

VisualBasic6Parser::AsTypeClauseContext* VisualBasic6Parser::ArgContext::asTypeClause() {
  return getRuleContext<VisualBasic6Parser::AsTypeClauseContext>(0);
}

VisualBasic6Parser::ArgDefaultValueContext* VisualBasic6Parser::ArgContext::argDefaultValue() {
  return getRuleContext<VisualBasic6Parser::ArgDefaultValueContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ArgContext::BYVAL() {
  return getToken(VisualBasic6Parser::BYVAL, 0);
}

tree::TerminalNode* VisualBasic6Parser::ArgContext::BYREF() {
  return getToken(VisualBasic6Parser::BYREF, 0);
}


size_t VisualBasic6Parser::ArgContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleArg;
}

antlrcpp::Any VisualBasic6Parser::ArgContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitArg(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ArgContext* VisualBasic6Parser::arg() {
  ArgContext *_localctx = _tracker.createInstance<ArgContext>(_ctx, getState());
  enterRule(_localctx, 270, VisualBasic6Parser::RuleArg);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2720);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 463, _ctx)) {
    case 1: {
      setState(2718);
      match(VisualBasic6Parser::OPTIONAL);
      setState(2719);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(2724);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 464, _ctx)) {
    case 1: {
      setState(2722);
      _la = _input->LA(1);
      if (!(_la == VisualBasic6Parser::BYVAL

      || _la == VisualBasic6Parser::BYREF)) {
      _errHandler->recoverInline(this);
      }
      else {
        _errHandler->reportMatch(this);
        consume();
      }
      setState(2723);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(2728);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 465, _ctx)) {
    case 1: {
      setState(2726);
      match(VisualBasic6Parser::PARAMARRAY);
      setState(2727);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(2730);
    ambiguousIdentifier();
    setState(2732);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (((((_la - 178) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 178)) & ((1ULL << (VisualBasic6Parser::AMPERSAND - 178))
      | (1ULL << (VisualBasic6Parser::AT - 178))
      | (1ULL << (VisualBasic6Parser::DOLLAR - 178))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 178))
      | (1ULL << (VisualBasic6Parser::HASH - 178))
      | (1ULL << (VisualBasic6Parser::PERCENT - 178)))) != 0)) {
      setState(2731);
      typeHint();
    }
    setState(2742);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 469, _ctx)) {
    case 1: {
      setState(2735);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2734);
        match(VisualBasic6Parser::WS);
      }
      setState(2737);
      match(VisualBasic6Parser::LPAREN);
      setState(2739);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2738);
        match(VisualBasic6Parser::WS);
      }
      setState(2741);
      match(VisualBasic6Parser::RPAREN);
      break;
    }

    }
    setState(2746);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 470, _ctx)) {
    case 1: {
      setState(2744);
      match(VisualBasic6Parser::WS);
      setState(2745);
      asTypeClause();
      break;
    }

    }
    setState(2752);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 472, _ctx)) {
    case 1: {
      setState(2749);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2748);
        match(VisualBasic6Parser::WS);
      }
      setState(2751);
      argDefaultValue();
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

//----------------- ArgDefaultValueContext ------------------------------------------------------------------

VisualBasic6Parser::ArgDefaultValueContext::ArgDefaultValueContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ArgDefaultValueContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::ArgDefaultValueContext::valueStmt() {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::ArgDefaultValueContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}


size_t VisualBasic6Parser::ArgDefaultValueContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleArgDefaultValue;
}

antlrcpp::Any VisualBasic6Parser::ArgDefaultValueContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitArgDefaultValue(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ArgDefaultValueContext* VisualBasic6Parser::argDefaultValue() {
  ArgDefaultValueContext *_localctx = _tracker.createInstance<ArgDefaultValueContext>(_ctx, getState());
  enterRule(_localctx, 272, VisualBasic6Parser::RuleArgDefaultValue);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2754);
    match(VisualBasic6Parser::EQ);
    setState(2756);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 473, _ctx)) {
    case 1: {
      setState(2755);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(2758);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SubscriptsContext ------------------------------------------------------------------

VisualBasic6Parser::SubscriptsContext::SubscriptsContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<VisualBasic6Parser::SubscriptContext *> VisualBasic6Parser::SubscriptsContext::subscript() {
  return getRuleContexts<VisualBasic6Parser::SubscriptContext>();
}

VisualBasic6Parser::SubscriptContext* VisualBasic6Parser::SubscriptsContext::subscript(size_t i) {
  return getRuleContext<VisualBasic6Parser::SubscriptContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SubscriptsContext::COMMA() {
  return getTokens(VisualBasic6Parser::COMMA);
}

tree::TerminalNode* VisualBasic6Parser::SubscriptsContext::COMMA(size_t i) {
  return getToken(VisualBasic6Parser::COMMA, i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SubscriptsContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::SubscriptsContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}


size_t VisualBasic6Parser::SubscriptsContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleSubscripts;
}

antlrcpp::Any VisualBasic6Parser::SubscriptsContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitSubscripts(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::SubscriptsContext* VisualBasic6Parser::subscripts() {
  SubscriptsContext *_localctx = _tracker.createInstance<SubscriptsContext>(_ctx, getState());
  enterRule(_localctx, 274, VisualBasic6Parser::RuleSubscripts);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(2760);
    subscript();
    setState(2771);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 476, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(2762);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == VisualBasic6Parser::WS) {
          setState(2761);
          match(VisualBasic6Parser::WS);
        }
        setState(2764);
        match(VisualBasic6Parser::COMMA);
        setState(2766);
        _errHandler->sync(this);

        switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 475, _ctx)) {
        case 1: {
          setState(2765);
          match(VisualBasic6Parser::WS);
          break;
        }

        }
        setState(2768);
        subscript(); 
      }
      setState(2773);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 476, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- SubscriptContext ------------------------------------------------------------------

VisualBasic6Parser::SubscriptContext::SubscriptContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<VisualBasic6Parser::ValueStmtContext *> VisualBasic6Parser::SubscriptContext::valueStmt() {
  return getRuleContexts<VisualBasic6Parser::ValueStmtContext>();
}

VisualBasic6Parser::ValueStmtContext* VisualBasic6Parser::SubscriptContext::valueStmt(size_t i) {
  return getRuleContext<VisualBasic6Parser::ValueStmtContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::SubscriptContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::SubscriptContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

tree::TerminalNode* VisualBasic6Parser::SubscriptContext::TO() {
  return getToken(VisualBasic6Parser::TO, 0);
}


size_t VisualBasic6Parser::SubscriptContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleSubscript;
}

antlrcpp::Any VisualBasic6Parser::SubscriptContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitSubscript(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::SubscriptContext* VisualBasic6Parser::subscript() {
  SubscriptContext *_localctx = _tracker.createInstance<SubscriptContext>(_ctx, getState());
  enterRule(_localctx, 276, VisualBasic6Parser::RuleSubscript);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2779);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 477, _ctx)) {
    case 1: {
      setState(2774);
      valueStmt(0);
      setState(2775);
      match(VisualBasic6Parser::WS);
      setState(2776);
      match(VisualBasic6Parser::TO);
      setState(2777);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(2781);
    valueStmt(0);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- AmbiguousIdentifierContext ------------------------------------------------------------------

VisualBasic6Parser::AmbiguousIdentifierContext::AmbiguousIdentifierContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::AmbiguousIdentifierContext::IDENTIFIER() {
  return getTokens(VisualBasic6Parser::IDENTIFIER);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousIdentifierContext::IDENTIFIER(size_t i) {
  return getToken(VisualBasic6Parser::IDENTIFIER, i);
}

std::vector<VisualBasic6Parser::AmbiguousKeywordContext *> VisualBasic6Parser::AmbiguousIdentifierContext::ambiguousKeyword() {
  return getRuleContexts<VisualBasic6Parser::AmbiguousKeywordContext>();
}

VisualBasic6Parser::AmbiguousKeywordContext* VisualBasic6Parser::AmbiguousIdentifierContext::ambiguousKeyword(size_t i) {
  return getRuleContext<VisualBasic6Parser::AmbiguousKeywordContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousIdentifierContext::L_SQUARE_BRACKET() {
  return getToken(VisualBasic6Parser::L_SQUARE_BRACKET, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousIdentifierContext::R_SQUARE_BRACKET() {
  return getToken(VisualBasic6Parser::R_SQUARE_BRACKET, 0);
}


size_t VisualBasic6Parser::AmbiguousIdentifierContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleAmbiguousIdentifier;
}

antlrcpp::Any VisualBasic6Parser::AmbiguousIdentifierContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitAmbiguousIdentifier(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::ambiguousIdentifier() {
  AmbiguousIdentifierContext *_localctx = _tracker.createInstance<AmbiguousIdentifierContext>(_ctx, getState());
  enterRule(_localctx, 278, VisualBasic6Parser::RuleAmbiguousIdentifier);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    setState(2797);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case VisualBasic6Parser::ACCESS:
      case VisualBasic6Parser::ADDRESSOF:
      case VisualBasic6Parser::ALIAS:
      case VisualBasic6Parser::AND:
      case VisualBasic6Parser::ATTRIBUTE:
      case VisualBasic6Parser::APPACTIVATE:
      case VisualBasic6Parser::APPEND:
      case VisualBasic6Parser::AS:
      case VisualBasic6Parser::BEEP:
      case VisualBasic6Parser::BEGIN:
      case VisualBasic6Parser::BINARY:
      case VisualBasic6Parser::BOOLEAN:
      case VisualBasic6Parser::BYVAL:
      case VisualBasic6Parser::BYREF:
      case VisualBasic6Parser::BYTE:
      case VisualBasic6Parser::CALL:
      case VisualBasic6Parser::CASE:
      case VisualBasic6Parser::CHDIR:
      case VisualBasic6Parser::CHDRIVE:
      case VisualBasic6Parser::CLASS:
      case VisualBasic6Parser::CLOSE:
      case VisualBasic6Parser::COLLECTION:
      case VisualBasic6Parser::CONST:
      case VisualBasic6Parser::DATE:
      case VisualBasic6Parser::DECLARE:
      case VisualBasic6Parser::DEFBOOL:
      case VisualBasic6Parser::DEFBYTE:
      case VisualBasic6Parser::DEFDATE:
      case VisualBasic6Parser::DEFDBL:
      case VisualBasic6Parser::DEFDEC:
      case VisualBasic6Parser::DEFCUR:
      case VisualBasic6Parser::DEFINT:
      case VisualBasic6Parser::DEFLNG:
      case VisualBasic6Parser::DEFOBJ:
      case VisualBasic6Parser::DEFSNG:
      case VisualBasic6Parser::DEFSTR:
      case VisualBasic6Parser::DEFVAR:
      case VisualBasic6Parser::DELETESETTING:
      case VisualBasic6Parser::DIM:
      case VisualBasic6Parser::DO:
      case VisualBasic6Parser::DOUBLE:
      case VisualBasic6Parser::EACH:
      case VisualBasic6Parser::ELSE:
      case VisualBasic6Parser::ELSEIF:
      case VisualBasic6Parser::END:
      case VisualBasic6Parser::ENUM:
      case VisualBasic6Parser::EQV:
      case VisualBasic6Parser::ERASE:
      case VisualBasic6Parser::ERROR:
      case VisualBasic6Parser::EVENT:
      case VisualBasic6Parser::FALSE1:
      case VisualBasic6Parser::FILECOPY:
      case VisualBasic6Parser::FRIEND:
      case VisualBasic6Parser::FOR:
      case VisualBasic6Parser::FUNCTION:
      case VisualBasic6Parser::GET:
      case VisualBasic6Parser::GLOBAL:
      case VisualBasic6Parser::GOSUB:
      case VisualBasic6Parser::GOTO:
      case VisualBasic6Parser::IF:
      case VisualBasic6Parser::IMP:
      case VisualBasic6Parser::IMPLEMENTS:
      case VisualBasic6Parser::IN:
      case VisualBasic6Parser::INPUT:
      case VisualBasic6Parser::IS:
      case VisualBasic6Parser::INTEGER:
      case VisualBasic6Parser::KILL:
      case VisualBasic6Parser::LOAD:
      case VisualBasic6Parser::LOCK:
      case VisualBasic6Parser::LONG:
      case VisualBasic6Parser::LOOP:
      case VisualBasic6Parser::LEN:
      case VisualBasic6Parser::LET:
      case VisualBasic6Parser::LIB:
      case VisualBasic6Parser::LIKE:
      case VisualBasic6Parser::LSET:
      case VisualBasic6Parser::ME:
      case VisualBasic6Parser::MID:
      case VisualBasic6Parser::MKDIR:
      case VisualBasic6Parser::MOD:
      case VisualBasic6Parser::NAME:
      case VisualBasic6Parser::NEXT:
      case VisualBasic6Parser::NEW:
      case VisualBasic6Parser::NOT:
      case VisualBasic6Parser::NOTHING:
      case VisualBasic6Parser::NULL1:
      case VisualBasic6Parser::OBJECT:
      case VisualBasic6Parser::ON:
      case VisualBasic6Parser::OPEN:
      case VisualBasic6Parser::OPTIONAL:
      case VisualBasic6Parser::OR:
      case VisualBasic6Parser::OUTPUT:
      case VisualBasic6Parser::PARAMARRAY:
      case VisualBasic6Parser::PRESERVE:
      case VisualBasic6Parser::PRINT:
      case VisualBasic6Parser::PRIVATE:
      case VisualBasic6Parser::PUBLIC:
      case VisualBasic6Parser::PUT:
      case VisualBasic6Parser::RANDOM:
      case VisualBasic6Parser::RANDOMIZE:
      case VisualBasic6Parser::RAISEEVENT:
      case VisualBasic6Parser::READ:
      case VisualBasic6Parser::REDIM:
      case VisualBasic6Parser::REM:
      case VisualBasic6Parser::RESET:
      case VisualBasic6Parser::RESUME:
      case VisualBasic6Parser::RETURN:
      case VisualBasic6Parser::RMDIR:
      case VisualBasic6Parser::RSET:
      case VisualBasic6Parser::SAVEPICTURE:
      case VisualBasic6Parser::SAVESETTING:
      case VisualBasic6Parser::SEEK:
      case VisualBasic6Parser::SELECT:
      case VisualBasic6Parser::SENDKEYS:
      case VisualBasic6Parser::SET:
      case VisualBasic6Parser::SETATTR:
      case VisualBasic6Parser::SHARED:
      case VisualBasic6Parser::SINGLE:
      case VisualBasic6Parser::SPC:
      case VisualBasic6Parser::STATIC:
      case VisualBasic6Parser::STEP:
      case VisualBasic6Parser::STOP:
      case VisualBasic6Parser::STRING:
      case VisualBasic6Parser::SUB:
      case VisualBasic6Parser::TAB:
      case VisualBasic6Parser::TEXT:
      case VisualBasic6Parser::THEN:
      case VisualBasic6Parser::TIME:
      case VisualBasic6Parser::TO:
      case VisualBasic6Parser::TRUE1:
      case VisualBasic6Parser::TYPE:
      case VisualBasic6Parser::TYPEOF:
      case VisualBasic6Parser::UNLOAD:
      case VisualBasic6Parser::UNLOCK:
      case VisualBasic6Parser::UNTIL:
      case VisualBasic6Parser::VARIANT:
      case VisualBasic6Parser::VERSION:
      case VisualBasic6Parser::WEND:
      case VisualBasic6Parser::WHILE:
      case VisualBasic6Parser::WIDTH:
      case VisualBasic6Parser::WITH:
      case VisualBasic6Parser::WITHEVENTS:
      case VisualBasic6Parser::WRITE:
      case VisualBasic6Parser::XOR:
      case VisualBasic6Parser::IDENTIFIER: {
        enterOuterAlt(_localctx, 1);
        setState(2785); 
        _errHandler->sync(this);
        alt = 1;
        do {
          switch (alt) {
            case 1: {
                  setState(2785);
                  _errHandler->sync(this);
                  switch (_input->LA(1)) {
                    case VisualBasic6Parser::IDENTIFIER: {
                      setState(2783);
                      match(VisualBasic6Parser::IDENTIFIER);
                      break;
                    }

                    case VisualBasic6Parser::ACCESS:
                    case VisualBasic6Parser::ADDRESSOF:
                    case VisualBasic6Parser::ALIAS:
                    case VisualBasic6Parser::AND:
                    case VisualBasic6Parser::ATTRIBUTE:
                    case VisualBasic6Parser::APPACTIVATE:
                    case VisualBasic6Parser::APPEND:
                    case VisualBasic6Parser::AS:
                    case VisualBasic6Parser::BEEP:
                    case VisualBasic6Parser::BEGIN:
                    case VisualBasic6Parser::BINARY:
                    case VisualBasic6Parser::BOOLEAN:
                    case VisualBasic6Parser::BYVAL:
                    case VisualBasic6Parser::BYREF:
                    case VisualBasic6Parser::BYTE:
                    case VisualBasic6Parser::CALL:
                    case VisualBasic6Parser::CASE:
                    case VisualBasic6Parser::CHDIR:
                    case VisualBasic6Parser::CHDRIVE:
                    case VisualBasic6Parser::CLASS:
                    case VisualBasic6Parser::CLOSE:
                    case VisualBasic6Parser::COLLECTION:
                    case VisualBasic6Parser::CONST:
                    case VisualBasic6Parser::DATE:
                    case VisualBasic6Parser::DECLARE:
                    case VisualBasic6Parser::DEFBOOL:
                    case VisualBasic6Parser::DEFBYTE:
                    case VisualBasic6Parser::DEFDATE:
                    case VisualBasic6Parser::DEFDBL:
                    case VisualBasic6Parser::DEFDEC:
                    case VisualBasic6Parser::DEFCUR:
                    case VisualBasic6Parser::DEFINT:
                    case VisualBasic6Parser::DEFLNG:
                    case VisualBasic6Parser::DEFOBJ:
                    case VisualBasic6Parser::DEFSNG:
                    case VisualBasic6Parser::DEFSTR:
                    case VisualBasic6Parser::DEFVAR:
                    case VisualBasic6Parser::DELETESETTING:
                    case VisualBasic6Parser::DIM:
                    case VisualBasic6Parser::DO:
                    case VisualBasic6Parser::DOUBLE:
                    case VisualBasic6Parser::EACH:
                    case VisualBasic6Parser::ELSE:
                    case VisualBasic6Parser::ELSEIF:
                    case VisualBasic6Parser::END:
                    case VisualBasic6Parser::ENUM:
                    case VisualBasic6Parser::EQV:
                    case VisualBasic6Parser::ERASE:
                    case VisualBasic6Parser::ERROR:
                    case VisualBasic6Parser::EVENT:
                    case VisualBasic6Parser::FALSE1:
                    case VisualBasic6Parser::FILECOPY:
                    case VisualBasic6Parser::FRIEND:
                    case VisualBasic6Parser::FOR:
                    case VisualBasic6Parser::FUNCTION:
                    case VisualBasic6Parser::GET:
                    case VisualBasic6Parser::GLOBAL:
                    case VisualBasic6Parser::GOSUB:
                    case VisualBasic6Parser::GOTO:
                    case VisualBasic6Parser::IF:
                    case VisualBasic6Parser::IMP:
                    case VisualBasic6Parser::IMPLEMENTS:
                    case VisualBasic6Parser::IN:
                    case VisualBasic6Parser::INPUT:
                    case VisualBasic6Parser::IS:
                    case VisualBasic6Parser::INTEGER:
                    case VisualBasic6Parser::KILL:
                    case VisualBasic6Parser::LOAD:
                    case VisualBasic6Parser::LOCK:
                    case VisualBasic6Parser::LONG:
                    case VisualBasic6Parser::LOOP:
                    case VisualBasic6Parser::LEN:
                    case VisualBasic6Parser::LET:
                    case VisualBasic6Parser::LIB:
                    case VisualBasic6Parser::LIKE:
                    case VisualBasic6Parser::LSET:
                    case VisualBasic6Parser::ME:
                    case VisualBasic6Parser::MID:
                    case VisualBasic6Parser::MKDIR:
                    case VisualBasic6Parser::MOD:
                    case VisualBasic6Parser::NAME:
                    case VisualBasic6Parser::NEXT:
                    case VisualBasic6Parser::NEW:
                    case VisualBasic6Parser::NOT:
                    case VisualBasic6Parser::NOTHING:
                    case VisualBasic6Parser::NULL1:
                    case VisualBasic6Parser::OBJECT:
                    case VisualBasic6Parser::ON:
                    case VisualBasic6Parser::OPEN:
                    case VisualBasic6Parser::OPTIONAL:
                    case VisualBasic6Parser::OR:
                    case VisualBasic6Parser::OUTPUT:
                    case VisualBasic6Parser::PARAMARRAY:
                    case VisualBasic6Parser::PRESERVE:
                    case VisualBasic6Parser::PRINT:
                    case VisualBasic6Parser::PRIVATE:
                    case VisualBasic6Parser::PUBLIC:
                    case VisualBasic6Parser::PUT:
                    case VisualBasic6Parser::RANDOM:
                    case VisualBasic6Parser::RANDOMIZE:
                    case VisualBasic6Parser::RAISEEVENT:
                    case VisualBasic6Parser::READ:
                    case VisualBasic6Parser::REDIM:
                    case VisualBasic6Parser::REM:
                    case VisualBasic6Parser::RESET:
                    case VisualBasic6Parser::RESUME:
                    case VisualBasic6Parser::RETURN:
                    case VisualBasic6Parser::RMDIR:
                    case VisualBasic6Parser::RSET:
                    case VisualBasic6Parser::SAVEPICTURE:
                    case VisualBasic6Parser::SAVESETTING:
                    case VisualBasic6Parser::SEEK:
                    case VisualBasic6Parser::SELECT:
                    case VisualBasic6Parser::SENDKEYS:
                    case VisualBasic6Parser::SET:
                    case VisualBasic6Parser::SETATTR:
                    case VisualBasic6Parser::SHARED:
                    case VisualBasic6Parser::SINGLE:
                    case VisualBasic6Parser::SPC:
                    case VisualBasic6Parser::STATIC:
                    case VisualBasic6Parser::STEP:
                    case VisualBasic6Parser::STOP:
                    case VisualBasic6Parser::STRING:
                    case VisualBasic6Parser::SUB:
                    case VisualBasic6Parser::TAB:
                    case VisualBasic6Parser::TEXT:
                    case VisualBasic6Parser::THEN:
                    case VisualBasic6Parser::TIME:
                    case VisualBasic6Parser::TO:
                    case VisualBasic6Parser::TRUE1:
                    case VisualBasic6Parser::TYPE:
                    case VisualBasic6Parser::TYPEOF:
                    case VisualBasic6Parser::UNLOAD:
                    case VisualBasic6Parser::UNLOCK:
                    case VisualBasic6Parser::UNTIL:
                    case VisualBasic6Parser::VARIANT:
                    case VisualBasic6Parser::VERSION:
                    case VisualBasic6Parser::WEND:
                    case VisualBasic6Parser::WHILE:
                    case VisualBasic6Parser::WIDTH:
                    case VisualBasic6Parser::WITH:
                    case VisualBasic6Parser::WITHEVENTS:
                    case VisualBasic6Parser::WRITE:
                    case VisualBasic6Parser::XOR: {
                      setState(2784);
                      ambiguousKeyword();
                      break;
                    }

                  default:
                    throw NoViableAltException(this);
                  }
                  break;
                }

          default:
            throw NoViableAltException(this);
          }
          setState(2787); 
          _errHandler->sync(this);
          alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 479, _ctx);
        } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
        break;
      }

      case VisualBasic6Parser::L_SQUARE_BRACKET: {
        enterOuterAlt(_localctx, 2);
        setState(2789);
        match(VisualBasic6Parser::L_SQUARE_BRACKET);
        setState(2792); 
        _errHandler->sync(this);
        _la = _input->LA(1);
        do {
          setState(2792);
          _errHandler->sync(this);
          switch (_input->LA(1)) {
            case VisualBasic6Parser::IDENTIFIER: {
              setState(2790);
              match(VisualBasic6Parser::IDENTIFIER);
              break;
            }

            case VisualBasic6Parser::ACCESS:
            case VisualBasic6Parser::ADDRESSOF:
            case VisualBasic6Parser::ALIAS:
            case VisualBasic6Parser::AND:
            case VisualBasic6Parser::ATTRIBUTE:
            case VisualBasic6Parser::APPACTIVATE:
            case VisualBasic6Parser::APPEND:
            case VisualBasic6Parser::AS:
            case VisualBasic6Parser::BEEP:
            case VisualBasic6Parser::BEGIN:
            case VisualBasic6Parser::BINARY:
            case VisualBasic6Parser::BOOLEAN:
            case VisualBasic6Parser::BYVAL:
            case VisualBasic6Parser::BYREF:
            case VisualBasic6Parser::BYTE:
            case VisualBasic6Parser::CALL:
            case VisualBasic6Parser::CASE:
            case VisualBasic6Parser::CHDIR:
            case VisualBasic6Parser::CHDRIVE:
            case VisualBasic6Parser::CLASS:
            case VisualBasic6Parser::CLOSE:
            case VisualBasic6Parser::COLLECTION:
            case VisualBasic6Parser::CONST:
            case VisualBasic6Parser::DATE:
            case VisualBasic6Parser::DECLARE:
            case VisualBasic6Parser::DEFBOOL:
            case VisualBasic6Parser::DEFBYTE:
            case VisualBasic6Parser::DEFDATE:
            case VisualBasic6Parser::DEFDBL:
            case VisualBasic6Parser::DEFDEC:
            case VisualBasic6Parser::DEFCUR:
            case VisualBasic6Parser::DEFINT:
            case VisualBasic6Parser::DEFLNG:
            case VisualBasic6Parser::DEFOBJ:
            case VisualBasic6Parser::DEFSNG:
            case VisualBasic6Parser::DEFSTR:
            case VisualBasic6Parser::DEFVAR:
            case VisualBasic6Parser::DELETESETTING:
            case VisualBasic6Parser::DIM:
            case VisualBasic6Parser::DO:
            case VisualBasic6Parser::DOUBLE:
            case VisualBasic6Parser::EACH:
            case VisualBasic6Parser::ELSE:
            case VisualBasic6Parser::ELSEIF:
            case VisualBasic6Parser::END:
            case VisualBasic6Parser::ENUM:
            case VisualBasic6Parser::EQV:
            case VisualBasic6Parser::ERASE:
            case VisualBasic6Parser::ERROR:
            case VisualBasic6Parser::EVENT:
            case VisualBasic6Parser::FALSE1:
            case VisualBasic6Parser::FILECOPY:
            case VisualBasic6Parser::FRIEND:
            case VisualBasic6Parser::FOR:
            case VisualBasic6Parser::FUNCTION:
            case VisualBasic6Parser::GET:
            case VisualBasic6Parser::GLOBAL:
            case VisualBasic6Parser::GOSUB:
            case VisualBasic6Parser::GOTO:
            case VisualBasic6Parser::IF:
            case VisualBasic6Parser::IMP:
            case VisualBasic6Parser::IMPLEMENTS:
            case VisualBasic6Parser::IN:
            case VisualBasic6Parser::INPUT:
            case VisualBasic6Parser::IS:
            case VisualBasic6Parser::INTEGER:
            case VisualBasic6Parser::KILL:
            case VisualBasic6Parser::LOAD:
            case VisualBasic6Parser::LOCK:
            case VisualBasic6Parser::LONG:
            case VisualBasic6Parser::LOOP:
            case VisualBasic6Parser::LEN:
            case VisualBasic6Parser::LET:
            case VisualBasic6Parser::LIB:
            case VisualBasic6Parser::LIKE:
            case VisualBasic6Parser::LSET:
            case VisualBasic6Parser::ME:
            case VisualBasic6Parser::MID:
            case VisualBasic6Parser::MKDIR:
            case VisualBasic6Parser::MOD:
            case VisualBasic6Parser::NAME:
            case VisualBasic6Parser::NEXT:
            case VisualBasic6Parser::NEW:
            case VisualBasic6Parser::NOT:
            case VisualBasic6Parser::NOTHING:
            case VisualBasic6Parser::NULL1:
            case VisualBasic6Parser::OBJECT:
            case VisualBasic6Parser::ON:
            case VisualBasic6Parser::OPEN:
            case VisualBasic6Parser::OPTIONAL:
            case VisualBasic6Parser::OR:
            case VisualBasic6Parser::OUTPUT:
            case VisualBasic6Parser::PARAMARRAY:
            case VisualBasic6Parser::PRESERVE:
            case VisualBasic6Parser::PRINT:
            case VisualBasic6Parser::PRIVATE:
            case VisualBasic6Parser::PUBLIC:
            case VisualBasic6Parser::PUT:
            case VisualBasic6Parser::RANDOM:
            case VisualBasic6Parser::RANDOMIZE:
            case VisualBasic6Parser::RAISEEVENT:
            case VisualBasic6Parser::READ:
            case VisualBasic6Parser::REDIM:
            case VisualBasic6Parser::REM:
            case VisualBasic6Parser::RESET:
            case VisualBasic6Parser::RESUME:
            case VisualBasic6Parser::RETURN:
            case VisualBasic6Parser::RMDIR:
            case VisualBasic6Parser::RSET:
            case VisualBasic6Parser::SAVEPICTURE:
            case VisualBasic6Parser::SAVESETTING:
            case VisualBasic6Parser::SEEK:
            case VisualBasic6Parser::SELECT:
            case VisualBasic6Parser::SENDKEYS:
            case VisualBasic6Parser::SET:
            case VisualBasic6Parser::SETATTR:
            case VisualBasic6Parser::SHARED:
            case VisualBasic6Parser::SINGLE:
            case VisualBasic6Parser::SPC:
            case VisualBasic6Parser::STATIC:
            case VisualBasic6Parser::STEP:
            case VisualBasic6Parser::STOP:
            case VisualBasic6Parser::STRING:
            case VisualBasic6Parser::SUB:
            case VisualBasic6Parser::TAB:
            case VisualBasic6Parser::TEXT:
            case VisualBasic6Parser::THEN:
            case VisualBasic6Parser::TIME:
            case VisualBasic6Parser::TO:
            case VisualBasic6Parser::TRUE1:
            case VisualBasic6Parser::TYPE:
            case VisualBasic6Parser::TYPEOF:
            case VisualBasic6Parser::UNLOAD:
            case VisualBasic6Parser::UNLOCK:
            case VisualBasic6Parser::UNTIL:
            case VisualBasic6Parser::VARIANT:
            case VisualBasic6Parser::VERSION:
            case VisualBasic6Parser::WEND:
            case VisualBasic6Parser::WHILE:
            case VisualBasic6Parser::WIDTH:
            case VisualBasic6Parser::WITH:
            case VisualBasic6Parser::WITHEVENTS:
            case VisualBasic6Parser::WRITE:
            case VisualBasic6Parser::XOR: {
              setState(2791);
              ambiguousKeyword();
              break;
            }

          default:
            throw NoViableAltException(this);
          }
          setState(2794); 
          _errHandler->sync(this);
          _la = _input->LA(1);
        } while ((((_la & ~ 0x3fULL) == 0) &&
          ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
          | (1ULL << VisualBasic6Parser::ADDRESSOF)
          | (1ULL << VisualBasic6Parser::ALIAS)
          | (1ULL << VisualBasic6Parser::AND)
          | (1ULL << VisualBasic6Parser::ATTRIBUTE)
          | (1ULL << VisualBasic6Parser::APPACTIVATE)
          | (1ULL << VisualBasic6Parser::APPEND)
          | (1ULL << VisualBasic6Parser::AS)
          | (1ULL << VisualBasic6Parser::BEEP)
          | (1ULL << VisualBasic6Parser::BEGIN)
          | (1ULL << VisualBasic6Parser::BINARY)
          | (1ULL << VisualBasic6Parser::BOOLEAN)
          | (1ULL << VisualBasic6Parser::BYVAL)
          | (1ULL << VisualBasic6Parser::BYREF)
          | (1ULL << VisualBasic6Parser::BYTE)
          | (1ULL << VisualBasic6Parser::CALL)
          | (1ULL << VisualBasic6Parser::CASE)
          | (1ULL << VisualBasic6Parser::CHDIR)
          | (1ULL << VisualBasic6Parser::CHDRIVE)
          | (1ULL << VisualBasic6Parser::CLASS)
          | (1ULL << VisualBasic6Parser::CLOSE)
          | (1ULL << VisualBasic6Parser::COLLECTION)
          | (1ULL << VisualBasic6Parser::CONST)
          | (1ULL << VisualBasic6Parser::DATE)
          | (1ULL << VisualBasic6Parser::DECLARE)
          | (1ULL << VisualBasic6Parser::DEFBOOL)
          | (1ULL << VisualBasic6Parser::DEFBYTE)
          | (1ULL << VisualBasic6Parser::DEFDATE)
          | (1ULL << VisualBasic6Parser::DEFDBL)
          | (1ULL << VisualBasic6Parser::DEFDEC)
          | (1ULL << VisualBasic6Parser::DEFCUR)
          | (1ULL << VisualBasic6Parser::DEFINT)
          | (1ULL << VisualBasic6Parser::DEFLNG)
          | (1ULL << VisualBasic6Parser::DEFOBJ)
          | (1ULL << VisualBasic6Parser::DEFSNG)
          | (1ULL << VisualBasic6Parser::DEFSTR)
          | (1ULL << VisualBasic6Parser::DEFVAR)
          | (1ULL << VisualBasic6Parser::DELETESETTING)
          | (1ULL << VisualBasic6Parser::DIM)
          | (1ULL << VisualBasic6Parser::DO)
          | (1ULL << VisualBasic6Parser::DOUBLE)
          | (1ULL << VisualBasic6Parser::EACH)
          | (1ULL << VisualBasic6Parser::ELSE)
          | (1ULL << VisualBasic6Parser::ELSEIF)
          | (1ULL << VisualBasic6Parser::END)
          | (1ULL << VisualBasic6Parser::ENUM)
          | (1ULL << VisualBasic6Parser::EQV)
          | (1ULL << VisualBasic6Parser::ERASE)
          | (1ULL << VisualBasic6Parser::ERROR)
          | (1ULL << VisualBasic6Parser::EVENT))) != 0) || ((((_la - 66) & ~ 0x3fULL) == 0) &&
          ((1ULL << (_la - 66)) & ((1ULL << (VisualBasic6Parser::FALSE1 - 66))
          | (1ULL << (VisualBasic6Parser::FILECOPY - 66))
          | (1ULL << (VisualBasic6Parser::FRIEND - 66))
          | (1ULL << (VisualBasic6Parser::FOR - 66))
          | (1ULL << (VisualBasic6Parser::FUNCTION - 66))
          | (1ULL << (VisualBasic6Parser::GET - 66))
          | (1ULL << (VisualBasic6Parser::GLOBAL - 66))
          | (1ULL << (VisualBasic6Parser::GOSUB - 66))
          | (1ULL << (VisualBasic6Parser::GOTO - 66))
          | (1ULL << (VisualBasic6Parser::IF - 66))
          | (1ULL << (VisualBasic6Parser::IMP - 66))
          | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 66))
          | (1ULL << (VisualBasic6Parser::IN - 66))
          | (1ULL << (VisualBasic6Parser::INPUT - 66))
          | (1ULL << (VisualBasic6Parser::IS - 66))
          | (1ULL << (VisualBasic6Parser::INTEGER - 66))
          | (1ULL << (VisualBasic6Parser::KILL - 66))
          | (1ULL << (VisualBasic6Parser::LOAD - 66))
          | (1ULL << (VisualBasic6Parser::LOCK - 66))
          | (1ULL << (VisualBasic6Parser::LONG - 66))
          | (1ULL << (VisualBasic6Parser::LOOP - 66))
          | (1ULL << (VisualBasic6Parser::LEN - 66))
          | (1ULL << (VisualBasic6Parser::LET - 66))
          | (1ULL << (VisualBasic6Parser::LIB - 66))
          | (1ULL << (VisualBasic6Parser::LIKE - 66))
          | (1ULL << (VisualBasic6Parser::LSET - 66))
          | (1ULL << (VisualBasic6Parser::ME - 66))
          | (1ULL << (VisualBasic6Parser::MID - 66))
          | (1ULL << (VisualBasic6Parser::MKDIR - 66))
          | (1ULL << (VisualBasic6Parser::MOD - 66))
          | (1ULL << (VisualBasic6Parser::NAME - 66))
          | (1ULL << (VisualBasic6Parser::NEXT - 66))
          | (1ULL << (VisualBasic6Parser::NEW - 66))
          | (1ULL << (VisualBasic6Parser::NOT - 66))
          | (1ULL << (VisualBasic6Parser::NOTHING - 66))
          | (1ULL << (VisualBasic6Parser::NULL1 - 66))
          | (1ULL << (VisualBasic6Parser::OBJECT - 66))
          | (1ULL << (VisualBasic6Parser::ON - 66))
          | (1ULL << (VisualBasic6Parser::OPEN - 66))
          | (1ULL << (VisualBasic6Parser::OPTIONAL - 66))
          | (1ULL << (VisualBasic6Parser::OR - 66))
          | (1ULL << (VisualBasic6Parser::OUTPUT - 66))
          | (1ULL << (VisualBasic6Parser::PARAMARRAY - 66))
          | (1ULL << (VisualBasic6Parser::PRESERVE - 66))
          | (1ULL << (VisualBasic6Parser::PRINT - 66))
          | (1ULL << (VisualBasic6Parser::PRIVATE - 66))
          | (1ULL << (VisualBasic6Parser::PUBLIC - 66)))) != 0) || ((((_la - 130) & ~ 0x3fULL) == 0) &&
          ((1ULL << (_la - 130)) & ((1ULL << (VisualBasic6Parser::PUT - 130))
          | (1ULL << (VisualBasic6Parser::RANDOM - 130))
          | (1ULL << (VisualBasic6Parser::RANDOMIZE - 130))
          | (1ULL << (VisualBasic6Parser::RAISEEVENT - 130))
          | (1ULL << (VisualBasic6Parser::READ - 130))
          | (1ULL << (VisualBasic6Parser::REDIM - 130))
          | (1ULL << (VisualBasic6Parser::REM - 130))
          | (1ULL << (VisualBasic6Parser::RESET - 130))
          | (1ULL << (VisualBasic6Parser::RESUME - 130))
          | (1ULL << (VisualBasic6Parser::RETURN - 130))
          | (1ULL << (VisualBasic6Parser::RMDIR - 130))
          | (1ULL << (VisualBasic6Parser::RSET - 130))
          | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 130))
          | (1ULL << (VisualBasic6Parser::SAVESETTING - 130))
          | (1ULL << (VisualBasic6Parser::SEEK - 130))
          | (1ULL << (VisualBasic6Parser::SELECT - 130))
          | (1ULL << (VisualBasic6Parser::SENDKEYS - 130))
          | (1ULL << (VisualBasic6Parser::SET - 130))
          | (1ULL << (VisualBasic6Parser::SETATTR - 130))
          | (1ULL << (VisualBasic6Parser::SHARED - 130))
          | (1ULL << (VisualBasic6Parser::SINGLE - 130))
          | (1ULL << (VisualBasic6Parser::SPC - 130))
          | (1ULL << (VisualBasic6Parser::STATIC - 130))
          | (1ULL << (VisualBasic6Parser::STEP - 130))
          | (1ULL << (VisualBasic6Parser::STOP - 130))
          | (1ULL << (VisualBasic6Parser::STRING - 130))
          | (1ULL << (VisualBasic6Parser::SUB - 130))
          | (1ULL << (VisualBasic6Parser::TAB - 130))
          | (1ULL << (VisualBasic6Parser::TEXT - 130))
          | (1ULL << (VisualBasic6Parser::THEN - 130))
          | (1ULL << (VisualBasic6Parser::TIME - 130))
          | (1ULL << (VisualBasic6Parser::TO - 130))
          | (1ULL << (VisualBasic6Parser::TRUE1 - 130))
          | (1ULL << (VisualBasic6Parser::TYPE - 130))
          | (1ULL << (VisualBasic6Parser::TYPEOF - 130))
          | (1ULL << (VisualBasic6Parser::UNLOAD - 130))
          | (1ULL << (VisualBasic6Parser::UNLOCK - 130))
          | (1ULL << (VisualBasic6Parser::UNTIL - 130))
          | (1ULL << (VisualBasic6Parser::VARIANT - 130))
          | (1ULL << (VisualBasic6Parser::VERSION - 130))
          | (1ULL << (VisualBasic6Parser::WEND - 130))
          | (1ULL << (VisualBasic6Parser::WHILE - 130))
          | (1ULL << (VisualBasic6Parser::WIDTH - 130))
          | (1ULL << (VisualBasic6Parser::WITH - 130))
          | (1ULL << (VisualBasic6Parser::WITHEVENTS - 130))
          | (1ULL << (VisualBasic6Parser::WRITE - 130))
          | (1ULL << (VisualBasic6Parser::XOR - 130)))) != 0) || _la == VisualBasic6Parser::IDENTIFIER);
        setState(2796);
        match(VisualBasic6Parser::R_SQUARE_BRACKET);
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

//----------------- AsTypeClauseContext ------------------------------------------------------------------

VisualBasic6Parser::AsTypeClauseContext::AsTypeClauseContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::AsTypeClauseContext::AS() {
  return getToken(VisualBasic6Parser::AS, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::AsTypeClauseContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::AsTypeClauseContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}

VisualBasic6Parser::TypeContext* VisualBasic6Parser::AsTypeClauseContext::type() {
  return getRuleContext<VisualBasic6Parser::TypeContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::AsTypeClauseContext::NEW() {
  return getToken(VisualBasic6Parser::NEW, 0);
}

VisualBasic6Parser::FieldLengthContext* VisualBasic6Parser::AsTypeClauseContext::fieldLength() {
  return getRuleContext<VisualBasic6Parser::FieldLengthContext>(0);
}


size_t VisualBasic6Parser::AsTypeClauseContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleAsTypeClause;
}

antlrcpp::Any VisualBasic6Parser::AsTypeClauseContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitAsTypeClause(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::AsTypeClauseContext* VisualBasic6Parser::asTypeClause() {
  AsTypeClauseContext *_localctx = _tracker.createInstance<AsTypeClauseContext>(_ctx, getState());
  enterRule(_localctx, 280, VisualBasic6Parser::RuleAsTypeClause);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2799);
    match(VisualBasic6Parser::AS);
    setState(2800);
    match(VisualBasic6Parser::WS);
    setState(2803);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 483, _ctx)) {
    case 1: {
      setState(2801);
      match(VisualBasic6Parser::NEW);
      setState(2802);
      match(VisualBasic6Parser::WS);
      break;
    }

    }
    setState(2805);
    type();
    setState(2808);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 484, _ctx)) {
    case 1: {
      setState(2806);
      match(VisualBasic6Parser::WS);
      setState(2807);
      fieldLength();
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

//----------------- BaseTypeContext ------------------------------------------------------------------

VisualBasic6Parser::BaseTypeContext::BaseTypeContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::BaseTypeContext::BOOLEAN() {
  return getToken(VisualBasic6Parser::BOOLEAN, 0);
}

tree::TerminalNode* VisualBasic6Parser::BaseTypeContext::BYTE() {
  return getToken(VisualBasic6Parser::BYTE, 0);
}

tree::TerminalNode* VisualBasic6Parser::BaseTypeContext::COLLECTION() {
  return getToken(VisualBasic6Parser::COLLECTION, 0);
}

tree::TerminalNode* VisualBasic6Parser::BaseTypeContext::DATE() {
  return getToken(VisualBasic6Parser::DATE, 0);
}

tree::TerminalNode* VisualBasic6Parser::BaseTypeContext::DOUBLE() {
  return getToken(VisualBasic6Parser::DOUBLE, 0);
}

tree::TerminalNode* VisualBasic6Parser::BaseTypeContext::INTEGER() {
  return getToken(VisualBasic6Parser::INTEGER, 0);
}

tree::TerminalNode* VisualBasic6Parser::BaseTypeContext::LONG() {
  return getToken(VisualBasic6Parser::LONG, 0);
}

tree::TerminalNode* VisualBasic6Parser::BaseTypeContext::OBJECT() {
  return getToken(VisualBasic6Parser::OBJECT, 0);
}

tree::TerminalNode* VisualBasic6Parser::BaseTypeContext::SINGLE() {
  return getToken(VisualBasic6Parser::SINGLE, 0);
}

tree::TerminalNode* VisualBasic6Parser::BaseTypeContext::STRING() {
  return getToken(VisualBasic6Parser::STRING, 0);
}

tree::TerminalNode* VisualBasic6Parser::BaseTypeContext::VARIANT() {
  return getToken(VisualBasic6Parser::VARIANT, 0);
}


size_t VisualBasic6Parser::BaseTypeContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleBaseType;
}

antlrcpp::Any VisualBasic6Parser::BaseTypeContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitBaseType(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::BaseTypeContext* VisualBasic6Parser::baseType() {
  BaseTypeContext *_localctx = _tracker.createInstance<BaseTypeContext>(_ctx, getState());
  enterRule(_localctx, 282, VisualBasic6Parser::RuleBaseType);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2810);
    _la = _input->LA(1);
    if (!((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DOUBLE))) != 0) || ((((_la - 81) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 81)) & ((1ULL << (VisualBasic6Parser::INTEGER - 81))
      | (1ULL << (VisualBasic6Parser::LONG - 81))
      | (1ULL << (VisualBasic6Parser::OBJECT - 81)))) != 0) || ((((_la - 151) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 151)) & ((1ULL << (VisualBasic6Parser::SINGLE - 151))
      | (1ULL << (VisualBasic6Parser::STRING - 151))
      | (1ULL << (VisualBasic6Parser::VARIANT - 151)))) != 0))) {
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

//----------------- CertainIdentifierContext ------------------------------------------------------------------

VisualBasic6Parser::CertainIdentifierContext::CertainIdentifierContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::CertainIdentifierContext::IDENTIFIER() {
  return getTokens(VisualBasic6Parser::IDENTIFIER);
}

tree::TerminalNode* VisualBasic6Parser::CertainIdentifierContext::IDENTIFIER(size_t i) {
  return getToken(VisualBasic6Parser::IDENTIFIER, i);
}

std::vector<VisualBasic6Parser::AmbiguousKeywordContext *> VisualBasic6Parser::CertainIdentifierContext::ambiguousKeyword() {
  return getRuleContexts<VisualBasic6Parser::AmbiguousKeywordContext>();
}

VisualBasic6Parser::AmbiguousKeywordContext* VisualBasic6Parser::CertainIdentifierContext::ambiguousKeyword(size_t i) {
  return getRuleContext<VisualBasic6Parser::AmbiguousKeywordContext>(i);
}


size_t VisualBasic6Parser::CertainIdentifierContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleCertainIdentifier;
}

antlrcpp::Any VisualBasic6Parser::CertainIdentifierContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitCertainIdentifier(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::CertainIdentifierContext* VisualBasic6Parser::certainIdentifier() {
  CertainIdentifierContext *_localctx = _tracker.createInstance<CertainIdentifierContext>(_ctx, getState());
  enterRule(_localctx, 284, VisualBasic6Parser::RuleCertainIdentifier);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    setState(2827);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case VisualBasic6Parser::IDENTIFIER: {
        enterOuterAlt(_localctx, 1);
        setState(2812);
        match(VisualBasic6Parser::IDENTIFIER);
        setState(2817);
        _errHandler->sync(this);
        alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 486, _ctx);
        while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
          if (alt == 1) {
            setState(2815);
            _errHandler->sync(this);
            switch (_input->LA(1)) {
              case VisualBasic6Parser::ACCESS:
              case VisualBasic6Parser::ADDRESSOF:
              case VisualBasic6Parser::ALIAS:
              case VisualBasic6Parser::AND:
              case VisualBasic6Parser::ATTRIBUTE:
              case VisualBasic6Parser::APPACTIVATE:
              case VisualBasic6Parser::APPEND:
              case VisualBasic6Parser::AS:
              case VisualBasic6Parser::BEEP:
              case VisualBasic6Parser::BEGIN:
              case VisualBasic6Parser::BINARY:
              case VisualBasic6Parser::BOOLEAN:
              case VisualBasic6Parser::BYVAL:
              case VisualBasic6Parser::BYREF:
              case VisualBasic6Parser::BYTE:
              case VisualBasic6Parser::CALL:
              case VisualBasic6Parser::CASE:
              case VisualBasic6Parser::CHDIR:
              case VisualBasic6Parser::CHDRIVE:
              case VisualBasic6Parser::CLASS:
              case VisualBasic6Parser::CLOSE:
              case VisualBasic6Parser::COLLECTION:
              case VisualBasic6Parser::CONST:
              case VisualBasic6Parser::DATE:
              case VisualBasic6Parser::DECLARE:
              case VisualBasic6Parser::DEFBOOL:
              case VisualBasic6Parser::DEFBYTE:
              case VisualBasic6Parser::DEFDATE:
              case VisualBasic6Parser::DEFDBL:
              case VisualBasic6Parser::DEFDEC:
              case VisualBasic6Parser::DEFCUR:
              case VisualBasic6Parser::DEFINT:
              case VisualBasic6Parser::DEFLNG:
              case VisualBasic6Parser::DEFOBJ:
              case VisualBasic6Parser::DEFSNG:
              case VisualBasic6Parser::DEFSTR:
              case VisualBasic6Parser::DEFVAR:
              case VisualBasic6Parser::DELETESETTING:
              case VisualBasic6Parser::DIM:
              case VisualBasic6Parser::DO:
              case VisualBasic6Parser::DOUBLE:
              case VisualBasic6Parser::EACH:
              case VisualBasic6Parser::ELSE:
              case VisualBasic6Parser::ELSEIF:
              case VisualBasic6Parser::END:
              case VisualBasic6Parser::ENUM:
              case VisualBasic6Parser::EQV:
              case VisualBasic6Parser::ERASE:
              case VisualBasic6Parser::ERROR:
              case VisualBasic6Parser::EVENT:
              case VisualBasic6Parser::FALSE1:
              case VisualBasic6Parser::FILECOPY:
              case VisualBasic6Parser::FRIEND:
              case VisualBasic6Parser::FOR:
              case VisualBasic6Parser::FUNCTION:
              case VisualBasic6Parser::GET:
              case VisualBasic6Parser::GLOBAL:
              case VisualBasic6Parser::GOSUB:
              case VisualBasic6Parser::GOTO:
              case VisualBasic6Parser::IF:
              case VisualBasic6Parser::IMP:
              case VisualBasic6Parser::IMPLEMENTS:
              case VisualBasic6Parser::IN:
              case VisualBasic6Parser::INPUT:
              case VisualBasic6Parser::IS:
              case VisualBasic6Parser::INTEGER:
              case VisualBasic6Parser::KILL:
              case VisualBasic6Parser::LOAD:
              case VisualBasic6Parser::LOCK:
              case VisualBasic6Parser::LONG:
              case VisualBasic6Parser::LOOP:
              case VisualBasic6Parser::LEN:
              case VisualBasic6Parser::LET:
              case VisualBasic6Parser::LIB:
              case VisualBasic6Parser::LIKE:
              case VisualBasic6Parser::LSET:
              case VisualBasic6Parser::ME:
              case VisualBasic6Parser::MID:
              case VisualBasic6Parser::MKDIR:
              case VisualBasic6Parser::MOD:
              case VisualBasic6Parser::NAME:
              case VisualBasic6Parser::NEXT:
              case VisualBasic6Parser::NEW:
              case VisualBasic6Parser::NOT:
              case VisualBasic6Parser::NOTHING:
              case VisualBasic6Parser::NULL1:
              case VisualBasic6Parser::OBJECT:
              case VisualBasic6Parser::ON:
              case VisualBasic6Parser::OPEN:
              case VisualBasic6Parser::OPTIONAL:
              case VisualBasic6Parser::OR:
              case VisualBasic6Parser::OUTPUT:
              case VisualBasic6Parser::PARAMARRAY:
              case VisualBasic6Parser::PRESERVE:
              case VisualBasic6Parser::PRINT:
              case VisualBasic6Parser::PRIVATE:
              case VisualBasic6Parser::PUBLIC:
              case VisualBasic6Parser::PUT:
              case VisualBasic6Parser::RANDOM:
              case VisualBasic6Parser::RANDOMIZE:
              case VisualBasic6Parser::RAISEEVENT:
              case VisualBasic6Parser::READ:
              case VisualBasic6Parser::REDIM:
              case VisualBasic6Parser::REM:
              case VisualBasic6Parser::RESET:
              case VisualBasic6Parser::RESUME:
              case VisualBasic6Parser::RETURN:
              case VisualBasic6Parser::RMDIR:
              case VisualBasic6Parser::RSET:
              case VisualBasic6Parser::SAVEPICTURE:
              case VisualBasic6Parser::SAVESETTING:
              case VisualBasic6Parser::SEEK:
              case VisualBasic6Parser::SELECT:
              case VisualBasic6Parser::SENDKEYS:
              case VisualBasic6Parser::SET:
              case VisualBasic6Parser::SETATTR:
              case VisualBasic6Parser::SHARED:
              case VisualBasic6Parser::SINGLE:
              case VisualBasic6Parser::SPC:
              case VisualBasic6Parser::STATIC:
              case VisualBasic6Parser::STEP:
              case VisualBasic6Parser::STOP:
              case VisualBasic6Parser::STRING:
              case VisualBasic6Parser::SUB:
              case VisualBasic6Parser::TAB:
              case VisualBasic6Parser::TEXT:
              case VisualBasic6Parser::THEN:
              case VisualBasic6Parser::TIME:
              case VisualBasic6Parser::TO:
              case VisualBasic6Parser::TRUE1:
              case VisualBasic6Parser::TYPE:
              case VisualBasic6Parser::TYPEOF:
              case VisualBasic6Parser::UNLOAD:
              case VisualBasic6Parser::UNLOCK:
              case VisualBasic6Parser::UNTIL:
              case VisualBasic6Parser::VARIANT:
              case VisualBasic6Parser::VERSION:
              case VisualBasic6Parser::WEND:
              case VisualBasic6Parser::WHILE:
              case VisualBasic6Parser::WIDTH:
              case VisualBasic6Parser::WITH:
              case VisualBasic6Parser::WITHEVENTS:
              case VisualBasic6Parser::WRITE:
              case VisualBasic6Parser::XOR: {
                setState(2813);
                ambiguousKeyword();
                break;
              }

              case VisualBasic6Parser::IDENTIFIER: {
                setState(2814);
                match(VisualBasic6Parser::IDENTIFIER);
                break;
              }

            default:
              throw NoViableAltException(this);
            } 
          }
          setState(2819);
          _errHandler->sync(this);
          alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 486, _ctx);
        }
        break;
      }

      case VisualBasic6Parser::ACCESS:
      case VisualBasic6Parser::ADDRESSOF:
      case VisualBasic6Parser::ALIAS:
      case VisualBasic6Parser::AND:
      case VisualBasic6Parser::ATTRIBUTE:
      case VisualBasic6Parser::APPACTIVATE:
      case VisualBasic6Parser::APPEND:
      case VisualBasic6Parser::AS:
      case VisualBasic6Parser::BEEP:
      case VisualBasic6Parser::BEGIN:
      case VisualBasic6Parser::BINARY:
      case VisualBasic6Parser::BOOLEAN:
      case VisualBasic6Parser::BYVAL:
      case VisualBasic6Parser::BYREF:
      case VisualBasic6Parser::BYTE:
      case VisualBasic6Parser::CALL:
      case VisualBasic6Parser::CASE:
      case VisualBasic6Parser::CHDIR:
      case VisualBasic6Parser::CHDRIVE:
      case VisualBasic6Parser::CLASS:
      case VisualBasic6Parser::CLOSE:
      case VisualBasic6Parser::COLLECTION:
      case VisualBasic6Parser::CONST:
      case VisualBasic6Parser::DATE:
      case VisualBasic6Parser::DECLARE:
      case VisualBasic6Parser::DEFBOOL:
      case VisualBasic6Parser::DEFBYTE:
      case VisualBasic6Parser::DEFDATE:
      case VisualBasic6Parser::DEFDBL:
      case VisualBasic6Parser::DEFDEC:
      case VisualBasic6Parser::DEFCUR:
      case VisualBasic6Parser::DEFINT:
      case VisualBasic6Parser::DEFLNG:
      case VisualBasic6Parser::DEFOBJ:
      case VisualBasic6Parser::DEFSNG:
      case VisualBasic6Parser::DEFSTR:
      case VisualBasic6Parser::DEFVAR:
      case VisualBasic6Parser::DELETESETTING:
      case VisualBasic6Parser::DIM:
      case VisualBasic6Parser::DO:
      case VisualBasic6Parser::DOUBLE:
      case VisualBasic6Parser::EACH:
      case VisualBasic6Parser::ELSE:
      case VisualBasic6Parser::ELSEIF:
      case VisualBasic6Parser::END:
      case VisualBasic6Parser::ENUM:
      case VisualBasic6Parser::EQV:
      case VisualBasic6Parser::ERASE:
      case VisualBasic6Parser::ERROR:
      case VisualBasic6Parser::EVENT:
      case VisualBasic6Parser::FALSE1:
      case VisualBasic6Parser::FILECOPY:
      case VisualBasic6Parser::FRIEND:
      case VisualBasic6Parser::FOR:
      case VisualBasic6Parser::FUNCTION:
      case VisualBasic6Parser::GET:
      case VisualBasic6Parser::GLOBAL:
      case VisualBasic6Parser::GOSUB:
      case VisualBasic6Parser::GOTO:
      case VisualBasic6Parser::IF:
      case VisualBasic6Parser::IMP:
      case VisualBasic6Parser::IMPLEMENTS:
      case VisualBasic6Parser::IN:
      case VisualBasic6Parser::INPUT:
      case VisualBasic6Parser::IS:
      case VisualBasic6Parser::INTEGER:
      case VisualBasic6Parser::KILL:
      case VisualBasic6Parser::LOAD:
      case VisualBasic6Parser::LOCK:
      case VisualBasic6Parser::LONG:
      case VisualBasic6Parser::LOOP:
      case VisualBasic6Parser::LEN:
      case VisualBasic6Parser::LET:
      case VisualBasic6Parser::LIB:
      case VisualBasic6Parser::LIKE:
      case VisualBasic6Parser::LSET:
      case VisualBasic6Parser::ME:
      case VisualBasic6Parser::MID:
      case VisualBasic6Parser::MKDIR:
      case VisualBasic6Parser::MOD:
      case VisualBasic6Parser::NAME:
      case VisualBasic6Parser::NEXT:
      case VisualBasic6Parser::NEW:
      case VisualBasic6Parser::NOT:
      case VisualBasic6Parser::NOTHING:
      case VisualBasic6Parser::NULL1:
      case VisualBasic6Parser::OBJECT:
      case VisualBasic6Parser::ON:
      case VisualBasic6Parser::OPEN:
      case VisualBasic6Parser::OPTIONAL:
      case VisualBasic6Parser::OR:
      case VisualBasic6Parser::OUTPUT:
      case VisualBasic6Parser::PARAMARRAY:
      case VisualBasic6Parser::PRESERVE:
      case VisualBasic6Parser::PRINT:
      case VisualBasic6Parser::PRIVATE:
      case VisualBasic6Parser::PUBLIC:
      case VisualBasic6Parser::PUT:
      case VisualBasic6Parser::RANDOM:
      case VisualBasic6Parser::RANDOMIZE:
      case VisualBasic6Parser::RAISEEVENT:
      case VisualBasic6Parser::READ:
      case VisualBasic6Parser::REDIM:
      case VisualBasic6Parser::REM:
      case VisualBasic6Parser::RESET:
      case VisualBasic6Parser::RESUME:
      case VisualBasic6Parser::RETURN:
      case VisualBasic6Parser::RMDIR:
      case VisualBasic6Parser::RSET:
      case VisualBasic6Parser::SAVEPICTURE:
      case VisualBasic6Parser::SAVESETTING:
      case VisualBasic6Parser::SEEK:
      case VisualBasic6Parser::SELECT:
      case VisualBasic6Parser::SENDKEYS:
      case VisualBasic6Parser::SET:
      case VisualBasic6Parser::SETATTR:
      case VisualBasic6Parser::SHARED:
      case VisualBasic6Parser::SINGLE:
      case VisualBasic6Parser::SPC:
      case VisualBasic6Parser::STATIC:
      case VisualBasic6Parser::STEP:
      case VisualBasic6Parser::STOP:
      case VisualBasic6Parser::STRING:
      case VisualBasic6Parser::SUB:
      case VisualBasic6Parser::TAB:
      case VisualBasic6Parser::TEXT:
      case VisualBasic6Parser::THEN:
      case VisualBasic6Parser::TIME:
      case VisualBasic6Parser::TO:
      case VisualBasic6Parser::TRUE1:
      case VisualBasic6Parser::TYPE:
      case VisualBasic6Parser::TYPEOF:
      case VisualBasic6Parser::UNLOAD:
      case VisualBasic6Parser::UNLOCK:
      case VisualBasic6Parser::UNTIL:
      case VisualBasic6Parser::VARIANT:
      case VisualBasic6Parser::VERSION:
      case VisualBasic6Parser::WEND:
      case VisualBasic6Parser::WHILE:
      case VisualBasic6Parser::WIDTH:
      case VisualBasic6Parser::WITH:
      case VisualBasic6Parser::WITHEVENTS:
      case VisualBasic6Parser::WRITE:
      case VisualBasic6Parser::XOR: {
        enterOuterAlt(_localctx, 2);
        setState(2820);
        ambiguousKeyword();
        setState(2823); 
        _errHandler->sync(this);
        alt = 1;
        do {
          switch (alt) {
            case 1: {
                  setState(2823);
                  _errHandler->sync(this);
                  switch (_input->LA(1)) {
                    case VisualBasic6Parser::ACCESS:
                    case VisualBasic6Parser::ADDRESSOF:
                    case VisualBasic6Parser::ALIAS:
                    case VisualBasic6Parser::AND:
                    case VisualBasic6Parser::ATTRIBUTE:
                    case VisualBasic6Parser::APPACTIVATE:
                    case VisualBasic6Parser::APPEND:
                    case VisualBasic6Parser::AS:
                    case VisualBasic6Parser::BEEP:
                    case VisualBasic6Parser::BEGIN:
                    case VisualBasic6Parser::BINARY:
                    case VisualBasic6Parser::BOOLEAN:
                    case VisualBasic6Parser::BYVAL:
                    case VisualBasic6Parser::BYREF:
                    case VisualBasic6Parser::BYTE:
                    case VisualBasic6Parser::CALL:
                    case VisualBasic6Parser::CASE:
                    case VisualBasic6Parser::CHDIR:
                    case VisualBasic6Parser::CHDRIVE:
                    case VisualBasic6Parser::CLASS:
                    case VisualBasic6Parser::CLOSE:
                    case VisualBasic6Parser::COLLECTION:
                    case VisualBasic6Parser::CONST:
                    case VisualBasic6Parser::DATE:
                    case VisualBasic6Parser::DECLARE:
                    case VisualBasic6Parser::DEFBOOL:
                    case VisualBasic6Parser::DEFBYTE:
                    case VisualBasic6Parser::DEFDATE:
                    case VisualBasic6Parser::DEFDBL:
                    case VisualBasic6Parser::DEFDEC:
                    case VisualBasic6Parser::DEFCUR:
                    case VisualBasic6Parser::DEFINT:
                    case VisualBasic6Parser::DEFLNG:
                    case VisualBasic6Parser::DEFOBJ:
                    case VisualBasic6Parser::DEFSNG:
                    case VisualBasic6Parser::DEFSTR:
                    case VisualBasic6Parser::DEFVAR:
                    case VisualBasic6Parser::DELETESETTING:
                    case VisualBasic6Parser::DIM:
                    case VisualBasic6Parser::DO:
                    case VisualBasic6Parser::DOUBLE:
                    case VisualBasic6Parser::EACH:
                    case VisualBasic6Parser::ELSE:
                    case VisualBasic6Parser::ELSEIF:
                    case VisualBasic6Parser::END:
                    case VisualBasic6Parser::ENUM:
                    case VisualBasic6Parser::EQV:
                    case VisualBasic6Parser::ERASE:
                    case VisualBasic6Parser::ERROR:
                    case VisualBasic6Parser::EVENT:
                    case VisualBasic6Parser::FALSE1:
                    case VisualBasic6Parser::FILECOPY:
                    case VisualBasic6Parser::FRIEND:
                    case VisualBasic6Parser::FOR:
                    case VisualBasic6Parser::FUNCTION:
                    case VisualBasic6Parser::GET:
                    case VisualBasic6Parser::GLOBAL:
                    case VisualBasic6Parser::GOSUB:
                    case VisualBasic6Parser::GOTO:
                    case VisualBasic6Parser::IF:
                    case VisualBasic6Parser::IMP:
                    case VisualBasic6Parser::IMPLEMENTS:
                    case VisualBasic6Parser::IN:
                    case VisualBasic6Parser::INPUT:
                    case VisualBasic6Parser::IS:
                    case VisualBasic6Parser::INTEGER:
                    case VisualBasic6Parser::KILL:
                    case VisualBasic6Parser::LOAD:
                    case VisualBasic6Parser::LOCK:
                    case VisualBasic6Parser::LONG:
                    case VisualBasic6Parser::LOOP:
                    case VisualBasic6Parser::LEN:
                    case VisualBasic6Parser::LET:
                    case VisualBasic6Parser::LIB:
                    case VisualBasic6Parser::LIKE:
                    case VisualBasic6Parser::LSET:
                    case VisualBasic6Parser::ME:
                    case VisualBasic6Parser::MID:
                    case VisualBasic6Parser::MKDIR:
                    case VisualBasic6Parser::MOD:
                    case VisualBasic6Parser::NAME:
                    case VisualBasic6Parser::NEXT:
                    case VisualBasic6Parser::NEW:
                    case VisualBasic6Parser::NOT:
                    case VisualBasic6Parser::NOTHING:
                    case VisualBasic6Parser::NULL1:
                    case VisualBasic6Parser::OBJECT:
                    case VisualBasic6Parser::ON:
                    case VisualBasic6Parser::OPEN:
                    case VisualBasic6Parser::OPTIONAL:
                    case VisualBasic6Parser::OR:
                    case VisualBasic6Parser::OUTPUT:
                    case VisualBasic6Parser::PARAMARRAY:
                    case VisualBasic6Parser::PRESERVE:
                    case VisualBasic6Parser::PRINT:
                    case VisualBasic6Parser::PRIVATE:
                    case VisualBasic6Parser::PUBLIC:
                    case VisualBasic6Parser::PUT:
                    case VisualBasic6Parser::RANDOM:
                    case VisualBasic6Parser::RANDOMIZE:
                    case VisualBasic6Parser::RAISEEVENT:
                    case VisualBasic6Parser::READ:
                    case VisualBasic6Parser::REDIM:
                    case VisualBasic6Parser::REM:
                    case VisualBasic6Parser::RESET:
                    case VisualBasic6Parser::RESUME:
                    case VisualBasic6Parser::RETURN:
                    case VisualBasic6Parser::RMDIR:
                    case VisualBasic6Parser::RSET:
                    case VisualBasic6Parser::SAVEPICTURE:
                    case VisualBasic6Parser::SAVESETTING:
                    case VisualBasic6Parser::SEEK:
                    case VisualBasic6Parser::SELECT:
                    case VisualBasic6Parser::SENDKEYS:
                    case VisualBasic6Parser::SET:
                    case VisualBasic6Parser::SETATTR:
                    case VisualBasic6Parser::SHARED:
                    case VisualBasic6Parser::SINGLE:
                    case VisualBasic6Parser::SPC:
                    case VisualBasic6Parser::STATIC:
                    case VisualBasic6Parser::STEP:
                    case VisualBasic6Parser::STOP:
                    case VisualBasic6Parser::STRING:
                    case VisualBasic6Parser::SUB:
                    case VisualBasic6Parser::TAB:
                    case VisualBasic6Parser::TEXT:
                    case VisualBasic6Parser::THEN:
                    case VisualBasic6Parser::TIME:
                    case VisualBasic6Parser::TO:
                    case VisualBasic6Parser::TRUE1:
                    case VisualBasic6Parser::TYPE:
                    case VisualBasic6Parser::TYPEOF:
                    case VisualBasic6Parser::UNLOAD:
                    case VisualBasic6Parser::UNLOCK:
                    case VisualBasic6Parser::UNTIL:
                    case VisualBasic6Parser::VARIANT:
                    case VisualBasic6Parser::VERSION:
                    case VisualBasic6Parser::WEND:
                    case VisualBasic6Parser::WHILE:
                    case VisualBasic6Parser::WIDTH:
                    case VisualBasic6Parser::WITH:
                    case VisualBasic6Parser::WITHEVENTS:
                    case VisualBasic6Parser::WRITE:
                    case VisualBasic6Parser::XOR: {
                      setState(2821);
                      ambiguousKeyword();
                      break;
                    }

                    case VisualBasic6Parser::IDENTIFIER: {
                      setState(2822);
                      match(VisualBasic6Parser::IDENTIFIER);
                      break;
                    }

                  default:
                    throw NoViableAltException(this);
                  }
                  break;
                }

          default:
            throw NoViableAltException(this);
          }
          setState(2825); 
          _errHandler->sync(this);
          alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 488, _ctx);
        } while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER);
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

//----------------- ComparisonOperatorContext ------------------------------------------------------------------

VisualBasic6Parser::ComparisonOperatorContext::ComparisonOperatorContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::ComparisonOperatorContext::LT() {
  return getToken(VisualBasic6Parser::LT, 0);
}

tree::TerminalNode* VisualBasic6Parser::ComparisonOperatorContext::LEQ() {
  return getToken(VisualBasic6Parser::LEQ, 0);
}

tree::TerminalNode* VisualBasic6Parser::ComparisonOperatorContext::GT() {
  return getToken(VisualBasic6Parser::GT, 0);
}

tree::TerminalNode* VisualBasic6Parser::ComparisonOperatorContext::GEQ() {
  return getToken(VisualBasic6Parser::GEQ, 0);
}

tree::TerminalNode* VisualBasic6Parser::ComparisonOperatorContext::EQ() {
  return getToken(VisualBasic6Parser::EQ, 0);
}

tree::TerminalNode* VisualBasic6Parser::ComparisonOperatorContext::NEQ() {
  return getToken(VisualBasic6Parser::NEQ, 0);
}

tree::TerminalNode* VisualBasic6Parser::ComparisonOperatorContext::IS() {
  return getToken(VisualBasic6Parser::IS, 0);
}

tree::TerminalNode* VisualBasic6Parser::ComparisonOperatorContext::LIKE() {
  return getToken(VisualBasic6Parser::LIKE, 0);
}


size_t VisualBasic6Parser::ComparisonOperatorContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleComparisonOperator;
}

antlrcpp::Any VisualBasic6Parser::ComparisonOperatorContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitComparisonOperator(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ComparisonOperatorContext* VisualBasic6Parser::comparisonOperator() {
  ComparisonOperatorContext *_localctx = _tracker.createInstance<ComparisonOperatorContext>(_ctx, getState());
  enterRule(_localctx, 286, VisualBasic6Parser::RuleComparisonOperator);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2829);
    _la = _input->LA(1);
    if (!(_la == VisualBasic6Parser::IS

    || _la == VisualBasic6Parser::LIKE || ((((_la - 186) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 186)) & ((1ULL << (VisualBasic6Parser::EQ - 186))
      | (1ULL << (VisualBasic6Parser::GEQ - 186))
      | (1ULL << (VisualBasic6Parser::GT - 186))
      | (1ULL << (VisualBasic6Parser::LEQ - 186))
      | (1ULL << (VisualBasic6Parser::LT - 186))
      | (1ULL << (VisualBasic6Parser::NEQ - 186)))) != 0))) {
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

//----------------- ComplexTypeContext ------------------------------------------------------------------

VisualBasic6Parser::ComplexTypeContext::ComplexTypeContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<VisualBasic6Parser::AmbiguousIdentifierContext *> VisualBasic6Parser::ComplexTypeContext::ambiguousIdentifier() {
  return getRuleContexts<VisualBasic6Parser::AmbiguousIdentifierContext>();
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::ComplexTypeContext::ambiguousIdentifier(size_t i) {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(i);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::ComplexTypeContext::DOT() {
  return getTokens(VisualBasic6Parser::DOT);
}

tree::TerminalNode* VisualBasic6Parser::ComplexTypeContext::DOT(size_t i) {
  return getToken(VisualBasic6Parser::DOT, i);
}


size_t VisualBasic6Parser::ComplexTypeContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleComplexType;
}

antlrcpp::Any VisualBasic6Parser::ComplexTypeContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitComplexType(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::ComplexTypeContext* VisualBasic6Parser::complexType() {
  ComplexTypeContext *_localctx = _tracker.createInstance<ComplexTypeContext>(_ctx, getState());
  enterRule(_localctx, 288, VisualBasic6Parser::RuleComplexType);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(2831);
    ambiguousIdentifier();
    setState(2836);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 490, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(2832);
        match(VisualBasic6Parser::DOT);
        setState(2833);
        ambiguousIdentifier(); 
      }
      setState(2838);
      _errHandler->sync(this);
      alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 490, _ctx);
    }
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- FieldLengthContext ------------------------------------------------------------------

VisualBasic6Parser::FieldLengthContext::FieldLengthContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::FieldLengthContext::MULT() {
  return getToken(VisualBasic6Parser::MULT, 0);
}

tree::TerminalNode* VisualBasic6Parser::FieldLengthContext::INTEGERLITERAL() {
  return getToken(VisualBasic6Parser::INTEGERLITERAL, 0);
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::FieldLengthContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::FieldLengthContext::WS() {
  return getToken(VisualBasic6Parser::WS, 0);
}


size_t VisualBasic6Parser::FieldLengthContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleFieldLength;
}

antlrcpp::Any VisualBasic6Parser::FieldLengthContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitFieldLength(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::FieldLengthContext* VisualBasic6Parser::fieldLength() {
  FieldLengthContext *_localctx = _tracker.createInstance<FieldLengthContext>(_ctx, getState());
  enterRule(_localctx, 290, VisualBasic6Parser::RuleFieldLength);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2839);
    match(VisualBasic6Parser::MULT);
    setState(2841);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == VisualBasic6Parser::WS) {
      setState(2840);
      match(VisualBasic6Parser::WS);
    }
    setState(2845);
    _errHandler->sync(this);
    switch (_input->LA(1)) {
      case VisualBasic6Parser::INTEGERLITERAL: {
        setState(2843);
        match(VisualBasic6Parser::INTEGERLITERAL);
        break;
      }

      case VisualBasic6Parser::ACCESS:
      case VisualBasic6Parser::ADDRESSOF:
      case VisualBasic6Parser::ALIAS:
      case VisualBasic6Parser::AND:
      case VisualBasic6Parser::ATTRIBUTE:
      case VisualBasic6Parser::APPACTIVATE:
      case VisualBasic6Parser::APPEND:
      case VisualBasic6Parser::AS:
      case VisualBasic6Parser::BEEP:
      case VisualBasic6Parser::BEGIN:
      case VisualBasic6Parser::BINARY:
      case VisualBasic6Parser::BOOLEAN:
      case VisualBasic6Parser::BYVAL:
      case VisualBasic6Parser::BYREF:
      case VisualBasic6Parser::BYTE:
      case VisualBasic6Parser::CALL:
      case VisualBasic6Parser::CASE:
      case VisualBasic6Parser::CHDIR:
      case VisualBasic6Parser::CHDRIVE:
      case VisualBasic6Parser::CLASS:
      case VisualBasic6Parser::CLOSE:
      case VisualBasic6Parser::COLLECTION:
      case VisualBasic6Parser::CONST:
      case VisualBasic6Parser::DATE:
      case VisualBasic6Parser::DECLARE:
      case VisualBasic6Parser::DEFBOOL:
      case VisualBasic6Parser::DEFBYTE:
      case VisualBasic6Parser::DEFDATE:
      case VisualBasic6Parser::DEFDBL:
      case VisualBasic6Parser::DEFDEC:
      case VisualBasic6Parser::DEFCUR:
      case VisualBasic6Parser::DEFINT:
      case VisualBasic6Parser::DEFLNG:
      case VisualBasic6Parser::DEFOBJ:
      case VisualBasic6Parser::DEFSNG:
      case VisualBasic6Parser::DEFSTR:
      case VisualBasic6Parser::DEFVAR:
      case VisualBasic6Parser::DELETESETTING:
      case VisualBasic6Parser::DIM:
      case VisualBasic6Parser::DO:
      case VisualBasic6Parser::DOUBLE:
      case VisualBasic6Parser::EACH:
      case VisualBasic6Parser::ELSE:
      case VisualBasic6Parser::ELSEIF:
      case VisualBasic6Parser::END:
      case VisualBasic6Parser::ENUM:
      case VisualBasic6Parser::EQV:
      case VisualBasic6Parser::ERASE:
      case VisualBasic6Parser::ERROR:
      case VisualBasic6Parser::EVENT:
      case VisualBasic6Parser::FALSE1:
      case VisualBasic6Parser::FILECOPY:
      case VisualBasic6Parser::FRIEND:
      case VisualBasic6Parser::FOR:
      case VisualBasic6Parser::FUNCTION:
      case VisualBasic6Parser::GET:
      case VisualBasic6Parser::GLOBAL:
      case VisualBasic6Parser::GOSUB:
      case VisualBasic6Parser::GOTO:
      case VisualBasic6Parser::IF:
      case VisualBasic6Parser::IMP:
      case VisualBasic6Parser::IMPLEMENTS:
      case VisualBasic6Parser::IN:
      case VisualBasic6Parser::INPUT:
      case VisualBasic6Parser::IS:
      case VisualBasic6Parser::INTEGER:
      case VisualBasic6Parser::KILL:
      case VisualBasic6Parser::LOAD:
      case VisualBasic6Parser::LOCK:
      case VisualBasic6Parser::LONG:
      case VisualBasic6Parser::LOOP:
      case VisualBasic6Parser::LEN:
      case VisualBasic6Parser::LET:
      case VisualBasic6Parser::LIB:
      case VisualBasic6Parser::LIKE:
      case VisualBasic6Parser::LSET:
      case VisualBasic6Parser::ME:
      case VisualBasic6Parser::MID:
      case VisualBasic6Parser::MKDIR:
      case VisualBasic6Parser::MOD:
      case VisualBasic6Parser::NAME:
      case VisualBasic6Parser::NEXT:
      case VisualBasic6Parser::NEW:
      case VisualBasic6Parser::NOT:
      case VisualBasic6Parser::NOTHING:
      case VisualBasic6Parser::NULL1:
      case VisualBasic6Parser::OBJECT:
      case VisualBasic6Parser::ON:
      case VisualBasic6Parser::OPEN:
      case VisualBasic6Parser::OPTIONAL:
      case VisualBasic6Parser::OR:
      case VisualBasic6Parser::OUTPUT:
      case VisualBasic6Parser::PARAMARRAY:
      case VisualBasic6Parser::PRESERVE:
      case VisualBasic6Parser::PRINT:
      case VisualBasic6Parser::PRIVATE:
      case VisualBasic6Parser::PUBLIC:
      case VisualBasic6Parser::PUT:
      case VisualBasic6Parser::RANDOM:
      case VisualBasic6Parser::RANDOMIZE:
      case VisualBasic6Parser::RAISEEVENT:
      case VisualBasic6Parser::READ:
      case VisualBasic6Parser::REDIM:
      case VisualBasic6Parser::REM:
      case VisualBasic6Parser::RESET:
      case VisualBasic6Parser::RESUME:
      case VisualBasic6Parser::RETURN:
      case VisualBasic6Parser::RMDIR:
      case VisualBasic6Parser::RSET:
      case VisualBasic6Parser::SAVEPICTURE:
      case VisualBasic6Parser::SAVESETTING:
      case VisualBasic6Parser::SEEK:
      case VisualBasic6Parser::SELECT:
      case VisualBasic6Parser::SENDKEYS:
      case VisualBasic6Parser::SET:
      case VisualBasic6Parser::SETATTR:
      case VisualBasic6Parser::SHARED:
      case VisualBasic6Parser::SINGLE:
      case VisualBasic6Parser::SPC:
      case VisualBasic6Parser::STATIC:
      case VisualBasic6Parser::STEP:
      case VisualBasic6Parser::STOP:
      case VisualBasic6Parser::STRING:
      case VisualBasic6Parser::SUB:
      case VisualBasic6Parser::TAB:
      case VisualBasic6Parser::TEXT:
      case VisualBasic6Parser::THEN:
      case VisualBasic6Parser::TIME:
      case VisualBasic6Parser::TO:
      case VisualBasic6Parser::TRUE1:
      case VisualBasic6Parser::TYPE:
      case VisualBasic6Parser::TYPEOF:
      case VisualBasic6Parser::UNLOAD:
      case VisualBasic6Parser::UNLOCK:
      case VisualBasic6Parser::UNTIL:
      case VisualBasic6Parser::VARIANT:
      case VisualBasic6Parser::VERSION:
      case VisualBasic6Parser::WEND:
      case VisualBasic6Parser::WHILE:
      case VisualBasic6Parser::WIDTH:
      case VisualBasic6Parser::WITH:
      case VisualBasic6Parser::WITHEVENTS:
      case VisualBasic6Parser::WRITE:
      case VisualBasic6Parser::XOR:
      case VisualBasic6Parser::L_SQUARE_BRACKET:
      case VisualBasic6Parser::IDENTIFIER: {
        setState(2844);
        ambiguousIdentifier();
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

//----------------- LetterrangeContext ------------------------------------------------------------------

VisualBasic6Parser::LetterrangeContext::LetterrangeContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<VisualBasic6Parser::CertainIdentifierContext *> VisualBasic6Parser::LetterrangeContext::certainIdentifier() {
  return getRuleContexts<VisualBasic6Parser::CertainIdentifierContext>();
}

VisualBasic6Parser::CertainIdentifierContext* VisualBasic6Parser::LetterrangeContext::certainIdentifier(size_t i) {
  return getRuleContext<VisualBasic6Parser::CertainIdentifierContext>(i);
}

tree::TerminalNode* VisualBasic6Parser::LetterrangeContext::MINUS() {
  return getToken(VisualBasic6Parser::MINUS, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::LetterrangeContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::LetterrangeContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}


size_t VisualBasic6Parser::LetterrangeContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleLetterrange;
}

antlrcpp::Any VisualBasic6Parser::LetterrangeContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitLetterrange(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::LetterrangeContext* VisualBasic6Parser::letterrange() {
  LetterrangeContext *_localctx = _tracker.createInstance<LetterrangeContext>(_ctx, getState());
  enterRule(_localctx, 292, VisualBasic6Parser::RuleLetterrange);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2847);
    certainIdentifier();
    setState(2856);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 495, _ctx)) {
    case 1: {
      setState(2849);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2848);
        match(VisualBasic6Parser::WS);
      }
      setState(2851);
      match(VisualBasic6Parser::MINUS);
      setState(2853);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2852);
        match(VisualBasic6Parser::WS);
      }
      setState(2855);
      certainIdentifier();
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

//----------------- LineLabelContext ------------------------------------------------------------------

VisualBasic6Parser::LineLabelContext::LineLabelContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::AmbiguousIdentifierContext* VisualBasic6Parser::LineLabelContext::ambiguousIdentifier() {
  return getRuleContext<VisualBasic6Parser::AmbiguousIdentifierContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::LineLabelContext::COLON() {
  return getToken(VisualBasic6Parser::COLON, 0);
}


size_t VisualBasic6Parser::LineLabelContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleLineLabel;
}

antlrcpp::Any VisualBasic6Parser::LineLabelContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitLineLabel(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::LineLabelContext* VisualBasic6Parser::lineLabel() {
  LineLabelContext *_localctx = _tracker.createInstance<LineLabelContext>(_ctx, getState());
  enterRule(_localctx, 294, VisualBasic6Parser::RuleLineLabel);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2858);
    ambiguousIdentifier();
    setState(2859);
    match(VisualBasic6Parser::COLON);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- LiteralContext ------------------------------------------------------------------

VisualBasic6Parser::LiteralContext::LiteralContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::LiteralContext::COLORLITERAL() {
  return getToken(VisualBasic6Parser::COLORLITERAL, 0);
}

tree::TerminalNode* VisualBasic6Parser::LiteralContext::DATELITERAL() {
  return getToken(VisualBasic6Parser::DATELITERAL, 0);
}

tree::TerminalNode* VisualBasic6Parser::LiteralContext::DOUBLELITERAL() {
  return getToken(VisualBasic6Parser::DOUBLELITERAL, 0);
}

tree::TerminalNode* VisualBasic6Parser::LiteralContext::FILENUMBER() {
  return getToken(VisualBasic6Parser::FILENUMBER, 0);
}

tree::TerminalNode* VisualBasic6Parser::LiteralContext::INTEGERLITERAL() {
  return getToken(VisualBasic6Parser::INTEGERLITERAL, 0);
}

tree::TerminalNode* VisualBasic6Parser::LiteralContext::OCTALLITERAL() {
  return getToken(VisualBasic6Parser::OCTALLITERAL, 0);
}

tree::TerminalNode* VisualBasic6Parser::LiteralContext::STRINGLITERAL() {
  return getToken(VisualBasic6Parser::STRINGLITERAL, 0);
}

tree::TerminalNode* VisualBasic6Parser::LiteralContext::TRUE1() {
  return getToken(VisualBasic6Parser::TRUE1, 0);
}

tree::TerminalNode* VisualBasic6Parser::LiteralContext::FALSE1() {
  return getToken(VisualBasic6Parser::FALSE1, 0);
}

tree::TerminalNode* VisualBasic6Parser::LiteralContext::NOTHING() {
  return getToken(VisualBasic6Parser::NOTHING, 0);
}

tree::TerminalNode* VisualBasic6Parser::LiteralContext::NULL1() {
  return getToken(VisualBasic6Parser::NULL1, 0);
}


size_t VisualBasic6Parser::LiteralContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleLiteral;
}

antlrcpp::Any VisualBasic6Parser::LiteralContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitLiteral(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::LiteralContext* VisualBasic6Parser::literal() {
  LiteralContext *_localctx = _tracker.createInstance<LiteralContext>(_ctx, getState());
  enterRule(_localctx, 296, VisualBasic6Parser::RuleLiteral);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2861);
    _la = _input->LA(1);
    if (!(((((_la - 66) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 66)) & ((1ULL << (VisualBasic6Parser::FALSE1 - 66))
      | (1ULL << (VisualBasic6Parser::NOTHING - 66))
      | (1ULL << (VisualBasic6Parser::NULL1 - 66)))) != 0) || ((((_la - 163) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 163)) & ((1ULL << (VisualBasic6Parser::TRUE1 - 163))
      | (1ULL << (VisualBasic6Parser::STRINGLITERAL - 163))
      | (1ULL << (VisualBasic6Parser::DATELITERAL - 163))
      | (1ULL << (VisualBasic6Parser::COLORLITERAL - 163))
      | (1ULL << (VisualBasic6Parser::INTEGERLITERAL - 163))
      | (1ULL << (VisualBasic6Parser::DOUBLELITERAL - 163))
      | (1ULL << (VisualBasic6Parser::FILENUMBER - 163))
      | (1ULL << (VisualBasic6Parser::OCTALLITERAL - 163)))) != 0))) {
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

//----------------- PublicPrivateVisibilityContext ------------------------------------------------------------------

VisualBasic6Parser::PublicPrivateVisibilityContext::PublicPrivateVisibilityContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::PublicPrivateVisibilityContext::PRIVATE() {
  return getToken(VisualBasic6Parser::PRIVATE, 0);
}

tree::TerminalNode* VisualBasic6Parser::PublicPrivateVisibilityContext::PUBLIC() {
  return getToken(VisualBasic6Parser::PUBLIC, 0);
}


size_t VisualBasic6Parser::PublicPrivateVisibilityContext::getRuleIndex() const {
  return VisualBasic6Parser::RulePublicPrivateVisibility;
}

antlrcpp::Any VisualBasic6Parser::PublicPrivateVisibilityContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitPublicPrivateVisibility(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::PublicPrivateVisibilityContext* VisualBasic6Parser::publicPrivateVisibility() {
  PublicPrivateVisibilityContext *_localctx = _tracker.createInstance<PublicPrivateVisibilityContext>(_ctx, getState());
  enterRule(_localctx, 298, VisualBasic6Parser::RulePublicPrivateVisibility);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2863);
    _la = _input->LA(1);
    if (!(_la == VisualBasic6Parser::PRIVATE

    || _la == VisualBasic6Parser::PUBLIC)) {
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

//----------------- PublicPrivateGlobalVisibilityContext ------------------------------------------------------------------

VisualBasic6Parser::PublicPrivateGlobalVisibilityContext::PublicPrivateGlobalVisibilityContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::PublicPrivateGlobalVisibilityContext::PRIVATE() {
  return getToken(VisualBasic6Parser::PRIVATE, 0);
}

tree::TerminalNode* VisualBasic6Parser::PublicPrivateGlobalVisibilityContext::PUBLIC() {
  return getToken(VisualBasic6Parser::PUBLIC, 0);
}

tree::TerminalNode* VisualBasic6Parser::PublicPrivateGlobalVisibilityContext::GLOBAL() {
  return getToken(VisualBasic6Parser::GLOBAL, 0);
}


size_t VisualBasic6Parser::PublicPrivateGlobalVisibilityContext::getRuleIndex() const {
  return VisualBasic6Parser::RulePublicPrivateGlobalVisibility;
}

antlrcpp::Any VisualBasic6Parser::PublicPrivateGlobalVisibilityContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitPublicPrivateGlobalVisibility(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::PublicPrivateGlobalVisibilityContext* VisualBasic6Parser::publicPrivateGlobalVisibility() {
  PublicPrivateGlobalVisibilityContext *_localctx = _tracker.createInstance<PublicPrivateGlobalVisibilityContext>(_ctx, getState());
  enterRule(_localctx, 300, VisualBasic6Parser::RulePublicPrivateGlobalVisibility);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2865);
    _la = _input->LA(1);
    if (!(((((_la - 72) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 72)) & ((1ULL << (VisualBasic6Parser::GLOBAL - 72))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 72))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 72)))) != 0))) {
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

//----------------- TypeContext ------------------------------------------------------------------

VisualBasic6Parser::TypeContext::TypeContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

VisualBasic6Parser::BaseTypeContext* VisualBasic6Parser::TypeContext::baseType() {
  return getRuleContext<VisualBasic6Parser::BaseTypeContext>(0);
}

VisualBasic6Parser::ComplexTypeContext* VisualBasic6Parser::TypeContext::complexType() {
  return getRuleContext<VisualBasic6Parser::ComplexTypeContext>(0);
}

tree::TerminalNode* VisualBasic6Parser::TypeContext::LPAREN() {
  return getToken(VisualBasic6Parser::LPAREN, 0);
}

tree::TerminalNode* VisualBasic6Parser::TypeContext::RPAREN() {
  return getToken(VisualBasic6Parser::RPAREN, 0);
}

std::vector<tree::TerminalNode *> VisualBasic6Parser::TypeContext::WS() {
  return getTokens(VisualBasic6Parser::WS);
}

tree::TerminalNode* VisualBasic6Parser::TypeContext::WS(size_t i) {
  return getToken(VisualBasic6Parser::WS, i);
}


size_t VisualBasic6Parser::TypeContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleType;
}

antlrcpp::Any VisualBasic6Parser::TypeContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitType(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::TypeContext* VisualBasic6Parser::type() {
  TypeContext *_localctx = _tracker.createInstance<TypeContext>(_ctx, getState());
  enterRule(_localctx, 302, VisualBasic6Parser::RuleType);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2869);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 496, _ctx)) {
    case 1: {
      setState(2867);
      baseType();
      break;
    }

    case 2: {
      setState(2868);
      complexType();
      break;
    }

    }
    setState(2879);
    _errHandler->sync(this);

    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 499, _ctx)) {
    case 1: {
      setState(2872);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2871);
        match(VisualBasic6Parser::WS);
      }
      setState(2874);
      match(VisualBasic6Parser::LPAREN);
      setState(2876);
      _errHandler->sync(this);

      _la = _input->LA(1);
      if (_la == VisualBasic6Parser::WS) {
        setState(2875);
        match(VisualBasic6Parser::WS);
      }
      setState(2878);
      match(VisualBasic6Parser::RPAREN);
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

//----------------- TypeHintContext ------------------------------------------------------------------

VisualBasic6Parser::TypeHintContext::TypeHintContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::TypeHintContext::AMPERSAND() {
  return getToken(VisualBasic6Parser::AMPERSAND, 0);
}

tree::TerminalNode* VisualBasic6Parser::TypeHintContext::AT() {
  return getToken(VisualBasic6Parser::AT, 0);
}

tree::TerminalNode* VisualBasic6Parser::TypeHintContext::DOLLAR() {
  return getToken(VisualBasic6Parser::DOLLAR, 0);
}

tree::TerminalNode* VisualBasic6Parser::TypeHintContext::EXCLAMATIONMARK() {
  return getToken(VisualBasic6Parser::EXCLAMATIONMARK, 0);
}

tree::TerminalNode* VisualBasic6Parser::TypeHintContext::HASH() {
  return getToken(VisualBasic6Parser::HASH, 0);
}

tree::TerminalNode* VisualBasic6Parser::TypeHintContext::PERCENT() {
  return getToken(VisualBasic6Parser::PERCENT, 0);
}


size_t VisualBasic6Parser::TypeHintContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleTypeHint;
}

antlrcpp::Any VisualBasic6Parser::TypeHintContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitTypeHint(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::TypeHintContext* VisualBasic6Parser::typeHint() {
  TypeHintContext *_localctx = _tracker.createInstance<TypeHintContext>(_ctx, getState());
  enterRule(_localctx, 304, VisualBasic6Parser::RuleTypeHint);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2881);
    _la = _input->LA(1);
    if (!(((((_la - 178) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 178)) & ((1ULL << (VisualBasic6Parser::AMPERSAND - 178))
      | (1ULL << (VisualBasic6Parser::AT - 178))
      | (1ULL << (VisualBasic6Parser::DOLLAR - 178))
      | (1ULL << (VisualBasic6Parser::EXCLAMATIONMARK - 178))
      | (1ULL << (VisualBasic6Parser::HASH - 178))
      | (1ULL << (VisualBasic6Parser::PERCENT - 178)))) != 0))) {
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

//----------------- VisibilityContext ------------------------------------------------------------------

VisualBasic6Parser::VisibilityContext::VisibilityContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::VisibilityContext::PRIVATE() {
  return getToken(VisualBasic6Parser::PRIVATE, 0);
}

tree::TerminalNode* VisualBasic6Parser::VisibilityContext::PUBLIC() {
  return getToken(VisualBasic6Parser::PUBLIC, 0);
}

tree::TerminalNode* VisualBasic6Parser::VisibilityContext::FRIEND() {
  return getToken(VisualBasic6Parser::FRIEND, 0);
}

tree::TerminalNode* VisualBasic6Parser::VisibilityContext::GLOBAL() {
  return getToken(VisualBasic6Parser::GLOBAL, 0);
}


size_t VisualBasic6Parser::VisibilityContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleVisibility;
}

antlrcpp::Any VisualBasic6Parser::VisibilityContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitVisibility(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::VisibilityContext* VisualBasic6Parser::visibility() {
  VisibilityContext *_localctx = _tracker.createInstance<VisibilityContext>(_ctx, getState());
  enterRule(_localctx, 306, VisualBasic6Parser::RuleVisibility);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2883);
    _la = _input->LA(1);
    if (!(((((_la - 68) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 68)) & ((1ULL << (VisualBasic6Parser::FRIEND - 68))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 68))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 68))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 68)))) != 0))) {
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

//----------------- AmbiguousKeywordContext ------------------------------------------------------------------

VisualBasic6Parser::AmbiguousKeywordContext::AmbiguousKeywordContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::ACCESS() {
  return getToken(VisualBasic6Parser::ACCESS, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::ADDRESSOF() {
  return getToken(VisualBasic6Parser::ADDRESSOF, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::ALIAS() {
  return getToken(VisualBasic6Parser::ALIAS, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::AND() {
  return getToken(VisualBasic6Parser::AND, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::ATTRIBUTE() {
  return getToken(VisualBasic6Parser::ATTRIBUTE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::APPACTIVATE() {
  return getToken(VisualBasic6Parser::APPACTIVATE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::APPEND() {
  return getToken(VisualBasic6Parser::APPEND, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::AS() {
  return getToken(VisualBasic6Parser::AS, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::BEEP() {
  return getToken(VisualBasic6Parser::BEEP, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::BEGIN() {
  return getToken(VisualBasic6Parser::BEGIN, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::BINARY() {
  return getToken(VisualBasic6Parser::BINARY, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::BOOLEAN() {
  return getToken(VisualBasic6Parser::BOOLEAN, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::BYVAL() {
  return getToken(VisualBasic6Parser::BYVAL, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::BYREF() {
  return getToken(VisualBasic6Parser::BYREF, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::BYTE() {
  return getToken(VisualBasic6Parser::BYTE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::CALL() {
  return getToken(VisualBasic6Parser::CALL, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::CASE() {
  return getToken(VisualBasic6Parser::CASE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::CLASS() {
  return getToken(VisualBasic6Parser::CLASS, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::CLOSE() {
  return getToken(VisualBasic6Parser::CLOSE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::CHDIR() {
  return getToken(VisualBasic6Parser::CHDIR, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::CHDRIVE() {
  return getToken(VisualBasic6Parser::CHDRIVE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::COLLECTION() {
  return getToken(VisualBasic6Parser::COLLECTION, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::CONST() {
  return getToken(VisualBasic6Parser::CONST, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DATE() {
  return getToken(VisualBasic6Parser::DATE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DECLARE() {
  return getToken(VisualBasic6Parser::DECLARE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DEFBOOL() {
  return getToken(VisualBasic6Parser::DEFBOOL, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DEFBYTE() {
  return getToken(VisualBasic6Parser::DEFBYTE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DEFCUR() {
  return getToken(VisualBasic6Parser::DEFCUR, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DEFDBL() {
  return getToken(VisualBasic6Parser::DEFDBL, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DEFDATE() {
  return getToken(VisualBasic6Parser::DEFDATE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DEFDEC() {
  return getToken(VisualBasic6Parser::DEFDEC, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DEFINT() {
  return getToken(VisualBasic6Parser::DEFINT, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DEFLNG() {
  return getToken(VisualBasic6Parser::DEFLNG, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DEFOBJ() {
  return getToken(VisualBasic6Parser::DEFOBJ, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DEFSNG() {
  return getToken(VisualBasic6Parser::DEFSNG, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DEFSTR() {
  return getToken(VisualBasic6Parser::DEFSTR, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DEFVAR() {
  return getToken(VisualBasic6Parser::DEFVAR, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DELETESETTING() {
  return getToken(VisualBasic6Parser::DELETESETTING, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DIM() {
  return getToken(VisualBasic6Parser::DIM, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DO() {
  return getToken(VisualBasic6Parser::DO, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::DOUBLE() {
  return getToken(VisualBasic6Parser::DOUBLE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::EACH() {
  return getToken(VisualBasic6Parser::EACH, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::ELSE() {
  return getToken(VisualBasic6Parser::ELSE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::ELSEIF() {
  return getToken(VisualBasic6Parser::ELSEIF, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::END() {
  return getToken(VisualBasic6Parser::END, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::ENUM() {
  return getToken(VisualBasic6Parser::ENUM, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::EQV() {
  return getToken(VisualBasic6Parser::EQV, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::ERASE() {
  return getToken(VisualBasic6Parser::ERASE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::ERROR() {
  return getToken(VisualBasic6Parser::ERROR, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::EVENT() {
  return getToken(VisualBasic6Parser::EVENT, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::FALSE1() {
  return getToken(VisualBasic6Parser::FALSE1, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::FILECOPY() {
  return getToken(VisualBasic6Parser::FILECOPY, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::FRIEND() {
  return getToken(VisualBasic6Parser::FRIEND, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::FOR() {
  return getToken(VisualBasic6Parser::FOR, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::FUNCTION() {
  return getToken(VisualBasic6Parser::FUNCTION, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::GET() {
  return getToken(VisualBasic6Parser::GET, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::GLOBAL() {
  return getToken(VisualBasic6Parser::GLOBAL, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::GOSUB() {
  return getToken(VisualBasic6Parser::GOSUB, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::GOTO() {
  return getToken(VisualBasic6Parser::GOTO, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::IF() {
  return getToken(VisualBasic6Parser::IF, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::IMP() {
  return getToken(VisualBasic6Parser::IMP, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::IMPLEMENTS() {
  return getToken(VisualBasic6Parser::IMPLEMENTS, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::IN() {
  return getToken(VisualBasic6Parser::IN, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::INPUT() {
  return getToken(VisualBasic6Parser::INPUT, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::IS() {
  return getToken(VisualBasic6Parser::IS, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::INTEGER() {
  return getToken(VisualBasic6Parser::INTEGER, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::KILL() {
  return getToken(VisualBasic6Parser::KILL, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::LOAD() {
  return getToken(VisualBasic6Parser::LOAD, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::LOCK() {
  return getToken(VisualBasic6Parser::LOCK, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::LONG() {
  return getToken(VisualBasic6Parser::LONG, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::LOOP() {
  return getToken(VisualBasic6Parser::LOOP, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::LEN() {
  return getToken(VisualBasic6Parser::LEN, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::LET() {
  return getToken(VisualBasic6Parser::LET, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::LIB() {
  return getToken(VisualBasic6Parser::LIB, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::LIKE() {
  return getToken(VisualBasic6Parser::LIKE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::LSET() {
  return getToken(VisualBasic6Parser::LSET, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::ME() {
  return getToken(VisualBasic6Parser::ME, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::MID() {
  return getToken(VisualBasic6Parser::MID, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::MKDIR() {
  return getToken(VisualBasic6Parser::MKDIR, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::MOD() {
  return getToken(VisualBasic6Parser::MOD, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::NAME() {
  return getToken(VisualBasic6Parser::NAME, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::NEXT() {
  return getToken(VisualBasic6Parser::NEXT, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::NEW() {
  return getToken(VisualBasic6Parser::NEW, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::NOT() {
  return getToken(VisualBasic6Parser::NOT, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::NOTHING() {
  return getToken(VisualBasic6Parser::NOTHING, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::NULL1() {
  return getToken(VisualBasic6Parser::NULL1, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::OBJECT() {
  return getToken(VisualBasic6Parser::OBJECT, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::ON() {
  return getToken(VisualBasic6Parser::ON, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::OPEN() {
  return getToken(VisualBasic6Parser::OPEN, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::OPTIONAL() {
  return getToken(VisualBasic6Parser::OPTIONAL, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::OR() {
  return getToken(VisualBasic6Parser::OR, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::OUTPUT() {
  return getToken(VisualBasic6Parser::OUTPUT, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::PARAMARRAY() {
  return getToken(VisualBasic6Parser::PARAMARRAY, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::PRESERVE() {
  return getToken(VisualBasic6Parser::PRESERVE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::PRINT() {
  return getToken(VisualBasic6Parser::PRINT, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::PRIVATE() {
  return getToken(VisualBasic6Parser::PRIVATE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::PUBLIC() {
  return getToken(VisualBasic6Parser::PUBLIC, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::PUT() {
  return getToken(VisualBasic6Parser::PUT, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::RANDOM() {
  return getToken(VisualBasic6Parser::RANDOM, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::RANDOMIZE() {
  return getToken(VisualBasic6Parser::RANDOMIZE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::RAISEEVENT() {
  return getToken(VisualBasic6Parser::RAISEEVENT, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::READ() {
  return getToken(VisualBasic6Parser::READ, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::REDIM() {
  return getToken(VisualBasic6Parser::REDIM, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::REM() {
  return getToken(VisualBasic6Parser::REM, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::RESET() {
  return getToken(VisualBasic6Parser::RESET, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::RESUME() {
  return getToken(VisualBasic6Parser::RESUME, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::RETURN() {
  return getToken(VisualBasic6Parser::RETURN, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::RMDIR() {
  return getToken(VisualBasic6Parser::RMDIR, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::RSET() {
  return getToken(VisualBasic6Parser::RSET, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::SAVEPICTURE() {
  return getToken(VisualBasic6Parser::SAVEPICTURE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::SAVESETTING() {
  return getToken(VisualBasic6Parser::SAVESETTING, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::SEEK() {
  return getToken(VisualBasic6Parser::SEEK, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::SELECT() {
  return getToken(VisualBasic6Parser::SELECT, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::SENDKEYS() {
  return getToken(VisualBasic6Parser::SENDKEYS, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::SET() {
  return getToken(VisualBasic6Parser::SET, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::SETATTR() {
  return getToken(VisualBasic6Parser::SETATTR, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::SHARED() {
  return getToken(VisualBasic6Parser::SHARED, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::SINGLE() {
  return getToken(VisualBasic6Parser::SINGLE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::SPC() {
  return getToken(VisualBasic6Parser::SPC, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::STATIC() {
  return getToken(VisualBasic6Parser::STATIC, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::STEP() {
  return getToken(VisualBasic6Parser::STEP, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::STOP() {
  return getToken(VisualBasic6Parser::STOP, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::STRING() {
  return getToken(VisualBasic6Parser::STRING, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::SUB() {
  return getToken(VisualBasic6Parser::SUB, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::TAB() {
  return getToken(VisualBasic6Parser::TAB, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::TEXT() {
  return getToken(VisualBasic6Parser::TEXT, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::THEN() {
  return getToken(VisualBasic6Parser::THEN, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::TIME() {
  return getToken(VisualBasic6Parser::TIME, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::TO() {
  return getToken(VisualBasic6Parser::TO, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::TRUE1() {
  return getToken(VisualBasic6Parser::TRUE1, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::TYPE() {
  return getToken(VisualBasic6Parser::TYPE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::TYPEOF() {
  return getToken(VisualBasic6Parser::TYPEOF, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::UNLOAD() {
  return getToken(VisualBasic6Parser::UNLOAD, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::UNLOCK() {
  return getToken(VisualBasic6Parser::UNLOCK, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::UNTIL() {
  return getToken(VisualBasic6Parser::UNTIL, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::VARIANT() {
  return getToken(VisualBasic6Parser::VARIANT, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::VERSION() {
  return getToken(VisualBasic6Parser::VERSION, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::WEND() {
  return getToken(VisualBasic6Parser::WEND, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::WHILE() {
  return getToken(VisualBasic6Parser::WHILE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::WIDTH() {
  return getToken(VisualBasic6Parser::WIDTH, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::WITH() {
  return getToken(VisualBasic6Parser::WITH, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::WITHEVENTS() {
  return getToken(VisualBasic6Parser::WITHEVENTS, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::WRITE() {
  return getToken(VisualBasic6Parser::WRITE, 0);
}

tree::TerminalNode* VisualBasic6Parser::AmbiguousKeywordContext::XOR() {
  return getToken(VisualBasic6Parser::XOR, 0);
}


size_t VisualBasic6Parser::AmbiguousKeywordContext::getRuleIndex() const {
  return VisualBasic6Parser::RuleAmbiguousKeyword;
}

antlrcpp::Any VisualBasic6Parser::AmbiguousKeywordContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<VisualBasic6Visitor*>(visitor))
    return parserVisitor->visitAmbiguousKeyword(this);
  else
    return visitor->visitChildren(this);
}

VisualBasic6Parser::AmbiguousKeywordContext* VisualBasic6Parser::ambiguousKeyword() {
  AmbiguousKeywordContext *_localctx = _tracker.createInstance<AmbiguousKeywordContext>(_ctx, getState());
  enterRule(_localctx, 308, VisualBasic6Parser::RuleAmbiguousKeyword);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(2885);
    _la = _input->LA(1);
    if (!((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << VisualBasic6Parser::ACCESS)
      | (1ULL << VisualBasic6Parser::ADDRESSOF)
      | (1ULL << VisualBasic6Parser::ALIAS)
      | (1ULL << VisualBasic6Parser::AND)
      | (1ULL << VisualBasic6Parser::ATTRIBUTE)
      | (1ULL << VisualBasic6Parser::APPACTIVATE)
      | (1ULL << VisualBasic6Parser::APPEND)
      | (1ULL << VisualBasic6Parser::AS)
      | (1ULL << VisualBasic6Parser::BEEP)
      | (1ULL << VisualBasic6Parser::BEGIN)
      | (1ULL << VisualBasic6Parser::BINARY)
      | (1ULL << VisualBasic6Parser::BOOLEAN)
      | (1ULL << VisualBasic6Parser::BYVAL)
      | (1ULL << VisualBasic6Parser::BYREF)
      | (1ULL << VisualBasic6Parser::BYTE)
      | (1ULL << VisualBasic6Parser::CALL)
      | (1ULL << VisualBasic6Parser::CASE)
      | (1ULL << VisualBasic6Parser::CHDIR)
      | (1ULL << VisualBasic6Parser::CHDRIVE)
      | (1ULL << VisualBasic6Parser::CLASS)
      | (1ULL << VisualBasic6Parser::CLOSE)
      | (1ULL << VisualBasic6Parser::COLLECTION)
      | (1ULL << VisualBasic6Parser::CONST)
      | (1ULL << VisualBasic6Parser::DATE)
      | (1ULL << VisualBasic6Parser::DECLARE)
      | (1ULL << VisualBasic6Parser::DEFBOOL)
      | (1ULL << VisualBasic6Parser::DEFBYTE)
      | (1ULL << VisualBasic6Parser::DEFDATE)
      | (1ULL << VisualBasic6Parser::DEFDBL)
      | (1ULL << VisualBasic6Parser::DEFDEC)
      | (1ULL << VisualBasic6Parser::DEFCUR)
      | (1ULL << VisualBasic6Parser::DEFINT)
      | (1ULL << VisualBasic6Parser::DEFLNG)
      | (1ULL << VisualBasic6Parser::DEFOBJ)
      | (1ULL << VisualBasic6Parser::DEFSNG)
      | (1ULL << VisualBasic6Parser::DEFSTR)
      | (1ULL << VisualBasic6Parser::DEFVAR)
      | (1ULL << VisualBasic6Parser::DELETESETTING)
      | (1ULL << VisualBasic6Parser::DIM)
      | (1ULL << VisualBasic6Parser::DO)
      | (1ULL << VisualBasic6Parser::DOUBLE)
      | (1ULL << VisualBasic6Parser::EACH)
      | (1ULL << VisualBasic6Parser::ELSE)
      | (1ULL << VisualBasic6Parser::ELSEIF)
      | (1ULL << VisualBasic6Parser::END)
      | (1ULL << VisualBasic6Parser::ENUM)
      | (1ULL << VisualBasic6Parser::EQV)
      | (1ULL << VisualBasic6Parser::ERASE)
      | (1ULL << VisualBasic6Parser::ERROR)
      | (1ULL << VisualBasic6Parser::EVENT))) != 0) || ((((_la - 66) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 66)) & ((1ULL << (VisualBasic6Parser::FALSE1 - 66))
      | (1ULL << (VisualBasic6Parser::FILECOPY - 66))
      | (1ULL << (VisualBasic6Parser::FRIEND - 66))
      | (1ULL << (VisualBasic6Parser::FOR - 66))
      | (1ULL << (VisualBasic6Parser::FUNCTION - 66))
      | (1ULL << (VisualBasic6Parser::GET - 66))
      | (1ULL << (VisualBasic6Parser::GLOBAL - 66))
      | (1ULL << (VisualBasic6Parser::GOSUB - 66))
      | (1ULL << (VisualBasic6Parser::GOTO - 66))
      | (1ULL << (VisualBasic6Parser::IF - 66))
      | (1ULL << (VisualBasic6Parser::IMP - 66))
      | (1ULL << (VisualBasic6Parser::IMPLEMENTS - 66))
      | (1ULL << (VisualBasic6Parser::IN - 66))
      | (1ULL << (VisualBasic6Parser::INPUT - 66))
      | (1ULL << (VisualBasic6Parser::IS - 66))
      | (1ULL << (VisualBasic6Parser::INTEGER - 66))
      | (1ULL << (VisualBasic6Parser::KILL - 66))
      | (1ULL << (VisualBasic6Parser::LOAD - 66))
      | (1ULL << (VisualBasic6Parser::LOCK - 66))
      | (1ULL << (VisualBasic6Parser::LONG - 66))
      | (1ULL << (VisualBasic6Parser::LOOP - 66))
      | (1ULL << (VisualBasic6Parser::LEN - 66))
      | (1ULL << (VisualBasic6Parser::LET - 66))
      | (1ULL << (VisualBasic6Parser::LIB - 66))
      | (1ULL << (VisualBasic6Parser::LIKE - 66))
      | (1ULL << (VisualBasic6Parser::LSET - 66))
      | (1ULL << (VisualBasic6Parser::ME - 66))
      | (1ULL << (VisualBasic6Parser::MID - 66))
      | (1ULL << (VisualBasic6Parser::MKDIR - 66))
      | (1ULL << (VisualBasic6Parser::MOD - 66))
      | (1ULL << (VisualBasic6Parser::NAME - 66))
      | (1ULL << (VisualBasic6Parser::NEXT - 66))
      | (1ULL << (VisualBasic6Parser::NEW - 66))
      | (1ULL << (VisualBasic6Parser::NOT - 66))
      | (1ULL << (VisualBasic6Parser::NOTHING - 66))
      | (1ULL << (VisualBasic6Parser::NULL1 - 66))
      | (1ULL << (VisualBasic6Parser::OBJECT - 66))
      | (1ULL << (VisualBasic6Parser::ON - 66))
      | (1ULL << (VisualBasic6Parser::OPEN - 66))
      | (1ULL << (VisualBasic6Parser::OPTIONAL - 66))
      | (1ULL << (VisualBasic6Parser::OR - 66))
      | (1ULL << (VisualBasic6Parser::OUTPUT - 66))
      | (1ULL << (VisualBasic6Parser::PARAMARRAY - 66))
      | (1ULL << (VisualBasic6Parser::PRESERVE - 66))
      | (1ULL << (VisualBasic6Parser::PRINT - 66))
      | (1ULL << (VisualBasic6Parser::PRIVATE - 66))
      | (1ULL << (VisualBasic6Parser::PUBLIC - 66)))) != 0) || ((((_la - 130) & ~ 0x3fULL) == 0) &&
      ((1ULL << (_la - 130)) & ((1ULL << (VisualBasic6Parser::PUT - 130))
      | (1ULL << (VisualBasic6Parser::RANDOM - 130))
      | (1ULL << (VisualBasic6Parser::RANDOMIZE - 130))
      | (1ULL << (VisualBasic6Parser::RAISEEVENT - 130))
      | (1ULL << (VisualBasic6Parser::READ - 130))
      | (1ULL << (VisualBasic6Parser::REDIM - 130))
      | (1ULL << (VisualBasic6Parser::REM - 130))
      | (1ULL << (VisualBasic6Parser::RESET - 130))
      | (1ULL << (VisualBasic6Parser::RESUME - 130))
      | (1ULL << (VisualBasic6Parser::RETURN - 130))
      | (1ULL << (VisualBasic6Parser::RMDIR - 130))
      | (1ULL << (VisualBasic6Parser::RSET - 130))
      | (1ULL << (VisualBasic6Parser::SAVEPICTURE - 130))
      | (1ULL << (VisualBasic6Parser::SAVESETTING - 130))
      | (1ULL << (VisualBasic6Parser::SEEK - 130))
      | (1ULL << (VisualBasic6Parser::SELECT - 130))
      | (1ULL << (VisualBasic6Parser::SENDKEYS - 130))
      | (1ULL << (VisualBasic6Parser::SET - 130))
      | (1ULL << (VisualBasic6Parser::SETATTR - 130))
      | (1ULL << (VisualBasic6Parser::SHARED - 130))
      | (1ULL << (VisualBasic6Parser::SINGLE - 130))
      | (1ULL << (VisualBasic6Parser::SPC - 130))
      | (1ULL << (VisualBasic6Parser::STATIC - 130))
      | (1ULL << (VisualBasic6Parser::STEP - 130))
      | (1ULL << (VisualBasic6Parser::STOP - 130))
      | (1ULL << (VisualBasic6Parser::STRING - 130))
      | (1ULL << (VisualBasic6Parser::SUB - 130))
      | (1ULL << (VisualBasic6Parser::TAB - 130))
      | (1ULL << (VisualBasic6Parser::TEXT - 130))
      | (1ULL << (VisualBasic6Parser::THEN - 130))
      | (1ULL << (VisualBasic6Parser::TIME - 130))
      | (1ULL << (VisualBasic6Parser::TO - 130))
      | (1ULL << (VisualBasic6Parser::TRUE1 - 130))
      | (1ULL << (VisualBasic6Parser::TYPE - 130))
      | (1ULL << (VisualBasic6Parser::TYPEOF - 130))
      | (1ULL << (VisualBasic6Parser::UNLOAD - 130))
      | (1ULL << (VisualBasic6Parser::UNLOCK - 130))
      | (1ULL << (VisualBasic6Parser::UNTIL - 130))
      | (1ULL << (VisualBasic6Parser::VARIANT - 130))
      | (1ULL << (VisualBasic6Parser::VERSION - 130))
      | (1ULL << (VisualBasic6Parser::WEND - 130))
      | (1ULL << (VisualBasic6Parser::WHILE - 130))
      | (1ULL << (VisualBasic6Parser::WIDTH - 130))
      | (1ULL << (VisualBasic6Parser::WITH - 130))
      | (1ULL << (VisualBasic6Parser::WITHEVENTS - 130))
      | (1ULL << (VisualBasic6Parser::WRITE - 130))
      | (1ULL << (VisualBasic6Parser::XOR - 130)))) != 0))) {
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

bool VisualBasic6Parser::sempred(RuleContext *context, size_t ruleIndex, size_t predicateIndex) {
  switch (ruleIndex) {
    case 110: return valueStmtSempred(dynamic_cast<ValueStmtContext *>(context), predicateIndex);

  default:
    break;
  }
  return true;
}

bool VisualBasic6Parser::valueStmtSempred(ValueStmtContext *_localctx, size_t predicateIndex) {
  switch (predicateIndex) {
    case 0: return precpred(_ctx, 25);
    case 1: return precpred(_ctx, 22);
    case 2: return precpred(_ctx, 21);
    case 3: return precpred(_ctx, 20);
    case 4: return precpred(_ctx, 19);
    case 5: return precpred(_ctx, 18);
    case 6: return precpred(_ctx, 17);
    case 7: return precpred(_ctx, 16);
    case 8: return precpred(_ctx, 15);
    case 9: return precpred(_ctx, 14);
    case 10: return precpred(_ctx, 13);
    case 11: return precpred(_ctx, 12);
    case 12: return precpred(_ctx, 11);
    case 13: return precpred(_ctx, 10);
    case 14: return precpred(_ctx, 9);
    case 15: return precpred(_ctx, 7);
    case 16: return precpred(_ctx, 6);
    case 17: return precpred(_ctx, 5);
    case 18: return precpred(_ctx, 4);
    case 19: return precpred(_ctx, 3);

  default:
    break;
  }
  return true;
}

// Static vars and initialization.
std::vector<dfa::DFA> VisualBasic6Parser::_decisionToDFA;
atn::PredictionContextCache VisualBasic6Parser::_sharedContextCache;

// We own the ATN which in turn owns the ATN states.
atn::ATN VisualBasic6Parser::_atn;
std::vector<uint16_t> VisualBasic6Parser::_serializedATN;

std::vector<std::string> VisualBasic6Parser::_ruleNames = {
  "startRule", "module", "moduleReferences", "moduleReference", "moduleReferenceValue", 
  "moduleReferenceComponent", "moduleHeader", "moduleConfig", "moduleConfigElement", 
  "moduleAttributes", "moduleOptions", "moduleOption", "moduleBody", "moduleBodyElement", 
  "controlProperties", "cp_Properties", "cp_SingleProperty", "cp_PropertyName", 
  "cp_PropertyValue", "cp_NestedProperty", "cp_ControlType", "cp_ControlIdentifier", 
  "moduleBlock", "attributeStmt", "block", "blockStmt", "appActivateStmt", 
  "beepStmt", "chDirStmt", "chDriveStmt", "closeStmt", "constStmt", "constSubStmt", 
  "dateStmt", "declareStmt", "deftypeStmt", "deleteSettingStmt", "doLoopStmt", 
  "endStmt", "enumerationStmt", "enumerationStmt_Constant", "eraseStmt", 
  "errorStmt", "eventStmt", "exitStmt", "filecopyStmt", "forEachStmt", "forNextStmt", 
  "functionStmt", "getStmt", "goSubStmt", "goToStmt", "ifThenElseStmt", 
  "ifBlockStmt", "ifConditionStmt", "ifElseIfBlockStmt", "ifElseBlockStmt", 
  "implementsStmt", "inputStmt", "killStmt", "letStmt", "lineInputStmt", 
  "loadStmt", "lockStmt", "lsetStmt", "macroIfThenElseStmt", "macroIfBlockStmt", 
  "macroElseIfBlockStmt", "macroElseBlockStmt", "midStmt", "mkdirStmt", 
  "nameStmt", "onErrorStmt", "onGoToStmt", "onGoSubStmt", "openStmt", "outputList", 
  "outputList_Expression", "printStmt", "propertyGetStmt", "propertySetStmt", 
  "propertyLetStmt", "putStmt", "raiseEventStmt", "randomizeStmt", "redimStmt", 
  "redimSubStmt", "resetStmt", "resumeStmt", "returnStmt", "rmdirStmt", 
  "rsetStmt", "savepictureStmt", "saveSettingStmt", "seekStmt", "selectCaseStmt", 
  "sC_Case", "sC_Cond", "sC_CondExpr", "sendkeysStmt", "setattrStmt", "setStmt", 
  "stopStmt", "subStmt", "timeStmt", "typeStmt", "typeStmt_Element", "typeOfStmt", 
  "unloadStmt", "unlockStmt", "valueStmt", "variableStmt", "variableListStmt", 
  "variableSubStmt", "whileWendStmt", "widthStmt", "withStmt", "writeStmt", 
  "explicitCallStmt", "eCS_ProcedureCall", "eCS_MemberProcedureCall", "implicitCallStmt_InBlock", 
  "iCS_B_ProcedureCall", "iCS_B_MemberProcedureCall", "implicitCallStmt_InStmt", 
  "iCS_S_VariableOrProcedureCall", "iCS_S_ProcedureOrArrayCall", "iCS_S_NestedProcedureCall", 
  "iCS_S_MembersCall", "iCS_S_MemberCall", "iCS_S_DictionaryCall", "argsCall", 
  "argCall", "dictionaryCallStmt", "argList", "arg", "argDefaultValue", 
  "subscripts", "subscript", "ambiguousIdentifier", "asTypeClause", "baseType", 
  "certainIdentifier", "comparisonOperator", "complexType", "fieldLength", 
  "letterrange", "lineLabel", "literal", "publicPrivateVisibility", "publicPrivateGlobalVisibility", 
  "type", "typeHint", "visibility", "ambiguousKeyword"
};

std::vector<std::string> VisualBasic6Parser::_literalNames = {
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", 
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", 
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", 
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", 
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", 
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", 
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", 
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", 
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", 
  "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "'&'", 
  "':='", "'@'", "':'", "','", "", "'$'", "'.'", "'='", "'!'", "'>='", "'>'", 
  "'#'", "'<='", "'{'", "'('", "'<'", "'-'", "'-='", "'*'", "'<>'", "'%'", 
  "'+'", "'+='", "'^'", "'}'", "')'", "';'", "'['", "']'"
};

std::vector<std::string> VisualBasic6Parser::_symbolicNames = {
  "", "ACCESS", "ADDRESSOF", "ALIAS", "AND", "ATTRIBUTE", "APPACTIVATE", 
  "APPEND", "AS", "BEEP", "BEGIN", "BEGINPROPERTY", "BINARY", "BOOLEAN", 
  "BYVAL", "BYREF", "BYTE", "CALL", "CASE", "CHDIR", "CHDRIVE", "CLASS", 
  "CLOSE", "COLLECTION", "CONST", "DATE", "DECLARE", "DEFBOOL", "DEFBYTE", 
  "DEFDATE", "DEFDBL", "DEFDEC", "DEFCUR", "DEFINT", "DEFLNG", "DEFOBJ", 
  "DEFSNG", "DEFSTR", "DEFVAR", "DELETESETTING", "DIM", "DO", "DOUBLE", 
  "EACH", "ELSE", "ELSEIF", "END_ENUM", "END_FUNCTION", "END_IF", "END_PROPERTY", 
  "END_SELECT", "END_SUB", "END_TYPE", "END_WITH", "END", "ENDPROPERTY", 
  "ENUM", "EQV", "ERASE", "ERROR", "EVENT", "EXIT_DO", "EXIT_FOR", "EXIT_FUNCTION", 
  "EXIT_PROPERTY", "EXIT_SUB", "FALSE1", "FILECOPY", "FRIEND", "FOR", "FUNCTION", 
  "GET", "GLOBAL", "GOSUB", "GOTO", "IF", "IMP", "IMPLEMENTS", "IN", "INPUT", 
  "IS", "INTEGER", "KILL", "LOAD", "LOCK", "LONG", "LOOP", "LEN", "LET", 
  "LIB", "LIKE", "LINE_INPUT", "LOCK_READ", "LOCK_WRITE", "LOCK_READ_WRITE", 
  "LSET", "MACRO_IF", "MACRO_ELSEIF", "MACRO_ELSE", "MACRO_END_IF", "ME", 
  "MID", "MKDIR", "MOD", "NAME", "NEXT", "NEW", "NOT", "NOTHING", "NULL1", 
  "OBJECT", "ON", "ON_ERROR", "ON_LOCAL_ERROR", "OPEN", "OPTIONAL", "OPTION_BASE", 
  "OPTION_EXPLICIT", "OPTION_COMPARE", "OPTION_PRIVATE_MODULE", "OR", "OUTPUT", 
  "PARAMARRAY", "PRESERVE", "PRINT", "PRIVATE", "PROPERTY_GET", "PROPERTY_LET", 
  "PROPERTY_SET", "PUBLIC", "PUT", "RANDOM", "RANDOMIZE", "RAISEEVENT", 
  "READ", "READ_WRITE", "REDIM", "REM", "RESET", "RESUME", "RETURN", "RMDIR", 
  "RSET", "SAVEPICTURE", "SAVESETTING", "SEEK", "SELECT", "SENDKEYS", "SET", 
  "SETATTR", "SHARED", "SINGLE", "SPC", "STATIC", "STEP", "STOP", "STRING", 
  "SUB", "TAB", "TEXT", "THEN", "TIME", "TO", "TRUE1", "TYPE", "TYPEOF", 
  "UNLOAD", "UNLOCK", "UNTIL", "VARIANT", "VERSION", "WEND", "WHILE", "WIDTH", 
  "WITH", "WITHEVENTS", "WRITE", "XOR", "AMPERSAND", "ASSIGN", "AT", "COLON", 
  "COMMA", "DIV", "DOLLAR", "DOT", "EQ", "EXCLAMATIONMARK", "GEQ", "GT", 
  "HASH", "LEQ", "LBRACE", "LPAREN", "LT", "MINUS", "MINUS_EQ", "MULT", 
  "NEQ", "PERCENT", "PLUS", "PLUS_EQ", "POW", "RBRACE", "RPAREN", "SEMICOLON", 
  "L_SQUARE_BRACKET", "R_SQUARE_BRACKET", "STRINGLITERAL", "DATELITERAL", 
  "COLORLITERAL", "INTEGERLITERAL", "DOUBLELITERAL", "FILENUMBER", "OCTALLITERAL", 
  "FRX_OFFSET", "GUID", "IDENTIFIER", "LINE_CONTINUATION", "NEWLINE", "COMMENT", 
  "WS"
};

dfa::Vocabulary VisualBasic6Parser::_vocabulary(_literalNames, _symbolicNames);

std::vector<std::string> VisualBasic6Parser::_tokenNames;

VisualBasic6Parser::Initializer::Initializer() {
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

  static uint16_t serializedATNSegment0[] = {
    0x3, 0x608b, 0xa72a, 0x8133, 0xb9ed, 0x417c, 0x3be7, 0x7786, 0x5964, 
       0x3, 0xdf, 0xb4a, 0x4, 0x2, 0x9, 0x2, 0x4, 0x3, 0x9, 0x3, 0x4, 0x4, 
       0x9, 0x4, 0x4, 0x5, 0x9, 0x5, 0x4, 0x6, 0x9, 0x6, 0x4, 0x7, 0x9, 
       0x7, 0x4, 0x8, 0x9, 0x8, 0x4, 0x9, 0x9, 0x9, 0x4, 0xa, 0x9, 0xa, 
       0x4, 0xb, 0x9, 0xb, 0x4, 0xc, 0x9, 0xc, 0x4, 0xd, 0x9, 0xd, 0x4, 
       0xe, 0x9, 0xe, 0x4, 0xf, 0x9, 0xf, 0x4, 0x10, 0x9, 0x10, 0x4, 0x11, 
       0x9, 0x11, 0x4, 0x12, 0x9, 0x12, 0x4, 0x13, 0x9, 0x13, 0x4, 0x14, 
       0x9, 0x14, 0x4, 0x15, 0x9, 0x15, 0x4, 0x16, 0x9, 0x16, 0x4, 0x17, 
       0x9, 0x17, 0x4, 0x18, 0x9, 0x18, 0x4, 0x19, 0x9, 0x19, 0x4, 0x1a, 
       0x9, 0x1a, 0x4, 0x1b, 0x9, 0x1b, 0x4, 0x1c, 0x9, 0x1c, 0x4, 0x1d, 
       0x9, 0x1d, 0x4, 0x1e, 0x9, 0x1e, 0x4, 0x1f, 0x9, 0x1f, 0x4, 0x20, 
       0x9, 0x20, 0x4, 0x21, 0x9, 0x21, 0x4, 0x22, 0x9, 0x22, 0x4, 0x23, 
       0x9, 0x23, 0x4, 0x24, 0x9, 0x24, 0x4, 0x25, 0x9, 0x25, 0x4, 0x26, 
       0x9, 0x26, 0x4, 0x27, 0x9, 0x27, 0x4, 0x28, 0x9, 0x28, 0x4, 0x29, 
       0x9, 0x29, 0x4, 0x2a, 0x9, 0x2a, 0x4, 0x2b, 0x9, 0x2b, 0x4, 0x2c, 
       0x9, 0x2c, 0x4, 0x2d, 0x9, 0x2d, 0x4, 0x2e, 0x9, 0x2e, 0x4, 0x2f, 
       0x9, 0x2f, 0x4, 0x30, 0x9, 0x30, 0x4, 0x31, 0x9, 0x31, 0x4, 0x32, 
       0x9, 0x32, 0x4, 0x33, 0x9, 0x33, 0x4, 0x34, 0x9, 0x34, 0x4, 0x35, 
       0x9, 0x35, 0x4, 0x36, 0x9, 0x36, 0x4, 0x37, 0x9, 0x37, 0x4, 0x38, 
       0x9, 0x38, 0x4, 0x39, 0x9, 0x39, 0x4, 0x3a, 0x9, 0x3a, 0x4, 0x3b, 
       0x9, 0x3b, 0x4, 0x3c, 0x9, 0x3c, 0x4, 0x3d, 0x9, 0x3d, 0x4, 0x3e, 
       0x9, 0x3e, 0x4, 0x3f, 0x9, 0x3f, 0x4, 0x40, 0x9, 0x40, 0x4, 0x41, 
       0x9, 0x41, 0x4, 0x42, 0x9, 0x42, 0x4, 0x43, 0x9, 0x43, 0x4, 0x44, 
       0x9, 0x44, 0x4, 0x45, 0x9, 0x45, 0x4, 0x46, 0x9, 0x46, 0x4, 0x47, 
       0x9, 0x47, 0x4, 0x48, 0x9, 0x48, 0x4, 0x49, 0x9, 0x49, 0x4, 0x4a, 
       0x9, 0x4a, 0x4, 0x4b, 0x9, 0x4b, 0x4, 0x4c, 0x9, 0x4c, 0x4, 0x4d, 
       0x9, 0x4d, 0x4, 0x4e, 0x9, 0x4e, 0x4, 0x4f, 0x9, 0x4f, 0x4, 0x50, 
       0x9, 0x50, 0x4, 0x51, 0x9, 0x51, 0x4, 0x52, 0x9, 0x52, 0x4, 0x53, 
       0x9, 0x53, 0x4, 0x54, 0x9, 0x54, 0x4, 0x55, 0x9, 0x55, 0x4, 0x56, 
       0x9, 0x56, 0x4, 0x57, 0x9, 0x57, 0x4, 0x58, 0x9, 0x58, 0x4, 0x59, 
       0x9, 0x59, 0x4, 0x5a, 0x9, 0x5a, 0x4, 0x5b, 0x9, 0x5b, 0x4, 0x5c, 
       0x9, 0x5c, 0x4, 0x5d, 0x9, 0x5d, 0x4, 0x5e, 0x9, 0x5e, 0x4, 0x5f, 
       0x9, 0x5f, 0x4, 0x60, 0x9, 0x60, 0x4, 0x61, 0x9, 0x61, 0x4, 0x62, 
       0x9, 0x62, 0x4, 0x63, 0x9, 0x63, 0x4, 0x64, 0x9, 0x64, 0x4, 0x65, 
       0x9, 0x65, 0x4, 0x66, 0x9, 0x66, 0x4, 0x67, 0x9, 0x67, 0x4, 0x68, 
       0x9, 0x68, 0x4, 0x69, 0x9, 0x69, 0x4, 0x6a, 0x9, 0x6a, 0x4, 0x6b, 
       0x9, 0x6b, 0x4, 0x6c, 0x9, 0x6c, 0x4, 0x6d, 0x9, 0x6d, 0x4, 0x6e, 
       0x9, 0x6e, 0x4, 0x6f, 0x9, 0x6f, 0x4, 0x70, 0x9, 0x70, 0x4, 0x71, 
       0x9, 0x71, 0x4, 0x72, 0x9, 0x72, 0x4, 0x73, 0x9, 0x73, 0x4, 0x74, 
       0x9, 0x74, 0x4, 0x75, 0x9, 0x75, 0x4, 0x76, 0x9, 0x76, 0x4, 0x77, 
       0x9, 0x77, 0x4, 0x78, 0x9, 0x78, 0x4, 0x79, 0x9, 0x79, 0x4, 0x7a, 
       0x9, 0x7a, 0x4, 0x7b, 0x9, 0x7b, 0x4, 0x7c, 0x9, 0x7c, 0x4, 0x7d, 
       0x9, 0x7d, 0x4, 0x7e, 0x9, 0x7e, 0x4, 0x7f, 0x9, 0x7f, 0x4, 0x80, 
       0x9, 0x80, 0x4, 0x81, 0x9, 0x81, 0x4, 0x82, 0x9, 0x82, 0x4, 0x83, 
       0x9, 0x83, 0x4, 0x84, 0x9, 0x84, 0x4, 0x85, 0x9, 0x85, 0x4, 0x86, 
       0x9, 0x86, 0x4, 0x87, 0x9, 0x87, 0x4, 0x88, 0x9, 0x88, 0x4, 0x89, 
       0x9, 0x89, 0x4, 0x8a, 0x9, 0x8a, 0x4, 0x8b, 0x9, 0x8b, 0x4, 0x8c, 
       0x9, 0x8c, 0x4, 0x8d, 0x9, 0x8d, 0x4, 0x8e, 0x9, 0x8e, 0x4, 0x8f, 
       0x9, 0x8f, 0x4, 0x90, 0x9, 0x90, 0x4, 0x91, 0x9, 0x91, 0x4, 0x92, 
       0x9, 0x92, 0x4, 0x93, 0x9, 0x93, 0x4, 0x94, 0x9, 0x94, 0x4, 0x95, 
       0x9, 0x95, 0x4, 0x96, 0x9, 0x96, 0x4, 0x97, 0x9, 0x97, 0x4, 0x98, 
       0x9, 0x98, 0x4, 0x99, 0x9, 0x99, 0x4, 0x9a, 0x9, 0x9a, 0x4, 0x9b, 
       0x9, 0x9b, 0x4, 0x9c, 0x9, 0x9c, 0x3, 0x2, 0x3, 0x2, 0x3, 0x2, 0x3, 
       0x3, 0x5, 0x3, 0x13d, 0xa, 0x3, 0x3, 0x3, 0x7, 0x3, 0x140, 0xa, 0x3, 
       0xc, 0x3, 0xe, 0x3, 0x143, 0xb, 0x3, 0x3, 0x3, 0x3, 0x3, 0x6, 0x3, 
       0x147, 0xa, 0x3, 0xd, 0x3, 0xe, 0x3, 0x148, 0x5, 0x3, 0x14b, 0xa, 
       0x3, 0x3, 0x3, 0x5, 0x3, 0x14e, 0xa, 0x3, 0x3, 0x3, 0x7, 0x3, 0x151, 
       0xa, 0x3, 0xc, 0x3, 0xe, 0x3, 0x154, 0xb, 0x3, 0x3, 0x3, 0x5, 0x3, 
       0x157, 0xa, 0x3, 0x3, 0x3, 0x7, 0x3, 0x15a, 0xa, 0x3, 0xc, 0x3, 0xe, 
       0x3, 0x15d, 0xb, 0x3, 0x3, 0x3, 0x5, 0x3, 0x160, 0xa, 0x3, 0x3, 0x3, 
       0x7, 0x3, 0x163, 0xa, 0x3, 0xc, 0x3, 0xe, 0x3, 0x166, 0xb, 0x3, 0x3, 
       0x3, 0x5, 0x3, 0x169, 0xa, 0x3, 0x3, 0x3, 0x7, 0x3, 0x16c, 0xa, 0x3, 
       0xc, 0x3, 0xe, 0x3, 0x16f, 0xb, 0x3, 0x3, 0x3, 0x5, 0x3, 0x172, 0xa, 
       0x3, 0x3, 0x3, 0x7, 0x3, 0x175, 0xa, 0x3, 0xc, 0x3, 0xe, 0x3, 0x178, 
       0xb, 0x3, 0x3, 0x3, 0x5, 0x3, 0x17b, 0xa, 0x3, 0x3, 0x3, 0x7, 0x3, 
       0x17e, 0xa, 0x3, 0xc, 0x3, 0xe, 0x3, 0x181, 0xb, 0x3, 0x3, 0x3, 0x5, 
       0x3, 0x184, 0xa, 0x3, 0x3, 0x4, 0x6, 0x4, 0x187, 0xa, 0x4, 0xd, 0x4, 
       0xe, 0x4, 0x188, 0x3, 0x5, 0x3, 0x5, 0x5, 0x5, 0x18d, 0xa, 0x5, 0x3, 
       0x5, 0x3, 0x5, 0x5, 0x5, 0x191, 0xa, 0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 
       0x5, 0x5, 0x5, 0x196, 0xa, 0x5, 0x3, 0x5, 0x5, 0x5, 0x199, 0xa, 0x5, 
       0x3, 0x5, 0x7, 0x5, 0x19c, 0xa, 0x5, 0xc, 0x5, 0xe, 0x5, 0x19f, 0xb, 
       0x5, 0x3, 0x6, 0x3, 0x6, 0x3, 0x7, 0x3, 0x7, 0x3, 0x8, 0x3, 0x8, 
       0x3, 0x8, 0x3, 0x8, 0x3, 0x8, 0x5, 0x8, 0x1aa, 0xa, 0x8, 0x3, 0x9, 
       0x3, 0x9, 0x6, 0x9, 0x1ae, 0xa, 0x9, 0xd, 0x9, 0xe, 0x9, 0x1af, 0x3, 
       0x9, 0x6, 0x9, 0x1b3, 0xa, 0x9, 0xd, 0x9, 0xe, 0x9, 0x1b4, 0x3, 0x9, 
       0x3, 0x9, 0x6, 0x9, 0x1b9, 0xa, 0x9, 0xd, 0x9, 0xe, 0x9, 0x1ba, 0x3, 
       0xa, 0x3, 0xa, 0x5, 0xa, 0x1bf, 0xa, 0xa, 0x3, 0xa, 0x3, 0xa, 0x5, 
       0xa, 0x1c3, 0xa, 0xa, 0x3, 0xa, 0x3, 0xa, 0x3, 0xa, 0x3, 0xb, 0x3, 
       0xb, 0x6, 0xb, 0x1ca, 0xa, 0xb, 0xd, 0xb, 0xe, 0xb, 0x1cb, 0x6, 0xb, 
       0x1ce, 0xa, 0xb, 0xd, 0xb, 0xe, 0xb, 0x1cf, 0x3, 0xc, 0x3, 0xc, 0x6, 
       0xc, 0x1d4, 0xa, 0xc, 0xd, 0xc, 0xe, 0xc, 0x1d5, 0x6, 0xc, 0x1d8, 
       0xa, 0xc, 0xd, 0xc, 0xe, 0xc, 0x1d9, 0x3, 0xd, 0x3, 0xd, 0x3, 0xd, 
       0x3, 0xd, 0x3, 0xd, 0x3, 0xd, 0x3, 0xd, 0x3, 0xd, 0x5, 0xd, 0x1e4, 
       0xa, 0xd, 0x3, 0xe, 0x3, 0xe, 0x6, 0xe, 0x1e8, 0xa, 0xe, 0xd, 0xe, 
       0xe, 0xe, 0x1e9, 0x3, 0xe, 0x7, 0xe, 0x1ed, 0xa, 0xe, 0xc, 0xe, 0xe, 
       0xe, 0x1f0, 0xb, 0xe, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 
       0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 0x3, 0xf, 
       0x3, 0xf, 0x5, 0xf, 0x1fe, 0xa, 0xf, 0x3, 0x10, 0x5, 0x10, 0x201, 
       0xa, 0x10, 0x3, 0x10, 0x3, 0x10, 0x3, 0x10, 0x3, 0x10, 0x3, 0x10, 
       0x3, 0x10, 0x5, 0x10, 0x209, 0xa, 0x10, 0x3, 0x10, 0x6, 0x10, 0x20c, 
       0xa, 0x10, 0xd, 0x10, 0xe, 0x10, 0x20d, 0x3, 0x10, 0x6, 0x10, 0x211, 
       0xa, 0x10, 0xd, 0x10, 0xe, 0x10, 0x212, 0x3, 0x10, 0x3, 0x10, 0x7, 
       0x10, 0x217, 0xa, 0x10, 0xc, 0x10, 0xe, 0x10, 0x21a, 0xb, 0x10, 0x3, 
       0x11, 0x3, 0x11, 0x3, 0x11, 0x5, 0x11, 0x21f, 0xa, 0x11, 0x3, 0x12, 
       0x5, 0x12, 0x222, 0xa, 0x12, 0x3, 0x12, 0x3, 0x12, 0x5, 0x12, 0x226, 
       0xa, 0x12, 0x3, 0x12, 0x3, 0x12, 0x5, 0x12, 0x22a, 0xa, 0x12, 0x3, 
       0x12, 0x5, 0x12, 0x22d, 0xa, 0x12, 0x3, 0x12, 0x3, 0x12, 0x5, 0x12, 
       0x231, 0xa, 0x12, 0x3, 0x12, 0x6, 0x12, 0x234, 0xa, 0x12, 0xd, 0x12, 
       0xe, 0x12, 0x235, 0x3, 0x13, 0x3, 0x13, 0x5, 0x13, 0x23a, 0xa, 0x13, 
       0x3, 0x13, 0x3, 0x13, 0x3, 0x13, 0x3, 0x13, 0x3, 0x13, 0x5, 0x13, 
       0x241, 0xa, 0x13, 0x3, 0x13, 0x3, 0x13, 0x3, 0x13, 0x3, 0x13, 0x3, 
       0x13, 0x3, 0x13, 0x5, 0x13, 0x249, 0xa, 0x13, 0x7, 0x13, 0x24b, 0xa, 
       0x13, 0xc, 0x13, 0xe, 0x13, 0x24e, 0xb, 0x13, 0x3, 0x14, 0x5, 0x14, 
       0x251, 0xa, 0x14, 0x3, 0x14, 0x3, 0x14, 0x3, 0x14, 0x3, 0x14, 0x3, 
       0x14, 0x3, 0x14, 0x3, 0x14, 0x5, 0x14, 0x25a, 0xa, 0x14, 0x3, 0x15, 
       0x5, 0x15, 0x25d, 0xa, 0x15, 0x3, 0x15, 0x3, 0x15, 0x3, 0x15, 0x3, 
       0x15, 0x3, 0x15, 0x3, 0x15, 0x5, 0x15, 0x265, 0xa, 0x15, 0x3, 0x15, 
       0x3, 0x15, 0x5, 0x15, 0x269, 0xa, 0x15, 0x3, 0x15, 0x6, 0x15, 0x26c, 
       0xa, 0x15, 0xd, 0x15, 0xe, 0x15, 0x26d, 0x3, 0x15, 0x6, 0x15, 0x271, 
       0xa, 0x15, 0xd, 0x15, 0xe, 0x15, 0x272, 0x5, 0x15, 0x275, 0xa, 0x15, 
       0x3, 0x15, 0x3, 0x15, 0x6, 0x15, 0x279, 0xa, 0x15, 0xd, 0x15, 0xe, 
       0x15, 0x27a, 0x3, 0x16, 0x3, 0x16, 0x3, 0x17, 0x3, 0x17, 0x3, 0x18, 
       0x3, 0x18, 0x3, 0x19, 0x3, 0x19, 0x3, 0x19, 0x3, 0x19, 0x5, 0x19, 
       0x287, 0xa, 0x19, 0x3, 0x19, 0x3, 0x19, 0x5, 0x19, 0x28b, 0xa, 0x19, 
       0x3, 0x19, 0x3, 0x19, 0x5, 0x19, 0x28f, 0xa, 0x19, 0x3, 0x19, 0x3, 
       0x19, 0x5, 0x19, 0x293, 0xa, 0x19, 0x3, 0x19, 0x7, 0x19, 0x296, 0xa, 
       0x19, 0xc, 0x19, 0xe, 0x19, 0x299, 0xb, 0x19, 0x3, 0x1a, 0x3, 0x1a, 
       0x6, 0x1a, 0x29d, 0xa, 0x1a, 0xd, 0x1a, 0xe, 0x1a, 0x29e, 0x3, 0x1a, 
       0x5, 0x1a, 0x2a2, 0xa, 0x1a, 0x3, 0x1a, 0x7, 0x1a, 0x2a5, 0xa, 0x1a, 
       0xc, 0x1a, 0xe, 0x1a, 0x2a8, 0xb, 0x1a, 0x3, 0x1b, 0x3, 0x1b, 0x3, 
       0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 
       0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 
       0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 
       0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 
       0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 
       0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 
       0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 
       0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 
       0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 
       0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 
       0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x3, 0x1b, 0x5, 0x1b, 0x2ed, 
       0xa, 0x1b, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x5, 0x1c, 
       0x2f3, 0xa, 0x1c, 0x3, 0x1c, 0x3, 0x1c, 0x5, 0x1c, 0x2f7, 0xa, 0x1c, 
       0x3, 0x1c, 0x5, 0x1c, 0x2fa, 0xa, 0x1c, 0x3, 0x1d, 0x3, 0x1d, 0x3, 
       0x1e, 0x3, 0x1e, 0x3, 0x1e, 0x3, 0x1e, 0x3, 0x1f, 0x3, 0x1f, 0x3, 
       0x1f, 0x3, 0x1f, 0x3, 0x20, 0x3, 0x20, 0x3, 0x20, 0x3, 0x20, 0x5, 
       0x20, 0x30a, 0xa, 0x20, 0x3, 0x20, 0x3, 0x20, 0x5, 0x20, 0x30e, 0xa, 
       0x20, 0x3, 0x20, 0x7, 0x20, 0x311, 0xa, 0x20, 0xc, 0x20, 0xe, 0x20, 
       0x314, 0xb, 0x20, 0x5, 0x20, 0x316, 0xa, 0x20, 0x3, 0x21, 0x3, 0x21, 
       0x3, 0x21, 0x5, 0x21, 0x31b, 0xa, 0x21, 0x3, 0x21, 0x3, 0x21, 0x3, 
       0x21, 0x3, 0x21, 0x5, 0x21, 0x321, 0xa, 0x21, 0x3, 0x21, 0x3, 0x21, 
       0x5, 0x21, 0x325, 0xa, 0x21, 0x3, 0x21, 0x7, 0x21, 0x328, 0xa, 0x21, 
       0xc, 0x21, 0xe, 0x21, 0x32b, 0xb, 0x21, 0x3, 0x22, 0x3, 0x22, 0x5, 
       0x22, 0x32f, 0xa, 0x22, 0x3, 0x22, 0x3, 0x22, 0x5, 0x22, 0x333, 0xa, 
       0x22, 0x3, 0x22, 0x5, 0x22, 0x336, 0xa, 0x22, 0x3, 0x22, 0x3, 0x22, 
       0x5, 0x22, 0x33a, 0xa, 0x22, 0x3, 0x22, 0x3, 0x22, 0x3, 0x23, 0x3, 
       0x23, 0x5, 0x23, 0x340, 0xa, 0x23, 0x3, 0x23, 0x3, 0x23, 0x5, 0x23, 
       0x344, 0xa, 0x23, 0x3, 0x23, 0x3, 0x23, 0x3, 0x24, 0x3, 0x24, 0x3, 
       0x24, 0x5, 0x24, 0x34b, 0xa, 0x24, 0x3, 0x24, 0x3, 0x24, 0x3, 0x24, 
       0x3, 0x24, 0x5, 0x24, 0x351, 0xa, 0x24, 0x3, 0x24, 0x5, 0x24, 0x354, 
       0xa, 0x24, 0x3, 0x24, 0x3, 0x24, 0x3, 0x24, 0x5, 0x24, 0x359, 0xa, 
       0x24, 0x3, 0x24, 0x3, 0x24, 0x3, 0x24, 0x3, 0x24, 0x3, 0x24, 0x3, 
       0x24, 0x3, 0x24, 0x3, 0x24, 0x5, 0x24, 0x363, 0xa, 0x24, 0x3, 0x24, 
       0x5, 0x24, 0x366, 0xa, 0x24, 0x3, 0x24, 0x5, 0x24, 0x369, 0xa, 0x24, 
       0x3, 0x24, 0x3, 0x24, 0x5, 0x24, 0x36d, 0xa, 0x24, 0x3, 0x25, 0x3, 
       0x25, 0x3, 0x25, 0x3, 0x25, 0x5, 0x25, 0x373, 0xa, 0x25, 0x3, 0x25, 
       0x3, 0x25, 0x5, 0x25, 0x377, 0xa, 0x25, 0x3, 0x25, 0x7, 0x25, 0x37a, 
       0xa, 0x25, 0xc, 0x25, 0xe, 0x25, 0x37d, 0xb, 0x25, 0x3, 0x26, 0x3, 
       0x26, 0x3, 0x26, 0x3, 0x26, 0x5, 0x26, 0x383, 0xa, 0x26, 0x3, 0x26, 
       0x3, 0x26, 0x5, 0x26, 0x387, 0xa, 0x26, 0x3, 0x26, 0x3, 0x26, 0x5, 
       0x26, 0x38b, 0xa, 0x26, 0x3, 0x26, 0x3, 0x26, 0x5, 0x26, 0x38f, 0xa, 
       0x26, 0x3, 0x26, 0x5, 0x26, 0x392, 0xa, 0x26, 0x3, 0x27, 0x3, 0x27, 
       0x6, 0x27, 0x396, 0xa, 0x27, 0xd, 0x27, 0xe, 0x27, 0x397, 0x3, 0x27, 
       0x3, 0x27, 0x6, 0x27, 0x39c, 0xa, 0x27, 0xd, 0x27, 0xe, 0x27, 0x39d, 
       0x5, 0x27, 0x3a0, 0xa, 0x27, 0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 0x3, 
       0x27, 0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 0x6, 0x27, 0x3a9, 0xa, 0x27, 
       0xd, 0x27, 0xe, 0x27, 0x3aa, 0x3, 0x27, 0x3, 0x27, 0x6, 0x27, 0x3af, 
       0xa, 0x27, 0xd, 0x27, 0xe, 0x27, 0x3b0, 0x5, 0x27, 0x3b3, 0xa, 0x27, 
       0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 0x6, 0x27, 0x3b9, 0xa, 
       0x27, 0xd, 0x27, 0xe, 0x27, 0x3ba, 0x3, 0x27, 0x3, 0x27, 0x6, 0x27, 
       0x3bf, 0xa, 0x27, 0xd, 0x27, 0xe, 0x27, 0x3c0, 0x3, 0x27, 0x3, 0x27, 
       0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 0x3, 0x27, 0x5, 0x27, 0x3c9, 0xa, 
       0x27, 0x3, 0x28, 0x3, 0x28, 0x3, 0x29, 0x3, 0x29, 0x3, 0x29, 0x5, 
       0x29, 0x3d0, 0xa, 0x29, 0x3, 0x29, 0x3, 0x29, 0x3, 0x29, 0x3, 0x29, 
       0x6, 0x29, 0x3d6, 0xa, 0x29, 0xd, 0x29, 0xe, 0x29, 0x3d7, 0x3, 0x29, 
       0x7, 0x29, 0x3db, 0xa, 0x29, 0xc, 0x29, 0xe, 0x29, 0x3de, 0xb, 0x29, 
       0x3, 0x29, 0x3, 0x29, 0x3, 0x2a, 0x3, 0x2a, 0x5, 0x2a, 0x3e4, 0xa, 
       0x2a, 0x3, 0x2a, 0x3, 0x2a, 0x5, 0x2a, 0x3e8, 0xa, 0x2a, 0x3, 0x2a, 
       0x5, 0x2a, 0x3eb, 0xa, 0x2a, 0x3, 0x2a, 0x6, 0x2a, 0x3ee, 0xa, 0x2a, 
       0xd, 0x2a, 0xe, 0x2a, 0x3ef, 0x3, 0x2b, 0x3, 0x2b, 0x3, 0x2b, 0x3, 
       0x2b, 0x5, 0x2b, 0x3f6, 0xa, 0x2b, 0x3, 0x2b, 0x3, 0x2b, 0x5, 0x2b, 
       0x3fa, 0xa, 0x2b, 0x3, 0x2b, 0x7, 0x2b, 0x3fd, 0xa, 0x2b, 0xc, 0x2b, 
       0xe, 0x2b, 0x400, 0xb, 0x2b, 0x3, 0x2c, 0x3, 0x2c, 0x3, 0x2c, 0x3, 
       0x2c, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x5, 0x2d, 0x409, 0xa, 0x2d, 
       0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x5, 0x2d, 0x40f, 0xa, 
       0x2d, 0x3, 0x2d, 0x3, 0x2d, 0x3, 0x2e, 0x3, 0x2e, 0x3, 0x2f, 0x3, 
       0x2f, 0x3, 0x2f, 0x3, 0x2f, 0x5, 0x2f, 0x419, 0xa, 0x2f, 0x3, 0x2f, 
       0x3, 0x2f, 0x5, 0x2f, 0x41d, 0xa, 0x2f, 0x3, 0x2f, 0x3, 0x2f, 0x3, 
       0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x5, 
       0x30, 0x427, 0xa, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 0x30, 
       0x3, 0x30, 0x6, 0x30, 0x42e, 0xa, 0x30, 0xd, 0x30, 0xe, 0x30, 0x42f, 
       0x3, 0x30, 0x3, 0x30, 0x6, 0x30, 0x434, 0xa, 0x30, 0xd, 0x30, 0xe, 
       0x30, 0x435, 0x5, 0x30, 0x438, 0xa, 0x30, 0x3, 0x30, 0x3, 0x30, 0x3, 
       0x30, 0x5, 0x30, 0x43d, 0xa, 0x30, 0x3, 0x31, 0x3, 0x31, 0x3, 0x31, 
       0x3, 0x31, 0x5, 0x31, 0x443, 0xa, 0x31, 0x3, 0x31, 0x3, 0x31, 0x5, 
       0x31, 0x447, 0xa, 0x31, 0x3, 0x31, 0x5, 0x31, 0x44a, 0xa, 0x31, 0x3, 
       0x31, 0x3, 0x31, 0x5, 0x31, 0x44e, 0xa, 0x31, 0x3, 0x31, 0x3, 0x31, 
       0x3, 0x31, 0x3, 0x31, 0x3, 0x31, 0x3, 0x31, 0x3, 0x31, 0x3, 0x31, 
       0x3, 0x31, 0x5, 0x31, 0x459, 0xa, 0x31, 0x3, 0x31, 0x6, 0x31, 0x45c, 
       0xa, 0x31, 0xd, 0x31, 0xe, 0x31, 0x45d, 0x3, 0x31, 0x3, 0x31, 0x6, 
       0x31, 0x462, 0xa, 0x31, 0xd, 0x31, 0xe, 0x31, 0x463, 0x5, 0x31, 0x466, 
       0xa, 0x31, 0x3, 0x31, 0x3, 0x31, 0x3, 0x31, 0x3, 0x31, 0x5, 0x31, 
       0x46c, 0xa, 0x31, 0x5, 0x31, 0x46e, 0xa, 0x31, 0x3, 0x32, 0x3, 0x32, 
       0x3, 0x32, 0x5, 0x32, 0x473, 0xa, 0x32, 0x3, 0x32, 0x3, 0x32, 0x5, 
       0x32, 0x477, 0xa, 0x32, 0x3, 0x32, 0x3, 0x32, 0x3, 0x32, 0x3, 0x32, 
       0x5, 0x32, 0x47d, 0xa, 0x32, 0x3, 0x32, 0x5, 0x32, 0x480, 0xa, 0x32, 
       0x3, 0x32, 0x3, 0x32, 0x5, 0x32, 0x484, 0xa, 0x32, 0x3, 0x32, 0x6, 
       0x32, 0x487, 0xa, 0x32, 0xd, 0x32, 0xe, 0x32, 0x488, 0x3, 0x32, 0x3, 
       0x32, 0x6, 0x32, 0x48d, 0xa, 0x32, 0xd, 0x32, 0xe, 0x32, 0x48e, 0x5, 
       0x32, 0x491, 0xa, 0x32, 0x3, 0x32, 0x3, 0x32, 0x3, 0x33, 0x3, 0x33, 
       0x3, 0x33, 0x3, 0x33, 0x5, 0x33, 0x499, 0xa, 0x33, 0x3, 0x33, 0x3, 
       0x33, 0x5, 0x33, 0x49d, 0xa, 0x33, 0x3, 0x33, 0x5, 0x33, 0x4a0, 0xa, 
       0x33, 0x3, 0x33, 0x5, 0x33, 0x4a3, 0xa, 0x33, 0x3, 0x33, 0x3, 0x33, 
       0x5, 0x33, 0x4a7, 0xa, 0x33, 0x3, 0x33, 0x3, 0x33, 0x3, 0x34, 0x3, 
       0x34, 0x3, 0x34, 0x3, 0x34, 0x3, 0x35, 0x3, 0x35, 0x3, 0x35, 0x3, 
       0x35, 0x3, 0x36, 0x3, 0x36, 0x3, 0x36, 0x3, 0x36, 0x3, 0x36, 0x3, 
       0x36, 0x3, 0x36, 0x3, 0x36, 0x3, 0x36, 0x3, 0x36, 0x3, 0x36, 0x5, 
       0x36, 0x4be, 0xa, 0x36, 0x3, 0x36, 0x3, 0x36, 0x7, 0x36, 0x4c2, 0xa, 
       0x36, 0xc, 0x36, 0xe, 0x36, 0x4c5, 0xb, 0x36, 0x3, 0x36, 0x5, 0x36, 
       0x4c8, 0xa, 0x36, 0x3, 0x36, 0x3, 0x36, 0x5, 0x36, 0x4cc, 0xa, 0x36, 
       0x3, 0x37, 0x3, 0x37, 0x3, 0x37, 0x3, 0x37, 0x3, 0x37, 0x3, 0x37, 
       0x6, 0x37, 0x4d4, 0xa, 0x37, 0xd, 0x37, 0xe, 0x37, 0x4d5, 0x3, 0x37, 
       0x3, 0x37, 0x6, 0x37, 0x4da, 0xa, 0x37, 0xd, 0x37, 0xe, 0x37, 0x4db, 
       0x5, 0x37, 0x4de, 0xa, 0x37, 0x3, 0x38, 0x3, 0x38, 0x3, 0x39, 0x3, 
       0x39, 0x3, 0x39, 0x3, 0x39, 0x3, 0x39, 0x3, 0x39, 0x6, 0x39, 0x4e8, 
       0xa, 0x39, 0xd, 0x39, 0xe, 0x39, 0x4e9, 0x3, 0x39, 0x3, 0x39, 0x6, 
       0x39, 0x4ee, 0xa, 0x39, 0xd, 0x39, 0xe, 0x39, 0x4ef, 0x5, 0x39, 0x4f2, 
       0xa, 0x39, 0x3, 0x3a, 0x3, 0x3a, 0x6, 0x3a, 0x4f6, 0xa, 0x3a, 0xd, 
       0x3a, 0xe, 0x3a, 0x4f7, 0x3, 0x3a, 0x3, 0x3a, 0x6, 0x3a, 0x4fc, 0xa, 
       0x3a, 0xd, 0x3a, 0xe, 0x3a, 0x4fd, 0x5, 0x3a, 0x500, 0xa, 0x3a, 0x3, 
       0x3b, 0x3, 0x3b, 0x3, 0x3b, 0x3, 0x3b, 0x3, 0x3c, 0x3, 0x3c, 0x3, 
       0x3c, 0x3, 0x3c, 0x5, 0x3c, 0x50a, 0xa, 0x3c, 0x3, 0x3c, 0x3, 0x3c, 
       0x5, 0x3c, 0x50e, 0xa, 0x3c, 0x3, 0x3c, 0x6, 0x3c, 0x511, 0xa, 0x3c, 
       0xd, 0x3c, 0xe, 0x3c, 0x512, 0x3, 0x3d, 0x3, 0x3d, 0x3, 0x3d, 0x3, 
       0x3d, 0x3, 0x3e, 0x3, 0x3e, 0x5, 0x3e, 0x51b, 0xa, 0x3e, 0x3, 0x3e, 
       0x3, 0x3e, 0x5, 0x3e, 0x51f, 0xa, 0x3e, 0x3, 0x3e, 0x3, 0x3e, 0x5, 
       0x3e, 0x523, 0xa, 0x3e, 0x3, 0x3e, 0x3, 0x3e, 0x3, 0x3f, 0x3, 0x3f, 
       0x3, 0x3f, 0x3, 0x3f, 0x5, 0x3f, 0x52b, 0xa, 0x3f, 0x3, 0x3f, 0x3, 
       0x3f, 0x5, 0x3f, 0x52f, 0xa, 0x3f, 0x3, 0x3f, 0x3, 0x3f, 0x3, 0x40, 
       0x3, 0x40, 0x3, 0x40, 0x3, 0x40, 0x3, 0x41, 0x3, 0x41, 0x3, 0x41, 
       0x3, 0x41, 0x5, 0x41, 0x53b, 0xa, 0x41, 0x3, 0x41, 0x3, 0x41, 0x5, 
       0x41, 0x53f, 0xa, 0x41, 0x3, 0x41, 0x3, 0x41, 0x3, 0x41, 0x3, 0x41, 
       0x3, 0x41, 0x5, 0x41, 0x546, 0xa, 0x41, 0x5, 0x41, 0x548, 0xa, 0x41, 
       0x3, 0x42, 0x3, 0x42, 0x3, 0x42, 0x3, 0x42, 0x5, 0x42, 0x54e, 0xa, 
       0x42, 0x3, 0x42, 0x3, 0x42, 0x5, 0x42, 0x552, 0xa, 0x42, 0x3, 0x42, 
       0x3, 0x42, 0x3, 0x43, 0x3, 0x43, 0x7, 0x43, 0x558, 0xa, 0x43, 0xc, 
       0x43, 0xe, 0x43, 0x55b, 0xb, 0x43, 0x3, 0x43, 0x5, 0x43, 0x55e, 0xa, 
       0x43, 0x3, 0x43, 0x3, 0x43, 0x3, 0x44, 0x3, 0x44, 0x3, 0x44, 0x3, 
       0x44, 0x3, 0x44, 0x3, 0x44, 0x6, 0x44, 0x568, 0xa, 0x44, 0xd, 0x44, 
       0xe, 0x44, 0x569, 0x3, 0x44, 0x3, 0x44, 0x6, 0x44, 0x56e, 0xa, 0x44, 
       0xd, 0x44, 0xe, 0x44, 0x56f, 0x5, 0x44, 0x572, 0xa, 0x44, 0x3, 0x45, 
       0x3, 0x45, 0x3, 0x45, 0x3, 0x45, 0x3, 0x45, 0x3, 0x45, 0x6, 0x45, 
       0x57a, 0xa, 0x45, 0xd, 0x45, 0xe, 0x45, 0x57b, 0x3, 0x45, 0x3, 0x45, 
       0x6, 0x45, 0x580, 0xa, 0x45, 0xd, 0x45, 0xe, 0x45, 0x581, 0x5, 0x45, 
       0x584, 0xa, 0x45, 0x3, 0x46, 0x3, 0x46, 0x6, 0x46, 0x588, 0xa, 0x46, 
       0xd, 0x46, 0xe, 0x46, 0x589, 0x3, 0x46, 0x3, 0x46, 0x6, 0x46, 0x58e, 
       0xa, 0x46, 0xd, 0x46, 0xe, 0x46, 0x58f, 0x5, 0x46, 0x592, 0xa, 0x46, 
       0x3, 0x47, 0x3, 0x47, 0x5, 0x47, 0x596, 0xa, 0x47, 0x3, 0x47, 0x3, 
       0x47, 0x5, 0x47, 0x59a, 0xa, 0x47, 0x3, 0x47, 0x3, 0x47, 0x5, 0x47, 
       0x59e, 0xa, 0x47, 0x3, 0x47, 0x3, 0x47, 0x3, 0x48, 0x3, 0x48, 0x3, 
       0x48, 0x3, 0x48, 0x3, 0x49, 0x3, 0x49, 0x3, 0x49, 0x3, 0x49, 0x3, 
       0x49, 0x3, 0x49, 0x3, 0x49, 0x3, 0x49, 0x3, 0x4a, 0x3, 0x4a, 0x3, 
       0x4a, 0x3, 0x4a, 0x3, 0x4a, 0x3, 0x4a, 0x5, 0x4a, 0x5b4, 0xa, 0x4a, 
       0x3, 0x4a, 0x3, 0x4a, 0x3, 0x4a, 0x5, 0x4a, 0x5b9, 0xa, 0x4a, 0x3, 
       0x4b, 0x3, 0x4b, 0x3, 0x4b, 0x3, 0x4b, 0x3, 0x4b, 0x3, 0x4b, 0x3, 
       0x4b, 0x3, 0x4b, 0x5, 0x4b, 0x5c3, 0xa, 0x4b, 0x3, 0x4b, 0x3, 0x4b, 
       0x5, 0x4b, 0x5c7, 0xa, 0x4b, 0x3, 0x4b, 0x7, 0x4b, 0x5ca, 0xa, 0x4b, 
       0xc, 0x4b, 0xe, 0x4b, 0x5cd, 0xb, 0x4b, 0x3, 0x4c, 0x3, 0x4c, 0x3, 
       0x4c, 0x3, 0x4c, 0x3, 0x4c, 0x3, 0x4c, 0x3, 0x4c, 0x3, 0x4c, 0x5, 
       0x4c, 0x5d7, 0xa, 0x4c, 0x3, 0x4c, 0x3, 0x4c, 0x5, 0x4c, 0x5db, 0xa, 
       0x4c, 0x3, 0x4c, 0x7, 0x4c, 0x5de, 0xa, 0x4c, 0xc, 0x4c, 0xe, 0x4c, 
       0x5e1, 0xb, 0x4c, 0x3, 0x4d, 0x3, 0x4d, 0x3, 0x4d, 0x3, 0x4d, 0x3, 
       0x4d, 0x3, 0x4d, 0x3, 0x4d, 0x3, 0x4d, 0x3, 0x4d, 0x3, 0x4d, 0x3, 
       0x4d, 0x5, 0x4d, 0x5ee, 0xa, 0x4d, 0x3, 0x4d, 0x3, 0x4d, 0x5, 0x4d, 
       0x5f2, 0xa, 0x4d, 0x3, 0x4d, 0x3, 0x4d, 0x3, 0x4d, 0x3, 0x4d, 0x3, 
       0x4d, 0x3, 0x4d, 0x3, 0x4d, 0x5, 0x4d, 0x5fb, 0xa, 0x4d, 0x3, 0x4d, 
       0x3, 0x4d, 0x5, 0x4d, 0x5ff, 0xa, 0x4d, 0x3, 0x4d, 0x5, 0x4d, 0x602, 
       0xa, 0x4d, 0x3, 0x4e, 0x3, 0x4e, 0x5, 0x4e, 0x606, 0xa, 0x4e, 0x3, 
       0x4e, 0x3, 0x4e, 0x5, 0x4e, 0x60a, 0xa, 0x4e, 0x3, 0x4e, 0x5, 0x4e, 
       0x60d, 0xa, 0x4e, 0x7, 0x4e, 0x60f, 0xa, 0x4e, 0xc, 0x4e, 0xe, 0x4e, 
       0x612, 0xb, 0x4e, 0x3, 0x4e, 0x5, 0x4e, 0x615, 0xa, 0x4e, 0x3, 0x4e, 
       0x5, 0x4e, 0x618, 0xa, 0x4e, 0x3, 0x4e, 0x3, 0x4e, 0x5, 0x4e, 0x61c, 
       0xa, 0x4e, 0x3, 0x4e, 0x5, 0x4e, 0x61f, 0xa, 0x4e, 0x6, 0x4e, 0x621, 
       0xa, 0x4e, 0xd, 0x4e, 0xe, 0x4e, 0x622, 0x5, 0x4e, 0x625, 0xa, 0x4e, 
       0x3, 0x4f, 0x3, 0x4f, 0x5, 0x4f, 0x629, 0xa, 0x4f, 0x3, 0x4f, 0x3, 
       0x4f, 0x5, 0x4f, 0x62d, 0xa, 0x4f, 0x3, 0x4f, 0x3, 0x4f, 0x5, 0x4f, 
       0x631, 0xa, 0x4f, 0x3, 0x4f, 0x3, 0x4f, 0x5, 0x4f, 0x635, 0xa, 0x4f, 
       0x3, 0x4f, 0x5, 0x4f, 0x638, 0xa, 0x4f, 0x3, 0x50, 0x3, 0x50, 0x3, 
       0x50, 0x3, 0x50, 0x5, 0x50, 0x63e, 0xa, 0x50, 0x3, 0x50, 0x3, 0x50, 
       0x5, 0x50, 0x642, 0xa, 0x50, 0x3, 0x50, 0x5, 0x50, 0x645, 0xa, 0x50, 
       0x3, 0x51, 0x3, 0x51, 0x3, 0x51, 0x5, 0x51, 0x64a, 0xa, 0x51, 0x3, 
       0x51, 0x3, 0x51, 0x5, 0x51, 0x64e, 0xa, 0x51, 0x3, 0x51, 0x3, 0x51, 
       0x3, 0x51, 0x3, 0x51, 0x5, 0x51, 0x654, 0xa, 0x51, 0x3, 0x51, 0x5, 
       0x51, 0x657, 0xa, 0x51, 0x3, 0x51, 0x5, 0x51, 0x65a, 0xa, 0x51, 0x3, 
       0x51, 0x3, 0x51, 0x5, 0x51, 0x65e, 0xa, 0x51, 0x3, 0x51, 0x6, 0x51, 
       0x661, 0xa, 0x51, 0xd, 0x51, 0xe, 0x51, 0x662, 0x3, 0x51, 0x3, 0x51, 
       0x6, 0x51, 0x667, 0xa, 0x51, 0xd, 0x51, 0xe, 0x51, 0x668, 0x5, 0x51, 
       0x66b, 0xa, 0x51, 0x3, 0x51, 0x3, 0x51, 0x3, 0x52, 0x3, 0x52, 0x3, 
       0x52, 0x5, 0x52, 0x672, 0xa, 0x52, 0x3, 0x52, 0x3, 0x52, 0x5, 0x52, 
       0x676, 0xa, 0x52, 0x3, 0x52, 0x3, 0x52, 0x3, 0x52, 0x3, 0x52, 0x5, 
       0x52, 0x67c, 0xa, 0x52, 0x3, 0x52, 0x5, 0x52, 0x67f, 0xa, 0x52, 0x3, 
       0x52, 0x6, 0x52, 0x682, 0xa, 0x52, 0xd, 0x52, 0xe, 0x52, 0x683, 0x3, 
       0x52, 0x3, 0x52, 0x6, 0x52, 0x688, 0xa, 0x52, 0xd, 0x52, 0xe, 0x52, 
       0x689, 0x5, 0x52, 0x68c, 0xa, 0x52, 0x3, 0x52, 0x3, 0x52, 0x3, 0x53, 
       0x3, 0x53, 0x3, 0x53, 0x5, 0x53, 0x693, 0xa, 0x53, 0x3, 0x53, 0x3, 
       0x53, 0x5, 0x53, 0x697, 0xa, 0x53, 0x3, 0x53, 0x3, 0x53, 0x3, 0x53, 
       0x3, 0x53, 0x5, 0x53, 0x69d, 0xa, 0x53, 0x3, 0x53, 0x5, 0x53, 0x6a0, 
       0xa, 0x53, 0x3, 0x53, 0x6, 0x53, 0x6a3, 0xa, 0x53, 0xd, 0x53, 0xe, 
       0x53, 0x6a4, 0x3, 0x53, 0x3, 0x53, 0x6, 0x53, 0x6a9, 0xa, 0x53, 0xd, 
       0x53, 0xe, 0x53, 0x6aa, 0x5, 0x53, 0x6ad, 0xa, 0x53, 0x3, 0x53, 0x3, 
       0x53, 0x3, 0x54, 0x3, 0x54, 0x3, 0x54, 0x3, 0x54, 0x5, 0x54, 0x6b5, 
       0xa, 0x54, 0x3, 0x54, 0x3, 0x54, 0x5, 0x54, 0x6b9, 0xa, 0x54, 0x3, 
       0x54, 0x5, 0x54, 0x6bc, 0xa, 0x54, 0x3, 0x54, 0x5, 0x54, 0x6bf, 0xa, 
       0x54, 0x3, 0x54, 0x3, 0x54, 0x5, 0x54, 0x6c3, 0xa, 0x54, 0x3, 0x54, 
       0x3, 0x54, 0x3, 0x55, 0x3, 0x55, 0x3, 0x55, 0x3, 0x55, 0x5, 0x55, 
       0x6cb, 0xa, 0x55, 0x3, 0x55, 0x3, 0x55, 0x5, 0x55, 0x6cf, 0xa, 0x55, 
       0x3, 0x55, 0x3, 0x55, 0x5, 0x55, 0x6d3, 0xa, 0x55, 0x5, 0x55, 0x6d5, 
       0xa, 0x55, 0x3, 0x55, 0x5, 0x55, 0x6d8, 0xa, 0x55, 0x3, 0x56, 0x3, 
       0x56, 0x3, 0x56, 0x5, 0x56, 0x6dd, 0xa, 0x56, 0x3, 0x57, 0x3, 0x57, 
       0x3, 0x57, 0x3, 0x57, 0x5, 0x57, 0x6e3, 0xa, 0x57, 0x3, 0x57, 0x3, 
       0x57, 0x5, 0x57, 0x6e7, 0xa, 0x57, 0x3, 0x57, 0x3, 0x57, 0x5, 0x57, 
       0x6eb, 0xa, 0x57, 0x3, 0x57, 0x7, 0x57, 0x6ee, 0xa, 0x57, 0xc, 0x57, 
       0xe, 0x57, 0x6f1, 0xb, 0x57, 0x3, 0x58, 0x3, 0x58, 0x5, 0x58, 0x6f5, 
       0xa, 0x58, 0x3, 0x58, 0x3, 0x58, 0x5, 0x58, 0x6f9, 0xa, 0x58, 0x3, 
       0x58, 0x3, 0x58, 0x5, 0x58, 0x6fd, 0xa, 0x58, 0x3, 0x58, 0x3, 0x58, 
       0x3, 0x58, 0x5, 0x58, 0x702, 0xa, 0x58, 0x3, 0x59, 0x3, 0x59, 0x3, 
       0x5a, 0x3, 0x5a, 0x3, 0x5a, 0x3, 0x5a, 0x5, 0x5a, 0x70a, 0xa, 0x5a, 
       0x5, 0x5a, 0x70c, 0xa, 0x5a, 0x3, 0x5b, 0x3, 0x5b, 0x3, 0x5c, 0x3, 
       0x5c, 0x3, 0x5c, 0x3, 0x5c, 0x3, 0x5d, 0x3, 0x5d, 0x3, 0x5d, 0x3, 
       0x5d, 0x5, 0x5d, 0x718, 0xa, 0x5d, 0x3, 0x5d, 0x3, 0x5d, 0x5, 0x5d, 
       0x71c, 0xa, 0x5d, 0x3, 0x5d, 0x3, 0x5d, 0x3, 0x5e, 0x3, 0x5e, 0x3, 
       0x5e, 0x3, 0x5e, 0x5, 0x5e, 0x724, 0xa, 0x5e, 0x3, 0x5e, 0x3, 0x5e, 
       0x5, 0x5e, 0x728, 0xa, 0x5e, 0x3, 0x5e, 0x3, 0x5e, 0x3, 0x5f, 0x3, 
       0x5f, 0x3, 0x5f, 0x3, 0x5f, 0x5, 0x5f, 0x730, 0xa, 0x5f, 0x3, 0x5f, 
       0x3, 0x5f, 0x5, 0x5f, 0x734, 0xa, 0x5f, 0x3, 0x5f, 0x3, 0x5f, 0x5, 
       0x5f, 0x738, 0xa, 0x5f, 0x3, 0x5f, 0x3, 0x5f, 0x5, 0x5f, 0x73c, 0xa, 
       0x5f, 0x3, 0x5f, 0x3, 0x5f, 0x5, 0x5f, 0x740, 0xa, 0x5f, 0x3, 0x5f, 
       0x3, 0x5f, 0x5, 0x5f, 0x744, 0xa, 0x5f, 0x3, 0x5f, 0x3, 0x5f, 0x3, 
       0x60, 0x3, 0x60, 0x3, 0x60, 0x3, 0x60, 0x5, 0x60, 0x74c, 0xa, 0x60, 
       0x3, 0x60, 0x3, 0x60, 0x5, 0x60, 0x750, 0xa, 0x60, 0x3, 0x60, 0x3, 
       0x60, 0x3, 0x61, 0x3, 0x61, 0x3, 0x61, 0x3, 0x61, 0x3, 0x61, 0x3, 
       0x61, 0x6, 0x61, 0x75a, 0xa, 0x61, 0xd, 0x61, 0xe, 0x61, 0x75b, 0x3, 
       0x61, 0x7, 0x61, 0x75f, 0xa, 0x61, 0xc, 0x61, 0xe, 0x61, 0x762, 0xb, 
       0x61, 0x3, 0x61, 0x5, 0x61, 0x765, 0xa, 0x61, 0x3, 0x61, 0x3, 0x61, 
       0x3, 0x62, 0x3, 0x62, 0x3, 0x62, 0x3, 0x62, 0x5, 0x62, 0x76d, 0xa, 
       0x62, 0x3, 0x62, 0x5, 0x62, 0x770, 0xa, 0x62, 0x3, 0x62, 0x7, 0x62, 
       0x773, 0xa, 0x62, 0xc, 0x62, 0xe, 0x62, 0x776, 0xb, 0x62, 0x3, 0x62, 
       0x6, 0x62, 0x779, 0xa, 0x62, 0xd, 0x62, 0xe, 0x62, 0x77a, 0x5, 0x62, 
       0x77d, 0xa, 0x62, 0x3, 0x62, 0x3, 0x62, 0x6, 0x62, 0x781, 0xa, 0x62, 
       0xd, 0x62, 0xe, 0x62, 0x782, 0x5, 0x62, 0x785, 0xa, 0x62, 0x3, 0x63, 
       0x3, 0x63, 0x3, 0x63, 0x5, 0x63, 0x78a, 0xa, 0x63, 0x3, 0x63, 0x3, 
       0x63, 0x5, 0x63, 0x78e, 0xa, 0x63, 0x3, 0x63, 0x7, 0x63, 0x791, 0xa, 
       0x63, 0xc, 0x63, 0xe, 0x63, 0x794, 0xb, 0x63, 0x5, 0x63, 0x796, 0xa, 
       0x63, 0x3, 0x64, 0x3, 0x64, 0x5, 0x64, 0x79a, 0xa, 0x64, 0x3, 0x64, 
       0x3, 0x64, 0x5, 0x64, 0x79e, 0xa, 0x64, 0x3, 0x64, 0x3, 0x64, 0x3, 
       0x64, 0x3, 0x64, 0x3, 0x64, 0x3, 0x64, 0x3, 0x64, 0x3, 0x64, 0x3, 
       0x64, 0x5, 0x64, 0x7a9, 0xa, 0x64, 0x3, 0x65, 0x3, 0x65, 0x3, 0x65, 
       0x3, 0x65, 0x5, 0x65, 0x7af, 0xa, 0x65, 0x3, 0x65, 0x3, 0x65, 0x5, 
       0x65, 0x7b3, 0xa, 0x65, 0x3, 0x65, 0x5, 0x65, 0x7b6, 0xa, 0x65, 0x3, 
       0x66, 0x3, 0x66, 0x3, 0x66, 0x3, 0x66, 0x5, 0x66, 0x7bc, 0xa, 0x66, 
       0x3, 0x66, 0x3, 0x66, 0x5, 0x66, 0x7c0, 0xa, 0x66, 0x3, 0x66, 0x3, 
       0x66, 0x3, 0x67, 0x3, 0x67, 0x3, 0x67, 0x3, 0x67, 0x5, 0x67, 0x7c8, 
       0xa, 0x67, 0x3, 0x67, 0x3, 0x67, 0x5, 0x67, 0x7cc, 0xa, 0x67, 0x3, 
       0x67, 0x3, 0x67, 0x3, 0x68, 0x3, 0x68, 0x3, 0x69, 0x3, 0x69, 0x3, 
       0x69, 0x5, 0x69, 0x7d5, 0xa, 0x69, 0x3, 0x69, 0x3, 0x69, 0x5, 0x69, 
       0x7d9, 0xa, 0x69, 0x3, 0x69, 0x3, 0x69, 0x3, 0x69, 0x3, 0x69, 0x5, 
       0x69, 0x7df, 0xa, 0x69, 0x3, 0x69, 0x5, 0x69, 0x7e2, 0xa, 0x69, 0x3, 
       0x69, 0x6, 0x69, 0x7e5, 0xa, 0x69, 0xd, 0x69, 0xe, 0x69, 0x7e6, 0x3, 
       0x69, 0x3, 0x69, 0x6, 0x69, 0x7eb, 0xa, 0x69, 0xd, 0x69, 0xe, 0x69, 
       0x7ec, 0x5, 0x69, 0x7ef, 0xa, 0x69, 0x3, 0x69, 0x3, 0x69, 0x3, 0x6a, 
       0x3, 0x6a, 0x5, 0x6a, 0x7f5, 0xa, 0x6a, 0x3, 0x6a, 0x3, 0x6a, 0x5, 
       0x6a, 0x7f9, 0xa, 0x6a, 0x3, 0x6a, 0x3, 0x6a, 0x3, 0x6b, 0x3, 0x6b, 
       0x3, 0x6b, 0x5, 0x6b, 0x800, 0xa, 0x6b, 0x3, 0x6b, 0x3, 0x6b, 0x3, 
       0x6b, 0x3, 0x6b, 0x6, 0x6b, 0x806, 0xa, 0x6b, 0xd, 0x6b, 0xe, 0x6b, 
       0x807, 0x3, 0x6b, 0x7, 0x6b, 0x80b, 0xa, 0x6b, 0xc, 0x6b, 0xe, 0x6b, 
       0x80e, 0xb, 0x6b, 0x3, 0x6b, 0x3, 0x6b, 0x3, 0x6c, 0x3, 0x6c, 0x5, 
       0x6c, 0x814, 0xa, 0x6c, 0x3, 0x6c, 0x3, 0x6c, 0x5, 0x6c, 0x818, 0xa, 
       0x6c, 0x3, 0x6c, 0x5, 0x6c, 0x81b, 0xa, 0x6c, 0x3, 0x6c, 0x5, 0x6c, 
       0x81e, 0xa, 0x6c, 0x3, 0x6c, 0x5, 0x6c, 0x821, 0xa, 0x6c, 0x3, 0x6c, 
       0x3, 0x6c, 0x5, 0x6c, 0x825, 0xa, 0x6c, 0x3, 0x6c, 0x6, 0x6c, 0x828, 
       0xa, 0x6c, 0xd, 0x6c, 0xe, 0x6c, 0x829, 0x3, 0x6d, 0x3, 0x6d, 0x3, 
       0x6d, 0x3, 0x6d, 0x3, 0x6d, 0x3, 0x6d, 0x3, 0x6d, 0x5, 0x6d, 0x833, 
       0xa, 0x6d, 0x3, 0x6e, 0x3, 0x6e, 0x3, 0x6e, 0x3, 0x6e, 0x3, 0x6f, 
       0x3, 0x6f, 0x3, 0x6f, 0x3, 0x6f, 0x5, 0x6f, 0x83d, 0xa, 0x6f, 0x3, 
       0x6f, 0x3, 0x6f, 0x5, 0x6f, 0x841, 0xa, 0x6f, 0x3, 0x6f, 0x3, 0x6f, 
       0x3, 0x6f, 0x3, 0x6f, 0x3, 0x6f, 0x5, 0x6f, 0x848, 0xa, 0x6f, 0x5, 
       0x6f, 0x84a, 0xa, 0x6f, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 
       0x5, 0x70, 0x850, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x854, 
       0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x858, 0xa, 0x70, 0x3, 
       0x70, 0x7, 0x70, 0x85b, 0xa, 0x70, 0xc, 0x70, 0xe, 0x70, 0x85e, 0xb, 
       0x70, 0x3, 0x70, 0x5, 0x70, 0x861, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 
       0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 
       0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x86e, 0xa, 0x70, 0x3, 
       0x70, 0x3, 0x70, 0x5, 0x70, 0x872, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 
       0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x878, 0xa, 0x70, 0x3, 0x70, 0x3, 
       0x70, 0x3, 0x70, 0x5, 0x70, 0x87d, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 
       0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x885, 0xa, 
       0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x889, 0xa, 0x70, 0x3, 0x70, 
       0x3, 0x70, 0x5, 0x70, 0x88d, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 
       0x70, 0x891, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x895, 0xa, 
       0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x899, 0xa, 0x70, 0x3, 0x70, 
       0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x89e, 0xa, 0x70, 0x3, 0x70, 0x3, 
       0x70, 0x5, 0x70, 0x8a2, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 
       0x5, 0x70, 0x8a7, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x8ab, 
       0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x8b0, 0xa, 
       0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x8b4, 0xa, 0x70, 0x3, 0x70, 
       0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x8b9, 0xa, 0x70, 0x3, 0x70, 0x3, 
       0x70, 0x5, 0x70, 0x8bd, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 
       0x5, 0x70, 0x8c2, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x8c6, 
       0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x8cb, 0xa, 
       0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x8cf, 0xa, 0x70, 0x3, 0x70, 
       0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x8d4, 0xa, 0x70, 0x3, 0x70, 0x3, 
       0x70, 0x5, 0x70, 0x8d8, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 
       0x5, 0x70, 0x8dd, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x8e1, 
       0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x8e6, 0xa, 
       0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x8ea, 0xa, 0x70, 0x3, 0x70, 
       0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x8ef, 0xa, 0x70, 0x3, 0x70, 0x3, 
       0x70, 0x5, 0x70, 0x8f3, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 
       0x5, 0x70, 0x8f8, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x8fc, 
       0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x901, 0xa, 
       0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x905, 0xa, 0x70, 0x3, 0x70, 
       0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 
       0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 
       0x5, 0x70, 0x914, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x918, 
       0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x91d, 0xa, 
       0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x921, 0xa, 0x70, 0x3, 0x70, 
       0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x926, 0xa, 0x70, 0x3, 0x70, 0x3, 
       0x70, 0x5, 0x70, 0x92a, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 
       0x5, 0x70, 0x92f, 0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x933, 
       0xa, 0x70, 0x3, 0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x938, 0xa, 
       0x70, 0x3, 0x70, 0x3, 0x70, 0x5, 0x70, 0x93c, 0xa, 0x70, 0x3, 0x70, 
       0x7, 0x70, 0x93f, 0xa, 0x70, 0xc, 0x70, 0xe, 0x70, 0x942, 0xb, 0x70, 
       0x3, 0x71, 0x3, 0x71, 0x3, 0x71, 0x5, 0x71, 0x947, 0xa, 0x71, 0x3, 
       0x71, 0x3, 0x71, 0x3, 0x71, 0x5, 0x71, 0x94c, 0xa, 0x71, 0x3, 0x71, 
       0x3, 0x71, 0x3, 0x72, 0x3, 0x72, 0x5, 0x72, 0x952, 0xa, 0x72, 0x3, 
       0x72, 0x3, 0x72, 0x5, 0x72, 0x956, 0xa, 0x72, 0x3, 0x72, 0x7, 0x72, 
       0x959, 0xa, 0x72, 0xc, 0x72, 0xe, 0x72, 0x95c, 0xb, 0x72, 0x3, 0x73, 
       0x3, 0x73, 0x5, 0x73, 0x960, 0xa, 0x73, 0x3, 0x73, 0x5, 0x73, 0x963, 
       0xa, 0x73, 0x3, 0x73, 0x3, 0x73, 0x5, 0x73, 0x967, 0xa, 0x73, 0x3, 
       0x73, 0x3, 0x73, 0x5, 0x73, 0x96b, 0xa, 0x73, 0x5, 0x73, 0x96d, 0xa, 
       0x73, 0x3, 0x73, 0x3, 0x73, 0x5, 0x73, 0x971, 0xa, 0x73, 0x5, 0x73, 
       0x973, 0xa, 0x73, 0x3, 0x73, 0x3, 0x73, 0x5, 0x73, 0x977, 0xa, 0x73, 
       0x3, 0x74, 0x3, 0x74, 0x3, 0x74, 0x3, 0x74, 0x6, 0x74, 0x97d, 0xa, 
       0x74, 0xd, 0x74, 0xe, 0x74, 0x97e, 0x3, 0x74, 0x7, 0x74, 0x982, 0xa, 
       0x74, 0xc, 0x74, 0xe, 0x74, 0x985, 0xb, 0x74, 0x3, 0x74, 0x7, 0x74, 
       0x988, 0xa, 0x74, 0xc, 0x74, 0xe, 0x74, 0x98b, 0xb, 0x74, 0x3, 0x74, 
       0x3, 0x74, 0x3, 0x75, 0x3, 0x75, 0x3, 0x75, 0x3, 0x75, 0x5, 0x75, 
       0x993, 0xa, 0x75, 0x3, 0x75, 0x3, 0x75, 0x5, 0x75, 0x997, 0xa, 0x75, 
       0x3, 0x75, 0x3, 0x75, 0x3, 0x76, 0x3, 0x76, 0x3, 0x76, 0x3, 0x76, 
       0x5, 0x76, 0x99f, 0xa, 0x76, 0x3, 0x76, 0x3, 0x76, 0x6, 0x76, 0x9a3, 
       0xa, 0x76, 0xd, 0x76, 0xe, 0x76, 0x9a4, 0x3, 0x76, 0x3, 0x76, 0x6, 
       0x76, 0x9a9, 0xa, 0x76, 0xd, 0x76, 0xe, 0x76, 0x9aa, 0x5, 0x76, 0x9ad, 
       0xa, 0x76, 0x3, 0x76, 0x3, 0x76, 0x3, 0x77, 0x3, 0x77, 0x3, 0x77, 
       0x3, 0x77, 0x5, 0x77, 0x9b5, 0xa, 0x77, 0x3, 0x77, 0x3, 0x77, 0x5, 
       0x77, 0x9b9, 0xa, 0x77, 0x3, 0x77, 0x5, 0x77, 0x9bc, 0xa, 0x77, 0x3, 
       0x78, 0x3, 0x78, 0x5, 0x78, 0x9c0, 0xa, 0x78, 0x3, 0x79, 0x3, 0x79, 
       0x3, 0x79, 0x3, 0x79, 0x5, 0x79, 0x9c6, 0xa, 0x79, 0x3, 0x79, 0x5, 
       0x79, 0x9c9, 0xa, 0x79, 0x3, 0x79, 0x3, 0x79, 0x5, 0x79, 0x9cd, 0xa, 
       0x79, 0x3, 0x79, 0x3, 0x79, 0x5, 0x79, 0x9d1, 0xa, 0x79, 0x3, 0x79, 
       0x3, 0x79, 0x5, 0x79, 0x9d5, 0xa, 0x79, 0x3, 0x7a, 0x3, 0x7a, 0x3, 
       0x7a, 0x5, 0x7a, 0x9da, 0xa, 0x7a, 0x3, 0x7a, 0x3, 0x7a, 0x5, 0x7a, 
       0x9de, 0xa, 0x7a, 0x3, 0x7a, 0x3, 0x7a, 0x5, 0x7a, 0x9e2, 0xa, 0x7a, 
       0x3, 0x7a, 0x5, 0x7a, 0x9e5, 0xa, 0x7a, 0x3, 0x7a, 0x3, 0x7a, 0x5, 
       0x7a, 0x9e9, 0xa, 0x7a, 0x3, 0x7a, 0x3, 0x7a, 0x5, 0x7a, 0x9ed, 0xa, 
       0x7a, 0x3, 0x7a, 0x3, 0x7a, 0x5, 0x7a, 0x9f1, 0xa, 0x7a, 0x3, 0x7b, 
       0x3, 0x7b, 0x5, 0x7b, 0x9f5, 0xa, 0x7b, 0x3, 0x7c, 0x3, 0x7c, 0x3, 
       0x7c, 0x5, 0x7c, 0x9fa, 0xa, 0x7c, 0x3, 0x7d, 0x5, 0x7d, 0x9fd, 0xa, 
       0x7d, 0x3, 0x7d, 0x3, 0x7d, 0x3, 0x7d, 0x5, 0x7d, 0xa02, 0xa, 0x7d, 
       0x3, 0x7d, 0x3, 0x7d, 0x5, 0x7d, 0xa06, 0xa, 0x7d, 0x3, 0x7d, 0x5, 
       0x7d, 0xa09, 0xa, 0x7d, 0x3, 0x7e, 0x3, 0x7e, 0x3, 0x7e, 0x3, 0x7e, 
       0x5, 0x7e, 0xa0f, 0xa, 0x7e, 0x3, 0x7f, 0x3, 0x7f, 0x5, 0x7f, 0xa13, 
       0xa, 0x7f, 0x3, 0x7f, 0x5, 0x7f, 0xa16, 0xa, 0x7f, 0x3, 0x80, 0x3, 
       0x80, 0x3, 0x80, 0x5, 0x80, 0xa1b, 0xa, 0x80, 0x3, 0x80, 0x5, 0x80, 
       0xa1e, 0xa, 0x80, 0x3, 0x80, 0x5, 0x80, 0xa21, 0xa, 0x80, 0x3, 0x80, 
       0x3, 0x80, 0x5, 0x80, 0xa25, 0xa, 0x80, 0x3, 0x80, 0x3, 0x80, 0x5, 
       0x80, 0xa29, 0xa, 0x80, 0x5, 0x80, 0xa2b, 0xa, 0x80, 0x3, 0x80, 0x6, 
       0x80, 0xa2e, 0xa, 0x80, 0xd, 0x80, 0xe, 0x80, 0xa2f, 0x3, 0x80, 0x5, 
       0x80, 0xa33, 0xa, 0x80, 0x3, 0x81, 0x3, 0x81, 0x5, 0x81, 0xa37, 0xa, 
       0x81, 0x3, 0x81, 0x5, 0x81, 0xa3a, 0xa, 0x81, 0x3, 0x81, 0x3, 0x81, 
       0x5, 0x81, 0xa3e, 0xa, 0x81, 0x3, 0x81, 0x3, 0x81, 0x5, 0x81, 0xa42, 
       0xa, 0x81, 0x5, 0x81, 0xa44, 0xa, 0x81, 0x3, 0x81, 0x3, 0x81, 0x3, 
       0x82, 0x3, 0x82, 0x5, 0x82, 0xa4a, 0xa, 0x82, 0x3, 0x82, 0x6, 0x82, 
       0xa4d, 0xa, 0x82, 0xd, 0x82, 0xe, 0x82, 0xa4e, 0x3, 0x82, 0x5, 0x82, 
       0xa52, 0xa, 0x82, 0x3, 0x83, 0x5, 0x83, 0xa55, 0xa, 0x83, 0x3, 0x83, 
       0x3, 0x83, 0x3, 0x83, 0x5, 0x83, 0xa5a, 0xa, 0x83, 0x3, 0x84, 0x3, 
       0x84, 0x3, 0x85, 0x5, 0x85, 0xa5f, 0xa, 0x85, 0x3, 0x85, 0x5, 0x85, 
       0xa62, 0xa, 0x85, 0x3, 0x85, 0x3, 0x85, 0x5, 0x85, 0xa66, 0xa, 0x85, 
       0x7, 0x85, 0xa68, 0xa, 0x85, 0xc, 0x85, 0xe, 0x85, 0xa6b, 0xb, 0x85, 
       0x3, 0x85, 0x3, 0x85, 0x5, 0x85, 0xa6f, 0xa, 0x85, 0x3, 0x85, 0x3, 
       0x85, 0x5, 0x85, 0xa73, 0xa, 0x85, 0x3, 0x85, 0x5, 0x85, 0xa76, 0xa, 
       0x85, 0x7, 0x85, 0xa78, 0xa, 0x85, 0xc, 0x85, 0xe, 0x85, 0xa7b, 0xb, 
       0x85, 0x3, 0x86, 0x3, 0x86, 0x5, 0x86, 0xa7f, 0xa, 0x86, 0x3, 0x86, 
       0x3, 0x86, 0x3, 0x87, 0x3, 0x87, 0x3, 0x87, 0x5, 0x87, 0xa86, 0xa, 
       0x87, 0x3, 0x88, 0x3, 0x88, 0x5, 0x88, 0xa8a, 0xa, 0x88, 0x3, 0x88, 
       0x3, 0x88, 0x5, 0x88, 0xa8e, 0xa, 0x88, 0x3, 0x88, 0x3, 0x88, 0x5, 
       0x88, 0xa92, 0xa, 0x88, 0x3, 0x88, 0x7, 0x88, 0xa95, 0xa, 0x88, 0xc, 
       0x88, 0xe, 0x88, 0xa98, 0xb, 0x88, 0x5, 0x88, 0xa9a, 0xa, 0x88, 0x3, 
       0x88, 0x5, 0x88, 0xa9d, 0xa, 0x88, 0x3, 0x88, 0x3, 0x88, 0x3, 0x89, 
       0x3, 0x89, 0x5, 0x89, 0xaa3, 0xa, 0x89, 0x3, 0x89, 0x3, 0x89, 0x5, 
       0x89, 0xaa7, 0xa, 0x89, 0x3, 0x89, 0x3, 0x89, 0x5, 0x89, 0xaab, 0xa, 
       0x89, 0x3, 0x89, 0x3, 0x89, 0x5, 0x89, 0xaaf, 0xa, 0x89, 0x3, 0x89, 
       0x5, 0x89, 0xab2, 0xa, 0x89, 0x3, 0x89, 0x3, 0x89, 0x5, 0x89, 0xab6, 
       0xa, 0x89, 0x3, 0x89, 0x5, 0x89, 0xab9, 0xa, 0x89, 0x3, 0x89, 0x3, 
       0x89, 0x5, 0x89, 0xabd, 0xa, 0x89, 0x3, 0x89, 0x5, 0x89, 0xac0, 0xa, 
       0x89, 0x3, 0x89, 0x5, 0x89, 0xac3, 0xa, 0x89, 0x3, 0x8a, 0x3, 0x8a, 
       0x5, 0x8a, 0xac7, 0xa, 0x8a, 0x3, 0x8a, 0x3, 0x8a, 0x3, 0x8b, 0x3, 
       0x8b, 0x5, 0x8b, 0xacd, 0xa, 0x8b, 0x3, 0x8b, 0x3, 0x8b, 0x5, 0x8b, 
       0xad1, 0xa, 0x8b, 0x3, 0x8b, 0x7, 0x8b, 0xad4, 0xa, 0x8b, 0xc, 0x8b, 
       0xe, 0x8b, 0xad7, 0xb, 0x8b, 0x3, 0x8c, 0x3, 0x8c, 0x3, 0x8c, 0x3, 
       0x8c, 0x3, 0x8c, 0x5, 0x8c, 0xade, 0xa, 0x8c, 0x3, 0x8c, 0x3, 0x8c, 
       0x3, 0x8d, 0x3, 0x8d, 0x6, 0x8d, 0xae4, 0xa, 0x8d, 0xd, 0x8d, 0xe, 
       0x8d, 0xae5, 0x3, 0x8d, 0x3, 0x8d, 0x3, 0x8d, 0x6, 0x8d, 0xaeb, 0xa, 
       0x8d, 0xd, 0x8d, 0xe, 0x8d, 0xaec, 0x3, 0x8d, 0x5, 0x8d, 0xaf0, 0xa, 
       0x8d, 0x3, 0x8e, 0x3, 0x8e, 0x3, 0x8e, 0x3, 0x8e, 0x5, 0x8e, 0xaf6, 
       0xa, 0x8e, 0x3, 0x8e, 0x3, 0x8e, 0x3, 0x8e, 0x5, 0x8e, 0xafb, 0xa, 
       0x8e, 0x3, 0x8f, 0x3, 0x8f, 0x3, 0x90, 0x3, 0x90, 0x3, 0x90, 0x7, 
       0x90, 0xb02, 0xa, 0x90, 0xc, 0x90, 0xe, 0x90, 0xb05, 0xb, 0x90, 0x3, 
       0x90, 0x3, 0x90, 0x3, 0x90, 0x6, 0x90, 0xb0a, 0xa, 0x90, 0xd, 0x90, 
       0xe, 0x90, 0xb0b, 0x5, 0x90, 0xb0e, 0xa, 0x90, 0x3, 0x91, 0x3, 0x91, 
       0x3, 0x92, 0x3, 0x92, 0x3, 0x92, 0x7, 0x92, 0xb15, 0xa, 0x92, 0xc, 
       0x92, 0xe, 0x92, 0xb18, 0xb, 0x92, 0x3, 0x93, 0x3, 0x93, 0x5, 0x93, 
       0xb1c, 0xa, 0x93, 0x3, 0x93, 0x3, 0x93, 0x5, 0x93, 0xb20, 0xa, 0x93, 
       0x3, 0x94, 0x3, 0x94, 0x5, 0x94, 0xb24, 0xa, 0x94, 0x3, 0x94, 0x3, 
       0x94, 0x5, 0x94, 0xb28, 0xa, 0x94, 0x3, 0x94, 0x5, 0x94, 0xb2b, 0xa, 
       0x94, 0x3, 0x95, 0x3, 0x95, 0x3, 0x95, 0x3, 0x96, 0x3, 0x96, 0x3, 
       0x97, 0x3, 0x97, 0x3, 0x98, 0x3, 0x98, 0x3, 0x99, 0x3, 0x99, 0x5, 
       0x99, 0xb38, 0xa, 0x99, 0x3, 0x99, 0x5, 0x99, 0xb3b, 0xa, 0x99, 0x3, 
       0x99, 0x3, 0x99, 0x5, 0x99, 0xb3f, 0xa, 0x99, 0x3, 0x99, 0x5, 0x99, 
       0xb42, 0xa, 0x99, 0x3, 0x9a, 0x3, 0x9a, 0x3, 0x9b, 0x3, 0x9b, 0x3, 
       0x9c, 0x3, 0x9c, 0x3, 0x9c, 0x2, 0x3, 0xde, 0x9d, 0x2, 0x4, 0x6, 
       0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 
       0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 
       0x36, 0x38, 0x3a, 0x3c, 0x3e, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 
       0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e, 0x60, 
       0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 
       0x78, 0x7a, 0x7c, 0x7e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 
       0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e, 0xa0, 0xa2, 
       0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 
       0xba, 0xbc, 0xbe, 0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 
       0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde, 0xe0, 0xe2, 0xe4, 
       0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 
       0xfc, 0xfe, 0x100, 0x102, 0x104, 0x106, 0x108, 0x10a, 0x10c, 0x10e, 
       0x110, 0x112, 0x114, 0x116, 0x118, 0x11a, 0x11c, 0x11e, 0x120, 0x122, 
       0x124, 0x126, 0x128, 0x12a, 0x12c, 0x12e, 0x130, 0x132, 0x134, 0x136, 
       0x2, 0x17, 0x4, 0x2, 0xe, 0xe, 0xa1, 0xa1, 0x3, 0x2, 0x1d, 0x28, 
       0x4, 0x2, 0xaa, 0xaa, 0xae, 0xae, 0x3, 0x2, 0x3f, 0x43, 0x5, 0x2, 
       0xbc, 0xbc, 0xc6, 0xc6, 0xcb, 0xcb, 0x3, 0x2, 0x72, 0x73, 0x7, 0x2, 
       0x9, 0x9, 0xe, 0xe, 0x51, 0x51, 0x7b, 0x7b, 0x85, 0x85, 0x4, 0x2, 
       0x88, 0x89, 0xb2, 0xb2, 0x4, 0x2, 0x5e, 0x60, 0x98, 0x98, 0x4, 0x2, 
       0xb8, 0xb8, 0xcf, 0xcf, 0x4, 0x2, 0x9a, 0x9a, 0xa0, 0xa0, 0x4, 0x2, 
       0x10, 0x11, 0x7c, 0x7c, 0x3, 0x2, 0x10, 0x11, 0xd, 0x2, 0xf, 0xf, 
       0x12, 0x12, 0x19, 0x19, 0x1b, 0x1b, 0x2c, 0x2c, 0x53, 0x53, 0x57, 
       0x57, 0x70, 0x70, 0x99, 0x99, 0x9e, 0x9e, 0xab, 0xab, 0x9, 0x2, 0x52, 
       0x52, 0x5c, 0x5c, 0xbc, 0xbc, 0xbe, 0xbf, 0xc1, 0xc1, 0xc4, 0xc4, 
       0xc8, 0xc8, 0x6, 0x2, 0x44, 0x44, 0x6e, 0x6f, 0xa5, 0xa5, 0xd2, 0xd8, 
       0x4, 0x2, 0x7f, 0x7f, 0x83, 0x83, 0x5, 0x2, 0x4a, 0x4a, 0x7f, 0x7f, 
       0x83, 0x83, 0x8, 0x2, 0xb4, 0xb4, 0xb6, 0xb6, 0xba, 0xba, 0xbd, 0xbd, 
       0xc0, 0xc0, 0xc9, 0xc9, 0x6, 0x2, 0x46, 0x46, 0x4a, 0x4a, 0x7f, 0x7f, 
       0x83, 0x83, 0xd, 0x2, 0x3, 0xc, 0xe, 0x2f, 0x38, 0x38, 0x3a, 0x3e, 
       0x44, 0x5c, 0x61, 0x61, 0x66, 0x71, 0x74, 0x75, 0x7a, 0x7f, 0x83, 
       0x88, 0x8a, 0xb3, 0x2, 0xd13, 0x2, 0x138, 0x3, 0x2, 0x2, 0x2, 0x4, 
       0x13c, 0x3, 0x2, 0x2, 0x2, 0x6, 0x186, 0x3, 0x2, 0x2, 0x2, 0x8, 0x18a, 
       0x3, 0x2, 0x2, 0x2, 0xa, 0x1a0, 0x3, 0x2, 0x2, 0x2, 0xc, 0x1a2, 0x3, 
       0x2, 0x2, 0x2, 0xe, 0x1a4, 0x3, 0x2, 0x2, 0x2, 0x10, 0x1ab, 0x3, 
       0x2, 0x2, 0x2, 0x12, 0x1bc, 0x3, 0x2, 0x2, 0x2, 0x14, 0x1cd, 0x3, 
       0x2, 0x2, 0x2, 0x16, 0x1d7, 0x3, 0x2, 0x2, 0x2, 0x18, 0x1e3, 0x3, 
       0x2, 0x2, 0x2, 0x1a, 0x1e5, 0x3, 0x2, 0x2, 0x2, 0x1c, 0x1fd, 0x3, 
       0x2, 0x2, 0x2, 0x1e, 0x200, 0x3, 0x2, 0x2, 0x2, 0x20, 0x21e, 0x3, 
       0x2, 0x2, 0x2, 0x22, 0x221, 0x3, 0x2, 0x2, 0x2, 0x24, 0x239, 0x3, 
       0x2, 0x2, 0x2, 0x26, 0x250, 0x3, 0x2, 0x2, 0x2, 0x28, 0x25c, 0x3, 
       0x2, 0x2, 0x2, 0x2a, 0x27c, 0x3, 0x2, 0x2, 0x2, 0x2c, 0x27e, 0x3, 
       0x2, 0x2, 0x2, 0x2e, 0x280, 0x3, 0x2, 0x2, 0x2, 0x30, 0x282, 0x3, 
       0x2, 0x2, 0x2, 0x32, 0x29a, 0x3, 0x2, 0x2, 0x2, 0x34, 0x2ec, 0x3, 
       0x2, 0x2, 0x2, 0x36, 0x2ee, 0x3, 0x2, 0x2, 0x2, 0x38, 0x2fb, 0x3, 
       0x2, 0x2, 0x2, 0x3a, 0x2fd, 0x3, 0x2, 0x2, 0x2, 0x3c, 0x301, 0x3, 
       0x2, 0x2, 0x2, 0x3e, 0x305, 0x3, 0x2, 0x2, 0x2, 0x40, 0x31a, 0x3, 
       0x2, 0x2, 0x2, 0x42, 0x32c, 0x3, 0x2, 0x2, 0x2, 0x44, 0x33d, 0x3, 
       0x2, 0x2, 0x2, 0x46, 0x34a, 0x3, 0x2, 0x2, 0x2, 0x48, 0x36e, 0x3, 
       0x2, 0x2, 0x2, 0x4a, 0x37e, 0x3, 0x2, 0x2, 0x2, 0x4c, 0x3c8, 0x3, 
       0x2, 0x2, 0x2, 0x4e, 0x3ca, 0x3, 0x2, 0x2, 0x2, 0x50, 0x3cf, 0x3, 
       0x2, 0x2, 0x2, 0x52, 0x3e1, 0x3, 0x2, 0x2, 0x2, 0x54, 0x3f1, 0x3, 
       0x2, 0x2, 0x2, 0x56, 0x401, 0x3, 0x2, 0x2, 0x2, 0x58, 0x408, 0x3, 
       0x2, 0x2, 0x2, 0x5a, 0x412, 0x3, 0x2, 0x2, 0x2, 0x5c, 0x414, 0x3, 
       0x2, 0x2, 0x2, 0x5e, 0x420, 0x3, 0x2, 0x2, 0x2, 0x60, 0x43e, 0x3, 
       0x2, 0x2, 0x2, 0x62, 0x472, 0x3, 0x2, 0x2, 0x2, 0x64, 0x494, 0x3, 
       0x2, 0x2, 0x2, 0x66, 0x4aa, 0x3, 0x2, 0x2, 0x2, 0x68, 0x4ae, 0x3, 
       0x2, 0x2, 0x2, 0x6a, 0x4cb, 0x3, 0x2, 0x2, 0x2, 0x6c, 0x4cd, 0x3, 
       0x2, 0x2, 0x2, 0x6e, 0x4df, 0x3, 0x2, 0x2, 0x2, 0x70, 0x4e1, 0x3, 
       0x2, 0x2, 0x2, 0x72, 0x4f3, 0x3, 0x2, 0x2, 0x2, 0x74, 0x501, 0x3, 
       0x2, 0x2, 0x2, 0x76, 0x505, 0x3, 0x2, 0x2, 0x2, 0x78, 0x514, 0x3, 
       0x2, 0x2, 0x2, 0x7a, 0x51a, 0x3, 0x2, 0x2, 0x2, 0x7c, 0x526, 0x3, 
       0x2, 0x2, 0x2, 0x7e, 0x532, 0x3, 0x2, 0x2, 0x2, 0x80, 0x536, 0x3, 
       0x2, 0x2, 0x2, 0x82, 0x549, 0x3, 0x2, 0x2, 0x2, 0x84, 0x555, 0x3, 
       0x2, 0x2, 0x2, 0x86, 0x561, 0x3, 0x2, 0x2, 0x2, 0x88, 0x573, 0x3, 
       0x2, 0x2, 0x2, 0x8a, 0x585, 0x3, 0x2, 0x2, 0x2, 0x8c, 0x593, 0x3, 
       0x2, 0x2, 0x2, 0x8e, 0x5a1, 0x3, 0x2, 0x2, 0x2, 0x90, 0x5a5, 0x3, 
       0x2, 0x2, 0x2, 0x92, 0x5ad, 0x3, 0x2, 0x2, 0x2, 0x94, 0x5ba, 0x3, 
       0x2, 0x2, 0x2, 0x96, 0x5ce, 0x3, 0x2, 0x2, 0x2, 0x98, 0x5e2, 0x3, 
       0x2, 0x2, 0x2, 0x9a, 0x624, 0x3, 0x2, 0x2, 0x2, 0x9c, 0x637, 0x3, 
       0x2, 0x2, 0x2, 0x9e, 0x639, 0x3, 0x2, 0x2, 0x2, 0xa0, 0x649, 0x3, 
       0x2, 0x2, 0x2, 0xa2, 0x671, 0x3, 0x2, 0x2, 0x2, 0xa4, 0x692, 0x3, 
       0x2, 0x2, 0x2, 0xa6, 0x6b0, 0x3, 0x2, 0x2, 0x2, 0xa8, 0x6c6, 0x3, 
       0x2, 0x2, 0x2, 0xaa, 0x6d9, 0x3, 0x2, 0x2, 0x2, 0xac, 0x6de, 0x3, 
       0x2, 0x2, 0x2, 0xae, 0x6f2, 0x3, 0x2, 0x2, 0x2, 0xb0, 0x703, 0x3, 
       0x2, 0x2, 0x2, 0xb2, 0x705, 0x3, 0x2, 0x2, 0x2, 0xb4, 0x70d, 0x3, 
       0x2, 0x2, 0x2, 0xb6, 0x70f, 0x3, 0x2, 0x2, 0x2, 0xb8, 0x713, 0x3, 
       0x2, 0x2, 0x2, 0xba, 0x71f, 0x3, 0x2, 0x2, 0x2, 0xbc, 0x72b, 0x3, 
       0x2, 0x2, 0x2, 0xbe, 0x747, 0x3, 0x2, 0x2, 0x2, 0xc0, 0x753, 0x3, 
       0x2, 0x2, 0x2, 0xc2, 0x768, 0x3, 0x2, 0x2, 0x2, 0xc4, 0x795, 0x3, 
       0x2, 0x2, 0x2, 0xc6, 0x7a8, 0x3, 0x2, 0x2, 0x2, 0xc8, 0x7aa, 0x3, 
       0x2, 0x2, 0x2, 0xca, 0x7b7, 0x3, 0x2, 0x2, 0x2, 0xcc, 0x7c3, 0x3, 
       0x2, 0x2, 0x2, 0xce, 0x7cf, 0x3, 0x2, 0x2, 0x2, 0xd0, 0x7d4, 0x3, 
       0x2, 0x2, 0x2, 0xd2, 0x7f2, 0x3, 0x2, 0x2, 0x2, 0xd4, 0x7ff, 0x3, 
       0x2, 0x2, 0x2, 0xd6, 0x811, 0x3, 0x2, 0x2, 0x2, 0xd8, 0x82b, 0x3, 
       0x2, 0x2, 0x2, 0xda, 0x834, 0x3, 0x2, 0x2, 0x2, 0xdc, 0x838, 0x3, 
       0x2, 0x2, 0x2, 0xde, 0x890, 0x3, 0x2, 0x2, 0x2, 0xe0, 0x946, 0x3, 
       0x2, 0x2, 0x2, 0xe2, 0x94f, 0x3, 0x2, 0x2, 0x2, 0xe4, 0x95d, 0x3, 
       0x2, 0x2, 0x2, 0xe6, 0x978, 0x3, 0x2, 0x2, 0x2, 0xe8, 0x98e, 0x3, 
       0x2, 0x2, 0x2, 0xea, 0x99a, 0x3, 0x2, 0x2, 0x2, 0xec, 0x9b0, 0x3, 
       0x2, 0x2, 0x2, 0xee, 0x9bf, 0x3, 0x2, 0x2, 0x2, 0xf0, 0x9c1, 0x3, 
       0x2, 0x2, 0x2, 0xf2, 0x9d6, 0x3, 0x2, 0x2, 0x2, 0xf4, 0x9f4, 0x3, 
       0x2, 0x2, 0x2, 0xf6, 0x9f6, 0x3, 0x2, 0x2, 0x2, 0xf8, 0x9fc, 0x3, 
       0x2, 0x2, 0x2, 0xfa, 0xa0e, 0x3, 0x2, 0x2, 0x2, 0xfc, 0xa10, 0x3, 
       0x2, 0x2, 0x2, 0xfe, 0xa1a, 0x3, 0x2, 0x2, 0x2, 0x100, 0xa34, 0x3, 
       0x2, 0x2, 0x2, 0x102, 0xa49, 0x3, 0x2, 0x2, 0x2, 0x104, 0xa54, 0x3, 
       0x2, 0x2, 0x2, 0x106, 0xa5b, 0x3, 0x2, 0x2, 0x2, 0x108, 0xa69, 0x3, 
       0x2, 0x2, 0x2, 0x10a, 0xa7e, 0x3, 0x2, 0x2, 0x2, 0x10c, 0xa82, 0x3, 
       0x2, 0x2, 0x2, 0x10e, 0xa87, 0x3, 0x2, 0x2, 0x2, 0x110, 0xaa2, 0x3, 
       0x2, 0x2, 0x2, 0x112, 0xac4, 0x3, 0x2, 0x2, 0x2, 0x114, 0xaca, 0x3, 
       0x2, 0x2, 0x2, 0x116, 0xadd, 0x3, 0x2, 0x2, 0x2, 0x118, 0xaef, 0x3, 
       0x2, 0x2, 0x2, 0x11a, 0xaf1, 0x3, 0x2, 0x2, 0x2, 0x11c, 0xafc, 0x3, 
       0x2, 0x2, 0x2, 0x11e, 0xb0d, 0x3, 0x2, 0x2, 0x2, 0x120, 0xb0f, 0x3, 
       0x2, 0x2, 0x2, 0x122, 0xb11, 0x3, 0x2, 0x2, 0x2, 0x124, 0xb19, 0x3, 
       0x2, 0x2, 0x2, 0x126, 0xb21, 0x3, 0x2, 0x2, 0x2, 0x128, 0xb2c, 0x3, 
       0x2, 0x2, 0x2, 0x12a, 0xb2f, 0x3, 0x2, 0x2, 0x2, 0x12c, 0xb31, 0x3, 
       0x2, 0x2, 0x2, 0x12e, 0xb33, 0x3, 0x2, 0x2, 0x2, 0x130, 0xb37, 0x3, 
       0x2, 0x2, 0x2, 0x132, 0xb43, 0x3, 0x2, 0x2, 0x2, 0x134, 0xb45, 0x3, 
       0x2, 0x2, 0x2, 0x136, 0xb47, 0x3, 0x2, 0x2, 0x2, 0x138, 0x139, 0x5, 
       0x4, 0x3, 0x2, 0x139, 0x13a, 0x7, 0x2, 0x2, 0x3, 0x13a, 0x3, 0x3, 
       0x2, 0x2, 0x2, 0x13b, 0x13d, 0x7, 0xdf, 0x2, 0x2, 0x13c, 0x13b, 0x3, 
       0x2, 0x2, 0x2, 0x13c, 0x13d, 0x3, 0x2, 0x2, 0x2, 0x13d, 0x141, 0x3, 
       0x2, 0x2, 0x2, 0x13e, 0x140, 0x7, 0xdd, 0x2, 0x2, 0x13f, 0x13e, 0x3, 
       0x2, 0x2, 0x2, 0x140, 0x143, 0x3, 0x2, 0x2, 0x2, 0x141, 0x13f, 0x3, 
       0x2, 0x2, 0x2, 0x141, 0x142, 0x3, 0x2, 0x2, 0x2, 0x142, 0x14a, 0x3, 
       0x2, 0x2, 0x2, 0x143, 0x141, 0x3, 0x2, 0x2, 0x2, 0x144, 0x146, 0x5, 
       0xe, 0x8, 0x2, 0x145, 0x147, 0x7, 0xdd, 0x2, 0x2, 0x146, 0x145, 0x3, 
       0x2, 0x2, 0x2, 0x147, 0x148, 0x3, 0x2, 0x2, 0x2, 0x148, 0x146, 0x3, 
       0x2, 0x2, 0x2, 0x148, 0x149, 0x3, 0x2, 0x2, 0x2, 0x149, 0x14b, 0x3, 
       0x2, 0x2, 0x2, 0x14a, 0x144, 0x3, 0x2, 0x2, 0x2, 0x14a, 0x14b, 0x3, 
       0x2, 0x2, 0x2, 0x14b, 0x14d, 0x3, 0x2, 0x2, 0x2, 0x14c, 0x14e, 0x5, 
       0x6, 0x4, 0x2, 0x14d, 0x14c, 0x3, 0x2, 0x2, 0x2, 0x14d, 0x14e, 0x3, 
       0x2, 0x2, 0x2, 0x14e, 0x152, 0x3, 0x2, 0x2, 0x2, 0x14f, 0x151, 0x7, 
       0xdd, 0x2, 0x2, 0x150, 0x14f, 0x3, 0x2, 0x2, 0x2, 0x151, 0x154, 0x3, 
       0x2, 0x2, 0x2, 0x152, 0x150, 0x3, 0x2, 0x2, 0x2, 0x152, 0x153, 0x3, 
       0x2, 0x2, 0x2, 0x153, 0x156, 0x3, 0x2, 0x2, 0x2, 0x154, 0x152, 0x3, 
       0x2, 0x2, 0x2, 0x155, 0x157, 0x5, 0x1e, 0x10, 0x2, 0x156, 0x155, 
       0x3, 0x2, 0x2, 0x2, 0x156, 0x157, 0x3, 0x2, 0x2, 0x2, 0x157, 0x15b, 
       0x3, 0x2, 0x2, 0x2, 0x158, 0x15a, 0x7, 0xdd, 0x2, 0x2, 0x159, 0x158, 
       0x3, 0x2, 0x2, 0x2, 0x15a, 0x15d, 0x3, 0x2, 0x2, 0x2, 0x15b, 0x159, 
       0x3, 0x2, 0x2, 0x2, 0x15b, 0x15c, 0x3, 0x2, 0x2, 0x2, 0x15c, 0x15f, 
       0x3, 0x2, 0x2, 0x2, 0x15d, 0x15b, 0x3, 0x2, 0x2, 0x2, 0x15e, 0x160, 
       0x5, 0x10, 0x9, 0x2, 0x15f, 0x15e, 0x3, 0x2, 0x2, 0x2, 0x15f, 0x160, 
       0x3, 0x2, 0x2, 0x2, 0x160, 0x164, 0x3, 0x2, 0x2, 0x2, 0x161, 0x163, 
       0x7, 0xdd, 0x2, 0x2, 0x162, 0x161, 0x3, 0x2, 0x2, 0x2, 0x163, 0x166, 
       0x3, 0x2, 0x2, 0x2, 0x164, 0x162, 0x3, 0x2, 0x2, 0x2, 0x164, 0x165, 
       0x3, 0x2, 0x2, 0x2, 0x165, 0x168, 0x3, 0x2, 0x2, 0x2, 0x166, 0x164, 
       0x3, 0x2, 0x2, 0x2, 0x167, 0x169, 0x5, 0x14, 0xb, 0x2, 0x168, 0x167, 
       0x3, 0x2, 0x2, 0x2, 0x168, 0x169, 0x3, 0x2, 0x2, 0x2, 0x169, 0x16d, 
       0x3, 0x2, 0x2, 0x2, 0x16a, 0x16c, 0x7, 0xdd, 0x2, 0x2, 0x16b, 0x16a, 
       0x3, 0x2, 0x2, 0x2, 0x16c, 0x16f, 0x3, 0x2, 0x2, 0x2, 0x16d, 0x16b, 
       0x3, 0x2, 0x2, 0x2, 0x16d, 0x16e, 0x3, 0x2, 0x2, 0x2, 0x16e, 0x171, 
       0x3, 0x2, 0x2, 0x2, 0x16f, 0x16d, 0x3, 0x2, 0x2, 0x2, 0x170, 0x172, 
       0x5, 0x16, 0xc, 0x2, 0x171, 0x170, 0x3, 0x2, 0x2, 0x2, 0x171, 0x172, 
       0x3, 0x2, 0x2, 0x2, 0x172, 0x176, 0x3, 0x2, 0x2, 0x2, 0x173, 0x175, 
       0x7, 0xdd, 0x2, 0x2, 0x174, 0x173, 0x3, 0x2, 0x2, 0x2, 0x175, 0x178, 
       0x3, 0x2, 0x2, 0x2, 0x176, 0x174, 0x3, 0x2, 0x2, 0x2, 0x176, 0x177, 
       0x3, 0x2, 0x2, 0x2, 0x177, 0x17a, 0x3, 0x2, 0x2, 0x2, 0x178, 0x176, 
       0x3, 0x2, 0x2, 0x2, 0x179, 0x17b, 0x5, 0x1a, 0xe, 0x2, 0x17a, 0x179, 
       0x3, 0x2, 0x2, 0x2, 0x17a, 0x17b, 0x3, 0x2, 0x2, 0x2, 0x17b, 0x17f, 
       0x3, 0x2, 0x2, 0x2, 0x17c, 0x17e, 0x7, 0xdd, 0x2, 0x2, 0x17d, 0x17c, 
       0x3, 0x2, 0x2, 0x2, 0x17e, 0x181, 0x3, 0x2, 0x2, 0x2, 0x17f, 0x17d, 
       0x3, 0x2, 0x2, 0x2, 0x17f, 0x180, 0x3, 0x2, 0x2, 0x2, 0x180, 0x183, 
       0x3, 0x2, 0x2, 0x2, 0x181, 0x17f, 0x3, 0x2, 0x2, 0x2, 0x182, 0x184, 
       0x7, 0xdf, 0x2, 0x2, 0x183, 0x182, 0x3, 0x2, 0x2, 0x2, 0x183, 0x184, 
       0x3, 0x2, 0x2, 0x2, 0x184, 0x5, 0x3, 0x2, 0x2, 0x2, 0x185, 0x187, 
       0x5, 0x8, 0x5, 0x2, 0x186, 0x185, 0x3, 0x2, 0x2, 0x2, 0x187, 0x188, 
       0x3, 0x2, 0x2, 0x2, 0x188, 0x186, 0x3, 0x2, 0x2, 0x2, 0x188, 0x189, 
       0x3, 0x2, 0x2, 0x2, 0x189, 0x7, 0x3, 0x2, 0x2, 0x2, 0x18a, 0x18c, 
       0x7, 0x70, 0x2, 0x2, 0x18b, 0x18d, 0x7, 0xdf, 0x2, 0x2, 0x18c, 0x18b, 
       0x3, 0x2, 0x2, 0x2, 0x18c, 0x18d, 0x3, 0x2, 0x2, 0x2, 0x18d, 0x18e, 
       0x3, 0x2, 0x2, 0x2, 0x18e, 0x190, 0x7, 0xbc, 0x2, 0x2, 0x18f, 0x191, 
       0x7, 0xdf, 0x2, 0x2, 0x190, 0x18f, 0x3, 0x2, 0x2, 0x2, 0x190, 0x191, 
       0x3, 0x2, 0x2, 0x2, 0x191, 0x192, 0x3, 0x2, 0x2, 0x2, 0x192, 0x198, 
       0x5, 0xa, 0x6, 0x2, 0x193, 0x195, 0x7, 0xcf, 0x2, 0x2, 0x194, 0x196, 
       0x7, 0xdf, 0x2, 0x2, 0x195, 0x194, 0x3, 0x2, 0x2, 0x2, 0x195, 0x196, 
       0x3, 0x2, 0x2, 0x2, 0x196, 0x197, 0x3, 0x2, 0x2, 0x2, 0x197, 0x199, 
       0x5, 0xc, 0x7, 0x2, 0x198, 0x193, 0x3, 0x2, 0x2, 0x2, 0x198, 0x199, 
       0x3, 0x2, 0x2, 0x2, 0x199, 0x19d, 0x3, 0x2, 0x2, 0x2, 0x19a, 0x19c, 
       0x7, 0xdd, 0x2, 0x2, 0x19b, 0x19a, 0x3, 0x2, 0x2, 0x2, 0x19c, 0x19f, 
       0x3, 0x2, 0x2, 0x2, 0x19d, 0x19b, 0x3, 0x2, 0x2, 0x2, 0x19d, 0x19e, 
       0x3, 0x2, 0x2, 0x2, 0x19e, 0x9, 0x3, 0x2, 0x2, 0x2, 0x19f, 0x19d, 
       0x3, 0x2, 0x2, 0x2, 0x1a0, 0x1a1, 0x7, 0xd2, 0x2, 0x2, 0x1a1, 0xb, 
       0x3, 0x2, 0x2, 0x2, 0x1a2, 0x1a3, 0x7, 0xd2, 0x2, 0x2, 0x1a3, 0xd, 
       0x3, 0x2, 0x2, 0x2, 0x1a4, 0x1a5, 0x7, 0xac, 0x2, 0x2, 0x1a5, 0x1a6, 
       0x7, 0xdf, 0x2, 0x2, 0x1a6, 0x1a9, 0x7, 0xd6, 0x2, 0x2, 0x1a7, 0x1a8, 
       0x7, 0xdf, 0x2, 0x2, 0x1a8, 0x1aa, 0x7, 0x17, 0x2, 0x2, 0x1a9, 0x1a7, 
       0x3, 0x2, 0x2, 0x2, 0x1a9, 0x1aa, 0x3, 0x2, 0x2, 0x2, 0x1aa, 0xf, 
       0x3, 0x2, 0x2, 0x2, 0x1ab, 0x1ad, 0x7, 0xc, 0x2, 0x2, 0x1ac, 0x1ae, 
       0x7, 0xdd, 0x2, 0x2, 0x1ad, 0x1ac, 0x3, 0x2, 0x2, 0x2, 0x1ae, 0x1af, 
       0x3, 0x2, 0x2, 0x2, 0x1af, 0x1ad, 0x3, 0x2, 0x2, 0x2, 0x1af, 0x1b0, 
       0x3, 0x2, 0x2, 0x2, 0x1b0, 0x1b2, 0x3, 0x2, 0x2, 0x2, 0x1b1, 0x1b3, 
       0x5, 0x12, 0xa, 0x2, 0x1b2, 0x1b1, 0x3, 0x2, 0x2, 0x2, 0x1b3, 0x1b4, 
       0x3, 0x2, 0x2, 0x2, 0x1b4, 0x1b2, 0x3, 0x2, 0x2, 0x2, 0x1b4, 0x1b5, 
       0x3, 0x2, 0x2, 0x2, 0x1b5, 0x1b6, 0x3, 0x2, 0x2, 0x2, 0x1b6, 0x1b8, 
       0x7, 0x38, 0x2, 0x2, 0x1b7, 0x1b9, 0x7, 0xdd, 0x2, 0x2, 0x1b8, 0x1b7, 
       0x3, 0x2, 0x2, 0x2, 0x1b9, 0x1ba, 0x3, 0x2, 0x2, 0x2, 0x1ba, 0x1b8, 
       0x3, 0x2, 0x2, 0x2, 0x1ba, 0x1bb, 0x3, 0x2, 0x2, 0x2, 0x1bb, 0x11, 
       0x3, 0x2, 0x2, 0x2, 0x1bc, 0x1be, 0x5, 0x118, 0x8d, 0x2, 0x1bd, 0x1bf, 
       0x7, 0xdf, 0x2, 0x2, 0x1be, 0x1bd, 0x3, 0x2, 0x2, 0x2, 0x1be, 0x1bf, 
       0x3, 0x2, 0x2, 0x2, 0x1bf, 0x1c0, 0x3, 0x2, 0x2, 0x2, 0x1c0, 0x1c2, 
       0x7, 0xbc, 0x2, 0x2, 0x1c1, 0x1c3, 0x7, 0xdf, 0x2, 0x2, 0x1c2, 0x1c1, 
       0x3, 0x2, 0x2, 0x2, 0x1c2, 0x1c3, 0x3, 0x2, 0x2, 0x2, 0x1c3, 0x1c4, 
       0x3, 0x2, 0x2, 0x2, 0x1c4, 0x1c5, 0x5, 0x12a, 0x96, 0x2, 0x1c5, 0x1c6, 
       0x7, 0xdd, 0x2, 0x2, 0x1c6, 0x13, 0x3, 0x2, 0x2, 0x2, 0x1c7, 0x1c9, 
       0x5, 0x30, 0x19, 0x2, 0x1c8, 0x1ca, 0x7, 0xdd, 0x2, 0x2, 0x1c9, 0x1c8, 
       0x3, 0x2, 0x2, 0x2, 0x1ca, 0x1cb, 0x3, 0x2, 0x2, 0x2, 0x1cb, 0x1c9, 
       0x3, 0x2, 0x2, 0x2, 0x1cb, 0x1cc, 0x3, 0x2, 0x2, 0x2, 0x1cc, 0x1ce, 
       0x3, 0x2, 0x2, 0x2, 0x1cd, 0x1c7, 0x3, 0x2, 0x2, 0x2, 0x1ce, 0x1cf, 
       0x3, 0x2, 0x2, 0x2, 0x1cf, 0x1cd, 0x3, 0x2, 0x2, 0x2, 0x1cf, 0x1d0, 
       0x3, 0x2, 0x2, 0x2, 0x1d0, 0x15, 0x3, 0x2, 0x2, 0x2, 0x1d1, 0x1d3, 
       0x5, 0x18, 0xd, 0x2, 0x1d2, 0x1d4, 0x7, 0xdd, 0x2, 0x2, 0x1d3, 0x1d2, 
       0x3, 0x2, 0x2, 0x2, 0x1d4, 0x1d5, 0x3, 0x2, 0x2, 0x2, 0x1d5, 0x1d3, 
       0x3, 0x2, 0x2, 0x2, 0x1d5, 0x1d6, 0x3, 0x2, 0x2, 0x2, 0x1d6, 0x1d8, 
       0x3, 0x2, 0x2, 0x2, 0x1d7, 0x1d1, 0x3, 0x2, 0x2, 0x2, 0x1d8, 0x1d9, 
       0x3, 0x2, 0x2, 0x2, 0x1d9, 0x1d7, 0x3, 0x2, 0x2, 0x2, 0x1d9, 0x1da, 
       0x3, 0x2, 0x2, 0x2, 0x1da, 0x17, 0x3, 0x2, 0x2, 0x2, 0x1db, 0x1dc, 
       0x7, 0x76, 0x2, 0x2, 0x1dc, 0x1dd, 0x7, 0xdf, 0x2, 0x2, 0x1dd, 0x1e4, 
       0x7, 0xd5, 0x2, 0x2, 0x1de, 0x1df, 0x7, 0x78, 0x2, 0x2, 0x1df, 0x1e0, 
       0x7, 0xdf, 0x2, 0x2, 0x1e0, 0x1e4, 0x9, 0x2, 0x2, 0x2, 0x1e1, 0x1e4, 
       0x7, 0x77, 0x2, 0x2, 0x1e2, 0x1e4, 0x7, 0x79, 0x2, 0x2, 0x1e3, 0x1db, 
       0x3, 0x2, 0x2, 0x2, 0x1e3, 0x1de, 0x3, 0x2, 0x2, 0x2, 0x1e3, 0x1e1, 
       0x3, 0x2, 0x2, 0x2, 0x1e3, 0x1e2, 0x3, 0x2, 0x2, 0x2, 0x1e4, 0x19, 
       0x3, 0x2, 0x2, 0x2, 0x1e5, 0x1ee, 0x5, 0x1c, 0xf, 0x2, 0x1e6, 0x1e8, 
       0x7, 0xdd, 0x2, 0x2, 0x1e7, 0x1e6, 0x3, 0x2, 0x2, 0x2, 0x1e8, 0x1e9, 
       0x3, 0x2, 0x2, 0x2, 0x1e9, 0x1e7, 0x3, 0x2, 0x2, 0x2, 0x1e9, 0x1ea, 
       0x3, 0x2, 0x2, 0x2, 0x1ea, 0x1eb, 0x3, 0x2, 0x2, 0x2, 0x1eb, 0x1ed, 
       0x5, 0x1c, 0xf, 0x2, 0x1ec, 0x1e7, 0x3, 0x2, 0x2, 0x2, 0x1ed, 0x1f0, 
       0x3, 0x2, 0x2, 0x2, 0x1ee, 0x1ec, 0x3, 0x2, 0x2, 0x2, 0x1ee, 0x1ef, 
       0x3, 0x2, 0x2, 0x2, 0x1ef, 0x1b, 0x3, 0x2, 0x2, 0x2, 0x1f0, 0x1ee, 
       0x3, 0x2, 0x2, 0x2, 0x1f1, 0x1fe, 0x5, 0x2e, 0x18, 0x2, 0x1f2, 0x1fe, 
       0x5, 0x18, 0xd, 0x2, 0x1f3, 0x1fe, 0x5, 0x46, 0x24, 0x2, 0x1f4, 0x1fe, 
       0x5, 0x50, 0x29, 0x2, 0x1f5, 0x1fe, 0x5, 0x58, 0x2d, 0x2, 0x1f6, 
       0x1fe, 0x5, 0x62, 0x32, 0x2, 0x1f7, 0x1fe, 0x5, 0x84, 0x43, 0x2, 
       0x1f8, 0x1fe, 0x5, 0xa0, 0x51, 0x2, 0x1f9, 0x1fe, 0x5, 0xa2, 0x52, 
       0x2, 0x1fa, 0x1fe, 0x5, 0xa4, 0x53, 0x2, 0x1fb, 0x1fe, 0x5, 0xd0, 
       0x69, 0x2, 0x1fc, 0x1fe, 0x5, 0xd4, 0x6b, 0x2, 0x1fd, 0x1f1, 0x3, 
       0x2, 0x2, 0x2, 0x1fd, 0x1f2, 0x3, 0x2, 0x2, 0x2, 0x1fd, 0x1f3, 0x3, 
       0x2, 0x2, 0x2, 0x1fd, 0x1f4, 0x3, 0x2, 0x2, 0x2, 0x1fd, 0x1f5, 0x3, 
       0x2, 0x2, 0x2, 0x1fd, 0x1f6, 0x3, 0x2, 0x2, 0x2, 0x1fd, 0x1f7, 0x3, 
       0x2, 0x2, 0x2, 0x1fd, 0x1f8, 0x3, 0x2, 0x2, 0x2, 0x1fd, 0x1f9, 0x3, 
       0x2, 0x2, 0x2, 0x1fd, 0x1fa, 0x3, 0x2, 0x2, 0x2, 0x1fd, 0x1fb, 0x3, 
       0x2, 0x2, 0x2, 0x1fd, 0x1fc, 0x3, 0x2, 0x2, 0x2, 0x1fe, 0x1d, 0x3, 
       0x2, 0x2, 0x2, 0x1ff, 0x201, 0x7, 0xdf, 0x2, 0x2, 0x200, 0x1ff, 0x3, 
       0x2, 0x2, 0x2, 0x200, 0x201, 0x3, 0x2, 0x2, 0x2, 0x201, 0x202, 0x3, 
       0x2, 0x2, 0x2, 0x202, 0x203, 0x7, 0xc, 0x2, 0x2, 0x203, 0x204, 0x7, 
       0xdf, 0x2, 0x2, 0x204, 0x205, 0x5, 0x2a, 0x16, 0x2, 0x205, 0x206, 
       0x7, 0xdf, 0x2, 0x2, 0x206, 0x208, 0x5, 0x2c, 0x17, 0x2, 0x207, 0x209, 
       0x7, 0xdf, 0x2, 0x2, 0x208, 0x207, 0x3, 0x2, 0x2, 0x2, 0x208, 0x209, 
       0x3, 0x2, 0x2, 0x2, 0x209, 0x20b, 0x3, 0x2, 0x2, 0x2, 0x20a, 0x20c, 
       0x7, 0xdd, 0x2, 0x2, 0x20b, 0x20a, 0x3, 0x2, 0x2, 0x2, 0x20c, 0x20d, 
       0x3, 0x2, 0x2, 0x2, 0x20d, 0x20b, 0x3, 0x2, 0x2, 0x2, 0x20d, 0x20e, 
       0x3, 0x2, 0x2, 0x2, 0x20e, 0x210, 0x3, 0x2, 0x2, 0x2, 0x20f, 0x211, 
       0x5, 0x20, 0x11, 0x2, 0x210, 0x20f, 0x3, 0x2, 0x2, 0x2, 0x211, 0x212, 
       0x3, 0x2, 0x2, 0x2, 0x212, 0x210, 0x3, 0x2, 0x2, 0x2, 0x212, 0x213, 
       0x3, 0x2, 0x2, 0x2, 0x213, 0x214, 0x3, 0x2, 0x2, 0x2, 0x214, 0x218, 
       0x7, 0x38, 0x2, 0x2, 0x215, 0x217, 0x7, 0xdd, 0x2, 0x2, 0x216, 0x215, 
       0x3, 0x2, 0x2, 0x2, 0x217, 0x21a, 0x3, 0x2, 0x2, 0x2, 0x218, 0x216, 
       0x3, 0x2, 0x2, 0x2, 0x218, 0x219, 0x3, 0x2, 0x2, 0x2, 0x219, 0x1f, 
       0x3, 0x2, 0x2, 0x2, 0x21a, 0x218, 0x3, 0x2, 0x2, 0x2, 0x21b, 0x21f, 
       0x5, 0x22, 0x12, 0x2, 0x21c, 0x21f, 0x5, 0x28, 0x15, 0x2, 0x21d, 
       0x21f, 0x5, 0x1e, 0x10, 0x2, 0x21e, 0x21b, 0x3, 0x2, 0x2, 0x2, 0x21e, 
       0x21c, 0x3, 0x2, 0x2, 0x2, 0x21e, 0x21d, 0x3, 0x2, 0x2, 0x2, 0x21f, 
       0x21, 0x3, 0x2, 0x2, 0x2, 0x220, 0x222, 0x7, 0xdf, 0x2, 0x2, 0x221, 
       0x220, 0x3, 0x2, 0x2, 0x2, 0x221, 0x222, 0x3, 0x2, 0x2, 0x2, 0x222, 
       0x223, 0x3, 0x2, 0x2, 0x2, 0x223, 0x225, 0x5, 0xfa, 0x7e, 0x2, 0x224, 
       0x226, 0x7, 0xdf, 0x2, 0x2, 0x225, 0x224, 0x3, 0x2, 0x2, 0x2, 0x225, 
       0x226, 0x3, 0x2, 0x2, 0x2, 0x226, 0x227, 0x3, 0x2, 0x2, 0x2, 0x227, 
       0x229, 0x7, 0xbc, 0x2, 0x2, 0x228, 0x22a, 0x7, 0xdf, 0x2, 0x2, 0x229, 
       0x228, 0x3, 0x2, 0x2, 0x2, 0x229, 0x22a, 0x3, 0x2, 0x2, 0x2, 0x22a, 
       0x22c, 0x3, 0x2, 0x2, 0x2, 0x22b, 0x22d, 0x7, 0xba, 0x2, 0x2, 0x22c, 
       0x22b, 0x3, 0x2, 0x2, 0x2, 0x22c, 0x22d, 0x3, 0x2, 0x2, 0x2, 0x22d, 
       0x22e, 0x3, 0x2, 0x2, 0x2, 0x22e, 0x230, 0x5, 0x26, 0x14, 0x2, 0x22f, 
       0x231, 0x7, 0xd9, 0x2, 0x2, 0x230, 0x22f, 0x3, 0x2, 0x2, 0x2, 0x230, 
       0x231, 0x3, 0x2, 0x2, 0x2, 0x231, 0x233, 0x3, 0x2, 0x2, 0x2, 0x232, 
       0x234, 0x7, 0xdd, 0x2, 0x2, 0x233, 0x232, 0x3, 0x2, 0x2, 0x2, 0x234, 
       0x235, 0x3, 0x2, 0x2, 0x2, 0x235, 0x233, 0x3, 0x2, 0x2, 0x2, 0x235, 
       0x236, 0x3, 0x2, 0x2, 0x2, 0x236, 0x23, 0x3, 0x2, 0x2, 0x2, 0x237, 
       0x238, 0x7, 0x70, 0x2, 0x2, 0x238, 0x23a, 0x7, 0xbb, 0x2, 0x2, 0x239, 
       0x237, 0x3, 0x2, 0x2, 0x2, 0x239, 0x23a, 0x3, 0x2, 0x2, 0x2, 0x23a, 
       0x23b, 0x3, 0x2, 0x2, 0x2, 0x23b, 0x240, 0x5, 0x118, 0x8d, 0x2, 0x23c, 
       0x23d, 0x7, 0xc3, 0x2, 0x2, 0x23d, 0x23e, 0x5, 0x12a, 0x96, 0x2, 
       0x23e, 0x23f, 0x7, 0xce, 0x2, 0x2, 0x23f, 0x241, 0x3, 0x2, 0x2, 0x2, 
       0x240, 0x23c, 0x3, 0x2, 0x2, 0x2, 0x240, 0x241, 0x3, 0x2, 0x2, 0x2, 
       0x241, 0x24c, 0x3, 0x2, 0x2, 0x2, 0x242, 0x243, 0x7, 0xbb, 0x2, 0x2, 
       0x243, 0x248, 0x5, 0x118, 0x8d, 0x2, 0x244, 0x245, 0x7, 0xc3, 0x2, 
       0x2, 0x245, 0x246, 0x5, 0x12a, 0x96, 0x2, 0x246, 0x247, 0x7, 0xce, 
       0x2, 0x2, 0x247, 0x249, 0x3, 0x2, 0x2, 0x2, 0x248, 0x244, 0x3, 0x2, 
       0x2, 0x2, 0x248, 0x249, 0x3, 0x2, 0x2, 0x2, 0x249, 0x24b, 0x3, 0x2, 
       0x2, 0x2, 0x24a, 0x242, 0x3, 0x2, 0x2, 0x2, 0x24b, 0x24e, 0x3, 0x2, 
       0x2, 0x2, 0x24c, 0x24a, 0x3, 0x2, 0x2, 0x2, 0x24c, 0x24d, 0x3, 0x2, 
       0x2, 0x2, 0x24d, 0x25, 0x3, 0x2, 0x2, 0x2, 0x24e, 0x24c, 0x3, 0x2, 
       0x2, 0x2, 0x24f, 0x251, 0x7, 0xba, 0x2, 0x2, 0x250, 0x24f, 0x3, 0x2, 
       0x2, 0x2, 0x250, 0x251, 0x3, 0x2, 0x2, 0x2, 0x251, 0x259, 0x3, 0x2, 
       0x2, 0x2, 0x252, 0x25a, 0x5, 0x12a, 0x96, 0x2, 0x253, 0x254, 0x7, 
       0xc2, 0x2, 0x2, 0x254, 0x255, 0x5, 0x118, 0x8d, 0x2, 0x255, 0x256, 
       0x7, 0xcd, 0x2, 0x2, 0x256, 0x25a, 0x3, 0x2, 0x2, 0x2, 0x257, 0x258, 
       0x7, 0xcc, 0x2, 0x2, 0x258, 0x25a, 0x5, 0x118, 0x8d, 0x2, 0x259, 
       0x252, 0x3, 0x2, 0x2, 0x2, 0x259, 0x253, 0x3, 0x2, 0x2, 0x2, 0x259, 
       0x257, 0x3, 0x2, 0x2, 0x2, 0x25a, 0x27, 0x3, 0x2, 0x2, 0x2, 0x25b, 
       0x25d, 0x7, 0xdf, 0x2, 0x2, 0x25c, 0x25b, 0x3, 0x2, 0x2, 0x2, 0x25c, 
       0x25d, 0x3, 0x2, 0x2, 0x2, 0x25d, 0x25e, 0x3, 0x2, 0x2, 0x2, 0x25e, 
       0x25f, 0x7, 0xd, 0x2, 0x2, 0x25f, 0x260, 0x7, 0xdf, 0x2, 0x2, 0x260, 
       0x264, 0x5, 0x118, 0x8d, 0x2, 0x261, 0x262, 0x7, 0xc3, 0x2, 0x2, 
       0x262, 0x263, 0x7, 0xd5, 0x2, 0x2, 0x263, 0x265, 0x7, 0xce, 0x2, 
       0x2, 0x264, 0x261, 0x3, 0x2, 0x2, 0x2, 0x264, 0x265, 0x3, 0x2, 0x2, 
       0x2, 0x265, 0x268, 0x3, 0x2, 0x2, 0x2, 0x266, 0x267, 0x7, 0xdf, 0x2, 
       0x2, 0x267, 0x269, 0x7, 0xda, 0x2, 0x2, 0x268, 0x266, 0x3, 0x2, 0x2, 
       0x2, 0x268, 0x269, 0x3, 0x2, 0x2, 0x2, 0x269, 0x26b, 0x3, 0x2, 0x2, 
       0x2, 0x26a, 0x26c, 0x7, 0xdd, 0x2, 0x2, 0x26b, 0x26a, 0x3, 0x2, 0x2, 
       0x2, 0x26c, 0x26d, 0x3, 0x2, 0x2, 0x2, 0x26d, 0x26b, 0x3, 0x2, 0x2, 
       0x2, 0x26d, 0x26e, 0x3, 0x2, 0x2, 0x2, 0x26e, 0x274, 0x3, 0x2, 0x2, 
       0x2, 0x26f, 0x271, 0x5, 0x20, 0x11, 0x2, 0x270, 0x26f, 0x3, 0x2, 
       0x2, 0x2, 0x271, 0x272, 0x3, 0x2, 0x2, 0x2, 0x272, 0x270, 0x3, 0x2, 
       0x2, 0x2, 0x272, 0x273, 0x3, 0x2, 0x2, 0x2, 0x273, 0x275, 0x3, 0x2, 
       0x2, 0x2, 0x274, 0x270, 0x3, 0x2, 0x2, 0x2, 0x274, 0x275, 0x3, 0x2, 
       0x2, 0x2, 0x275, 0x276, 0x3, 0x2, 0x2, 0x2, 0x276, 0x278, 0x7, 0x39, 
       0x2, 0x2, 0x277, 0x279, 0x7, 0xdd, 0x2, 0x2, 0x278, 0x277, 0x3, 0x2, 
       0x2, 0x2, 0x279, 0x27a, 0x3, 0x2, 0x2, 0x2, 0x27a, 0x278, 0x3, 0x2, 
       0x2, 0x2, 0x27a, 0x27b, 0x3, 0x2, 0x2, 0x2, 0x27b, 0x29, 0x3, 0x2, 
       0x2, 0x2, 0x27c, 0x27d, 0x5, 0x122, 0x92, 0x2, 0x27d, 0x2b, 0x3, 
       0x2, 0x2, 0x2, 0x27e, 0x27f, 0x5, 0x118, 0x8d, 0x2, 0x27f, 0x2d, 
       0x3, 0x2, 0x2, 0x2, 0x280, 0x281, 0x5, 0x32, 0x1a, 0x2, 0x281, 0x2f, 
       0x3, 0x2, 0x2, 0x2, 0x282, 0x283, 0x7, 0x7, 0x2, 0x2, 0x283, 0x284, 
       0x7, 0xdf, 0x2, 0x2, 0x284, 0x286, 0x5, 0xfa, 0x7e, 0x2, 0x285, 0x287, 
       0x7, 0xdf, 0x2, 0x2, 0x286, 0x285, 0x3, 0x2, 0x2, 0x2, 0x286, 0x287, 
       0x3, 0x2, 0x2, 0x2, 0x287, 0x288, 0x3, 0x2, 0x2, 0x2, 0x288, 0x28a, 
       0x7, 0xbc, 0x2, 0x2, 0x289, 0x28b, 0x7, 0xdf, 0x2, 0x2, 0x28a, 0x289, 
       0x3, 0x2, 0x2, 0x2, 0x28a, 0x28b, 0x3, 0x2, 0x2, 0x2, 0x28b, 0x28c, 
       0x3, 0x2, 0x2, 0x2, 0x28c, 0x297, 0x5, 0x12a, 0x96, 0x2, 0x28d, 0x28f, 
       0x7, 0xdf, 0x2, 0x2, 0x28e, 0x28d, 0x3, 0x2, 0x2, 0x2, 0x28e, 0x28f, 
       0x3, 0x2, 0x2, 0x2, 0x28f, 0x290, 0x3, 0x2, 0x2, 0x2, 0x290, 0x292, 
       0x7, 0xb8, 0x2, 0x2, 0x291, 0x293, 0x7, 0xdf, 0x2, 0x2, 0x292, 0x291, 
       0x3, 0x2, 0x2, 0x2, 0x292, 0x293, 0x3, 0x2, 0x2, 0x2, 0x293, 0x294, 
       0x3, 0x2, 0x2, 0x2, 0x294, 0x296, 0x5, 0x12a, 0x96, 0x2, 0x295, 0x28e, 
       0x3, 0x2, 0x2, 0x2, 0x296, 0x299, 0x3, 0x2, 0x2, 0x2, 0x297, 0x295, 
       0x3, 0x2, 0x2, 0x2, 0x297, 0x298, 0x3, 0x2, 0x2, 0x2, 0x298, 0x31, 
       0x3, 0x2, 0x2, 0x2, 0x299, 0x297, 0x3, 0x2, 0x2, 0x2, 0x29a, 0x2a6, 
       0x5, 0x34, 0x1b, 0x2, 0x29b, 0x29d, 0x7, 0xdd, 0x2, 0x2, 0x29c, 0x29b, 
       0x3, 0x2, 0x2, 0x2, 0x29d, 0x29e, 0x3, 0x2, 0x2, 0x2, 0x29e, 0x29c, 
       0x3, 0x2, 0x2, 0x2, 0x29e, 0x29f, 0x3, 0x2, 0x2, 0x2, 0x29f, 0x2a1, 
       0x3, 0x2, 0x2, 0x2, 0x2a0, 0x2a2, 0x7, 0xdf, 0x2, 0x2, 0x2a1, 0x2a0, 
       0x3, 0x2, 0x2, 0x2, 0x2a1, 0x2a2, 0x3, 0x2, 0x2, 0x2, 0x2a2, 0x2a3, 
       0x3, 0x2, 0x2, 0x2, 0x2a3, 0x2a5, 0x5, 0x34, 0x1b, 0x2, 0x2a4, 0x29c, 
       0x3, 0x2, 0x2, 0x2, 0x2a5, 0x2a8, 0x3, 0x2, 0x2, 0x2, 0x2a6, 0x2a4, 
       0x3, 0x2, 0x2, 0x2, 0x2a6, 0x2a7, 0x3, 0x2, 0x2, 0x2, 0x2a7, 0x33, 
       0x3, 0x2, 0x2, 0x2, 0x2a8, 0x2a6, 0x3, 0x2, 0x2, 0x2, 0x2a9, 0x2ed, 
       0x5, 0x36, 0x1c, 0x2, 0x2aa, 0x2ed, 0x5, 0x30, 0x19, 0x2, 0x2ab, 
       0x2ed, 0x5, 0x38, 0x1d, 0x2, 0x2ac, 0x2ed, 0x5, 0x3a, 0x1e, 0x2, 
       0x2ad, 0x2ed, 0x5, 0x3c, 0x1f, 0x2, 0x2ae, 0x2ed, 0x5, 0x3e, 0x20, 
       0x2, 0x2af, 0x2ed, 0x5, 0x40, 0x21, 0x2, 0x2b0, 0x2ed, 0x5, 0x44, 
       0x23, 0x2, 0x2b1, 0x2ed, 0x5, 0x4a, 0x26, 0x2, 0x2b2, 0x2ed, 0x5, 
       0x48, 0x25, 0x2, 0x2b3, 0x2ed, 0x5, 0x4c, 0x27, 0x2, 0x2b4, 0x2ed, 
       0x5, 0x4e, 0x28, 0x2, 0x2b5, 0x2ed, 0x5, 0x54, 0x2b, 0x2, 0x2b6, 
       0x2ed, 0x5, 0x56, 0x2c, 0x2, 0x2b7, 0x2ed, 0x5, 0x5a, 0x2e, 0x2, 
       0x2b8, 0x2ed, 0x5, 0xee, 0x78, 0x2, 0x2b9, 0x2ed, 0x5, 0x5c, 0x2f, 
       0x2, 0x2ba, 0x2ed, 0x5, 0x5e, 0x30, 0x2, 0x2bb, 0x2ed, 0x5, 0x60, 
       0x31, 0x2, 0x2bc, 0x2ed, 0x5, 0x64, 0x33, 0x2, 0x2bd, 0x2ed, 0x5, 
       0x66, 0x34, 0x2, 0x2be, 0x2ed, 0x5, 0x68, 0x35, 0x2, 0x2bf, 0x2ed, 
       0x5, 0x6a, 0x36, 0x2, 0x2c0, 0x2ed, 0x5, 0x74, 0x3b, 0x2, 0x2c1, 
       0x2ed, 0x5, 0x76, 0x3c, 0x2, 0x2c2, 0x2ed, 0x5, 0x78, 0x3d, 0x2, 
       0x2c3, 0x2ed, 0x5, 0x7a, 0x3e, 0x2, 0x2c4, 0x2ed, 0x5, 0x7c, 0x3f, 
       0x2, 0x2c5, 0x2ed, 0x5, 0x128, 0x95, 0x2, 0x2c6, 0x2ed, 0x5, 0x7e, 
       0x40, 0x2, 0x2c7, 0x2ed, 0x5, 0x80, 0x41, 0x2, 0x2c8, 0x2ed, 0x5, 
       0x82, 0x42, 0x2, 0x2c9, 0x2ed, 0x5, 0x84, 0x43, 0x2, 0x2ca, 0x2ed, 
       0x5, 0x8c, 0x47, 0x2, 0x2cb, 0x2ed, 0x5, 0x8e, 0x48, 0x2, 0x2cc, 
       0x2ed, 0x5, 0x90, 0x49, 0x2, 0x2cd, 0x2ed, 0x5, 0x92, 0x4a, 0x2, 
       0x2ce, 0x2ed, 0x5, 0x94, 0x4b, 0x2, 0x2cf, 0x2ed, 0x5, 0x96, 0x4c, 
       0x2, 0x2d0, 0x2ed, 0x5, 0x98, 0x4d, 0x2, 0x2d1, 0x2ed, 0x5, 0x9e, 
       0x50, 0x2, 0x2d2, 0x2ed, 0x5, 0xa6, 0x54, 0x2, 0x2d3, 0x2ed, 0x5, 
       0xa8, 0x55, 0x2, 0x2d4, 0x2ed, 0x5, 0xaa, 0x56, 0x2, 0x2d5, 0x2ed, 
       0x5, 0xac, 0x57, 0x2, 0x2d6, 0x2ed, 0x5, 0xb0, 0x59, 0x2, 0x2d7, 
       0x2ed, 0x5, 0xb2, 0x5a, 0x2, 0x2d8, 0x2ed, 0x5, 0xb4, 0x5b, 0x2, 
       0x2d9, 0x2ed, 0x5, 0xb6, 0x5c, 0x2, 0x2da, 0x2ed, 0x5, 0xb8, 0x5d, 
       0x2, 0x2db, 0x2ed, 0x5, 0xba, 0x5e, 0x2, 0x2dc, 0x2ed, 0x5, 0xbc, 
       0x5f, 0x2, 0x2dd, 0x2ed, 0x5, 0xbe, 0x60, 0x2, 0x2de, 0x2ed, 0x5, 
       0xc0, 0x61, 0x2, 0x2df, 0x2ed, 0x5, 0xc8, 0x65, 0x2, 0x2e0, 0x2ed, 
       0x5, 0xca, 0x66, 0x2, 0x2e1, 0x2ed, 0x5, 0xcc, 0x67, 0x2, 0x2e2, 
       0x2ed, 0x5, 0xce, 0x68, 0x2, 0x2e3, 0x2ed, 0x5, 0xd2, 0x6a, 0x2, 
       0x2e4, 0x2ed, 0x5, 0xda, 0x6e, 0x2, 0x2e5, 0x2ed, 0x5, 0xdc, 0x6f, 
       0x2, 0x2e6, 0x2ed, 0x5, 0xe0, 0x71, 0x2, 0x2e7, 0x2ed, 0x5, 0xe6, 
       0x74, 0x2, 0x2e8, 0x2ed, 0x5, 0xe8, 0x75, 0x2, 0x2e9, 0x2ed, 0x5, 
       0xea, 0x76, 0x2, 0x2ea, 0x2ed, 0x5, 0xec, 0x77, 0x2, 0x2eb, 0x2ed, 
       0x5, 0xf4, 0x7b, 0x2, 0x2ec, 0x2a9, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2aa, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2ab, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2ac, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2ad, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2ae, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2af, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2b0, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2b1, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2b2, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2b3, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2b4, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2b5, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2b6, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2b7, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2b8, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2b9, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2ba, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2bb, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2bc, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2bd, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2be, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2bf, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2c0, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2c1, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2c2, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2c3, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2c4, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2c5, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2c6, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2c7, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2c8, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2c9, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2ca, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2cb, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2cc, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2cd, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2ce, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2cf, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2d0, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2d1, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2d2, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2d3, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2d4, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2d5, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2d6, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2d7, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2d8, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2d9, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2da, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2db, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2dc, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2dd, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2de, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2df, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2e0, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2e1, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2e2, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2e3, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2e4, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2e5, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2e6, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2e7, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2e8, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2e9, 0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2ea, 
       0x3, 0x2, 0x2, 0x2, 0x2ec, 0x2eb, 0x3, 0x2, 0x2, 0x2, 0x2ed, 0x35, 
       0x3, 0x2, 0x2, 0x2, 0x2ee, 0x2ef, 0x7, 0x8, 0x2, 0x2, 0x2ef, 0x2f0, 
       0x7, 0xdf, 0x2, 0x2, 0x2f0, 0x2f9, 0x5, 0xde, 0x70, 0x2, 0x2f1, 0x2f3, 
       0x7, 0xdf, 0x2, 0x2, 0x2f2, 0x2f1, 0x3, 0x2, 0x2, 0x2, 0x2f2, 0x2f3, 
       0x3, 0x2, 0x2, 0x2, 0x2f3, 0x2f4, 0x3, 0x2, 0x2, 0x2, 0x2f4, 0x2f6, 
       0x7, 0xb8, 0x2, 0x2, 0x2f5, 0x2f7, 0x7, 0xdf, 0x2, 0x2, 0x2f6, 0x2f5, 
       0x3, 0x2, 0x2, 0x2, 0x2f6, 0x2f7, 0x3, 0x2, 0x2, 0x2, 0x2f7, 0x2f8, 
       0x3, 0x2, 0x2, 0x2, 0x2f8, 0x2fa, 0x5, 0xde, 0x70, 0x2, 0x2f9, 0x2f2, 
       0x3, 0x2, 0x2, 0x2, 0x2f9, 0x2fa, 0x3, 0x2, 0x2, 0x2, 0x2fa, 0x37, 
       0x3, 0x2, 0x2, 0x2, 0x2fb, 0x2fc, 0x7, 0xb, 0x2, 0x2, 0x2fc, 0x39, 
       0x3, 0x2, 0x2, 0x2, 0x2fd, 0x2fe, 0x7, 0x15, 0x2, 0x2, 0x2fe, 0x2ff, 
       0x7, 0xdf, 0x2, 0x2, 0x2ff, 0x300, 0x5, 0xde, 0x70, 0x2, 0x300, 0x3b, 
       0x3, 0x2, 0x2, 0x2, 0x301, 0x302, 0x7, 0x16, 0x2, 0x2, 0x302, 0x303, 
       0x7, 0xdf, 0x2, 0x2, 0x303, 0x304, 0x5, 0xde, 0x70, 0x2, 0x304, 0x3d, 
       0x3, 0x2, 0x2, 0x2, 0x305, 0x315, 0x7, 0x18, 0x2, 0x2, 0x306, 0x307, 
       0x7, 0xdf, 0x2, 0x2, 0x307, 0x312, 0x5, 0xde, 0x70, 0x2, 0x308, 0x30a, 
       0x7, 0xdf, 0x2, 0x2, 0x309, 0x308, 0x3, 0x2, 0x2, 0x2, 0x309, 0x30a, 
       0x3, 0x2, 0x2, 0x2, 0x30a, 0x30b, 0x3, 0x2, 0x2, 0x2, 0x30b, 0x30d, 
       0x7, 0xb8, 0x2, 0x2, 0x30c, 0x30e, 0x7, 0xdf, 0x2, 0x2, 0x30d, 0x30c, 
       0x3, 0x2, 0x2, 0x2, 0x30d, 0x30e, 0x3, 0x2, 0x2, 0x2, 0x30e, 0x30f, 
       0x3, 0x2, 0x2, 0x2, 0x30f, 0x311, 0x5, 0xde, 0x70, 0x2, 0x310, 0x309, 
       0x3, 0x2, 0x2, 0x2, 0x311, 0x314, 0x3, 0x2, 0x2, 0x2, 0x312, 0x310, 
       0x3, 0x2, 0x2, 0x2, 0x312, 0x313, 0x3, 0x2, 0x2, 0x2, 0x313, 0x316, 
       0x3, 0x2, 0x2, 0x2, 0x314, 0x312, 0x3, 0x2, 0x2, 0x2, 0x315, 0x306, 
       0x3, 0x2, 0x2, 0x2, 0x315, 0x316, 0x3, 0x2, 0x2, 0x2, 0x316, 0x3f, 
       0x3, 0x2, 0x2, 0x2, 0x317, 0x318, 0x5, 0x12e, 0x98, 0x2, 0x318, 0x319, 
       0x7, 0xdf, 0x2, 0x2, 0x319, 0x31b, 0x3, 0x2, 0x2, 0x2, 0x31a, 0x317, 
       0x3, 0x2, 0x2, 0x2, 0x31a, 0x31b, 0x3, 0x2, 0x2, 0x2, 0x31b, 0x31c, 
       0x3, 0x2, 0x2, 0x2, 0x31c, 0x31d, 0x7, 0x1a, 0x2, 0x2, 0x31d, 0x31e, 
       0x7, 0xdf, 0x2, 0x2, 0x31e, 0x329, 0x5, 0x42, 0x22, 0x2, 0x31f, 0x321, 
       0x7, 0xdf, 0x2, 0x2, 0x320, 0x31f, 0x3, 0x2, 0x2, 0x2, 0x320, 0x321, 
       0x3, 0x2, 0x2, 0x2, 0x321, 0x322, 0x3, 0x2, 0x2, 0x2, 0x322, 0x324, 
       0x7, 0xb8, 0x2, 0x2, 0x323, 0x325, 0x7, 0xdf, 0x2, 0x2, 0x324, 0x323, 
       0x3, 0x2, 0x2, 0x2, 0x324, 0x325, 0x3, 0x2, 0x2, 0x2, 0x325, 0x326, 
       0x3, 0x2, 0x2, 0x2, 0x326, 0x328, 0x5, 0x42, 0x22, 0x2, 0x327, 0x320, 
       0x3, 0x2, 0x2, 0x2, 0x328, 0x32b, 0x3, 0x2, 0x2, 0x2, 0x329, 0x327, 
       0x3, 0x2, 0x2, 0x2, 0x329, 0x32a, 0x3, 0x2, 0x2, 0x2, 0x32a, 0x41, 
       0x3, 0x2, 0x2, 0x2, 0x32b, 0x329, 0x3, 0x2, 0x2, 0x2, 0x32c, 0x32e, 
       0x5, 0x118, 0x8d, 0x2, 0x32d, 0x32f, 0x5, 0x132, 0x9a, 0x2, 0x32e, 
       0x32d, 0x3, 0x2, 0x2, 0x2, 0x32e, 0x32f, 0x3, 0x2, 0x2, 0x2, 0x32f, 
       0x332, 0x3, 0x2, 0x2, 0x2, 0x330, 0x331, 0x7, 0xdf, 0x2, 0x2, 0x331, 
       0x333, 0x5, 0x11a, 0x8e, 0x2, 0x332, 0x330, 0x3, 0x2, 0x2, 0x2, 0x332, 
       0x333, 0x3, 0x2, 0x2, 0x2, 0x333, 0x335, 0x3, 0x2, 0x2, 0x2, 0x334, 
       0x336, 0x7, 0xdf, 0x2, 0x2, 0x335, 0x334, 0x3, 0x2, 0x2, 0x2, 0x335, 
       0x336, 0x3, 0x2, 0x2, 0x2, 0x336, 0x337, 0x3, 0x2, 0x2, 0x2, 0x337, 
       0x339, 0x7, 0xbc, 0x2, 0x2, 0x338, 0x33a, 0x7, 0xdf, 0x2, 0x2, 0x339, 
       0x338, 0x3, 0x2, 0x2, 0x2, 0x339, 0x33a, 0x3, 0x2, 0x2, 0x2, 0x33a, 
       0x33b, 0x3, 0x2, 0x2, 0x2, 0x33b, 0x33c, 0x5, 0xde, 0x70, 0x2, 0x33c, 
       0x43, 0x3, 0x2, 0x2, 0x2, 0x33d, 0x33f, 0x7, 0x1b, 0x2, 0x2, 0x33e, 
       0x340, 0x7, 0xdf, 0x2, 0x2, 0x33f, 0x33e, 0x3, 0x2, 0x2, 0x2, 0x33f, 
       0x340, 0x3, 0x2, 0x2, 0x2, 0x340, 0x341, 0x3, 0x2, 0x2, 0x2, 0x341, 
       0x343, 0x7, 0xbc, 0x2, 0x2, 0x342, 0x344, 0x7, 0xdf, 0x2, 0x2, 0x343, 
       0x342, 0x3, 0x2, 0x2, 0x2, 0x343, 0x344, 0x3, 0x2, 0x2, 0x2, 0x344, 
       0x345, 0x3, 0x2, 0x2, 0x2, 0x345, 0x346, 0x5, 0xde, 0x70, 0x2, 0x346, 
       0x45, 0x3, 0x2, 0x2, 0x2, 0x347, 0x348, 0x5, 0x134, 0x9b, 0x2, 0x348, 
       0x349, 0x7, 0xdf, 0x2, 0x2, 0x349, 0x34b, 0x3, 0x2, 0x2, 0x2, 0x34a, 
       0x347, 0x3, 0x2, 0x2, 0x2, 0x34a, 0x34b, 0x3, 0x2, 0x2, 0x2, 0x34b, 
       0x34c, 0x3, 0x2, 0x2, 0x2, 0x34c, 0x34d, 0x7, 0x1c, 0x2, 0x2, 0x34d, 
       0x353, 0x7, 0xdf, 0x2, 0x2, 0x34e, 0x350, 0x7, 0x48, 0x2, 0x2, 0x34f, 
       0x351, 0x5, 0x132, 0x9a, 0x2, 0x350, 0x34f, 0x3, 0x2, 0x2, 0x2, 0x350, 
       0x351, 0x3, 0x2, 0x2, 0x2, 0x351, 0x354, 0x3, 0x2, 0x2, 0x2, 0x352, 
       0x354, 0x7, 0x9f, 0x2, 0x2, 0x353, 0x34e, 0x3, 0x2, 0x2, 0x2, 0x353, 
       0x352, 0x3, 0x2, 0x2, 0x2, 0x354, 0x355, 0x3, 0x2, 0x2, 0x2, 0x355, 
       0x356, 0x7, 0xdf, 0x2, 0x2, 0x356, 0x358, 0x5, 0x118, 0x8d, 0x2, 
       0x357, 0x359, 0x5, 0x132, 0x9a, 0x2, 0x358, 0x357, 0x3, 0x2, 0x2, 
       0x2, 0x358, 0x359, 0x3, 0x2, 0x2, 0x2, 0x359, 0x35a, 0x3, 0x2, 0x2, 
       0x2, 0x35a, 0x35b, 0x7, 0xdf, 0x2, 0x2, 0x35b, 0x35c, 0x7, 0x5b, 
       0x2, 0x2, 0x35c, 0x35d, 0x7, 0xdf, 0x2, 0x2, 0x35d, 0x362, 0x7, 0xd2, 
       0x2, 0x2, 0x35e, 0x35f, 0x7, 0xdf, 0x2, 0x2, 0x35f, 0x360, 0x7, 0x5, 
       0x2, 0x2, 0x360, 0x361, 0x7, 0xdf, 0x2, 0x2, 0x361, 0x363, 0x7, 0xd2, 
       0x2, 0x2, 0x362, 0x35e, 0x3, 0x2, 0x2, 0x2, 0x362, 0x363, 0x3, 0x2, 
       0x2, 0x2, 0x363, 0x368, 0x3, 0x2, 0x2, 0x2, 0x364, 0x366, 0x7, 0xdf, 
       0x2, 0x2, 0x365, 0x364, 0x3, 0x2, 0x2, 0x2, 0x365, 0x366, 0x3, 0x2, 
       0x2, 0x2, 0x366, 0x367, 0x3, 0x2, 0x2, 0x2, 0x367, 0x369, 0x5, 0x10e, 
       0x88, 0x2, 0x368, 0x365, 0x3, 0x2, 0x2, 0x2, 0x368, 0x369, 0x3, 0x2, 
       0x2, 0x2, 0x369, 0x36c, 0x3, 0x2, 0x2, 0x2, 0x36a, 0x36b, 0x7, 0xdf, 
       0x2, 0x2, 0x36b, 0x36d, 0x5, 0x11a, 0x8e, 0x2, 0x36c, 0x36a, 0x3, 
       0x2, 0x2, 0x2, 0x36c, 0x36d, 0x3, 0x2, 0x2, 0x2, 0x36d, 0x47, 0x3, 
       0x2, 0x2, 0x2, 0x36e, 0x36f, 0x9, 0x3, 0x2, 0x2, 0x36f, 0x370, 0x7, 
       0xdf, 0x2, 0x2, 0x370, 0x37b, 0x5, 0x126, 0x94, 0x2, 0x371, 0x373, 
       0x7, 0xdf, 0x2, 0x2, 0x372, 0x371, 0x3, 0x2, 0x2, 0x2, 0x372, 0x373, 
       0x3, 0x2, 0x2, 0x2, 0x373, 0x374, 0x3, 0x2, 0x2, 0x2, 0x374, 0x376, 
       0x7, 0xb8, 0x2, 0x2, 0x375, 0x377, 0x7, 0xdf, 0x2, 0x2, 0x376, 0x375, 
       0x3, 0x2, 0x2, 0x2, 0x376, 0x377, 0x3, 0x2, 0x2, 0x2, 0x377, 0x378, 
       0x3, 0x2, 0x2, 0x2, 0x378, 0x37a, 0x5, 0x126, 0x94, 0x2, 0x379, 0x372, 
       0x3, 0x2, 0x2, 0x2, 0x37a, 0x37d, 0x3, 0x2, 0x2, 0x2, 0x37b, 0x379, 
       0x3, 0x2, 0x2, 0x2, 0x37b, 0x37c, 0x3, 0x2, 0x2, 0x2, 0x37c, 0x49, 
       0x3, 0x2, 0x2, 0x2, 0x37d, 0x37b, 0x3, 0x2, 0x2, 0x2, 0x37e, 0x37f, 
       0x7, 0x29, 0x2, 0x2, 0x37f, 0x380, 0x7, 0xdf, 0x2, 0x2, 0x380, 0x382, 
       0x5, 0xde, 0x70, 0x2, 0x381, 0x383, 0x7, 0xdf, 0x2, 0x2, 0x382, 0x381, 
       0x3, 0x2, 0x2, 0x2, 0x382, 0x383, 0x3, 0x2, 0x2, 0x2, 0x383, 0x384, 
       0x3, 0x2, 0x2, 0x2, 0x384, 0x386, 0x7, 0xb8, 0x2, 0x2, 0x385, 0x387, 
       0x7, 0xdf, 0x2, 0x2, 0x386, 0x385, 0x3, 0x2, 0x2, 0x2, 0x386, 0x387, 
       0x3, 0x2, 0x2, 0x2, 0x387, 0x388, 0x3, 0x2, 0x2, 0x2, 0x388, 0x391, 
       0x5, 0xde, 0x70, 0x2, 0x389, 0x38b, 0x7, 0xdf, 0x2, 0x2, 0x38a, 0x389, 
       0x3, 0x2, 0x2, 0x2, 0x38a, 0x38b, 0x3, 0x2, 0x2, 0x2, 0x38b, 0x38c, 
       0x3, 0x2, 0x2, 0x2, 0x38c, 0x38e, 0x7, 0xb8, 0x2, 0x2, 0x38d, 0x38f, 
       0x7, 0xdf, 0x2, 0x2, 0x38e, 0x38d, 0x3, 0x2, 0x2, 0x2, 0x38e, 0x38f, 
       0x3, 0x2, 0x2, 0x2, 0x38f, 0x390, 0x3, 0x2, 0x2, 0x2, 0x390, 0x392, 
       0x5, 0xde, 0x70, 0x2, 0x391, 0x38a, 0x3, 0x2, 0x2, 0x2, 0x391, 0x392, 
       0x3, 0x2, 0x2, 0x2, 0x392, 0x4b, 0x3, 0x2, 0x2, 0x2, 0x393, 0x395, 
       0x7, 0x2b, 0x2, 0x2, 0x394, 0x396, 0x7, 0xdd, 0x2, 0x2, 0x395, 0x394, 
       0x3, 0x2, 0x2, 0x2, 0x396, 0x397, 0x3, 0x2, 0x2, 0x2, 0x397, 0x395, 
       0x3, 0x2, 0x2, 0x2, 0x397, 0x398, 0x3, 0x2, 0x2, 0x2, 0x398, 0x39f, 
       0x3, 0x2, 0x2, 0x2, 0x399, 0x39b, 0x5, 0x32, 0x1a, 0x2, 0x39a, 0x39c, 
       0x7, 0xdd, 0x2, 0x2, 0x39b, 0x39a, 0x3, 0x2, 0x2, 0x2, 0x39c, 0x39d, 
       0x3, 0x2, 0x2, 0x2, 0x39d, 0x39b, 0x3, 0x2, 0x2, 0x2, 0x39d, 0x39e, 
       0x3, 0x2, 0x2, 0x2, 0x39e, 0x3a0, 0x3, 0x2, 0x2, 0x2, 0x39f, 0x399, 
       0x3, 0x2, 0x2, 0x2, 0x39f, 0x3a0, 0x3, 0x2, 0x2, 0x2, 0x3a0, 0x3a1, 
       0x3, 0x2, 0x2, 0x2, 0x3a1, 0x3c9, 0x7, 0x58, 0x2, 0x2, 0x3a2, 0x3a3, 
       0x7, 0x2b, 0x2, 0x2, 0x3a3, 0x3a4, 0x7, 0xdf, 0x2, 0x2, 0x3a4, 0x3a5, 
       0x9, 0x4, 0x2, 0x2, 0x3a5, 0x3a6, 0x7, 0xdf, 0x2, 0x2, 0x3a6, 0x3a8, 
       0x5, 0xde, 0x70, 0x2, 0x3a7, 0x3a9, 0x7, 0xdd, 0x2, 0x2, 0x3a8, 0x3a7, 
       0x3, 0x2, 0x2, 0x2, 0x3a9, 0x3aa, 0x3, 0x2, 0x2, 0x2, 0x3aa, 0x3a8, 
       0x3, 0x2, 0x2, 0x2, 0x3aa, 0x3ab, 0x3, 0x2, 0x2, 0x2, 0x3ab, 0x3b2, 
       0x3, 0x2, 0x2, 0x2, 0x3ac, 0x3ae, 0x5, 0x32, 0x1a, 0x2, 0x3ad, 0x3af, 
       0x7, 0xdd, 0x2, 0x2, 0x3ae, 0x3ad, 0x3, 0x2, 0x2, 0x2, 0x3af, 0x3b0, 
       0x3, 0x2, 0x2, 0x2, 0x3b0, 0x3ae, 0x3, 0x2, 0x2, 0x2, 0x3b0, 0x3b1, 
       0x3, 0x2, 0x2, 0x2, 0x3b1, 0x3b3, 0x3, 0x2, 0x2, 0x2, 0x3b2, 0x3ac, 
       0x3, 0x2, 0x2, 0x2, 0x3b2, 0x3b3, 0x3, 0x2, 0x2, 0x2, 0x3b3, 0x3b4, 
       0x3, 0x2, 0x2, 0x2, 0x3b4, 0x3b5, 0x7, 0x58, 0x2, 0x2, 0x3b5, 0x3c9, 
       0x3, 0x2, 0x2, 0x2, 0x3b6, 0x3b8, 0x7, 0x2b, 0x2, 0x2, 0x3b7, 0x3b9, 
       0x7, 0xdd, 0x2, 0x2, 0x3b8, 0x3b7, 0x3, 0x2, 0x2, 0x2, 0x3b9, 0x3ba, 
       0x3, 0x2, 0x2, 0x2, 0x3ba, 0x3b8, 0x3, 0x2, 0x2, 0x2, 0x3ba, 0x3bb, 
       0x3, 0x2, 0x2, 0x2, 0x3bb, 0x3bc, 0x3, 0x2, 0x2, 0x2, 0x3bc, 0x3be, 
       0x5, 0x32, 0x1a, 0x2, 0x3bd, 0x3bf, 0x7, 0xdd, 0x2, 0x2, 0x3be, 0x3bd, 
       0x3, 0x2, 0x2, 0x2, 0x3bf, 0x3c0, 0x3, 0x2, 0x2, 0x2, 0x3c0, 0x3be, 
       0x3, 0x2, 0x2, 0x2, 0x3c0, 0x3c1, 0x3, 0x2, 0x2, 0x2, 0x3c1, 0x3c2, 
       0x3, 0x2, 0x2, 0x2, 0x3c2, 0x3c3, 0x7, 0x58, 0x2, 0x2, 0x3c3, 0x3c4, 
       0x7, 0xdf, 0x2, 0x2, 0x3c4, 0x3c5, 0x9, 0x4, 0x2, 0x2, 0x3c5, 0x3c6, 
       0x7, 0xdf, 0x2, 0x2, 0x3c6, 0x3c7, 0x5, 0xde, 0x70, 0x2, 0x3c7, 0x3c9, 
       0x3, 0x2, 0x2, 0x2, 0x3c8, 0x393, 0x3, 0x2, 0x2, 0x2, 0x3c8, 0x3a2, 
       0x3, 0x2, 0x2, 0x2, 0x3c8, 0x3b6, 0x3, 0x2, 0x2, 0x2, 0x3c9, 0x4d, 
       0x3, 0x2, 0x2, 0x2, 0x3ca, 0x3cb, 0x7, 0x38, 0x2, 0x2, 0x3cb, 0x4f, 
       0x3, 0x2, 0x2, 0x2, 0x3cc, 0x3cd, 0x5, 0x12c, 0x97, 0x2, 0x3cd, 0x3ce, 
       0x7, 0xdf, 0x2, 0x2, 0x3ce, 0x3d0, 0x3, 0x2, 0x2, 0x2, 0x3cf, 0x3cc, 
       0x3, 0x2, 0x2, 0x2, 0x3cf, 0x3d0, 0x3, 0x2, 0x2, 0x2, 0x3d0, 0x3d1, 
       0x3, 0x2, 0x2, 0x2, 0x3d1, 0x3d2, 0x7, 0x3a, 0x2, 0x2, 0x3d2, 0x3d3, 
       0x7, 0xdf, 0x2, 0x2, 0x3d3, 0x3d5, 0x5, 0x118, 0x8d, 0x2, 0x3d4, 
       0x3d6, 0x7, 0xdd, 0x2, 0x2, 0x3d5, 0x3d4, 0x3, 0x2, 0x2, 0x2, 0x3d6, 
       0x3d7, 0x3, 0x2, 0x2, 0x2, 0x3d7, 0x3d5, 0x3, 0x2, 0x2, 0x2, 0x3d7, 
       0x3d8, 0x3, 0x2, 0x2, 0x2, 0x3d8, 0x3dc, 0x3, 0x2, 0x2, 0x2, 0x3d9, 
       0x3db, 0x5, 0x52, 0x2a, 0x2, 0x3da, 0x3d9, 0x3, 0x2, 0x2, 0x2, 0x3db, 
       0x3de, 0x3, 0x2, 0x2, 0x2, 0x3dc, 0x3da, 0x3, 0x2, 0x2, 0x2, 0x3dc, 
       0x3dd, 0x3, 0x2, 0x2, 0x2, 0x3dd, 0x3df, 0x3, 0x2, 0x2, 0x2, 0x3de, 
       0x3dc, 0x3, 0x2, 0x2, 0x2, 0x3df, 0x3e0, 0x7, 0x30, 0x2, 0x2, 0x3e0, 
       0x51, 0x3, 0x2, 0x2, 0x2, 0x3e1, 0x3ea, 0x5, 0x118, 0x8d, 0x2, 0x3e2, 
       0x3e4, 0x7, 0xdf, 0x2, 0x2, 0x3e3, 0x3e2, 0x3, 0x2, 0x2, 0x2, 0x3e3, 
       0x3e4, 0x3, 0x2, 0x2, 0x2, 0x3e4, 0x3e5, 0x3, 0x2, 0x2, 0x2, 0x3e5, 
       0x3e7, 0x7, 0xbc, 0x2, 0x2, 0x3e6, 0x3e8, 0x7, 0xdf, 0x2, 0x2, 0x3e7, 
       0x3e6, 0x3, 0x2, 0x2, 0x2, 0x3e7, 0x3e8, 0x3, 0x2, 0x2, 0x2, 0x3e8, 
       0x3e9, 0x3, 0x2, 0x2, 0x2, 0x3e9, 0x3eb, 0x5, 0xde, 0x70, 0x2, 0x3ea, 
       0x3e3, 0x3, 0x2, 0x2, 0x2, 0x3ea, 0x3eb, 0x3, 0x2, 0x2, 0x2, 0x3eb, 
       0x3ed, 0x3, 0x2, 0x2, 0x2, 0x3ec, 0x3ee, 0x7, 0xdd, 0x2, 0x2, 0x3ed, 
       0x3ec, 0x3, 0x2, 0x2, 0x2, 0x3ee, 0x3ef, 0x3, 0x2, 0x2, 0x2, 0x3ef, 
       0x3ed, 0x3, 0x2, 0x2, 0x2, 0x3ef, 0x3f0, 0x3, 0x2, 0x2, 0x2, 0x3f0, 
       0x53, 0x3, 0x2, 0x2, 0x2, 0x3f1, 0x3f2, 0x7, 0x3c, 0x2, 0x2, 0x3f2, 
       0x3f3, 0x7, 0xdf, 0x2, 0x2, 0x3f3, 0x3fe, 0x5, 0xde, 0x70, 0x2, 0x3f4, 
       0x3f6, 0x7, 0xdf, 0x2, 0x2, 0x3f5, 0x3f4, 0x3, 0x2, 0x2, 0x2, 0x3f5, 
       0x3f6, 0x3, 0x2, 0x2, 0x2, 0x3f6, 0x3f7, 0x3, 0x2, 0x2, 0x2, 0x3f7, 
       0x3f9, 0x7, 0xb8, 0x2, 0x2, 0x3f8, 0x3fa, 0x7, 0xdf, 0x2, 0x2, 0x3f9, 
       0x3f8, 0x3, 0x2, 0x2, 0x2, 0x3f9, 0x3fa, 0x3, 0x2, 0x2, 0x2, 0x3fa, 
       0x3fb, 0x3, 0x2, 0x2, 0x2, 0x3fb, 0x3fd, 0x5, 0xde, 0x70, 0x2, 0x3fc, 
       0x3f5, 0x3, 0x2, 0x2, 0x2, 0x3fd, 0x400, 0x3, 0x2, 0x2, 0x2, 0x3fe, 
       0x3fc, 0x3, 0x2, 0x2, 0x2, 0x3fe, 0x3ff, 0x3, 0x2, 0x2, 0x2, 0x3ff, 
       0x55, 0x3, 0x2, 0x2, 0x2, 0x400, 0x3fe, 0x3, 0x2, 0x2, 0x2, 0x401, 
       0x402, 0x7, 0x3d, 0x2, 0x2, 0x402, 0x403, 0x7, 0xdf, 0x2, 0x2, 0x403, 
       0x404, 0x5, 0xde, 0x70, 0x2, 0x404, 0x57, 0x3, 0x2, 0x2, 0x2, 0x405, 
       0x406, 0x5, 0x134, 0x9b, 0x2, 0x406, 0x407, 0x7, 0xdf, 0x2, 0x2, 
       0x407, 0x409, 0x3, 0x2, 0x2, 0x2, 0x408, 0x405, 0x3, 0x2, 0x2, 0x2, 
       0x408, 0x409, 0x3, 0x2, 0x2, 0x2, 0x409, 0x40a, 0x3, 0x2, 0x2, 0x2, 
       0x40a, 0x40b, 0x7, 0x3e, 0x2, 0x2, 0x40b, 0x40c, 0x7, 0xdf, 0x2, 
       0x2, 0x40c, 0x40e, 0x5, 0x118, 0x8d, 0x2, 0x40d, 0x40f, 0x7, 0xdf, 
       0x2, 0x2, 0x40e, 0x40d, 0x3, 0x2, 0x2, 0x2, 0x40e, 0x40f, 0x3, 0x2, 
       0x2, 0x2, 0x40f, 0x410, 0x3, 0x2, 0x2, 0x2, 0x410, 0x411, 0x5, 0x10e, 
       0x88, 0x2, 0x411, 0x59, 0x3, 0x2, 0x2, 0x2, 0x412, 0x413, 0x9, 0x5, 
       0x2, 0x2, 0x413, 0x5b, 0x3, 0x2, 0x2, 0x2, 0x414, 0x415, 0x7, 0x45, 
       0x2, 0x2, 0x415, 0x416, 0x7, 0xdf, 0x2, 0x2, 0x416, 0x418, 0x5, 0xde, 
       0x70, 0x2, 0x417, 0x419, 0x7, 0xdf, 0x2, 0x2, 0x418, 0x417, 0x3, 
       0x2, 0x2, 0x2, 0x418, 0x419, 0x3, 0x2, 0x2, 0x2, 0x419, 0x41a, 0x3, 
       0x2, 0x2, 0x2, 0x41a, 0x41c, 0x7, 0xb8, 0x2, 0x2, 0x41b, 0x41d, 0x7, 
       0xdf, 0x2, 0x2, 0x41c, 0x41b, 0x3, 0x2, 0x2, 0x2, 0x41c, 0x41d, 0x3, 
       0x2, 0x2, 0x2, 0x41d, 0x41e, 0x3, 0x2, 0x2, 0x2, 0x41e, 0x41f, 0x5, 
       0xde, 0x70, 0x2, 0x41f, 0x5d, 0x3, 0x2, 0x2, 0x2, 0x420, 0x421, 0x7, 
       0x47, 0x2, 0x2, 0x421, 0x422, 0x7, 0xdf, 0x2, 0x2, 0x422, 0x423, 
       0x7, 0x2d, 0x2, 0x2, 0x423, 0x424, 0x7, 0xdf, 0x2, 0x2, 0x424, 0x426, 
       0x5, 0x118, 0x8d, 0x2, 0x425, 0x427, 0x5, 0x132, 0x9a, 0x2, 0x426, 
       0x425, 0x3, 0x2, 0x2, 0x2, 0x426, 0x427, 0x3, 0x2, 0x2, 0x2, 0x427, 
       0x428, 0x3, 0x2, 0x2, 0x2, 0x428, 0x429, 0x7, 0xdf, 0x2, 0x2, 0x429, 
       0x42a, 0x7, 0x50, 0x2, 0x2, 0x42a, 0x42b, 0x7, 0xdf, 0x2, 0x2, 0x42b, 
       0x42d, 0x5, 0xde, 0x70, 0x2, 0x42c, 0x42e, 0x7, 0xdd, 0x2, 0x2, 0x42d, 
       0x42c, 0x3, 0x2, 0x2, 0x2, 0x42e, 0x42f, 0x3, 0x2, 0x2, 0x2, 0x42f, 
       0x42d, 0x3, 0x2, 0x2, 0x2, 0x42f, 0x430, 0x3, 0x2, 0x2, 0x2, 0x430, 
       0x437, 0x3, 0x2, 0x2, 0x2, 0x431, 0x433, 0x5, 0x32, 0x1a, 0x2, 0x432, 
       0x434, 0x7, 0xdd, 0x2, 0x2, 0x433, 0x432, 0x3, 0x2, 0x2, 0x2, 0x434, 
       0x435, 0x3, 0x2, 0x2, 0x2, 0x435, 0x433, 0x3, 0x2, 0x2, 0x2, 0x435, 
       0x436, 0x3, 0x2, 0x2, 0x2, 0x436, 0x438, 0x3, 0x2, 0x2, 0x2, 0x437, 
       0x431, 0x3, 0x2, 0x2, 0x2, 0x437, 0x438, 0x3, 0x2, 0x2, 0x2, 0x438, 
       0x439, 0x3, 0x2, 0x2, 0x2, 0x439, 0x43c, 0x7, 0x6b, 0x2, 0x2, 0x43a, 
       0x43b, 0x7, 0xdf, 0x2, 0x2, 0x43b, 0x43d, 0x5, 0x118, 0x8d, 0x2, 
       0x43c, 0x43a, 0x3, 0x2, 0x2, 0x2, 0x43c, 0x43d, 0x3, 0x2, 0x2, 0x2, 
       0x43d, 0x5f, 0x3, 0x2, 0x2, 0x2, 0x43e, 0x43f, 0x7, 0x47, 0x2, 0x2, 
       0x43f, 0x440, 0x7, 0xdf, 0x2, 0x2, 0x440, 0x442, 0x5, 0xfc, 0x7f, 
       0x2, 0x441, 0x443, 0x5, 0x132, 0x9a, 0x2, 0x442, 0x441, 0x3, 0x2, 
       0x2, 0x2, 0x442, 0x443, 0x3, 0x2, 0x2, 0x2, 0x443, 0x446, 0x3, 0x2, 
       0x2, 0x2, 0x444, 0x445, 0x7, 0xdf, 0x2, 0x2, 0x445, 0x447, 0x5, 0x11a, 
       0x8e, 0x2, 0x446, 0x444, 0x3, 0x2, 0x2, 0x2, 0x446, 0x447, 0x3, 0x2, 
       0x2, 0x2, 0x447, 0x449, 0x3, 0x2, 0x2, 0x2, 0x448, 0x44a, 0x7, 0xdf, 
       0x2, 0x2, 0x449, 0x448, 0x3, 0x2, 0x2, 0x2, 0x449, 0x44a, 0x3, 0x2, 
       0x2, 0x2, 0x44a, 0x44b, 0x3, 0x2, 0x2, 0x2, 0x44b, 0x44d, 0x7, 0xbc, 
       0x2, 0x2, 0x44c, 0x44e, 0x7, 0xdf, 0x2, 0x2, 0x44d, 0x44c, 0x3, 0x2, 
       0x2, 0x2, 0x44d, 0x44e, 0x3, 0x2, 0x2, 0x2, 0x44e, 0x44f, 0x3, 0x2, 
       0x2, 0x2, 0x44f, 0x450, 0x5, 0xde, 0x70, 0x2, 0x450, 0x451, 0x7, 
       0xdf, 0x2, 0x2, 0x451, 0x452, 0x7, 0xa4, 0x2, 0x2, 0x452, 0x453, 
       0x7, 0xdf, 0x2, 0x2, 0x453, 0x458, 0x5, 0xde, 0x70, 0x2, 0x454, 0x455, 
       0x7, 0xdf, 0x2, 0x2, 0x455, 0x456, 0x7, 0x9c, 0x2, 0x2, 0x456, 0x457, 
       0x7, 0xdf, 0x2, 0x2, 0x457, 0x459, 0x5, 0xde, 0x70, 0x2, 0x458, 0x454, 
       0x3, 0x2, 0x2, 0x2, 0x458, 0x459, 0x3, 0x2, 0x2, 0x2, 0x459, 0x45b, 
       0x3, 0x2, 0x2, 0x2, 0x45a, 0x45c, 0x7, 0xdd, 0x2, 0x2, 0x45b, 0x45a, 
       0x3, 0x2, 0x2, 0x2, 0x45c, 0x45d, 0x3, 0x2, 0x2, 0x2, 0x45d, 0x45b, 
       0x3, 0x2, 0x2, 0x2, 0x45d, 0x45e, 0x3, 0x2, 0x2, 0x2, 0x45e, 0x465, 
       0x3, 0x2, 0x2, 0x2, 0x45f, 0x461, 0x5, 0x32, 0x1a, 0x2, 0x460, 0x462, 
       0x7, 0xdd, 0x2, 0x2, 0x461, 0x460, 0x3, 0x2, 0x2, 0x2, 0x462, 0x463, 
       0x3, 0x2, 0x2, 0x2, 0x463, 0x461, 0x3, 0x2, 0x2, 0x2, 0x463, 0x464, 
       0x3, 0x2, 0x2, 0x2, 0x464, 0x466, 0x3, 0x2, 0x2, 0x2, 0x465, 0x45f, 
       0x3, 0x2, 0x2, 0x2, 0x465, 0x466, 0x3, 0x2, 0x2, 0x2, 0x466, 0x467, 
       0x3, 0x2, 0x2, 0x2, 0x467, 0x46d, 0x7, 0x6b, 0x2, 0x2, 0x468, 0x469, 
       0x7, 0xdf, 0x2, 0x2, 0x469, 0x46b, 0x5, 0x118, 0x8d, 0x2, 0x46a, 
       0x46c, 0x5, 0x132, 0x9a, 0x2, 0x46b, 0x46a, 0x3, 0x2, 0x2, 0x2, 0x46b, 
       0x46c, 0x3, 0x2, 0x2, 0x2, 0x46c, 0x46e, 0x3, 0x2, 0x2, 0x2, 0x46d, 
       0x468, 0x3, 0x2, 0x2, 0x2, 0x46d, 0x46e, 0x3, 0x2, 0x2, 0x2, 0x46e, 
       0x61, 0x3, 0x2, 0x2, 0x2, 0x46f, 0x470, 0x5, 0x134, 0x9b, 0x2, 0x470, 
       0x471, 0x7, 0xdf, 0x2, 0x2, 0x471, 0x473, 0x3, 0x2, 0x2, 0x2, 0x472, 
       0x46f, 0x3, 0x2, 0x2, 0x2, 0x472, 0x473, 0x3, 0x2, 0x2, 0x2, 0x473, 
       0x476, 0x3, 0x2, 0x2, 0x2, 0x474, 0x475, 0x7, 0x9b, 0x2, 0x2, 0x475, 
       0x477, 0x7, 0xdf, 0x2, 0x2, 0x476, 0x474, 0x3, 0x2, 0x2, 0x2, 0x476, 
       0x477, 0x3, 0x2, 0x2, 0x2, 0x477, 0x478, 0x3, 0x2, 0x2, 0x2, 0x478, 
       0x479, 0x7, 0x48, 0x2, 0x2, 0x479, 0x47a, 0x7, 0xdf, 0x2, 0x2, 0x47a, 
       0x47f, 0x5, 0x118, 0x8d, 0x2, 0x47b, 0x47d, 0x7, 0xdf, 0x2, 0x2, 
       0x47c, 0x47b, 0x3, 0x2, 0x2, 0x2, 0x47c, 0x47d, 0x3, 0x2, 0x2, 0x2, 
       0x47d, 0x47e, 0x3, 0x2, 0x2, 0x2, 0x47e, 0x480, 0x5, 0x10e, 0x88, 
       0x2, 0x47f, 0x47c, 0x3, 0x2, 0x2, 0x2, 0x47f, 0x480, 0x3, 0x2, 0x2, 
       0x2, 0x480, 0x483, 0x3, 0x2, 0x2, 0x2, 0x481, 0x482, 0x7, 0xdf, 0x2, 
       0x2, 0x482, 0x484, 0x5, 0x11a, 0x8e, 0x2, 0x483, 0x481, 0x3, 0x2, 
       0x2, 0x2, 0x483, 0x484, 0x3, 0x2, 0x2, 0x2, 0x484, 0x486, 0x3, 0x2, 
       0x2, 0x2, 0x485, 0x487, 0x7, 0xdd, 0x2, 0x2, 0x486, 0x485, 0x3, 0x2, 
       0x2, 0x2, 0x487, 0x488, 0x3, 0x2, 0x2, 0x2, 0x488, 0x486, 0x3, 0x2, 
       0x2, 0x2, 0x488, 0x489, 0x3, 0x2, 0x2, 0x2, 0x489, 0x490, 0x3, 0x2, 
       0x2, 0x2, 0x48a, 0x48c, 0x5, 0x32, 0x1a, 0x2, 0x48b, 0x48d, 0x7, 
       0xdd, 0x2, 0x2, 0x48c, 0x48b, 0x3, 0x2, 0x2, 0x2, 0x48d, 0x48e, 0x3, 
       0x2, 0x2, 0x2, 0x48e, 0x48c, 0x3, 0x2, 0x2, 0x2, 0x48e, 0x48f, 0x3, 
       0x2, 0x2, 0x2, 0x48f, 0x491, 0x3, 0x2, 0x2, 0x2, 0x490, 0x48a, 0x3, 
       0x2, 0x2, 0x2, 0x490, 0x491, 0x3, 0x2, 0x2, 0x2, 0x491, 0x492, 0x3, 
       0x2, 0x2, 0x2, 0x492, 0x493, 0x7, 0x31, 0x2, 0x2, 0x493, 0x63, 0x3, 
       0x2, 0x2, 0x2, 0x494, 0x495, 0x7, 0x49, 0x2, 0x2, 0x495, 0x496, 0x7, 
       0xdf, 0x2, 0x2, 0x496, 0x498, 0x5, 0xde, 0x70, 0x2, 0x497, 0x499, 
       0x7, 0xdf, 0x2, 0x2, 0x498, 0x497, 0x3, 0x2, 0x2, 0x2, 0x498, 0x499, 
       0x3, 0x2, 0x2, 0x2, 0x499, 0x49a, 0x3, 0x2, 0x2, 0x2, 0x49a, 0x49c, 
       0x7, 0xb8, 0x2, 0x2, 0x49b, 0x49d, 0x7, 0xdf, 0x2, 0x2, 0x49c, 0x49b, 
       0x3, 0x2, 0x2, 0x2, 0x49c, 0x49d, 0x3, 0x2, 0x2, 0x2, 0x49d, 0x49f, 
       0x3, 0x2, 0x2, 0x2, 0x49e, 0x4a0, 0x5, 0xde, 0x70, 0x2, 0x49f, 0x49e, 
       0x3, 0x2, 0x2, 0x2, 0x49f, 0x4a0, 0x3, 0x2, 0x2, 0x2, 0x4a0, 0x4a2, 
       0x3, 0x2, 0x2, 0x2, 0x4a1, 0x4a3, 0x7, 0xdf, 0x2, 0x2, 0x4a2, 0x4a1, 
       0x3, 0x2, 0x2, 0x2, 0x4a2, 0x4a3, 0x3, 0x2, 0x2, 0x2, 0x4a3, 0x4a4, 
       0x3, 0x2, 0x2, 0x2, 0x4a4, 0x4a6, 0x7, 0xb8, 0x2, 0x2, 0x4a5, 0x4a7, 
       0x7, 0xdf, 0x2, 0x2, 0x4a6, 0x4a5, 0x3, 0x2, 0x2, 0x2, 0x4a6, 0x4a7, 
       0x3, 0x2, 0x2, 0x2, 0x4a7, 0x4a8, 0x3, 0x2, 0x2, 0x2, 0x4a8, 0x4a9, 
       0x5, 0xde, 0x70, 0x2, 0x4a9, 0x65, 0x3, 0x2, 0x2, 0x2, 0x4aa, 0x4ab, 
       0x7, 0x4b, 0x2, 0x2, 0x4ab, 0x4ac, 0x7, 0xdf, 0x2, 0x2, 0x4ac, 0x4ad, 
       0x5, 0xde, 0x70, 0x2, 0x4ad, 0x67, 0x3, 0x2, 0x2, 0x2, 0x4ae, 0x4af, 
       0x7, 0x4c, 0x2, 0x2, 0x4af, 0x4b0, 0x7, 0xdf, 0x2, 0x2, 0x4b0, 0x4b1, 
       0x5, 0xde, 0x70, 0x2, 0x4b1, 0x69, 0x3, 0x2, 0x2, 0x2, 0x4b2, 0x4b3, 
       0x7, 0x4d, 0x2, 0x2, 0x4b3, 0x4b4, 0x7, 0xdf, 0x2, 0x2, 0x4b4, 0x4b5, 
       0x5, 0x6e, 0x38, 0x2, 0x4b5, 0x4b6, 0x7, 0xdf, 0x2, 0x2, 0x4b6, 0x4b7, 
       0x7, 0xa2, 0x2, 0x2, 0x4b7, 0x4b8, 0x7, 0xdf, 0x2, 0x2, 0x4b8, 0x4bd, 
       0x5, 0x34, 0x1b, 0x2, 0x4b9, 0x4ba, 0x7, 0xdf, 0x2, 0x2, 0x4ba, 0x4bb, 
       0x7, 0x2e, 0x2, 0x2, 0x4bb, 0x4bc, 0x7, 0xdf, 0x2, 0x2, 0x4bc, 0x4be, 
       0x5, 0x34, 0x1b, 0x2, 0x4bd, 0x4b9, 0x3, 0x2, 0x2, 0x2, 0x4bd, 0x4be, 
       0x3, 0x2, 0x2, 0x2, 0x4be, 0x4cc, 0x3, 0x2, 0x2, 0x2, 0x4bf, 0x4c3, 
       0x5, 0x6c, 0x37, 0x2, 0x4c0, 0x4c2, 0x5, 0x70, 0x39, 0x2, 0x4c1, 
       0x4c0, 0x3, 0x2, 0x2, 0x2, 0x4c2, 0x4c5, 0x3, 0x2, 0x2, 0x2, 0x4c3, 
       0x4c1, 0x3, 0x2, 0x2, 0x2, 0x4c3, 0x4c4, 0x3, 0x2, 0x2, 0x2, 0x4c4, 
       0x4c7, 0x3, 0x2, 0x2, 0x2, 0x4c5, 0x4c3, 0x3, 0x2, 0x2, 0x2, 0x4c6, 
       0x4c8, 0x5, 0x72, 0x3a, 0x2, 0x4c7, 0x4c6, 0x3, 0x2, 0x2, 0x2, 0x4c7, 
       0x4c8, 0x3, 0x2, 0x2, 0x2, 0x4c8, 0x4c9, 0x3, 0x2, 0x2, 0x2, 0x4c9, 
       0x4ca, 0x7, 0x32, 0x2, 0x2, 0x4ca, 0x4cc, 0x3, 0x2, 0x2, 0x2, 0x4cb, 
       0x4b2, 0x3, 0x2, 0x2, 0x2, 0x4cb, 0x4bf, 0x3, 0x2, 0x2, 0x2, 0x4cc, 
       0x6b, 0x3, 0x2, 0x2, 0x2, 0x4cd, 0x4ce, 0x7, 0x4d, 0x2, 0x2, 0x4ce, 
       0x4cf, 0x7, 0xdf, 0x2, 0x2, 0x4cf, 0x4d0, 0x5, 0x6e, 0x38, 0x2, 0x4d0, 
       0x4d1, 0x7, 0xdf, 0x2, 0x2, 0x4d1, 0x4d3, 0x7, 0xa2, 0x2, 0x2, 0x4d2, 
       0x4d4, 0x7, 0xdd, 0x2, 0x2, 0x4d3, 0x4d2, 0x3, 0x2, 0x2, 0x2, 0x4d4, 
       0x4d5, 0x3, 0x2, 0x2, 0x2, 0x4d5, 0x4d3, 0x3, 0x2, 0x2, 0x2, 0x4d5, 
       0x4d6, 0x3, 0x2, 0x2, 0x2, 0x4d6, 0x4dd, 0x3, 0x2, 0x2, 0x2, 0x4d7, 
       0x4d9, 0x5, 0x32, 0x1a, 0x2, 0x4d8, 0x4da, 0x7, 0xdd, 0x2, 0x2, 0x4d9, 
       0x4d8, 0x3, 0x2, 0x2, 0x2, 0x4da, 0x4db, 0x3, 0x2, 0x2, 0x2, 0x4db, 
       0x4d9, 0x3, 0x2, 0x2, 0x2, 0x4db, 0x4dc, 0x3, 0x2, 0x2, 0x2, 0x4dc, 
       0x4de, 0x3, 0x2, 0x2, 0x2, 0x4dd, 0x4d7, 0x3, 0x2, 0x2, 0x2, 0x4dd, 
       0x4de, 0x3, 0x2, 0x2, 0x2, 0x4de, 0x6d, 0x3, 0x2, 0x2, 0x2, 0x4df, 
       0x4e0, 0x5, 0xde, 0x70, 0x2, 0x4e0, 0x6f, 0x3, 0x2, 0x2, 0x2, 0x4e1, 
       0x4e2, 0x7, 0x2f, 0x2, 0x2, 0x4e2, 0x4e3, 0x7, 0xdf, 0x2, 0x2, 0x4e3, 
       0x4e4, 0x5, 0x6e, 0x38, 0x2, 0x4e4, 0x4e5, 0x7, 0xdf, 0x2, 0x2, 0x4e5, 
       0x4e7, 0x7, 0xa2, 0x2, 0x2, 0x4e6, 0x4e8, 0x7, 0xdd, 0x2, 0x2, 0x4e7, 
       0x4e6, 0x3, 0x2, 0x2, 0x2, 0x4e8, 0x4e9, 0x3, 0x2, 0x2, 0x2, 0x4e9, 
       0x4e7, 0x3, 0x2, 0x2, 0x2, 0x4e9, 0x4ea, 0x3, 0x2, 0x2, 0x2, 0x4ea, 
       0x4f1, 0x3, 0x2, 0x2, 0x2, 0x4eb, 0x4ed, 0x5, 0x32, 0x1a, 0x2, 0x4ec, 
       0x4ee, 0x7, 0xdd, 0x2, 0x2, 0x4ed, 0x4ec, 0x3, 0x2, 0x2, 0x2, 0x4ee, 
       0x4ef, 0x3, 0x2, 0x2, 0x2, 0x4ef, 0x4ed, 0x3, 0x2, 0x2, 0x2, 0x4ef, 
       0x4f0, 0x3, 0x2, 0x2, 0x2, 0x4f0, 0x4f2, 0x3, 0x2, 0x2, 0x2, 0x4f1, 
       0x4eb, 0x3, 0x2, 0x2, 0x2, 0x4f1, 0x4f2, 0x3, 0x2, 0x2, 0x2, 0x4f2, 
       0x71, 0x3, 0x2, 0x2, 0x2, 0x4f3, 0x4f5, 0x7, 0x2e, 0x2, 0x2, 0x4f4, 
       0x4f6, 0x7, 0xdd, 0x2, 0x2, 0x4f5, 0x4f4, 0x3, 0x2, 0x2, 0x2, 0x4f6, 
       0x4f7, 0x3, 0x2, 0x2, 0x2, 0x4f7, 0x4f5, 0x3, 0x2, 0x2, 0x2, 0x4f7, 
       0x4f8, 0x3, 0x2, 0x2, 0x2, 0x4f8, 0x4ff, 0x3, 0x2, 0x2, 0x2, 0x4f9, 
       0x4fb, 0x5, 0x32, 0x1a, 0x2, 0x4fa, 0x4fc, 0x7, 0xdd, 0x2, 0x2, 0x4fb, 
       0x4fa, 0x3, 0x2, 0x2, 0x2, 0x4fc, 0x4fd, 0x3, 0x2, 0x2, 0x2, 0x4fd, 
       0x4fb, 0x3, 0x2, 0x2, 0x2, 0x4fd, 0x4fe, 0x3, 0x2, 0x2, 0x2, 0x4fe, 
       0x500, 0x3, 0x2, 0x2, 0x2, 0x4ff, 0x4f9, 0x3, 0x2, 0x2, 0x2, 0x4ff, 
       0x500, 0x3, 0x2, 0x2, 0x2, 0x500, 0x73, 0x3, 0x2, 0x2, 0x2, 0x501, 
       0x502, 0x7, 0x4f, 0x2, 0x2, 0x502, 0x503, 0x7, 0xdf, 0x2, 0x2, 0x503, 
       0x504, 0x5, 0x118, 0x8d, 0x2, 0x504, 0x75, 0x3, 0x2, 0x2, 0x2, 0x505, 
       0x506, 0x7, 0x51, 0x2, 0x2, 0x506, 0x507, 0x7, 0xdf, 0x2, 0x2, 0x507, 
       0x510, 0x5, 0xde, 0x70, 0x2, 0x508, 0x50a, 0x7, 0xdf, 0x2, 0x2, 0x509, 
       0x508, 0x3, 0x2, 0x2, 0x2, 0x509, 0x50a, 0x3, 0x2, 0x2, 0x2, 0x50a, 
       0x50b, 0x3, 0x2, 0x2, 0x2, 0x50b, 0x50d, 0x7, 0xb8, 0x2, 0x2, 0x50c, 
       0x50e, 0x7, 0xdf, 0x2, 0x2, 0x50d, 0x50c, 0x3, 0x2, 0x2, 0x2, 0x50d, 
       0x50e, 0x3, 0x2, 0x2, 0x2, 0x50e, 0x50f, 0x3, 0x2, 0x2, 0x2, 0x50f, 
       0x511, 0x5, 0xde, 0x70, 0x2, 0x510, 0x509, 0x3, 0x2, 0x2, 0x2, 0x511, 
       0x512, 0x3, 0x2, 0x2, 0x2, 0x512, 0x510, 0x3, 0x2, 0x2, 0x2, 0x512, 
       0x513, 0x3, 0x2, 0x2, 0x2, 0x513, 0x77, 0x3, 0x2, 0x2, 0x2, 0x514, 
       0x515, 0x7, 0x54, 0x2, 0x2, 0x515, 0x516, 0x7, 0xdf, 0x2, 0x2, 0x516, 
       0x517, 0x5, 0xde, 0x70, 0x2, 0x517, 0x79, 0x3, 0x2, 0x2, 0x2, 0x518, 
       0x519, 0x7, 0x5a, 0x2, 0x2, 0x519, 0x51b, 0x7, 0xdf, 0x2, 0x2, 0x51a, 
       0x518, 0x3, 0x2, 0x2, 0x2, 0x51a, 0x51b, 0x3, 0x2, 0x2, 0x2, 0x51b, 
       0x51c, 0x3, 0x2, 0x2, 0x2, 0x51c, 0x51e, 0x5, 0xfa, 0x7e, 0x2, 0x51d, 
       0x51f, 0x7, 0xdf, 0x2, 0x2, 0x51e, 0x51d, 0x3, 0x2, 0x2, 0x2, 0x51e, 
       0x51f, 0x3, 0x2, 0x2, 0x2, 0x51f, 0x520, 0x3, 0x2, 0x2, 0x2, 0x520, 
       0x522, 0x9, 0x6, 0x2, 0x2, 0x521, 0x523, 0x7, 0xdf, 0x2, 0x2, 0x522, 
       0x521, 0x3, 0x2, 0x2, 0x2, 0x522, 0x523, 0x3, 0x2, 0x2, 0x2, 0x523, 
       0x524, 0x3, 0x2, 0x2, 0x2, 0x524, 0x525, 0x5, 0xde, 0x70, 0x2, 0x525, 
       0x7b, 0x3, 0x2, 0x2, 0x2, 0x526, 0x527, 0x7, 0x5d, 0x2, 0x2, 0x527, 
       0x528, 0x7, 0xdf, 0x2, 0x2, 0x528, 0x52a, 0x5, 0xde, 0x70, 0x2, 0x529, 
       0x52b, 0x7, 0xdf, 0x2, 0x2, 0x52a, 0x529, 0x3, 0x2, 0x2, 0x2, 0x52a, 
       0x52b, 0x3, 0x2, 0x2, 0x2, 0x52b, 0x52c, 0x3, 0x2, 0x2, 0x2, 0x52c, 
       0x52e, 0x7, 0xb8, 0x2, 0x2, 0x52d, 0x52f, 0x7, 0xdf, 0x2, 0x2, 0x52e, 
       0x52d, 0x3, 0x2, 0x2, 0x2, 0x52e, 0x52f, 0x3, 0x2, 0x2, 0x2, 0x52f, 
       0x530, 0x3, 0x2, 0x2, 0x2, 0x530, 0x531, 0x5, 0xde, 0x70, 0x2, 0x531, 
       0x7d, 0x3, 0x2, 0x2, 0x2, 0x532, 0x533, 0x7, 0x55, 0x2, 0x2, 0x533, 
       0x534, 0x7, 0xdf, 0x2, 0x2, 0x534, 0x535, 0x5, 0xde, 0x70, 0x2, 0x535, 
       0x7f, 0x3, 0x2, 0x2, 0x2, 0x536, 0x537, 0x7, 0x56, 0x2, 0x2, 0x537, 
       0x538, 0x7, 0xdf, 0x2, 0x2, 0x538, 0x547, 0x5, 0xde, 0x70, 0x2, 0x539, 
       0x53b, 0x7, 0xdf, 0x2, 0x2, 0x53a, 0x539, 0x3, 0x2, 0x2, 0x2, 0x53a, 
       0x53b, 0x3, 0x2, 0x2, 0x2, 0x53b, 0x53c, 0x3, 0x2, 0x2, 0x2, 0x53c, 
       0x53e, 0x7, 0xb8, 0x2, 0x2, 0x53d, 0x53f, 0x7, 0xdf, 0x2, 0x2, 0x53e, 
       0x53d, 0x3, 0x2, 0x2, 0x2, 0x53e, 0x53f, 0x3, 0x2, 0x2, 0x2, 0x53f, 
       0x540, 0x3, 0x2, 0x2, 0x2, 0x540, 0x545, 0x5, 0xde, 0x70, 0x2, 0x541, 
       0x542, 0x7, 0xdf, 0x2, 0x2, 0x542, 0x543, 0x7, 0xa4, 0x2, 0x2, 0x543, 
       0x544, 0x7, 0xdf, 0x2, 0x2, 0x544, 0x546, 0x5, 0xde, 0x70, 0x2, 0x545, 
       0x541, 0x3, 0x2, 0x2, 0x2, 0x545, 0x546, 0x3, 0x2, 0x2, 0x2, 0x546, 
       0x548, 0x3, 0x2, 0x2, 0x2, 0x547, 0x53a, 0x3, 0x2, 0x2, 0x2, 0x547, 
       0x548, 0x3, 0x2, 0x2, 0x2, 0x548, 0x81, 0x3, 0x2, 0x2, 0x2, 0x549, 
       0x54a, 0x7, 0x61, 0x2, 0x2, 0x54a, 0x54b, 0x7, 0xdf, 0x2, 0x2, 0x54b, 
       0x54d, 0x5, 0xfa, 0x7e, 0x2, 0x54c, 0x54e, 0x7, 0xdf, 0x2, 0x2, 0x54d, 
       0x54c, 0x3, 0x2, 0x2, 0x2, 0x54d, 0x54e, 0x3, 0x2, 0x2, 0x2, 0x54e, 
       0x54f, 0x3, 0x2, 0x2, 0x2, 0x54f, 0x551, 0x7, 0xbc, 0x2, 0x2, 0x550, 
       0x552, 0x7, 0xdf, 0x2, 0x2, 0x551, 0x550, 0x3, 0x2, 0x2, 0x2, 0x551, 
       0x552, 0x3, 0x2, 0x2, 0x2, 0x552, 0x553, 0x3, 0x2, 0x2, 0x2, 0x553, 
       0x554, 0x5, 0xde, 0x70, 0x2, 0x554, 0x83, 0x3, 0x2, 0x2, 0x2, 0x555, 
       0x559, 0x5, 0x86, 0x44, 0x2, 0x556, 0x558, 0x5, 0x88, 0x45, 0x2, 
       0x557, 0x556, 0x3, 0x2, 0x2, 0x2, 0x558, 0x55b, 0x3, 0x2, 0x2, 0x2, 
       0x559, 0x557, 0x3, 0x2, 0x2, 0x2, 0x559, 0x55a, 0x3, 0x2, 0x2, 0x2, 
       0x55a, 0x55d, 0x3, 0x2, 0x2, 0x2, 0x55b, 0x559, 0x3, 0x2, 0x2, 0x2, 
       0x55c, 0x55e, 0x5, 0x8a, 0x46, 0x2, 0x55d, 0x55c, 0x3, 0x2, 0x2, 
       0x2, 0x55d, 0x55e, 0x3, 0x2, 0x2, 0x2, 0x55e, 0x55f, 0x3, 0x2, 0x2, 
       0x2, 0x55f, 0x560, 0x7, 0x65, 0x2, 0x2, 0x560, 0x85, 0x3, 0x2, 0x2, 
       0x2, 0x561, 0x562, 0x7, 0x62, 0x2, 0x2, 0x562, 0x563, 0x7, 0xdf, 
       0x2, 0x2, 0x563, 0x564, 0x5, 0x6e, 0x38, 0x2, 0x564, 0x565, 0x7, 
       0xdf, 0x2, 0x2, 0x565, 0x567, 0x7, 0xa2, 0x2, 0x2, 0x566, 0x568, 
       0x7, 0xdd, 0x2, 0x2, 0x567, 0x566, 0x3, 0x2, 0x2, 0x2, 0x568, 0x569, 
       0x3, 0x2, 0x2, 0x2, 0x569, 0x567, 0x3, 0x2, 0x2, 0x2, 0x569, 0x56a, 
       0x3, 0x2, 0x2, 0x2, 0x56a, 0x571, 0x3, 0x2, 0x2, 0x2, 0x56b, 0x56d, 
       0x5, 0x1a, 0xe, 0x2, 0x56c, 0x56e, 0x7, 0xdd, 0x2, 0x2, 0x56d, 0x56c, 
       0x3, 0x2, 0x2, 0x2, 0x56e, 0x56f, 0x3, 0x2, 0x2, 0x2, 0x56f, 0x56d, 
       0x3, 0x2, 0x2, 0x2, 0x56f, 0x570, 0x3, 0x2, 0x2, 0x2, 0x570, 0x572, 
       0x3, 0x2, 0x2, 0x2, 0x571, 0x56b, 0x3, 0x2, 0x2, 0x2, 0x571, 0x572, 
       0x3, 0x2, 0x2, 0x2, 0x572, 0x87, 0x3, 0x2, 0x2, 0x2, 0x573, 0x574, 
       0x7, 0x63, 0x2, 0x2, 0x574, 0x575, 0x7, 0xdf, 0x2, 0x2, 0x575, 0x576, 
       0x5, 0x6e, 0x38, 0x2, 0x576, 0x577, 0x7, 0xdf, 0x2, 0x2, 0x577, 0x579, 
       0x7, 0xa2, 0x2, 0x2, 0x578, 0x57a, 0x7, 0xdd, 0x2, 0x2, 0x579, 0x578, 
       0x3, 0x2, 0x2, 0x2, 0x57a, 0x57b, 0x3, 0x2, 0x2, 0x2, 0x57b, 0x579, 
       0x3, 0x2, 0x2, 0x2, 0x57b, 0x57c, 0x3, 0x2, 0x2, 0x2, 0x57c, 0x583, 
       0x3, 0x2, 0x2, 0x2, 0x57d, 0x57f, 0x5, 0x1a, 0xe, 0x2, 0x57e, 0x580, 
       0x7, 0xdd, 0x2, 0x2, 0x57f, 0x57e, 0x3, 0x2, 0x2, 0x2, 0x580, 0x581, 
       0x3, 0x2, 0x2, 0x2, 0x581, 0x57f, 0x3, 0x2, 0x2, 0x2, 0x581, 0x582, 
       0x3, 0x2, 0x2, 0x2, 0x582, 0x584, 0x3, 0x2, 0x2, 0x2, 0x583, 0x57d, 
       0x3, 0x2, 0x2, 0x2, 0x583, 0x584, 0x3, 0x2, 0x2, 0x2, 0x584, 0x89, 
       0x3, 0x2, 0x2, 0x2, 0x585, 0x587, 0x7, 0x64, 0x2, 0x2, 0x586, 0x588, 
       0x7, 0xdd, 0x2, 0x2, 0x587, 0x586, 0x3, 0x2, 0x2, 0x2, 0x588, 0x589, 
       0x3, 0x2, 0x2, 0x2, 0x589, 0x587, 0x3, 0x2, 0x2, 0x2, 0x589, 0x58a, 
       0x3, 0x2, 0x2, 0x2, 0x58a, 0x591, 0x3, 0x2, 0x2, 0x2, 0x58b, 0x58d, 
       0x5, 0x1a, 0xe, 0x2, 0x58c, 0x58e, 0x7, 0xdd, 0x2, 0x2, 0x58d, 0x58c, 
       0x3, 0x2, 0x2, 0x2, 0x58e, 0x58f, 0x3, 0x2, 0x2, 0x2, 0x58f, 0x58d, 
       0x3, 0x2, 0x2, 0x2, 0x58f, 0x590, 0x3, 0x2, 0x2, 0x2, 0x590, 0x592, 
       0x3, 0x2, 0x2, 0x2, 0x591, 0x58b, 0x3, 0x2, 0x2, 0x2, 0x591, 0x592, 
       0x3, 0x2, 0x2, 0x2, 0x592, 0x8b, 0x3, 0x2, 0x2, 0x2, 0x593, 0x595, 
       0x7, 0x67, 0x2, 0x2, 0x594, 0x596, 0x7, 0xdf, 0x2, 0x2, 0x595, 0x594, 
       0x3, 0x2, 0x2, 0x2, 0x595, 0x596, 0x3, 0x2, 0x2, 0x2, 0x596, 0x597, 
       0x3, 0x2, 0x2, 0x2, 0x597, 0x599, 0x7, 0xc3, 0x2, 0x2, 0x598, 0x59a, 
       0x7, 0xdf, 0x2, 0x2, 0x599, 0x598, 0x3, 0x2, 0x2, 0x2, 0x599, 0x59a, 
       0x3, 0x2, 0x2, 0x2, 0x59a, 0x59b, 0x3, 0x2, 0x2, 0x2, 0x59b, 0x59d, 
       0x5, 0x108, 0x85, 0x2, 0x59c, 0x59e, 0x7, 0xdf, 0x2, 0x2, 0x59d, 
       0x59c, 0x3, 0x2, 0x2, 0x2, 0x59d, 0x59e, 0x3, 0x2, 0x2, 0x2, 0x59e, 
       0x59f, 0x3, 0x2, 0x2, 0x2, 0x59f, 0x5a0, 0x7, 0xce, 0x2, 0x2, 0x5a0, 
       0x8d, 0x3, 0x2, 0x2, 0x2, 0x5a1, 0x5a2, 0x7, 0x68, 0x2, 0x2, 0x5a2, 
       0x5a3, 0x7, 0xdf, 0x2, 0x2, 0x5a3, 0x5a4, 0x5, 0xde, 0x70, 0x2, 0x5a4, 
       0x8f, 0x3, 0x2, 0x2, 0x2, 0x5a5, 0x5a6, 0x7, 0x6a, 0x2, 0x2, 0x5a6, 
       0x5a7, 0x7, 0xdf, 0x2, 0x2, 0x5a7, 0x5a8, 0x5, 0xde, 0x70, 0x2, 0x5a8, 
       0x5a9, 0x7, 0xdf, 0x2, 0x2, 0x5a9, 0x5aa, 0x7, 0xa, 0x2, 0x2, 0x5aa, 
       0x5ab, 0x7, 0xdf, 0x2, 0x2, 0x5ab, 0x5ac, 0x5, 0xde, 0x70, 0x2, 0x5ac, 
       0x91, 0x3, 0x2, 0x2, 0x2, 0x5ad, 0x5ae, 0x9, 0x7, 0x2, 0x2, 0x5ae, 
       0x5b8, 0x7, 0xdf, 0x2, 0x2, 0x5af, 0x5b0, 0x7, 0x4c, 0x2, 0x2, 0x5b0, 
       0x5b1, 0x7, 0xdf, 0x2, 0x2, 0x5b1, 0x5b3, 0x5, 0xde, 0x70, 0x2, 0x5b2, 
       0x5b4, 0x7, 0xb7, 0x2, 0x2, 0x5b3, 0x5b2, 0x3, 0x2, 0x2, 0x2, 0x5b3, 
       0x5b4, 0x3, 0x2, 0x2, 0x2, 0x5b4, 0x5b9, 0x3, 0x2, 0x2, 0x2, 0x5b5, 
       0x5b6, 0x7, 0x8d, 0x2, 0x2, 0x5b6, 0x5b7, 0x7, 0xdf, 0x2, 0x2, 0x5b7, 
       0x5b9, 0x7, 0x6b, 0x2, 0x2, 0x5b8, 0x5af, 0x3, 0x2, 0x2, 0x2, 0x5b8, 
       0x5b5, 0x3, 0x2, 0x2, 0x2, 0x5b9, 0x93, 0x3, 0x2, 0x2, 0x2, 0x5ba, 
       0x5bb, 0x7, 0x71, 0x2, 0x2, 0x5bb, 0x5bc, 0x7, 0xdf, 0x2, 0x2, 0x5bc, 
       0x5bd, 0x5, 0xde, 0x70, 0x2, 0x5bd, 0x5be, 0x7, 0xdf, 0x2, 0x2, 0x5be, 
       0x5bf, 0x7, 0x4c, 0x2, 0x2, 0x5bf, 0x5c0, 0x7, 0xdf, 0x2, 0x2, 0x5c0, 
       0x5cb, 0x5, 0xde, 0x70, 0x2, 0x5c1, 0x5c3, 0x7, 0xdf, 0x2, 0x2, 0x5c2, 
       0x5c1, 0x3, 0x2, 0x2, 0x2, 0x5c2, 0x5c3, 0x3, 0x2, 0x2, 0x2, 0x5c3, 
       0x5c4, 0x3, 0x2, 0x2, 0x2, 0x5c4, 0x5c6, 0x7, 0xb8, 0x2, 0x2, 0x5c5, 
       0x5c7, 0x7, 0xdf, 0x2, 0x2, 0x5c6, 0x5c5, 0x3, 0x2, 0x2, 0x2, 0x5c6, 
       0x5c7, 0x3, 0x2, 0x2, 0x2, 0x5c7, 0x5c8, 0x3, 0x2, 0x2, 0x2, 0x5c8, 
       0x5ca, 0x5, 0xde, 0x70, 0x2, 0x5c9, 0x5c2, 0x3, 0x2, 0x2, 0x2, 0x5ca, 
       0x5cd, 0x3, 0x2, 0x2, 0x2, 0x5cb, 0x5c9, 0x3, 0x2, 0x2, 0x2, 0x5cb, 
       0x5cc, 0x3, 0x2, 0x2, 0x2, 0x5cc, 0x95, 0x3, 0x2, 0x2, 0x2, 0x5cd, 
       0x5cb, 0x3, 0x2, 0x2, 0x2, 0x5ce, 0x5cf, 0x7, 0x71, 0x2, 0x2, 0x5cf, 
       0x5d0, 0x7, 0xdf, 0x2, 0x2, 0x5d0, 0x5d1, 0x5, 0xde, 0x70, 0x2, 0x5d1, 
       0x5d2, 0x7, 0xdf, 0x2, 0x2, 0x5d2, 0x5d3, 0x7, 0x4b, 0x2, 0x2, 0x5d3, 
       0x5d4, 0x7, 0xdf, 0x2, 0x2, 0x5d4, 0x5df, 0x5, 0xde, 0x70, 0x2, 0x5d5, 
       0x5d7, 0x7, 0xdf, 0x2, 0x2, 0x5d6, 0x5d5, 0x3, 0x2, 0x2, 0x2, 0x5d6, 
       0x5d7, 0x3, 0x2, 0x2, 0x2, 0x5d7, 0x5d8, 0x3, 0x2, 0x2, 0x2, 0x5d8, 
       0x5da, 0x7, 0xb8, 0x2, 0x2, 0x5d9, 0x5db, 0x7, 0xdf, 0x2, 0x2, 0x5da, 
       0x5d9, 0x3, 0x2, 0x2, 0x2, 0x5da, 0x5db, 0x3, 0x2, 0x2, 0x2, 0x5db, 
       0x5dc, 0x3, 0x2, 0x2, 0x2, 0x5dc, 0x5de, 0x5, 0xde, 0x70, 0x2, 0x5dd, 
       0x5d6, 0x3, 0x2, 0x2, 0x2, 0x5de, 0x5e1, 0x3, 0x2, 0x2, 0x2, 0x5df, 
       0x5dd, 0x3, 0x2, 0x2, 0x2, 0x5df, 0x5e0, 0x3, 0x2, 0x2, 0x2, 0x5e0, 
       0x97, 0x3, 0x2, 0x2, 0x2, 0x5e1, 0x5df, 0x3, 0x2, 0x2, 0x2, 0x5e2, 
       0x5e3, 0x7, 0x74, 0x2, 0x2, 0x5e3, 0x5e4, 0x7, 0xdf, 0x2, 0x2, 0x5e4, 
       0x5e5, 0x5, 0xde, 0x70, 0x2, 0x5e5, 0x5e6, 0x7, 0xdf, 0x2, 0x2, 0x5e6, 
       0x5e7, 0x7, 0x47, 0x2, 0x2, 0x5e7, 0x5e8, 0x7, 0xdf, 0x2, 0x2, 0x5e8, 
       0x5ed, 0x9, 0x8, 0x2, 0x2, 0x5e9, 0x5ea, 0x7, 0xdf, 0x2, 0x2, 0x5ea, 
       0x5eb, 0x7, 0x3, 0x2, 0x2, 0x5eb, 0x5ec, 0x7, 0xdf, 0x2, 0x2, 0x5ec, 
       0x5ee, 0x9, 0x9, 0x2, 0x2, 0x5ed, 0x5e9, 0x3, 0x2, 0x2, 0x2, 0x5ed, 
       0x5ee, 0x3, 0x2, 0x2, 0x2, 0x5ee, 0x5f1, 0x3, 0x2, 0x2, 0x2, 0x5ef, 
       0x5f0, 0x7, 0xdf, 0x2, 0x2, 0x5f0, 0x5f2, 0x9, 0xa, 0x2, 0x2, 0x5f1, 
       0x5ef, 0x3, 0x2, 0x2, 0x2, 0x5f1, 0x5f2, 0x3, 0x2, 0x2, 0x2, 0x5f2, 
       0x5f3, 0x3, 0x2, 0x2, 0x2, 0x5f3, 0x5f4, 0x7, 0xdf, 0x2, 0x2, 0x5f4, 
       0x5f5, 0x7, 0xa, 0x2, 0x2, 0x5f5, 0x5f6, 0x7, 0xdf, 0x2, 0x2, 0x5f6, 
       0x601, 0x5, 0xde, 0x70, 0x2, 0x5f7, 0x5f8, 0x7, 0xdf, 0x2, 0x2, 0x5f8, 
       0x5fa, 0x7, 0x59, 0x2, 0x2, 0x5f9, 0x5fb, 0x7, 0xdf, 0x2, 0x2, 0x5fa, 
       0x5f9, 0x3, 0x2, 0x2, 0x2, 0x5fa, 0x5fb, 0x3, 0x2, 0x2, 0x2, 0x5fb, 
       0x5fc, 0x3, 0x2, 0x2, 0x2, 0x5fc, 0x5fe, 0x7, 0xbc, 0x2, 0x2, 0x5fd, 
       0x5ff, 0x7, 0xdf, 0x2, 0x2, 0x5fe, 0x5fd, 0x3, 0x2, 0x2, 0x2, 0x5fe, 
       0x5ff, 0x3, 0x2, 0x2, 0x2, 0x5ff, 0x600, 0x3, 0x2, 0x2, 0x2, 0x600, 
       0x602, 0x5, 0xde, 0x70, 0x2, 0x601, 0x5f7, 0x3, 0x2, 0x2, 0x2, 0x601, 
       0x602, 0x3, 0x2, 0x2, 0x2, 0x602, 0x99, 0x3, 0x2, 0x2, 0x2, 0x603, 
       0x610, 0x5, 0x9c, 0x4f, 0x2, 0x604, 0x606, 0x7, 0xdf, 0x2, 0x2, 0x605, 
       0x604, 0x3, 0x2, 0x2, 0x2, 0x605, 0x606, 0x3, 0x2, 0x2, 0x2, 0x606, 
       0x607, 0x3, 0x2, 0x2, 0x2, 0x607, 0x609, 0x9, 0xb, 0x2, 0x2, 0x608, 
       0x60a, 0x7, 0xdf, 0x2, 0x2, 0x609, 0x608, 0x3, 0x2, 0x2, 0x2, 0x609, 
       0x60a, 0x3, 0x2, 0x2, 0x2, 0x60a, 0x60c, 0x3, 0x2, 0x2, 0x2, 0x60b, 
       0x60d, 0x5, 0x9c, 0x4f, 0x2, 0x60c, 0x60b, 0x3, 0x2, 0x2, 0x2, 0x60c, 
       0x60d, 0x3, 0x2, 0x2, 0x2, 0x60d, 0x60f, 0x3, 0x2, 0x2, 0x2, 0x60e, 
       0x605, 0x3, 0x2, 0x2, 0x2, 0x60f, 0x612, 0x3, 0x2, 0x2, 0x2, 0x610, 
       0x60e, 0x3, 0x2, 0x2, 0x2, 0x610, 0x611, 0x3, 0x2, 0x2, 0x2, 0x611, 
       0x625, 0x3, 0x2, 0x2, 0x2, 0x612, 0x610, 0x3, 0x2, 0x2, 0x2, 0x613, 
       0x615, 0x5, 0x9c, 0x4f, 0x2, 0x614, 0x613, 0x3, 0x2, 0x2, 0x2, 0x614, 
       0x615, 0x3, 0x2, 0x2, 0x2, 0x615, 0x620, 0x3, 0x2, 0x2, 0x2, 0x616, 
       0x618, 0x7, 0xdf, 0x2, 0x2, 0x617, 0x616, 0x3, 0x2, 0x2, 0x2, 0x617, 
       0x618, 0x3, 0x2, 0x2, 0x2, 0x618, 0x619, 0x3, 0x2, 0x2, 0x2, 0x619, 
       0x61b, 0x9, 0xb, 0x2, 0x2, 0x61a, 0x61c, 0x7, 0xdf, 0x2, 0x2, 0x61b, 
       0x61a, 0x3, 0x2, 0x2, 0x2, 0x61b, 0x61c, 0x3, 0x2, 0x2, 0x2, 0x61c, 
       0x61e, 0x3, 0x2, 0x2, 0x2, 0x61d, 0x61f, 0x5, 0x9c, 0x4f, 0x2, 0x61e, 
       0x61d, 0x3, 0x2, 0x2, 0x2, 0x61e, 0x61f, 0x3, 0x2, 0x2, 0x2, 0x61f, 
       0x621, 0x3, 0x2, 0x2, 0x2, 0x620, 0x617, 0x3, 0x2, 0x2, 0x2, 0x621, 
       0x622, 0x3, 0x2, 0x2, 0x2, 0x622, 0x620, 0x3, 0x2, 0x2, 0x2, 0x622, 
       0x623, 0x3, 0x2, 0x2, 0x2, 0x623, 0x625, 0x3, 0x2, 0x2, 0x2, 0x624, 
       0x603, 0x3, 0x2, 0x2, 0x2, 0x624, 0x614, 0x3, 0x2, 0x2, 0x2, 0x625, 
       0x9b, 0x3, 0x2, 0x2, 0x2, 0x626, 0x634, 0x9, 0xc, 0x2, 0x2, 0x627, 
       0x629, 0x7, 0xdf, 0x2, 0x2, 0x628, 0x627, 0x3, 0x2, 0x2, 0x2, 0x628, 
       0x629, 0x3, 0x2, 0x2, 0x2, 0x629, 0x62a, 0x3, 0x2, 0x2, 0x2, 0x62a, 
       0x62c, 0x7, 0xc3, 0x2, 0x2, 0x62b, 0x62d, 0x7, 0xdf, 0x2, 0x2, 0x62c, 
       0x62b, 0x3, 0x2, 0x2, 0x2, 0x62c, 0x62d, 0x3, 0x2, 0x2, 0x2, 0x62d, 
       0x62e, 0x3, 0x2, 0x2, 0x2, 0x62e, 0x630, 0x5, 0x108, 0x85, 0x2, 0x62f, 
       0x631, 0x7, 0xdf, 0x2, 0x2, 0x630, 0x62f, 0x3, 0x2, 0x2, 0x2, 0x630, 
       0x631, 0x3, 0x2, 0x2, 0x2, 0x631, 0x632, 0x3, 0x2, 0x2, 0x2, 0x632, 
       0x633, 0x7, 0xce, 0x2, 0x2, 0x633, 0x635, 0x3, 0x2, 0x2, 0x2, 0x634, 
       0x628, 0x3, 0x2, 0x2, 0x2, 0x634, 0x635, 0x3, 0x2, 0x2, 0x2, 0x635, 
       0x638, 0x3, 0x2, 0x2, 0x2, 0x636, 0x638, 0x5, 0xde, 0x70, 0x2, 0x637, 
       0x626, 0x3, 0x2, 0x2, 0x2, 0x637, 0x636, 0x3, 0x2, 0x2, 0x2, 0x638, 
       0x9d, 0x3, 0x2, 0x2, 0x2, 0x639, 0x63a, 0x7, 0x7e, 0x2, 0x2, 0x63a, 
       0x63b, 0x7, 0xdf, 0x2, 0x2, 0x63b, 0x63d, 0x5, 0xde, 0x70, 0x2, 0x63c, 
       0x63e, 0x7, 0xdf, 0x2, 0x2, 0x63d, 0x63c, 0x3, 0x2, 0x2, 0x2, 0x63d, 
       0x63e, 0x3, 0x2, 0x2, 0x2, 0x63e, 0x63f, 0x3, 0x2, 0x2, 0x2, 0x63f, 
       0x644, 0x7, 0xb8, 0x2, 0x2, 0x640, 0x642, 0x7, 0xdf, 0x2, 0x2, 0x641, 
       0x640, 0x3, 0x2, 0x2, 0x2, 0x641, 0x642, 0x3, 0x2, 0x2, 0x2, 0x642, 
       0x643, 0x3, 0x2, 0x2, 0x2, 0x643, 0x645, 0x5, 0x9a, 0x4e, 0x2, 0x644, 
       0x641, 0x3, 0x2, 0x2, 0x2, 0x644, 0x645, 0x3, 0x2, 0x2, 0x2, 0x645, 
       0x9f, 0x3, 0x2, 0x2, 0x2, 0x646, 0x647, 0x5, 0x134, 0x9b, 0x2, 0x647, 
       0x648, 0x7, 0xdf, 0x2, 0x2, 0x648, 0x64a, 0x3, 0x2, 0x2, 0x2, 0x649, 
       0x646, 0x3, 0x2, 0x2, 0x2, 0x649, 0x64a, 0x3, 0x2, 0x2, 0x2, 0x64a, 
       0x64d, 0x3, 0x2, 0x2, 0x2, 0x64b, 0x64c, 0x7, 0x9b, 0x2, 0x2, 0x64c, 
       0x64e, 0x7, 0xdf, 0x2, 0x2, 0x64d, 0x64b, 0x3, 0x2, 0x2, 0x2, 0x64d, 
       0x64e, 0x3, 0x2, 0x2, 0x2, 0x64e, 0x64f, 0x3, 0x2, 0x2, 0x2, 0x64f, 
       0x650, 0x7, 0x80, 0x2, 0x2, 0x650, 0x651, 0x7, 0xdf, 0x2, 0x2, 0x651, 
       0x653, 0x5, 0x118, 0x8d, 0x2, 0x652, 0x654, 0x5, 0x132, 0x9a, 0x2, 
       0x653, 0x652, 0x3, 0x2, 0x2, 0x2, 0x653, 0x654, 0x3, 0x2, 0x2, 0x2, 
       0x654, 0x659, 0x3, 0x2, 0x2, 0x2, 0x655, 0x657, 0x7, 0xdf, 0x2, 0x2, 
       0x656, 0x655, 0x3, 0x2, 0x2, 0x2, 0x656, 0x657, 0x3, 0x2, 0x2, 0x2, 
       0x657, 0x658, 0x3, 0x2, 0x2, 0x2, 0x658, 0x65a, 0x5, 0x10e, 0x88, 
       0x2, 0x659, 0x656, 0x3, 0x2, 0x2, 0x2, 0x659, 0x65a, 0x3, 0x2, 0x2, 
       0x2, 0x65a, 0x65d, 0x3, 0x2, 0x2, 0x2, 0x65b, 0x65c, 0x7, 0xdf, 0x2, 
       0x2, 0x65c, 0x65e, 0x5, 0x11a, 0x8e, 0x2, 0x65d, 0x65b, 0x3, 0x2, 
       0x2, 0x2, 0x65d, 0x65e, 0x3, 0x2, 0x2, 0x2, 0x65e, 0x660, 0x3, 0x2, 
       0x2, 0x2, 0x65f, 0x661, 0x7, 0xdd, 0x2, 0x2, 0x660, 0x65f, 0x3, 0x2, 
       0x2, 0x2, 0x661, 0x662, 0x3, 0x2, 0x2, 0x2, 0x662, 0x660, 0x3, 0x2, 
       0x2, 0x2, 0x662, 0x663, 0x3, 0x2, 0x2, 0x2, 0x663, 0x66a, 0x3, 0x2, 
       0x2, 0x2, 0x664, 0x666, 0x5, 0x32, 0x1a, 0x2, 0x665, 0x667, 0x7, 
       0xdd, 0x2, 0x2, 0x666, 0x665, 0x3, 0x2, 0x2, 0x2, 0x667, 0x668, 0x3, 
       0x2, 0x2, 0x2, 0x668, 0x666, 0x3, 0x2, 0x2, 0x2, 0x668, 0x669, 0x3, 
       0x2, 0x2, 0x2, 0x669, 0x66b, 0x3, 0x2, 0x2, 0x2, 0x66a, 0x664, 0x3, 
       0x2, 0x2, 0x2, 0x66a, 0x66b, 0x3, 0x2, 0x2, 0x2, 0x66b, 0x66c, 0x3, 
       0x2, 0x2, 0x2, 0x66c, 0x66d, 0x7, 0x33, 0x2, 0x2, 0x66d, 0xa1, 0x3, 
       0x2, 0x2, 0x2, 0x66e, 0x66f, 0x5, 0x134, 0x9b, 0x2, 0x66f, 0x670, 
       0x7, 0xdf, 0x2, 0x2, 0x670, 0x672, 0x3, 0x2, 0x2, 0x2, 0x671, 0x66e, 
       0x3, 0x2, 0x2, 0x2, 0x671, 0x672, 0x3, 0x2, 0x2, 0x2, 0x672, 0x675, 
       0x3, 0x2, 0x2, 0x2, 0x673, 0x674, 0x7, 0x9b, 0x2, 0x2, 0x674, 0x676, 
       0x7, 0xdf, 0x2, 0x2, 0x675, 0x673, 0x3, 0x2, 0x2, 0x2, 0x675, 0x676, 
       0x3, 0x2, 0x2, 0x2, 0x676, 0x677, 0x3, 0x2, 0x2, 0x2, 0x677, 0x678, 
       0x7, 0x82, 0x2, 0x2, 0x678, 0x679, 0x7, 0xdf, 0x2, 0x2, 0x679, 0x67e, 
       0x5, 0x118, 0x8d, 0x2, 0x67a, 0x67c, 0x7, 0xdf, 0x2, 0x2, 0x67b, 
       0x67a, 0x3, 0x2, 0x2, 0x2, 0x67b, 0x67c, 0x3, 0x2, 0x2, 0x2, 0x67c, 
       0x67d, 0x3, 0x2, 0x2, 0x2, 0x67d, 0x67f, 0x5, 0x10e, 0x88, 0x2, 0x67e, 
       0x67b, 0x3, 0x2, 0x2, 0x2, 0x67e, 0x67f, 0x3, 0x2, 0x2, 0x2, 0x67f, 
       0x681, 0x3, 0x2, 0x2, 0x2, 0x680, 0x682, 0x7, 0xdd, 0x2, 0x2, 0x681, 
       0x680, 0x3, 0x2, 0x2, 0x2, 0x682, 0x683, 0x3, 0x2, 0x2, 0x2, 0x683, 
       0x681, 0x3, 0x2, 0x2, 0x2, 0x683, 0x684, 0x3, 0x2, 0x2, 0x2, 0x684, 
       0x68b, 0x3, 0x2, 0x2, 0x2, 0x685, 0x687, 0x5, 0x32, 0x1a, 0x2, 0x686, 
       0x688, 0x7, 0xdd, 0x2, 0x2, 0x687, 0x686, 0x3, 0x2, 0x2, 0x2, 0x688, 
       0x689, 0x3, 0x2, 0x2, 0x2, 0x689, 0x687, 0x3, 0x2, 0x2, 0x2, 0x689, 
       0x68a, 0x3, 0x2, 0x2, 0x2, 0x68a, 0x68c, 0x3, 0x2, 0x2, 0x2, 0x68b, 
       0x685, 0x3, 0x2, 0x2, 0x2, 0x68b, 0x68c, 0x3, 0x2, 0x2, 0x2, 0x68c, 
       0x68d, 0x3, 0x2, 0x2, 0x2, 0x68d, 0x68e, 0x7, 0x33, 0x2, 0x2, 0x68e, 
       0xa3, 0x3, 0x2, 0x2, 0x2, 0x68f, 0x690, 0x5, 0x134, 0x9b, 0x2, 0x690, 
       0x691, 0x7, 0xdf, 0x2, 0x2, 0x691, 0x693, 0x3, 0x2, 0x2, 0x2, 0x692, 
       0x68f, 0x3, 0x2, 0x2, 0x2, 0x692, 0x693, 0x3, 0x2, 0x2, 0x2, 0x693, 
       0x696, 0x3, 0x2, 0x2, 0x2, 0x694, 0x695, 0x7, 0x9b, 0x2, 0x2, 0x695, 
       0x697, 0x7, 0xdf, 0x2, 0x2, 0x696, 0x694, 0x3, 0x2, 0x2, 0x2, 0x696, 
       0x697, 0x3, 0x2, 0x2, 0x2, 0x697, 0x698, 0x3, 0x2, 0x2, 0x2, 0x698, 
       0x699, 0x7, 0x81, 0x2, 0x2, 0x699, 0x69a, 0x7, 0xdf, 0x2, 0x2, 0x69a, 
       0x69f, 0x5, 0x118, 0x8d, 0x2, 0x69b, 0x69d, 0x7, 0xdf, 0x2, 0x2, 
       0x69c, 0x69b, 0x3, 0x2, 0x2, 0x2, 0x69c, 0x69d, 0x3, 0x2, 0x2, 0x2, 
       0x69d, 0x69e, 0x3, 0x2, 0x2, 0x2, 0x69e, 0x6a0, 0x5, 0x10e, 0x88, 
       0x2, 0x69f, 0x69c, 0x3, 0x2, 0x2, 0x2, 0x69f, 0x6a0, 0x3, 0x2, 0x2, 
       0x2, 0x6a0, 0x6a2, 0x3, 0x2, 0x2, 0x2, 0x6a1, 0x6a3, 0x7, 0xdd, 0x2, 
       0x2, 0x6a2, 0x6a1, 0x3, 0x2, 0x2, 0x2, 0x6a3, 0x6a4, 0x3, 0x2, 0x2, 
       0x2, 0x6a4, 0x6a2, 0x3, 0x2, 0x2, 0x2, 0x6a4, 0x6a5, 0x3, 0x2, 0x2, 
       0x2, 0x6a5, 0x6ac, 0x3, 0x2, 0x2, 0x2, 0x6a6, 0x6a8, 0x5, 0x32, 0x1a, 
       0x2, 0x6a7, 0x6a9, 0x7, 0xdd, 0x2, 0x2, 0x6a8, 0x6a7, 0x3, 0x2, 0x2, 
       0x2, 0x6a9, 0x6aa, 0x3, 0x2, 0x2, 0x2, 0x6aa, 0x6a8, 0x3, 0x2, 0x2, 
       0x2, 0x6aa, 0x6ab, 0x3, 0x2, 0x2, 0x2, 0x6ab, 0x6ad, 0x3, 0x2, 0x2, 
       0x2, 0x6ac, 0x6a6, 0x3, 0x2, 0x2, 0x2, 0x6ac, 0x6ad, 0x3, 0x2, 0x2, 
       0x2, 0x6ad, 0x6ae, 0x3, 0x2, 0x2, 0x2, 0x6ae, 0x6af, 0x7, 0x33, 0x2, 
       0x2, 0x6af, 0xa5, 0x3, 0x2, 0x2, 0x2, 0x6b0, 0x6b1, 0x7, 0x84, 0x2, 
       0x2, 0x6b1, 0x6b2, 0x7, 0xdf, 0x2, 0x2, 0x6b2, 0x6b4, 0x5, 0xde, 
       0x70, 0x2, 0x6b3, 0x6b5, 0x7, 0xdf, 0x2, 0x2, 0x6b4, 0x6b3, 0x3, 
       0x2, 0x2, 0x2, 0x6b4, 0x6b5, 0x3, 0x2, 0x2, 0x2, 0x6b5, 0x6b6, 0x3, 
       0x2, 0x2, 0x2, 0x6b6, 0x6b8, 0x7, 0xb8, 0x2, 0x2, 0x6b7, 0x6b9, 0x7, 
       0xdf, 0x2, 0x2, 0x6b8, 0x6b7, 0x3, 0x2, 0x2, 0x2, 0x6b8, 0x6b9, 0x3, 
       0x2, 0x2, 0x2, 0x6b9, 0x6bb, 0x3, 0x2, 0x2, 0x2, 0x6ba, 0x6bc, 0x5, 
       0xde, 0x70, 0x2, 0x6bb, 0x6ba, 0x3, 0x2, 0x2, 0x2, 0x6bb, 0x6bc, 
       0x3, 0x2, 0x2, 0x2, 0x6bc, 0x6be, 0x3, 0x2, 0x2, 0x2, 0x6bd, 0x6bf, 
       0x7, 0xdf, 0x2, 0x2, 0x6be, 0x6bd, 0x3, 0x2, 0x2, 0x2, 0x6be, 0x6bf, 
       0x3, 0x2, 0x2, 0x2, 0x6bf, 0x6c0, 0x3, 0x2, 0x2, 0x2, 0x6c0, 0x6c2, 
       0x7, 0xb8, 0x2, 0x2, 0x6c1, 0x6c3, 0x7, 0xdf, 0x2, 0x2, 0x6c2, 0x6c1, 
       0x3, 0x2, 0x2, 0x2, 0x6c2, 0x6c3, 0x3, 0x2, 0x2, 0x2, 0x6c3, 0x6c4, 
       0x3, 0x2, 0x2, 0x2, 0x6c4, 0x6c5, 0x5, 0xde, 0x70, 0x2, 0x6c5, 0xa7, 
       0x3, 0x2, 0x2, 0x2, 0x6c6, 0x6c7, 0x7, 0x87, 0x2, 0x2, 0x6c7, 0x6c8, 
       0x7, 0xdf, 0x2, 0x2, 0x6c8, 0x6d7, 0x5, 0x118, 0x8d, 0x2, 0x6c9, 
       0x6cb, 0x7, 0xdf, 0x2, 0x2, 0x6ca, 0x6c9, 0x3, 0x2, 0x2, 0x2, 0x6ca, 
       0x6cb, 0x3, 0x2, 0x2, 0x2, 0x6cb, 0x6cc, 0x3, 0x2, 0x2, 0x2, 0x6cc, 
       0x6ce, 0x7, 0xc3, 0x2, 0x2, 0x6cd, 0x6cf, 0x7, 0xdf, 0x2, 0x2, 0x6ce, 
       0x6cd, 0x3, 0x2, 0x2, 0x2, 0x6ce, 0x6cf, 0x3, 0x2, 0x2, 0x2, 0x6cf, 
       0x6d4, 0x3, 0x2, 0x2, 0x2, 0x6d0, 0x6d2, 0x5, 0x108, 0x85, 0x2, 0x6d1, 
       0x6d3, 0x7, 0xdf, 0x2, 0x2, 0x6d2, 0x6d1, 0x3, 0x2, 0x2, 0x2, 0x6d2, 
       0x6d3, 0x3, 0x2, 0x2, 0x2, 0x6d3, 0x6d5, 0x3, 0x2, 0x2, 0x2, 0x6d4, 
       0x6d0, 0x3, 0x2, 0x2, 0x2, 0x6d4, 0x6d5, 0x3, 0x2, 0x2, 0x2, 0x6d5, 
       0x6d6, 0x3, 0x2, 0x2, 0x2, 0x6d6, 0x6d8, 0x7, 0xce, 0x2, 0x2, 0x6d7, 
       0x6ca, 0x3, 0x2, 0x2, 0x2, 0x6d7, 0x6d8, 0x3, 0x2, 0x2, 0x2, 0x6d8, 
       0xa9, 0x3, 0x2, 0x2, 0x2, 0x6d9, 0x6dc, 0x7, 0x86, 0x2, 0x2, 0x6da, 
       0x6db, 0x7, 0xdf, 0x2, 0x2, 0x6db, 0x6dd, 0x5, 0xde, 0x70, 0x2, 0x6dc, 
       0x6da, 0x3, 0x2, 0x2, 0x2, 0x6dc, 0x6dd, 0x3, 0x2, 0x2, 0x2, 0x6dd, 
       0xab, 0x3, 0x2, 0x2, 0x2, 0x6de, 0x6df, 0x7, 0x8a, 0x2, 0x2, 0x6df, 
       0x6e2, 0x7, 0xdf, 0x2, 0x2, 0x6e0, 0x6e1, 0x7, 0x7d, 0x2, 0x2, 0x6e1, 
       0x6e3, 0x7, 0xdf, 0x2, 0x2, 0x6e2, 0x6e0, 0x3, 0x2, 0x2, 0x2, 0x6e2, 
       0x6e3, 0x3, 0x2, 0x2, 0x2, 0x6e3, 0x6e4, 0x3, 0x2, 0x2, 0x2, 0x6e4, 
       0x6ef, 0x5, 0xae, 0x58, 0x2, 0x6e5, 0x6e7, 0x7, 0xdf, 0x2, 0x2, 0x6e6, 
       0x6e5, 0x3, 0x2, 0x2, 0x2, 0x6e6, 0x6e7, 0x3, 0x2, 0x2, 0x2, 0x6e7, 
       0x6e8, 0x3, 0x2, 0x2, 0x2, 0x6e8, 0x6ea, 0x7, 0xb8, 0x2, 0x2, 0x6e9, 
       0x6eb, 0x7, 0xdf, 0x2, 0x2, 0x6ea, 0x6e9, 0x3, 0x2, 0x2, 0x2, 0x6ea, 
       0x6eb, 0x3, 0x2, 0x2, 0x2, 0x6eb, 0x6ec, 0x3, 0x2, 0x2, 0x2, 0x6ec, 
       0x6ee, 0x5, 0xae, 0x58, 0x2, 0x6ed, 0x6e6, 0x3, 0x2, 0x2, 0x2, 0x6ee, 
       0x6f1, 0x3, 0x2, 0x2, 0x2, 0x6ef, 0x6ed, 0x3, 0x2, 0x2, 0x2, 0x6ef, 
       0x6f0, 0x3, 0x2, 0x2, 0x2, 0x6f0, 0xad, 0x3, 0x2, 0x2, 0x2, 0x6f1, 
       0x6ef, 0x3, 0x2, 0x2, 0x2, 0x6f2, 0x6f4, 0x5, 0xfa, 0x7e, 0x2, 0x6f3, 
       0x6f5, 0x7, 0xdf, 0x2, 0x2, 0x6f4, 0x6f3, 0x3, 0x2, 0x2, 0x2, 0x6f4, 
       0x6f5, 0x3, 0x2, 0x2, 0x2, 0x6f5, 0x6f6, 0x3, 0x2, 0x2, 0x2, 0x6f6, 
       0x6f8, 0x7, 0xc3, 0x2, 0x2, 0x6f7, 0x6f9, 0x7, 0xdf, 0x2, 0x2, 0x6f8, 
       0x6f7, 0x3, 0x2, 0x2, 0x2, 0x6f8, 0x6f9, 0x3, 0x2, 0x2, 0x2, 0x6f9, 
       0x6fa, 0x3, 0x2, 0x2, 0x2, 0x6fa, 0x6fc, 0x5, 0x114, 0x8b, 0x2, 0x6fb, 
       0x6fd, 0x7, 0xdf, 0x2, 0x2, 0x6fc, 0x6fb, 0x3, 0x2, 0x2, 0x2, 0x6fc, 
       0x6fd, 0x3, 0x2, 0x2, 0x2, 0x6fd, 0x6fe, 0x3, 0x2, 0x2, 0x2, 0x6fe, 
       0x701, 0x7, 0xce, 0x2, 0x2, 0x6ff, 0x700, 0x7, 0xdf, 0x2, 0x2, 0x700, 
       0x702, 0x5, 0x11a, 0x8e, 0x2, 0x701, 0x6ff, 0x3, 0x2, 0x2, 0x2, 0x701, 
       0x702, 0x3, 0x2, 0x2, 0x2, 0x702, 0xaf, 0x3, 0x2, 0x2, 0x2, 0x703, 
       0x704, 0x7, 0x8c, 0x2, 0x2, 0x704, 0xb1, 0x3, 0x2, 0x2, 0x2, 0x705, 
       0x70b, 0x7, 0x8d, 0x2, 0x2, 0x706, 0x709, 0x7, 0xdf, 0x2, 0x2, 0x707, 
       0x70a, 0x7, 0x6b, 0x2, 0x2, 0x708, 0x70a, 0x5, 0x118, 0x8d, 0x2, 
       0x709, 0x707, 0x3, 0x2, 0x2, 0x2, 0x709, 0x708, 0x3, 0x2, 0x2, 0x2, 
       0x70a, 0x70c, 0x3, 0x2, 0x2, 0x2, 0x70b, 0x706, 0x3, 0x2, 0x2, 0x2, 
       0x70b, 0x70c, 0x3, 0x2, 0x2, 0x2, 0x70c, 0xb3, 0x3, 0x2, 0x2, 0x2, 
       0x70d, 0x70e, 0x7, 0x8e, 0x2, 0x2, 0x70e, 0xb5, 0x3, 0x2, 0x2, 0x2, 
       0x70f, 0x710, 0x7, 0x8f, 0x2, 0x2, 0x710, 0x711, 0x7, 0xdf, 0x2, 
       0x2, 0x711, 0x712, 0x5, 0xde, 0x70, 0x2, 0x712, 0xb7, 0x3, 0x2, 0x2, 
       0x2, 0x713, 0x714, 0x7, 0x90, 0x2, 0x2, 0x714, 0x715, 0x7, 0xdf, 
       0x2, 0x2, 0x715, 0x717, 0x5, 0xfa, 0x7e, 0x2, 0x716, 0x718, 0x7, 
       0xdf, 0x2, 0x2, 0x717, 0x716, 0x3, 0x2, 0x2, 0x2, 0x717, 0x718, 0x3, 
       0x2, 0x2, 0x2, 0x718, 0x719, 0x3, 0x2, 0x2, 0x2, 0x719, 0x71b, 0x7, 
       0xbc, 0x2, 0x2, 0x71a, 0x71c, 0x7, 0xdf, 0x2, 0x2, 0x71b, 0x71a, 
       0x3, 0x2, 0x2, 0x2, 0x71b, 0x71c, 0x3, 0x2, 0x2, 0x2, 0x71c, 0x71d, 
       0x3, 0x2, 0x2, 0x2, 0x71d, 0x71e, 0x5, 0xde, 0x70, 0x2, 0x71e, 0xb9, 
       0x3, 0x2, 0x2, 0x2, 0x71f, 0x720, 0x7, 0x91, 0x2, 0x2, 0x720, 0x721, 
       0x7, 0xdf, 0x2, 0x2, 0x721, 0x723, 0x5, 0xde, 0x70, 0x2, 0x722, 0x724, 
       0x7, 0xdf, 0x2, 0x2, 0x723, 0x722, 0x3, 0x2, 0x2, 0x2, 0x723, 0x724, 
       0x3, 0x2, 0x2, 0x2, 0x724, 0x725, 0x3, 0x2, 0x2, 0x2, 0x725, 0x727, 
       0x7, 0xb8, 0x2, 0x2, 0x726, 0x728, 0x7, 0xdf, 0x2, 0x2, 0x727, 0x726, 
       0x3, 0x2, 0x2, 0x2, 0x727, 0x728, 0x3, 0x2, 0x2, 0x2, 0x728, 0x729, 
       0x3, 0x2, 0x2, 0x2, 0x729, 0x72a, 0x5, 0xde, 0x70, 0x2, 0x72a, 0xbb, 
       0x3, 0x2, 0x2, 0x2, 0x72b, 0x72c, 0x7, 0x92, 0x2, 0x2, 0x72c, 0x72d, 
       0x7, 0xdf, 0x2, 0x2, 0x72d, 0x72f, 0x5, 0xde, 0x70, 0x2, 0x72e, 0x730, 
       0x7, 0xdf, 0x2, 0x2, 0x72f, 0x72e, 0x3, 0x2, 0x2, 0x2, 0x72f, 0x730, 
       0x3, 0x2, 0x2, 0x2, 0x730, 0x731, 0x3, 0x2, 0x2, 0x2, 0x731, 0x733, 
       0x7, 0xb8, 0x2, 0x2, 0x732, 0x734, 0x7, 0xdf, 0x2, 0x2, 0x733, 0x732, 
       0x3, 0x2, 0x2, 0x2, 0x733, 0x734, 0x3, 0x2, 0x2, 0x2, 0x734, 0x735, 
       0x3, 0x2, 0x2, 0x2, 0x735, 0x737, 0x5, 0xde, 0x70, 0x2, 0x736, 0x738, 
       0x7, 0xdf, 0x2, 0x2, 0x737, 0x736, 0x3, 0x2, 0x2, 0x2, 0x737, 0x738, 
       0x3, 0x2, 0x2, 0x2, 0x738, 0x739, 0x3, 0x2, 0x2, 0x2, 0x739, 0x73b, 
       0x7, 0xb8, 0x2, 0x2, 0x73a, 0x73c, 0x7, 0xdf, 0x2, 0x2, 0x73b, 0x73a, 
       0x3, 0x2, 0x2, 0x2, 0x73b, 0x73c, 0x3, 0x2, 0x2, 0x2, 0x73c, 0x73d, 
       0x3, 0x2, 0x2, 0x2, 0x73d, 0x73f, 0x5, 0xde, 0x70, 0x2, 0x73e, 0x740, 
       0x7, 0xdf, 0x2, 0x2, 0x73f, 0x73e, 0x3, 0x2, 0x2, 0x2, 0x73f, 0x740, 
       0x3, 0x2, 0x2, 0x2, 0x740, 0x741, 0x3, 0x2, 0x2, 0x2, 0x741, 0x743, 
       0x7, 0xb8, 0x2, 0x2, 0x742, 0x744, 0x7, 0xdf, 0x2, 0x2, 0x743, 0x742, 
       0x3, 0x2, 0x2, 0x2, 0x743, 0x744, 0x3, 0x2, 0x2, 0x2, 0x744, 0x745, 
       0x3, 0x2, 0x2, 0x2, 0x745, 0x746, 0x5, 0xde, 0x70, 0x2, 0x746, 0xbd, 
       0x3, 0x2, 0x2, 0x2, 0x747, 0x748, 0x7, 0x93, 0x2, 0x2, 0x748, 0x749, 
       0x7, 0xdf, 0x2, 0x2, 0x749, 0x74b, 0x5, 0xde, 0x70, 0x2, 0x74a, 0x74c, 
       0x7, 0xdf, 0x2, 0x2, 0x74b, 0x74a, 0x3, 0x2, 0x2, 0x2, 0x74b, 0x74c, 
       0x3, 0x2, 0x2, 0x2, 0x74c, 0x74d, 0x3, 0x2, 0x2, 0x2, 0x74d, 0x74f, 
       0x7, 0xb8, 0x2, 0x2, 0x74e, 0x750, 0x7, 0xdf, 0x2, 0x2, 0x74f, 0x74e, 
       0x3, 0x2, 0x2, 0x2, 0x74f, 0x750, 0x3, 0x2, 0x2, 0x2, 0x750, 0x751, 
       0x3, 0x2, 0x2, 0x2, 0x751, 0x752, 0x5, 0xde, 0x70, 0x2, 0x752, 0xbf, 
       0x3, 0x2, 0x2, 0x2, 0x753, 0x754, 0x7, 0x94, 0x2, 0x2, 0x754, 0x755, 
       0x7, 0xdf, 0x2, 0x2, 0x755, 0x756, 0x7, 0x14, 0x2, 0x2, 0x756, 0x757, 
       0x7, 0xdf, 0x2, 0x2, 0x757, 0x759, 0x5, 0xde, 0x70, 0x2, 0x758, 0x75a, 
       0x7, 0xdd, 0x2, 0x2, 0x759, 0x758, 0x3, 0x2, 0x2, 0x2, 0x75a, 0x75b, 
       0x3, 0x2, 0x2, 0x2, 0x75b, 0x759, 0x3, 0x2, 0x2, 0x2, 0x75b, 0x75c, 
       0x3, 0x2, 0x2, 0x2, 0x75c, 0x760, 0x3, 0x2, 0x2, 0x2, 0x75d, 0x75f, 
       0x5, 0xc2, 0x62, 0x2, 0x75e, 0x75d, 0x3, 0x2, 0x2, 0x2, 0x75f, 0x762, 
       0x3, 0x2, 0x2, 0x2, 0x760, 0x75e, 0x3, 0x2, 0x2, 0x2, 0x760, 0x761, 
       0x3, 0x2, 0x2, 0x2, 0x761, 0x764, 0x3, 0x2, 0x2, 0x2, 0x762, 0x760, 
       0x3, 0x2, 0x2, 0x2, 0x763, 0x765, 0x7, 0xdf, 0x2, 0x2, 0x764, 0x763, 
       0x3, 0x2, 0x2, 0x2, 0x764, 0x765, 0x3, 0x2, 0x2, 0x2, 0x765, 0x766, 
       0x3, 0x2, 0x2, 0x2, 0x766, 0x767, 0x7, 0x34, 0x2, 0x2, 0x767, 0xc1, 
       0x3, 0x2, 0x2, 0x2, 0x768, 0x769, 0x7, 0x14, 0x2, 0x2, 0x769, 0x76a, 
       0x7, 0xdf, 0x2, 0x2, 0x76a, 0x76c, 0x5, 0xc4, 0x63, 0x2, 0x76b, 0x76d, 
       0x7, 0xdf, 0x2, 0x2, 0x76c, 0x76b, 0x3, 0x2, 0x2, 0x2, 0x76c, 0x76d, 
       0x3, 0x2, 0x2, 0x2, 0x76d, 0x77c, 0x3, 0x2, 0x2, 0x2, 0x76e, 0x770, 
       0x7, 0xb7, 0x2, 0x2, 0x76f, 0x76e, 0x3, 0x2, 0x2, 0x2, 0x76f, 0x770, 
       0x3, 0x2, 0x2, 0x2, 0x770, 0x774, 0x3, 0x2, 0x2, 0x2, 0x771, 0x773, 
       0x7, 0xdd, 0x2, 0x2, 0x772, 0x771, 0x3, 0x2, 0x2, 0x2, 0x773, 0x776, 
       0x3, 0x2, 0x2, 0x2, 0x774, 0x772, 0x3, 0x2, 0x2, 0x2, 0x774, 0x775, 
       0x3, 0x2, 0x2, 0x2, 0x775, 0x77d, 0x3, 0x2, 0x2, 0x2, 0x776, 0x774, 
       0x3, 0x2, 0x2, 0x2, 0x777, 0x779, 0x7, 0xdd, 0x2, 0x2, 0x778, 0x777, 
       0x3, 0x2, 0x2, 0x2, 0x779, 0x77a, 0x3, 0x2, 0x2, 0x2, 0x77a, 0x778, 
       0x3, 0x2, 0x2, 0x2, 0x77a, 0x77b, 0x3, 0x2, 0x2, 0x2, 0x77b, 0x77d, 
       0x3, 0x2, 0x2, 0x2, 0x77c, 0x76f, 0x3, 0x2, 0x2, 0x2, 0x77c, 0x778, 
       0x3, 0x2, 0x2, 0x2, 0x77d, 0x784, 0x3, 0x2, 0x2, 0x2, 0x77e, 0x780, 
       0x5, 0x32, 0x1a, 0x2, 0x77f, 0x781, 0x7, 0xdd, 0x2, 0x2, 0x780, 0x77f, 
       0x3, 0x2, 0x2, 0x2, 0x781, 0x782, 0x3, 0x2, 0x2, 0x2, 0x782, 0x780, 
       0x3, 0x2, 0x2, 0x2, 0x782, 0x783, 0x3, 0x2, 0x2, 0x2, 0x783, 0x785, 
       0x3, 0x2, 0x2, 0x2, 0x784, 0x77e, 0x3, 0x2, 0x2, 0x2, 0x784, 0x785, 
       0x3, 0x2, 0x2, 0x2, 0x785, 0xc3, 0x3, 0x2, 0x2, 0x2, 0x786, 0x796, 
       0x7, 0x2e, 0x2, 0x2, 0x787, 0x792, 0x5, 0xc6, 0x64, 0x2, 0x788, 0x78a, 
       0x7, 0xdf, 0x2, 0x2, 0x789, 0x788, 0x3, 0x2, 0x2, 0x2, 0x789, 0x78a, 
       0x3, 0x2, 0x2, 0x2, 0x78a, 0x78b, 0x3, 0x2, 0x2, 0x2, 0x78b, 0x78d, 
       0x7, 0xb8, 0x2, 0x2, 0x78c, 0x78e, 0x7, 0xdf, 0x2, 0x2, 0x78d, 0x78c, 
       0x3, 0x2, 0x2, 0x2, 0x78d, 0x78e, 0x3, 0x2, 0x2, 0x2, 0x78e, 0x78f, 
       0x3, 0x2, 0x2, 0x2, 0x78f, 0x791, 0x5, 0xc6, 0x64, 0x2, 0x790, 0x789, 
       0x3, 0x2, 0x2, 0x2, 0x791, 0x794, 0x3, 0x2, 0x2, 0x2, 0x792, 0x790, 
       0x3, 0x2, 0x2, 0x2, 0x792, 0x793, 0x3, 0x2, 0x2, 0x2, 0x793, 0x796, 
       0x3, 0x2, 0x2, 0x2, 0x794, 0x792, 0x3, 0x2, 0x2, 0x2, 0x795, 0x786, 
       0x3, 0x2, 0x2, 0x2, 0x795, 0x787, 0x3, 0x2, 0x2, 0x2, 0x796, 0xc5, 
       0x3, 0x2, 0x2, 0x2, 0x797, 0x799, 0x7, 0x52, 0x2, 0x2, 0x798, 0x79a, 
       0x7, 0xdf, 0x2, 0x2, 0x799, 0x798, 0x3, 0x2, 0x2, 0x2, 0x799, 0x79a, 
       0x3, 0x2, 0x2, 0x2, 0x79a, 0x79b, 0x3, 0x2, 0x2, 0x2, 0x79b, 0x79d, 
       0x5, 0x120, 0x91, 0x2, 0x79c, 0x79e, 0x7, 0xdf, 0x2, 0x2, 0x79d, 
       0x79c, 0x3, 0x2, 0x2, 0x2, 0x79d, 0x79e, 0x3, 0x2, 0x2, 0x2, 0x79e, 
       0x79f, 0x3, 0x2, 0x2, 0x2, 0x79f, 0x7a0, 0x5, 0xde, 0x70, 0x2, 0x7a0, 
       0x7a9, 0x3, 0x2, 0x2, 0x2, 0x7a1, 0x7a9, 0x5, 0xde, 0x70, 0x2, 0x7a2, 
       0x7a3, 0x5, 0xde, 0x70, 0x2, 0x7a3, 0x7a4, 0x7, 0xdf, 0x2, 0x2, 0x7a4, 
       0x7a5, 0x7, 0xa4, 0x2, 0x2, 0x7a5, 0x7a6, 0x7, 0xdf, 0x2, 0x2, 0x7a6, 
       0x7a7, 0x5, 0xde, 0x70, 0x2, 0x7a7, 0x7a9, 0x3, 0x2, 0x2, 0x2, 0x7a8, 
       0x797, 0x3, 0x2, 0x2, 0x2, 0x7a8, 0x7a1, 0x3, 0x2, 0x2, 0x2, 0x7a8, 
       0x7a2, 0x3, 0x2, 0x2, 0x2, 0x7a9, 0xc7, 0x3, 0x2, 0x2, 0x2, 0x7aa, 
       0x7ab, 0x7, 0x95, 0x2, 0x2, 0x7ab, 0x7ac, 0x7, 0xdf, 0x2, 0x2, 0x7ac, 
       0x7b5, 0x5, 0xde, 0x70, 0x2, 0x7ad, 0x7af, 0x7, 0xdf, 0x2, 0x2, 0x7ae, 
       0x7ad, 0x3, 0x2, 0x2, 0x2, 0x7ae, 0x7af, 0x3, 0x2, 0x2, 0x2, 0x7af, 
       0x7b0, 0x3, 0x2, 0x2, 0x2, 0x7b0, 0x7b2, 0x7, 0xb8, 0x2, 0x2, 0x7b1, 
       0x7b3, 0x7, 0xdf, 0x2, 0x2, 0x7b2, 0x7b1, 0x3, 0x2, 0x2, 0x2, 0x7b2, 
       0x7b3, 0x3, 0x2, 0x2, 0x2, 0x7b3, 0x7b4, 0x3, 0x2, 0x2, 0x2, 0x7b4, 
       0x7b6, 0x5, 0xde, 0x70, 0x2, 0x7b5, 0x7ae, 0x3, 0x2, 0x2, 0x2, 0x7b5, 
       0x7b6, 0x3, 0x2, 0x2, 0x2, 0x7b6, 0xc9, 0x3, 0x2, 0x2, 0x2, 0x7b7, 
       0x7b8, 0x7, 0x97, 0x2, 0x2, 0x7b8, 0x7b9, 0x7, 0xdf, 0x2, 0x2, 0x7b9, 
       0x7bb, 0x5, 0xde, 0x70, 0x2, 0x7ba, 0x7bc, 0x7, 0xdf, 0x2, 0x2, 0x7bb, 
       0x7ba, 0x3, 0x2, 0x2, 0x2, 0x7bb, 0x7bc, 0x3, 0x2, 0x2, 0x2, 0x7bc, 
       0x7bd, 0x3, 0x2, 0x2, 0x2, 0x7bd, 0x7bf, 0x7, 0xb8, 0x2, 0x2, 0x7be, 
       0x7c0, 0x7, 0xdf, 0x2, 0x2, 0x7bf, 0x7be, 0x3, 0x2, 0x2, 0x2, 0x7bf, 
       0x7c0, 0x3, 0x2, 0x2, 0x2, 0x7c0, 0x7c1, 0x3, 0x2, 0x2, 0x2, 0x7c1, 
       0x7c2, 0x5, 0xde, 0x70, 0x2, 0x7c2, 0xcb, 0x3, 0x2, 0x2, 0x2, 0x7c3, 
       0x7c4, 0x7, 0x96, 0x2, 0x2, 0x7c4, 0x7c5, 0x7, 0xdf, 0x2, 0x2, 0x7c5, 
       0x7c7, 0x5, 0xfa, 0x7e, 0x2, 0x7c6, 0x7c8, 0x7, 0xdf, 0x2, 0x2, 0x7c7, 
       0x7c6, 0x3, 0x2, 0x2, 0x2, 0x7c7, 0x7c8, 0x3, 0x2, 0x2, 0x2, 0x7c8, 
       0x7c9, 0x3, 0x2, 0x2, 0x2, 0x7c9, 0x7cb, 0x7, 0xbc, 0x2, 0x2, 0x7ca, 
       0x7cc, 0x7, 0xdf, 0x2, 0x2, 0x7cb, 0x7ca, 0x3, 0x2, 0x2, 0x2, 0x7cb, 
       0x7cc, 0x3, 0x2, 0x2, 0x2, 0x7cc, 0x7cd, 0x3, 0x2, 0x2, 0x2, 0x7cd, 
       0x7ce, 0x5, 0xde, 0x70, 0x2, 0x7ce, 0xcd, 0x3, 0x2, 0x2, 0x2, 0x7cf, 
       0x7d0, 0x7, 0x9d, 0x2, 0x2, 0x7d0, 0xcf, 0x3, 0x2, 0x2, 0x2, 0x7d1, 
       0x7d2, 0x5, 0x134, 0x9b, 0x2, 0x7d2, 0x7d3, 0x7, 0xdf, 0x2, 0x2, 
       0x7d3, 0x7d5, 0x3, 0x2, 0x2, 0x2, 0x7d4, 0x7d1, 0x3, 0x2, 0x2, 0x2, 
       0x7d4, 0x7d5, 0x3, 0x2, 0x2, 0x2, 0x7d5, 0x7d8, 0x3, 0x2, 0x2, 0x2, 
       0x7d6, 0x7d7, 0x7, 0x9b, 0x2, 0x2, 0x7d7, 0x7d9, 0x7, 0xdf, 0x2, 
       0x2, 0x7d8, 0x7d6, 0x3, 0x2, 0x2, 0x2, 0x7d8, 0x7d9, 0x3, 0x2, 0x2, 
       0x2, 0x7d9, 0x7da, 0x3, 0x2, 0x2, 0x2, 0x7da, 0x7db, 0x7, 0x9f, 0x2, 
       0x2, 0x7db, 0x7dc, 0x7, 0xdf, 0x2, 0x2, 0x7dc, 0x7e1, 0x5, 0x118, 
       0x8d, 0x2, 0x7dd, 0x7df, 0x7, 0xdf, 0x2, 0x2, 0x7de, 0x7dd, 0x3, 
       0x2, 0x2, 0x2, 0x7de, 0x7df, 0x3, 0x2, 0x2, 0x2, 0x7df, 0x7e0, 0x3, 
       0x2, 0x2, 0x2, 0x7e0, 0x7e2, 0x5, 0x10e, 0x88, 0x2, 0x7e1, 0x7de, 
       0x3, 0x2, 0x2, 0x2, 0x7e1, 0x7e2, 0x3, 0x2, 0x2, 0x2, 0x7e2, 0x7e4, 
       0x3, 0x2, 0x2, 0x2, 0x7e3, 0x7e5, 0x7, 0xdd, 0x2, 0x2, 0x7e4, 0x7e3, 
       0x3, 0x2, 0x2, 0x2, 0x7e5, 0x7e6, 0x3, 0x2, 0x2, 0x2, 0x7e6, 0x7e4, 
       0x3, 0x2, 0x2, 0x2, 0x7e6, 0x7e7, 0x3, 0x2, 0x2, 0x2, 0x7e7, 0x7ee, 
       0x3, 0x2, 0x2, 0x2, 0x7e8, 0x7ea, 0x5, 0x32, 0x1a, 0x2, 0x7e9, 0x7eb, 
       0x7, 0xdd, 0x2, 0x2, 0x7ea, 0x7e9, 0x3, 0x2, 0x2, 0x2, 0x7eb, 0x7ec, 
       0x3, 0x2, 0x2, 0x2, 0x7ec, 0x7ea, 0x3, 0x2, 0x2, 0x2, 0x7ec, 0x7ed, 
       0x3, 0x2, 0x2, 0x2, 0x7ed, 0x7ef, 0x3, 0x2, 0x2, 0x2, 0x7ee, 0x7e8, 
       0x3, 0x2, 0x2, 0x2, 0x7ee, 0x7ef, 0x3, 0x2, 0x2, 0x2, 0x7ef, 0x7f0, 
       0x3, 0x2, 0x2, 0x2, 0x7f0, 0x7f1, 0x7, 0x35, 0x2, 0x2, 0x7f1, 0xd1, 
       0x3, 0x2, 0x2, 0x2, 0x7f2, 0x7f4, 0x7, 0xa3, 0x2, 0x2, 0x7f3, 0x7f5, 
       0x7, 0xdf, 0x2, 0x2, 0x7f4, 0x7f3, 0x3, 0x2, 0x2, 0x2, 0x7f4, 0x7f5, 
       0x3, 0x2, 0x2, 0x2, 0x7f5, 0x7f6, 0x3, 0x2, 0x2, 0x2, 0x7f6, 0x7f8, 
       0x7, 0xbc, 0x2, 0x2, 0x7f7, 0x7f9, 0x7, 0xdf, 0x2, 0x2, 0x7f8, 0x7f7, 
       0x3, 0x2, 0x2, 0x2, 0x7f8, 0x7f9, 0x3, 0x2, 0x2, 0x2, 0x7f9, 0x7fa, 
       0x3, 0x2, 0x2, 0x2, 0x7fa, 0x7fb, 0x5, 0xde, 0x70, 0x2, 0x7fb, 0xd3, 
       0x3, 0x2, 0x2, 0x2, 0x7fc, 0x7fd, 0x5, 0x134, 0x9b, 0x2, 0x7fd, 0x7fe, 
       0x7, 0xdf, 0x2, 0x2, 0x7fe, 0x800, 0x3, 0x2, 0x2, 0x2, 0x7ff, 0x7fc, 
       0x3, 0x2, 0x2, 0x2, 0x7ff, 0x800, 0x3, 0x2, 0x2, 0x2, 0x800, 0x801, 
       0x3, 0x2, 0x2, 0x2, 0x801, 0x802, 0x7, 0xa6, 0x2, 0x2, 0x802, 0x803, 
       0x7, 0xdf, 0x2, 0x2, 0x803, 0x805, 0x5, 0x118, 0x8d, 0x2, 0x804, 
       0x806, 0x7, 0xdd, 0x2, 0x2, 0x805, 0x804, 0x3, 0x2, 0x2, 0x2, 0x806, 
       0x807, 0x3, 0x2, 0x2, 0x2, 0x807, 0x805, 0x3, 0x2, 0x2, 0x2, 0x807, 
       0x808, 0x3, 0x2, 0x2, 0x2, 0x808, 0x80c, 0x3, 0x2, 0x2, 0x2, 0x809, 
       0x80b, 0x5, 0xd6, 0x6c, 0x2, 0x80a, 0x809, 0x3, 0x2, 0x2, 0x2, 0x80b, 
       0x80e, 0x3, 0x2, 0x2, 0x2, 0x80c, 0x80a, 0x3, 0x2, 0x2, 0x2, 0x80c, 
       0x80d, 0x3, 0x2, 0x2, 0x2, 0x80d, 0x80f, 0x3, 0x2, 0x2, 0x2, 0x80e, 
       0x80c, 0x3, 0x2, 0x2, 0x2, 0x80f, 0x810, 0x7, 0x36, 0x2, 0x2, 0x810, 
       0xd5, 0x3, 0x2, 0x2, 0x2, 0x811, 0x820, 0x5, 0x118, 0x8d, 0x2, 0x812, 
       0x814, 0x7, 0xdf, 0x2, 0x2, 0x813, 0x812, 0x3, 0x2, 0x2, 0x2, 0x813, 
       0x814, 0x3, 0x2, 0x2, 0x2, 0x814, 0x815, 0x3, 0x2, 0x2, 0x2, 0x815, 
       0x81a, 0x7, 0xc3, 0x2, 0x2, 0x816, 0x818, 0x7, 0xdf, 0x2, 0x2, 0x817, 
       0x816, 0x3, 0x2, 0x2, 0x2, 0x817, 0x818, 0x3, 0x2, 0x2, 0x2, 0x818, 
       0x819, 0x3, 0x2, 0x2, 0x2, 0x819, 0x81b, 0x5, 0x114, 0x8b, 0x2, 0x81a, 
       0x817, 0x3, 0x2, 0x2, 0x2, 0x81a, 0x81b, 0x3, 0x2, 0x2, 0x2, 0x81b, 
       0x81d, 0x3, 0x2, 0x2, 0x2, 0x81c, 0x81e, 0x7, 0xdf, 0x2, 0x2, 0x81d, 
       0x81c, 0x3, 0x2, 0x2, 0x2, 0x81d, 0x81e, 0x3, 0x2, 0x2, 0x2, 0x81e, 
       0x81f, 0x3, 0x2, 0x2, 0x2, 0x81f, 0x821, 0x7, 0xce, 0x2, 0x2, 0x820, 
       0x813, 0x3, 0x2, 0x2, 0x2, 0x820, 0x821, 0x3, 0x2, 0x2, 0x2, 0x821, 
       0x824, 0x3, 0x2, 0x2, 0x2, 0x822, 0x823, 0x7, 0xdf, 0x2, 0x2, 0x823, 
       0x825, 0x5, 0x11a, 0x8e, 0x2, 0x824, 0x822, 0x3, 0x2, 0x2, 0x2, 0x824, 
       0x825, 0x3, 0x2, 0x2, 0x2, 0x825, 0x827, 0x3, 0x2, 0x2, 0x2, 0x826, 
       0x828, 0x7, 0xdd, 0x2, 0x2, 0x827, 0x826, 0x3, 0x2, 0x2, 0x2, 0x828, 
       0x829, 0x3, 0x2, 0x2, 0x2, 0x829, 0x827, 0x3, 0x2, 0x2, 0x2, 0x829, 
       0x82a, 0x3, 0x2, 0x2, 0x2, 0x82a, 0xd7, 0x3, 0x2, 0x2, 0x2, 0x82b, 
       0x82c, 0x7, 0xa7, 0x2, 0x2, 0x82c, 0x82d, 0x7, 0xdf, 0x2, 0x2, 0x82d, 
       0x832, 0x5, 0xde, 0x70, 0x2, 0x82e, 0x82f, 0x7, 0xdf, 0x2, 0x2, 0x82f, 
       0x830, 0x7, 0x52, 0x2, 0x2, 0x830, 0x831, 0x7, 0xdf, 0x2, 0x2, 0x831, 
       0x833, 0x5, 0x130, 0x99, 0x2, 0x832, 0x82e, 0x3, 0x2, 0x2, 0x2, 0x832, 
       0x833, 0x3, 0x2, 0x2, 0x2, 0x833, 0xd9, 0x3, 0x2, 0x2, 0x2, 0x834, 
       0x835, 0x7, 0xa8, 0x2, 0x2, 0x835, 0x836, 0x7, 0xdf, 0x2, 0x2, 0x836, 
       0x837, 0x5, 0xde, 0x70, 0x2, 0x837, 0xdb, 0x3, 0x2, 0x2, 0x2, 0x838, 
       0x839, 0x7, 0xa9, 0x2, 0x2, 0x839, 0x83a, 0x7, 0xdf, 0x2, 0x2, 0x83a, 
       0x849, 0x5, 0xde, 0x70, 0x2, 0x83b, 0x83d, 0x7, 0xdf, 0x2, 0x2, 0x83c, 
       0x83b, 0x3, 0x2, 0x2, 0x2, 0x83c, 0x83d, 0x3, 0x2, 0x2, 0x2, 0x83d, 
       0x83e, 0x3, 0x2, 0x2, 0x2, 0x83e, 0x840, 0x7, 0xb8, 0x2, 0x2, 0x83f, 
       0x841, 0x7, 0xdf, 0x2, 0x2, 0x840, 0x83f, 0x3, 0x2, 0x2, 0x2, 0x840, 
       0x841, 0x3, 0x2, 0x2, 0x2, 0x841, 0x842, 0x3, 0x2, 0x2, 0x2, 0x842, 
       0x847, 0x5, 0xde, 0x70, 0x2, 0x843, 0x844, 0x7, 0xdf, 0x2, 0x2, 0x844, 
       0x845, 0x7, 0xa4, 0x2, 0x2, 0x845, 0x846, 0x7, 0xdf, 0x2, 0x2, 0x846, 
       0x848, 0x5, 0xde, 0x70, 0x2, 0x847, 0x843, 0x3, 0x2, 0x2, 0x2, 0x847, 
       0x848, 0x3, 0x2, 0x2, 0x2, 0x848, 0x84a, 0x3, 0x2, 0x2, 0x2, 0x849, 
       0x83c, 0x3, 0x2, 0x2, 0x2, 0x849, 0x84a, 0x3, 0x2, 0x2, 0x2, 0x84a, 
       0xdd, 0x3, 0x2, 0x2, 0x2, 0x84b, 0x84c, 0x8, 0x70, 0x1, 0x2, 0x84c, 
       0x891, 0x5, 0x12a, 0x96, 0x2, 0x84d, 0x84f, 0x7, 0xc3, 0x2, 0x2, 
       0x84e, 0x850, 0x7, 0xdf, 0x2, 0x2, 0x84f, 0x84e, 0x3, 0x2, 0x2, 0x2, 
       0x84f, 0x850, 0x3, 0x2, 0x2, 0x2, 0x850, 0x851, 0x3, 0x2, 0x2, 0x2, 
       0x851, 0x85c, 0x5, 0xde, 0x70, 0x2, 0x852, 0x854, 0x7, 0xdf, 0x2, 
       0x2, 0x853, 0x852, 0x3, 0x2, 0x2, 0x2, 0x853, 0x854, 0x3, 0x2, 0x2, 
       0x2, 0x854, 0x855, 0x3, 0x2, 0x2, 0x2, 0x855, 0x857, 0x7, 0xb8, 0x2, 
       0x2, 0x856, 0x858, 0x7, 0xdf, 0x2, 0x2, 0x857, 0x856, 0x3, 0x2, 0x2, 
       0x2, 0x857, 0x858, 0x3, 0x2, 0x2, 0x2, 0x858, 0x859, 0x3, 0x2, 0x2, 
       0x2, 0x859, 0x85b, 0x5, 0xde, 0x70, 0x2, 0x85a, 0x853, 0x3, 0x2, 
       0x2, 0x2, 0x85b, 0x85e, 0x3, 0x2, 0x2, 0x2, 0x85c, 0x85a, 0x3, 0x2, 
       0x2, 0x2, 0x85c, 0x85d, 0x3, 0x2, 0x2, 0x2, 0x85d, 0x860, 0x3, 0x2, 
       0x2, 0x2, 0x85e, 0x85c, 0x3, 0x2, 0x2, 0x2, 0x85f, 0x861, 0x7, 0xdf, 
       0x2, 0x2, 0x860, 0x85f, 0x3, 0x2, 0x2, 0x2, 0x860, 0x861, 0x3, 0x2, 
       0x2, 0x2, 0x861, 0x862, 0x3, 0x2, 0x2, 0x2, 0x862, 0x863, 0x7, 0xce, 
       0x2, 0x2, 0x863, 0x891, 0x3, 0x2, 0x2, 0x2, 0x864, 0x865, 0x7, 0x6c, 
       0x2, 0x2, 0x865, 0x866, 0x7, 0xdf, 0x2, 0x2, 0x866, 0x891, 0x5, 0xde, 
       0x70, 0x1f, 0x867, 0x891, 0x5, 0xd8, 0x6d, 0x2, 0x868, 0x869, 0x7, 
       0x4, 0x2, 0x2, 0x869, 0x86a, 0x7, 0xdf, 0x2, 0x2, 0x86a, 0x891, 0x5, 
       0xde, 0x70, 0x1d, 0x86b, 0x86d, 0x5, 0xfa, 0x7e, 0x2, 0x86c, 0x86e, 
       0x7, 0xdf, 0x2, 0x2, 0x86d, 0x86c, 0x3, 0x2, 0x2, 0x2, 0x86d, 0x86e, 
       0x3, 0x2, 0x2, 0x2, 0x86e, 0x86f, 0x3, 0x2, 0x2, 0x2, 0x86f, 0x871, 
       0x7, 0xb5, 0x2, 0x2, 0x870, 0x872, 0x7, 0xdf, 0x2, 0x2, 0x871, 0x870, 
       0x3, 0x2, 0x2, 0x2, 0x871, 0x872, 0x3, 0x2, 0x2, 0x2, 0x872, 0x873, 
       0x3, 0x2, 0x2, 0x2, 0x873, 0x874, 0x5, 0xde, 0x70, 0x1c, 0x874, 0x891, 
       0x3, 0x2, 0x2, 0x2, 0x875, 0x877, 0x7, 0xc5, 0x2, 0x2, 0x876, 0x878, 
       0x7, 0xdf, 0x2, 0x2, 0x877, 0x876, 0x3, 0x2, 0x2, 0x2, 0x877, 0x878, 
       0x3, 0x2, 0x2, 0x2, 0x878, 0x879, 0x3, 0x2, 0x2, 0x2, 0x879, 0x891, 
       0x5, 0xde, 0x70, 0x1a, 0x87a, 0x87c, 0x7, 0xca, 0x2, 0x2, 0x87b, 
       0x87d, 0x7, 0xdf, 0x2, 0x2, 0x87c, 0x87b, 0x3, 0x2, 0x2, 0x2, 0x87c, 
       0x87d, 0x3, 0x2, 0x2, 0x2, 0x87d, 0x87e, 0x3, 0x2, 0x2, 0x2, 0x87e, 
       0x891, 0x5, 0xde, 0x70, 0x19, 0x87f, 0x88c, 0x7, 0x6d, 0x2, 0x2, 
       0x880, 0x881, 0x7, 0xdf, 0x2, 0x2, 0x881, 0x88d, 0x5, 0xde, 0x70, 
       0x2, 0x882, 0x884, 0x7, 0xc3, 0x2, 0x2, 0x883, 0x885, 0x7, 0xdf, 
       0x2, 0x2, 0x884, 0x883, 0x3, 0x2, 0x2, 0x2, 0x884, 0x885, 0x3, 0x2, 
       0x2, 0x2, 0x885, 0x886, 0x3, 0x2, 0x2, 0x2, 0x886, 0x888, 0x5, 0xde, 
       0x70, 0x2, 0x887, 0x889, 0x7, 0xdf, 0x2, 0x2, 0x888, 0x887, 0x3, 
       0x2, 0x2, 0x2, 0x888, 0x889, 0x3, 0x2, 0x2, 0x2, 0x889, 0x88a, 0x3, 
       0x2, 0x2, 0x2, 0x88a, 0x88b, 0x7, 0xce, 0x2, 0x2, 0x88b, 0x88d, 0x3, 
       0x2, 0x2, 0x2, 0x88c, 0x880, 0x3, 0x2, 0x2, 0x2, 0x88c, 0x882, 0x3, 
       0x2, 0x2, 0x2, 0x88d, 0x891, 0x3, 0x2, 0x2, 0x2, 0x88e, 0x891, 0x5, 
       0xfa, 0x7e, 0x2, 0x88f, 0x891, 0x5, 0x8c, 0x47, 0x2, 0x890, 0x84b, 
       0x3, 0x2, 0x2, 0x2, 0x890, 0x84d, 0x3, 0x2, 0x2, 0x2, 0x890, 0x864, 
       0x3, 0x2, 0x2, 0x2, 0x890, 0x867, 0x3, 0x2, 0x2, 0x2, 0x890, 0x868, 
       0x3, 0x2, 0x2, 0x2, 0x890, 0x86b, 0x3, 0x2, 0x2, 0x2, 0x890, 0x875, 
       0x3, 0x2, 0x2, 0x2, 0x890, 0x87a, 0x3, 0x2, 0x2, 0x2, 0x890, 0x87f, 
       0x3, 0x2, 0x2, 0x2, 0x890, 0x88e, 0x3, 0x2, 0x2, 0x2, 0x890, 0x88f, 
       0x3, 0x2, 0x2, 0x2, 0x891, 0x940, 0x3, 0x2, 0x2, 0x2, 0x892, 0x894, 
       0xc, 0x1b, 0x2, 0x2, 0x893, 0x895, 0x7, 0xdf, 0x2, 0x2, 0x894, 0x893, 
       0x3, 0x2, 0x2, 0x2, 0x894, 0x895, 0x3, 0x2, 0x2, 0x2, 0x895, 0x896, 
       0x3, 0x2, 0x2, 0x2, 0x896, 0x898, 0x7, 0xcc, 0x2, 0x2, 0x897, 0x899, 
       0x7, 0xdf, 0x2, 0x2, 0x898, 0x897, 0x3, 0x2, 0x2, 0x2, 0x898, 0x899, 
       0x3, 0x2, 0x2, 0x2, 0x899, 0x89a, 0x3, 0x2, 0x2, 0x2, 0x89a, 0x93f, 
       0x5, 0xde, 0x70, 0x1c, 0x89b, 0x89d, 0xc, 0x18, 0x2, 0x2, 0x89c, 
       0x89e, 0x7, 0xdf, 0x2, 0x2, 0x89d, 0x89c, 0x3, 0x2, 0x2, 0x2, 0x89d, 
       0x89e, 0x3, 0x2, 0x2, 0x2, 0x89e, 0x89f, 0x3, 0x2, 0x2, 0x2, 0x89f, 
       0x8a1, 0x7, 0xb9, 0x2, 0x2, 0x8a0, 0x8a2, 0x7, 0xdf, 0x2, 0x2, 0x8a1, 
       0x8a0, 0x3, 0x2, 0x2, 0x2, 0x8a1, 0x8a2, 0x3, 0x2, 0x2, 0x2, 0x8a2, 
       0x8a3, 0x3, 0x2, 0x2, 0x2, 0x8a3, 0x93f, 0x5, 0xde, 0x70, 0x19, 0x8a4, 
       0x8a6, 0xc, 0x17, 0x2, 0x2, 0x8a5, 0x8a7, 0x7, 0xdf, 0x2, 0x2, 0x8a6, 
       0x8a5, 0x3, 0x2, 0x2, 0x2, 0x8a6, 0x8a7, 0x3, 0x2, 0x2, 0x2, 0x8a7, 
       0x8a8, 0x3, 0x2, 0x2, 0x2, 0x8a8, 0x8aa, 0x7, 0xc7, 0x2, 0x2, 0x8a9, 
       0x8ab, 0x7, 0xdf, 0x2, 0x2, 0x8aa, 0x8a9, 0x3, 0x2, 0x2, 0x2, 0x8aa, 
       0x8ab, 0x3, 0x2, 0x2, 0x2, 0x8ab, 0x8ac, 0x3, 0x2, 0x2, 0x2, 0x8ac, 
       0x93f, 0x5, 0xde, 0x70, 0x18, 0x8ad, 0x8af, 0xc, 0x16, 0x2, 0x2, 
       0x8ae, 0x8b0, 0x7, 0xdf, 0x2, 0x2, 0x8af, 0x8ae, 0x3, 0x2, 0x2, 0x2, 
       0x8af, 0x8b0, 0x3, 0x2, 0x2, 0x2, 0x8b0, 0x8b1, 0x3, 0x2, 0x2, 0x2, 
       0x8b1, 0x8b3, 0x7, 0x69, 0x2, 0x2, 0x8b2, 0x8b4, 0x7, 0xdf, 0x2, 
       0x2, 0x8b3, 0x8b2, 0x3, 0x2, 0x2, 0x2, 0x8b3, 0x8b4, 0x3, 0x2, 0x2, 
       0x2, 0x8b4, 0x8b5, 0x3, 0x2, 0x2, 0x2, 0x8b5, 0x93f, 0x5, 0xde, 0x70, 
       0x17, 0x8b6, 0x8b8, 0xc, 0x15, 0x2, 0x2, 0x8b7, 0x8b9, 0x7, 0xdf, 
       0x2, 0x2, 0x8b8, 0x8b7, 
  };
  static uint16_t serializedATNSegment1[] = {
    0x3, 0x2, 0x2, 0x2, 0x8b8, 0x8b9, 0x3, 0x2, 0x2, 0x2, 0x8b9, 0x8ba, 
       0x3, 0x2, 0x2, 0x2, 0x8ba, 0x8bc, 0x7, 0xca, 0x2, 0x2, 0x8bb, 0x8bd, 
       0x7, 0xdf, 0x2, 0x2, 0x8bc, 0x8bb, 0x3, 0x2, 0x2, 0x2, 0x8bc, 0x8bd, 
       0x3, 0x2, 0x2, 0x2, 0x8bd, 0x8be, 0x3, 0x2, 0x2, 0x2, 0x8be, 0x93f, 
       0x5, 0xde, 0x70, 0x16, 0x8bf, 0x8c1, 0xc, 0x14, 0x2, 0x2, 0x8c0, 
       0x8c2, 0x7, 0xdf, 0x2, 0x2, 0x8c1, 0x8c0, 0x3, 0x2, 0x2, 0x2, 0x8c1, 
       0x8c2, 0x3, 0x2, 0x2, 0x2, 0x8c2, 0x8c3, 0x3, 0x2, 0x2, 0x2, 0x8c3, 
       0x8c5, 0x7, 0xc5, 0x2, 0x2, 0x8c4, 0x8c6, 0x7, 0xdf, 0x2, 0x2, 0x8c5, 
       0x8c4, 0x3, 0x2, 0x2, 0x2, 0x8c5, 0x8c6, 0x3, 0x2, 0x2, 0x2, 0x8c6, 
       0x8c7, 0x3, 0x2, 0x2, 0x2, 0x8c7, 0x93f, 0x5, 0xde, 0x70, 0x15, 0x8c8, 
       0x8ca, 0xc, 0x13, 0x2, 0x2, 0x8c9, 0x8cb, 0x7, 0xdf, 0x2, 0x2, 0x8ca, 
       0x8c9, 0x3, 0x2, 0x2, 0x2, 0x8ca, 0x8cb, 0x3, 0x2, 0x2, 0x2, 0x8cb, 
       0x8cc, 0x3, 0x2, 0x2, 0x2, 0x8cc, 0x8ce, 0x7, 0xb4, 0x2, 0x2, 0x8cd, 
       0x8cf, 0x7, 0xdf, 0x2, 0x2, 0x8ce, 0x8cd, 0x3, 0x2, 0x2, 0x2, 0x8ce, 
       0x8cf, 0x3, 0x2, 0x2, 0x2, 0x8cf, 0x8d0, 0x3, 0x2, 0x2, 0x2, 0x8d0, 
       0x93f, 0x5, 0xde, 0x70, 0x14, 0x8d1, 0x8d3, 0xc, 0x12, 0x2, 0x2, 
       0x8d2, 0x8d4, 0x7, 0xdf, 0x2, 0x2, 0x8d3, 0x8d2, 0x3, 0x2, 0x2, 0x2, 
       0x8d3, 0x8d4, 0x3, 0x2, 0x2, 0x2, 0x8d4, 0x8d5, 0x3, 0x2, 0x2, 0x2, 
       0x8d5, 0x8d7, 0x7, 0xbc, 0x2, 0x2, 0x8d6, 0x8d8, 0x7, 0xdf, 0x2, 
       0x2, 0x8d7, 0x8d6, 0x3, 0x2, 0x2, 0x2, 0x8d7, 0x8d8, 0x3, 0x2, 0x2, 
       0x2, 0x8d8, 0x8d9, 0x3, 0x2, 0x2, 0x2, 0x8d9, 0x93f, 0x5, 0xde, 0x70, 
       0x13, 0x8da, 0x8dc, 0xc, 0x11, 0x2, 0x2, 0x8db, 0x8dd, 0x7, 0xdf, 
       0x2, 0x2, 0x8dc, 0x8db, 0x3, 0x2, 0x2, 0x2, 0x8dc, 0x8dd, 0x3, 0x2, 
       0x2, 0x2, 0x8dd, 0x8de, 0x3, 0x2, 0x2, 0x2, 0x8de, 0x8e0, 0x7, 0xc8, 
       0x2, 0x2, 0x8df, 0x8e1, 0x7, 0xdf, 0x2, 0x2, 0x8e0, 0x8df, 0x3, 0x2, 
       0x2, 0x2, 0x8e0, 0x8e1, 0x3, 0x2, 0x2, 0x2, 0x8e1, 0x8e2, 0x3, 0x2, 
       0x2, 0x2, 0x8e2, 0x93f, 0x5, 0xde, 0x70, 0x12, 0x8e3, 0x8e5, 0xc, 
       0x10, 0x2, 0x2, 0x8e4, 0x8e6, 0x7, 0xdf, 0x2, 0x2, 0x8e5, 0x8e4, 
       0x3, 0x2, 0x2, 0x2, 0x8e5, 0x8e6, 0x3, 0x2, 0x2, 0x2, 0x8e6, 0x8e7, 
       0x3, 0x2, 0x2, 0x2, 0x8e7, 0x8e9, 0x7, 0xc4, 0x2, 0x2, 0x8e8, 0x8ea, 
       0x7, 0xdf, 0x2, 0x2, 0x8e9, 0x8e8, 0x3, 0x2, 0x2, 0x2, 0x8e9, 0x8ea, 
       0x3, 0x2, 0x2, 0x2, 0x8ea, 0x8eb, 0x3, 0x2, 0x2, 0x2, 0x8eb, 0x93f, 
       0x5, 0xde, 0x70, 0x11, 0x8ec, 0x8ee, 0xc, 0xf, 0x2, 0x2, 0x8ed, 0x8ef, 
       0x7, 0xdf, 0x2, 0x2, 0x8ee, 0x8ed, 0x3, 0x2, 0x2, 0x2, 0x8ee, 0x8ef, 
       0x3, 0x2, 0x2, 0x2, 0x8ef, 0x8f0, 0x3, 0x2, 0x2, 0x2, 0x8f0, 0x8f2, 
       0x7, 0xbf, 0x2, 0x2, 0x8f1, 0x8f3, 0x7, 0xdf, 0x2, 0x2, 0x8f2, 0x8f1, 
       0x3, 0x2, 0x2, 0x2, 0x8f2, 0x8f3, 0x3, 0x2, 0x2, 0x2, 0x8f3, 0x8f4, 
       0x3, 0x2, 0x2, 0x2, 0x8f4, 0x93f, 0x5, 0xde, 0x70, 0x10, 0x8f5, 0x8f7, 
       0xc, 0xe, 0x2, 0x2, 0x8f6, 0x8f8, 0x7, 0xdf, 0x2, 0x2, 0x8f7, 0x8f6, 
       0x3, 0x2, 0x2, 0x2, 0x8f7, 0x8f8, 0x3, 0x2, 0x2, 0x2, 0x8f8, 0x8f9, 
       0x3, 0x2, 0x2, 0x2, 0x8f9, 0x8fb, 0x7, 0xc1, 0x2, 0x2, 0x8fa, 0x8fc, 
       0x7, 0xdf, 0x2, 0x2, 0x8fb, 0x8fa, 0x3, 0x2, 0x2, 0x2, 0x8fb, 0x8fc, 
       0x3, 0x2, 0x2, 0x2, 0x8fc, 0x8fd, 0x3, 0x2, 0x2, 0x2, 0x8fd, 0x93f, 
       0x5, 0xde, 0x70, 0xf, 0x8fe, 0x900, 0xc, 0xd, 0x2, 0x2, 0x8ff, 0x901, 
       0x7, 0xdf, 0x2, 0x2, 0x900, 0x8ff, 0x3, 0x2, 0x2, 0x2, 0x900, 0x901, 
       0x3, 0x2, 0x2, 0x2, 0x901, 0x902, 0x3, 0x2, 0x2, 0x2, 0x902, 0x904, 
       0x7, 0xbe, 0x2, 0x2, 0x903, 0x905, 0x7, 0xdf, 0x2, 0x2, 0x904, 0x903, 
       0x3, 0x2, 0x2, 0x2, 0x904, 0x905, 0x3, 0x2, 0x2, 0x2, 0x905, 0x906, 
       0x3, 0x2, 0x2, 0x2, 0x906, 0x93f, 0x5, 0xde, 0x70, 0xe, 0x907, 0x908, 
       0xc, 0xc, 0x2, 0x2, 0x908, 0x909, 0x7, 0xdf, 0x2, 0x2, 0x909, 0x90a, 
       0x7, 0x5c, 0x2, 0x2, 0x90a, 0x90b, 0x7, 0xdf, 0x2, 0x2, 0x90b, 0x93f, 
       0x5, 0xde, 0x70, 0xd, 0x90c, 0x90d, 0xc, 0xb, 0x2, 0x2, 0x90d, 0x90e, 
       0x7, 0xdf, 0x2, 0x2, 0x90e, 0x90f, 0x7, 0x52, 0x2, 0x2, 0x90f, 0x910, 
       0x7, 0xdf, 0x2, 0x2, 0x910, 0x93f, 0x5, 0xde, 0x70, 0xc, 0x911, 0x913, 
       0xc, 0x9, 0x2, 0x2, 0x912, 0x914, 0x7, 0xdf, 0x2, 0x2, 0x913, 0x912, 
       0x3, 0x2, 0x2, 0x2, 0x913, 0x914, 0x3, 0x2, 0x2, 0x2, 0x914, 0x915, 
       0x3, 0x2, 0x2, 0x2, 0x915, 0x917, 0x7, 0x6, 0x2, 0x2, 0x916, 0x918, 
       0x7, 0xdf, 0x2, 0x2, 0x917, 0x916, 0x3, 0x2, 0x2, 0x2, 0x917, 0x918, 
       0x3, 0x2, 0x2, 0x2, 0x918, 0x919, 0x3, 0x2, 0x2, 0x2, 0x919, 0x93f, 
       0x5, 0xde, 0x70, 0xa, 0x91a, 0x91c, 0xc, 0x8, 0x2, 0x2, 0x91b, 0x91d, 
       0x7, 0xdf, 0x2, 0x2, 0x91c, 0x91b, 0x3, 0x2, 0x2, 0x2, 0x91c, 0x91d, 
       0x3, 0x2, 0x2, 0x2, 0x91d, 0x91e, 0x3, 0x2, 0x2, 0x2, 0x91e, 0x920, 
       0x7, 0x7a, 0x2, 0x2, 0x91f, 0x921, 0x7, 0xdf, 0x2, 0x2, 0x920, 0x91f, 
       0x3, 0x2, 0x2, 0x2, 0x920, 0x921, 0x3, 0x2, 0x2, 0x2, 0x921, 0x922, 
       0x3, 0x2, 0x2, 0x2, 0x922, 0x93f, 0x5, 0xde, 0x70, 0x9, 0x923, 0x925, 
       0xc, 0x7, 0x2, 0x2, 0x924, 0x926, 0x7, 0xdf, 0x2, 0x2, 0x925, 0x924, 
       0x3, 0x2, 0x2, 0x2, 0x925, 0x926, 0x3, 0x2, 0x2, 0x2, 0x926, 0x927, 
       0x3, 0x2, 0x2, 0x2, 0x927, 0x929, 0x7, 0xb3, 0x2, 0x2, 0x928, 0x92a, 
       0x7, 0xdf, 0x2, 0x2, 0x929, 0x928, 0x3, 0x2, 0x2, 0x2, 0x929, 0x92a, 
       0x3, 0x2, 0x2, 0x2, 0x92a, 0x92b, 0x3, 0x2, 0x2, 0x2, 0x92b, 0x93f, 
       0x5, 0xde, 0x70, 0x8, 0x92c, 0x92e, 0xc, 0x6, 0x2, 0x2, 0x92d, 0x92f, 
       0x7, 0xdf, 0x2, 0x2, 0x92e, 0x92d, 0x3, 0x2, 0x2, 0x2, 0x92e, 0x92f, 
       0x3, 0x2, 0x2, 0x2, 0x92f, 0x930, 0x3, 0x2, 0x2, 0x2, 0x930, 0x932, 
       0x7, 0x3b, 0x2, 0x2, 0x931, 0x933, 0x7, 0xdf, 0x2, 0x2, 0x932, 0x931, 
       0x3, 0x2, 0x2, 0x2, 0x932, 0x933, 0x3, 0x2, 0x2, 0x2, 0x933, 0x934, 
       0x3, 0x2, 0x2, 0x2, 0x934, 0x93f, 0x5, 0xde, 0x70, 0x7, 0x935, 0x937, 
       0xc, 0x5, 0x2, 0x2, 0x936, 0x938, 0x7, 0xdf, 0x2, 0x2, 0x937, 0x936, 
       0x3, 0x2, 0x2, 0x2, 0x937, 0x938, 0x3, 0x2, 0x2, 0x2, 0x938, 0x939, 
       0x3, 0x2, 0x2, 0x2, 0x939, 0x93b, 0x7, 0x4e, 0x2, 0x2, 0x93a, 0x93c, 
       0x7, 0xdf, 0x2, 0x2, 0x93b, 0x93a, 0x3, 0x2, 0x2, 0x2, 0x93b, 0x93c, 
       0x3, 0x2, 0x2, 0x2, 0x93c, 0x93d, 0x3, 0x2, 0x2, 0x2, 0x93d, 0x93f, 
       0x5, 0xde, 0x70, 0x6, 0x93e, 0x892, 0x3, 0x2, 0x2, 0x2, 0x93e, 0x89b, 
       0x3, 0x2, 0x2, 0x2, 0x93e, 0x8a4, 0x3, 0x2, 0x2, 0x2, 0x93e, 0x8ad, 
       0x3, 0x2, 0x2, 0x2, 0x93e, 0x8b6, 0x3, 0x2, 0x2, 0x2, 0x93e, 0x8bf, 
       0x3, 0x2, 0x2, 0x2, 0x93e, 0x8c8, 0x3, 0x2, 0x2, 0x2, 0x93e, 0x8d1, 
       0x3, 0x2, 0x2, 0x2, 0x93e, 0x8da, 0x3, 0x2, 0x2, 0x2, 0x93e, 0x8e3, 
       0x3, 0x2, 0x2, 0x2, 0x93e, 0x8ec, 0x3, 0x2, 0x2, 0x2, 0x93e, 0x8f5, 
       0x3, 0x2, 0x2, 0x2, 0x93e, 0x8fe, 0x3, 0x2, 0x2, 0x2, 0x93e, 0x907, 
       0x3, 0x2, 0x2, 0x2, 0x93e, 0x90c, 0x3, 0x2, 0x2, 0x2, 0x93e, 0x911, 
       0x3, 0x2, 0x2, 0x2, 0x93e, 0x91a, 0x3, 0x2, 0x2, 0x2, 0x93e, 0x923, 
       0x3, 0x2, 0x2, 0x2, 0x93e, 0x92c, 0x3, 0x2, 0x2, 0x2, 0x93e, 0x935, 
       0x3, 0x2, 0x2, 0x2, 0x93f, 0x942, 0x3, 0x2, 0x2, 0x2, 0x940, 0x93e, 
       0x3, 0x2, 0x2, 0x2, 0x940, 0x941, 0x3, 0x2, 0x2, 0x2, 0x941, 0xdf, 
       0x3, 0x2, 0x2, 0x2, 0x942, 0x940, 0x3, 0x2, 0x2, 0x2, 0x943, 0x947, 
       0x7, 0x2a, 0x2, 0x2, 0x944, 0x947, 0x7, 0x9b, 0x2, 0x2, 0x945, 0x947, 
       0x5, 0x134, 0x9b, 0x2, 0x946, 0x943, 0x3, 0x2, 0x2, 0x2, 0x946, 0x944, 
       0x3, 0x2, 0x2, 0x2, 0x946, 0x945, 0x3, 0x2, 0x2, 0x2, 0x947, 0x948, 
       0x3, 0x2, 0x2, 0x2, 0x948, 0x94b, 0x7, 0xdf, 0x2, 0x2, 0x949, 0x94a, 
       0x7, 0xb1, 0x2, 0x2, 0x94a, 0x94c, 0x7, 0xdf, 0x2, 0x2, 0x94b, 0x949, 
       0x3, 0x2, 0x2, 0x2, 0x94b, 0x94c, 0x3, 0x2, 0x2, 0x2, 0x94c, 0x94d, 
       0x3, 0x2, 0x2, 0x2, 0x94d, 0x94e, 0x5, 0xe2, 0x72, 0x2, 0x94e, 0xe1, 
       0x3, 0x2, 0x2, 0x2, 0x94f, 0x95a, 0x5, 0xe4, 0x73, 0x2, 0x950, 0x952, 
       0x7, 0xdf, 0x2, 0x2, 0x951, 0x950, 0x3, 0x2, 0x2, 0x2, 0x951, 0x952, 
       0x3, 0x2, 0x2, 0x2, 0x952, 0x953, 0x3, 0x2, 0x2, 0x2, 0x953, 0x955, 
       0x7, 0xb8, 0x2, 0x2, 0x954, 0x956, 0x7, 0xdf, 0x2, 0x2, 0x955, 0x954, 
       0x3, 0x2, 0x2, 0x2, 0x955, 0x956, 0x3, 0x2, 0x2, 0x2, 0x956, 0x957, 
       0x3, 0x2, 0x2, 0x2, 0x957, 0x959, 0x5, 0xe4, 0x73, 0x2, 0x958, 0x951, 
       0x3, 0x2, 0x2, 0x2, 0x959, 0x95c, 0x3, 0x2, 0x2, 0x2, 0x95a, 0x958, 
       0x3, 0x2, 0x2, 0x2, 0x95a, 0x95b, 0x3, 0x2, 0x2, 0x2, 0x95b, 0xe3, 
       0x3, 0x2, 0x2, 0x2, 0x95c, 0x95a, 0x3, 0x2, 0x2, 0x2, 0x95d, 0x95f, 
       0x5, 0x118, 0x8d, 0x2, 0x95e, 0x960, 0x5, 0x132, 0x9a, 0x2, 0x95f, 
       0x95e, 0x3, 0x2, 0x2, 0x2, 0x95f, 0x960, 0x3, 0x2, 0x2, 0x2, 0x960, 
       0x972, 0x3, 0x2, 0x2, 0x2, 0x961, 0x963, 0x7, 0xdf, 0x2, 0x2, 0x962, 
       0x961, 0x3, 0x2, 0x2, 0x2, 0x962, 0x963, 0x3, 0x2, 0x2, 0x2, 0x963, 
       0x964, 0x3, 0x2, 0x2, 0x2, 0x964, 0x966, 0x7, 0xc3, 0x2, 0x2, 0x965, 
       0x967, 0x7, 0xdf, 0x2, 0x2, 0x966, 0x965, 0x3, 0x2, 0x2, 0x2, 0x966, 
       0x967, 0x3, 0x2, 0x2, 0x2, 0x967, 0x96c, 0x3, 0x2, 0x2, 0x2, 0x968, 
       0x96a, 0x5, 0x114, 0x8b, 0x2, 0x969, 0x96b, 0x7, 0xdf, 0x2, 0x2, 
       0x96a, 0x969, 0x3, 0x2, 0x2, 0x2, 0x96a, 0x96b, 0x3, 0x2, 0x2, 0x2, 
       0x96b, 0x96d, 0x3, 0x2, 0x2, 0x2, 0x96c, 0x968, 0x3, 0x2, 0x2, 0x2, 
       0x96c, 0x96d, 0x3, 0x2, 0x2, 0x2, 0x96d, 0x96e, 0x3, 0x2, 0x2, 0x2, 
       0x96e, 0x970, 0x7, 0xce, 0x2, 0x2, 0x96f, 0x971, 0x7, 0xdf, 0x2, 
       0x2, 0x970, 0x96f, 0x3, 0x2, 0x2, 0x2, 0x970, 0x971, 0x3, 0x2, 0x2, 
       0x2, 0x971, 0x973, 0x3, 0x2, 0x2, 0x2, 0x972, 0x962, 0x3, 0x2, 0x2, 
       0x2, 0x972, 0x973, 0x3, 0x2, 0x2, 0x2, 0x973, 0x976, 0x3, 0x2, 0x2, 
       0x2, 0x974, 0x975, 0x7, 0xdf, 0x2, 0x2, 0x975, 0x977, 0x5, 0x11a, 
       0x8e, 0x2, 0x976, 0x974, 0x3, 0x2, 0x2, 0x2, 0x976, 0x977, 0x3, 0x2, 
       0x2, 0x2, 0x977, 0xe5, 0x3, 0x2, 0x2, 0x2, 0x978, 0x979, 0x7, 0xae, 
       0x2, 0x2, 0x979, 0x97a, 0x7, 0xdf, 0x2, 0x2, 0x97a, 0x97c, 0x5, 0xde, 
       0x70, 0x2, 0x97b, 0x97d, 0x7, 0xdd, 0x2, 0x2, 0x97c, 0x97b, 0x3, 
       0x2, 0x2, 0x2, 0x97d, 0x97e, 0x3, 0x2, 0x2, 0x2, 0x97e, 0x97c, 0x3, 
       0x2, 0x2, 0x2, 0x97e, 0x97f, 0x3, 0x2, 0x2, 0x2, 0x97f, 0x983, 0x3, 
       0x2, 0x2, 0x2, 0x980, 0x982, 0x5, 0x32, 0x1a, 0x2, 0x981, 0x980, 
       0x3, 0x2, 0x2, 0x2, 0x982, 0x985, 0x3, 0x2, 0x2, 0x2, 0x983, 0x981, 
       0x3, 0x2, 0x2, 0x2, 0x983, 0x984, 0x3, 0x2, 0x2, 0x2, 0x984, 0x989, 
       0x3, 0x2, 0x2, 0x2, 0x985, 0x983, 0x3, 0x2, 0x2, 0x2, 0x986, 0x988, 
       0x7, 0xdd, 0x2, 0x2, 0x987, 0x986, 0x3, 0x2, 0x2, 0x2, 0x988, 0x98b, 
       0x3, 0x2, 0x2, 0x2, 0x989, 0x987, 0x3, 0x2, 0x2, 0x2, 0x989, 0x98a, 
       0x3, 0x2, 0x2, 0x2, 0x98a, 0x98c, 0x3, 0x2, 0x2, 0x2, 0x98b, 0x989, 
       0x3, 0x2, 0x2, 0x2, 0x98c, 0x98d, 0x7, 0xad, 0x2, 0x2, 0x98d, 0xe7, 
       0x3, 0x2, 0x2, 0x2, 0x98e, 0x98f, 0x7, 0xaf, 0x2, 0x2, 0x98f, 0x990, 
       0x7, 0xdf, 0x2, 0x2, 0x990, 0x992, 0x5, 0xde, 0x70, 0x2, 0x991, 0x993, 
       0x7, 0xdf, 0x2, 0x2, 0x992, 0x991, 0x3, 0x2, 0x2, 0x2, 0x992, 0x993, 
       0x3, 0x2, 0x2, 0x2, 0x993, 0x994, 0x3, 0x2, 0x2, 0x2, 0x994, 0x996, 
       0x7, 0xb8, 0x2, 0x2, 0x995, 0x997, 0x7, 0xdf, 0x2, 0x2, 0x996, 0x995, 
       0x3, 0x2, 0x2, 0x2, 0x996, 0x997, 0x3, 0x2, 0x2, 0x2, 0x997, 0x998, 
       0x3, 0x2, 0x2, 0x2, 0x998, 0x999, 0x5, 0xde, 0x70, 0x2, 0x999, 0xe9, 
       0x3, 0x2, 0x2, 0x2, 0x99a, 0x99b, 0x7, 0xb0, 0x2, 0x2, 0x99b, 0x99e, 
       0x7, 0xdf, 0x2, 0x2, 0x99c, 0x99d, 0x7, 0x6c, 0x2, 0x2, 0x99d, 0x99f, 
       0x7, 0xdf, 0x2, 0x2, 0x99e, 0x99c, 0x3, 0x2, 0x2, 0x2, 0x99e, 0x99f, 
       0x3, 0x2, 0x2, 0x2, 0x99f, 0x9a0, 0x3, 0x2, 0x2, 0x2, 0x9a0, 0x9a2, 
       0x5, 0xfa, 0x7e, 0x2, 0x9a1, 0x9a3, 0x7, 0xdd, 0x2, 0x2, 0x9a2, 0x9a1, 
       0x3, 0x2, 0x2, 0x2, 0x9a3, 0x9a4, 0x3, 0x2, 0x2, 0x2, 0x9a4, 0x9a2, 
       0x3, 0x2, 0x2, 0x2, 0x9a4, 0x9a5, 0x3, 0x2, 0x2, 0x2, 0x9a5, 0x9ac, 
       0x3, 0x2, 0x2, 0x2, 0x9a6, 0x9a8, 0x5, 0x32, 0x1a, 0x2, 0x9a7, 0x9a9, 
       0x7, 0xdd, 0x2, 0x2, 0x9a8, 0x9a7, 0x3, 0x2, 0x2, 0x2, 0x9a9, 0x9aa, 
       0x3, 0x2, 0x2, 0x2, 0x9aa, 0x9a8, 0x3, 0x2, 0x2, 0x2, 0x9aa, 0x9ab, 
       0x3, 0x2, 0x2, 0x2, 0x9ab, 0x9ad, 0x3, 0x2, 0x2, 0x2, 0x9ac, 0x9a6, 
       0x3, 0x2, 0x2, 0x2, 0x9ac, 0x9ad, 0x3, 0x2, 0x2, 0x2, 0x9ad, 0x9ae, 
       0x3, 0x2, 0x2, 0x2, 0x9ae, 0x9af, 0x7, 0x37, 0x2, 0x2, 0x9af, 0xeb, 
       0x3, 0x2, 0x2, 0x2, 0x9b0, 0x9b1, 0x7, 0xb2, 0x2, 0x2, 0x9b1, 0x9b2, 
       0x7, 0xdf, 0x2, 0x2, 0x9b2, 0x9b4, 0x5, 0xde, 0x70, 0x2, 0x9b3, 0x9b5, 
       0x7, 0xdf, 0x2, 0x2, 0x9b4, 0x9b3, 0x3, 0x2, 0x2, 0x2, 0x9b4, 0x9b5, 
       0x3, 0x2, 0x2, 0x2, 0x9b5, 0x9b6, 0x3, 0x2, 0x2, 0x2, 0x9b6, 0x9bb, 
       0x7, 0xb8, 0x2, 0x2, 0x9b7, 0x9b9, 0x7, 0xdf, 0x2, 0x2, 0x9b8, 0x9b7, 
       0x3, 0x2, 0x2, 0x2, 0x9b8, 0x9b9, 0x3, 0x2, 0x2, 0x2, 0x9b9, 0x9ba, 
       0x3, 0x2, 0x2, 0x2, 0x9ba, 0x9bc, 0x5, 0x9a, 0x4e, 0x2, 0x9bb, 0x9b8, 
       0x3, 0x2, 0x2, 0x2, 0x9bb, 0x9bc, 0x3, 0x2, 0x2, 0x2, 0x9bc, 0xed, 
       0x3, 0x2, 0x2, 0x2, 0x9bd, 0x9c0, 0x5, 0xf0, 0x79, 0x2, 0x9be, 0x9c0, 
       0x5, 0xf2, 0x7a, 0x2, 0x9bf, 0x9bd, 0x3, 0x2, 0x2, 0x2, 0x9bf, 0x9be, 
       0x3, 0x2, 0x2, 0x2, 0x9c0, 0xef, 0x3, 0x2, 0x2, 0x2, 0x9c1, 0x9c2, 
       0x7, 0x13, 0x2, 0x2, 0x9c2, 0x9c3, 0x7, 0xdf, 0x2, 0x2, 0x9c3, 0x9c5, 
       0x5, 0x118, 0x8d, 0x2, 0x9c4, 0x9c6, 0x5, 0x132, 0x9a, 0x2, 0x9c5, 
       0x9c4, 0x3, 0x2, 0x2, 0x2, 0x9c5, 0x9c6, 0x3, 0x2, 0x2, 0x2, 0x9c6, 
       0x9d4, 0x3, 0x2, 0x2, 0x2, 0x9c7, 0x9c9, 0x7, 0xdf, 0x2, 0x2, 0x9c8, 
       0x9c7, 0x3, 0x2, 0x2, 0x2, 0x9c8, 0x9c9, 0x3, 0x2, 0x2, 0x2, 0x9c9, 
       0x9ca, 0x3, 0x2, 0x2, 0x2, 0x9ca, 0x9cc, 0x7, 0xc3, 0x2, 0x2, 0x9cb, 
       0x9cd, 0x7, 0xdf, 0x2, 0x2, 0x9cc, 0x9cb, 0x3, 0x2, 0x2, 0x2, 0x9cc, 
       0x9cd, 0x3, 0x2, 0x2, 0x2, 0x9cd, 0x9ce, 0x3, 0x2, 0x2, 0x2, 0x9ce, 
       0x9d0, 0x5, 0x108, 0x85, 0x2, 0x9cf, 0x9d1, 0x7, 0xdf, 0x2, 0x2, 
       0x9d0, 0x9cf, 0x3, 0x2, 0x2, 0x2, 0x9d0, 0x9d1, 0x3, 0x2, 0x2, 0x2, 
       0x9d1, 0x9d2, 0x3, 0x2, 0x2, 0x2, 0x9d2, 0x9d3, 0x7, 0xce, 0x2, 0x2, 
       0x9d3, 0x9d5, 0x3, 0x2, 0x2, 0x2, 0x9d4, 0x9c8, 0x3, 0x2, 0x2, 0x2, 
       0x9d4, 0x9d5, 0x3, 0x2, 0x2, 0x2, 0x9d5, 0xf1, 0x3, 0x2, 0x2, 0x2, 
       0x9d6, 0x9d7, 0x7, 0x13, 0x2, 0x2, 0x9d7, 0x9d9, 0x7, 0xdf, 0x2, 
       0x2, 0x9d8, 0x9da, 0x5, 0xfa, 0x7e, 0x2, 0x9d9, 0x9d8, 0x3, 0x2, 
       0x2, 0x2, 0x9d9, 0x9da, 0x3, 0x2, 0x2, 0x2, 0x9da, 0x9db, 0x3, 0x2, 
       0x2, 0x2, 0x9db, 0x9dd, 0x7, 0xbb, 0x2, 0x2, 0x9dc, 0x9de, 0x7, 0xdf, 
       0x2, 0x2, 0x9dd, 0x9dc, 0x3, 0x2, 0x2, 0x2, 0x9dd, 0x9de, 0x3, 0x2, 
       0x2, 0x2, 0x9de, 0x9df, 0x3, 0x2, 0x2, 0x2, 0x9df, 0x9e1, 0x5, 0x118, 
       0x8d, 0x2, 0x9e0, 0x9e2, 0x5, 0x132, 0x9a, 0x2, 0x9e1, 0x9e0, 0x3, 
       0x2, 0x2, 0x2, 0x9e1, 0x9e2, 0x3, 0x2, 0x2, 0x2, 0x9e2, 0x9f0, 0x3, 
       0x2, 0x2, 0x2, 0x9e3, 0x9e5, 0x7, 0xdf, 0x2, 0x2, 0x9e4, 0x9e3, 0x3, 
       0x2, 0x2, 0x2, 0x9e4, 0x9e5, 0x3, 0x2, 0x2, 0x2, 0x9e5, 0x9e6, 0x3, 
       0x2, 0x2, 0x2, 0x9e6, 0x9e8, 0x7, 0xc3, 0x2, 0x2, 0x9e7, 0x9e9, 0x7, 
       0xdf, 0x2, 0x2, 0x9e8, 0x9e7, 0x3, 0x2, 0x2, 0x2, 0x9e8, 0x9e9, 0x3, 
       0x2, 0x2, 0x2, 0x9e9, 0x9ea, 0x3, 0x2, 0x2, 0x2, 0x9ea, 0x9ec, 0x5, 
       0x108, 0x85, 0x2, 0x9eb, 0x9ed, 0x7, 0xdf, 0x2, 0x2, 0x9ec, 0x9eb, 
       0x3, 0x2, 0x2, 0x2, 0x9ec, 0x9ed, 0x3, 0x2, 0x2, 0x2, 0x9ed, 0x9ee, 
       0x3, 0x2, 0x2, 0x2, 0x9ee, 0x9ef, 0x7, 0xce, 0x2, 0x2, 0x9ef, 0x9f1, 
       0x3, 0x2, 0x2, 0x2, 0x9f0, 0x9e4, 0x3, 0x2, 0x2, 0x2, 0x9f0, 0x9f1, 
       0x3, 0x2, 0x2, 0x2, 0x9f1, 0xf3, 0x3, 0x2, 0x2, 0x2, 0x9f2, 0x9f5, 
       0x5, 0xf6, 0x7c, 0x2, 0x9f3, 0x9f5, 0x5, 0xf8, 0x7d, 0x2, 0x9f4, 
       0x9f2, 0x3, 0x2, 0x2, 0x2, 0x9f4, 0x9f3, 0x3, 0x2, 0x2, 0x2, 0x9f5, 
       0xf5, 0x3, 0x2, 0x2, 0x2, 0x9f6, 0x9f9, 0x5, 0x11e, 0x90, 0x2, 0x9f7, 
       0x9f8, 0x7, 0xdf, 0x2, 0x2, 0x9f8, 0x9fa, 0x5, 0x108, 0x85, 0x2, 
       0x9f9, 0x9f7, 0x3, 0x2, 0x2, 0x2, 0x9f9, 0x9fa, 0x3, 0x2, 0x2, 0x2, 
       0x9fa, 0xf7, 0x3, 0x2, 0x2, 0x2, 0x9fb, 0x9fd, 0x5, 0xfa, 0x7e, 0x2, 
       0x9fc, 0x9fb, 0x3, 0x2, 0x2, 0x2, 0x9fc, 0x9fd, 0x3, 0x2, 0x2, 0x2, 
       0x9fd, 0x9fe, 0x3, 0x2, 0x2, 0x2, 0x9fe, 0x9ff, 0x7, 0xbb, 0x2, 0x2, 
       0x9ff, 0xa01, 0x5, 0x118, 0x8d, 0x2, 0xa00, 0xa02, 0x5, 0x132, 0x9a, 
       0x2, 0xa01, 0xa00, 0x3, 0x2, 0x2, 0x2, 0xa01, 0xa02, 0x3, 0x2, 0x2, 
       0x2, 0xa02, 0xa05, 0x3, 0x2, 0x2, 0x2, 0xa03, 0xa04, 0x7, 0xdf, 0x2, 
       0x2, 0xa04, 0xa06, 0x5, 0x108, 0x85, 0x2, 0xa05, 0xa03, 0x3, 0x2, 
       0x2, 0x2, 0xa05, 0xa06, 0x3, 0x2, 0x2, 0x2, 0xa06, 0xa08, 0x3, 0x2, 
       0x2, 0x2, 0xa07, 0xa09, 0x5, 0x10c, 0x87, 0x2, 0xa08, 0xa07, 0x3, 
       0x2, 0x2, 0x2, 0xa08, 0xa09, 0x3, 0x2, 0x2, 0x2, 0xa09, 0xf9, 0x3, 
       0x2, 0x2, 0x2, 0xa0a, 0xa0f, 0x5, 0x102, 0x82, 0x2, 0xa0b, 0xa0f, 
       0x5, 0xfc, 0x7f, 0x2, 0xa0c, 0xa0f, 0x5, 0xfe, 0x80, 0x2, 0xa0d, 
       0xa0f, 0x5, 0x106, 0x84, 0x2, 0xa0e, 0xa0a, 0x3, 0x2, 0x2, 0x2, 0xa0e, 
       0xa0b, 0x3, 0x2, 0x2, 0x2, 0xa0e, 0xa0c, 0x3, 0x2, 0x2, 0x2, 0xa0e, 
       0xa0d, 0x3, 0x2, 0x2, 0x2, 0xa0f, 0xfb, 0x3, 0x2, 0x2, 0x2, 0xa10, 
       0xa12, 0x5, 0x118, 0x8d, 0x2, 0xa11, 0xa13, 0x5, 0x132, 0x9a, 0x2, 
       0xa12, 0xa11, 0x3, 0x2, 0x2, 0x2, 0xa12, 0xa13, 0x3, 0x2, 0x2, 0x2, 
       0xa13, 0xa15, 0x3, 0x2, 0x2, 0x2, 0xa14, 0xa16, 0x5, 0x10c, 0x87, 
       0x2, 0xa15, 0xa14, 0x3, 0x2, 0x2, 0x2, 0xa15, 0xa16, 0x3, 0x2, 0x2, 
       0x2, 0xa16, 0xfd, 0x3, 0x2, 0x2, 0x2, 0xa17, 0xa1b, 0x5, 0x118, 0x8d, 
       0x2, 0xa18, 0xa1b, 0x5, 0x11c, 0x8f, 0x2, 0xa19, 0xa1b, 0x5, 0x100, 
       0x81, 0x2, 0xa1a, 0xa17, 0x3, 0x2, 0x2, 0x2, 0xa1a, 0xa18, 0x3, 0x2, 
       0x2, 0x2, 0xa1a, 0xa19, 0x3, 0x2, 0x2, 0x2, 0xa1b, 0xa1d, 0x3, 0x2, 
       0x2, 0x2, 0xa1c, 0xa1e, 0x5, 0x132, 0x9a, 0x2, 0xa1d, 0xa1c, 0x3, 
       0x2, 0x2, 0x2, 0xa1d, 0xa1e, 0x3, 0x2, 0x2, 0x2, 0xa1e, 0xa20, 0x3, 
       0x2, 0x2, 0x2, 0xa1f, 0xa21, 0x7, 0xdf, 0x2, 0x2, 0xa20, 0xa1f, 0x3, 
       0x2, 0x2, 0x2, 0xa20, 0xa21, 0x3, 0x2, 0x2, 0x2, 0xa21, 0xa2d, 0x3, 
       0x2, 0x2, 0x2, 0xa22, 0xa24, 0x7, 0xc3, 0x2, 0x2, 0xa23, 0xa25, 0x7, 
       0xdf, 0x2, 0x2, 0xa24, 0xa23, 0x3, 0x2, 0x2, 0x2, 0xa24, 0xa25, 0x3, 
       0x2, 0x2, 0x2, 0xa25, 0xa2a, 0x3, 0x2, 0x2, 0x2, 0xa26, 0xa28, 0x5, 
       0x108, 0x85, 0x2, 0xa27, 0xa29, 0x7, 0xdf, 0x2, 0x2, 0xa28, 0xa27, 
       0x3, 0x2, 0x2, 0x2, 0xa28, 0xa29, 0x3, 0x2, 0x2, 0x2, 0xa29, 0xa2b, 
       0x3, 0x2, 0x2, 0x2, 0xa2a, 0xa26, 0x3, 0x2, 0x2, 0x2, 0xa2a, 0xa2b, 
       0x3, 0x2, 0x2, 0x2, 0xa2b, 0xa2c, 0x3, 0x2, 0x2, 0x2, 0xa2c, 0xa2e, 
       0x7, 0xce, 0x2, 0x2, 0xa2d, 0xa22, 0x3, 0x2, 0x2, 0x2, 0xa2e, 0xa2f, 
       0x3, 0x2, 0x2, 0x2, 0xa2f, 0xa2d, 0x3, 0x2, 0x2, 0x2, 0xa2f, 0xa30, 
       0x3, 0x2, 0x2, 0x2, 0xa30, 0xa32, 0x3, 0x2, 0x2, 0x2, 0xa31, 0xa33, 
       0x5, 0x10c, 0x87, 0x2, 0xa32, 0xa31, 0x3, 0x2, 0x2, 0x2, 0xa32, 0xa33, 
       0x3, 0x2, 0x2, 0x2, 0xa33, 0xff, 0x3, 0x2, 0x2, 0x2, 0xa34, 0xa36, 
       0x5, 0x118, 0x8d, 0x2, 0xa35, 0xa37, 0x5, 0x132, 0x9a, 0x2, 0xa36, 
       0xa35, 0x3, 0x2, 0x2, 0x2, 0xa36, 0xa37, 0x3, 0x2, 0x2, 0x2, 0xa37, 
       0xa39, 0x3, 0x2, 0x2, 0x2, 0xa38, 0xa3a, 0x7, 0xdf, 0x2, 0x2, 0xa39, 
       0xa38, 0x3, 0x2, 0x2, 0x2, 0xa39, 0xa3a, 0x3, 0x2, 0x2, 0x2, 0xa3a, 
       0xa3b, 0x3, 0x2, 0x2, 0x2, 0xa3b, 0xa3d, 0x7, 0xc3, 0x2, 0x2, 0xa3c, 
       0xa3e, 0x7, 0xdf, 0x2, 0x2, 0xa3d, 0xa3c, 0x3, 0x2, 0x2, 0x2, 0xa3d, 
       0xa3e, 0x3, 0x2, 0x2, 0x2, 0xa3e, 0xa43, 0x3, 0x2, 0x2, 0x2, 0xa3f, 
       0xa41, 0x5, 0x108, 0x85, 0x2, 0xa40, 0xa42, 0x7, 0xdf, 0x2, 0x2, 
       0xa41, 0xa40, 0x3, 0x2, 0x2, 0x2, 0xa41, 0xa42, 0x3, 0x2, 0x2, 0x2, 
       0xa42, 0xa44, 0x3, 0x2, 0x2, 0x2, 0xa43, 0xa3f, 0x3, 0x2, 0x2, 0x2, 
       0xa43, 0xa44, 0x3, 0x2, 0x2, 0x2, 0xa44, 0xa45, 0x3, 0x2, 0x2, 0x2, 
       0xa45, 0xa46, 0x7, 0xce, 0x2, 0x2, 0xa46, 0x101, 0x3, 0x2, 0x2, 0x2, 
       0xa47, 0xa4a, 0x5, 0xfc, 0x7f, 0x2, 0xa48, 0xa4a, 0x5, 0xfe, 0x80, 
       0x2, 0xa49, 0xa47, 0x3, 0x2, 0x2, 0x2, 0xa49, 0xa48, 0x3, 0x2, 0x2, 
       0x2, 0xa49, 0xa4a, 0x3, 0x2, 0x2, 0x2, 0xa4a, 0xa4c, 0x3, 0x2, 0x2, 
       0x2, 0xa4b, 0xa4d, 0x5, 0x104, 0x83, 0x2, 0xa4c, 0xa4b, 0x3, 0x2, 
       0x2, 0x2, 0xa4d, 0xa4e, 0x3, 0x2, 0x2, 0x2, 0xa4e, 0xa4c, 0x3, 0x2, 
       0x2, 0x2, 0xa4e, 0xa4f, 0x3, 0x2, 0x2, 0x2, 0xa4f, 0xa51, 0x3, 0x2, 
       0x2, 0x2, 0xa50, 0xa52, 0x5, 0x10c, 0x87, 0x2, 0xa51, 0xa50, 0x3, 
       0x2, 0x2, 0x2, 0xa51, 0xa52, 0x3, 0x2, 0x2, 0x2, 0xa52, 0x103, 0x3, 
       0x2, 0x2, 0x2, 0xa53, 0xa55, 0x7, 0xdf, 0x2, 0x2, 0xa54, 0xa53, 0x3, 
       0x2, 0x2, 0x2, 0xa54, 0xa55, 0x3, 0x2, 0x2, 0x2, 0xa55, 0xa56, 0x3, 
       0x2, 0x2, 0x2, 0xa56, 0xa59, 0x7, 0xbb, 0x2, 0x2, 0xa57, 0xa5a, 0x5, 
       0xfc, 0x7f, 0x2, 0xa58, 0xa5a, 0x5, 0xfe, 0x80, 0x2, 0xa59, 0xa57, 
       0x3, 0x2, 0x2, 0x2, 0xa59, 0xa58, 0x3, 0x2, 0x2, 0x2, 0xa5a, 0x105, 
       0x3, 0x2, 0x2, 0x2, 0xa5b, 0xa5c, 0x5, 0x10c, 0x87, 0x2, 0xa5c, 0x107, 
       0x3, 0x2, 0x2, 0x2, 0xa5d, 0xa5f, 0x5, 0x10a, 0x86, 0x2, 0xa5e, 0xa5d, 
       0x3, 0x2, 0x2, 0x2, 0xa5e, 0xa5f, 0x3, 0x2, 0x2, 0x2, 0xa5f, 0xa61, 
       0x3, 0x2, 0x2, 0x2, 0xa60, 0xa62, 0x7, 0xdf, 0x2, 0x2, 0xa61, 0xa60, 
       0x3, 0x2, 0x2, 0x2, 0xa61, 0xa62, 0x3, 0x2, 0x2, 0x2, 0xa62, 0xa63, 
       0x3, 0x2, 0x2, 0x2, 0xa63, 0xa65, 0x9, 0xb, 0x2, 0x2, 0xa64, 0xa66, 
       0x7, 0xdf, 0x2, 0x2, 0xa65, 0xa64, 0x3, 0x2, 0x2, 0x2, 0xa65, 0xa66, 
       0x3, 0x2, 0x2, 0x2, 0xa66, 0xa68, 0x3, 0x2, 0x2, 0x2, 0xa67, 0xa5e, 
       0x3, 0x2, 0x2, 0x2, 0xa68, 0xa6b, 0x3, 0x2, 0x2, 0x2, 0xa69, 0xa67, 
       0x3, 0x2, 0x2, 0x2, 0xa69, 0xa6a, 0x3, 0x2, 0x2, 0x2, 0xa6a, 0xa6c, 
       0x3, 0x2, 0x2, 0x2, 0xa6b, 0xa69, 0x3, 0x2, 0x2, 0x2, 0xa6c, 0xa79, 
       0x5, 0x10a, 0x86, 0x2, 0xa6d, 0xa6f, 0x7, 0xdf, 0x2, 0x2, 0xa6e, 
       0xa6d, 0x3, 0x2, 0x2, 0x2, 0xa6e, 0xa6f, 0x3, 0x2, 0x2, 0x2, 0xa6f, 
       0xa70, 0x3, 0x2, 0x2, 0x2, 0xa70, 0xa72, 0x9, 0xb, 0x2, 0x2, 0xa71, 
       0xa73, 0x7, 0xdf, 0x2, 0x2, 0xa72, 0xa71, 0x3, 0x2, 0x2, 0x2, 0xa72, 
       0xa73, 0x3, 0x2, 0x2, 0x2, 0xa73, 0xa75, 0x3, 0x2, 0x2, 0x2, 0xa74, 
       0xa76, 0x5, 0x10a, 0x86, 0x2, 0xa75, 0xa74, 0x3, 0x2, 0x2, 0x2, 0xa75, 
       0xa76, 0x3, 0x2, 0x2, 0x2, 0xa76, 0xa78, 0x3, 0x2, 0x2, 0x2, 0xa77, 
       0xa6e, 0x3, 0x2, 0x2, 0x2, 0xa78, 0xa7b, 0x3, 0x2, 0x2, 0x2, 0xa79, 
       0xa77, 0x3, 0x2, 0x2, 0x2, 0xa79, 0xa7a, 0x3, 0x2, 0x2, 0x2, 0xa7a, 
       0x109, 0x3, 0x2, 0x2, 0x2, 0xa7b, 0xa79, 0x3, 0x2, 0x2, 0x2, 0xa7c, 
       0xa7d, 0x9, 0xd, 0x2, 0x2, 0xa7d, 0xa7f, 0x7, 0xdf, 0x2, 0x2, 0xa7e, 
       0xa7c, 0x3, 0x2, 0x2, 0x2, 0xa7e, 0xa7f, 0x3, 0x2, 0x2, 0x2, 0xa7f, 
       0xa80, 0x3, 0x2, 0x2, 0x2, 0xa80, 0xa81, 0x5, 0xde, 0x70, 0x2, 0xa81, 
       0x10b, 0x3, 0x2, 0x2, 0x2, 0xa82, 0xa83, 0x7, 0xbd, 0x2, 0x2, 0xa83, 
       0xa85, 0x5, 0x118, 0x8d, 0x2, 0xa84, 0xa86, 0x5, 0x132, 0x9a, 0x2, 
       0xa85, 0xa84, 0x3, 0x2, 0x2, 0x2, 0xa85, 0xa86, 0x3, 0x2, 0x2, 0x2, 
       0xa86, 0x10d, 0x3, 0x2, 0x2, 0x2, 0xa87, 0xa99, 0x7, 0xc3, 0x2, 0x2, 
       0xa88, 0xa8a, 0x7, 0xdf, 0x2, 0x2, 0xa89, 0xa88, 0x3, 0x2, 0x2, 0x2, 
       0xa89, 0xa8a, 0x3, 0x2, 0x2, 0x2, 0xa8a, 0xa8b, 0x3, 0x2, 0x2, 0x2, 
       0xa8b, 0xa96, 0x5, 0x110, 0x89, 0x2, 0xa8c, 0xa8e, 0x7, 0xdf, 0x2, 
       0x2, 0xa8d, 0xa8c, 0x3, 0x2, 0x2, 0x2, 0xa8d, 0xa8e, 0x3, 0x2, 0x2, 
       0x2, 0xa8e, 0xa8f, 0x3, 0x2, 0x2, 0x2, 0xa8f, 0xa91, 0x7, 0xb8, 0x2, 
       0x2, 0xa90, 0xa92, 0x7, 0xdf, 0x2, 0x2, 0xa91, 0xa90, 0x3, 0x2, 0x2, 
       0x2, 0xa91, 0xa92, 0x3, 0x2, 0x2, 0x2, 0xa92, 0xa93, 0x3, 0x2, 0x2, 
       0x2, 0xa93, 0xa95, 0x5, 0x110, 0x89, 0x2, 0xa94, 0xa8d, 0x3, 0x2, 
       0x2, 0x2, 0xa95, 0xa98, 0x3, 0x2, 0x2, 0x2, 0xa96, 0xa94, 0x3, 0x2, 
       0x2, 0x2, 0xa96, 0xa97, 0x3, 0x2, 0x2, 0x2, 0xa97, 0xa9a, 0x3, 0x2, 
       0x2, 0x2, 0xa98, 0xa96, 0x3, 0x2, 0x2, 0x2, 0xa99, 0xa89, 0x3, 0x2, 
       0x2, 0x2, 0xa99, 0xa9a, 0x3, 0x2, 0x2, 0x2, 0xa9a, 0xa9c, 0x3, 0x2, 
       0x2, 0x2, 0xa9b, 0xa9d, 0x7, 0xdf, 0x2, 0x2, 0xa9c, 0xa9b, 0x3, 0x2, 
       0x2, 0x2, 0xa9c, 0xa9d, 0x3, 0x2, 0x2, 0x2, 0xa9d, 0xa9e, 0x3, 0x2, 
       0x2, 0x2, 0xa9e, 0xa9f, 0x7, 0xce, 0x2, 0x2, 0xa9f, 0x10f, 0x3, 0x2, 
       0x2, 0x2, 0xaa0, 0xaa1, 0x7, 0x75, 0x2, 0x2, 0xaa1, 0xaa3, 0x7, 0xdf, 
       0x2, 0x2, 0xaa2, 0xaa0, 0x3, 0x2, 0x2, 0x2, 0xaa2, 0xaa3, 0x3, 0x2, 
       0x2, 0x2, 0xaa3, 0xaa6, 0x3, 0x2, 0x2, 0x2, 0xaa4, 0xaa5, 0x9, 0xe, 
       0x2, 0x2, 0xaa5, 0xaa7, 0x7, 0xdf, 0x2, 0x2, 0xaa6, 0xaa4, 0x3, 0x2, 
       0x2, 0x2, 0xaa6, 0xaa7, 0x3, 0x2, 0x2, 0x2, 0xaa7, 0xaaa, 0x3, 0x2, 
       0x2, 0x2, 0xaa8, 0xaa9, 0x7, 0x7c, 0x2, 0x2, 0xaa9, 0xaab, 0x7, 0xdf, 
       0x2, 0x2, 0xaaa, 0xaa8, 0x3, 0x2, 0x2, 0x2, 0xaaa, 0xaab, 0x3, 0x2, 
       0x2, 0x2, 0xaab, 0xaac, 0x3, 0x2, 0x2, 0x2, 0xaac, 0xaae, 0x5, 0x118, 
       0x8d, 0x2, 0xaad, 0xaaf, 0x5, 0x132, 0x9a, 0x2, 0xaae, 0xaad, 0x3, 
       0x2, 0x2, 0x2, 0xaae, 0xaaf, 0x3, 0x2, 0x2, 0x2, 0xaaf, 0xab8, 0x3, 
       0x2, 0x2, 0x2, 0xab0, 0xab2, 0x7, 0xdf, 0x2, 0x2, 0xab1, 0xab0, 0x3, 
       0x2, 0x2, 0x2, 0xab1, 0xab2, 0x3, 0x2, 0x2, 0x2, 0xab2, 0xab3, 0x3, 
       0x2, 0x2, 0x2, 0xab3, 0xab5, 0x7, 0xc3, 0x2, 0x2, 0xab4, 0xab6, 0x7, 
       0xdf, 0x2, 0x2, 0xab5, 0xab4, 0x3, 0x2, 0x2, 0x2, 0xab5, 0xab6, 0x3, 
       0x2, 0x2, 0x2, 0xab6, 0xab7, 0x3, 0x2, 0x2, 0x2, 0xab7, 0xab9, 0x7, 
       0xce, 0x2, 0x2, 0xab8, 0xab1, 0x3, 0x2, 0x2, 0x2, 0xab8, 0xab9, 0x3, 
       0x2, 0x2, 0x2, 0xab9, 0xabc, 0x3, 0x2, 0x2, 0x2, 0xaba, 0xabb, 0x7, 
       0xdf, 0x2, 0x2, 0xabb, 0xabd, 0x5, 0x11a, 0x8e, 0x2, 0xabc, 0xaba, 
       0x3, 0x2, 0x2, 0x2, 0xabc, 0xabd, 0x3, 0x2, 0x2, 0x2, 0xabd, 0xac2, 
       0x3, 0x2, 0x2, 0x2, 0xabe, 0xac0, 0x7, 0xdf, 0x2, 0x2, 0xabf, 0xabe, 
       0x3, 0x2, 0x2, 0x2, 0xabf, 0xac0, 0x3, 0x2, 0x2, 0x2, 0xac0, 0xac1, 
       0x3, 0x2, 0x2, 0x2, 0xac1, 0xac3, 0x5, 0x112, 0x8a, 0x2, 0xac2, 0xabf, 
       0x3, 0x2, 0x2, 0x2, 0xac2, 0xac3, 0x3, 0x2, 0x2, 0x2, 0xac3, 0x111, 
       0x3, 0x2, 0x2, 0x2, 0xac4, 0xac6, 0x7, 0xbc, 0x2, 0x2, 0xac5, 0xac7, 
       0x7, 0xdf, 0x2, 0x2, 0xac6, 0xac5, 0x3, 0x2, 0x2, 0x2, 0xac6, 0xac7, 
       0x3, 0x2, 0x2, 0x2, 0xac7, 0xac8, 0x3, 0x2, 0x2, 0x2, 0xac8, 0xac9, 
       0x5, 0xde, 0x70, 0x2, 0xac9, 0x113, 0x3, 0x2, 0x2, 0x2, 0xaca, 0xad5, 
       0x5, 0x116, 0x8c, 0x2, 0xacb, 0xacd, 0x7, 0xdf, 0x2, 0x2, 0xacc, 
       0xacb, 0x3, 0x2, 0x2, 0x2, 0xacc, 0xacd, 0x3, 0x2, 0x2, 0x2, 0xacd, 
       0xace, 0x3, 0x2, 0x2, 0x2, 0xace, 0xad0, 0x7, 0xb8, 0x2, 0x2, 0xacf, 
       0xad1, 0x7, 0xdf, 0x2, 0x2, 0xad0, 0xacf, 0x3, 0x2, 0x2, 0x2, 0xad0, 
       0xad1, 0x3, 0x2, 0x2, 0x2, 0xad1, 0xad2, 0x3, 0x2, 0x2, 0x2, 0xad2, 
       0xad4, 0x5, 0x116, 0x8c, 0x2, 0xad3, 0xacc, 0x3, 0x2, 0x2, 0x2, 0xad4, 
       0xad7, 0x3, 0x2, 0x2, 0x2, 0xad5, 0xad3, 0x3, 0x2, 0x2, 0x2, 0xad5, 
       0xad6, 0x3, 0x2, 0x2, 0x2, 0xad6, 0x115, 0x3, 0x2, 0x2, 0x2, 0xad7, 
       0xad5, 0x3, 0x2, 0x2, 0x2, 0xad8, 0xad9, 0x5, 0xde, 0x70, 0x2, 0xad9, 
       0xada, 0x7, 0xdf, 0x2, 0x2, 0xada, 0xadb, 0x7, 0xa4, 0x2, 0x2, 0xadb, 
       0xadc, 0x7, 0xdf, 0x2, 0x2, 0xadc, 0xade, 0x3, 0x2, 0x2, 0x2, 0xadd, 
       0xad8, 0x3, 0x2, 0x2, 0x2, 0xadd, 0xade, 0x3, 0x2, 0x2, 0x2, 0xade, 
       0xadf, 0x3, 0x2, 0x2, 0x2, 0xadf, 0xae0, 0x5, 0xde, 0x70, 0x2, 0xae0, 
       0x117, 0x3, 0x2, 0x2, 0x2, 0xae1, 0xae4, 0x7, 0xdb, 0x2, 0x2, 0xae2, 
       0xae4, 0x5, 0x136, 0x9c, 0x2, 0xae3, 0xae1, 0x3, 0x2, 0x2, 0x2, 0xae3, 
       0xae2, 0x3, 0x2, 0x2, 0x2, 0xae4, 0xae5, 0x3, 0x2, 0x2, 0x2, 0xae5, 
       0xae3, 0x3, 0x2, 0x2, 0x2, 0xae5, 0xae6, 0x3, 0x2, 0x2, 0x2, 0xae6, 
       0xaf0, 0x3, 0x2, 0x2, 0x2, 0xae7, 0xaea, 0x7, 0xd0, 0x2, 0x2, 0xae8, 
       0xaeb, 0x7, 0xdb, 0x2, 0x2, 0xae9, 0xaeb, 0x5, 0x136, 0x9c, 0x2, 
       0xaea, 0xae8, 0x3, 0x2, 0x2, 0x2, 0xaea, 0xae9, 0x3, 0x2, 0x2, 0x2, 
       0xaeb, 0xaec, 0x3, 0x2, 0x2, 0x2, 0xaec, 0xaea, 0x3, 0x2, 0x2, 0x2, 
       0xaec, 0xaed, 0x3, 0x2, 0x2, 0x2, 0xaed, 0xaee, 0x3, 0x2, 0x2, 0x2, 
       0xaee, 0xaf0, 0x7, 0xd1, 0x2, 0x2, 0xaef, 0xae3, 0x3, 0x2, 0x2, 0x2, 
       0xaef, 0xae7, 0x3, 0x2, 0x2, 0x2, 0xaf0, 0x119, 0x3, 0x2, 0x2, 0x2, 
       0xaf1, 0xaf2, 0x7, 0xa, 0x2, 0x2, 0xaf2, 0xaf5, 0x7, 0xdf, 0x2, 0x2, 
       0xaf3, 0xaf4, 0x7, 0x6c, 0x2, 0x2, 0xaf4, 0xaf6, 0x7, 0xdf, 0x2, 
       0x2, 0xaf5, 0xaf3, 0x3, 0x2, 0x2, 0x2, 0xaf5, 0xaf6, 0x3, 0x2, 0x2, 
       0x2, 0xaf6, 0xaf7, 0x3, 0x2, 0x2, 0x2, 0xaf7, 0xafa, 0x5, 0x130, 
       0x99, 0x2, 0xaf8, 0xaf9, 0x7, 0xdf, 0x2, 0x2, 0xaf9, 0xafb, 0x5, 
       0x124, 0x93, 0x2, 0xafa, 0xaf8, 0x3, 0x2, 0x2, 0x2, 0xafa, 0xafb, 
       0x3, 0x2, 0x2, 0x2, 0xafb, 0x11b, 0x3, 0x2, 0x2, 0x2, 0xafc, 0xafd, 
       0x9, 0xf, 0x2, 0x2, 0xafd, 0x11d, 0x3, 0x2, 0x2, 0x2, 0xafe, 0xb03, 
       0x7, 0xdb, 0x2, 0x2, 0xaff, 0xb02, 0x5, 0x136, 0x9c, 0x2, 0xb00, 
       0xb02, 0x7, 0xdb, 0x2, 0x2, 0xb01, 0xaff, 0x3, 0x2, 0x2, 0x2, 0xb01, 
       0xb00, 0x3, 0x2, 0x2, 0x2, 0xb02, 0xb05, 0x3, 0x2, 0x2, 0x2, 0xb03, 
       0xb01, 0x3, 0x2, 0x2, 0x2, 0xb03, 0xb04, 0x3, 0x2, 0x2, 0x2, 0xb04, 
       0xb0e, 0x3, 0x2, 0x2, 0x2, 0xb05, 0xb03, 0x3, 0x2, 0x2, 0x2, 0xb06, 
       0xb09, 0x5, 0x136, 0x9c, 0x2, 0xb07, 0xb0a, 0x5, 0x136, 0x9c, 0x2, 
       0xb08, 0xb0a, 0x7, 0xdb, 0x2, 0x2, 0xb09, 0xb07, 0x3, 0x2, 0x2, 0x2, 
       0xb09, 0xb08, 0x3, 0x2, 0x2, 0x2, 0xb0a, 0xb0b, 0x3, 0x2, 0x2, 0x2, 
       0xb0b, 0xb09, 0x3, 0x2, 0x2, 0x2, 0xb0b, 0xb0c, 0x3, 0x2, 0x2, 0x2, 
       0xb0c, 0xb0e, 0x3, 0x2, 0x2, 0x2, 0xb0d, 0xafe, 0x3, 0x2, 0x2, 0x2, 
       0xb0d, 0xb06, 0x3, 0x2, 0x2, 0x2, 0xb0e, 0x11f, 0x3, 0x2, 0x2, 0x2, 
       0xb0f, 0xb10, 0x9, 0x10, 0x2, 0x2, 0xb10, 0x121, 0x3, 0x2, 0x2, 0x2, 
       0xb11, 0xb16, 0x5, 0x118, 0x8d, 0x2, 0xb12, 0xb13, 0x7, 0xbb, 0x2, 
       0x2, 0xb13, 0xb15, 0x5, 0x118, 0x8d, 0x2, 0xb14, 0xb12, 0x3, 0x2, 
       0x2, 0x2, 0xb15, 0xb18, 0x3, 0x2, 0x2, 0x2, 0xb16, 0xb14, 0x3, 0x2, 
       0x2, 0x2, 0xb16, 0xb17, 0x3, 0x2, 0x2, 0x2, 0xb17, 0x123, 0x3, 0x2, 
       0x2, 0x2, 0xb18, 0xb16, 0x3, 0x2, 0x2, 0x2, 0xb19, 0xb1b, 0x7, 0xc7, 
       0x2, 0x2, 0xb1a, 0xb1c, 0x7, 0xdf, 0x2, 0x2, 0xb1b, 0xb1a, 0x3, 0x2, 
       0x2, 0x2, 0xb1b, 0xb1c, 0x3, 0x2, 0x2, 0x2, 0xb1c, 0xb1f, 0x3, 0x2, 
       0x2, 0x2, 0xb1d, 0xb20, 0x7, 0xd5, 0x2, 0x2, 0xb1e, 0xb20, 0x5, 0x118, 
       0x8d, 0x2, 0xb1f, 0xb1d, 0x3, 0x2, 0x2, 0x2, 0xb1f, 0xb1e, 0x3, 0x2, 
       0x2, 0x2, 0xb20, 0x125, 0x3, 0x2, 0x2, 0x2, 0xb21, 0xb2a, 0x5, 0x11e, 
       0x90, 0x2, 0xb22, 0xb24, 0x7, 0xdf, 0x2, 0x2, 0xb23, 0xb22, 0x3, 
       0x2, 0x2, 0x2, 0xb23, 0xb24, 0x3, 0x2, 0x2, 0x2, 0xb24, 0xb25, 0x3, 
       0x2, 0x2, 0x2, 0xb25, 0xb27, 0x7, 0xc5, 0x2, 0x2, 0xb26, 0xb28, 0x7, 
       0xdf, 0x2, 0x2, 0xb27, 0xb26, 0x3, 0x2, 0x2, 0x2, 0xb27, 0xb28, 0x3, 
       0x2, 0x2, 0x2, 0xb28, 0xb29, 0x3, 0x2, 0x2, 0x2, 0xb29, 0xb2b, 0x5, 
       0x11e, 0x90, 0x2, 0xb2a, 0xb23, 0x3, 0x2, 0x2, 0x2, 0xb2a, 0xb2b, 
       0x3, 0x2, 0x2, 0x2, 0xb2b, 0x127, 0x3, 0x2, 0x2, 0x2, 0xb2c, 0xb2d, 
       0x5, 0x118, 0x8d, 0x2, 0xb2d, 0xb2e, 0x7, 0xb7, 0x2, 0x2, 0xb2e, 
       0x129, 0x3, 0x2, 0x2, 0x2, 0xb2f, 0xb30, 0x9, 0x11, 0x2, 0x2, 0xb30, 
       0x12b, 0x3, 0x2, 0x2, 0x2, 0xb31, 0xb32, 0x9, 0x12, 0x2, 0x2, 0xb32, 
       0x12d, 0x3, 0x2, 0x2, 0x2, 0xb33, 0xb34, 0x9, 0x13, 0x2, 0x2, 0xb34, 
       0x12f, 0x3, 0x2, 0x2, 0x2, 0xb35, 0xb38, 0x5, 0x11c, 0x8f, 0x2, 0xb36, 
       0xb38, 0x5, 0x122, 0x92, 0x2, 0xb37, 0xb35, 0x3, 0x2, 0x2, 0x2, 0xb37, 
       0xb36, 0x3, 0x2, 0x2, 0x2, 0xb38, 0xb41, 0x3, 0x2, 0x2, 0x2, 0xb39, 
       0xb3b, 0x7, 0xdf, 0x2, 0x2, 0xb3a, 0xb39, 0x3, 0x2, 0x2, 0x2, 0xb3a, 
       0xb3b, 0x3, 0x2, 0x2, 0x2, 0xb3b, 0xb3c, 0x3, 0x2, 0x2, 0x2, 0xb3c, 
       0xb3e, 0x7, 0xc3, 0x2, 0x2, 0xb3d, 0xb3f, 0x7, 0xdf, 0x2, 0x2, 0xb3e, 
       0xb3d, 0x3, 0x2, 0x2, 0x2, 0xb3e, 0xb3f, 0x3, 0x2, 0x2, 0x2, 0xb3f, 
       0xb40, 0x3, 0x2, 0x2, 0x2, 0xb40, 0xb42, 0x7, 0xce, 0x2, 0x2, 0xb41, 
       0xb3a, 0x3, 0x2, 0x2, 0x2, 0xb41, 0xb42, 0x3, 0x2, 0x2, 0x2, 0xb42, 
       0x131, 0x3, 0x2, 0x2, 0x2, 0xb43, 0xb44, 0x9, 0x14, 0x2, 0x2, 0xb44, 
       0x133, 0x3, 0x2, 0x2, 0x2, 0xb45, 0xb46, 0x9, 0x15, 0x2, 0x2, 0xb46, 
       0x135, 0x3, 0x2, 0x2, 0x2, 0xb47, 0xb48, 0x9, 0x16, 0x2, 0x2, 0xb48, 
       0x137, 0x3, 0x2, 0x2, 0x2, 0x1f6, 0x13c, 0x141, 0x148, 0x14a, 0x14d, 
       0x152, 0x156, 0x15b, 0x15f, 0x164, 0x168, 0x16d, 0x171, 0x176, 0x17a, 
       0x17f, 0x183, 0x188, 0x18c, 0x190, 0x195, 0x198, 0x19d, 0x1a9, 0x1af, 
       0x1b4, 0x1ba, 0x1be, 0x1c2, 0x1cb, 0x1cf, 0x1d5, 0x1d9, 0x1e3, 0x1e9, 
       0x1ee, 0x1fd, 0x200, 0x208, 0x20d, 0x212, 0x218, 0x21e, 0x221, 0x225, 
       0x229, 0x22c, 0x230, 0x235, 0x239, 0x240, 0x248, 0x24c, 0x250, 0x259, 
       0x25c, 0x264, 0x268, 0x26d, 0x272, 0x274, 0x27a, 0x286, 0x28a, 0x28e, 
       0x292, 0x297, 0x29e, 0x2a1, 0x2a6, 0x2ec, 0x2f2, 0x2f6, 0x2f9, 0x309, 
       0x30d, 0x312, 0x315, 0x31a, 0x320, 0x324, 0x329, 0x32e, 0x332, 0x335, 
       0x339, 0x33f, 0x343, 0x34a, 0x350, 0x353, 0x358, 0x362, 0x365, 0x368, 
       0x36c, 0x372, 0x376, 0x37b, 0x382, 0x386, 0x38a, 0x38e, 0x391, 0x397, 
       0x39d, 0x39f, 0x3aa, 0x3b0, 0x3b2, 0x3ba, 0x3c0, 0x3c8, 0x3cf, 0x3d7, 
       0x3dc, 0x3e3, 0x3e7, 0x3ea, 0x3ef, 0x3f5, 0x3f9, 0x3fe, 0x408, 0x40e, 
       0x418, 0x41c, 0x426, 0x42f, 0x435, 0x437, 0x43c, 0x442, 0x446, 0x449, 
       0x44d, 0x458, 0x45d, 0x463, 0x465, 0x46b, 0x46d, 0x472, 0x476, 0x47c, 
       0x47f, 0x483, 0x488, 0x48e, 0x490, 0x498, 0x49c, 0x49f, 0x4a2, 0x4a6, 
       0x4bd, 0x4c3, 0x4c7, 0x4cb, 0x4d5, 0x4db, 0x4dd, 0x4e9, 0x4ef, 0x4f1, 
       0x4f7, 0x4fd, 0x4ff, 0x509, 0x50d, 0x512, 0x51a, 0x51e, 0x522, 0x52a, 
       0x52e, 0x53a, 0x53e, 0x545, 0x547, 0x54d, 0x551, 0x559, 0x55d, 0x569, 
       0x56f, 0x571, 0x57b, 0x581, 0x583, 0x589, 0x58f, 0x591, 0x595, 0x599, 
       0x59d, 0x5b3, 0x5b8, 0x5c2, 0x5c6, 0x5cb, 0x5d6, 0x5da, 0x5df, 0x5ed, 
       0x5f1, 0x5fa, 0x5fe, 0x601, 0x605, 0x609, 0x60c, 0x610, 0x614, 0x617, 
       0x61b, 0x61e, 0x622, 0x624, 0x628, 0x62c, 0x630, 0x634, 0x637, 0x63d, 
       0x641, 0x644, 0x649, 0x64d, 0x653, 0x656, 0x659, 0x65d, 0x662, 0x668, 
       0x66a, 0x671, 0x675, 0x67b, 0x67e, 0x683, 0x689, 0x68b, 0x692, 0x696, 
       0x69c, 0x69f, 0x6a4, 0x6aa, 0x6ac, 0x6b4, 0x6b8, 0x6bb, 0x6be, 0x6c2, 
       0x6ca, 0x6ce, 0x6d2, 0x6d4, 0x6d7, 0x6dc, 0x6e2, 0x6e6, 0x6ea, 0x6ef, 
       0x6f4, 0x6f8, 0x6fc, 0x701, 0x709, 0x70b, 0x717, 0x71b, 0x723, 0x727, 
       0x72f, 0x733, 0x737, 0x73b, 0x73f, 0x743, 0x74b, 0x74f, 0x75b, 0x760, 
       0x764, 0x76c, 0x76f, 0x774, 0x77a, 0x77c, 0x782, 0x784, 0x789, 0x78d, 
       0x792, 0x795, 0x799, 0x79d, 0x7a8, 0x7ae, 0x7b2, 0x7b5, 0x7bb, 0x7bf, 
       0x7c7, 0x7cb, 0x7d4, 0x7d8, 0x7de, 0x7e1, 0x7e6, 0x7ec, 0x7ee, 0x7f4, 
       0x7f8, 0x7ff, 0x807, 0x80c, 0x813, 0x817, 0x81a, 0x81d, 0x820, 0x824, 
       0x829, 0x832, 0x83c, 0x840, 0x847, 0x849, 0x84f, 0x853, 0x857, 0x85c, 
       0x860, 0x86d, 0x871, 0x877, 0x87c, 0x884, 0x888, 0x88c, 0x890, 0x894, 
       0x898, 0x89d, 0x8a1, 0x8a6, 0x8aa, 0x8af, 0x8b3, 0x8b8, 0x8bc, 0x8c1, 
       0x8c5, 0x8ca, 0x8ce, 0x8d3, 0x8d7, 0x8dc, 0x8e0, 0x8e5, 0x8e9, 0x8ee, 
       0x8f2, 0x8f7, 0x8fb, 0x900, 0x904, 0x913, 0x917, 0x91c, 0x920, 0x925, 
       0x929, 0x92e, 0x932, 0x937, 0x93b, 0x93e, 0x940, 0x946, 0x94b, 0x951, 
       0x955, 0x95a, 0x95f, 0x962, 0x966, 0x96a, 0x96c, 0x970, 0x972, 0x976, 
       0x97e, 0x983, 0x989, 0x992, 0x996, 0x99e, 0x9a4, 0x9aa, 0x9ac, 0x9b4, 
       0x9b8, 0x9bb, 0x9bf, 0x9c5, 0x9c8, 0x9cc, 0x9d0, 0x9d4, 0x9d9, 0x9dd, 
       0x9e1, 0x9e4, 0x9e8, 0x9ec, 0x9f0, 0x9f4, 0x9f9, 0x9fc, 0xa01, 0xa05, 
       0xa08, 0xa0e, 0xa12, 0xa15, 0xa1a, 0xa1d, 0xa20, 0xa24, 0xa28, 0xa2a, 
       0xa2f, 0xa32, 0xa36, 0xa39, 0xa3d, 0xa41, 0xa43, 0xa49, 0xa4e, 0xa51, 
       0xa54, 0xa59, 0xa5e, 0xa61, 0xa65, 0xa69, 0xa6e, 0xa72, 0xa75, 0xa79, 
       0xa7e, 0xa85, 0xa89, 0xa8d, 0xa91, 0xa96, 0xa99, 0xa9c, 0xaa2, 0xaa6, 
       0xaaa, 0xaae, 0xab1, 0xab5, 0xab8, 0xabc, 0xabf, 0xac2, 0xac6, 0xacc, 
       0xad0, 0xad5, 0xadd, 0xae3, 0xae5, 0xaea, 0xaec, 0xaef, 0xaf5, 0xafa, 
       0xb01, 0xb03, 0xb09, 0xb0b, 0xb0d, 0xb16, 0xb1b, 0xb1f, 0xb23, 0xb27, 
       0xb2a, 0xb37, 0xb3a, 0xb3e, 0xb41, 
  };

  _serializedATN.insert(_serializedATN.end(), serializedATNSegment0,
    serializedATNSegment0 + sizeof(serializedATNSegment0) / sizeof(serializedATNSegment0[0]));
  _serializedATN.insert(_serializedATN.end(), serializedATNSegment1,
    serializedATNSegment1 + sizeof(serializedATNSegment1) / sizeof(serializedATNSegment1[0]));


  atn::ATNDeserializer deserializer;
  _atn = deserializer.deserialize(_serializedATN);

  size_t count = _atn.getNumberOfDecisions();
  _decisionToDFA.reserve(count);
  for (size_t i = 0; i < count; i++) { 
    _decisionToDFA.emplace_back(_atn.getDecisionState(i), i);
  }
}

VisualBasic6Parser::Initializer VisualBasic6Parser::_init;
