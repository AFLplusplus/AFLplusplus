
// Generated from E:\xml\XMLParser.g4 by ANTLR 4.7


#include "XMLParserVisitor.h"

#include "XMLParser.h"


using namespace antlrcpp;
using namespace antlr4;

XMLParser::XMLParser(TokenStream *input) : Parser(input) {
  _interpreter = new atn::ParserATNSimulator(this, _atn, _decisionToDFA, _sharedContextCache);
}

XMLParser::~XMLParser() {
  delete _interpreter;
}

std::string XMLParser::getGrammarFileName() const {
  return "XMLParser.g4";
}

const std::vector<std::string>& XMLParser::getRuleNames() const {
  return _ruleNames;
}

dfa::Vocabulary& XMLParser::getVocabulary() const {
  return _vocabulary;
}


//----------------- DocumentContext ------------------------------------------------------------------

XMLParser::DocumentContext::DocumentContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

XMLParser::ElementContext* XMLParser::DocumentContext::element() {
  return getRuleContext<XMLParser::ElementContext>(0);
}

XMLParser::PrologContext* XMLParser::DocumentContext::prolog() {
  return getRuleContext<XMLParser::PrologContext>(0);
}

std::vector<XMLParser::MiscContext *> XMLParser::DocumentContext::misc() {
  return getRuleContexts<XMLParser::MiscContext>();
}

XMLParser::MiscContext* XMLParser::DocumentContext::misc(size_t i) {
  return getRuleContext<XMLParser::MiscContext>(i);
}


size_t XMLParser::DocumentContext::getRuleIndex() const {
  return XMLParser::RuleDocument;
}

antlrcpp::Any XMLParser::DocumentContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<XMLParserVisitor*>(visitor))
    return parserVisitor->visitDocument(this);
  else
    return visitor->visitChildren(this);
}

XMLParser::DocumentContext* XMLParser::document() {
  DocumentContext *_localctx = _tracker.createInstance<DocumentContext>(_ctx, getState());
  enterRule(_localctx, 0, XMLParser::RuleDocument);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(17);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == XMLParser::XMLDeclOpen) {
      setState(16);
      prolog();
    }
    setState(22);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << XMLParser::COMMENT)
      | (1ULL << XMLParser::SEA_WS)
      | (1ULL << XMLParser::PI))) != 0)) {
      setState(19);
      misc();
      setState(24);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
    setState(25);
    element();
    setState(29);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while ((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << XMLParser::COMMENT)
      | (1ULL << XMLParser::SEA_WS)
      | (1ULL << XMLParser::PI))) != 0)) {
      setState(26);
      misc();
      setState(31);
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

//----------------- PrologContext ------------------------------------------------------------------

XMLParser::PrologContext::PrologContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* XMLParser::PrologContext::XMLDeclOpen() {
  return getToken(XMLParser::XMLDeclOpen, 0);
}

tree::TerminalNode* XMLParser::PrologContext::SPECIAL_CLOSE() {
  return getToken(XMLParser::SPECIAL_CLOSE, 0);
}

std::vector<XMLParser::AttributeContext *> XMLParser::PrologContext::attribute() {
  return getRuleContexts<XMLParser::AttributeContext>();
}

XMLParser::AttributeContext* XMLParser::PrologContext::attribute(size_t i) {
  return getRuleContext<XMLParser::AttributeContext>(i);
}


size_t XMLParser::PrologContext::getRuleIndex() const {
  return XMLParser::RuleProlog;
}

antlrcpp::Any XMLParser::PrologContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<XMLParserVisitor*>(visitor))
    return parserVisitor->visitProlog(this);
  else
    return visitor->visitChildren(this);
}

XMLParser::PrologContext* XMLParser::prolog() {
  PrologContext *_localctx = _tracker.createInstance<PrologContext>(_ctx, getState());
  enterRule(_localctx, 2, XMLParser::RuleProlog);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(32);
    match(XMLParser::XMLDeclOpen);
    setState(36);
    _errHandler->sync(this);
    _la = _input->LA(1);
    while (_la == XMLParser::Name) {
      setState(33);
      attribute();
      setState(38);
      _errHandler->sync(this);
      _la = _input->LA(1);
    }
    setState(39);
    match(XMLParser::SPECIAL_CLOSE);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ContentContext ------------------------------------------------------------------

XMLParser::ContentContext::ContentContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<XMLParser::ChardataContext *> XMLParser::ContentContext::chardata() {
  return getRuleContexts<XMLParser::ChardataContext>();
}

XMLParser::ChardataContext* XMLParser::ContentContext::chardata(size_t i) {
  return getRuleContext<XMLParser::ChardataContext>(i);
}

std::vector<XMLParser::ElementContext *> XMLParser::ContentContext::element() {
  return getRuleContexts<XMLParser::ElementContext>();
}

XMLParser::ElementContext* XMLParser::ContentContext::element(size_t i) {
  return getRuleContext<XMLParser::ElementContext>(i);
}

std::vector<XMLParser::ReferenceContext *> XMLParser::ContentContext::reference() {
  return getRuleContexts<XMLParser::ReferenceContext>();
}

XMLParser::ReferenceContext* XMLParser::ContentContext::reference(size_t i) {
  return getRuleContext<XMLParser::ReferenceContext>(i);
}

std::vector<tree::TerminalNode *> XMLParser::ContentContext::CDATA() {
  return getTokens(XMLParser::CDATA);
}

tree::TerminalNode* XMLParser::ContentContext::CDATA(size_t i) {
  return getToken(XMLParser::CDATA, i);
}

std::vector<tree::TerminalNode *> XMLParser::ContentContext::PI() {
  return getTokens(XMLParser::PI);
}

tree::TerminalNode* XMLParser::ContentContext::PI(size_t i) {
  return getToken(XMLParser::PI, i);
}

std::vector<tree::TerminalNode *> XMLParser::ContentContext::COMMENT() {
  return getTokens(XMLParser::COMMENT);
}

tree::TerminalNode* XMLParser::ContentContext::COMMENT(size_t i) {
  return getToken(XMLParser::COMMENT, i);
}


size_t XMLParser::ContentContext::getRuleIndex() const {
  return XMLParser::RuleContent;
}

antlrcpp::Any XMLParser::ContentContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<XMLParserVisitor*>(visitor))
    return parserVisitor->visitContent(this);
  else
    return visitor->visitChildren(this);
}

XMLParser::ContentContext* XMLParser::content() {
  ContentContext *_localctx = _tracker.createInstance<ContentContext>(_ctx, getState());
  enterRule(_localctx, 4, XMLParser::RuleContent);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    size_t alt;
    enterOuterAlt(_localctx, 1);
    setState(42);
    _errHandler->sync(this);

    _la = _input->LA(1);
    if (_la == XMLParser::SEA_WS

    || _la == XMLParser::TEXT) {
      setState(41);
      chardata();
    }
    setState(56);
    _errHandler->sync(this);
    alt = getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 7, _ctx);
    while (alt != 2 && alt != atn::ATN::INVALID_ALT_NUMBER) {
      if (alt == 1) {
        setState(49);
        _errHandler->sync(this);
        switch (_input->LA(1)) {
          case XMLParser::OPEN: {
            setState(44);
            element();
            break;
          }

          case XMLParser::EntityRef:
          case XMLParser::CharRef: {
            setState(45);
            reference();
            break;
          }

          case XMLParser::CDATA: {
            setState(46);
            match(XMLParser::CDATA);
            break;
          }

          case XMLParser::PI: {
            setState(47);
            match(XMLParser::PI);
            break;
          }

          case XMLParser::COMMENT: {
            setState(48);
            match(XMLParser::COMMENT);
            break;
          }

        default:
          throw NoViableAltException(this);
        }
        setState(52);
        _errHandler->sync(this);

        _la = _input->LA(1);
        if (_la == XMLParser::SEA_WS

        || _la == XMLParser::TEXT) {
          setState(51);
          chardata();
        } 
      }
      setState(58);
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

//----------------- ElementContext ------------------------------------------------------------------

XMLParser::ElementContext::ElementContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

std::vector<tree::TerminalNode *> XMLParser::ElementContext::Name() {
  return getTokens(XMLParser::Name);
}

tree::TerminalNode* XMLParser::ElementContext::Name(size_t i) {
  return getToken(XMLParser::Name, i);
}

XMLParser::ContentContext* XMLParser::ElementContext::content() {
  return getRuleContext<XMLParser::ContentContext>(0);
}

std::vector<XMLParser::AttributeContext *> XMLParser::ElementContext::attribute() {
  return getRuleContexts<XMLParser::AttributeContext>();
}

XMLParser::AttributeContext* XMLParser::ElementContext::attribute(size_t i) {
  return getRuleContext<XMLParser::AttributeContext>(i);
}


size_t XMLParser::ElementContext::getRuleIndex() const {
  return XMLParser::RuleElement;
}

antlrcpp::Any XMLParser::ElementContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<XMLParserVisitor*>(visitor))
    return parserVisitor->visitElement(this);
  else
    return visitor->visitChildren(this);
}

XMLParser::ElementContext* XMLParser::element() {
  ElementContext *_localctx = _tracker.createInstance<ElementContext>(_ctx, getState());
  enterRule(_localctx, 6, XMLParser::RuleElement);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    setState(83);
    _errHandler->sync(this);
    switch (getInterpreter<atn::ParserATNSimulator>()->adaptivePredict(_input, 10, _ctx)) {
    case 1: {
      enterOuterAlt(_localctx, 1);
      setState(59);
      match(XMLParser::OPEN);
      setState(60);
      match(XMLParser::Name);
      setState(64);
      _errHandler->sync(this);
      _la = _input->LA(1);
      while (_la == XMLParser::Name) {
        setState(61);
        attribute();
        setState(66);
        _errHandler->sync(this);
        _la = _input->LA(1);
      }
      setState(67);
      match(XMLParser::CLOSE);
      setState(68);
      content();
      setState(69);
      match(XMLParser::OPEN);
      setState(70);
      match(XMLParser::SLASH);
      setState(71);
      match(XMLParser::Name);
      setState(72);
      match(XMLParser::CLOSE);
      break;
    }

    case 2: {
      enterOuterAlt(_localctx, 2);
      setState(74);
      match(XMLParser::OPEN);
      setState(75);
      match(XMLParser::Name);
      setState(79);
      _errHandler->sync(this);
      _la = _input->LA(1);
      while (_la == XMLParser::Name) {
        setState(76);
        attribute();
        setState(81);
        _errHandler->sync(this);
        _la = _input->LA(1);
      }
      setState(82);
      match(XMLParser::SLASH_CLOSE);
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

//----------------- ReferenceContext ------------------------------------------------------------------

XMLParser::ReferenceContext::ReferenceContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* XMLParser::ReferenceContext::EntityRef() {
  return getToken(XMLParser::EntityRef, 0);
}

tree::TerminalNode* XMLParser::ReferenceContext::CharRef() {
  return getToken(XMLParser::CharRef, 0);
}


size_t XMLParser::ReferenceContext::getRuleIndex() const {
  return XMLParser::RuleReference;
}

antlrcpp::Any XMLParser::ReferenceContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<XMLParserVisitor*>(visitor))
    return parserVisitor->visitReference(this);
  else
    return visitor->visitChildren(this);
}

XMLParser::ReferenceContext* XMLParser::reference() {
  ReferenceContext *_localctx = _tracker.createInstance<ReferenceContext>(_ctx, getState());
  enterRule(_localctx, 8, XMLParser::RuleReference);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(85);
    _la = _input->LA(1);
    if (!(_la == XMLParser::EntityRef

    || _la == XMLParser::CharRef)) {
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

//----------------- AttributeContext ------------------------------------------------------------------

XMLParser::AttributeContext::AttributeContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* XMLParser::AttributeContext::Name() {
  return getToken(XMLParser::Name, 0);
}

tree::TerminalNode* XMLParser::AttributeContext::STRING() {
  return getToken(XMLParser::STRING, 0);
}


size_t XMLParser::AttributeContext::getRuleIndex() const {
  return XMLParser::RuleAttribute;
}

antlrcpp::Any XMLParser::AttributeContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<XMLParserVisitor*>(visitor))
    return parserVisitor->visitAttribute(this);
  else
    return visitor->visitChildren(this);
}

XMLParser::AttributeContext* XMLParser::attribute() {
  AttributeContext *_localctx = _tracker.createInstance<AttributeContext>(_ctx, getState());
  enterRule(_localctx, 10, XMLParser::RuleAttribute);

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(87);
    match(XMLParser::Name);
    setState(88);
    match(XMLParser::EQUALS);
    setState(89);
    match(XMLParser::STRING);
   
  }
  catch (RecognitionException &e) {
    _errHandler->reportError(this, e);
    _localctx->exception = std::current_exception();
    _errHandler->recover(this, _localctx->exception);
  }

  return _localctx;
}

//----------------- ChardataContext ------------------------------------------------------------------

XMLParser::ChardataContext::ChardataContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* XMLParser::ChardataContext::TEXT() {
  return getToken(XMLParser::TEXT, 0);
}

tree::TerminalNode* XMLParser::ChardataContext::SEA_WS() {
  return getToken(XMLParser::SEA_WS, 0);
}


size_t XMLParser::ChardataContext::getRuleIndex() const {
  return XMLParser::RuleChardata;
}

antlrcpp::Any XMLParser::ChardataContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<XMLParserVisitor*>(visitor))
    return parserVisitor->visitChardata(this);
  else
    return visitor->visitChildren(this);
}

XMLParser::ChardataContext* XMLParser::chardata() {
  ChardataContext *_localctx = _tracker.createInstance<ChardataContext>(_ctx, getState());
  enterRule(_localctx, 12, XMLParser::RuleChardata);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(91);
    _la = _input->LA(1);
    if (!(_la == XMLParser::SEA_WS

    || _la == XMLParser::TEXT)) {
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

//----------------- MiscContext ------------------------------------------------------------------

XMLParser::MiscContext::MiscContext(ParserRuleContext *parent, size_t invokingState)
  : ParserRuleContext(parent, invokingState) {
}

tree::TerminalNode* XMLParser::MiscContext::COMMENT() {
  return getToken(XMLParser::COMMENT, 0);
}

tree::TerminalNode* XMLParser::MiscContext::PI() {
  return getToken(XMLParser::PI, 0);
}

tree::TerminalNode* XMLParser::MiscContext::SEA_WS() {
  return getToken(XMLParser::SEA_WS, 0);
}


size_t XMLParser::MiscContext::getRuleIndex() const {
  return XMLParser::RuleMisc;
}

antlrcpp::Any XMLParser::MiscContext::accept(tree::ParseTreeVisitor *visitor) {
  if (auto parserVisitor = dynamic_cast<XMLParserVisitor*>(visitor))
    return parserVisitor->visitMisc(this);
  else
    return visitor->visitChildren(this);
}

XMLParser::MiscContext* XMLParser::misc() {
  MiscContext *_localctx = _tracker.createInstance<MiscContext>(_ctx, getState());
  enterRule(_localctx, 14, XMLParser::RuleMisc);
  size_t _la = 0;

  auto onExit = finally([=] {
    exitRule();
  });
  try {
    enterOuterAlt(_localctx, 1);
    setState(93);
    _la = _input->LA(1);
    if (!((((_la & ~ 0x3fULL) == 0) &&
      ((1ULL << _la) & ((1ULL << XMLParser::COMMENT)
      | (1ULL << XMLParser::SEA_WS)
      | (1ULL << XMLParser::PI))) != 0))) {
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

// Static vars and initialization.
std::vector<dfa::DFA> XMLParser::_decisionToDFA;
atn::PredictionContextCache XMLParser::_sharedContextCache;

// We own the ATN which in turn owns the ATN states.
atn::ATN XMLParser::_atn;
std::vector<uint16_t> XMLParser::_serializedATN;

std::vector<std::string> XMLParser::_ruleNames = {
  "document", "prolog", "content", "element", "reference", "attribute", 
  "chardata", "misc"
};

std::vector<std::string> XMLParser::_literalNames = {
  "", "", "", "", "", "", "", "'<'", "", "", "'>'", "", "'/>'", "'/'", "'='"
};

std::vector<std::string> XMLParser::_symbolicNames = {
  "", "COMMENT", "CDATA", "DTD", "EntityRef", "CharRef", "SEA_WS", "OPEN", 
  "XMLDeclOpen", "TEXT", "CLOSE", "SPECIAL_CLOSE", "SLASH_CLOSE", "SLASH", 
  "EQUALS", "STRING", "Name", "S", "PI"
};

dfa::Vocabulary XMLParser::_vocabulary(_literalNames, _symbolicNames);

std::vector<std::string> XMLParser::_tokenNames;

XMLParser::Initializer::Initializer() {
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
    0x3, 0x14, 0x62, 0x4, 0x2, 0x9, 0x2, 0x4, 0x3, 0x9, 0x3, 0x4, 0x4, 0x9, 
    0x4, 0x4, 0x5, 0x9, 0x5, 0x4, 0x6, 0x9, 0x6, 0x4, 0x7, 0x9, 0x7, 0x4, 
    0x8, 0x9, 0x8, 0x4, 0x9, 0x9, 0x9, 0x3, 0x2, 0x5, 0x2, 0x14, 0xa, 0x2, 
    0x3, 0x2, 0x7, 0x2, 0x17, 0xa, 0x2, 0xc, 0x2, 0xe, 0x2, 0x1a, 0xb, 0x2, 
    0x3, 0x2, 0x3, 0x2, 0x7, 0x2, 0x1e, 0xa, 0x2, 0xc, 0x2, 0xe, 0x2, 0x21, 
    0xb, 0x2, 0x3, 0x3, 0x3, 0x3, 0x7, 0x3, 0x25, 0xa, 0x3, 0xc, 0x3, 0xe, 
    0x3, 0x28, 0xb, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x4, 0x5, 0x4, 0x2d, 0xa, 
    0x4, 0x3, 0x4, 0x3, 0x4, 0x3, 0x4, 0x3, 0x4, 0x3, 0x4, 0x5, 0x4, 0x34, 
    0xa, 0x4, 0x3, 0x4, 0x5, 0x4, 0x37, 0xa, 0x4, 0x7, 0x4, 0x39, 0xa, 0x4, 
    0xc, 0x4, 0xe, 0x4, 0x3c, 0xb, 0x4, 0x3, 0x5, 0x3, 0x5, 0x3, 0x5, 0x7, 
    0x5, 0x41, 0xa, 0x5, 0xc, 0x5, 0xe, 0x5, 0x44, 0xb, 0x5, 0x3, 0x5, 0x3, 
    0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 0x5, 0x3, 
    0x5, 0x3, 0x5, 0x7, 0x5, 0x50, 0xa, 0x5, 0xc, 0x5, 0xe, 0x5, 0x53, 0xb, 
    0x5, 0x3, 0x5, 0x5, 0x5, 0x56, 0xa, 0x5, 0x3, 0x6, 0x3, 0x6, 0x3, 0x7, 
    0x3, 0x7, 0x3, 0x7, 0x3, 0x7, 0x3, 0x8, 0x3, 0x8, 0x3, 0x9, 0x3, 0x9, 
    0x3, 0x9, 0x2, 0x2, 0xa, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x2, 
    0x5, 0x3, 0x2, 0x6, 0x7, 0x4, 0x2, 0x8, 0x8, 0xb, 0xb, 0x5, 0x2, 0x3, 
    0x3, 0x8, 0x8, 0x14, 0x14, 0x2, 0x67, 0x2, 0x13, 0x3, 0x2, 0x2, 0x2, 
    0x4, 0x22, 0x3, 0x2, 0x2, 0x2, 0x6, 0x2c, 0x3, 0x2, 0x2, 0x2, 0x8, 0x55, 
    0x3, 0x2, 0x2, 0x2, 0xa, 0x57, 0x3, 0x2, 0x2, 0x2, 0xc, 0x59, 0x3, 0x2, 
    0x2, 0x2, 0xe, 0x5d, 0x3, 0x2, 0x2, 0x2, 0x10, 0x5f, 0x3, 0x2, 0x2, 
    0x2, 0x12, 0x14, 0x5, 0x4, 0x3, 0x2, 0x13, 0x12, 0x3, 0x2, 0x2, 0x2, 
    0x13, 0x14, 0x3, 0x2, 0x2, 0x2, 0x14, 0x18, 0x3, 0x2, 0x2, 0x2, 0x15, 
    0x17, 0x5, 0x10, 0x9, 0x2, 0x16, 0x15, 0x3, 0x2, 0x2, 0x2, 0x17, 0x1a, 
    0x3, 0x2, 0x2, 0x2, 0x18, 0x16, 0x3, 0x2, 0x2, 0x2, 0x18, 0x19, 0x3, 
    0x2, 0x2, 0x2, 0x19, 0x1b, 0x3, 0x2, 0x2, 0x2, 0x1a, 0x18, 0x3, 0x2, 
    0x2, 0x2, 0x1b, 0x1f, 0x5, 0x8, 0x5, 0x2, 0x1c, 0x1e, 0x5, 0x10, 0x9, 
    0x2, 0x1d, 0x1c, 0x3, 0x2, 0x2, 0x2, 0x1e, 0x21, 0x3, 0x2, 0x2, 0x2, 
    0x1f, 0x1d, 0x3, 0x2, 0x2, 0x2, 0x1f, 0x20, 0x3, 0x2, 0x2, 0x2, 0x20, 
    0x3, 0x3, 0x2, 0x2, 0x2, 0x21, 0x1f, 0x3, 0x2, 0x2, 0x2, 0x22, 0x26, 
    0x7, 0xa, 0x2, 0x2, 0x23, 0x25, 0x5, 0xc, 0x7, 0x2, 0x24, 0x23, 0x3, 
    0x2, 0x2, 0x2, 0x25, 0x28, 0x3, 0x2, 0x2, 0x2, 0x26, 0x24, 0x3, 0x2, 
    0x2, 0x2, 0x26, 0x27, 0x3, 0x2, 0x2, 0x2, 0x27, 0x29, 0x3, 0x2, 0x2, 
    0x2, 0x28, 0x26, 0x3, 0x2, 0x2, 0x2, 0x29, 0x2a, 0x7, 0xd, 0x2, 0x2, 
    0x2a, 0x5, 0x3, 0x2, 0x2, 0x2, 0x2b, 0x2d, 0x5, 0xe, 0x8, 0x2, 0x2c, 
    0x2b, 0x3, 0x2, 0x2, 0x2, 0x2c, 0x2d, 0x3, 0x2, 0x2, 0x2, 0x2d, 0x3a, 
    0x3, 0x2, 0x2, 0x2, 0x2e, 0x34, 0x5, 0x8, 0x5, 0x2, 0x2f, 0x34, 0x5, 
    0xa, 0x6, 0x2, 0x30, 0x34, 0x7, 0x4, 0x2, 0x2, 0x31, 0x34, 0x7, 0x14, 
    0x2, 0x2, 0x32, 0x34, 0x7, 0x3, 0x2, 0x2, 0x33, 0x2e, 0x3, 0x2, 0x2, 
    0x2, 0x33, 0x2f, 0x3, 0x2, 0x2, 0x2, 0x33, 0x30, 0x3, 0x2, 0x2, 0x2, 
    0x33, 0x31, 0x3, 0x2, 0x2, 0x2, 0x33, 0x32, 0x3, 0x2, 0x2, 0x2, 0x34, 
    0x36, 0x3, 0x2, 0x2, 0x2, 0x35, 0x37, 0x5, 0xe, 0x8, 0x2, 0x36, 0x35, 
    0x3, 0x2, 0x2, 0x2, 0x36, 0x37, 0x3, 0x2, 0x2, 0x2, 0x37, 0x39, 0x3, 
    0x2, 0x2, 0x2, 0x38, 0x33, 0x3, 0x2, 0x2, 0x2, 0x39, 0x3c, 0x3, 0x2, 
    0x2, 0x2, 0x3a, 0x38, 0x3, 0x2, 0x2, 0x2, 0x3a, 0x3b, 0x3, 0x2, 0x2, 
    0x2, 0x3b, 0x7, 0x3, 0x2, 0x2, 0x2, 0x3c, 0x3a, 0x3, 0x2, 0x2, 0x2, 
    0x3d, 0x3e, 0x7, 0x9, 0x2, 0x2, 0x3e, 0x42, 0x7, 0x12, 0x2, 0x2, 0x3f, 
    0x41, 0x5, 0xc, 0x7, 0x2, 0x40, 0x3f, 0x3, 0x2, 0x2, 0x2, 0x41, 0x44, 
    0x3, 0x2, 0x2, 0x2, 0x42, 0x40, 0x3, 0x2, 0x2, 0x2, 0x42, 0x43, 0x3, 
    0x2, 0x2, 0x2, 0x43, 0x45, 0x3, 0x2, 0x2, 0x2, 0x44, 0x42, 0x3, 0x2, 
    0x2, 0x2, 0x45, 0x46, 0x7, 0xc, 0x2, 0x2, 0x46, 0x47, 0x5, 0x6, 0x4, 
    0x2, 0x47, 0x48, 0x7, 0x9, 0x2, 0x2, 0x48, 0x49, 0x7, 0xf, 0x2, 0x2, 
    0x49, 0x4a, 0x7, 0x12, 0x2, 0x2, 0x4a, 0x4b, 0x7, 0xc, 0x2, 0x2, 0x4b, 
    0x56, 0x3, 0x2, 0x2, 0x2, 0x4c, 0x4d, 0x7, 0x9, 0x2, 0x2, 0x4d, 0x51, 
    0x7, 0x12, 0x2, 0x2, 0x4e, 0x50, 0x5, 0xc, 0x7, 0x2, 0x4f, 0x4e, 0x3, 
    0x2, 0x2, 0x2, 0x50, 0x53, 0x3, 0x2, 0x2, 0x2, 0x51, 0x4f, 0x3, 0x2, 
    0x2, 0x2, 0x51, 0x52, 0x3, 0x2, 0x2, 0x2, 0x52, 0x54, 0x3, 0x2, 0x2, 
    0x2, 0x53, 0x51, 0x3, 0x2, 0x2, 0x2, 0x54, 0x56, 0x7, 0xe, 0x2, 0x2, 
    0x55, 0x3d, 0x3, 0x2, 0x2, 0x2, 0x55, 0x4c, 0x3, 0x2, 0x2, 0x2, 0x56, 
    0x9, 0x3, 0x2, 0x2, 0x2, 0x57, 0x58, 0x9, 0x2, 0x2, 0x2, 0x58, 0xb, 
    0x3, 0x2, 0x2, 0x2, 0x59, 0x5a, 0x7, 0x12, 0x2, 0x2, 0x5a, 0x5b, 0x7, 
    0x10, 0x2, 0x2, 0x5b, 0x5c, 0x7, 0x11, 0x2, 0x2, 0x5c, 0xd, 0x3, 0x2, 
    0x2, 0x2, 0x5d, 0x5e, 0x9, 0x3, 0x2, 0x2, 0x5e, 0xf, 0x3, 0x2, 0x2, 
    0x2, 0x5f, 0x60, 0x9, 0x4, 0x2, 0x2, 0x60, 0x11, 0x3, 0x2, 0x2, 0x2, 
    0xd, 0x13, 0x18, 0x1f, 0x26, 0x2c, 0x33, 0x36, 0x3a, 0x42, 0x51, 0x55, 
  };

  atn::ATNDeserializer deserializer;
  _atn = deserializer.deserialize(_serializedATN);

  size_t count = _atn.getNumberOfDecisions();
  _decisionToDFA.reserve(count);
  for (size_t i = 0; i < count; i++) { 
    _decisionToDFA.emplace_back(_atn.getDecisionState(i), i);
  }
}

XMLParser::Initializer XMLParser::_init;
