
// Generated from E:\xml\XMLParser.g4 by ANTLR 4.7

#pragma once


#include "antlr4-runtime.h"




class  XMLParser : public antlr4::Parser {
public:
  enum {
    COMMENT = 1, CDATA = 2, DTD = 3, EntityRef = 4, CharRef = 5, SEA_WS = 6, 
    OPEN = 7, XMLDeclOpen = 8, TEXT = 9, CLOSE = 10, SPECIAL_CLOSE = 11, 
    SLASH_CLOSE = 12, SLASH = 13, EQUALS = 14, STRING = 15, Name = 16, S = 17, 
    PI = 18
  };

  enum {
    RuleDocument = 0, RuleProlog = 1, RuleContent = 2, RuleElement = 3, 
    RuleReference = 4, RuleAttribute = 5, RuleChardata = 6, RuleMisc = 7
  };

  XMLParser(antlr4::TokenStream *input);
  ~XMLParser();

  virtual std::string getGrammarFileName() const override;
  virtual const antlr4::atn::ATN& getATN() const override { return _atn; };
  virtual const std::vector<std::string>& getTokenNames() const override { return _tokenNames; }; // deprecated: use vocabulary instead.
  virtual const std::vector<std::string>& getRuleNames() const override;
  virtual antlr4::dfa::Vocabulary& getVocabulary() const override;


  class DocumentContext;
  class PrologContext;
  class ContentContext;
  class ElementContext;
  class ReferenceContext;
  class AttributeContext;
  class ChardataContext;
  class MiscContext; 

  class  DocumentContext : public antlr4::ParserRuleContext {
  public:
    DocumentContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    ElementContext *element();
    PrologContext *prolog();
    std::vector<MiscContext *> misc();
    MiscContext* misc(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  DocumentContext* document();

  class  PrologContext : public antlr4::ParserRuleContext {
  public:
    PrologContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *XMLDeclOpen();
    antlr4::tree::TerminalNode *SPECIAL_CLOSE();
    std::vector<AttributeContext *> attribute();
    AttributeContext* attribute(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  PrologContext* prolog();

  class  ContentContext : public antlr4::ParserRuleContext {
  public:
    ContentContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<ChardataContext *> chardata();
    ChardataContext* chardata(size_t i);
    std::vector<ElementContext *> element();
    ElementContext* element(size_t i);
    std::vector<ReferenceContext *> reference();
    ReferenceContext* reference(size_t i);
    std::vector<antlr4::tree::TerminalNode *> CDATA();
    antlr4::tree::TerminalNode* CDATA(size_t i);
    std::vector<antlr4::tree::TerminalNode *> PI();
    antlr4::tree::TerminalNode* PI(size_t i);
    std::vector<antlr4::tree::TerminalNode *> COMMENT();
    antlr4::tree::TerminalNode* COMMENT(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ContentContext* content();

  class  ElementContext : public antlr4::ParserRuleContext {
  public:
    ElementContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    std::vector<antlr4::tree::TerminalNode *> Name();
    antlr4::tree::TerminalNode* Name(size_t i);
    ContentContext *content();
    std::vector<AttributeContext *> attribute();
    AttributeContext* attribute(size_t i);

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ElementContext* element();

  class  ReferenceContext : public antlr4::ParserRuleContext {
  public:
    ReferenceContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *EntityRef();
    antlr4::tree::TerminalNode *CharRef();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ReferenceContext* reference();

  class  AttributeContext : public antlr4::ParserRuleContext {
  public:
    AttributeContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *Name();
    antlr4::tree::TerminalNode *STRING();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  AttributeContext* attribute();

  class  ChardataContext : public antlr4::ParserRuleContext {
  public:
    ChardataContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *TEXT();
    antlr4::tree::TerminalNode *SEA_WS();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  ChardataContext* chardata();

  class  MiscContext : public antlr4::ParserRuleContext {
  public:
    MiscContext(antlr4::ParserRuleContext *parent, size_t invokingState);
    virtual size_t getRuleIndex() const override;
    antlr4::tree::TerminalNode *COMMENT();
    antlr4::tree::TerminalNode *PI();
    antlr4::tree::TerminalNode *SEA_WS();

    virtual antlrcpp::Any accept(antlr4::tree::ParseTreeVisitor *visitor) override;
   
  };

  MiscContext* misc();


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

