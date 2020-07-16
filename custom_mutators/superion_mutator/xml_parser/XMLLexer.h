
// Generated from E:\xml\XMLLexer.g4 by ANTLR 4.7

#pragma once


#include "antlr4-runtime.h"




class  XMLLexer : public antlr4::Lexer {
public:
  enum {
    COMMENT = 1, CDATA = 2, DTD = 3, EntityRef = 4, CharRef = 5, SEA_WS = 6, 
    OPEN = 7, XMLDeclOpen = 8, TEXT = 9, CLOSE = 10, SPECIAL_CLOSE = 11, 
    SLASH_CLOSE = 12, SLASH = 13, EQUALS = 14, STRING = 15, Name = 16, S = 17, 
    PI = 18
  };

  enum {
    INSIDE = 1, PROC_INSTR = 2
  };

  XMLLexer(antlr4::CharStream *input);
  ~XMLLexer();

  virtual std::string getGrammarFileName() const override;
  virtual const std::vector<std::string>& getRuleNames() const override;

  virtual const std::vector<std::string>& getChannelNames() const override;
  virtual const std::vector<std::string>& getModeNames() const override;
  virtual const std::vector<std::string>& getTokenNames() const override; // deprecated, use vocabulary instead
  virtual antlr4::dfa::Vocabulary& getVocabulary() const override;

  virtual const std::vector<uint16_t> getSerializedATN() const override;
  virtual const antlr4::atn::ATN& getATN() const override;

private:
  static std::vector<antlr4::dfa::DFA> _decisionToDFA;
  static antlr4::atn::PredictionContextCache _sharedContextCache;
  static std::vector<std::string> _ruleNames;
  static std::vector<std::string> _tokenNames;
  static std::vector<std::string> _channelNames;
  static std::vector<std::string> _modeNames;

  static std::vector<std::string> _literalNames;
  static std::vector<std::string> _symbolicNames;
  static antlr4::dfa::Vocabulary _vocabulary;
  static antlr4::atn::ATN _atn;
  static std::vector<uint16_t> _serializedATN;


  // Individual action functions triggered by action() above.

  // Individual semantic predicate functions triggered by sempred() above.

  struct Initializer {
    Initializer();
  };
  static Initializer _init;
};

