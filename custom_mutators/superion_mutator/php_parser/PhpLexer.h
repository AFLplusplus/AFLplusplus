
// Generated from C:\Users\xiang\Documents\GitHub\php_parser\PhpLexer.g4 by ANTLR 4.7

#pragma once


#include "antlr4-runtime.h"




class  PhpLexer : public antlr4::Lexer {
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
    PhpComments = 2, ErrorLexem = 3, SkipChannel = 4
  };

  enum {
    PHP = 1, InterpolationString = 2, SingleLineCommentMode = 3, HereDoc = 4
  };

  PhpLexer(antlr4::CharStream *input);
  ~PhpLexer();

  bool _phpScript;
  bool _insideString;

  virtual std::string getGrammarFileName() const override;
  virtual const std::vector<std::string>& getRuleNames() const override;

  virtual const std::vector<std::string>& getChannelNames() const override;
  virtual const std::vector<std::string>& getModeNames() const override;
  virtual const std::vector<std::string>& getTokenNames() const override; // deprecated, use vocabulary instead
  virtual antlr4::dfa::Vocabulary& getVocabulary() const override;

  virtual const std::vector<uint16_t> getSerializedATN() const override;
  virtual const antlr4::atn::ATN& getATN() const override;

  virtual void action(antlr4::RuleContext *context, size_t ruleIndex, size_t actionIndex) override;
  virtual bool sempred(antlr4::RuleContext *_localctx, size_t ruleIndex, size_t predicateIndex) override;

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
  void CurlyDollarAction(antlr4::RuleContext *context, size_t actionIndex);

  // Individual semantic predicate functions triggered by sempred() above.
  bool ShebangSempred(antlr4::RuleContext *_localctx, size_t predicateIndex);
  bool StartNowDocSempred(antlr4::RuleContext *_localctx, size_t predicateIndex);
  bool StartHereDocSempred(antlr4::RuleContext *_localctx, size_t predicateIndex);
  bool CurlyDollarSempred(antlr4::RuleContext *_localctx, size_t predicateIndex);

  struct Initializer {
    Initializer();
  };
  static Initializer _init;
};

