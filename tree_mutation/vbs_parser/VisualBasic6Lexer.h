
// Generated from C:\Users\xiang\Desktop\vbs_parser\VisualBasic6.g4 by ANTLR 4.7

#pragma once


#include "antlr4-runtime.h"




class  VisualBasic6Lexer : public antlr4::Lexer {
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

  VisualBasic6Lexer(antlr4::CharStream *input);
  ~VisualBasic6Lexer();

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

