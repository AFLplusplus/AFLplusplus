
// Generated from E:\xml\XMLParser.g4 by ANTLR 4.7

#pragma once


#include "antlr4-runtime.h"
#include "XMLParser.h"



/**
 * This class defines an abstract visitor for a parse tree
 * produced by XMLParser.
 */
class  XMLParserVisitor : public antlr4::tree::AbstractParseTreeVisitor {
public:

  /**
   * Visit parse trees produced by XMLParser.
   */
    virtual antlrcpp::Any visitDocument(XMLParser::DocumentContext *context) = 0;

    virtual antlrcpp::Any visitProlog(XMLParser::PrologContext *context) = 0;

    virtual antlrcpp::Any visitContent(XMLParser::ContentContext *context) = 0;

    virtual antlrcpp::Any visitElement(XMLParser::ElementContext *context) = 0;

    virtual antlrcpp::Any visitReference(XMLParser::ReferenceContext *context) = 0;

    virtual antlrcpp::Any visitAttribute(XMLParser::AttributeContext *context) = 0;

    virtual antlrcpp::Any visitChardata(XMLParser::ChardataContext *context) = 0;

    virtual antlrcpp::Any visitMisc(XMLParser::MiscContext *context) = 0;


};

