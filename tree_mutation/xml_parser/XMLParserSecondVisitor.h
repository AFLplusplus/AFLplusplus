
// Generated from E:\xml\XMLParser.g4 by ANTLR 4.7

#pragma once

#include <iostream>
#include <vector>
#include "antlr4-runtime.h"
#include "XMLParserVisitor.h"

using namespace std;

/**
 * This class provides an empty implementation of XMLParserVisitor, which can be
 * extended to create a visitor which only needs to handle a subset of the available methods.
 */
class  XMLParserSecondVisitor : public XMLParserVisitor {
public:
  vector<string> texts;

  virtual antlrcpp::Any visitDocument(XMLParser::DocumentContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitProlog(XMLParser::PrologContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitContent(XMLParser::ContentContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitElement(XMLParser::ElementContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitReference(XMLParser::ReferenceContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitAttribute(XMLParser::AttributeContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitChardata(XMLParser::ChardataContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }

  virtual antlrcpp::Any visitMisc(XMLParser::MiscContext *ctx) override {
    texts.push_back(ctx->start->getInputStream()->getText(ctx->getSourceInterval()));
    return visitChildren(ctx);
  }


};

