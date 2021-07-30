/*
   american fuzzy lop++ - LLVM LTO instrumentation pass
   ----------------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-lto.

 */

#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

#include <list>
#include <string>
#include <fstream>
#include <set>
#include <iostream>

#include "llvm/Config/llvm-config.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/MemorySSAUpdater.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Pass.h"
#include "llvm/IR/Constants.h"

#include "afl-llvm-common.h"

using namespace llvm;

namespace {

class AFLLTOPass : public ModulePass {

 public:
  static char ID;

  AFLLTOPass() : ModulePass(ID) {

    char *ptr;

    if (getenv("AFL_DEBUG")) debug = 1;
    if ((ptr = getenv("AFL_LLVM_LTO_STARTID")) != NULL)
      if ((afl_global_id = (uint32_t)atoi(ptr)) < 0 ||
          afl_global_id >= MAP_SIZE)
        FATAL("AFL_LLVM_LTO_STARTID value of \"%s\" is not between 0 and %u\n",
              ptr, MAP_SIZE - 1);

    skip_nozero = getenv("AFL_LLVM_SKIP_NEVERZERO");

  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {

    ModulePass::getAnalysisUsage(AU);
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<LoopInfoWrapperPass>();

  }

  bool runOnModule(Module &M) override;

 protected:
  uint32_t               afl_global_id = 1, autodictionary = 1;
  uint32_t               function_minimum_size = 1;
  uint32_t               inst_blocks = 0, inst_funcs = 0, total_instr = 0;
  unsigned long long int map_addr = 0x10000;
  const char *           skip_nozero = NULL;
  const char *           use_threadsafe_counters = nullptr;

};

}  // namespace

bool AFLLTOPass::runOnModule(Module &M) {

  LLVMContext &            C = M.getContext();
  std::vector<std::string> dictionary;
  //  std::vector<CallInst *>          calls;
  DenseMap<Value *, std::string *> valueMap;
  std::vector<BasicBlock *>        BlockList;
  char *                           ptr;
  FILE *                           documentFile = NULL;
  size_t                           found = 0;

  srand((unsigned int)time(NULL));

  unsigned long long int moduleID =
      (((unsigned long long int)(rand() & 0xffffffff)) << 32) | getpid();

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

  /* Show a banner */
  setvbuf(stdout, NULL, _IONBF, 0);

  if ((isatty(2) && !getenv("AFL_QUIET")) || debug) {

    SAYF(cCYA "afl-llvm-lto" VERSION cRST
              " by Marc \"vanHauser\" Heuse <mh@mh-sec.de>\n");

  } else

    be_quiet = 1;

  use_threadsafe_counters = getenv("AFL_LLVM_THREADSAFE_INST");

  if ((ptr = getenv("AFL_LLVM_DOCUMENT_IDS")) != NULL) {

    if ((documentFile = fopen(ptr, "a")) == NULL)
      WARNF("Cannot access document file %s", ptr);

  }

  // we make this the default as the fixed map has problems with
  // defered forkserver, early constructors, ifuncs and maybe more
  /*if (getenv("AFL_LLVM_MAP_DYNAMIC"))*/
  map_addr = 0;

  if ((ptr = getenv("AFL_LLVM_MAP_ADDR"))) {

    uint64_t val;
    if (!*ptr || !strcmp(ptr, "0") || !strcmp(ptr, "0x0")) {

      map_addr = 0;

    } else if (getenv("AFL_LLVM_MAP_DYNAMIC")) {

      FATAL(
          "AFL_LLVM_MAP_ADDR and AFL_LLVM_MAP_DYNAMIC cannot be used together");

    } else if (strncmp(ptr, "0x", 2) != 0) {

      map_addr = 0x10000;  // the default

    } else {

      val = strtoull(ptr, NULL, 16);
      if (val < 0x100 || val > 0xffffffff00000000) {

        FATAL(
            "AFL_LLVM_MAP_ADDR must be a value between 0x100 and "
            "0xffffffff00000000");

      }

      map_addr = val;

    }

  }

  if (debug) { fprintf(stderr, "map address is 0x%llx\n", map_addr); }

  /* Get/set the globals for the SHM region. */

  GlobalVariable *AFLMapPtr = NULL;
  Value *         MapPtrFixed = NULL;

  if (!map_addr) {

    AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  } else {

    ConstantInt *MapAddr = ConstantInt::get(Int64Ty, map_addr);
    MapPtrFixed =
        ConstantExpr::getIntToPtr(MapAddr, PointerType::getUnqual(Int8Ty));

  }

  ConstantInt *Zero = ConstantInt::get(Int8Ty, 0);
  ConstantInt *One = ConstantInt::get(Int8Ty, 1);

  // This dumps all inialized global strings - might be useful in the future
  /*
  for (auto G=M.getGlobalList().begin(); G!=M.getGlobalList().end(); G++) {

    GlobalVariable &GV=*G;
    if (!GV.getName().str().empty()) {

      fprintf(stderr, "Global Variable: %s", GV.getName().str().c_str());
      if (GV.hasInitializer())
        if (auto *Val = dyn_cast<ConstantDataArray>(GV.getInitializer()))
          fprintf(stderr, " Value: \"%s\"", Val->getAsString().str().c_str());
      fprintf(stderr, "\n");

    }

  }

  */

  scanForDangerousFunctions(&M);

  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M) {

    /*For debugging
    AttributeSet X = F.getAttributes().getFnAttributes();
    fprintf(stderr, "DEBUG: Module %s Function %s attributes %u\n",
      M.getName().str().c_str(), F.getName().str().c_str(),
      X.getNumAttributes());
    */

    if (F.size() < function_minimum_size) continue;
    if (isIgnoreFunction(&F)) continue;

    // the instrument file list check
    AttributeList Attrs = F.getAttributes();
    if (Attrs.hasAttribute(-1, StringRef("skipinstrument"))) {

      if (debug)
        fprintf(stderr,
                "DEBUG: Function %s is not in a source file that was specified "
                "in the instrument file list\n",
                F.getName().str().c_str());
      continue;

    }

    std::vector<BasicBlock *> InsBlocks;

    if (autodictionary) {

      /*  Some implementation notes.
       *
       *  We try to handle 3 cases:
       *  - memcmp("foo", arg, 3) <- literal string
       *  - static char globalvar[] = "foo";
       *    memcmp(globalvar, arg, 3) <- global variable
       *  - char localvar[] = "foo";
       *    memcmp(locallvar, arg, 3) <- local variable
       *
       *  The local variable case is the hardest. We can only detect that
       *  case if there is no reassignment or change in the variable.
       *  And it might not work across llvm version.
       *  What we do is hooking the initializer function for local variables
       *  (llvm.memcpy.p0i8.p0i8.i64) and note the string and the assigned
       *  variable. And if that variable is then used in a compare function
       *  we use that noted string.
       *  This seems not to work for tokens that have a size <= 4 :-(
       *
       *  - if the compared length is smaller than the string length we
       *    save the full string. This is likely better for fuzzing but
       *    might be wrong in a few cases depending on optimizers
       *
       *  - not using StringRef because there is a bug in the llvm 11
       *    checkout I am using which sometimes points to wrong strings
       *
       *  Over and out. Took me a full day. damn. mh/vh
       */

      for (auto &BB : F) {

        for (auto &IN : BB) {

          CallInst *callInst = nullptr;
          CmpInst * cmpInst = nullptr;

          if ((cmpInst = dyn_cast<CmpInst>(&IN))) {

            Value *      op = cmpInst->getOperand(1);
            ConstantInt *ilen = dyn_cast<ConstantInt>(op);

            if (ilen && ilen->uge(0xffffffffffffffff) == false) {

              u64 val2 = 0, val = ilen->getZExtValue();
              u32 len = 0;
              if (val > 0x10000 && val < 0xffffffff) len = 4;
              if (val > 0x100000001 && val < 0xffffffffffffffff) len = 8;

              if (len) {

                auto c = cmpInst->getPredicate();

                switch (c) {

                  case CmpInst::FCMP_OGT:  // fall through
                  case CmpInst::FCMP_OLE:  // fall through
                  case CmpInst::ICMP_SLE:  // fall through
                  case CmpInst::ICMP_SGT:

                    // signed comparison and it is a negative constant
                    if ((len == 4 && (val & 80000000)) ||
                        (len == 8 && (val & 8000000000000000))) {

                      if ((val & 0xffff) != 1) val2 = val - 1;
                      break;

                    }

                    // fall through

                  case CmpInst::FCMP_UGT:  // fall through
                  case CmpInst::FCMP_ULE:  // fall through
                  case CmpInst::ICMP_UGT:  // fall through
                  case CmpInst::ICMP_ULE:
                    if ((val & 0xffff) != 0xfffe) val2 = val + 1;
                    break;

                  case CmpInst::FCMP_OLT:  // fall through
                  case CmpInst::FCMP_OGE:  // fall through
                  case CmpInst::ICMP_SLT:  // fall through
                  case CmpInst::ICMP_SGE:

                    // signed comparison and it is a negative constant
                    if ((len == 4 && (val & 80000000)) ||
                        (len == 8 && (val & 8000000000000000))) {

                      if ((val & 0xffff) != 1) val2 = val - 1;
                      break;

                    }

                    // fall through

                  case CmpInst::FCMP_ULT:  // fall through
                  case CmpInst::FCMP_UGE:  // fall through
                  case CmpInst::ICMP_ULT:  // fall through
                  case CmpInst::ICMP_UGE:
                    if ((val & 0xffff) != 1) val2 = val - 1;
                    break;

                  default:
                    val2 = 0;

                }

                dictionary.push_back(std::string((char *)&val, len));
                found++;

                if (val2) {

                  dictionary.push_back(std::string((char *)&val2, len));
                  found++;

                }

              }

            }

          }

          if ((callInst = dyn_cast<CallInst>(&IN))) {

            bool   isStrcmp = true;
            bool   isMemcmp = true;
            bool   isStrncmp = true;
            bool   isStrcasecmp = true;
            bool   isStrncasecmp = true;
            bool   isIntMemcpy = true;
            bool   isStdString = true;
            bool   addedNull = false;
            size_t optLen = 0;

            Function *Callee = callInst->getCalledFunction();
            if (!Callee) continue;
            if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
            std::string FuncName = Callee->getName().str();

            isStrcmp &= (!FuncName.compare("strcmp") ||
                         !FuncName.compare("xmlStrcmp") ||
                         !FuncName.compare("xmlStrEqual") ||
                         !FuncName.compare("g_strcmp0") ||
                         !FuncName.compare("curl_strequal") ||
                         !FuncName.compare("strcsequal"));
            isMemcmp &=
                (!FuncName.compare("memcmp") || !FuncName.compare("bcmp") ||
                 !FuncName.compare("CRYPTO_memcmp") ||
                 !FuncName.compare("OPENSSL_memcmp") ||
                 !FuncName.compare("memcmp_const_time") ||
                 !FuncName.compare("memcmpct"));
            isStrncmp &= (!FuncName.compare("strncmp") ||
                          !FuncName.compare("xmlStrncmp") ||
                          !FuncName.compare("curl_strnequal"));
            isStrcasecmp &= (!FuncName.compare("strcasecmp") ||
                             !FuncName.compare("stricmp") ||
                             !FuncName.compare("ap_cstr_casecmp") ||
                             !FuncName.compare("OPENSSL_strcasecmp") ||
                             !FuncName.compare("xmlStrcasecmp") ||
                             !FuncName.compare("g_strcasecmp") ||
                             !FuncName.compare("g_ascii_strcasecmp") ||
                             !FuncName.compare("Curl_strcasecompare") ||
                             !FuncName.compare("Curl_safe_strcasecompare") ||
                             !FuncName.compare("cmsstrcasecmp"));
            isStrncasecmp &= (!FuncName.compare("strncasecmp") ||
                              !FuncName.compare("strnicmp") ||
                              !FuncName.compare("ap_cstr_casecmpn") ||
                              !FuncName.compare("OPENSSL_strncasecmp") ||
                              !FuncName.compare("xmlStrncasecmp") ||
                              !FuncName.compare("g_ascii_strncasecmp") ||
                              !FuncName.compare("Curl_strncasecompare") ||
                              !FuncName.compare("g_strncasecmp"));
            isIntMemcpy &= !FuncName.compare("llvm.memcpy.p0i8.p0i8.i64");
            isStdString &=
                ((FuncName.find("basic_string") != std::string::npos &&
                  FuncName.find("compare") != std::string::npos) ||
                 (FuncName.find("basic_string") != std::string::npos &&
                  FuncName.find("find") != std::string::npos));

            /* we do something different here, putting this BB and the
               successors in a block map */
            if (!FuncName.compare("__afl_persistent_loop")) {

              BlockList.push_back(&BB);
              /*
                            for (succ_iterator SI = succ_begin(&BB), SE =
                 succ_end(&BB); SI != SE; ++SI) {

                              BasicBlock *succ = *SI;
                              BlockList.push_back(succ);

                            }

              */

            }

            if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
                !isStrncasecmp && !isIntMemcpy && !isStdString)
              continue;

            /* Verify the strcmp/memcmp/strncmp/strcasecmp/strncasecmp function
             * prototype */
            FunctionType *FT = Callee->getFunctionType();

            isStrcmp &= FT->getNumParams() == 2 &&
                        FT->getReturnType()->isIntegerTy(32) &&
                        FT->getParamType(0) == FT->getParamType(1) &&
                        FT->getParamType(0) ==
                            IntegerType::getInt8PtrTy(M.getContext());
            isStrcasecmp &= FT->getNumParams() == 2 &&
                            FT->getReturnType()->isIntegerTy(32) &&
                            FT->getParamType(0) == FT->getParamType(1) &&
                            FT->getParamType(0) ==
                                IntegerType::getInt8PtrTy(M.getContext());
            isMemcmp &= FT->getNumParams() == 3 &&
                        FT->getReturnType()->isIntegerTy(32) &&
                        FT->getParamType(0)->isPointerTy() &&
                        FT->getParamType(1)->isPointerTy() &&
                        FT->getParamType(2)->isIntegerTy();
            isStrncmp &= FT->getNumParams() == 3 &&
                         FT->getReturnType()->isIntegerTy(32) &&
                         FT->getParamType(0) == FT->getParamType(1) &&
                         FT->getParamType(0) ==
                             IntegerType::getInt8PtrTy(M.getContext()) &&
                         FT->getParamType(2)->isIntegerTy();
            isStrncasecmp &= FT->getNumParams() == 3 &&
                             FT->getReturnType()->isIntegerTy(32) &&
                             FT->getParamType(0) == FT->getParamType(1) &&
                             FT->getParamType(0) ==
                                 IntegerType::getInt8PtrTy(M.getContext()) &&
                             FT->getParamType(2)->isIntegerTy();
            isStdString &= FT->getNumParams() >= 2 &&
                           FT->getParamType(0)->isPointerTy() &&
                           FT->getParamType(1)->isPointerTy();

            if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
                !isStrncasecmp && !isIntMemcpy && !isStdString)
              continue;

            /* is a str{n,}{case,}cmp/memcmp, check if we have
             * str{case,}cmp(x, "const") or str{case,}cmp("const", x)
             * strn{case,}cmp(x, "const", ..) or strn{case,}cmp("const", x, ..)
             * memcmp(x, "const", ..) or memcmp("const", x, ..) */
            Value *Str1P = callInst->getArgOperand(0),
                  *Str2P = callInst->getArgOperand(1);
            std::string Str1, Str2;
            StringRef   TmpStr;
            bool        HasStr1;
            getConstantStringInfo(Str1P, TmpStr);
            if (TmpStr.empty()) {

              HasStr1 = false;

            } else {

              HasStr1 = true;
              Str1 = TmpStr.str();

            }

            bool HasStr2;
            getConstantStringInfo(Str2P, TmpStr);
            if (TmpStr.empty()) {

              HasStr2 = false;

            } else {

              HasStr2 = true;
              Str2 = TmpStr.str();

            }

            if (debug)
              fprintf(stderr, "F:%s %p(%s)->\"%s\"(%s) %p(%s)->\"%s\"(%s)\n",
                      FuncName.c_str(), Str1P, Str1P->getName().str().c_str(),
                      Str1.c_str(), HasStr1 == true ? "true" : "false", Str2P,
                      Str2P->getName().str().c_str(), Str2.c_str(),
                      HasStr2 == true ? "true" : "false");

            // we handle the 2nd parameter first because of llvm memcpy
            if (!HasStr2) {

              auto *Ptr = dyn_cast<ConstantExpr>(Str2P);
              if (Ptr && Ptr->isGEPWithNoNotionalOverIndexing()) {

                if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {

                  if (Var->hasInitializer()) {

                    if (auto *Array = dyn_cast<ConstantDataArray>(
                            Var->getInitializer())) {

                      HasStr2 = true;
                      Str2 = Array->getRawDataValues().str();

                    }

                  }

                }

              }

            }

            // for the internal memcpy routine we only care for the second
            // parameter and are not reporting anything.
            if (isIntMemcpy == true) {

              if (HasStr2 == true) {

                Value *      op2 = callInst->getArgOperand(2);
                ConstantInt *ilen = dyn_cast<ConstantInt>(op2);
                if (ilen) {

                  uint64_t literalLength = Str2.size();
                  uint64_t optLength = ilen->getZExtValue();
                  if (optLength > literalLength + 1) {

                    optLength = Str2.length() + 1;

                  }

                  if (literalLength + 1 == optLength) {

                    Str2.append("\0", 1);  // add null byte
                    // addedNull = true;

                  }

                }

                valueMap[Str1P] = new std::string(Str2);

                if (debug)
                  fprintf(stderr, "Saved: %s for %p\n", Str2.c_str(), Str1P);
                continue;

              }

              continue;

            }

            // Neither a literal nor a global variable?
            // maybe it is a local variable that we saved
            if (!HasStr2) {

              std::string *strng = valueMap[Str2P];
              if (strng && !strng->empty()) {

                Str2 = *strng;
                HasStr2 = true;
                if (debug)
                  fprintf(stderr, "Filled2: %s for %p\n", strng->c_str(),
                          Str2P);

              }

            }

            if (!HasStr1) {

              auto Ptr = dyn_cast<ConstantExpr>(Str1P);

              if (Ptr && Ptr->isGEPWithNoNotionalOverIndexing()) {

                if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {

                  if (Var->hasInitializer()) {

                    if (auto *Array = dyn_cast<ConstantDataArray>(
                            Var->getInitializer())) {

                      HasStr1 = true;
                      Str1 = Array->getRawDataValues().str();

                    }

                  }

                }

              }

            }

            // Neither a literal nor a global variable?
            // maybe it is a local variable that we saved
            if (!HasStr1) {

              std::string *strng = valueMap[Str1P];
              if (strng && !strng->empty()) {

                Str1 = *strng;
                HasStr1 = true;
                if (debug)
                  fprintf(stderr, "Filled1: %s for %p\n", strng->c_str(),
                          Str1P);

              }

            }

            /* handle cases of one string is const, one string is variable */
            if (!(HasStr1 ^ HasStr2)) continue;

            std::string thestring;

            if (HasStr1)
              thestring = Str1;
            else
              thestring = Str2;

            optLen = thestring.length();
            if (optLen < 2 || (optLen == 2 && !thestring[1])) { continue; }

            if (isMemcmp || isStrncmp || isStrncasecmp) {

              Value *      op2 = callInst->getArgOperand(2);
              ConstantInt *ilen = dyn_cast<ConstantInt>(op2);

              if (ilen) {

                uint64_t literalLength = optLen;
                optLen = ilen->getZExtValue();
                if (optLen > literalLength + 1) { optLen = literalLength + 1; }
                if (optLen < 2) { continue; }
                if (literalLength + 1 == optLen) {  // add null byte
                  thestring.append("\0", 1);
                  addedNull = true;

                }

              }

            }

            // add null byte if this is a string compare function and a null
            // was not already added
            if (!isMemcmp) {

              if (addedNull == false && thestring[optLen - 1] != '\0') {

                thestring.append("\0", 1);  // add null byte
                optLen++;

              }

              if (!isStdString) {

                // ensure we do not have garbage
                size_t offset = thestring.find('\0', 0);
                if (offset + 1 < optLen) optLen = offset + 1;
                thestring = thestring.substr(0, optLen);

              }

            }

            if (!be_quiet) {

              fprintf(stderr, "%s: length %zu/%zu \"", FuncName.c_str(), optLen,
                      thestring.length());
              for (uint8_t i = 0; i < thestring.length(); i++) {

                uint8_t c = thestring[i];
                if (c <= 32 || c >= 127)
                  fprintf(stderr, "\\x%02x", c);
                else
                  fprintf(stderr, "%c", c);

              }

              fprintf(stderr, "\"\n");

            }

            // we take the longer string, even if the compare was to a
            // shorter part. Note that depending on the optimizer of the
            // compiler this can be wrong, but it is more likely that this
            // is helping the fuzzer
            if (optLen != thestring.length()) optLen = thestring.length();
            if (optLen > MAX_AUTO_EXTRA) optLen = MAX_AUTO_EXTRA;
            if (optLen < MIN_AUTO_EXTRA)  // too short? skip
              continue;

            dictionary.push_back(thestring.substr(0, optLen));

          }

        }

      }

    }

    for (auto &BB : F) {

      if (F.size() == 1) {

        InsBlocks.push_back(&BB);
        continue;

      }

      uint32_t succ = 0;
      for (succ_iterator SI = succ_begin(&BB), SE = succ_end(&BB); SI != SE;
           ++SI)
        if ((*SI)->size() > 0) succ++;
      if (succ < 2)  // no need to instrument
        continue;

      if (BlockList.size()) {

        int skip = 0;
        for (uint32_t k = 0; k < BlockList.size(); k++) {

          if (&BB == BlockList[k]) {

            if (debug)
              fprintf(stderr,
                      "DEBUG: Function %s skipping BB with/after __afl_loop\n",
                      F.getName().str().c_str());
            skip = 1;

          }

        }

        if (skip) continue;

      }

      InsBlocks.push_back(&BB);

    }

    if (InsBlocks.size() > 0) {

      uint32_t i = InsBlocks.size();

      do {

        --i;
        BasicBlock *              newBB = NULL;
        BasicBlock *              origBB = &(*InsBlocks[i]);
        std::vector<BasicBlock *> Successors;
        Instruction *             TI = origBB->getTerminator();
        uint32_t                  fs = origBB->getParent()->size();
        uint32_t                  countto;

        for (succ_iterator SI = succ_begin(origBB), SE = succ_end(origBB);
             SI != SE; ++SI) {

          BasicBlock *succ = *SI;
          Successors.push_back(succ);

        }

        if (fs == 1) {

          newBB = origBB;
          countto = 1;

        } else {

          if (TI == NULL || TI->getNumSuccessors() < 2) continue;
          countto = Successors.size();

        }

        // if (Successors.size() != TI->getNumSuccessors())
        //  FATAL("Different successor numbers %lu <-> %u\n", Successors.size(),
        //        TI->getNumSuccessors());

        for (uint32_t j = 0; j < countto; j++) {

          if (fs != 1) newBB = llvm::SplitEdge(origBB, Successors[j]);

          if (!newBB) {

            if (!be_quiet) WARNF("Split failed!");
            continue;

          }

          if (documentFile) {

            fprintf(documentFile, "ModuleID=%llu Function=%s edgeID=%u\n",
                    moduleID, F.getName().str().c_str(), afl_global_id);

          }

          BasicBlock::iterator IP = newBB->getFirstInsertionPt();
          IRBuilder<>          IRB(&(*IP));

          /* Set the ID of the inserted basic block */

          ConstantInt *CurLoc = ConstantInt::get(Int32Ty, afl_global_id++);

          /* Load SHM pointer */

          Value *MapPtrIdx;

          if (map_addr) {

            MapPtrIdx = IRB.CreateGEP(MapPtrFixed, CurLoc);

          } else {

            LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
            MapPtr->setMetadata(M.getMDKindID("nosanitize"),
                                MDNode::get(C, None));
            MapPtrIdx = IRB.CreateGEP(MapPtr, CurLoc);

          }

          /* Update bitmap */

          if (use_threadsafe_counters) {

            IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                                llvm::MaybeAlign(1),
#endif
                                llvm::AtomicOrdering::Monotonic);

          } else {

            LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
            Counter->setMetadata(M.getMDKindID("nosanitize"),
                                 MDNode::get(C, None));

            Value *Incr = IRB.CreateAdd(Counter, One);

            if (skip_nozero == NULL) {

              auto cf = IRB.CreateICmpEQ(Incr, Zero);
              auto carry = IRB.CreateZExt(cf, Int8Ty);
              Incr = IRB.CreateAdd(Incr, carry);

            }

            IRB.CreateStore(Incr, MapPtrIdx)
                ->setMetadata(M.getMDKindID("nosanitize"),
                              MDNode::get(C, None));

          }

          // done :)

          inst_blocks++;

        }

      } while (i > 0);

    }

  }

  if (documentFile) fclose(documentFile);
  documentFile = NULL;

  // save highest location ID to global variable
  // do this after each function to fail faster
  if (!be_quiet && afl_global_id > MAP_SIZE &&
      afl_global_id > FS_OPT_MAX_MAPSIZE) {

    uint32_t pow2map = 1, map = afl_global_id;
    while ((map = map >> 1))
      pow2map++;
    WARNF(
        "We have %u blocks to instrument but the map size is only %u. Either "
        "edit config.h and set MAP_SIZE_POW2 from %d to %u, then recompile "
        "afl-fuzz and llvm_mode and then make this target - or set "
        "AFL_MAP_SIZE with at least size %u when running afl-fuzz with this "
        "target.",
        afl_global_id, MAP_SIZE, MAP_SIZE_POW2, pow2map, afl_global_id);

  }

  if (!getenv("AFL_LLVM_LTO_DONTWRITEID") || dictionary.size() || map_addr) {

    // yes we could create our own function, insert it into ctors ...
    // but this would be a pain in the butt ... so we use afl-llvm-rt-lto.o

    Function *f = M.getFunction("__afl_auto_init_globals");

    if (!f) {

      fprintf(stderr,
              "Error: init function could not be found (this should not "
              "happen)\n");
      exit(-1);

    }

    BasicBlock *bb = &f->getEntryBlock();
    if (!bb) {

      fprintf(stderr,
              "Error: init function does not have an EntryBlock (this should "
              "not happen)\n");
      exit(-1);

    }

    BasicBlock::iterator IP = bb->getFirstInsertionPt();
    IRBuilder<>          IRB(&(*IP));

    if (map_addr) {

      GlobalVariable *AFLMapAddrFixed = new GlobalVariable(
          M, Int64Ty, true, GlobalValue::ExternalLinkage, 0, "__afl_map_addr");
      ConstantInt *MapAddr = ConstantInt::get(Int64Ty, map_addr);
      StoreInst *  StoreMapAddr = IRB.CreateStore(MapAddr, AFLMapAddrFixed);
      StoreMapAddr->setMetadata(M.getMDKindID("nosanitize"),
                                MDNode::get(C, None));

    }

    if (getenv("AFL_LLVM_LTO_DONTWRITEID") == NULL) {

      uint32_t write_loc = (((afl_global_id + 63) >> 6) << 6);

      GlobalVariable *AFLFinalLoc = new GlobalVariable(
          M, Int32Ty, true, GlobalValue::ExternalLinkage, 0, "__afl_final_loc");
      ConstantInt *const_loc = ConstantInt::get(Int32Ty, write_loc);
      StoreInst *  StoreFinalLoc = IRB.CreateStore(const_loc, AFLFinalLoc);
      StoreFinalLoc->setMetadata(M.getMDKindID("nosanitize"),
                                 MDNode::get(C, None));

    }

    if (dictionary.size()) {

      size_t memlen = 0, count = 0;

      // sort and unique the dictionary
      std::sort(dictionary.begin(), dictionary.end());
      auto last = std::unique(dictionary.begin(), dictionary.end());
      dictionary.erase(last, dictionary.end());

      for (auto token : dictionary) {

        memlen += token.length();
        count++;

      }

      if (!be_quiet)
        printf("AUTODICTIONARY: %zu string%s found\n", count,
               count == 1 ? "" : "s");

      if (count) {

        if ((ptr = (char *)malloc(memlen + count)) == NULL) {

          fprintf(stderr, "Error: malloc for %zu bytes failed!\n",
                  memlen + count);
          exit(-1);

        }

        count = 0;

        size_t offset = 0;
        for (auto token : dictionary) {

          if (offset + token.length() < 0xfffff0 && count < MAX_AUTO_EXTRAS) {

            ptr[offset++] = (uint8_t)token.length();
            memcpy(ptr + offset, token.c_str(), token.length());
            offset += token.length();
            count++;

          }

        }

        GlobalVariable *AFLDictionaryLen =
            new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage,
                               0, "__afl_dictionary_len");
        ConstantInt *const_len = ConstantInt::get(Int32Ty, offset);
        StoreInst *StoreDictLen = IRB.CreateStore(const_len, AFLDictionaryLen);
        StoreDictLen->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));

        ArrayType *ArrayTy = ArrayType::get(IntegerType::get(C, 8), offset);
        GlobalVariable *AFLInternalDictionary = new GlobalVariable(
            M, ArrayTy, true, GlobalValue::ExternalLinkage,
            ConstantDataArray::get(C,
                                   *(new ArrayRef<char>((char *)ptr, offset))),
            "__afl_internal_dictionary");
        AFLInternalDictionary->setInitializer(ConstantDataArray::get(
            C, *(new ArrayRef<char>((char *)ptr, offset))));
        AFLInternalDictionary->setConstant(true);

        GlobalVariable *AFLDictionary = new GlobalVariable(
            M, PointerType::get(Int8Ty, 0), false, GlobalValue::ExternalLinkage,
            0, "__afl_dictionary");

        Value *AFLDictOff = IRB.CreateGEP(AFLInternalDictionary, Zero);
        Value *AFLDictPtr =
            IRB.CreatePointerCast(AFLDictOff, PointerType::get(Int8Ty, 0));
        StoreInst *StoreDict = IRB.CreateStore(AFLDictPtr, AFLDictionary);
        StoreDict->setMetadata(M.getMDKindID("nosanitize"),
                               MDNode::get(C, None));

      }

    }

  }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else {

      char modeline[100];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
      OKF("Instrumented %d locations with no collisions (on average %llu "
          "collisions would be in afl-gcc/vanilla AFL) (%s mode).",
          inst_blocks, calculateCollisions(inst_blocks), modeline);

    }

  }

  return true;

}

char AFLLTOPass::ID = 0;

static void registerAFLLTOPass(const PassManagerBuilder &,
                               legacy::PassManagerBase &PM) {

  PM.add(new AFLLTOPass());

}

static RegisterPass<AFLLTOPass> X("afl-lto", "afl++ LTO instrumentation pass",
                                  false, false);

static RegisterStandardPasses RegisterAFLLTOPass(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast, registerAFLLTOPass);

