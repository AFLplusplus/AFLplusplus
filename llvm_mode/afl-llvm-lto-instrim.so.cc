/*
   american fuzzy lop++ - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast
   or afl-clang-lto with AFL_LLVM_INSTRUMENT=CFG or =INSTRIM

 */

#define AFL_LLVM_PASS

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

#include <unordered_set>
#include <list>
#include <string>
#include <fstream>
#include <set>

#include "llvm/Config/llvm-config.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/MemorySSAUpdater.h"
#include "llvm/Analysis/ValueTracking.h"

#include "MarkNodes.h"
#include "afl-llvm-common.h"

#include "config.h"
#include "debug.h"

using namespace llvm;

static cl::opt<bool> MarkSetOpt("markset", cl::desc("MarkSet"),
                                cl::init(false));
static cl::opt<bool> LoopHeadOpt("loophead", cl::desc("LoopHead"),
                                 cl::init(false));

namespace {

struct InsTrimLTO : public ModulePass {

 protected:
  uint32_t function_minimum_size = 1;
  char *   skip_nozero = NULL;
  int      afl_global_id = 1, debug = 0, autodictionary = 0;
  uint32_t be_quiet = 0, inst_blocks = 0, inst_funcs = 0;
  uint64_t map_addr = 0x10000;

 public:
  static char ID;

  InsTrimLTO() : ModulePass(ID) {

    char *ptr;

    if (getenv("AFL_DEBUG")) debug = 1;
    if ((ptr = getenv("AFL_LLVM_LTO_STARTID")) != NULL)
      if ((afl_global_id = atoi(ptr)) < 0 || afl_global_id >= MAP_SIZE)
        FATAL("AFL_LLVM_LTO_STARTID value of \"%s\" is not between 0 and %d\n",
              ptr, MAP_SIZE - 1);

    skip_nozero = getenv("AFL_LLVM_SKIP_NEVERZERO");

  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {

    ModulePass::getAnalysisUsage(AU);
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<LoopInfoWrapperPass>();

  }

  StringRef getPassName() const override {

    return "InstTrim LTO Instrumentation";

  }

  bool runOnModule(Module &M) override {

    char  be_quiet = 0;
    char *ptr;

    if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {

      SAYF(cCYA "InsTrimLTO" VERSION cRST
                " by csienslab and Marc \"vanHauser\" Heuse\n");

    } else

      be_quiet = 1;

    /* Process environment variables */

    if (getenv("AFL_LLVM_AUTODICTIONARY") ||
        getenv("AFL_LLVM_LTO_AUTODICTIONARY"))
      autodictionary = 1;

    if (getenv("AFL_LLVM_MAP_DYNAMIC")) map_addr = 0;

    if ((ptr = getenv("AFL_LLVM_MAP_ADDR"))) {

      uint64_t val;
      if (!*ptr || !strcmp(ptr, "0") || !strcmp(ptr, "0x0")) {

        map_addr = 0;

      } else if (map_addr == 0) {

        FATAL(
            "AFL_LLVM_MAP_ADDR and AFL_LLVM_MAP_DYNAMIC cannot be used "
            "together");

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

    if (debug) { fprintf(stderr, "map address is %lu\n", map_addr); }

    if (getenv("AFL_LLVM_INSTRIM_LOOPHEAD") != NULL ||
        getenv("LOOPHEAD") != NULL) {

      LoopHeadOpt = true;

    }

    if (getenv("AFL_LLVM_INSTRIM_SKIPSINGLEBLOCK") ||
        getenv("AFL_LLVM_SKIPSINGLEBLOCK"))
      function_minimum_size = 2;

    // this is our default
    MarkSetOpt = true;

    /* Initialize LLVM instrumentation */

    LLVMContext &                    C = M.getContext();
    std::vector<std::string>         dictionary;
    std::vector<CallInst *>          calls;
    DenseMap<Value *, std::string *> valueMap;

    IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

    ConstantInt *Zero = ConstantInt::get(Int8Ty, 0);
    ConstantInt *One = ConstantInt::get(Int8Ty, 1);

    /* Get/set globals for the SHM region. */

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

      for (Function &F : M) {

        for (auto &BB : F) {

          for (auto &IN : BB) {

            CallInst *callInst = nullptr;

            if ((callInst = dyn_cast<CallInst>(&IN))) {

              bool    isStrcmp = true;
              bool    isMemcmp = true;
              bool    isStrncmp = true;
              bool    isStrcasecmp = true;
              bool    isStrncasecmp = true;
              bool    isIntMemcpy = true;
              bool    addedNull = false;
              uint8_t optLen = 0;

              Function *Callee = callInst->getCalledFunction();
              if (!Callee) continue;
              if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
              std::string FuncName = Callee->getName().str();
              isStrcmp &= !FuncName.compare("strcmp");
              isMemcmp &= !FuncName.compare("memcmp");
              isStrncmp &= !FuncName.compare("strncmp");
              isStrcasecmp &= !FuncName.compare("strcasecmp");
              isStrncasecmp &= !FuncName.compare("strncasecmp");
              isIntMemcpy &= !FuncName.compare("llvm.memcpy.p0i8.p0i8.i64");

              if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
                  !isStrncasecmp && !isIntMemcpy)
                continue;

              /* Verify the strcmp/memcmp/strncmp/strcasecmp/strncasecmp
               * function prototype */
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

              if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
                  !isStrncasecmp && !isIntMemcpy)
                continue;

              /* is a str{n,}{case,}cmp/memcmp, check if we have
               * str{case,}cmp(x, "const") or str{case,}cmp("const", x)
               * strn{case,}cmp(x, "const", ..) or strn{case,}cmp("const", x,
               * ..) memcmp(x, "const", ..) or memcmp("const", x, ..) */
              Value *Str1P = callInst->getArgOperand(0),
                    *Str2P = callInst->getArgOperand(1);
              std::string Str1, Str2;
              StringRef   TmpStr;
              bool        HasStr1 = getConstantStringInfo(Str1P, TmpStr);
              if (TmpStr.empty())
                HasStr1 = false;
              else
                Str1 = TmpStr.str();
              bool HasStr2 = getConstantStringInfo(Str2P, TmpStr);
              if (TmpStr.empty())
                HasStr2 = false;
              else
                Str2 = TmpStr.str();

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

                  if (auto *Var =
                          dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {

                    if (Var->hasInitializer()) {

                      if (auto *Array = dyn_cast<ConstantDataArray>(
                              Var->getInitializer())) {

                        HasStr2 = true;
                        Str2 = Array->getAsString().str();

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
                    if (literalLength + 1 == optLength) {

                      Str2.append("\0", 1);  // add null byte
                      addedNull = true;

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

                  if (auto *Var =
                          dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {

                    if (Var->hasInitializer()) {

                      if (auto *Array = dyn_cast<ConstantDataArray>(
                              Var->getInitializer())) {

                        HasStr1 = true;
                        Str1 = Array->getAsString().str();

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

              if (isMemcmp || isStrncmp || isStrncasecmp) {

                Value *      op2 = callInst->getArgOperand(2);
                ConstantInt *ilen = dyn_cast<ConstantInt>(op2);
                if (ilen) {

                  uint64_t literalLength = optLen;
                  optLen = ilen->getZExtValue();
                  if (literalLength + 1 == optLen) {  // add null byte
                    thestring.append("\0", 1);
                    addedNull = true;

                  }

                }

              }

              // add null byte if this is a string compare function and a null
              // was not already added
              if (addedNull == false && !isMemcmp) {

                thestring.append("\0", 1);  // add null byte
                optLen++;

              }

              if (!be_quiet) {

                std::string outstring;
                fprintf(stderr, "%s: length %u/%u \"", FuncName.c_str(), optLen,
                        (unsigned int)thestring.length());
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

    }

    /* InsTrim instrumentation starts here */

    u64 total_rs = 0;
    u64 total_hs = 0;

    for (Function &F : M) {

      if (debug) {

        uint32_t bb_cnt = 0;

        for (auto &BB : F)
          if (BB.size() > 0) ++bb_cnt;
        SAYF(cMGN "[D] " cRST "Function %s size %zu %u\n",
             F.getName().str().c_str(), F.size(), bb_cnt);

      }

      // if the function below our minimum size skip it (1 or 2)
      if (F.size() < function_minimum_size) continue;
      if (isBlacklisted(&F)) continue;

      std::unordered_set<BasicBlock *> MS;
      if (!MarkSetOpt) {

        for (auto &BB : F) {

          MS.insert(&BB);

        }

        total_rs += F.size();

      } else {

        auto Result = markNodes(&F);
        auto RS = Result.first;
        auto HS = Result.second;

        MS.insert(RS.begin(), RS.end());
        if (!LoopHeadOpt) {

          MS.insert(HS.begin(), HS.end());
          total_rs += MS.size();

        } else {

          DenseSet<std::pair<BasicBlock *, BasicBlock *>> EdgeSet;
          DominatorTreeWrapperPass *                      DTWP =
              &getAnalysis<DominatorTreeWrapperPass>(F);
          auto DT = &DTWP->getDomTree();

          total_rs += RS.size();
          total_hs += HS.size();

          for (BasicBlock *BB : HS) {

            bool Inserted = false;
            for (auto BI = pred_begin(BB), BE = pred_end(BB); BI != BE; ++BI) {

              auto Edge = BasicBlockEdge(*BI, BB);
              if (Edge.isSingleEdge() && DT->dominates(Edge, BB)) {

                EdgeSet.insert({*BI, BB});
                Inserted = true;
                break;

              }

            }

            if (!Inserted) {

              MS.insert(BB);
              total_rs += 1;
              total_hs -= 1;

            }

          }

          for (auto I = EdgeSet.begin(), E = EdgeSet.end(); I != E; ++I) {

            auto PredBB = I->first;
            auto SuccBB = I->second;
            auto NewBB = SplitBlockPredecessors(SuccBB, {PredBB}, ".split", DT,
                                                nullptr, nullptr, false);
            MS.insert(NewBB);

          }

        }

      }

      for (BasicBlock &BB : F) {

        auto        PI = pred_begin(&BB);
        auto        PE = pred_end(&BB);
        IRBuilder<> IRB(&*BB.getFirstInsertionPt());
        Value *     L = NULL;

        if (MarkSetOpt && MS.find(&BB) == MS.end()) { continue; }

        if (PI == PE) {

          L = ConstantInt::get(Int32Ty, afl_global_id++);

        } else {

          auto *PN = PHINode::Create(Int32Ty, 0, "", &*BB.begin());
          DenseMap<BasicBlock *, unsigned> PredMap;
          for (auto PI = pred_begin(&BB), PE = pred_end(&BB); PI != PE; ++PI) {

            BasicBlock *PBB = *PI;
            auto        It = PredMap.insert({PBB, afl_global_id++});
            unsigned    Label = It.first->second;
            PN->addIncoming(ConstantInt::get(Int32Ty, Label), PBB);

          }

          L = PN;

        }

        /* Load SHM pointer */
        Value *MapPtrIdx;

        if (map_addr) {

          MapPtrIdx = IRB.CreateGEP(MapPtrFixed, L);

        } else {

          LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
          MapPtr->setMetadata(M.getMDKindID("nosanitize"),
                              MDNode::get(C, None));
          MapPtrIdx = IRB.CreateGEP(MapPtr, L);

        }

        /* Update bitmap */
        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        Value *Incr = IRB.CreateAdd(Counter, One);

        if (skip_nozero) {

          auto cf = IRB.CreateICmpEQ(Incr, Zero);
          auto carry = IRB.CreateZExt(cf, Int8Ty);
          Incr = IRB.CreateAdd(Incr, carry);

        }

        IRB.CreateStore(Incr, MapPtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        // done :)

        inst_blocks++;

      }

    }

    // save highest location ID to global variable
    // do this after each function to fail faster
    if (!be_quiet && afl_global_id > MAP_SIZE &&
        afl_global_id > FS_OPT_MAX_MAPSIZE) {

      uint32_t pow2map = 1, map = afl_global_id;
      while ((map = map >> 1))
        pow2map++;
      WARNF(
          "We have %u blocks to instrument but the map size is only %u. Either "
          "edit config.h and set MAP_SIZE_POW2 from %u to %u, then recompile "
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

        GlobalVariable *AFLMapAddrFixed =
            new GlobalVariable(M, Int64Ty, true, GlobalValue::ExternalLinkage,
                               0, "__afl_map_addr");
        ConstantInt *MapAddr = ConstantInt::get(Int64Ty, map_addr);
        StoreInst *  StoreMapAddr = IRB.CreateStore(MapAddr, AFLMapAddrFixed);
        StoreMapAddr->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));

      }

      if (getenv("AFL_LLVM_LTO_DONTWRITEID") == NULL) {

        uint32_t write_loc = afl_global_id;

        if (afl_global_id % 8) write_loc = (((afl_global_id + 8) >> 3) << 3);

        GlobalVariable *AFLFinalLoc =
            new GlobalVariable(M, Int32Ty, true, GlobalValue::ExternalLinkage,
                               0, "__afl_final_loc");
        ConstantInt *const_loc = ConstantInt::get(Int32Ty, write_loc);
        StoreInst *  StoreFinalLoc = IRB.CreateStore(const_loc, AFLFinalLoc);
        StoreFinalLoc->setMetadata(M.getMDKindID("nosanitize"),
                                   MDNode::get(C, None));

      }

      if (dictionary.size()) {

        size_t memlen = 0, count = 0, offset = 0;
        char * ptr;

        for (auto token : dictionary) {

          memlen += token.length();
          count++;

        }

        if (!be_quiet)
          printf("AUTODICTIONARY: %lu string%s found\n", count,
                 count == 1 ? "" : "s");

        if (count) {

          if ((ptr = (char *)malloc(memlen + count)) == NULL) {

            fprintf(stderr, "Error: malloc for %lu bytes failed!\n",
                    memlen + count);
            exit(-1);

          }

          count = 0;

          for (auto token : dictionary) {

            if (offset + token.length() < 0xfffff0 && count < MAX_AUTO_EXTRAS) {

              ptr[offset++] = (uint8_t)token.length();
              memcpy(ptr + offset, token.c_str(), token.length());
              offset += token.length();
              count++;

            }

          }

          GlobalVariable *AFLDictionaryLen = new GlobalVariable(
              M, Int32Ty, false, GlobalValue::ExternalLinkage, 0,
              "__afl_dictionary_len");
          ConstantInt *const_len = ConstantInt::get(Int32Ty, offset);
          StoreInst *  StoreDictLen =
              IRB.CreateStore(const_len, AFLDictionaryLen);
          StoreDictLen->setMetadata(M.getMDKindID("nosanitize"),
                                    MDNode::get(C, None));

          ArrayType *ArrayTy = ArrayType::get(IntegerType::get(C, 8), offset);
          GlobalVariable *AFLInternalDictionary = new GlobalVariable(
              M, ArrayTy, true, GlobalValue::ExternalLinkage,
              ConstantDataArray::get(
                  C, *(new ArrayRef<char>((char *)ptr, offset))),
              "__afl_internal_dictionary");
          AFLInternalDictionary->setInitializer(ConstantDataArray::get(
              C, *(new ArrayRef<char>((char *)ptr, offset))));
          AFLInternalDictionary->setConstant(true);

          GlobalVariable *AFLDictionary = new GlobalVariable(
              M, PointerType::get(Int8Ty, 0), false,
              GlobalValue::ExternalLinkage, 0, "__afl_dictionary");

          Value *AFLDictOff = IRB.CreateGEP(AFLInternalDictionary, Zero);
          Value *AFLDictPtr =
              IRB.CreatePointerCast(AFLDictOff, PointerType::get(Int8Ty, 0));
          StoreInst *StoreDict = IRB.CreateStore(AFLDictPtr, AFLDictionary);
          StoreDict->setMetadata(M.getMDKindID("nosanitize"),
                                 MDNode::get(C, None));

        }

      }

    }

    // count basic blocks for comparison with classic instrumentation

    u32 edges = 0;
    for (auto &F : M) {

      if (F.size() < function_minimum_size) continue;

      for (auto &BB : F) {

        bool would_instrument = false;

        for (BasicBlock *Pred : predecessors(&BB)) {

          int count = 0;
          for (BasicBlock *Succ : successors(Pred))
            if (Succ != NULL) count++;

          if (count > 1) return true;

        }

        if (would_instrument == true) edges++;

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
        OKF("Instrumented %u locations (%llu, %llu) with no collisions (on "
            "average %llu collisions would be in afl-gcc/afl-clang-fast for %u "
            "edges) (%s mode).",
            inst_blocks, total_rs, total_hs, calculateCollisions(edges), edges,
            modeline);

      }

    }

    return true;

  }

};  // end of struct InsTrim

}  // end of anonymous namespace

char InsTrimLTO::ID = 0;

static void registerInsTrimLTO(const PassManagerBuilder &,
                               legacy::PassManagerBase &PM) {

  PM.add(new InsTrimLTO());

}

static RegisterPass<InsTrimLTO> X("afl-lto-instrim",
                                  "afl++ InsTrim LTO instrumentation pass",
                                  false, false);

static RegisterStandardPasses RegisterInsTrimLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast, registerInsTrimLTO);

