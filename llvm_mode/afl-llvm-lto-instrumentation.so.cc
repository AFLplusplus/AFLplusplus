/*
   american fuzzy lop++ - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>

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

#include <set>

using namespace llvm;

namespace {

class AFLLTOPass : public ModulePass {

 public:
  static char ID;

  AFLLTOPass() : ModulePass(ID) {

    char *ptr;

    if (getenv("AFL_DEBUG")) debug = 1;
    if ((ptr = getenv("AFL_LLVM_LTO_STARTID")) != NULL)
      if ((afl_global_id = atoi(ptr)) < 0 || afl_global_id >= MAP_SIZE)
        FATAL("AFL_LLVM_LTO_STARTID value of \"%s\" is not between 0 and %d\n",
              ptr, MAP_SIZE - 1);

  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {

    ModulePass::getAnalysisUsage(AU);
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<LoopInfoWrapperPass>();

  }

  // Calculate the number of average collisions that would occur if all
  // location IDs would be assigned randomly (like normal afl/afl++).
  // This uses the "balls in bins" algorithm.
  unsigned long long int calculateCollisions(uint32_t edges) {

    double                 bins = MAP_SIZE;
    double                 balls = edges;
    double                 step1 = 1 - (1 / bins);
    double                 step2 = pow(step1, balls);
    double                 step3 = bins * step2;
    double                 step4 = round(step3);
    unsigned long long int empty = step4;
    unsigned long long int collisions = edges - (MAP_SIZE - empty);
    return collisions;

  }

  // Get the internal llvm name of a basic block
  // This is an ugly debug support so it is commented out :-)
  /*
    static char *getBBName(const BasicBlock *BB) {

      static char *name;

      if (!BB->getName().empty()) {

        name = strdup(BB->getName().str().c_str());
        return name;

      }

      std::string        Str;
      raw_string_ostream OS(Str);

      BB->printAsOperand(OS, false);

      name = strdup(OS.str().c_str());

      return name;

    }

  */

  static bool isBlacklisted(const Function *F) {

    static const char *Blacklist[] = {

        "asan.",  "llvm.", "sancov.",   "__ubsan_handle_", "ign.",
        "__afl_", "_fini", "__libc_csu"

    };

    for (auto const &BlacklistFunc : Blacklist) {

      if (F->getName().startswith(BlacklistFunc)) { return true; }

    }

    return false;

  }

  bool runOnModule(Module &M) override;

 protected:
  int      afl_global_id = 1, debug = 0, autodictionary = 0;
  uint32_t be_quiet = 0, inst_blocks = 0, inst_funcs = 0, total_instr = 0;

};

}  // namespace

bool AFLLTOPass::runOnModule(Module &M) {

  LLVMContext &            C = M.getContext();
  std::vector<std::string> dictionary;
  std::vector<CallInst *>  calls;

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  if (getenv("AFL_DEBUG")) debug = 1;

  /* Show a banner */

  if ((isatty(2) && !getenv("AFL_QUIET")) || debug) {

    SAYF(cCYA "afl-llvm-lto" VERSION cRST
              " by Marc \"vanHauser\" Heuse <mh@mh-sec.de>\n");

  } else

    be_quiet = 1;

  if (getenv("AFL_LLVM_AUTODICTIONARY") ||
      getenv("AFL_LLVM_LTO_AUTODICTIONARY"))
    autodictionary = 1;

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  ConstantInt *Zero = ConstantInt::get(Int8Ty, 0);
  ConstantInt *One = ConstantInt::get(Int8Ty, 1);

  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M) {

    if (F.size() < 2) continue;
    if (isBlacklisted(&F)) continue;

    std::vector<BasicBlock *> InsBlocks;

    if (autodictionary) {

      for (auto &BB : F) {

        for (auto &IN : BB) {

          CallInst *callInst = nullptr;

          if ((callInst = dyn_cast<CallInst>(&IN))) {

            bool isStrcmp = true;
            bool isMemcmp = true;
            bool isStrncmp = true;
            bool isStrcasecmp = true;
            bool isStrncasecmp = true;

            Function *Callee = callInst->getCalledFunction();
            if (!Callee) continue;
            if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
            StringRef FuncName = Callee->getName();
            isStrcmp &= !FuncName.compare(StringRef("strcmp"));
            isMemcmp &= !FuncName.compare(StringRef("memcmp"));
            isStrncmp &= !FuncName.compare(StringRef("strncmp"));
            isStrcasecmp &= !FuncName.compare(StringRef("strcasecmp"));
            isStrncasecmp &= !FuncName.compare(StringRef("strncasecmp"));

            if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
                !isStrncasecmp)
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

            if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
                !isStrncasecmp)
              continue;

            /* is a str{n,}{case,}cmp/memcmp, check if we have
             * str{case,}cmp(x, "const") or str{case,}cmp("const", x)
             * strn{case,}cmp(x, "const", ..) or strn{case,}cmp("const", x, ..)
             * memcmp(x, "const", ..) or memcmp("const", x, ..) */
            Value *Str1P = callInst->getArgOperand(0),
                  *Str2P = callInst->getArgOperand(1);
            StringRef Str1, Str2;
            bool      HasStr1 = getConstantStringInfo(Str1P, Str1);
            bool      HasStr2 = getConstantStringInfo(Str2P, Str2);

            /* handle cases of one string is const, one string is variable */
            if (!(HasStr1 ^ HasStr2)) continue;

            if (isMemcmp || isStrncmp || isStrncasecmp) {

              /* check if third operand is a constant integer
               * strlen("constStr") and sizeof() are treated as constant */
              Value *      op2 = callInst->getArgOperand(2);
              ConstantInt *ilen = dyn_cast<ConstantInt>(op2);
              if (!ilen) continue;
              /* final precaution: if size of compare is larger than constant
               * string skip it*/
              uint64_t literalLength =
                  HasStr1 ? GetStringLength(Str1P) : GetStringLength(Str2P);
              if (literalLength < ilen->getZExtValue()) continue;

            }

            calls.push_back(callInst);

          }

        }

      }

    }

    for (auto &BB : F) {

      uint32_t succ = 0;

      for (succ_iterator SI = succ_begin(&BB), SE = succ_end(&BB); SI != SE;
           ++SI)
        if ((*SI)->size() > 0) succ++;

      if (succ < 2)  // no need to instrument
        continue;

      InsBlocks.push_back(&BB);

    }

    if (InsBlocks.size() > 0) {

      uint32_t i = InsBlocks.size();

      do {

        --i;
        BasicBlock *              origBB = &(*InsBlocks[i]);
        std::vector<BasicBlock *> Successors;
        Instruction *             TI = origBB->getTerminator();

        for (succ_iterator SI = succ_begin(origBB), SE = succ_end(origBB);
             SI != SE; ++SI) {

          BasicBlock *succ = *SI;
          Successors.push_back(succ);

        }

        if (TI == NULL || TI->getNumSuccessors() < 2) continue;

        // if (Successors.size() != TI->getNumSuccessors())
        //  FATAL("Different successor numbers %lu <-> %u\n", Successors.size(),
        //        TI->getNumSuccessors());

        for (uint32_t j = 0; j < Successors.size(); j++) {

          BasicBlock *newBB = llvm::SplitEdge(origBB, Successors[j]);

          if (!newBB) {

            if (!be_quiet) WARNF("Split failed!");
            continue;

          }

          BasicBlock::iterator IP = newBB->getFirstInsertionPt();
          IRBuilder<>          IRB(&(*IP));

          /* Set the ID of the inserted basic block */

          ConstantInt *CurLoc = ConstantInt::get(Int32Ty, afl_global_id++);

          /* Load SHM pointer */

          LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
          MapPtr->setMetadata(M.getMDKindID("nosanitize"),
                              MDNode::get(C, None));
          Value *MapPtrIdx = IRB.CreateGEP(MapPtr, CurLoc);

          /* Update bitmap */

          LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
          Counter->setMetadata(M.getMDKindID("nosanitize"),
                               MDNode::get(C, None));

          Value *Incr = IRB.CreateAdd(Counter, One);

          auto cf = IRB.CreateICmpEQ(Incr, Zero);
          auto carry = IRB.CreateZExt(cf, Int8Ty);
          Incr = IRB.CreateAdd(Incr, carry);
          IRB.CreateStore(Incr, MapPtrIdx)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          // done :)

          inst_blocks++;

        }

      } while (i > 0);

    }

    // save highest location ID to global variable
    // do this after each function to fail faster
    if (afl_global_id > MAP_SIZE) {

      uint32_t pow2map = 1, map = afl_global_id;
      while ((map = map >> 1))
        pow2map++;
      FATAL(
          "We have %u blocks to instrument but the map size is only %u! Edit "
          "config.h and set MAP_SIZE_POW2 from %u to %u, then recompile "
          "afl-fuzz and llvm_mode.",
          afl_global_id, MAP_SIZE, MAP_SIZE_POW2, pow2map);

    }

  }

  if (calls.size()) {

    for (auto &callInst : calls) {

      Value *Str1P = callInst->getArgOperand(0),
            *Str2P = callInst->getArgOperand(1);
      StringRef   Str1, Str2, ConstStr;
      std::string TmpConstStr;
      Value *     VarStr;
      bool        HasStr1 = getConstantStringInfo(Str1P, Str1);
      getConstantStringInfo(Str2P, Str2);
      uint64_t constLen, sizedLen;
      bool     isMemcmp = !callInst->getCalledFunction()->getName().compare(
          StringRef("memcmp"));
      bool isSizedcmp = isMemcmp ||
                        !callInst->getCalledFunction()->getName().compare(
                            StringRef("strncmp")) ||
                        !callInst->getCalledFunction()->getName().compare(
                            StringRef("strncasecmp"));

      if (isSizedcmp) {

        Value *      op2 = callInst->getArgOperand(2);
        ConstantInt *ilen = dyn_cast<ConstantInt>(op2);
        sizedLen = ilen->getZExtValue();

      } else {

        sizedLen = 0;

      }

      if (HasStr1) {

        TmpConstStr = Str1.str();
        VarStr = Str2P;
        constLen = isMemcmp ? sizedLen : GetStringLength(Str1P);

      } else {

        TmpConstStr = Str2.str();
        VarStr = Str1P;
        constLen = isMemcmp ? sizedLen : GetStringLength(Str2P);

      }

      /* properly handle zero terminated C strings by adding the terminating 0
       * to the StringRef (in comparison to std::string a StringRef has built-in
       * runtime bounds checking, which makes debugging easier) */
      TmpConstStr.append("\0", 1);
      ConstStr = StringRef(TmpConstStr);

      if (isSizedcmp && constLen > sizedLen) { constLen = sizedLen; }

      if (!be_quiet)
        errs() << callInst->getCalledFunction()->getName() << ": len "
               << constLen << ": " << ConstStr << "\n";

      if (constLen && constLen < MAX_DICT_FILE)
        dictionary.push_back(ConstStr.str().substr(0, constLen));

    }

  }

  if (getenv("AFL_LLVM_LTO_DONTWRITEID") == NULL || dictionary.size()) {

    // yes we could create our own function, insert it into ctors ...
    // but this would be a pain in the butt ... so we use afl-llvm-rt-lto.o

    Function *f = M.getFunction("__afl_auto_init_globals");

    if (!f) {

      fprintf(stderr,
              "Error: init function could not be found (this hould not "
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

    if (getenv("AFL_LLVM_LTO_DONTWRITEID") == NULL) {

      GlobalVariable *AFLFinalLoc = new GlobalVariable(
          M, Int32Ty, true, GlobalValue::ExternalLinkage, 0, "__afl_final_loc",
          0, GlobalVariable::GeneralDynamicTLSModel, 0, false);
      ConstantInt *const_loc = ConstantInt::get(Int32Ty, afl_global_id);
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

      if (!be_quiet) printf("AUTODICTIONARY: %lu strings found\n", count);

      if (count) {

        if ((ptr = (char *)malloc(memlen + count)) == NULL) {

          fprintf(stderr, "Error: malloc for %lu bytes failed!\n",
                  memlen + count);
          exit(-1);

        }

        for (auto token : dictionary) {

          if (offset + token.length() < 0xfffff0) {

            ptr[offset++] = (uint8_t)token.length();
            memcpy(ptr + offset, token.c_str(), token.length());
            offset += token.length();

          }

        }

        GlobalVariable *AFLDictionaryLen = new GlobalVariable(
            M, Int32Ty, false, GlobalValue::ExternalLinkage, 0,
            "__afl_dictionary_len", 0, GlobalVariable::GeneralDynamicTLSModel,
            0, false);
        ConstantInt *const_len = ConstantInt::get(Int32Ty, offset);
        StoreInst *StoreDictLen = IRB.CreateStore(const_len, AFLDictionaryLen);
        StoreDictLen->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));

        ArrayType *ArrayTy = ArrayType::get(IntegerType::get(C, 8), offset);
        GlobalVariable *AFLInternalDictionary = new GlobalVariable(
            M, ArrayTy, true, GlobalValue::ExternalLinkage,
            ConstantDataArray::get(C,
                                   *(new ArrayRef<char>((char *)ptr, offset))),
            "__afl_internal_dictionary", 0,
            GlobalVariable::GeneralDynamicTLSModel, 0, false);
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
      OKF("Instrumented %u locations with no collisions (on average %llu "
          "collisions would be in afl-gcc/afl-clang-fast) (%s mode).",
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

