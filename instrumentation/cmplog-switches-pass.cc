/*
   american fuzzy lop++ - LLVM CmpLog instrumentation
   --------------------------------------------------

   Written by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>

#include "llvm/Config/llvm-config.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  #include "llvm/Passes/PassPlugin.h"
  #include "llvm/Passes/PassBuilder.h"
  #include "llvm/IR/PassManager.h"
#else
  #include "llvm/IR/LegacyPassManager.h"
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#if LLVM_VERSION_MAJOR < 17
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/ValueTracking.h"

#include "llvm/IR/IRBuilder.h"
#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/Verifier.h"
  #include "llvm/IR/DebugInfo.h"
#else
  #include "llvm/Analysis/Verifier.h"
  #include "llvm/DebugInfo.h"
  #define nullptr 0
#endif

#include <set>
#include "afl-llvm-common.h"

using namespace llvm;

namespace {

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
class CmplogSwitches : public PassInfoMixin<CmplogSwitches> {

 public:
  CmplogSwitches() {

#else
class CmplogSwitches : public ModulePass {

 public:
  static char ID;
  CmplogSwitches() : ModulePass(ID) {

#endif
    initInstrumentList();

  }

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;

  #if LLVM_VERSION_MAJOR < 4
  const char *getPassName() const override {

  #else
  StringRef getPassName() const override {

  #endif
    return "cmplog switch split";

  }

#endif

 private:
  bool hookInstrs(Module &M);

};

}  // namespace

#if LLVM_MAJOR >= 11
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "cmplogswitches", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

  #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
  #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(CmplogSwitches());

                });

          }};

}

#else
char CmplogSwitches::ID = 0;
#endif

template <class Iterator>
Iterator Unique(Iterator first, Iterator last) {

  while (first != last) {

    Iterator next(first);
    last = std::remove(++next, last, *first);
    first = next;

  }

  return last;

}

bool CmplogSwitches::hookInstrs(Module &M) {

  std::vector<SwitchInst *> switches;
  LLVMContext              &C = M.getContext();

  Type        *VoidTy = Type::getVoidTy(C);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee
#else
  Constant *
#endif
      c1 = M.getOrInsertFunction("__cmplog_ins_hook1", VoidTy, Int8Ty, Int8Ty,
                                 Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee cmplogHookIns1 = c1;
#else
  Function *cmplogHookIns1 = cast<Function>(c1);
#endif

#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee
#else
  Constant *
#endif
      c2 = M.getOrInsertFunction("__cmplog_ins_hook2", VoidTy, Int16Ty, Int16Ty,
                                 Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee cmplogHookIns2 = c2;
#else
  Function *cmplogHookIns2 = cast<Function>(c2);
#endif

#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee
#else
  Constant *
#endif
      c4 = M.getOrInsertFunction("__cmplog_ins_hook4", VoidTy, Int32Ty, Int32Ty,
                                 Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee cmplogHookIns4 = c4;
#else
  Function *cmplogHookIns4 = cast<Function>(c4);
#endif

#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee
#else
  Constant *
#endif
      c8 = M.getOrInsertFunction("__cmplog_ins_hook8", VoidTy, Int64Ty, Int64Ty,
                                 Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee cmplogHookIns8 = c8;
#else
  Function *cmplogHookIns8 = cast<Function>(c8);
#endif

  GlobalVariable *AFLCmplogPtr = M.getNamedGlobal("__afl_cmp_map");

  if (!AFLCmplogPtr) {

    AFLCmplogPtr = new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                                      GlobalValue::ExternalWeakLinkage, 0,
                                      "__afl_cmp_map");

  }

  Constant *Null = Constant::getNullValue(PointerType::get(Int8Ty, 0));

  /* iterate over all functions, bbs and instruction and add suitable calls */
  for (auto &F : M) {

    if (!isInInstrumentList(&F, MNAME)) continue;

    for (auto &BB : F) {

      SwitchInst *switchInst = nullptr;
      if ((switchInst = dyn_cast<SwitchInst>(BB.getTerminator()))) {

        if (switchInst->getNumCases() > 1) { switches.push_back(switchInst); }

      }

    }

  }

  // unique the collected switches
  switches.erase(Unique(switches.begin(), switches.end()), switches.end());

  // Instrument switch values for cmplog
  if (switches.size()) {

    if (!be_quiet)
      errs() << "Hooking " << switches.size() << " switch instructions\n";

    for (auto &SI : switches) {

      Value        *Val = SI->getCondition();
      unsigned int  max_size = Val->getType()->getIntegerBitWidth(), cast_size;
      unsigned char do_cast = 0;

      if (!SI->getNumCases() || max_size < 16) {

        // if (!be_quiet) errs() << "skip trivial switch..\n";
        continue;

      }

      if (max_size % 8) {

        max_size = (((max_size / 8) + 1) * 8);
        do_cast = 1;

      }

      IRBuilder<> IRB2(SI->getParent());
      IRB2.SetInsertPoint(SI);

      LoadInst *CmpPtr = IRB2.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
          PointerType::get(Int8Ty, 0),
#endif
          AFLCmplogPtr);
      CmpPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      auto is_not_null = IRB2.CreateICmpNE(CmpPtr, Null);
      auto ThenTerm = SplitBlockAndInsertIfThen(is_not_null, SI, false);

      IRBuilder<> IRB(ThenTerm);

      if (max_size > 128) {

        if (!be_quiet) {

          fprintf(stderr,
                  "Cannot handle this switch bit size: %u (truncating)\n",
                  max_size);

        }

        max_size = 128;
        do_cast = 1;

      }

      // do we need to cast?
      switch (max_size) {

        case 8:
        case 16:
        case 32:
        case 64:
        case 128:
          cast_size = max_size;
          break;
        default:
          cast_size = 128;
          do_cast = 1;

      }

      Value *CompareTo = Val;

      if (do_cast) {

        CompareTo =
            IRB.CreateIntCast(CompareTo, IntegerType::get(C, cast_size), false);

      }

      for (SwitchInst::CaseIt i = SI->case_begin(), e = SI->case_end(); i != e;
           ++i) {

#if LLVM_VERSION_MAJOR < 5
        ConstantInt *cint = i.getCaseValue();
#else
        ConstantInt *cint = i->getCaseValue();
#endif

        if (cint) {

          std::vector<Value *> args;
          args.push_back(CompareTo);

          Value *new_param = cint;

          if (do_cast) {

            new_param =
                IRB.CreateIntCast(cint, IntegerType::get(C, cast_size), false);

          }

          if (new_param) {

            args.push_back(new_param);
            ConstantInt *attribute = ConstantInt::get(Int8Ty, 1);
            args.push_back(attribute);
            if (cast_size != max_size) {

              ConstantInt *bitsize =
                  ConstantInt::get(Int8Ty, (max_size / 8) - 1);
              args.push_back(bitsize);

            }

            switch (cast_size) {

              case 8:
                IRB.CreateCall(cmplogHookIns1, args);
                break;
              case 16:
                IRB.CreateCall(cmplogHookIns2, args);
                break;
              case 32:
                IRB.CreateCall(cmplogHookIns4, args);
                break;
              case 64:
                IRB.CreateCall(cmplogHookIns8, args);
                break;
              case 128:
#ifdef WORD_SIZE_64
                if (max_size == 128) {

                  IRB.CreateCall(cmplogHookIns16, args);

                } else {

                  IRB.CreateCall(cmplogHookInsN, args);

                }

#endif
                break;
              default:
                break;

            }

          }

        }

      }

    }

  }

  if (switches.size())
    return true;
  else
    return false;

}

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
PreservedAnalyses CmplogSwitches::run(Module &M, ModuleAnalysisManager &MAM) {

#else
bool CmplogSwitches::runOnModule(Module &M) {

#endif

  if (getenv("AFL_QUIET") == NULL)
    printf("Running cmplog-switches-pass by andreafioraldi@gmail.com\n");
  else
    be_quiet = 1;
  bool ret = hookInstrs(M);
  verifyModule(M);

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  if (ret == false)
    return PreservedAnalyses::all();
  else
    return PreservedAnalyses();
#else
  return ret;
#endif

}

#if LLVM_VERSION_MAJOR < 11                         /* use old pass manager */
static void registerCmplogSwitchesPass(const PassManagerBuilder &,
                                       legacy::PassManagerBase &PM) {

  auto p = new CmplogSwitches();
  PM.add(p);

}

static RegisterStandardPasses RegisterCmplogSwitchesPass(
    PassManagerBuilder::EP_OptimizerLast, registerCmplogSwitchesPass);

static RegisterStandardPasses RegisterCmplogSwitchesPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerCmplogSwitchesPass);

  #if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterCmplogSwitchesPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    registerCmplogSwitchesPass);
  #endif
#endif

