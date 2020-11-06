/*
   american fuzzy lop++ - LLVM CmpLog instrumentation
   --------------------------------------------------

   Written by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

*/

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
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/ValueTracking.h"

#if LLVM_VERSION_MAJOR > 3 || \
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

class CmpLogRoutines : public ModulePass {

 public:
  static char ID;
  CmpLogRoutines() : ModulePass(ID) {

    initInstrumentList();

  }

  bool runOnModule(Module &M) override;

#if LLVM_VERSION_MAJOR < 4
  const char *getPassName() const override {

#else
  StringRef getPassName() const override {

#endif
    return "cmplog routines";

  }

 private:
  bool hookRtns(Module &M);

};

}  // namespace

char CmpLogRoutines::ID = 0;

bool CmpLogRoutines::hookRtns(Module &M) {

  std::vector<CallInst *> calls;
  LLVMContext &           C = M.getContext();

  Type *VoidTy = Type::getVoidTy(C);
  // PointerType *VoidPtrTy = PointerType::get(VoidTy, 0);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  PointerType *i8PtrTy = PointerType::get(Int8Ty, 0);

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c = M.getOrInsertFunction("__cmplog_rtn_hook", VoidTy, i8PtrTy, i8PtrTy
#if LLVM_VERSION_MAJOR < 5
                                ,
                                NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogHookFn = cast<Function>(c);
#else
  FunctionCallee cmplogHookFn = c;
#endif

  /* iterate over all functions, bbs and instruction and add suitable calls */
  for (auto &F : M) {

    if (!isInInstrumentList(&F)) continue;

    for (auto &BB : F) {

      for (auto &IN : BB) {

        CallInst *callInst = nullptr;

        if ((callInst = dyn_cast<CallInst>(&IN))) {

          Function *Callee = callInst->getCalledFunction();
          if (!Callee) continue;
          if (callInst->getCallingConv() != llvm::CallingConv::C) continue;

          FunctionType *FT = Callee->getFunctionType();

          bool isPtrRtn = FT->getNumParams() >= 2 &&
                          !FT->getReturnType()->isVoidTy() &&
                          FT->getParamType(0) == FT->getParamType(1) &&
                          FT->getParamType(0)->isPointerTy();

          if (!isPtrRtn) continue;

          calls.push_back(callInst);

        }

      }

    }

  }

  if (!calls.size()) return false;
  /*
    if (!be_quiet)
      errs() << "Hooking " << calls.size()
             << " calls with pointers as arguments\n";
  */

  for (auto &callInst : calls) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB(callInst->getParent());
    IRB.SetInsertPoint(callInst);

    std::vector<Value *> args;
    Value *              v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value *              v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);

    IRB.CreateCall(cmplogHookFn, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";

  }

  return true;

}

bool CmpLogRoutines::runOnModule(Module &M) {

  if (getenv("AFL_QUIET") == NULL)
    printf("Running cmplog-routines-pass by andreafioraldi@gmail.com\n");
  else
    be_quiet = 1;
  hookRtns(M);
  verifyModule(M);

  return true;

}

static void registerCmpLogRoutinesPass(const PassManagerBuilder &,
                                       legacy::PassManagerBase &PM) {

  auto p = new CmpLogRoutines();
  PM.add(p);

}

static RegisterStandardPasses RegisterCmpLogRoutinesPass(
    PassManagerBuilder::EP_OptimizerLast, registerCmpLogRoutinesPass);

static RegisterStandardPasses RegisterCmpLogRoutinesPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerCmpLogRoutinesPass);

#if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterCmpLogRoutinesPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    registerCmpLogRoutinesPass);
#endif

