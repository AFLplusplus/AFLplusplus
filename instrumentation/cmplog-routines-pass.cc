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

  std::vector<CallInst *> calls, llvmStdStd, llvmStdC, gccStdStd, gccStdC;
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

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c1 = M.getOrInsertFunction("__cmplog_rtn_llvm_stdstring_stdstring",
                                 VoidTy, i8PtrTy, i8PtrTy
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogLlvmStdStd = cast<Function>(c1);
#else
  FunctionCallee cmplogLlvmStdStd = c1;
#endif

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c2 = M.getOrInsertFunction("__cmplog_rtn_llvm_stdstring_cstring", VoidTy,
                                 i8PtrTy, i8PtrTy
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogLlvmStdC = cast<Function>(c2);
#else
  FunctionCallee cmplogLlvmStdC = c2;
#endif

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c3 = M.getOrInsertFunction("__cmplog_rtn_gcc_stdstring_stdstring", VoidTy,
                                 i8PtrTy, i8PtrTy
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogGccStdStd = cast<Function>(c3);
#else
  FunctionCallee cmplogGccStdStd = c3;
#endif

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c4 = M.getOrInsertFunction("__cmplog_rtn_gcc_stdstring_cstring", VoidTy,
                                 i8PtrTy, i8PtrTy
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogGccStdC = cast<Function>(c4);
#else
  FunctionCallee cmplogGccStdC = c4;
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

          bool isGccStdStringStdString =
              Callee->getName().find("__is_charIT_EE7__value") !=
                  std::string::npos &&
              Callee->getName().find(
                  "St7__cxx1112basic_stringIS2_St11char_traits") !=
                  std::string::npos &&
              FT->getNumParams() >= 2 &&
              FT->getParamType(0) == FT->getParamType(1) &&
              FT->getParamType(0)->isPointerTy();

          bool isGccStdStringCString =
              Callee->getName().find(
                  "St7__cxx1112basic_stringIcSt11char_"
                  "traitsIcESaIcEE7compareEPK") != std::string::npos &&
              FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
              FT->getParamType(1)->isPointerTy();

          bool isLlvmStdStringStdString =
              Callee->getName().find("_ZNSt3__1eqI") != std::string::npos &&
              Callee->getName().find("_12basic_stringI") != std::string::npos &&
              Callee->getName().find("_11char_traits") != std::string::npos &&
              FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
              FT->getParamType(1)->isPointerTy();

          bool isLlvmStdStringCString =
              Callee->getName().find("_ZNSt3__1eqI") != std::string::npos &&
              Callee->getName().find("_12basic_stringI") != std::string::npos &&
              FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
              FT->getParamType(1)->isPointerTy();

          /*
                    {

                       fprintf(stderr, "F:%s C:%s argc:%u\n",
                       F.getName().str().c_str(),
             Callee->getName().str().c_str(), FT->getNumParams());
                       fprintf(stderr, "ptr0:%u ptr1:%u ptr2:%u\n",
                              FT->getParamType(0)->isPointerTy(),
                              FT->getParamType(1)->isPointerTy(),
                              FT->getNumParams() > 2 ?
             FT->getParamType(2)->isPointerTy() : 22 );

                    }

          */

          if (isGccStdStringCString || isGccStdStringStdString ||
              isLlvmStdStringStdString || isLlvmStdStringCString) {

            isPtrRtn = false;

          }

          if (isPtrRtn) { calls.push_back(callInst); }
          if (isGccStdStringStdString) { gccStdStd.push_back(callInst); }
          if (isGccStdStringCString) { gccStdC.push_back(callInst); }
          if (isLlvmStdStringStdString) { llvmStdStd.push_back(callInst); }
          if (isLlvmStdStringCString) { llvmStdC.push_back(callInst); }

        }

      }

    }

  }

  if (!calls.size() && !gccStdStd.size() && !gccStdC.size() &&
      !llvmStdStd.size() && !llvmStdC.size())
    return false;

  /*
    if (!be_quiet)
      errs() << "Hooking " << calls.size()
             << " calls with pointers as arguments\n";
  */

  for (auto &callInst : calls) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB2(callInst->getParent());
    IRB2.SetInsertPoint(callInst);

    LoadInst *CmpPtr = IRB2.CreateLoad(AFLCmplogPtr);
    CmpPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
    auto is_not_null = IRB2.CreateICmpNE(CmpPtr, Null);
    auto ThenTerm = SplitBlockAndInsertIfThen(is_not_null, callInst, false);

    IRBuilder<> IRB(ThenTerm);

    std::vector<Value *> args;
    Value *              v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value *              v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);

    IRB.CreateCall(cmplogHookFn, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";

  }

  for (auto &callInst : gccStdStd) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB2(callInst->getParent());
    IRB2.SetInsertPoint(callInst);

    LoadInst *CmpPtr = IRB2.CreateLoad(AFLCmplogPtr);
    CmpPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
    auto is_not_null = IRB2.CreateICmpNE(CmpPtr, Null);
    auto ThenTerm = SplitBlockAndInsertIfThen(is_not_null, callInst, false);

    IRBuilder<> IRB(ThenTerm);

    std::vector<Value *> args;
    Value *              v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value *              v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);

    IRB.CreateCall(cmplogGccStdStd, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";

  }

  for (auto &callInst : gccStdC) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB2(callInst->getParent());
    IRB2.SetInsertPoint(callInst);

    LoadInst *CmpPtr = IRB2.CreateLoad(AFLCmplogPtr);
    CmpPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
    auto is_not_null = IRB2.CreateICmpNE(CmpPtr, Null);
    auto ThenTerm = SplitBlockAndInsertIfThen(is_not_null, callInst, false);

    IRBuilder<> IRB(ThenTerm);

    std::vector<Value *> args;
    Value *              v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value *              v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);

    IRB.CreateCall(cmplogGccStdC, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";

  }

  for (auto &callInst : llvmStdStd) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB2(callInst->getParent());
    IRB2.SetInsertPoint(callInst);

    LoadInst *CmpPtr = IRB2.CreateLoad(AFLCmplogPtr);
    CmpPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
    auto is_not_null = IRB2.CreateICmpNE(CmpPtr, Null);
    auto ThenTerm = SplitBlockAndInsertIfThen(is_not_null, callInst, false);

    IRBuilder<> IRB(ThenTerm);

    std::vector<Value *> args;
    Value *              v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value *              v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);

    IRB.CreateCall(cmplogLlvmStdStd, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";

  }

  for (auto &callInst : llvmStdC) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB2(callInst->getParent());
    IRB2.SetInsertPoint(callInst);

    LoadInst *CmpPtr = IRB2.CreateLoad(AFLCmplogPtr);
    CmpPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
    auto is_not_null = IRB2.CreateICmpNE(CmpPtr, Null);
    auto ThenTerm = SplitBlockAndInsertIfThen(is_not_null, callInst, false);

    IRBuilder<> IRB(ThenTerm);

    std::vector<Value *> args;
    Value *              v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value *              v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);

    IRB.CreateCall(cmplogLlvmStdC, args);

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

