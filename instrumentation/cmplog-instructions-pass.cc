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

#include <iostream>
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

class CmpLogInstructions : public ModulePass {

 public:
  static char ID;
  CmpLogInstructions() : ModulePass(ID) {

    initInstrumentList();

  }

  bool runOnModule(Module &M) override;

#if LLVM_VERSION_MAJOR < 4
  const char *getPassName() const override {

#else
  StringRef getPassName() const override {

#endif
    return "cmplog instructions";

  }

 private:
  bool hookInstrs(Module &M);

};

}  // namespace

char CmpLogInstructions::ID = 0;

template <class Iterator>
Iterator Unique(Iterator first, Iterator last) {

  while (first != last) {

    Iterator next(first);
    last = std::remove(++next, last, *first);
    first = next;

  }

  return last;

}

bool CmpLogInstructions::hookInstrs(Module &M) {

  std::vector<Instruction *> icomps;
  LLVMContext &              C = M.getContext();

  Type *       VoidTy = Type::getVoidTy(C);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
  IntegerType *Int128Ty = IntegerType::getInt128Ty(C);

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c1 = M.getOrInsertFunction("__cmplog_ins_hook1", VoidTy, Int8Ty, Int8Ty,
                                 Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogHookIns1 = cast<Function>(c1);
#else
  FunctionCallee cmplogHookIns1 = c1;
#endif

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c2 = M.getOrInsertFunction("__cmplog_ins_hook2", VoidTy, Int16Ty, Int16Ty,
                                 Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogHookIns2 = cast<Function>(c2);
#else
  FunctionCallee cmplogHookIns2 = c2;
#endif

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c4 = M.getOrInsertFunction("__cmplog_ins_hook4", VoidTy, Int32Ty, Int32Ty,
                                 Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogHookIns4 = cast<Function>(c4);
#else
  FunctionCallee cmplogHookIns4 = c4;
#endif

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c8 = M.getOrInsertFunction("__cmplog_ins_hook8", VoidTy, Int64Ty, Int64Ty,
                                 Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogHookIns8 = cast<Function>(c8);
#else
  FunctionCallee cmplogHookIns8 = c8;
#endif

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c16 = M.getOrInsertFunction("__cmplog_ins_hook16", VoidTy, Int128Ty,
                                  Int128Ty, Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                  ,
                                  NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogHookIns16 = cast<Function>(c16);
#else
  FunctionCallee cmplogHookIns16 = c16;
#endif

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      cN = M.getOrInsertFunction("__cmplog_ins_hookN", VoidTy, Int128Ty,
                                 Int128Ty, Int8Ty, Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogHookInsN = cast<Function>(cN);
#else
  FunctionCallee cmplogHookInsN = cN;
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

        CmpInst *selectcmpInst = nullptr;
        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {

          icomps.push_back(selectcmpInst);

        }

      }

    }

  }

  if (icomps.size()) {

    // if (!be_quiet) errs() << "Hooking " << icomps.size() <<
    //                          " cmp instructions\n";

    for (auto &selectcmpInst : icomps) {

      IRBuilder<> IRB2(selectcmpInst->getParent());
      IRB2.SetInsertPoint(selectcmpInst);
      LoadInst *CmpPtr = IRB2.CreateLoad(AFLCmplogPtr);
      CmpPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      auto is_not_null = IRB2.CreateICmpNE(CmpPtr, Null);
      auto ThenTerm =
          SplitBlockAndInsertIfThen(is_not_null, selectcmpInst, false);

      IRBuilder<> IRB(ThenTerm);

      Value *op0 = selectcmpInst->getOperand(0);
      Value *op1 = selectcmpInst->getOperand(1);

      IntegerType *        intTyOp0 = NULL;
      IntegerType *        intTyOp1 = NULL;
      unsigned             max_size = 0, cast_size = 0;
      unsigned char        attr = 0;
      std::vector<Value *> args;

      CmpInst *cmpInst = dyn_cast<CmpInst>(selectcmpInst);

      if (!cmpInst) { continue; }

      switch (cmpInst->getPredicate()) {

        case CmpInst::ICMP_NE:
        case CmpInst::FCMP_UNE:
        case CmpInst::FCMP_ONE:
          break;
        case CmpInst::ICMP_EQ:
        case CmpInst::FCMP_UEQ:
        case CmpInst::FCMP_OEQ:
          attr += 1;
          break;
        case CmpInst::ICMP_UGT:
        case CmpInst::ICMP_SGT:
        case CmpInst::FCMP_OGT:
        case CmpInst::FCMP_UGT:
          attr += 2;
          break;
        case CmpInst::ICMP_UGE:
        case CmpInst::ICMP_SGE:
        case CmpInst::FCMP_OGE:
        case CmpInst::FCMP_UGE:
          attr += 3;
          break;
        case CmpInst::ICMP_ULT:
        case CmpInst::ICMP_SLT:
        case CmpInst::FCMP_OLT:
        case CmpInst::FCMP_ULT:
          attr += 4;
          break;
        case CmpInst::ICMP_ULE:
        case CmpInst::ICMP_SLE:
        case CmpInst::FCMP_OLE:
        case CmpInst::FCMP_ULE:
          attr += 5;
          break;
        default:
          break;

      }

      if (selectcmpInst->getOpcode() == Instruction::FCmp) {

        auto ty0 = op0->getType();
        if (ty0->isHalfTy()
#if LLVM_VERSION_MAJOR >= 11
            || ty0->isBFloatTy()
#endif
        )
          max_size = 16;
        else if (ty0->isFloatTy())
          max_size = 32;
        else if (ty0->isDoubleTy())
          max_size = 64;
        else if (ty0->isX86_FP80Ty())
          max_size = 80;
        else if (ty0->isFP128Ty() || ty0->isPPC_FP128Ty())
          max_size = 128;

        attr += 8;

      } else {

        intTyOp0 = dyn_cast<IntegerType>(op0->getType());
        intTyOp1 = dyn_cast<IntegerType>(op1->getType());

        if (intTyOp0 && intTyOp1) {

          max_size = intTyOp0->getBitWidth() > intTyOp1->getBitWidth()
                         ? intTyOp0->getBitWidth()
                         : intTyOp1->getBitWidth();

        }

      }

      if (!max_size || max_size < 16) { continue; }

      if (max_size % 8) { max_size = (((max_size / 8) + 1) * 8); }

      if (max_size > 128) {

        if (!be_quiet) {

          fprintf(stderr,
                  "Cannot handle this compare bit size: %u (truncating)\n",
                  max_size);

        }

        max_size = 128;

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

      }

      // errs() << "[CMPLOG] cmp  " << *cmpInst << "(in function " <<
      // cmpInst->getFunction()->getName() << ")\n";

      // first bitcast to integer type of the same bitsize as the original
      // type (this is a nop, if already integer)
      Value *op0_i = IRB.CreateBitCast(
          op0, IntegerType::get(C, op0->getType()->getPrimitiveSizeInBits()));
      // then create a int cast, which does zext, trunc or bitcast. In our case
      // usually zext to the next larger supported type (this is a nop if
      // already the right type)
      Value *V0 =
          IRB.CreateIntCast(op0_i, IntegerType::get(C, cast_size), false);
      args.push_back(V0);
      Value *op1_i = IRB.CreateBitCast(
          op1, IntegerType::get(C, op1->getType()->getPrimitiveSizeInBits()));
      Value *V1 =
          IRB.CreateIntCast(op1_i, IntegerType::get(C, cast_size), false);
      args.push_back(V1);

      // errs() << "[CMPLOG] casted parameters:\n0: " << *V0 << "\n1: " << *V1
      // << "\n";

      ConstantInt *attribute = ConstantInt::get(Int8Ty, attr);
      args.push_back(attribute);

      if (cast_size != max_size) {

        ConstantInt *bitsize = ConstantInt::get(Int8Ty, (max_size / 8) - 1);
        args.push_back(bitsize);

      }

      // fprintf(stderr, "_ExtInt(%u) castTo %u with attr %u didcast %u\n",
      //         max_size, cast_size, attr);

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
          if (max_size == 128) {

            IRB.CreateCall(cmplogHookIns16, args);

          } else {

            IRB.CreateCall(cmplogHookInsN, args);

          }

          break;

      }

    }

  }

  if (icomps.size())
    return true;
  else
    return false;

}

bool CmpLogInstructions::runOnModule(Module &M) {

  if (getenv("AFL_QUIET") == NULL)
    printf("Running cmplog-instructions-pass by andreafioraldi@gmail.com\n");
  else
    be_quiet = 1;
  hookInstrs(M);
  verifyModule(M);

  return true;

}

static void registerCmpLogInstructionsPass(const PassManagerBuilder &,
                                           legacy::PassManagerBase &PM) {

  auto p = new CmpLogInstructions();
  PM.add(p);

}

static RegisterStandardPasses RegisterCmpLogInstructionsPass(
    PassManagerBuilder::EP_OptimizerLast, registerCmpLogInstructionsPass);

static RegisterStandardPasses RegisterCmpLogInstructionsPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerCmpLogInstructionsPass);

#if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterCmpLogInstructionsPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    registerCmpLogInstructionsPass);
#endif

