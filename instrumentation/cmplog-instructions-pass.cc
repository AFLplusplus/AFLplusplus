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
#include <cstdint>
#include <iostream>
#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>

#include "llvm/Config/llvm-config.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Passes/OptimizationLevel.h"

#include "llvm/IR/Verifier.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Support/raw_ostream.h"

#include <set>
#include "afl-llvm-common.h"

using namespace llvm;

namespace {

using DomTreeCallback = function_ref<const DominatorTree *(Function &F)>;

class CmpLogInstructions : public PassInfoMixin<CmpLogInstructions> {

 public:
  CmpLogInstructions() {

    initInstrumentList();

  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

 private:
  bool hookInstrs(Module &M, DomTreeCallback DTCallback);

};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "cmploginstructions", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

#if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
            PB.registerOptimizerLastEPCallback([](ModulePassManager &MPM,
                                                  OptimizationLevel  OL
#if LLVM_VERSION_MAJOR >= 20
                                                  ,
                                                  ThinOrFullLTOPhase Phase
#endif
                                               ) {

              MPM.addPass(CmpLogInstructions());

            });

          }};

}

template <class Iterator>
Iterator Unique(Iterator first, Iterator last) {

  while (first != last) {

    Iterator next(first);
    last = std::remove(++next, last, *first);
    first = next;

  }

  return last;

}

bool IsBackEdge(BasicBlock *From, BasicBlock *To, const DominatorTree *DT) {

  if (DT->dominates(To, From)) return true;
  if (auto Next = To->getUniqueSuccessor())
    if (DT->dominates(Next, From)) return true;
  return false;

}

bool CmpLogInstructions::hookInstrs(Module &M, DomTreeCallback DTCallback) {

  std::vector<Instruction *> icomps;
  LLVMContext               &C = M.getContext();

  Type        *VoidTy = Type::getVoidTy(C);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
  IntegerType *Int128Ty = IntegerType::getInt128Ty(C);

#if LLVM_MAJOR >= 20
  Type *PtrTy = PointerType::getUnqual(C);
#else
  Type *PtrTy = PointerType::get(Int8Ty, 0);
#endif

  /*
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
  */

  FunctionCallee c2 = M.getOrInsertFunction("__cmplog_ins_hook2", VoidTy,
                                            Int16Ty, Int16Ty, Int8Ty);
  FunctionCallee cmplogHookIns2 = c2;

  FunctionCallee c4 = M.getOrInsertFunction("__cmplog_ins_hook4", VoidTy,
                                            Int32Ty, Int32Ty, Int8Ty);
  FunctionCallee cmplogHookIns4 = c4;

  FunctionCallee c8 = M.getOrInsertFunction("__cmplog_ins_hook8", VoidTy,
                                            Int64Ty, Int64Ty, Int8Ty);
  FunctionCallee cmplogHookIns8 = c8;

  FunctionCallee c16 = M.getOrInsertFunction("__cmplog_ins_hook16", VoidTy,
                                             Int128Ty, Int128Ty, Int8Ty);
  FunctionCallee cmplogHookIns16 = c16;

  FunctionCallee cN = M.getOrInsertFunction("__cmplog_ins_hookN", VoidTy,
                                            Int128Ty, Int128Ty, Int8Ty, Int8Ty);
  FunctionCallee cmplogHookInsN = cN;

  GlobalVariable *AFLCmplogPtr = M.getNamedGlobal("__afl_cmp_map");

  if (!AFLCmplogPtr) {

    AFLCmplogPtr = new GlobalVariable(
        M, PtrTy, false, GlobalValue::ExternalWeakLinkage, 0, "__afl_cmp_map");

  }

  Constant *Null = Constant::getNullValue(PtrTy);

  /* iterate over all functions, bbs and instruction and add suitable calls */
  for (auto &F : M) {

    if (!isInInstrumentList(&F, MNAME)) continue;
    const DominatorTree *DT = DTCallback(F);

    for (auto &BB : F) {

      for (auto &IN : BB) {

        CmpInst *selectcmpInst = nullptr;
        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {

          // skip loop comparisons
          if (selectcmpInst->hasOneUse())
            if (auto BR = dyn_cast<BranchInst>(selectcmpInst->user_back()))
              for (BasicBlock *B : BR->successors())
                if (IsBackEdge(BR->getParent(), B, DT)) continue;

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
      LoadInst *CmpPtr = IRB2.CreateLoad(PtrTy, AFLCmplogPtr);
      CmpPtr->setMetadata(M.getMDKindID("nosanitize"),
#if LLVM_MAJOR >= 20
                          MDNode::get(C, {}));
#else
                          MDNode::get(C, None));
#endif
      auto is_not_null = IRB2.CreateICmpNE(CmpPtr, Null);
      auto ThenTerm =
          SplitBlockAndInsertIfThen(is_not_null, selectcmpInst, false);

      IRBuilder<> IRB(ThenTerm);

      Value *op0 = selectcmpInst->getOperand(0);
      Value *op1 = selectcmpInst->getOperand(1);
      Value *op0_saved = op0, *op1_saved = op1;
      auto   ty0 = op0->getType();
      auto   ty1 = op1->getType();

      IntegerType *intTyOp0 = NULL;
      IntegerType *intTyOp1 = NULL;
      unsigned     max_size = 0, cast_size = 0;
      unsigned     attr = 0, vector_cnt = 0, is_fp = 0;
      CmpInst     *cmpInst = dyn_cast<CmpInst>(selectcmpInst);

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

        if (ty0->isVectorTy()) {

          VectorType *tt = dyn_cast<VectorType>(ty0);
          if (!tt) {

            fprintf(stderr, "Warning: cmplog cmp vector is not a vector!\n");
            continue;

          }

          vector_cnt = tt->getElementCount().getKnownMinValue();
          ty0 = tt->getElementType();

        }

        if (ty0->isHalfTy() || ty0->isBFloatTy())
          max_size = 16;
        else if (ty0->isFloatTy())
          max_size = 32;
        else if (ty0->isDoubleTy())
          max_size = 64;
        else if (ty0->isX86_FP80Ty())
          max_size = 80;
        else if (ty0->isFP128Ty() || ty0->isPPC_FP128Ty())
          max_size = 128;
        else if (ty0->getTypeID() != llvm::Type::PointerTyID && !be_quiet)
          fprintf(stderr, "Warning: unsupported cmp type for cmplog: %u!\n",
                  ty0->getTypeID());

        attr += 8;
        is_fp = 1;
        // fprintf(stderr, "HAVE FP %u!\n", vector_cnt);

      } else {

        if (ty0->isVectorTy()) {

          VectorType *tt = dyn_cast<VectorType>(ty0);
          if (!tt) {

            fprintf(stderr, "Warning: cmplog cmp vector is not a vector!\n");
            continue;

          }

          vector_cnt = tt->getElementCount().getKnownMinValue();
          ty1 = ty0 = tt->getElementType();

        }

        intTyOp0 = dyn_cast<IntegerType>(ty0);
        intTyOp1 = dyn_cast<IntegerType>(ty1);

        if (intTyOp0 && intTyOp1) {

          max_size = intTyOp0->getBitWidth() > intTyOp1->getBitWidth()
                         ? intTyOp0->getBitWidth()
                         : intTyOp1->getBitWidth();

        } else {

          if (ty0->getTypeID() != llvm::Type::PointerTyID && !be_quiet) {

            fprintf(stderr, "Warning: unsupported cmp type for cmplog: %u\n",
                    ty0->getTypeID());

          }

        }

      }

      if (!max_size || max_size < 16) {

        // fprintf(stderr, "too small\n");
        continue;

      }

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

        case 16:
          cast_size = 16;
          break;
        case 17 ... 32:
          cast_size = 32;
          break;
        case 33 ... 64:
          cast_size = 64;
          break;
        default:
          cast_size = 128;

      }

      // XXX FIXME BUG TODO
      if (is_fp && vector_cnt) { continue; }

      uint64_t cur = 0, last_val0 = 0, last_val1 = 0, cur_val;

      while (1) {

        std::vector<Value *> args;
        bool                 skip = false;

        if (vector_cnt) {

          op0 = IRB.CreateExtractElement(op0_saved, cur);
          op1 = IRB.CreateExtractElement(op1_saved, cur);
          /*
          std::string errMsg;
          raw_string_ostream os(errMsg);
          op0_saved->print(os);
          fprintf(stderr, "X: %s\n", os.str().c_str());
          */
          if (is_fp) {

            /*
                        ConstantFP *i0 = dyn_cast<ConstantFP>(op0);
                        ConstantFP *i1 = dyn_cast<ConstantFP>(op1);
                        // BUG FIXME TODO: this is null ... but why?
                        // fprintf(stderr, "%p %p\n", i0, i1);
                        if (i0) {

                          cur_val = (uint64_t)i0->getValue().convertToDouble();
                          if (last_val0 && last_val0 == cur_val) { skip = true;

               } last_val0 = cur_val;

                        }

                        if (i1) {

                          cur_val = (uint64_t)i1->getValue().convertToDouble();
                          if (last_val1 && last_val1 == cur_val) { skip = true;

               } last_val1 = cur_val;

                        }

            */

          } else {

            ConstantInt *i0 = dyn_cast<ConstantInt>(op0);
            ConstantInt *i1 = dyn_cast<ConstantInt>(op1);
            if (i0 && i0->uge(0xffffffffffffffff) == false) {

              cur_val = i0->getZExtValue();
              if (last_val0 && last_val0 == cur_val) { skip = true; }
              last_val0 = cur_val;

            }

            if (i1 && i1->uge(0xffffffffffffffff) == false) {

              cur_val = i1->getZExtValue();
              if (last_val1 && last_val1 == cur_val) { skip = true; }
              last_val1 = cur_val;

            }

          }

        }

        if (!skip) {

          // errs() << "[CMPLOG] cmp  " << *cmpInst << "(in function " <<
          // cmpInst->getFunction()->getName() << ")\n";

          // first bitcast to integer type of the same bitsize as the original
          // type (this is a nop, if already integer)
          Value *op0_i = IRB.CreateBitCast(
              op0, IntegerType::get(C, ty0->getPrimitiveSizeInBits()));
          // then create a int cast, which does zext, trunc or bitcast. In our
          // case usually zext to the next larger supported type (this is a nop
          // if already the right type)
          Value *V0 =
              IRB.CreateIntCast(op0_i, IntegerType::get(C, cast_size), false);
          args.push_back(V0);
          Value *op1_i = IRB.CreateBitCast(
              op1, IntegerType::get(C, ty1->getPrimitiveSizeInBits()));
          Value *V1 =
              IRB.CreateIntCast(op1_i, IntegerType::get(C, cast_size), false);
          args.push_back(V1);

          // errs() << "[CMPLOG] casted parameters:\n0: " << *V0 << "\n1: " <<
          // *V1
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
              // IRB.CreateCall(cmplogHookIns1, args);
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

        /* else fprintf(stderr, "skipped\n"); */

        ++cur;
        if (cur >= vector_cnt) { break; }

      }

    }

  }

  if (icomps.size())
    return true;
  else
    return false;

}

PreservedAnalyses CmpLogInstructions::run(Module                &M,
                                          ModuleAnalysisManager &MAM) {

  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  auto  DTCallback = [&FAM](Function &F) -> const DominatorTree  *{

    return &FAM.getResult<DominatorTreeAnalysis>(F);

  };

  if (getenv("AFL_QUIET") == NULL)
    printf("Running cmplog-instructions-pass by andreafioraldi@gmail.com\n");
  else
    be_quiet = 1;

  bool ret = hookInstrs(M, DTCallback);
  verifyModule(M);

  if (ret == false)
    return PreservedAnalyses::all();
  else
    return PreservedAnalyses();

}

