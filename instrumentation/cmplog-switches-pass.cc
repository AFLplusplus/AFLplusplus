/*
   american fuzzy lop++ - LLVM CmpLog instrumentation
   --------------------------------------------------

   Written by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include <iostream>
#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>

#include "llvm/Config/llvm-config.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#if defined(__has_include) && __has_include("llvm/Plugins/PassPlugin.h")
  #include "llvm/Plugins/PassPlugin.h"
#else
  #include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"
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
#include "llvm/IR/Verifier.h"
#include "llvm/IR/DebugInfo.h"

#include <set>
#include "afl-llvm-common.h"
#include "cmplog.h"

using namespace llvm;

namespace {

class CmplogSwitches : public PassInfoMixin<CmplogSwitches> {

 public:
  explicit CmplogSwitches(CompareObserverMode mode) : mode_(mode) {

    initInstrumentList();

  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

 private:
  CompareObserverMode mode_;
  bool                hookInstrs(Module &M);

};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {

      LLVM_PLUGIN_API_VERSION, "cmplogswitches", "v0.1",
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

          MPM.addPass(CmplogSwitches(getCompareObserverModeFromEnv()));

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

bool CmplogSwitches::hookInstrs(Module &M) {

  std::vector<SwitchInst *> switches;
  LLVMContext              &C = M.getContext();
  bool                      vp_mode = isValueProfileMode(mode_);

  Type        *VoidTy = Type::getVoidTy(C);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

#if LLVM_MAJOR >= 20
  Type *PtrTy = PointerType::getUnqual(C);
#else
  Type *PtrTy = PointerType::get(Int8Ty, 0);
#endif

  FunctionCallee hookIns1 = nullptr;
  FunctionCallee hookIns2 = nullptr;
  FunctionCallee hookIns4 = nullptr;
  FunctionCallee hookIns8 = nullptr;
  FunctionCallee hookSwitch = nullptr;

#if INTPTR_MAX != INT32_MAX
  IntegerType   *Int128Ty = IntegerType::getInt128Ty(C);
  FunctionCallee hookIns16 = nullptr;
  FunctionCallee hookInsN = nullptr;
#endif

  if (vp_mode) {

    hookIns1 = M.getOrInsertFunction("__valueprofile_hook1", VoidTy, Int8Ty,
                                     Int8Ty, Int8Ty, Int64Ty);

    hookIns2 = M.getOrInsertFunction("__valueprofile_hook2", VoidTy, Int16Ty,
                                     Int16Ty, Int8Ty, Int64Ty);

    hookIns4 = M.getOrInsertFunction("__valueprofile_hook4", VoidTy, Int32Ty,
                                     Int32Ty, Int8Ty, Int64Ty);

    hookIns8 = M.getOrInsertFunction("__valueprofile_hook8", VoidTy, Int64Ty,
                                     Int64Ty, Int8Ty, Int64Ty);
    hookSwitch = M.getOrInsertFunction("__valueprofile_switch", VoidTy, Int64Ty,
                                       PtrTy, Int64Ty);

#if INTPTR_MAX != INT32_MAX
    hookIns16 = M.getOrInsertFunction("__valueprofile_hook16", VoidTy, Int128Ty,
                                      Int128Ty, Int8Ty, Int64Ty);
    hookInsN = M.getOrInsertFunction("__valueprofile_hookN", VoidTy, Int128Ty,
                                     Int128Ty, Int8Ty, Int8Ty, Int64Ty);
#endif

  } else {

    hookIns1 = M.getOrInsertFunction("__cmplog_ins_hook1", VoidTy, Int8Ty,
                                     Int8Ty, Int8Ty);

    hookIns2 = M.getOrInsertFunction("__cmplog_ins_hook2", VoidTy, Int16Ty,
                                     Int16Ty, Int8Ty);

    hookIns4 = M.getOrInsertFunction("__cmplog_ins_hook4", VoidTy, Int32Ty,
                                     Int32Ty, Int8Ty);

    hookIns8 = M.getOrInsertFunction("__cmplog_ins_hook8", VoidTy, Int64Ty,
                                     Int64Ty, Int8Ty);

#if INTPTR_MAX != INT32_MAX
    hookIns16 = M.getOrInsertFunction("__cmplog_ins_hook16", VoidTy, Int128Ty,
                                      Int128Ty, Int8Ty);
    hookInsN = M.getOrInsertFunction("__cmplog_ins_hookN", VoidTy, Int128Ty,
                                     Int128Ty, Int8Ty, Int8Ty);
#endif

  }

  GlobalVariable *AFLCmplogPtr =
      getOrCreateExternalWeakPtrGlobal(M, PtrTy, "__afl_cmp_map");

  GlobalVariable *AFLVpEnabledPtr = nullptr;
  if (vp_mode) {

    AFLVpEnabledPtr =
        getOrCreateExternalPtrGlobal(M, PtrTy, "__afl_vp_enabled_ptr");

  }

  /* iterate over all functions, bbs and instruction and add suitable calls */
  for (auto &F : M) {

    if (!isInInstrumentList(&F, MNAME)) continue;

    for (auto &BB : F) {

      SwitchInst *switchInst = nullptr;
      if ((switchInst = dyn_cast<SwitchInst>(BB.getTerminator()))) {

        if (switchInst->getMetadata("afl.skip")) continue;
        if (switchInst->getNumCases() > 1) { switches.push_back(switchInst); }

      }

    }

  }

  // unique the collected switches
  switches.erase(Unique(switches.begin(), switches.end()), switches.end());

  // Instrument switch values for cmplog
  if (switches.size()) {

    constexpr uint64_t                   kVpSwitchSiteSalt = 0x53565350ULL;
    DenseMap<const Function *, uint64_t> vp_site_fallback_ordinal;
    DenseMap<const Function *, DenseMap<uint64_t, uint64_t>>
        vp_site_debug_disambiguator;

    if (!be_quiet)
      errs() << "Hooking " << switches.size() << " switch instructions\n";

    auto getHookInsertPoint = [&](Instruction *InsertBefore) -> Instruction * {

      if (vp_mode) {

        IRBuilder<> IRB2(InsertBefore->getParent());
        IRB2.SetInsertPoint(InsertBefore);
        Value *is_enabled = createValueProfileEnabledGuard(
            IRB2, AFLVpEnabledPtr, PtrTy, Int8Ty);

        Instruction *ThenTerm = SplitBlockAndInsertIfThen(
            is_enabled, InsertBefore, false,
            createValueProfileGuardWeights(M.getContext()));
        markAflSyntheticBlock(ThenTerm->getParent());
        return ThenTerm;

      }

      IRBuilder<> IRB2(InsertBefore->getParent());
      IRB2.SetInsertPoint(InsertBefore);
      Value *is_not_null =
          createMapPtrNotNullGuard(IRB2, M, AFLCmplogPtr, PtrTy);

      return SplitBlockAndInsertIfThen(is_not_null, InsertBefore, false);

    };

    for (auto &SI : switches) {

      Value        *Val = SI->getCondition();
      unsigned int  orig_size = Val->getType()->getIntegerBitWidth();
      unsigned int  max_size = orig_size, cast_size;
      unsigned char do_cast = 0;
      uint64_t      site_disambiguator = 0;
      uint64_t      case_index = 0;

      if (!SI->getNumCases() || max_size < 13) {

        // if (!be_quiet) errs() << "skip trivial switch..\n";
        continue;

      }

      if (max_size % 8) {

        max_size = (((max_size / 8) + 1) * 8);
        do_cast = 1;

      }

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

      if (vp_mode) {

        if (SI->getDebugLoc()) {

          uint64_t debug_site_key = getValueProfileDebugSiteKey(*SI);
          site_disambiguator =
              vp_site_debug_disambiguator[SI->getFunction()][debug_site_key]++;

        } else {

          site_disambiguator = vp_site_fallback_ordinal[SI->getFunction()]++;

        }

      }

      if (vp_mode && orig_size <= 64) {

        IRBuilder<> IRB(getHookInsertPoint(SI));
        Value      *SwitchVal64 = Val;
        if (orig_size < 64) {

          SwitchVal64 = IRB.CreateZExt(Val, Int64Ty, "afl.vp.sw64");

        }

        std::vector<uint64_t> case_values;
        case_values.reserve(SI->getNumCases() + 2);
        case_values.push_back(SI->getNumCases());
        case_values.push_back(orig_size);

        for (SwitchInst::CaseIt i = SI->case_begin(), e = SI->case_end();
             i != e; ++i) {

          ConstantInt *cint = i->getCaseValue();
          if (!cint) continue;
          case_values.push_back(
              cint->getValue().zextOrTrunc(64).getZExtValue());

        }

        ArrayType *CasesTy =
            ArrayType::get(Int64Ty, (unsigned)case_values.size());
        std::vector<Constant *> case_consts;
        case_consts.reserve(case_values.size());
        for (uint64_t case_value : case_values) {

          case_consts.push_back(ConstantInt::get(Int64Ty, case_value));

        }

        auto *CasesGV = new GlobalVariable(
            M, CasesTy, true, GlobalValue::PrivateLinkage,
            ConstantArray::get(CasesTy, case_consts), "__afl_vp_switch_cases");
        CasesGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        CasesGV->setAlignment(Align(8));

        uint64_t site_token = computeValueProfileSiteToken(
            *SI, kVpSwitchSiteSalt, site_disambiguator, 0);
        Value *CasesPtr = IRB.CreatePointerCast(CasesGV, PtrTy);
        IRB.CreateCall(hookSwitch, {SwitchVal64, CasesPtr,
                                    ConstantInt::get(Int64Ty, site_token)});
        continue;

      }

      IRBuilder<> IRB(getHookInsertPoint(SI));

      Value *CompareTo = Val;

      if (do_cast) {

        CompareTo =
            IRB.CreateIntCast(CompareTo, IntegerType::get(C, cast_size), false);

      }

      for (SwitchInst::CaseIt i = SI->case_begin(), e = SI->case_end(); i != e;
           ++i) {

        ConstantInt *cint = i->getCaseValue();

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
            ConstantInt *attribute = ConstantInt::get(Int8Ty, CMP_ATTR_ICMP_EQ);
            args.push_back(attribute);
            if (cast_size != max_size) {

              ConstantInt *bitsize =
                  ConstantInt::get(Int8Ty, (max_size / 8) - 1);
              args.push_back(bitsize);

            }

            if (vp_mode) {

              args.push_back(ConstantInt::get(
                  Int64Ty, computeValueProfileSiteToken(*SI, kVpSwitchSiteSalt,
                                                        site_disambiguator,
                                                        case_index++)));

            }

            switch (cast_size) {

              case 8:
                IRB.CreateCall(hookIns1, args);
                break;
              case 16:
                IRB.CreateCall(hookIns2, args);
                break;
              case 32:
                IRB.CreateCall(hookIns4, args);
                break;
              case 64:
                IRB.CreateCall(hookIns8, args);
                break;
              case 128:
#if INTPTR_MAX != INT32_MAX
                if (max_size == 128) {

                  IRB.CreateCall(hookIns16, args);

                } else {

                  IRB.CreateCall(hookInsN, args);

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

PreservedAnalyses CmplogSwitches::run(Module &M, ModuleAnalysisManager &MAM) {

  bool vp_mode = isValueProfileMode(mode_);

  if (vp_mode) { markInstrumentedMarker(M, "__afl_vp_instrumented"); }

  if (getenv("AFL_QUIET") != NULL) {

    be_quiet = 1;

  } else if (vp_mode) {

    printf("Running valueprofile-switches-pass by AFL++ team\n");

  } else {

    printf("Running cmplog-switches-pass by andreafioraldi@gmail.com\n");

  }

  bool ret = hookInstrs(M);

  verifyModule(M);
  if (ret || vp_mode) { return PreservedAnalyses::none(); }
  return PreservedAnalyses::all();

}

