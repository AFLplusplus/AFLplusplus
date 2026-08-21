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

using namespace llvm;

namespace {

class CmpLogRoutines : public PassInfoMixin<CmpLogRoutines> {

 public:
  explicit CmpLogRoutines(CompareObserverMode mode) : mode_(mode) {

    initInstrumentList();

  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

 private:
  CompareObserverMode mode_;
  bool                hookRtns(Module &M);

};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {

      LLVM_PLUGIN_API_VERSION, "cmplogroutines", "v0.1",
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

          MPM.addPass(CmpLogRoutines(getCompareObserverModeFromEnv()));

        });

      }};

}

bool CmpLogRoutines::hookRtns(Module &M) {

  std::vector<CallInst *> calls, llvmStdStd, llvmStdC, gccStdStd, gccStdC,
      Memcmp, Strcmp, Strncmp, Strcasecmp, Strncasecmp, GStrstrLen, Memmem,
      Strstr, Strcasestr, Strnstr;
  LLVMContext &C = M.getContext();
  bool         vp_mode = isValueProfileMode(mode_);

  Type *VoidTy = Type::getVoidTy(C);
  // PointerType *VoidPtrTy = PointerType::get(VoidTy, 0);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
  PointerType *i8PtrTy = PointerType::get(Int8Ty, 0);

  FunctionCallee hookFn = nullptr;
  FunctionCallee hookLlvmStdStd = nullptr;
  FunctionCallee hookLlvmStdC = nullptr;
  FunctionCallee hookGccStdStd = nullptr;
  FunctionCallee hookGccStdC = nullptr;
  FunctionCallee hookFnN = nullptr;
  FunctionCallee hookFnStrN = nullptr;
  FunctionCallee hookFnStr = nullptr;
  FunctionCallee hookFnStrNCi = nullptr;
  FunctionCallee hookFnStrCi = nullptr;
  FunctionCallee hookFnSub = nullptr;
  FunctionCallee hookFnSubCi = nullptr;
  FunctionCallee hookFnSubN = nullptr;
  FunctionCallee hookFnSubHN = nullptr;

  if (vp_mode) {

    hookFn = M.getOrInsertFunction("__valueprofile_rtn_hook", VoidTy, i8PtrTy,
                                   i8PtrTy, Int64Ty);

    hookLlvmStdStd =
        M.getOrInsertFunction("__valueprofile_rtn_llvm_stdstring_stdstring",
                              VoidTy, i8PtrTy, i8PtrTy, Int64Ty);

    hookLlvmStdC =
        M.getOrInsertFunction("__valueprofile_rtn_llvm_stdstring_cstring",
                              VoidTy, i8PtrTy, i8PtrTy, Int64Ty);

    hookGccStdStd =
        M.getOrInsertFunction("__valueprofile_rtn_gcc_stdstring_stdstring",
                              VoidTy, i8PtrTy, i8PtrTy, Int64Ty);

    hookGccStdC =
        M.getOrInsertFunction("__valueprofile_rtn_gcc_stdstring_cstring",
                              VoidTy, i8PtrTy, i8PtrTy, Int64Ty);

    hookFnN = M.getOrInsertFunction("__valueprofile_rtn_hook_n", VoidTy,
                                    i8PtrTy, i8PtrTy, Int64Ty, Int64Ty);

    hookFnStrN = M.getOrInsertFunction("__valueprofile_rtn_hook_strn", VoidTy,
                                       i8PtrTy, i8PtrTy, Int64Ty, Int64Ty);

    hookFnStr = M.getOrInsertFunction("__valueprofile_rtn_hook_str", VoidTy,
                                      i8PtrTy, i8PtrTy, Int64Ty);

    hookFnStrNCi =
        M.getOrInsertFunction("__valueprofile_rtn_hook_strn_ci", VoidTy,
                              i8PtrTy, i8PtrTy, Int64Ty, Int64Ty);

    hookFnStrCi = M.getOrInsertFunction("__valueprofile_rtn_hook_str_ci",
                                        VoidTy, i8PtrTy, i8PtrTy, Int64Ty);

    hookFnSub = M.getOrInsertFunction("__valueprofile_rtn_hook_sub", VoidTy,
                                      i8PtrTy, i8PtrTy, Int64Ty);

    hookFnSubCi = M.getOrInsertFunction("__valueprofile_rtn_hook_sub_ci",
                                        VoidTy, i8PtrTy, i8PtrTy, Int64Ty);

    hookFnSubN =
        M.getOrInsertFunction("__valueprofile_rtn_hook_sub_n", VoidTy, i8PtrTy,
                              Int64Ty, i8PtrTy, Int64Ty, Int64Ty);

    hookFnSubHN =
        M.getOrInsertFunction("__valueprofile_rtn_hook_sub_hn", VoidTy, i8PtrTy,
                              Int64Ty, i8PtrTy, Int64Ty);

  } else {

    hookFn =
        M.getOrInsertFunction("__cmplog_rtn_hook", VoidTy, i8PtrTy, i8PtrTy);

    hookLlvmStdStd = M.getOrInsertFunction(
        "__cmplog_rtn_llvm_stdstring_stdstring", VoidTy, i8PtrTy, i8PtrTy);

    hookLlvmStdC = M.getOrInsertFunction("__cmplog_rtn_llvm_stdstring_cstring",
                                         VoidTy, i8PtrTy, i8PtrTy);

    hookGccStdStd = M.getOrInsertFunction(
        "__cmplog_rtn_gcc_stdstring_stdstring", VoidTy, i8PtrTy, i8PtrTy);

    hookGccStdC = M.getOrInsertFunction("__cmplog_rtn_gcc_stdstring_cstring",
                                        VoidTy, i8PtrTy, i8PtrTy);

    hookFnN = M.getOrInsertFunction("__cmplog_rtn_hook_n", VoidTy, i8PtrTy,
                                    i8PtrTy, Int64Ty);

    hookFnStrN = M.getOrInsertFunction("__cmplog_rtn_hook_strn", VoidTy,
                                       i8PtrTy, i8PtrTy, Int64Ty);

    hookFnStr = M.getOrInsertFunction("__cmplog_rtn_hook_str", VoidTy, i8PtrTy,
                                      i8PtrTy);

    hookFnStrNCi = hookFnStrN;
    hookFnStrCi = hookFnStr;

  }

  Type           *PtrTy = PointerType::get(Int8Ty, 0);
  GlobalVariable *AFLCmplogPtr =
      getOrCreateExternalWeakPtrGlobal(M, PtrTy, "__afl_cmp_map");

  GlobalVariable *AFLVpEnabledPtr = nullptr;
  if (vp_mode) {

    AFLVpEnabledPtr =
        getOrCreateExternalPtrGlobal(M, PtrTy, "__afl_vp_enabled_ptr");

  }

  auto buildMapGuard = [&](IRBuilder<> &IRB2) -> Value * {

    return createMapPtrNotNullGuard(IRB2, M, AFLCmplogPtr, PtrTy);

  };

  auto getHookInsertPoint = [&](Instruction *InsertBefore) -> Instruction * {

    if (vp_mode) {

      IRBuilder<> IRB2(InsertBefore->getParent());
      IRB2.SetInsertPoint(InsertBefore);
      Value *is_enabled =
          createValueProfileEnabledGuard(IRB2, AFLVpEnabledPtr, PtrTy, Int8Ty);

      Instruction *ThenTerm = SplitBlockAndInsertIfThen(
          is_enabled, InsertBefore, false,
          createValueProfileGuardWeights(M.getContext()));
      markAflSyntheticBlock(ThenTerm->getParent());
      return ThenTerm;

    }

    IRBuilder<> IRB2(InsertBefore->getParent());
    IRB2.SetInsertPoint(InsertBefore);

    return SplitBlockAndInsertIfThen(buildMapGuard(IRB2), InsertBefore, false);

  };

  /* iterate over all functions, bbs and instruction and add suitable calls */
  for (auto &F : M) {

    if (!isInInstrumentList(&F, MNAME)) continue;

    for (auto &BB : F) {

      for (auto &IN : BB) {

        CallInst *callInst = nullptr;

        if ((callInst = dyn_cast<CallInst>(&IN))) {

          if (callInst->getMetadata("afl.skip")) continue;
          Function *Callee = callInst->getCalledFunction();
          if (!Callee) continue;
          if (Callee->isIntrinsic()) continue;
          if (callInst->getCallingConv() != llvm::CallingConv::C) continue;

          FunctionType *FT = Callee->getFunctionType();
          std::string   FuncName = Callee->getName().str();

          bool isPtrRtn = FT->getNumParams() >= 2 &&
                          !FT->getReturnType()->isVoidTy() &&
                          FT->getParamType(0) == FT->getParamType(1) &&
                          FT->getParamType(0)->isPointerTy();

          bool isPtrRtnN = FT->getNumParams() >= 3 &&
                           !FT->getReturnType()->isVoidTy() &&
                           FT->getParamType(0) == FT->getParamType(1) &&
                           FT->getParamType(0)->isPointerTy() &&
                           FT->getParamType(2)->isIntegerTy();
          if (isPtrRtnN) {

            auto intTyOp =
                dyn_cast<IntegerType>(callInst->getArgOperand(2)->getType());
            if (intTyOp) {

              if (intTyOp->getBitWidth() != 32 &&
                  intTyOp->getBitWidth() != 64) {

                isPtrRtnN = false;

              }

            }

          }

          bool isMemcmp = isMemcmpRoutineName(FuncName);
          isMemcmp &= FT->getNumParams() == 3 &&
                      FT->getReturnType()->isIntegerTy(32) &&
                      FT->getParamType(0)->isPointerTy() &&
                      FT->getParamType(1)->isPointerTy() &&
                      FT->getParamType(2)->isIntegerTy();

          bool isStrcmp = isStrcmpRoutineName(FuncName);
          isStrcmp &= FT->getNumParams() == 2 &&
                      FT->getReturnType()->isIntegerTy(32) &&
                      FT->getParamType(0) == FT->getParamType(1) &&
#if LLVM_MAJOR >= 17
                      FT->getParamType(0)->isPointerTy();
#else
                      FT->getParamType(0) ==
                          IntegerType::getInt8Ty(M.getContext())
                              ->getPointerTo(0);
#endif

          bool isStrcasecmp = isStrcasecmpRoutineName(FuncName);
          isStrcasecmp &= FT->getNumParams() == 2 &&
                          FT->getReturnType()->isIntegerTy(32) &&
                          FT->getParamType(0) == FT->getParamType(1) &&
#if LLVM_MAJOR >= 17
                          FT->getParamType(0)->isPointerTy();
#else
                          FT->getParamType(0) ==
                              IntegerType::getInt8Ty(M.getContext())
                                  ->getPointerTo(0);
#endif

          bool isStrncmp = isStrncmpRoutineName(FuncName);
          isStrncmp &= FT->getNumParams() == 3 &&
                       FT->getReturnType()->isIntegerTy(32) &&
                       FT->getParamType(0) == FT->getParamType(1) &&
#if LLVM_MAJOR >= 17
                       FT->getParamType(0)->isPointerTy() &&
#else
                       FT->getParamType(0) ==
                           IntegerType::getInt8Ty(M.getContext())
                               ->getPointerTo(0) &&
#endif
                       FT->getParamType(2)->isIntegerTy();

          bool isStrncasecmp = isStrncasecmpRoutineName(FuncName);
          isStrncasecmp &= FT->getNumParams() == 3 &&
                           FT->getReturnType()->isIntegerTy(32) &&
                           FT->getParamType(0) == FT->getParamType(1) &&
#if LLVM_MAJOR >= 17
                           FT->getParamType(0)->isPointerTy() &&
#else
                           FT->getParamType(0) ==
                               IntegerType::getInt8Ty(M.getContext())
                                   ->getPointerTo(0) &&
#endif
                           FT->getParamType(2)->isIntegerTy();

          // Functions like strstr that return a pointer to the found substring
          // Signature: ptr strstr(ptr haystack, ptr needle)
          bool isStrstr =
              (!FuncName.compare("strstr") || !FuncName.compare("xmlStrstr"));
          isStrstr &= FT->getNumParams() == 2 &&
                      FT->getReturnType()->isPointerTy() &&
                      FT->getParamType(0)->isPointerTy() &&
                      FT->getParamType(1)->isPointerTy();

          bool isStrcasestr = (!FuncName.compare("strcasestr") ||
                               !FuncName.compare("ap_strcasestr") ||
                               !FuncName.compare("xmlStrcasestr"));
          isStrcasestr &= FT->getNumParams() == 2 &&
                          FT->getReturnType()->isPointerTy() &&
                          FT->getParamType(0)->isPointerTy() &&
                          FT->getParamType(1)->isPointerTy();

          // g_strstr_len: gchar* (const gchar *haystack, gssize haystack_len,
          //                       const gchar *needle)
          bool isGStrstrLen = (!FuncName.compare("g_strstr_len"));
          isGStrstrLen &= FT->getNumParams() == 3 &&
                          FT->getReturnType()->isPointerTy() &&
                          FT->getParamType(0)->isPointerTy() &&
                          FT->getParamType(1)->isIntegerTy() &&
                          FT->getParamType(2)->isPointerTy();

          // memmem: void* (const void *haystack, size_t haystacklen,
          //                const void *needle, size_t needlelen)
          bool isMemmem = (!FuncName.compare("memmem"));
          isMemmem &= FT->getNumParams() == 4 &&
                      FT->getReturnType()->isPointerTy() &&
                      FT->getParamType(0)->isPointerTy() &&
                      FT->getParamType(1)->isIntegerTy() &&
                      FT->getParamType(2)->isPointerTy() &&
                      FT->getParamType(3)->isIntegerTy();

          // strnstr: char* (const char *big, const char *little, size_t len)
          // BSD-specific function
          bool isStrnstr = (!FuncName.compare("strnstr"));
          isStrnstr &= FT->getNumParams() == 3 &&
                       FT->getReturnType()->isPointerTy() &&
                       FT->getParamType(0)->isPointerTy() &&
                       FT->getParamType(1)->isPointerTy() &&
                       FT->getParamType(2)->isIntegerTy();

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
              isLlvmStdStringStdString || isLlvmStdStringCString || isMemcmp ||
              isStrcmp || isStrncmp || isStrcasecmp || isStrncasecmp ||
              isStrstr || isStrcasestr || isGStrstrLen || isMemmem ||
              isStrnstr) {

            isPtrRtnN = isPtrRtn = false;

          }

          if (isPtrRtnN) { isPtrRtn = false; }

          if (isPtrRtn && !vp_mode) { calls.push_back(callInst); }
          if (isMemcmp || (isPtrRtnN && !vp_mode)) {

            Memcmp.push_back(callInst);

          }

          if (isStrcmp || ((isStrstr || isStrcasestr) && !vp_mode)) {

            Strcmp.push_back(callInst);

          }

          if (isStrncmp || (isStrnstr && !vp_mode)) {

            Strncmp.push_back(callInst);

          }

          if (isStrcasecmp) { Strcasecmp.push_back(callInst); }
          if (isStrncasecmp) { Strncasecmp.push_back(callInst); }
          if (isGStrstrLen) { GStrstrLen.push_back(callInst); }
          if (isMemmem) { Memmem.push_back(callInst); }
          if (vp_mode && isStrstr) { Strstr.push_back(callInst); }
          if (vp_mode && isStrcasestr) { Strcasestr.push_back(callInst); }
          if (vp_mode && isStrnstr) { Strnstr.push_back(callInst); }
          if (isGccStdStringStdString) { gccStdStd.push_back(callInst); }
          if (isGccStdStringCString) { gccStdC.push_back(callInst); }
          if (isLlvmStdStringStdString) { llvmStdStd.push_back(callInst); }
          if (isLlvmStdStringCString) { llvmStdC.push_back(callInst); }

        }

      }

    }

  }

  if (!calls.size() && !gccStdStd.size() && !gccStdC.size() &&
      !llvmStdStd.size() && !llvmStdC.size() && !Memcmp.size() &&
      !Strcmp.size() && !Strncmp.size() && !Strcasecmp.size() &&
      !Strncasecmp.size() && !GStrstrLen.size() && !Memmem.size() &&
      !Strstr.size() && !Strcasestr.size() && !Strnstr.size())
    return false;

  constexpr uint64_t                   kVpRoutineSiteSalt = 0x52565350ULL;
  DenseMap<const Function *, uint64_t> vp_site_fallback_ordinal;
  DenseMap<const Function *, DenseMap<uint64_t, uint64_t>>
      vp_site_debug_disambiguator;

  auto getVpSiteToken = [&](Instruction *I) -> ConstantInt * {

    uint64_t site_disambiguator = 0;
    if (I->getDebugLoc()) {

      uint64_t debug_site_key = getValueProfileDebugSiteKey(*I);
      site_disambiguator =
          vp_site_debug_disambiguator[I->getFunction()][debug_site_key]++;

    } else {

      site_disambiguator = vp_site_fallback_ordinal[I->getFunction()]++;

    }

    return ConstantInt::get(
        Int64Ty, computeValueProfileSiteToken(*I, kVpRoutineSiteSalt,
                                              site_disambiguator, 0));

  };

  /*
    if (!be_quiet)
      errs() << "Hooking " << calls.size()
             << " calls with pointers as arguments\n";
  */

  for (auto &callInst : calls) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB(getHookInsertPoint(callInst));

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);
    if (vp_mode) { args.push_back(getVpSiteToken(callInst)); }

    IRB.CreateCall(hookFn, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";

  }

  for (auto &callInst : Memcmp) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1),
          *v3P = callInst->getArgOperand(2);

    IRBuilder<> IRB(getHookInsertPoint(callInst));

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    Value               *v3Pbitcast = IRB.CreateBitCast(
        v3P, IntegerType::get(C, v3P->getType()->getPrimitiveSizeInBits()));
    Value *v3Pcasted =
        IRB.CreateIntCast(v3Pbitcast, IntegerType::get(C, 64), false);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);
    args.push_back(v3Pcasted);
    if (vp_mode) { args.push_back(getVpSiteToken(callInst)); }

    IRB.CreateCall(hookFnN, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";

  }

  for (auto &callInst : Strcmp) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB(getHookInsertPoint(callInst));

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);
    if (vp_mode) { args.push_back(getVpSiteToken(callInst)); }

    IRB.CreateCall(hookFnStr, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";

  }

  for (auto &callInst : Strncmp) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1),
          *v3P = callInst->getArgOperand(2);

    IRBuilder<> IRB(getHookInsertPoint(callInst));

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    Value               *v3Pbitcast = IRB.CreateBitCast(
        v3P, IntegerType::get(C, v3P->getType()->getPrimitiveSizeInBits()));
    Value *v3Pcasted =
        IRB.CreateIntCast(v3Pbitcast, IntegerType::get(C, 64), false);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);
    args.push_back(v3Pcasted);
    if (vp_mode) { args.push_back(getVpSiteToken(callInst)); }

    IRB.CreateCall(hookFnStrN, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";

  }

  for (auto &callInst : Strcasecmp) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB(getHookInsertPoint(callInst));

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);
    if (vp_mode) { args.push_back(getVpSiteToken(callInst)); }

    IRB.CreateCall(hookFnStrCi, args);

  }

  for (auto &callInst : Strncasecmp) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1),
          *v3P = callInst->getArgOperand(2);

    IRBuilder<> IRB(getHookInsertPoint(callInst));

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    Value               *v3Pbitcast = IRB.CreateBitCast(
        v3P, IntegerType::get(C, v3P->getType()->getPrimitiveSizeInBits()));
    Value *v3Pcasted =
        IRB.CreateIntCast(v3Pbitcast, IntegerType::get(C, 64), false);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);
    args.push_back(v3Pcasted);
    if (vp_mode) { args.push_back(getVpSiteToken(callInst)); }

    IRB.CreateCall(hookFnStrNCi, args);

  }

  for (auto &callInst : Strstr) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB(getHookInsertPoint(callInst));

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);
    args.push_back(getVpSiteToken(callInst));

    IRB.CreateCall(hookFnSub, args);

  }

  for (auto &callInst : Strcasestr) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB(getHookInsertPoint(callInst));

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);
    args.push_back(getVpSiteToken(callInst));

    IRB.CreateCall(hookFnSubCi, args);

  }

  for (auto &callInst : gccStdStd) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB(getHookInsertPoint(callInst));

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);
    if (vp_mode) { args.push_back(getVpSiteToken(callInst)); }

    IRB.CreateCall(hookGccStdStd, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";

  }

  for (auto &callInst : gccStdC) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB(getHookInsertPoint(callInst));

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);
    if (vp_mode) { args.push_back(getVpSiteToken(callInst)); }

    IRB.CreateCall(hookGccStdC, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";

  }

  for (auto &callInst : llvmStdStd) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB(getHookInsertPoint(callInst));

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);
    if (vp_mode) { args.push_back(getVpSiteToken(callInst)); }

    IRB.CreateCall(hookLlvmStdStd, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";

  }

  for (auto &callInst : llvmStdC) {

    Value *v1P = callInst->getArgOperand(0), *v2P = callInst->getArgOperand(1);

    IRBuilder<> IRB(getHookInsertPoint(callInst));

    std::vector<Value *> args;
    Value               *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value               *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);
    args.push_back(v1Pcasted);
    args.push_back(v2Pcasted);
    if (vp_mode) { args.push_back(getVpSiteToken(callInst)); }

    IRB.CreateCall(hookLlvmStdC, args);

    // errs() << callInst->getCalledFunction()->getName() << "\n";

  }

  // g_strstr_len: gchar* (const gchar *haystack, gssize haystack_len,
  //                       const gchar *needle)
  // Extract arg0 (haystack) and arg2 (needle)
  for (auto &callInst : GStrstrLen) {

    Value *v1P = callInst->getArgOperand(0),  // haystack
        *v2P = callInst->getArgOperand(2);    // needle

    IRBuilder<> IRB(getHookInsertPoint(callInst));

    Value *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);

    if (vp_mode) {

      Value *hayLenP = callInst->getArgOperand(1);
      Value *hayLenCasted = IRB.CreateIntCast(hayLenP, Int64Ty, true);

      std::vector<Value *> args = {v1Pcasted, hayLenCasted, v2Pcasted,
                                   getVpSiteToken(callInst)};

      IRB.CreateCall(hookFnSubHN, args);

    } else {

      std::vector<Value *> args = {v1Pcasted, v2Pcasted};
      IRB.CreateCall(hookFnStr, args);

    }

    // errs() << callInst->getCalledFunction()->getName() << "\n";

  }

  // memmem: void* (const void *haystack, size_t haystacklen,
  //                const void *needle, size_t needlelen)
  // Extract arg0 (haystack), arg2 (needle), arg3 (needlelen)
  for (auto &callInst : Memmem) {

    Value *v1P = callInst->getArgOperand(0),  // haystack
        *v2P = callInst->getArgOperand(2);    // needle

    IRBuilder<> IRB(getHookInsertPoint(callInst));

    Value *v1Pcasted = IRB.CreatePointerCast(v1P, i8PtrTy);
    Value *v2Pcasted = IRB.CreatePointerCast(v2P, i8PtrTy);

    if (vp_mode) {

      Value *hayLenP = callInst->getArgOperand(1);
      Value *needleLenP = callInst->getArgOperand(3);
      Value *hayLenCasted = IRB.CreateIntCast(hayLenP, Int64Ty, false);
      Value *needleLenCasted = IRB.CreateIntCast(needleLenP, Int64Ty, false);

      std::vector<Value *> args = {v1Pcasted, hayLenCasted, v2Pcasted,
                                   needleLenCasted, getVpSiteToken(callInst)};

      IRB.CreateCall(hookFnSubN, args);

    } else {

      Value *v3P = callInst->getArgOperand(3);  // needlelen
      Value *v3Pbitcast = IRB.CreateBitCast(
          v3P, IntegerType::get(C, v3P->getType()->getPrimitiveSizeInBits()));
      Value *v3Pcasted =
          IRB.CreateIntCast(v3Pbitcast, IntegerType::get(C, 64), false);

      std::vector<Value *> args = {v1Pcasted, v2Pcasted, v3Pcasted};
      IRB.CreateCall(hookFnN, args);

    }

    // errs() << callInst->getCalledFunction()->getName() << "\n";

  }

  for (auto &callInst : Strnstr) {

    Value *hayP = callInst->getArgOperand(0),
          *needleP = callInst->getArgOperand(1),
          *hayLenP = callInst->getArgOperand(2);

    IRBuilder<> IRB(getHookInsertPoint(callInst));

    Value *hayPcasted = IRB.CreatePointerCast(hayP, i8PtrTy);
    Value *needlePcasted = IRB.CreatePointerCast(needleP, i8PtrTy);
    Value *hayLenCasted = IRB.CreateIntCast(hayLenP, Int64Ty, false);

    std::vector<Value *> args = {hayPcasted, hayLenCasted, needlePcasted,
                                 getVpSiteToken(callInst)};

    IRB.CreateCall(hookFnSubHN, args);

  }

  return true;

}

PreservedAnalyses CmpLogRoutines::run(Module &M, ModuleAnalysisManager &MAM) {

  bool vp_mode = isValueProfileMode(mode_);

  if (vp_mode) { markInstrumentedMarker(M, "__afl_vp_instrumented"); }

  if (getenv("AFL_QUIET") != NULL) {

    be_quiet = 1;

  } else if (vp_mode) {

    printf("Running valueprofile-routines-pass by AFL++ team\n");

  } else {

    printf("Running cmplog-routines-pass by andreafioraldi@gmail.com\n");

  }

  bool ret = hookRtns(M);

  verifyModule(M);
  if (ret || vp_mode) { return PreservedAnalyses::none(); }
  return PreservedAnalyses::all();

}

