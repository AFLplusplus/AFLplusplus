/*
   american fuzzy lop++ - LLVM Injection instrumentation
   --------------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

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

#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>
#include "llvm/Config/llvm-config.h"

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Passes/PassPlugin.h"
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

class InjectionRoutines : public PassInfoMixin<InjectionRoutines> {

 public:
  InjectionRoutines() {

    initInstrumentList();

  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

 private:
  bool hookRtns(Module &M);

  bool doSQL = false;
  bool doLDAP = false;
  bool doXSS = false;

};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "Injectionroutines", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

            PB.registerOptimizerLastEPCallback([](ModulePassManager &MPM,
                                                  OptimizationLevel  OL
#if LLVM_VERSION_MAJOR >= 20
                                                  ,
                                                  ThinOrFullLTOPhase Phase
#endif
                                               ) {

              MPM.addPass(InjectionRoutines());

            });

          }};

}

bool InjectionRoutines::hookRtns(Module &M) {

  std::vector<CallInst *> calls, llvmStdStd, llvmStdC, gccStdStd, gccStdC,
      Memcmp, Strcmp, Strncmp;
  LLVMContext &C = M.getContext();

  Type *VoidTy = Type::getVoidTy(C);
#if LLVM_MAJOR >= 20
  PointerType *i8PtrTy = PointerType::getUnqual(C);
#else
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  PointerType *i8PtrTy = PointerType::get(Int8Ty, 0);
#endif

  FunctionCallee c1 =
      M.getOrInsertFunction("__afl_injection_sql", VoidTy, i8PtrTy);
  FunctionCallee sqlfunc = c1;

  FunctionCallee c2 =
      M.getOrInsertFunction("__afl_injection_ldap", VoidTy, i8PtrTy);
  FunctionCallee ldapfunc = c2;

  FunctionCallee c3 =
      M.getOrInsertFunction("__afl_injection_xss", VoidTy, i8PtrTy);
  FunctionCallee xssfunc = c3;

  FunctionCallee FuncPtr;

  bool ret = false;

  /* iterate over all functions, bbs and instruction and add suitable calls */
  for (auto &F : M) {

    if (!isInInstrumentList(&F, MNAME)) continue;

    for (auto &BB : F) {

      for (auto &IN : BB) {

        CallInst *callInst = nullptr;

        if ((callInst = dyn_cast<CallInst>(&IN))) {

          Function *Callee = callInst->getCalledFunction();
          if (!Callee) continue;
          if (callInst->getCallingConv() != llvm::CallingConv::C) continue;

          std::string FuncName = Callee->getName().str();
          FuncPtr = nullptr;
          size_t param = 0;

          // Marker: ADD_TO_INJECTIONS
          // If you just need to add another function to test for SQL etc.
          // then add them here.
          // To add a new class or to work on e.g. std::string/Rust strings/...
          // you will need to add a function to afl-compiler-rt.c.o and
          // and upwards in this file add a pointer to that function to use
          // here.

          if (doSQL &&
              (FuncName.compare("sqlite3_exec") == 0 ||
               FuncName.compare("PQexec") == 0 || FuncName.compare("") == 0 ||
               FuncName.compare("PQexecParams") == 0 ||
               FuncName.compare("mysql_query") == 0)) {

            if (!be_quiet) {

              errs() << "Injection SQL hook: " << FuncName << "\n";

            }

            FuncPtr = sqlfunc;
            param = 1;

          }

          if (doLDAP && (FuncName.compare("ldap_search_ext") == 0 ||
                         FuncName.compare("ldap_search_ext_s") == 0)) {

            if (!be_quiet) {

              errs() << "Injection LDAP hook: " << FuncName << "\n";

            }

            FuncPtr = ldapfunc;
            param = 1;

          }

          if (doXSS && (FuncName.compare("htmlReadMemory") == 0)) {

            if (!be_quiet) {

              errs() << "Injection XSS hook: " << FuncName << "\n";

            }

            FuncPtr = xssfunc;
            param = 1;

          }

          if (FuncPtr) {

            IRBuilder<> IRB(callInst->getParent());
            IRB.SetInsertPoint(callInst);
            ret = true;

            Value *parameter = callInst->getArgOperand(param);

            std::vector<Value *> args;
            Value *casted = IRB.CreatePointerCast(parameter, i8PtrTy);
            args.push_back(casted);
            IRB.CreateCall(FuncPtr, args);

          }

        }

      }

    }

  }

  return ret;

}

PreservedAnalyses InjectionRoutines::run(Module                &M,
                                         ModuleAnalysisManager &MAM) {

  if (getenv("AFL_QUIET") == NULL)
    printf("Running injection-pass by Marc Heuse (mh@mh-sec.de)\n");
  else
    be_quiet = 1;
  if (getenv("AFL_LLVM_INJECTIONS_ALL")) {

    doSQL = true;
    doLDAP = true;
    doXSS = true;

  }

  if (getenv("AFL_LLVM_INJECTIONS_SQL")) { doSQL = true; }
  if (getenv("AFL_LLVM_INJECTIONS_LDAP")) { doLDAP = true; }
  if (getenv("AFL_LLVM_INJECTIONS_XSS")) { doXSS = true; }

  bool ret = hookRtns(M);
  verifyModule(M);

  if (ret == false)
    return PreservedAnalyses::all();
  else
    return PreservedAnalyses();

}

