/*
   american fuzzy lop++ - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

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
#include <fnmatch.h>

#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
//#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/CFG.h"
#if LLVM_VERSION_MAJOR >= 14                /* how about stable interfaces? */
  #include "llvm/Passes/OptimizationLevel.h"
#endif

#include "afl-llvm-common.h"

using namespace llvm;

namespace {

class AFLcheckIfInstrument : public PassInfoMixin<AFLcheckIfInstrument> {

 public:
  AFLcheckIfInstrument() {

    if (getenv("AFL_DEBUG")) debug = 1;

    initInstrumentList();

  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

 protected:
  std::list<std::string> myInstrumentList;

};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "AFLcheckIfInstrument", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

#if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(AFLcheckIfInstrument());

                });

          }};

}

PreservedAnalyses AFLcheckIfInstrument::run(Module &               M,
                                            ModuleAnalysisManager &MAM) {

  /* Show a banner */

  setvbuf(stdout, NULL, _IONBF, 0);

  if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {

    SAYF(cCYA "afl-llvm-lto-instrumentlist" VERSION cRST
              " by Marc \"vanHauser\" Heuse <mh@mh-sec.de>\n");

  } else if (getenv("AFL_QUIET"))

    be_quiet = 1;

  for (auto &F : M) {

    if (F.size() < 1) continue;

    // fprintf(stderr, "F:%s\n", F.getName().str().c_str());

    if (isInInstrumentList(&F, MNAME)) {

      if (debug)
        DEBUGF("function %s is in the instrument file list\n",
               F.getName().str().c_str());

    } else {

      if (debug)
        DEBUGF("function %s is NOT in the instrument file list\n",
               F.getName().str().c_str());

      auto &        Ctx = F.getContext();
      AttributeList Attrs = F.getAttributes();
#if LLVM_VERSION_MAJOR >= 14
      AttributeList NewAttrs = Attrs.addFnAttribute(Ctx, "skipinstrument");
      F.setAttributes(NewAttrs);
#else
      AttrBuilder NewAttrs;
      NewAttrs.addAttribute("skipinstrument");
      F.setAttributes(
          Attrs.addAttributes(Ctx, AttributeList::FunctionIndex, NewAttrs));
#endif

    }

  }

  auto PA = PreservedAnalyses::all();
  return PA;

}

#if 0
static void registerAFLcheckIfInstrumentpass(const PassManagerBuilder &,
                                             legacy::PassManagerBase &PM) {

  PM.add(new AFLcheckIfInstrument());

}

static RegisterStandardPasses RegisterAFLcheckIfInstrumentpass(
    PassManagerBuilder::EP_ModuleOptimizerEarly,
    registerAFLcheckIfInstrumentpass);

static RegisterStandardPasses RegisterAFLcheckIfInstrumentpass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0,
    registerAFLcheckIfInstrumentpass);
#endif

