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
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 5
typedef long double max_align_t;
#endif

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/CFG.h"
#else
#include "llvm/DebugInfo.h"
#include "llvm/Support/CFG.h"
#endif

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
              ptr, MAP_SIZE);

  }

  static bool isBlacklisted(const Function *F) {

    static const char *Blacklist[] = {

        "asan.", "llvm.", "sancov.", "__ubsan_handle_", "ign."

    };

    for (auto const &BlacklistFunc : Blacklist) {

      if (F->getName().startswith(BlacklistFunc)) { return true; }

    }

    return false;

  }

  bool runOnModule(Module &M) override;

 protected:
  int      afl_global_id = 1, debug = 0;
  uint32_t be_quiet = 0, inst_blocks = 0, inst_funcs = 0, total_instr = 0;

};

}  // namespace

bool AFLLTOPass::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

  IntegerType *   Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *   Int32Ty = IntegerType::getInt32Ty(C);
  struct timeval  tv;
  struct timezone tz;
  u32             rand_seed;

  /* Setup random() so we get Actually Random(TM) outputs from AFL_R() */
  gettimeofday(&tv, &tz);
  rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();
  AFL_SR(rand_seed);

  /* Show a banner */

  if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {

    SAYF(cCYA "afl-llvm-pass" VERSION cRST " by <lszekeres@google.com>\n");

  } else

    be_quiet = 1;

#if LLVM_VERSION_MAJOR < 9
  char *neverZero_counters_str = getenv("AFL_LLVM_NOT_ZERO");
#endif

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

    if (isBlacklisted(&F)) continue;

    std::vector<BasicBlock *> InsBlocks;

    for (auto &BB : F) {

      uint32_t succ = 0;

      for (succ_iterator SI = succ_begin(&BB), SE = succ_end(&BB); SI != SE;
           ++SI)
        succ++;

      if (succ < 2)  // no need to instrument
        continue;

      InsBlocks.push_back(&BB);

    }

    if (InsBlocks.size() > 0) {

      for (uint32_t i = 0; i < InsBlocks.size(); i++) {

        BasicBlock *              oldBB = &*InsBlocks[i];
        std::vector<BasicBlock *> Successors;

        Instruction *TI = oldBB->getTerminator();
        
        if (TI == NULL)
          continue;

        for (succ_iterator SI = succ_begin(oldBB), SE = succ_end(oldBB);
             SI != SE; ++SI) {

          BasicBlock *succ = *SI;
          Successors.push_back(succ);

        }

        for (uint32_t j = 0; j < Successors.size(); j++) {

          BasicBlock *BB = BasicBlock::Create(C, "", &F, nullptr);

          IRBuilder<> IRB(BB);

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

#if LLVM_VERSION_MAJOR < 9
          if (neverZero_counters_str !=
              NULL) {  // with llvm 9 we make this the default as the bug in
                       // llvm is then fixed
#endif
            auto cf = IRB.CreateICmpEQ(Incr, Zero);
            auto carry = IRB.CreateZExt(cf, Int8Ty);
            Incr = IRB.CreateAdd(Incr, carry);
#if LLVM_VERSION_MAJOR < 9

          }

#endif
          IRB.CreateStore(Incr, MapPtrIdx)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          // Unconditional jump to the destination BB

          IRB.CreateBr(Successors[j]);

          // Replace the original destination to this newly inserted BB

          BB->replaceSuccessorsPhiUsesWith(Successors[j], BB);
          TI->setSuccessor(j, BB);

          // done :)

          inst_blocks++;

        }

      }

    }

  }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else {

      char modeline[100];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
      OKF("Instrumented %u locations with no collisions :-) (%s mode).",
          inst_blocks, modeline);

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
    PassManagerBuilder::EP_OptimizerLast, registerAFLLTOPass);

