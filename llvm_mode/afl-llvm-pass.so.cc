/*
   american fuzzy lop++ - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com>,
              Adrian Herrera <adrian.herrera@anu.edu.au>,
              Michal Zalewski

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   NGRAM previous location coverage comes from Adrian Herrera.

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
#include "llvm/Support/MathExtras.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/CFG.h"
#else
#include "llvm/DebugInfo.h"
#include "llvm/Support/CFG.h"
#endif

#include "llvm-ngram-coverage.h"

using namespace llvm;

namespace {

class AFLCoverage : public ModulePass {

 public:
  static char ID;
  AFLCoverage() : ModulePass(ID) {

    char *instWhiteListFilename = getenv("AFL_LLVM_WHITELIST");
    if (instWhiteListFilename) {

      std::string   line;
      std::ifstream fileStream;
      fileStream.open(instWhiteListFilename);
      if (!fileStream) report_fatal_error("Unable to open AFL_LLVM_WHITELIST");
      getline(fileStream, line);
      while (fileStream) {

        myWhitelist.push_back(line);
        getline(fileStream, line);

      }

    }

  }

  // ripped from aflgo
  static bool isBlacklisted(const Function *F) {

    static const char *Blacklist[] = {

        "asan.",
        "llvm.",
        "sancov.",
        "__ubsan_handle_",

    };

    for (auto const &BlacklistFunc : Blacklist) {

      if (F->getName().startswith(BlacklistFunc)) { return true; }

    }

    return false;

  }

  bool runOnModule(Module &M) override;

  // StringRef getPassName() const override {

  //  return "American Fuzzy Lop Instrumentation";
  // }

 protected:
  std::list<std::string> myWhitelist;
  uint32_t               ngram_size = 0;
  uint32_t               debug = 0;
  char *                 ctx_str = NULL;

};

}  // namespace

char AFLCoverage::ID = 0;

/* needed up to 3.9.0 */
#if LLVM_VERSION_MAJOR == 3 && \
    (LLVM_VERSION_MINOR < 9 || \
     (LLVM_VERSION_MINOR == 9 && LLVM_VERSION_PATCH < 1))
uint64_t PowerOf2Ceil(unsigned in) {

  uint64_t in64 = in - 1;
  in64 |= (in64 >> 1);
  in64 |= (in64 >> 2);
  in64 |= (in64 >> 4);
  in64 |= (in64 >> 8);
  in64 |= (in64 >> 16);
  in64 |= (in64 >> 32);
  return in64 + 1;

}

#endif

/* #if LLVM_VERSION_STRING >= "4.0.1" */
#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 4 && LLVM_VERSION_PATCH >= 1)
#define AFL_HAVE_VECTOR_INTRINSICS 1
#endif
bool AFLCoverage::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
#ifdef AFL_HAVE_VECTOR_INTRINSICS
  IntegerType *IntLocTy =
      IntegerType::getIntNTy(C, sizeof(PREV_LOC_T) * CHAR_BIT);
#endif
  struct timeval  tv;
  struct timezone tz;
  u32             rand_seed;
  unsigned int    cur_loc = 0;

  /* Setup random() so we get Actually Random(TM) outputs from AFL_R() */
  gettimeofday(&tv, &tz);
  rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();
  AFL_SR(rand_seed);

  /* Show a banner */

  char be_quiet = 0;

  if (getenv("AFL_DEBUG")) debug = 1;

  if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {

    SAYF(cCYA "afl-llvm-pass" VERSION cRST
              " by <lszekeres@google.com> and <adrian.herrera@anu.edu.au>\n");

  } else

    be_quiet = 1;

  /* Decide instrumentation ratio */

  char *       inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

#if LLVM_VERSION_MAJOR < 9
  char *neverZero_counters_str = getenv("AFL_LLVM_NOT_ZERO");
#endif

  unsigned PrevLocSize;

  char *ngram_size_str = getenv("AFL_LLVM_NGRAM_SIZE");
  if (!ngram_size_str) ngram_size_str = getenv("AFL_NGRAM_SIZE");
  ctx_str = getenv("AFL_LLVM_CTX");

#ifdef AFL_HAVE_VECTOR_INTRINSICS
  /* Decide previous location vector size (must be a power of two) */
  VectorType *PrevLocTy;

  if (ngram_size_str)
    if (sscanf(ngram_size_str, "%u", &ngram_size) != 1 || ngram_size < 2 ||
        ngram_size > NGRAM_SIZE_MAX)
      FATAL(
          "Bad value of AFL_NGRAM_SIZE (must be between 2 and NGRAM_SIZE_MAX "
          "(%u))",
          NGRAM_SIZE_MAX);

  if (ngram_size == 1) ngram_size = 0;
  if (ngram_size)
    PrevLocSize = ngram_size - 1;
  else
#else
  if (ngram_size_str)
    FATAL("Sorry, NGRAM branch coverage is not supported with llvm version %s!",
          LLVM_VERSION_STRING);
#endif
    PrevLocSize = 1;

#ifdef AFL_HAVE_VECTOR_INTRINSICS
  uint64_t PrevLocVecSize = PowerOf2Ceil(PrevLocSize);
  if (ngram_size) PrevLocTy = VectorType::get(IntLocTy, PrevLocVecSize);
#endif

  if (ctx_str && ngram_size_str)
    FATAL("you must decide between NGRAM and CTX instrumentation");

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
  GlobalVariable *AFLPrevLoc;
  GlobalVariable *AFLContext;

  if (ctx_str)
#ifdef __ANDROID__
    AFLContext = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx");
#else
    AFLContext = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx", 0,
        GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

#ifdef AFL_HAVE_VECTOR_INTRINSICS
  if (ngram_size)
#ifdef __ANDROID__
    AFLPrevLoc = new GlobalVariable(
        M, PrevLocTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
        /* Initializer */ nullptr, "__afl_prev_loc");
#else
    AFLPrevLoc = new GlobalVariable(
        M, PrevLocTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
        /* Initializer */ nullptr, "__afl_prev_loc",
        /* InsertBefore */ nullptr, GlobalVariable::GeneralDynamicTLSModel,
        /* AddressSpace */ 0, /* IsExternallyInitialized */ false);
#endif
  else
#endif
#ifdef __ANDROID__
    AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc");
#else
  AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

#ifdef AFL_HAVE_VECTOR_INTRINSICS
  /* Create the vector shuffle mask for updating the previous block history.
     Note that the first element of the vector will store cur_loc, so just set
     it to undef to allow the optimizer to do its thing. */

  SmallVector<Constant *, 32> PrevLocShuffle = {UndefValue::get(Int32Ty)};

  for (unsigned I = 0; I < PrevLocSize - 1; ++I)
    PrevLocShuffle.push_back(ConstantInt::get(Int32Ty, I));

  for (unsigned I = PrevLocSize; I < PrevLocVecSize; ++I)
    PrevLocShuffle.push_back(ConstantInt::get(Int32Ty, PrevLocSize));

  Constant *PrevLocShuffleMask = ConstantVector::get(PrevLocShuffle);
#endif

  // other constants we need
  ConstantInt *Zero = ConstantInt::get(Int8Ty, 0);
  ConstantInt *One = ConstantInt::get(Int8Ty, 1);

  LoadInst *PrevCtx;  // CTX sensitive coverage

  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M) {

    int has_calls = 0;
    if (debug)
      fprintf(stderr, "FUNCTION: %s (%zu)\n", F.getName().str().c_str(),
              F.size());

    if (isBlacklisted(&F)) continue;

    // AllocaInst *CallingContext = nullptr;

    if (ctx_str && F.size() > 1) {  // Context sensitive coverage
      // load the context ID of the previous function and write to to a local
      // variable on the stack
      auto                 bb = &F.getEntryBlock();
      BasicBlock::iterator IP = bb->getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));
      PrevCtx = IRB.CreateLoad(AFLContext);
      PrevCtx->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      // does the function have calls? and is any of the calls larger than one
      // basic block?
      has_calls = 0;
      for (auto &BB : F) {

        if (has_calls) break;
        for (auto &IN : BB) {

          CallInst *callInst = nullptr;
          if ((callInst = dyn_cast<CallInst>(&IN))) {

            Function *Callee = callInst->getCalledFunction();
            if (!Callee || Callee->size() < 2)
              continue;
            else {

              has_calls = 1;
              break;

            }

          }

        }

      }

      // if yes we store a context ID for this function in the global var
      if (has_calls) {

        ConstantInt *NewCtx = ConstantInt::get(Int32Ty, AFL_R(MAP_SIZE));
        StoreInst *  StoreCtx = IRB.CreateStore(NewCtx, AFLContext);
        StoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                              MDNode::get(C, None));

      }

    }

    for (auto &BB : F) {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));

      if (!myWhitelist.empty()) {

        bool instrumentBlock = false;

        /* Get the current location using debug information.
         * For now, just instrument the block if we are not able
         * to determine our location. */
        DebugLoc Loc = IP->getDebugLoc();
#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR >= 7)
        if (Loc) {

          DILocation *cDILoc = dyn_cast<DILocation>(Loc.getAsMDNode());

          unsigned int instLine = cDILoc->getLine();
          StringRef    instFilename = cDILoc->getFilename();

          if (instFilename.str().empty()) {

            /* If the original location is empty, try using the inlined location
             */
            DILocation *oDILoc = cDILoc->getInlinedAt();
            if (oDILoc) {

              instFilename = oDILoc->getFilename();
              instLine = oDILoc->getLine();

            }

          }

          (void)instLine;

          /* Continue only if we know where we actually are */
          if (!instFilename.str().empty()) {

            for (std::list<std::string>::iterator it = myWhitelist.begin();
                 it != myWhitelist.end(); ++it) {

              /* We don't check for filename equality here because
               * filenames might actually be full paths. Instead we
               * check that the actual filename ends in the filename
               * specified in the list. */
              if (instFilename.str().length() >= it->length()) {

                if (instFilename.str().compare(
                        instFilename.str().length() - it->length(),
                        it->length(), *it) == 0) {

                  instrumentBlock = true;
                  break;

                }

              }

            }

          }

        }

#else
        if (!Loc.isUnknown()) {

          DILocation cDILoc(Loc.getAsMDNode(C));

          unsigned int instLine = cDILoc.getLineNumber();
          StringRef    instFilename = cDILoc.getFilename();

          (void)instLine;

          /* Continue only if we know where we actually are */
          if (!instFilename.str().empty()) {

            for (std::list<std::string>::iterator it = myWhitelist.begin();
                 it != myWhitelist.end(); ++it) {

              /* We don't check for filename equality here because
               * filenames might actually be full paths. Instead we
               * check that the actual filename ends in the filename
               * specified in the list. */
              if (instFilename.str().length() >= it->length()) {

                if (instFilename.str().compare(
                        instFilename.str().length() - it->length(),
                        it->length(), *it) == 0) {

                  instrumentBlock = true;
                  break;

                }

              }

            }

          }

        }

#endif

        /* Either we couldn't figure out our location or the location is
         * not whitelisted, so we skip instrumentation. */
        if (!instrumentBlock) continue;

      }

      // in CTX mode we have to restore the original context for the caller -
      // she might be calling other functions which need the correct CTX
      if (ctx_str && has_calls) {

        Instruction *Inst = BB.getTerminator();
        if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {

          IRBuilder<> Post_IRB(Inst);
          StoreInst * RestoreCtx = Post_IRB.CreateStore(PrevCtx, AFLContext);
          RestoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));

        }

      }

      if (AFL_R(100) >= inst_ratio) continue;

      /* Make up cur_loc */

      // cur_loc++;
      cur_loc = AFL_R(MAP_SIZE);

/* There is a problem with Ubuntu 18.04 and llvm 6.0 (see issue #63).
   The inline function successors() is not inlined and also not found at runtime
   :-( As I am unable to detect Ubuntu18.04 heree, the next best thing is to
   disable this optional optimization for LLVM 6.0.0 and Linux */
#if !(LLVM_VERSION_MAJOR == 6 && LLVM_VERSION_MINOR == 0) || !defined __linux__
      // only instrument if this basic block is the destination of a previous
      // basic block that has multiple successors
      // this gets rid of ~5-10% of instrumentations that are unnecessary
      // result: a little more speed and less map pollution
      int more_than_one = -1;
      // fprintf(stderr, "BB %u: ", cur_loc);
      for (pred_iterator PI = pred_begin(&BB), E = pred_end(&BB); PI != E;
           ++PI) {

        BasicBlock *Pred = *PI;

        int count = 0;
        if (more_than_one == -1) more_than_one = 0;
        // fprintf(stderr, " %p=>", Pred);

        for (succ_iterator SI = succ_begin(Pred), E = succ_end(Pred); SI != E;
             ++SI) {

          BasicBlock *Succ = *SI;

          // if (count > 0)
          //  fprintf(stderr, "|");
          if (Succ != NULL) count++;
          // fprintf(stderr, "%p", Succ);

        }

        if (count > 1) more_than_one = 1;

      }

      // fprintf(stderr, " == %d\n", more_than_one);
      if (more_than_one != 1) continue;
#endif

      ConstantInt *CurLoc;

#ifdef AFL_HAVE_VECTOR_INTRINSICS
      if (ngram_size)
        CurLoc = ConstantInt::get(IntLocTy, cur_loc);
      else
#endif
        CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocTrans;

#ifdef AFL_HAVE_VECTOR_INTRINSICS
      /* "For efficiency, we propose to hash the tuple as a key into the
         hit_count map as (prev_block_trans << 1) ^ curr_block_trans, where
         prev_block_trans = (block_trans_1 ^ ... ^ block_trans_(n-1)" */

      if (ngram_size)
        PrevLocTrans = IRB.CreateXorReduce(PrevLoc);
      else
#endif
          if (ctx_str)
        PrevLocTrans = IRB.CreateZExt(IRB.CreateXor(PrevLoc, PrevCtx), Int32Ty);
      else
        PrevLocTrans = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      Value *MapPtrIdx;
#ifdef AFL_HAVE_VECTOR_INTRINSICS
      if (ngram_size)
        MapPtrIdx = IRB.CreateGEP(
            MapPtr,
            IRB.CreateZExt(IRB.CreateXor(PrevLocTrans, CurLoc), Int32Ty));
      else
#endif
        MapPtrIdx = IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocTrans, CurLoc));

      /* Update bitmap */

      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      Value *Incr = IRB.CreateAdd(Counter, One);

#if LLVM_VERSION_MAJOR < 9
      if (neverZero_counters_str !=
          NULL) {  // with llvm 9 we make this the default as the bug in llvm is
                   // then fixed
#endif
        /* hexcoder: Realize a counter that skips zero during overflow.
         * Once this counter reaches its maximum value, it next increments to 1
         *
         * Instead of
         * Counter + 1 -> Counter
         * we inject now this
         * Counter + 1 -> {Counter, OverflowFlag}
         * Counter + OverflowFlag -> Counter
         */
        /*       // we keep the old solutions just in case
                 // Solution #1
                 if (neverZero_counters_str[0] == '1') {

                   CallInst *AddOv =
           IRB.CreateBinaryIntrinsic(Intrinsic::uadd_with_overflow, Counter,
           ConstantInt::get(Int8Ty, 1));
                   AddOv->setMetadata(M.getMDKindID("nosanitize"),
           MDNode::get(C, None)); Value *SumWithOverflowBit = AddOv; Incr =
           IRB.CreateAdd(IRB.CreateExtractValue(SumWithOverflowBit, 0),  // sum
                                        IRB.CreateZExt( // convert from one bit
           type to 8 bits type IRB.CreateExtractValue(SumWithOverflowBit, 1), //
           overflow Int8Ty));
                  // Solution #2

                  } else if (neverZero_counters_str[0] == '2') {

                     auto cf = IRB.CreateICmpEQ(Counter,
           ConstantInt::get(Int8Ty, 255)); Value *HowMuch =
           IRB.CreateAdd(ConstantInt::get(Int8Ty, 1), cf); Incr =
           IRB.CreateAdd(Counter, HowMuch);
                  // Solution #3

                  } else if (neverZero_counters_str[0] == '3') {

        */
        // this is the solution we choose because llvm9 should do the right
        // thing here
        auto cf = IRB.CreateICmpEQ(Incr, Zero);
        auto carry = IRB.CreateZExt(cf, Int8Ty);
        Incr = IRB.CreateAdd(Incr, carry);
/*
         // Solution #4

         } else if (neverZero_counters_str[0] == '4') {

            auto cf = IRB.CreateICmpULT(Incr, ConstantInt::get(Int8Ty, 1));
            auto carry = IRB.CreateZExt(cf, Int8Ty);
            Incr = IRB.CreateAdd(Incr, carry);

         } else {

            fprintf(stderr, "Error: unknown value for AFL_NZERO_COUNTS: %s
   (valid is 1-4)\n", neverZero_counters_str); exit(-1);

         }

*/
#if LLVM_VERSION_MAJOR < 9

      }

#endif

      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Update prev_loc history vector (by placing cur_loc at the head of the
         vector and shuffle the other elements back by one) */

      StoreInst *Store;

#ifdef AFL_HAVE_VECTOR_INTRINSICS
      if (ngram_size) {

        Value *ShuffledPrevLoc = IRB.CreateShuffleVector(
            PrevLoc, UndefValue::get(PrevLocTy), PrevLocShuffleMask);
        Value *UpdatedPrevLoc = IRB.CreateInsertElement(
            ShuffledPrevLoc, IRB.CreateLShr(CurLoc, (uint64_t)1), (uint64_t)0);

        Store = IRB.CreateStore(UpdatedPrevLoc, AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      } else

#endif
      {

        Store = IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1),
                                AFLPrevLoc);

      }

      inst_blocks++;

    }

  }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else {

      char modeline[100];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
      OKF("Instrumented %u locations (%s mode, ratio %u%%).", inst_blocks,
          modeline, inst_ratio);

    }

  }

  return true;

}

static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);

