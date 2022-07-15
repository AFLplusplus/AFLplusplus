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

#include "llvm/Config/llvm-config.h"
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 5
typedef long double max_align_t;
#endif

#include "llvm/Pass.h"
#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  #include "llvm/Passes/PassPlugin.h"
  #include "llvm/Passes/PassBuilder.h"
  #include "llvm/IR/PassManager.h"
#else
  #include "llvm/IR/LegacyPassManager.h"
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"
#if LLVM_VERSION_MAJOR >= 14                /* how about stable interfaces? */
  #include "llvm/Passes/OptimizationLevel.h"
#endif

#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/DebugInfo.h"
  #include "llvm/IR/CFG.h"
#else
  #include "llvm/DebugInfo.h"
  #include "llvm/Support/CFG.h"
#endif

#include "llvm/IR/IRBuilder.h"

#include "afl-llvm-common.h"
#include "llvm-alternative-coverage.h"

using namespace llvm;

namespace {

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
class AFLCoverage : public PassInfoMixin<AFLCoverage> {

 public:
  AFLCoverage() {

#else
class AFLCoverage : public ModulePass {

 public:
  static char ID;
  AFLCoverage() : ModulePass(ID) {

#endif

    initInstrumentList();

  }

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif

 protected:
  uint32_t    ngram_size = 0;
  uint32_t    ctx_k = 0;
  uint32_t    map_size = MAP_SIZE;
  uint32_t    function_minimum_size = 1;
  const char *ctx_str = NULL, *caller_str = NULL, *skip_nozero = NULL;
  const char *use_threadsafe_counters = nullptr;

};

}  // namespace

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "AFLCoverage", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

  #if 1
    #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
    #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(AFLCoverage());

                });

  /* TODO LTO registration */
  #else
            using PipelineElement = typename PassBuilder::PipelineElement;
            PB.registerPipelineParsingCallback([](StringRef          Name,
                                                  ModulePassManager &MPM,
                                                  ArrayRef<PipelineElement>) {

              if (Name == "AFLCoverage") {

                MPM.addPass(AFLCoverage());
                return true;

              } else {

                return false;

              }

            });

  #endif

          }};

}

#else

char AFLCoverage::ID = 0;
#endif

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
#if LLVM_VERSION_MAJOR >= 5 || \
    (LLVM_VERSION_MAJOR == 4 && LLVM_VERSION_PATCH >= 1)
  #define AFL_HAVE_VECTOR_INTRINSICS 1
#endif

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
PreservedAnalyses AFLCoverage::run(Module &M, ModuleAnalysisManager &MAM) {

#else
bool AFLCoverage::runOnModule(Module &M) {

#endif

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

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  auto PA = PreservedAnalyses::all();
#endif

  /* Setup random() so we get Actually Random(TM) outputs from AFL_R() */
  gettimeofday(&tv, &tz);
  rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();
  AFL_SR(rand_seed);

  /* Show a banner */

  setvbuf(stdout, NULL, _IONBF, 0);

  if (getenv("AFL_DEBUG")) debug = 1;

  if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {

    SAYF(cCYA "afl-llvm-pass" VERSION cRST
              " by <lszekeres@google.com> and <adrian.herrera@anu.edu.au>\n");

  } else

    be_quiet = 1;

  /*
    char *ptr;
    if ((ptr = getenv("AFL_MAP_SIZE")) || (ptr = getenv("AFL_MAPSIZE"))) {

      map_size = atoi(ptr);
      if (map_size < 8 || map_size > (1 << 29))
        FATAL("illegal AFL_MAP_SIZE %u, must be between 2^3 and 2^30",
    map_size); if (map_size % 8) map_size = (((map_size >> 3) + 1) << 3);

    }

  */

  /* Decide instrumentation ratio */

  char        *inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

#if LLVM_VERSION_MAJOR < 9
  char *neverZero_counters_str = getenv("AFL_LLVM_NOT_ZERO");
#endif
  skip_nozero = getenv("AFL_LLVM_SKIP_NEVERZERO");
  use_threadsafe_counters = getenv("AFL_LLVM_THREADSAFE_INST");

  if ((isatty(2) && !getenv("AFL_QUIET")) || !!getenv("AFL_DEBUG")) {

    if (use_threadsafe_counters) {

      // disabled unless there is support for other modules as well
      // (increases documentation complexity)
      /*      if (!getenv("AFL_LLVM_NOT_ZERO")) { */

      skip_nozero = "1";
      SAYF(cCYA "afl-llvm-pass" VERSION cRST " using thread safe counters\n");

      /*

            } else {

              SAYF(cCYA "afl-llvm-pass" VERSION cRST
                        " using thread safe not-zero-counters\n");

            }

      */

    } else {

      SAYF(cCYA "afl-llvm-pass" VERSION cRST
                " using non-thread safe instrumentation\n");

    }

  }

  unsigned PrevLocSize = 0;
  unsigned PrevCallerSize = 0;

  char *ngram_size_str = getenv("AFL_LLVM_NGRAM_SIZE");
  if (!ngram_size_str) ngram_size_str = getenv("AFL_NGRAM_SIZE");
  char *ctx_k_str = getenv("AFL_LLVM_CTX_K");
  if (!ctx_k_str) ctx_k_str = getenv("AFL_CTX_K");
  ctx_str = getenv("AFL_LLVM_CTX");
  caller_str = getenv("AFL_LLVM_CALLER");

  bool instrument_ctx = ctx_str || caller_str;

#ifdef AFL_HAVE_VECTOR_INTRINSICS
  /* Decide previous location vector size (must be a power of two) */
  VectorType *PrevLocTy = NULL;

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
    PrevLocSize = 1;

  /* Decide K-ctx vector size (must be a power of two) */
  VectorType *PrevCallerTy = NULL;

  if (ctx_k_str)
    if (sscanf(ctx_k_str, "%u", &ctx_k) != 1 || ctx_k < 1 || ctx_k > CTX_MAX_K)
      FATAL("Bad value of AFL_CTX_K (must be between 1 and CTX_MAX_K (%u))",
            CTX_MAX_K);

  if (ctx_k == 1) {

    ctx_k = 0;
    instrument_ctx = true;
    caller_str = ctx_k_str;  // Enable CALLER instead

  }

  if (ctx_k) {

    PrevCallerSize = ctx_k;
    instrument_ctx = true;

  }

#else
  if (ngram_size_str)
  #ifndef LLVM_VERSION_PATCH
    FATAL(
        "Sorry, NGRAM branch coverage is not supported with llvm version "
        "%d.%d.%d!",
        LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR, 0);
  #else
    FATAL(
        "Sorry, NGRAM branch coverage is not supported with llvm version "
        "%d.%d.%d!",
        LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR, LLVM_VERSION_PATCH);
  #endif
  if (ctx_k_str)
  #ifndef LLVM_VERSION_PATCH
    FATAL(
        "Sorry, K-CTX branch coverage is not supported with llvm version "
        "%d.%d.%d!",
        LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR, 0);
  #else
    FATAL(
        "Sorry, K-CTX branch coverage is not supported with llvm version "
        "%d.%d.%d!",
        LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR, LLVM_VERSION_PATCH);
  #endif
  PrevLocSize = 1;
#endif

#ifdef AFL_HAVE_VECTOR_INTRINSICS
  int PrevLocVecSize = PowerOf2Ceil(PrevLocSize);
  if (ngram_size)
    PrevLocTy = VectorType::get(IntLocTy, PrevLocVecSize
  #if LLVM_VERSION_MAJOR >= 12
                                ,
                                false
  #endif
    );
#endif

#ifdef AFL_HAVE_VECTOR_INTRINSICS
  int PrevCallerVecSize = PowerOf2Ceil(PrevCallerSize);
  if (ctx_k)
    PrevCallerTy = VectorType::get(IntLocTy, PrevCallerVecSize
  #if LLVM_VERSION_MAJOR >= 12
                                   ,
                                   false
  #endif
    );
#endif

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
  GlobalVariable *AFLPrevLoc;
  GlobalVariable *AFLPrevCaller;
  GlobalVariable *AFLContext = NULL;

  if (ctx_str || caller_str)
#if defined(__ANDROID__) || defined(__HAIKU__)
    AFLContext = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx");
#else
    AFLContext = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx", 0,
        GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

#ifdef AFL_HAVE_VECTOR_INTRINSICS
  if (ngram_size)
  #if defined(__ANDROID__) || defined(__HAIKU__)
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
#if defined(__ANDROID__) || defined(__HAIKU__)
    AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc");
#else
  AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

#ifdef AFL_HAVE_VECTOR_INTRINSICS
  if (ctx_k)
  #if defined(__ANDROID__) || defined(__HAIKU__)
    AFLPrevCaller = new GlobalVariable(
        M, PrevCallerTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
        /* Initializer */ nullptr, "__afl_prev_caller");
  #else
    AFLPrevCaller = new GlobalVariable(
        M, PrevCallerTy, /* isConstant */ false, GlobalValue::ExternalLinkage,
        /* Initializer */ nullptr, "__afl_prev_caller",
        /* InsertBefore */ nullptr, GlobalVariable::GeneralDynamicTLSModel,
        /* AddressSpace */ 0, /* IsExternallyInitialized */ false);
  #endif
  else
#endif
#if defined(__ANDROID__) || defined(__HAIKU__)
    AFLPrevCaller =
        new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage, 0,
                           "__afl_prev_caller");
#else
  AFLPrevCaller = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_caller",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

#ifdef AFL_HAVE_VECTOR_INTRINSICS
  /* Create the vector shuffle mask for updating the previous block history.
     Note that the first element of the vector will store cur_loc, so just set
     it to undef to allow the optimizer to do its thing. */

  SmallVector<Constant *, 32> PrevLocShuffle = {UndefValue::get(Int32Ty)};

  for (unsigned I = 0; I < PrevLocSize - 1; ++I)
    PrevLocShuffle.push_back(ConstantInt::get(Int32Ty, I));

  for (int I = PrevLocSize; I < PrevLocVecSize; ++I)
    PrevLocShuffle.push_back(ConstantInt::get(Int32Ty, PrevLocSize));

  Constant *PrevLocShuffleMask = ConstantVector::get(PrevLocShuffle);

  Constant                   *PrevCallerShuffleMask = NULL;
  SmallVector<Constant *, 32> PrevCallerShuffle = {UndefValue::get(Int32Ty)};

  if (ctx_k) {

    for (unsigned I = 0; I < PrevCallerSize - 1; ++I)
      PrevCallerShuffle.push_back(ConstantInt::get(Int32Ty, I));

    for (int I = PrevCallerSize; I < PrevCallerVecSize; ++I)
      PrevCallerShuffle.push_back(ConstantInt::get(Int32Ty, PrevCallerSize));

    PrevCallerShuffleMask = ConstantVector::get(PrevCallerShuffle);

  }

#endif

  // other constants we need
  ConstantInt *One = ConstantInt::get(Int8Ty, 1);

  Value    *PrevCtx = NULL;     // CTX sensitive coverage
  LoadInst *PrevCaller = NULL;  // K-CTX coverage

  /* Instrument all the things! */

  int inst_blocks = 0;
  scanForDangerousFunctions(&M);

  for (auto &F : M) {

    int has_calls = 0;
    if (debug)
      fprintf(stderr, "FUNCTION: %s (%zu)\n", F.getName().str().c_str(),
              F.size());

    if (!isInInstrumentList(&F, MNAME)) { continue; }

    if (F.size() < function_minimum_size) { continue; }

    std::list<Value *> todo;
    for (auto &BB : F) {

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));

      // Context sensitive coverage
      if (instrument_ctx && &BB == &F.getEntryBlock()) {

#ifdef AFL_HAVE_VECTOR_INTRINSICS
        if (ctx_k) {

          PrevCaller = IRB.CreateLoad(
  #if LLVM_VERSION_MAJOR >= 14
              PrevCallerTy,
  #endif
              AFLPrevCaller);
          PrevCaller->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));
          PrevCtx =
              IRB.CreateZExt(IRB.CreateXorReduce(PrevCaller), IRB.getInt32Ty());

        } else

#endif
        {

          // load the context ID of the previous function and write to to a
          // local variable on the stack
          LoadInst *PrevCtxLoad = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
              IRB.getInt32Ty(),
#endif
              AFLContext);
          PrevCtxLoad->setMetadata(M.getMDKindID("nosanitize"),
                                   MDNode::get(C, None));
          PrevCtx = PrevCtxLoad;

        }

        // does the function have calls? and is any of the calls larger than one
        // basic block?
        for (auto &BB_2 : F) {

          if (has_calls) break;
          for (auto &IN : BB_2) {

            CallInst *callInst = nullptr;
            if ((callInst = dyn_cast<CallInst>(&IN))) {

              Function *Callee = callInst->getCalledFunction();
              if (!Callee || Callee->size() < function_minimum_size)
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

          Value *NewCtx = ConstantInt::get(Int32Ty, AFL_R(map_size));
#ifdef AFL_HAVE_VECTOR_INTRINSICS
          if (ctx_k) {

            Value *ShuffledPrevCaller = IRB.CreateShuffleVector(
                PrevCaller, UndefValue::get(PrevCallerTy),
                PrevCallerShuffleMask);
            Value *UpdatedPrevCaller = IRB.CreateInsertElement(
                ShuffledPrevCaller, NewCtx, (uint64_t)0);

            StoreInst *Store =
                IRB.CreateStore(UpdatedPrevCaller, AFLPrevCaller);
            Store->setMetadata(M.getMDKindID("nosanitize"),
                               MDNode::get(C, None));

          } else

#endif
          {

            if (ctx_str) NewCtx = IRB.CreateXor(PrevCtx, NewCtx);
            StoreInst *StoreCtx = IRB.CreateStore(NewCtx, AFLContext);
            StoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));

          }

        }

      }

      if (AFL_R(100) >= inst_ratio) continue;

      /* Make up cur_loc */

      // cur_loc++;
      cur_loc = AFL_R(map_size);

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
      if (F.size() > 1 && more_than_one != 1) {

        // in CTX mode we have to restore the original context for the caller -
        // she might be calling other functions which need the correct CTX
        if (instrument_ctx && has_calls) {

          Instruction *Inst = BB.getTerminator();
          if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {

            IRBuilder<> Post_IRB(Inst);

            StoreInst *RestoreCtx;
  #ifdef AFL_HAVE_VECTOR_INTRINSICS
            if (ctx_k)
              RestoreCtx = IRB.CreateStore(PrevCaller, AFLPrevCaller);
            else
  #endif
              RestoreCtx = Post_IRB.CreateStore(PrevCtx, AFLContext);
            RestoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                    MDNode::get(C, None));

          }

        }

        continue;

      }

#endif

      ConstantInt *CurLoc;

#ifdef AFL_HAVE_VECTOR_INTRINSICS
      if (ngram_size)
        CurLoc = ConstantInt::get(IntLocTy, cur_loc);
      else
#endif
        CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc;

      if (ngram_size) {

        PrevLoc = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
            PrevLocTy,
#endif
            AFLPrevLoc);

      } else {

        PrevLoc = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
            IRB.getInt32Ty(),
#endif
            AFLPrevLoc);

      }

      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocTrans;

#ifdef AFL_HAVE_VECTOR_INTRINSICS
      /* "For efficiency, we propose to hash the tuple as a key into the
         hit_count map as (prev_block_trans << 1) ^ curr_block_trans, where
         prev_block_trans = (block_trans_1 ^ ... ^ block_trans_(n-1)" */

      if (ngram_size)
        PrevLocTrans =
            IRB.CreateZExt(IRB.CreateXorReduce(PrevLoc), IRB.getInt32Ty());
      else
#endif
        PrevLocTrans = PrevLoc;

      if (instrument_ctx)
        PrevLocTrans =
            IRB.CreateZExt(IRB.CreateXor(PrevLocTrans, PrevCtx), Int32Ty);
      else
        PrevLocTrans = IRB.CreateZExt(PrevLocTrans, IRB.getInt32Ty());

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
          PointerType::get(Int8Ty, 0),
#endif
          AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      Value *MapPtrIdx;
#ifdef AFL_HAVE_VECTOR_INTRINSICS
      if (ngram_size)
        MapPtrIdx = IRB.CreateGEP(
            Int8Ty, MapPtr,
            IRB.CreateZExt(
                IRB.CreateXor(PrevLocTrans, IRB.CreateZExt(CurLoc, Int32Ty)),
                Int32Ty));
      else
#endif
        MapPtrIdx = IRB.CreateGEP(
#if LLVM_VERSION_MAJOR >= 14
            Int8Ty,
#endif
            MapPtr, IRB.CreateXor(PrevLocTrans, CurLoc));

      /* Update bitmap */

      if (use_threadsafe_counters) {                              /* Atomic */

        IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                            llvm::MaybeAlign(1),
#endif
                            llvm::AtomicOrdering::Monotonic);
        /*

                }

        */

      } else {

        LoadInst *Counter = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
            IRB.getInt8Ty(),
#endif
            MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        Value *Incr = IRB.CreateAdd(Counter, One);

#if LLVM_VERSION_MAJOR >= 9
        if (!skip_nozero) {

#else
        if (neverZero_counters_str != NULL) {

#endif
          /* hexcoder: Realize a counter that skips zero during overflow.
           * Once this counter reaches its maximum value, it next increments to
           * 1
           *
           * Instead of
           * Counter + 1 -> Counter
           * we inject now this
           * Counter + 1 -> {Counter, OverflowFlag}
           * Counter + OverflowFlag -> Counter
           */

          ConstantInt *Zero = ConstantInt::get(Int8Ty, 0);
          auto         cf = IRB.CreateICmpEQ(Incr, Zero);
          auto         carry = IRB.CreateZExt(cf, Int8Ty);
          Incr = IRB.CreateAdd(Incr, carry);

        }

        IRB.CreateStore(Incr, MapPtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      }                                                  /* non atomic case */

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
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      }

      // in CTX mode we have to restore the original context for the caller -
      // she might be calling other functions which need the correct CTX.
      // Currently this is only needed for the Ubuntu clang-6.0 bug
      if (instrument_ctx && has_calls) {

        Instruction *Inst = BB.getTerminator();
        if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {

          IRBuilder<> Post_IRB(Inst);

          StoreInst *RestoreCtx;
#ifdef AFL_HAVE_VECTOR_INTRINSICS
          if (ctx_k)
            RestoreCtx = IRB.CreateStore(PrevCaller, AFLPrevCaller);
          else
#endif
            RestoreCtx = Post_IRB.CreateStore(PrevCtx, AFLContext);
          RestoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));

        }

      }

      inst_blocks++;

    }

#if 0
    if (use_threadsafe_counters) {                       /*Atomic NeverZero */
      // handle the list of registered blocks to instrument
      for (auto val : todo) {

        /* hexcoder: Realize a thread-safe counter that skips zero during
         * overflow. Once this counter reaches its maximum value, it next
         * increments to 1
         *
         * Instead of
         * Counter + 1 -> Counter
         * we inject now this
         * Counter + 1 -> {Counter, OverflowFlag}
         * Counter + OverflowFlag -> Counter
         */

        /* equivalent c code looks like this
         * Thanks to
         https://preshing.com/20150402/you-can-do-any-kind-of-atomic-read-modify-write-operation/

            int old = atomic_load_explicit(&Counter, memory_order_relaxed);
            int new;
            do {

                 if (old == 255) {

                   new = 1;

                 } else {

                   new = old + 1;

                 }

            } while (!atomic_compare_exchange_weak_explicit(&Counter, &old, new,

         memory_order_relaxed, memory_order_relaxed));

         */

        Value *              MapPtrIdx = val;
        Instruction *        MapPtrIdxInst = cast<Instruction>(val);
        BasicBlock::iterator it0(&(*MapPtrIdxInst));
        ++it0;
        IRBuilder<> IRB(&(*it0));

        // load the old counter value atomically
        LoadInst *Counter = IRB.CreateLoad(
  #if LLVM_VERSION_MAJOR >= 14
        IRB.getInt8Ty(),
  #endif
        MapPtrIdx);
        Counter->setAlignment(llvm::Align());
        Counter->setAtomic(llvm::AtomicOrdering::Monotonic);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        BasicBlock *BB = IRB.GetInsertBlock();
        // insert a basic block with the corpus of a do while loop
        // the calculation may need to repeat, if atomic compare_exchange is not
        // successful

        BasicBlock::iterator it(*Counter);
        it++;  // split after load counter
        BasicBlock *end_bb = BB->splitBasicBlock(it);
        end_bb->setName("injected");

        // insert the block before the second half of the split
        BasicBlock *do_while_bb =
            BasicBlock::Create(C, "injected", end_bb->getParent(), end_bb);

        // set terminator of BB from target end_bb to target do_while_bb
        auto term = BB->getTerminator();
        BranchInst::Create(do_while_bb, BB);
        term->eraseFromParent();

        // continue to fill instructions into the do_while loop
        IRB.SetInsertPoint(do_while_bb, do_while_bb->getFirstInsertionPt());

        PHINode *PN = IRB.CreatePHI(Int8Ty, 2);

        // compare with maximum value 0xff
        auto *Cmp = IRB.CreateICmpEQ(Counter, ConstantInt::get(Int8Ty, -1));

        // increment the counter
        Value *Incr = IRB.CreateAdd(Counter, One);

        // select the counter value or 1
        auto *Select = IRB.CreateSelect(Cmp, One, Incr);

        // try to save back the new counter value
        auto *CmpXchg = IRB.CreateAtomicCmpXchg(
            MapPtrIdx, PN, Select, llvm::AtomicOrdering::Monotonic,
            llvm::AtomicOrdering::Monotonic);
        CmpXchg->setAlignment(llvm::Align());
        CmpXchg->setWeak(true);
        CmpXchg->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        // get the result of trying to update the Counter
        Value *Success =
            IRB.CreateExtractValue(CmpXchg, ArrayRef<unsigned>({1}));
        // get the (possibly updated) value of Counter
        Value *OldVal =
            IRB.CreateExtractValue(CmpXchg, ArrayRef<unsigned>({0}));

        // initially we use Counter
        PN->addIncoming(Counter, BB);
        // on retry, we use the updated value
        PN->addIncoming(OldVal, do_while_bb);

        // if the cmpXchg was not successful, retry
        IRB.CreateCondBr(Success, end_bb, do_while_bb);

      }

    }

#endif

  }

  /*
    // This is currently disabled because we not only need to create/insert a
    // function (easy), but also add it as a constructor with an ID < 5

    if (getenv("AFL_LLVM_DONTWRITEID") == NULL) {

      // yes we could create our own function, insert it into ctors ...
      // but this would be a pain in the butt ... so we use afl-llvm-rt.o

      Function *f = ...

      if (!f) {

        fprintf(stderr,
                "Error: init function could not be created (this should not
    happen)\n"); exit(-1);

      }

      ... constructor for f = 4

      BasicBlock *bb = &f->getEntryBlock();
      if (!bb) {

        fprintf(stderr,
                "Error: init function does not have an EntryBlock (this should
    not happen)\n"); exit(-1);

      }

      BasicBlock::iterator IP = bb->getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));

      if (map_size <= 0x800000) {

        GlobalVariable *AFLFinalLoc = new GlobalVariable(
            M, Int32Ty, true, GlobalValue::ExternalLinkage, 0,
            "__afl_final_loc");
        ConstantInt *const_loc = ConstantInt::get(Int32Ty, map_size);
        StoreInst *  StoreFinalLoc = IRB.CreateStore(const_loc, AFLFinalLoc);
        StoreFinalLoc->setMetadata(M.getMDKindID("nosanitize"),
                                     MDNode::get(C, None));

      }

    }

  */

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else {

      char modeline[100];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
               getenv("AFL_USE_TSAN") ? ", TSAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
      OKF("Instrumented %d locations (%s mode, ratio %u%%).", inst_blocks,
          modeline, inst_ratio);

    }

  }

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  return PA;
#else
  return true;
#endif

}

#if LLVM_VERSION_MAJOR < 11                         /* use old pass manager */
static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
#endif

