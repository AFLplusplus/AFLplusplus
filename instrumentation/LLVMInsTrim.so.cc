#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

#include "llvm/Config/llvm-config.h"
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 5
typedef long double max_align_t;
#endif

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/CFG.h"
  #include "llvm/IR/Dominators.h"
  #include "llvm/IR/DebugInfo.h"
#else
  #include "llvm/Support/CFG.h"
  #include "llvm/Analysis/Dominators.h"
  #include "llvm/DebugInfo.h"
#endif
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/BasicBlock.h"
#include <unordered_set>
#include <random>
#include <list>
#include <string>
#include <fstream>

#include "MarkNodes.h"
#include "afl-llvm-common.h"
#include "llvm-alternative-coverage.h"

#include "config.h"
#include "debug.h"

using namespace llvm;

static cl::opt<bool> MarkSetOpt("markset", cl::desc("MarkSet"),
                                cl::init(false));
static cl::opt<bool> LoopHeadOpt("loophead", cl::desc("LoopHead"),
                                 cl::init(false));

namespace {

struct InsTrim : public ModulePass {

 protected:
  uint32_t function_minimum_size = 1;
  char *   skip_nozero = NULL;

 private:
  std::mt19937 generator;
  int          total_instr = 0;

  unsigned int genLabel() {

    return generator() & (MAP_SIZE - 1);

  }

 public:
  static char ID;

  InsTrim() : ModulePass(ID), generator(0) {

    initInstrumentList();

  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {

    AU.addRequired<DominatorTreeWrapperPass>();

  }

#if LLVM_VERSION_MAJOR < 4
  const char *
#else
  StringRef
#endif
  getPassName() const override {

    return "InstTrim Instrumentation";

  }

#if LLVM_VERSION_MAJOR > 4 || \
    (LLVM_VERSION_MAJOR == 4 && LLVM_VERSION_PATCH >= 1)
  #define AFL_HAVE_VECTOR_INTRINSICS 1
#endif

  bool runOnModule(Module &M) override {

    setvbuf(stdout, NULL, _IONBF, 0);

    if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {

      SAYF(cCYA "LLVMInsTrim" VERSION cRST " by csienslab\n");

    } else

      be_quiet = 1;

    if (getenv("AFL_DEBUG") != NULL) debug = 1;

    LLVMContext &C = M.getContext();

    IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

#if LLVM_VERSION_MAJOR < 9
    char *neverZero_counters_str;
    if ((neverZero_counters_str = getenv("AFL_LLVM_NOT_ZERO")) != NULL)
      if (!be_quiet) OKF("LLVM neverZero activated (by hexcoder)\n");
#endif
    skip_nozero = getenv("AFL_LLVM_SKIP_NEVERZERO");

    if (getenv("AFL_LLVM_INSTRIM_LOOPHEAD") != NULL ||
        getenv("LOOPHEAD") != NULL) {

      LoopHeadOpt = true;

    }

    unsigned int PrevLocSize = 0;
    char *       ngram_size_str = getenv("AFL_LLVM_NGRAM_SIZE");
    if (!ngram_size_str) ngram_size_str = getenv("AFL_NGRAM_SIZE");
    char *caller_str = getenv("AFL_LLVM_CALLER");

#ifdef AFL_HAVE_VECTOR_INTRINSICS
    unsigned int ngram_size = 0;
    /* Decide previous location vector size (must be a power of two) */
    VectorType *PrevLocTy = NULL;

    if (ngram_size_str)
      if (sscanf(ngram_size_str, "%u", &ngram_size) != 1 || ngram_size < 2 ||
          ngram_size > NGRAM_SIZE_MAX)
        FATAL(
            "Bad value of AFL_NGRAM_SIZE (must be between 2 and NGRAM_SIZE_MAX "
            "(%u))",
            NGRAM_SIZE_MAX);

    if (ngram_size)
      PrevLocSize = ngram_size - 1;
    else
#else
    if (ngram_size_str)
  #ifdef LLVM_VERSION_STRING
      FATAL(
          "Sorry, NGRAM branch coverage is not supported with llvm version %s!",
          LLVM_VERSION_STRING);
  #else
    #ifndef LLVM_VERSION_PATCH
      FATAL(
          "Sorry, NGRAM branch coverage is not supported with llvm version "
          "%d.%d.%d!",
          LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR, 0);
    #else
      FATAL(
          "Sorry, NGRAM branch coverage is not supported with llvm version "
          "%d.%d.%d!",
          LLVM_VERSION_MAJOR, LLVM_VERSION_MINOR, LLVM_VERISON_PATCH);
    #endif
  #endif
#endif
      PrevLocSize = 1;

#ifdef AFL_HAVE_VECTOR_INTRINSICS
    // IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
    int          PrevLocVecSize = PowerOf2Ceil(PrevLocSize);
    IntegerType *IntLocTy =
        IntegerType::getIntNTy(C, sizeof(PREV_LOC_T) * CHAR_BIT);
    if (ngram_size)
      PrevLocTy = VectorType::get(IntLocTy, PrevLocVecSize
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
    GlobalVariable *AFLContext = NULL;
    LoadInst *      PrevCaller = NULL;  // for CALLER sensitive coverage

    if (caller_str)
#if defined(__ANDROID__) || defined(__HAIKU__)
      AFLContext = new GlobalVariable(
          M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx");
#else
      AFLContext = new GlobalVariable(
          M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx",
          0, GlobalVariable::GeneralDynamicTLSModel, 0, false);
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
    /* Create the vector shuffle mask for updating the previous block history.
       Note that the first element of the vector will store cur_loc, so just set
       it to undef to allow the optimizer to do its thing. */

    SmallVector<Constant *, 32> PrevLocShuffle = {UndefValue::get(Int32Ty)};

    for (unsigned I = 0; I < PrevLocSize - 1; ++I)
      PrevLocShuffle.push_back(ConstantInt::get(Int32Ty, I));

    for (int I = PrevLocSize; I < PrevLocVecSize; ++I)
      PrevLocShuffle.push_back(ConstantInt::get(Int32Ty, PrevLocSize));

    Constant *PrevLocShuffleMask = ConstantVector::get(PrevLocShuffle);
#endif

    // this is our default
    MarkSetOpt = true;

    ConstantInt *Zero = ConstantInt::get(Int8Ty, 0);
    ConstantInt *One = ConstantInt::get(Int8Ty, 1);

    u64 total_rs = 0;
    u64 total_hs = 0;

    scanForDangerousFunctions(&M);

    for (Function &F : M) {

      if (debug) {

        uint32_t bb_cnt = 0;

        for (auto &BB : F)
          if (BB.size() > 0) ++bb_cnt;
        DEBUGF("Function %s size %zu %u\n", F.getName().str().c_str(), F.size(),
               bb_cnt);

      }

      if (!isInInstrumentList(&F)) continue;

      // if the function below our minimum size skip it (1 or 2)
      if (F.size() < function_minimum_size) { continue; }

      std::unordered_set<BasicBlock *> MS;
      if (!MarkSetOpt) {

        for (auto &BB : F) {

          MS.insert(&BB);

        }

        total_rs += F.size();

      } else {

        auto Result = markNodes(&F);
        auto RS = Result.first;
        auto HS = Result.second;

        MS.insert(RS.begin(), RS.end());
        if (!LoopHeadOpt) {

          MS.insert(HS.begin(), HS.end());
          total_rs += MS.size();

        } else {

          DenseSet<std::pair<BasicBlock *, BasicBlock *>> EdgeSet;
          DominatorTreeWrapperPass *                      DTWP =
              &getAnalysis<DominatorTreeWrapperPass>(F);
          auto DT = &DTWP->getDomTree();

          total_rs += RS.size();
          total_hs += HS.size();

          for (BasicBlock *BB : HS) {

            bool Inserted = false;
            for (auto BI = pred_begin(BB), BE = pred_end(BB); BI != BE; ++BI) {

              auto Edge = BasicBlockEdge(*BI, BB);
              if (Edge.isSingleEdge() && DT->dominates(Edge, BB)) {

                EdgeSet.insert({*BI, BB});
                Inserted = true;
                break;

              }

            }

            if (!Inserted) {

              MS.insert(BB);
              total_rs += 1;
              total_hs -= 1;

            }

          }

          for (auto I = EdgeSet.begin(), E = EdgeSet.end(); I != E; ++I) {

            auto PredBB = I->first;
            auto SuccBB = I->second;
            auto NewBB =
                SplitBlockPredecessors(SuccBB, {PredBB}, ".split", DT, nullptr,
#if LLVM_VERSION_MAJOR >= 8
                                       nullptr,
#endif
                                       false);
            MS.insert(NewBB);

          }

        }

        for (BasicBlock &BB : F) {

          if (MS.find(&BB) == MS.end()) { continue; }
          IRBuilder<> IRB(&*BB.getFirstInsertionPt());

#ifdef AFL_HAVE_VECTOR_INTRINSICS
          if (ngram_size) {

            LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
            PrevLoc->setMetadata(M.getMDKindID("nosanitize"),
                                 MDNode::get(C, None));

            Value *ShuffledPrevLoc = IRB.CreateShuffleVector(
                PrevLoc, UndefValue::get(PrevLocTy), PrevLocShuffleMask);
            Value *UpdatedPrevLoc = IRB.CreateInsertElement(
                ShuffledPrevLoc, ConstantInt::get(Int32Ty, genLabel()),
                (uint64_t)0);

            IRB.CreateStore(UpdatedPrevLoc, AFLPrevLoc)
                ->setMetadata(M.getMDKindID("nosanitize"),
                              MDNode::get(C, None));

          } else

#endif
          {

            IRB.CreateStore(ConstantInt::get(Int32Ty, genLabel()), AFLPrevLoc);

          }

        }

      }

      int has_calls = 0;
      for (BasicBlock &BB : F) {

        auto         PI = pred_begin(&BB);
        auto         PE = pred_end(&BB);
        IRBuilder<>  IRB(&*BB.getFirstInsertionPt());
        Value *      L = NULL;
        unsigned int cur_loc;

        // Context sensitive coverage
        if (caller_str && &BB == &F.getEntryBlock()) {

          PrevCaller = IRB.CreateLoad(AFLContext);
          PrevCaller->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));

          // does the function have calls? and is any of the calls larger than
          // one basic block?
          has_calls = 0;
          for (auto &BB2 : F) {

            if (has_calls) break;
            for (auto &IN : BB2) {

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

            ConstantInt *NewCtx = ConstantInt::get(Int32Ty, genLabel());
            StoreInst *  StoreCtx = IRB.CreateStore(NewCtx, AFLContext);
            StoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                  MDNode::get(C, None));

          }

        }  // END of caller_str

        if (MarkSetOpt && MS.find(&BB) == MS.end()) { continue; }

        if (PI == PE) {

          cur_loc = genLabel();
          L = ConstantInt::get(Int32Ty, cur_loc);

        } else {

          auto *PN = PHINode::Create(Int32Ty, 0, "", &*BB.begin());
          DenseMap<BasicBlock *, unsigned> PredMap;
          for (PI = pred_begin(&BB), PE = pred_end(&BB); PI != PE; ++PI) {

            BasicBlock *PBB = *PI;
            auto        It = PredMap.insert({PBB, genLabel()});
            unsigned    Label = It.first->second;
            // cur_loc = Label;
            PN->addIncoming(ConstantInt::get(Int32Ty, Label), PBB);

          }

          L = PN;

        }

        /* Load prev_loc */
        LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
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
          PrevLocTrans = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

        if (caller_str)
          PrevLocTrans =
              IRB.CreateZExt(IRB.CreateXor(PrevLocTrans, PrevCaller), Int32Ty);

        /* Load SHM pointer */
        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MapPtrIdx;
#ifdef AFL_HAVE_VECTOR_INTRINSICS
        if (ngram_size)
          MapPtrIdx = IRB.CreateGEP(
              MapPtr, IRB.CreateZExt(IRB.CreateXor(PrevLocTrans, L), Int32Ty));
        else
#endif
          MapPtrIdx = IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocTrans, L));

        /* Update bitmap */
        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        Value *Incr = IRB.CreateAdd(Counter, One);

#if LLVM_VERSION_MAJOR < 9
        if (neverZero_counters_str !=
            NULL)  // with llvm 9 we make this the default as the bug in llvm is
                   // then fixed
#else
        if (!skip_nozero)
#endif
        {

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
          auto cf = IRB.CreateICmpEQ(Incr, Zero);
          auto carry = IRB.CreateZExt(cf, Int8Ty);
          Incr = IRB.CreateAdd(Incr, carry);

        }

        IRB.CreateStore(Incr, MapPtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        if (caller_str && has_calls) {

          // in CALLER mode we have to restore the original context for the
          // caller - she might be calling other functions which need the
          // correct CALLER
          Instruction *Inst = BB.getTerminator();
          if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {

            IRBuilder<> Post_IRB(Inst);
            StoreInst * RestoreCtx =
                Post_IRB.CreateStore(PrevCaller, AFLContext);
            RestoreCtx->setMetadata(M.getMDKindID("nosanitize"),
                                    MDNode::get(C, None));

          }

        }

        total_instr++;

      }

    }

    if (!be_quiet) {

      char modeline[100];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");

      OKF("Instrumented %d locations (%llu, %llu) (%s mode)\n", total_instr,
          total_rs, total_hs, modeline);

    }

    return false;

  }

};  // end of struct InsTrim

}  // end of anonymous namespace

char InsTrim::ID = 0;

static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new InsTrim());

}

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);

