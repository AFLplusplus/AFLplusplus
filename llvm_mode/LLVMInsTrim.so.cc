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

#include "config.h"
#include "debug.h"

#include "MarkNodes.h"

using namespace llvm;

static cl::opt<bool> MarkSetOpt("markset", cl::desc("MarkSet"),
                                cl::init(false));
static cl::opt<bool> LoopHeadOpt("loophead", cl::desc("LoopHead"),
                                 cl::init(false));

namespace {

struct InsTrim : public ModulePass {

 protected:
  std::list<std::string> myWhitelist;
  uint32_t               function_minimum_size = 1;
  uint32_t               debug = 0;

 private:
  std::mt19937 generator;
  int          total_instr = 0;

  unsigned int genLabel() {

    return generator() & (MAP_SIZE - 1);

  }

 public:
  static char ID;
  InsTrim() : ModulePass(ID), generator(0) {

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

  bool runOnModule(Module &M) override {

    char be_quiet = 0;

    if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {

      SAYF(cCYA "LLVMInsTrim" VERSION cRST " by csienslab\n");

    } else

      be_quiet = 1;

    if (getenv("AFL_DEBUG") != NULL) debug = 1;

#if LLVM_VERSION_MAJOR < 9
    char *neverZero_counters_str;
    if ((neverZero_counters_str = getenv("AFL_LLVM_NOT_ZERO")) != NULL)
      if (!be_quiet) OKF("LLVM neverZero activated (by hexcoder)\n");
#endif

    if (getenv("AFL_LLVM_INSTRIM_LOOPHEAD") != NULL ||
        getenv("LOOPHEAD") != NULL) {

      LoopHeadOpt = true;

    }

    if (getenv("AFL_LLVM_INSTRIM_SKIPSINGLEBLOCK") != NULL)
      function_minimum_size = 2;

    // this is our default
    MarkSetOpt = true;

    LLVMContext &C = M.getContext();
    IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

    GlobalVariable *CovMapPtr = new GlobalVariable(
        M, PointerType::getUnqual(Int8Ty), false, GlobalValue::ExternalLinkage,
        nullptr, "__afl_area_ptr");

    GlobalVariable *OldPrev = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc", 0,
        GlobalVariable::GeneralDynamicTLSModel, 0, false);

    ConstantInt *Zero = ConstantInt::get(Int8Ty, 0);
    ConstantInt *One = ConstantInt::get(Int8Ty, 1);
    ConstantInt *One32 = ConstantInt::get(Int32Ty, 1);

    u64 total_rs = 0;
    u64 total_hs = 0;

    for (Function &F : M) {

      if (debug) {

        uint32_t bb_cnt = 0;

        for (auto &BB : F)
          if (BB.size() > 0) ++bb_cnt;
        SAYF(cMGN "[D] " cRST "Function %s size %zu %u\n",
             F.getName().str().c_str(), F.size(), bb_cnt);

      }

      // if the function below our minimum size skip it (1 or 2)
      if (F.size() < function_minimum_size) { continue; }

      if (!myWhitelist.empty()) {

        bool         instrumentBlock = false;
        DebugLoc     Loc;
        StringRef    instFilename;
        unsigned int instLine = 0;

#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR >= 7)
        for (auto &BB : F) {

          BasicBlock::iterator IP = BB.getFirstInsertionPt();
          IRBuilder<>          IRB(&(*IP));
          if (!Loc) Loc = IP->getDebugLoc();

        }

        if (Loc) {

          DILocation *cDILoc = dyn_cast<DILocation>(Loc.getAsMDNode());

          instLine = cDILoc->getLine();
          instFilename = cDILoc->getFilename();

          if (instFilename.str().empty()) {

            /* If the original location is empty, try using the inlined location
             */
            DILocation *oDILoc = cDILoc->getInlinedAt();
            if (oDILoc) {

              instFilename = oDILoc->getFilename();
              instLine = oDILoc->getLine();

            }

          }

          /* Continue only if we know where we actually are */
          if (!instFilename.str().empty()) {

            for (std::list<std::string>::iterator it = myWhitelist.begin();
                 it != myWhitelist.end(); ++it) {

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
        for (auto &BB : F) {

          BasicBlock::iterator IP = BB.getFirstInsertionPt();
          IRBuilder<>          IRB(&(*IP));
          if (Loc.isUnknown()) Loc = IP->getDebugLoc();

        }

        if (!Loc.isUnknown()) {

          DILocation cDILoc(Loc.getAsMDNode(C));

          instLine = cDILoc.getLineNumber();
          instFilename = cDILoc.getFilename();

          /* Continue only if we know where we actually are */
          if (!instFilename.str().empty()) {

            for (std::list<std::string>::iterator it = myWhitelist.begin();
                 it != myWhitelist.end(); ++it) {

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
        if (!instrumentBlock) {

          if (!be_quiet) {

            if (!instFilename.str().empty())
              SAYF(cYEL "[!] " cBRI
                        "Not in whitelist, skipping %s line %u...\n",
                   instFilename.str().c_str(), instLine);
            else
              SAYF(cYEL "[!] " cBRI
                        "No filename information found, skipping it");

          }

          continue;

        }

      }

      if (isBlacklisted(&F)) continue;

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

        if (function_minimum_size < 2) {

          for (BasicBlock &BB : F) {

            if (MS.find(&BB) == MS.end()) { continue; }
            IRBuilder<> IRB(&*BB.getFirstInsertionPt());
            IRB.CreateStore(ConstantInt::get(Int32Ty, genLabel()), OldPrev);

          }

        }

      }

      for (BasicBlock &BB : F) {

        if (MarkSetOpt && MS.find(&BB) == MS.end()) { continue; }

        auto        PI = pred_begin(&BB);
        auto        PE = pred_end(&BB);
        IRBuilder<> IRB(&*BB.getFirstInsertionPt());
        Value *     L = NULL;

        if (function_minimum_size < 2 && PI == PE) {

          L = ConstantInt::get(Int32Ty, genLabel());

        } else {

          auto *PN = PHINode::Create(Int32Ty, 0, "", &*BB.begin());
          DenseMap<BasicBlock *, unsigned> PredMap;
          for (auto PI = pred_begin(&BB), PE = pred_end(&BB); PI != PE; ++PI) {

            BasicBlock *PBB = *PI;
            auto        It = PredMap.insert({PBB, genLabel()});
            unsigned    Label = It.first->second;
            PN->addIncoming(ConstantInt::get(Int32Ty, Label), PBB);

          }

          L = PN;

        }

        /* Load prev_loc */
        LoadInst *PrevLoc = IRB.CreateLoad(OldPrev);
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

        /* Load SHM pointer */
        LoadInst *MapPtr = IRB.CreateLoad(CovMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MapPtrIdx =
            IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, L));

        /* Update bitmap */
        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        Value *Incr = IRB.CreateAdd(Counter, One);

#if LLVM_VERSION_MAJOR < 9
        if (neverZero_counters_str !=
            NULL)  // with llvm 9 we make this the default as the bug in llvm is
                   // then fixed
#else
        if (1)  // with llvm 9 we make this the default as the bug in llvm is
                // then fixed
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

        // save the actually location ID to OldPrev if function_minimum_size > 1
        if (function_minimum_size > 1) {

          Value *Shr = IRB.CreateLShr(L, One32);
          IRB.CreateStore(Shr, OldPrev)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

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

      OKF("Instrumented %u locations (%llu, %llu) (%s mode)\n", total_instr,
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

