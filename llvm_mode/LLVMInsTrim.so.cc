#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <unordered_set>
#include <random>

#include "MarkNodes.h"

using namespace llvm;

static cl::opt<bool> MarkSetOpt("markset", cl::desc("MarkSet"),
                                cl::init(false));
static cl::opt<bool> LoopHeadOpt("loophead", cl::desc("LoopHead"),
                                 cl::init(false));

namespace {
  struct InsTrim : public ModulePass {
  private:
    std::mt19937 generator;
    int total_instr = 0;

    unsigned genLabel() {
      return generator() % 65536;
    }

  public:
    static char ID;
    InsTrim() : ModulePass(ID), generator(0) {}

    void getAnalysisUsage(AnalysisUsage &AU) const override {
      AU.addRequired<DominatorTreeWrapperPass>();
    }

    StringRef getPassName() const override {
      return "InstTrim Instrumentation";
    }

    bool runOnModule(Module &M) override {
      if (getenv("LOOPHEAD")) {
        LoopHeadOpt = true;
        MarkSetOpt = true;
      } else if (getenv("MARKSET")) {
        MarkSetOpt = true;
      }

      LLVMContext &C = M.getContext();
      IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
      IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

      GlobalVariable *CovMapPtr = new GlobalVariable(
        M, PointerType::getUnqual(Int8Ty), false, GlobalValue::ExternalLinkage,
        nullptr, "__afl_area_ptr");

      GlobalVariable *OldPrev = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
        0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

      unsigned total_rs = 0;
      unsigned total_hs = 0;

      for (Function &F : M) {
        if (!F.size()) {
          continue;
        }

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
            DominatorTreeWrapperPass *DTWP =
              &getAnalysis<DominatorTreeWrapperPass>(F);
            auto DT = &DTWP->getDomTree();

            total_rs += RS.size();
            total_hs += HS.size();

            for (BasicBlock *BB : HS) {
              bool Inserted = false;
              for (auto BI = pred_begin(BB), BE = pred_end(BB);
                   BI != BE; ++BI
              ) {
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
              auto NewBB = SplitBlockPredecessors(SuccBB, {PredBB}, ".split",
                                                  DT);
              MS.insert(NewBB);
            }
          }

          auto *EBB = &F.getEntryBlock();
          if (succ_begin(EBB) == succ_end(EBB)) {
            MS.insert(EBB);
            total_rs += 1;
          }

          for (BasicBlock &BB : F) {
            if (MS.find(&BB) == MS.end()) {
              continue;
            }
            IRBuilder<> IRB(&*BB.getFirstInsertionPt());
            IRB.CreateStore(ConstantInt::get(Int32Ty, genLabel()), OldPrev);
          }
        }

        for (BasicBlock &BB : F) {
          auto PI = pred_begin(&BB);
          auto PE = pred_end(&BB);
          if (MarkSetOpt && MS.find(&BB) == MS.end()) {
            continue;
          }

          IRBuilder<> IRB(&*BB.getFirstInsertionPt());
          Value *L = NULL;
          if (PI == PE) {
            L = ConstantInt::get(Int32Ty, genLabel());
          } else {
            auto *PN = PHINode::Create(Int32Ty, 0, "", &*BB.begin());
            DenseMap<BasicBlock *, unsigned> PredMap;
            for (auto PI = pred_begin(&BB), PE = pred_end(&BB);
                 PI != PE; ++PI
            ) {
              BasicBlock *PBB = *PI;
              auto It = PredMap.insert({PBB, genLabel()});
              unsigned Label = It.first->second;
              PN->addIncoming(ConstantInt::get(Int32Ty, Label), PBB);
            }
            L = PN;
          }

          LoadInst *PrevLoc = IRB.CreateLoad(OldPrev);
          Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

          LoadInst *MapPtr = IRB.CreateLoad(CovMapPtr);
          Value *MapPtrIdx = IRB.CreateGEP(MapPtr,
                                           IRB.CreateXor(PrevLocCasted, L));

          LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
          Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
          IRB.CreateStore(Incr, MapPtrIdx);
          total_instr++;
        }
      }

      errs() << total_instr << " locations instrumented ("<< total_rs << "," << total_hs << ")\n";
      return false;
    }
  }; // end of struct InsTrim
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
