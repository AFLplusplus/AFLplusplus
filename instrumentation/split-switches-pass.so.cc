/*
 * Copyright 2016 laf-intel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  #include "llvm/Passes/PassPlugin.h"
  #include "llvm/Passes/PassBuilder.h"
  #include "llvm/IR/PassManager.h"
#else
  #include "llvm/IR/LegacyPassManager.h"
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/ValueTracking.h"
#if LLVM_VERSION_MAJOR >= 14                /* how about stable interfaces? */
  #include "llvm/Passes/OptimizationLevel.h"
#endif

#include "llvm/IR/IRBuilder.h"
#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/Verifier.h"
  #include "llvm/IR/DebugInfo.h"
#else
  #include "llvm/Analysis/Verifier.h"
  #include "llvm/DebugInfo.h"
  #define nullptr 0
#endif

#include <set>
#include "afl-llvm-common.h"

using namespace llvm;

namespace {

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
class SplitSwitchesTransform : public PassInfoMixin<SplitSwitchesTransform> {

 public:
  SplitSwitchesTransform() {

#else
class SplitSwitchesTransform : public ModulePass {

 public:
  static char ID;
  SplitSwitchesTransform() : ModulePass(ID) {

#endif
    initInstrumentList();

  }

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool      runOnModule(Module &M) override;

  #if LLVM_VERSION_MAJOR >= 4
  StringRef getPassName() const override {

  #else
  const char *getPassName() const override {

  #endif
    return "splits switch constructs";

  }

#endif

  struct CaseExpr {

    ConstantInt *Val;
    BasicBlock * BB;

    CaseExpr(ConstantInt *val = nullptr, BasicBlock *bb = nullptr)
        : Val(val), BB(bb) {

    }

  };

  using CaseVector = std::vector<CaseExpr>;

 private:
  bool        splitSwitches(Module &M);
  bool        transformCmps(Module &M, const bool processStrcmp,
                            const bool processMemcmp);
  BasicBlock *switchConvert(CaseVector Cases, std::vector<bool> bytesChecked,
                            BasicBlock *OrigBlock, BasicBlock *NewDefault,
                            Value *Val, unsigned level);

};

}  // namespace

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "splitswitches", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

  #if 1
    #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
    #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(SplitSwitchesTransform());

                });

  /* TODO LTO registration */
  #else
            using PipelineElement = typename PassBuilder::PipelineElement;
            PB.registerPipelineParsingCallback([](StringRef          Name,
                                                  ModulePassManager &MPM,
                                                  ArrayRef<PipelineElement>) {

              if (Name == "splitswitches") {

                MPM.addPass(SplitSwitchesTransform());
                return true;

              } else {

                return false;

              }

            });

  #endif

          }};

}

#else
char SplitSwitchesTransform::ID = 0;
#endif

/* switchConvert - Transform simple list of Cases into list of CaseRange's */
BasicBlock *SplitSwitchesTransform::switchConvert(
    CaseVector Cases, std::vector<bool> bytesChecked, BasicBlock *OrigBlock,
    BasicBlock *NewDefault, Value *Val, unsigned level) {

  unsigned     ValTypeBitWidth = Cases[0].Val->getBitWidth();
  IntegerType *ValType =
      IntegerType::get(OrigBlock->getContext(), ValTypeBitWidth);
  IntegerType *        ByteType = IntegerType::get(OrigBlock->getContext(), 8);
  unsigned             BytesInValue = bytesChecked.size();
  std::vector<uint8_t> setSizes;
  std::vector<std::set<uint8_t> > byteSets(BytesInValue, std::set<uint8_t>());

  /* for each of the possible cases we iterate over all bytes of the values
   * build a set of possible values at each byte position in byteSets */
  for (CaseExpr &Case : Cases) {

    for (unsigned i = 0; i < BytesInValue; i++) {

      uint8_t byte = (Case.Val->getZExtValue() >> (i * 8)) & 0xFF;
      byteSets[i].insert(byte);

    }

  }

  /* find the index of the first byte position that was not yet checked. then
   * save the number of possible values at that byte position */
  unsigned smallestIndex = 0;
  unsigned smallestSize = 257;
  for (unsigned i = 0; i < byteSets.size(); i++) {

    if (bytesChecked[i]) continue;
    if (byteSets[i].size() < smallestSize) {

      smallestIndex = i;
      smallestSize = byteSets[i].size();

    }

  }

  assert(bytesChecked[smallestIndex] == false);

  /* there are only smallestSize different bytes at index smallestIndex */

  Instruction *Shift, *Trunc;
  Function *   F = OrigBlock->getParent();
  BasicBlock * NewNode = BasicBlock::Create(Val->getContext(), "NodeBlock", F);
  Shift = BinaryOperator::Create(Instruction::LShr, Val,
                                 ConstantInt::get(ValType, smallestIndex * 8));
  NewNode->getInstList().push_back(Shift);

  if (ValTypeBitWidth > 8) {

    Trunc = new TruncInst(Shift, ByteType);
    NewNode->getInstList().push_back(Trunc);

  } else {

    /* not necessary to trunc */
    Trunc = Shift;

  }

  /* this is a trivial case, we can directly check for the byte,
   * if the byte is not found go to default. if the byte was found
   * mark the byte as checked. if this was the last byte to check
   * we can finally execute the block belonging to this case */

  if (smallestSize == 1) {

    uint8_t byte = *(byteSets[smallestIndex].begin());

    /* insert instructions to check whether the value we are switching on is
     * equal to byte */
    ICmpInst *Comp =
        new ICmpInst(ICmpInst::ICMP_EQ, Trunc, ConstantInt::get(ByteType, byte),
                     "byteMatch");
    NewNode->getInstList().push_back(Comp);

    bytesChecked[smallestIndex] = true;
    bool allBytesAreChecked = true;

    for (std::vector<bool>::iterator BCI = bytesChecked.begin(),
                                     E = bytesChecked.end();
         BCI != E; ++BCI) {

      if (!*BCI) {

        allBytesAreChecked = false;
        break;

      }

    }

    //    if (std::all_of(bytesChecked.begin(), bytesChecked.end(),
    //                    [](bool b) { return b; })) {

    if (allBytesAreChecked) {

      assert(Cases.size() == 1);
      BranchInst::Create(Cases[0].BB, NewDefault, Comp, NewNode);

      /* we have to update the phi nodes! */
      for (BasicBlock::iterator I = Cases[0].BB->begin();
           I != Cases[0].BB->end(); ++I) {

        if (!isa<PHINode>(&*I)) { continue; }
        PHINode *PN = cast<PHINode>(I);

        /* Only update the first occurrence. */
        unsigned Idx = 0, E = PN->getNumIncomingValues();
        for (; Idx != E; ++Idx) {

          if (PN->getIncomingBlock(Idx) == OrigBlock) {

            PN->setIncomingBlock(Idx, NewNode);
            break;

          }

        }

      }

    } else {

      BasicBlock *BB = switchConvert(Cases, bytesChecked, OrigBlock, NewDefault,
                                     Val, level + 1);
      BranchInst::Create(BB, NewDefault, Comp, NewNode);

    }

  }

  /* there is no byte which we can directly check on, split the tree */
  else {

    std::vector<uint8_t> byteVector;
    std::copy(byteSets[smallestIndex].begin(), byteSets[smallestIndex].end(),
              std::back_inserter(byteVector));
    std::sort(byteVector.begin(), byteVector.end());
    uint8_t pivot = byteVector[byteVector.size() / 2];

    /* we already chose to divide the cases based on the value of byte at index
     * smallestIndex the pivot value determines the threshold for the decicion;
     * if a case value
     * is smaller at this byte index move it to the LHS vector, otherwise to the
     * RHS vector */

    CaseVector LHSCases, RHSCases;

    for (CaseExpr &Case : Cases) {

      uint8_t byte = (Case.Val->getZExtValue() >> (smallestIndex * 8)) & 0xFF;

      if (byte < pivot) {

        LHSCases.push_back(Case);

      } else {

        RHSCases.push_back(Case);

      }

    }

    BasicBlock *LBB, *RBB;
    LBB = switchConvert(LHSCases, bytesChecked, OrigBlock, NewDefault, Val,
                        level + 1);
    RBB = switchConvert(RHSCases, bytesChecked, OrigBlock, NewDefault, Val,
                        level + 1);

    /* insert instructions to check whether the value we are switching on is
     * equal to byte */
    ICmpInst *Comp =
        new ICmpInst(ICmpInst::ICMP_ULT, Trunc,
                     ConstantInt::get(ByteType, pivot), "byteMatch");
    NewNode->getInstList().push_back(Comp);
    BranchInst::Create(LBB, RBB, Comp, NewNode);

  }

  return NewNode;

}

bool SplitSwitchesTransform::splitSwitches(Module &M) {

#if (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 7)
  LLVMContext &C = M.getContext();
#endif

  std::vector<SwitchInst *> switches;

  /* iterate over all functions, bbs and instruction and add
   * all switches to switches vector for later processing */
  for (auto &F : M) {

    if (!isInInstrumentList(&F, MNAME)) continue;

    for (auto &BB : F) {

      SwitchInst *switchInst = nullptr;

      if ((switchInst = dyn_cast<SwitchInst>(BB.getTerminator()))) {

        if (switchInst->getNumCases() < 1) continue;
        switches.push_back(switchInst);

      }

    }

  }

  if (!switches.size()) return false;
  /*
    if (!be_quiet)
      errs() << "Rewriting " << switches.size() << " switch statements "
             << "\n";
  */
  for (auto &SI : switches) {

    BasicBlock *CurBlock = SI->getParent();
    BasicBlock *OrigBlock = CurBlock;
    Function *  F = CurBlock->getParent();
    /* this is the value we are switching on */
    Value *     Val = SI->getCondition();
    BasicBlock *Default = SI->getDefaultDest();
    unsigned    bitw = Val->getType()->getIntegerBitWidth();

    /*
        if (!be_quiet)
          errs() << "switch: " << SI->getNumCases() << " cases " << bitw
                 << " bit\n";
    */

    /* If there is only the default destination or the condition checks 8 bit or
     * less, don't bother with the code below. */
    if (SI->getNumCases() < 2 || bitw % 8 || bitw > 64) {

      // if (!be_quiet) errs() << "skip switch..\n";
      continue;

    }

    /* Create a new, empty default block so that the new hierarchy of
     * if-then statements go to this and the PHI nodes are happy.
     * if the default block is set as an unreachable we avoid creating one
     * because will never be a valid target.*/
    BasicBlock *NewDefault = nullptr;
    NewDefault = BasicBlock::Create(SI->getContext(), "NewDefault", F, Default);
    BranchInst::Create(Default, NewDefault);

    /* Prepare cases vector. */
    CaseVector Cases;
    for (SwitchInst::CaseIt i = SI->case_begin(), e = SI->case_end(); i != e;
         ++i)
#if LLVM_VERSION_MAJOR >= 5
      Cases.push_back(CaseExpr(i->getCaseValue(), i->getCaseSuccessor()));
#else
      Cases.push_back(CaseExpr(i.getCaseValue(), i.getCaseSuccessor()));
#endif
    /* bugfix thanks to pbst
     * round up bytesChecked (in case getBitWidth() % 8 != 0) */
    std::vector<bool> bytesChecked((7 + Cases[0].Val->getBitWidth()) / 8,
                                   false);
    BasicBlock *      SwitchBlock =
        switchConvert(Cases, bytesChecked, OrigBlock, NewDefault, Val, 0);

    /* Branch to our shiny new if-then stuff... */
    BranchInst::Create(SwitchBlock, OrigBlock);

    /* We are now done with the switch instruction, delete it. */
    CurBlock->getInstList().erase(SI);

    /* we have to update the phi nodes! */
    for (BasicBlock::iterator I = Default->begin(); I != Default->end(); ++I) {

      if (!isa<PHINode>(&*I)) { continue; }
      PHINode *PN = cast<PHINode>(I);

      /* Only update the first occurrence. */
      unsigned Idx = 0, E = PN->getNumIncomingValues();
      for (; Idx != E; ++Idx) {

        if (PN->getIncomingBlock(Idx) == OrigBlock) {

          PN->setIncomingBlock(Idx, NewDefault);
          break;

        }

      }

    }

  }

  verifyModule(M);
  return true;

}

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
PreservedAnalyses SplitSwitchesTransform::run(Module &               M,
                                              ModuleAnalysisManager &MAM) {

#else
bool SplitSwitchesTransform::runOnModule(Module &M) {

#endif

  if ((isatty(2) && getenv("AFL_QUIET") == NULL) || getenv("AFL_DEBUG") != NULL)
    printf("Running split-switches-pass by laf.intel@gmail.com\n");
  else
    be_quiet = 1;

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
  auto PA = PreservedAnalyses::all();
#endif

  splitSwitches(M);
  verifyModule(M);

#if LLVM_VERSION_MAJOR >= 11                        /* use new pass manager */
                             /*  if (modified) {
                           
                                 PA.abandon<XX_Manager>();
                           
                               }*/

  return PA;
#else
  return true;
#endif

}

#if LLVM_VERSION_MAJOR < 11                         /* use old pass manager */
static void registerSplitSwitchesTransPass(const PassManagerBuilder &,
                                           legacy::PassManagerBase &PM) {

  auto p = new SplitSwitchesTransform();
  PM.add(p);

}

static RegisterStandardPasses RegisterSplitSwitchesTransPass(
    PassManagerBuilder::EP_OptimizerLast, registerSplitSwitchesTransPass);

static RegisterStandardPasses RegisterSplitSwitchesTransPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerSplitSwitchesTransPass);

  #if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterSplitSwitchesTransPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    registerSplitSwitchesTransPass);
  #endif
#endif

