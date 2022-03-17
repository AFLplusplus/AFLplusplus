/*
 * Copyright 2016 laf-intel
 * extended for floating point by Heiko Eißfeldt
 * adapted to new pass manager by Heiko Eißfeldt
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

#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

#if LLVM_MAJOR >= 11
  #include "llvm/Passes/PassPlugin.h"
  #include "llvm/Passes/PassBuilder.h"
  #include "llvm/IR/PassManager.h"
#else
  #include "llvm/IR/LegacyPassManager.h"
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/Module.h"
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

using namespace llvm;
#include "afl-llvm-common.h"

// uncomment this toggle function verification at each step. horribly slow, but
// helps to pinpoint a potential problem in the splitting code.
//#define VERIFY_TOO_MUCH 1

namespace {

#if LLVM_MAJOR >= 11
class SplitComparesTransform : public PassInfoMixin<SplitComparesTransform> {

 public:
  //  static char ID;
  SplitComparesTransform() : enableFPSplit(0) {

#else
class SplitComparesTransform : public ModulePass {

 public:
  static char ID;
  SplitComparesTransform() : ModulePass(ID), enableFPSplit(0) {

#endif

    initInstrumentList();

  }

#if LLVM_MAJOR >= 11
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif

 private:
  int enableFPSplit;

  unsigned target_bitwidth = 8;

  size_t count = 0;

  size_t splitFPCompares(Module &M);
  bool   simplifyFPCompares(Module &M);
  size_t nextPowerOfTwo(size_t in);

  using CmpWorklist = SmallVector<CmpInst *, 8>;

  /// simplify the comparison and then split the comparison until the
  /// target_bitwidth is reached.
  bool simplifyAndSplit(CmpInst *I, Module &M);
  /// simplify a non-strict comparison (e.g., less than or equals)
  bool simplifyOrEqualsCompare(CmpInst *IcmpInst, Module &M,
                               CmpWorklist &worklist);
  /// simplify a signed comparison (signed less or greater than)
  bool simplifySignedCompare(CmpInst *IcmpInst, Module &M,
                             CmpWorklist &worklist);
  /// splits an icmp into nested icmps recursivly until target_bitwidth is
  /// reached
  bool splitCompare(CmpInst *I, Module &M, CmpWorklist &worklist);

  /// print an error to llvm's errs stream, but only if not ordered to be quiet
  void reportError(const StringRef msg, Instruction *I, Module &M) {

    if (!be_quiet) {

      errs() << "[AFL++ SplitComparesTransform] ERROR: " << msg << "\n";
      if (debug) {

        if (I) {

          errs() << "Instruction = " << *I << "\n";
          if (auto BB = I->getParent()) {

            if (auto F = BB->getParent()) {

              if (F->hasName()) {

                errs() << "|-> in function " << F->getName() << " ";

              }

            }

          }

        }

        auto n = M.getName();
        if (n.size() > 0) { errs() << "in module " << n << "\n"; }

      }

    }

  }

  bool isSupportedBitWidth(unsigned bitw) {

    // IDK whether the icmp code works on other bitwidths. I guess not? So we
    // try to avoid dealing with other weird icmp's that llvm might use (looking
    // at you `icmp i0`).
    switch (bitw) {

      case 8:
      case 16:
      case 32:
      case 64:
      case 128:
      case 256:
        return true;
      default:
        return false;

    }

  }

};

}  // namespace

#if LLVM_MAJOR >= 11
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "splitcompares", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

  #if 1
    #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
    #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(SplitComparesTransform());

                });

  /* TODO LTO registration */
  #else
            using PipelineElement = typename PassBuilder::PipelineElement;
            PB.registerPipelineParsingCallback([](StringRef          Name,
                                                  ModulePassManager &MPM,
                                                  ArrayRef<PipelineElement>) {

              if (Name == "splitcompares") {

                MPM.addPass(SplitComparesTransform());
                return true;

              } else {

                return false;

              }

            });

  #endif

          }};

}

#else
char SplitComparesTransform::ID = 0;
#endif

/// This function splits FCMP instructions with xGE or xLE predicates into two
/// FCMP instructions with predicate xGT or xLT and EQ
bool SplitComparesTransform::simplifyFPCompares(Module &M) {

  LLVMContext &              C = M.getContext();
  std::vector<Instruction *> fcomps;
  IntegerType *              Int1Ty = IntegerType::getInt1Ty(C);

  /* iterate over all functions, bbs and instruction and add
   * all integer comparisons with >= and <= predicates to the icomps vector */
  for (auto &F : M) {

    if (!isInInstrumentList(&F, MNAME)) continue;

    for (auto &BB : F) {

      for (auto &IN : BB) {

        CmpInst *selectcmpInst = nullptr;

        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {

          if (enableFPSplit &&
              (selectcmpInst->getPredicate() == CmpInst::FCMP_OGE ||
               selectcmpInst->getPredicate() == CmpInst::FCMP_UGE ||
               selectcmpInst->getPredicate() == CmpInst::FCMP_OLE ||
               selectcmpInst->getPredicate() == CmpInst::FCMP_ULE)) {

            auto op0 = selectcmpInst->getOperand(0);
            auto op1 = selectcmpInst->getOperand(1);

            Type *TyOp0 = op0->getType();
            Type *TyOp1 = op1->getType();

            /* this is probably not needed but we do it anyway */
            if (TyOp0 != TyOp1) { continue; }

            if (TyOp0->isArrayTy() || TyOp0->isVectorTy()) { continue; }

            fcomps.push_back(selectcmpInst);

          }

        }

      }

    }

  }

  if (!fcomps.size()) { return false; }

  /* transform for floating point */
  for (auto &FcmpInst : fcomps) {

    BasicBlock *bb = FcmpInst->getParent();

    auto op0 = FcmpInst->getOperand(0);
    auto op1 = FcmpInst->getOperand(1);

    /* find out what the new predicate is going to be */
    auto cmp_inst = dyn_cast<CmpInst>(FcmpInst);
    if (!cmp_inst) { continue; }
    auto               pred = cmp_inst->getPredicate();
    CmpInst::Predicate new_pred;

    switch (pred) {

      case CmpInst::FCMP_UGE:
        new_pred = CmpInst::FCMP_UGT;
        break;
      case CmpInst::FCMP_OGE:
        new_pred = CmpInst::FCMP_OGT;
        break;
      case CmpInst::FCMP_ULE:
        new_pred = CmpInst::FCMP_ULT;
        break;
      case CmpInst::FCMP_OLE:
        new_pred = CmpInst::FCMP_OLT;
        break;
      default:  // keep the compiler happy
        continue;

    }

    /* split before the fcmp instruction */
    BasicBlock *end_bb = bb->splitBasicBlock(BasicBlock::iterator(FcmpInst));

    /* the old bb now contains a unconditional jump to the new one (end_bb)
     * we need to delete it later */

    /* create the FCMP instruction with new_pred and add it to the old basic
     * block bb it is now at the position where the old FcmpInst was */
    Instruction *fcmp_np;
    fcmp_np = CmpInst::Create(Instruction::FCmp, new_pred, op0, op1);
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()),
                             fcmp_np);

    /* create a new basic block which holds the new EQ fcmp */
    Instruction *fcmp_eq;
    /* insert middle_bb before end_bb */
    BasicBlock *middle_bb =
        BasicBlock::Create(C, "injected", end_bb->getParent(), end_bb);
    fcmp_eq = CmpInst::Create(Instruction::FCmp, CmpInst::FCMP_OEQ, op0, op1);
    middle_bb->getInstList().push_back(fcmp_eq);
    /* add an unconditional branch to the end of middle_bb with destination
     * end_bb */
    BranchInst::Create(end_bb, middle_bb);

    /* replace the uncond branch with a conditional one, which depends on the
     * new_pred fcmp. True goes to end, false to the middle (injected) bb */
    auto term = bb->getTerminator();
    BranchInst::Create(end_bb, middle_bb, fcmp_np, bb);
    term->eraseFromParent();

    /* replace the old FcmpInst (which is the first inst in end_bb) with a PHI
     * inst to wire up the loose ends */
    PHINode *PN = PHINode::Create(Int1Ty, 2, "");
    /* the first result depends on the outcome of fcmp_eq */
    PN->addIncoming(fcmp_eq, middle_bb);
    /* if the source was the original bb we know that the fcmp_np yielded true
     * hence we can hardcode this value */
    PN->addIncoming(ConstantInt::get(Int1Ty, 1), bb);
    /* replace the old FcmpInst with our new and shiny PHI inst */
    BasicBlock::iterator ii(FcmpInst);
    ReplaceInstWithInst(FcmpInst->getParent()->getInstList(), ii, PN);

  }

  return true;

}

/// This function splits ICMP instructions with xGE or xLE predicates into two
/// ICMP instructions with predicate xGT or xLT and EQ
bool SplitComparesTransform::simplifyOrEqualsCompare(CmpInst *    IcmpInst,
                                                     Module &     M,
                                                     CmpWorklist &worklist) {

  LLVMContext &C = M.getContext();
  IntegerType *Int1Ty = IntegerType::getInt1Ty(C);

  /* find out what the new predicate is going to be */
  auto cmp_inst = dyn_cast<CmpInst>(IcmpInst);
  if (!cmp_inst) { return false; }

  BasicBlock *bb = IcmpInst->getParent();

  auto op0 = IcmpInst->getOperand(0);
  auto op1 = IcmpInst->getOperand(1);

  CmpInst::Predicate pred = cmp_inst->getPredicate();
  CmpInst::Predicate new_pred;

  switch (pred) {

    case CmpInst::ICMP_UGE:
      new_pred = CmpInst::ICMP_UGT;
      break;
    case CmpInst::ICMP_SGE:
      new_pred = CmpInst::ICMP_SGT;
      break;
    case CmpInst::ICMP_ULE:
      new_pred = CmpInst::ICMP_ULT;
      break;
    case CmpInst::ICMP_SLE:
      new_pred = CmpInst::ICMP_SLT;
      break;
    default:  // keep the compiler happy
      return false;

  }

  /* split before the icmp instruction */
  BasicBlock *end_bb = bb->splitBasicBlock(BasicBlock::iterator(IcmpInst));

  /* the old bb now contains a unconditional jump to the new one (end_bb)
   * we need to delete it later */

  /* create the ICMP instruction with new_pred and add it to the old basic
   * block bb it is now at the position where the old IcmpInst was */
  CmpInst *icmp_np = CmpInst::Create(Instruction::ICmp, new_pred, op0, op1);
  bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()), icmp_np);

  /* create a new basic block which holds the new EQ icmp */
  CmpInst *icmp_eq;
  /* insert middle_bb before end_bb */
  BasicBlock *middle_bb =
      BasicBlock::Create(C, "injected", end_bb->getParent(), end_bb);
  icmp_eq = CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_EQ, op0, op1);
  middle_bb->getInstList().push_back(icmp_eq);
  /* add an unconditional branch to the end of middle_bb with destination
   * end_bb */
  BranchInst::Create(end_bb, middle_bb);

  /* replace the uncond branch with a conditional one, which depends on the
   * new_pred icmp. True goes to end, false to the middle (injected) bb */
  auto term = bb->getTerminator();
  BranchInst::Create(end_bb, middle_bb, icmp_np, bb);
  term->eraseFromParent();

  /* replace the old IcmpInst (which is the first inst in end_bb) with a PHI
   * inst to wire up the loose ends */
  PHINode *PN = PHINode::Create(Int1Ty, 2, "");
  /* the first result depends on the outcome of icmp_eq */
  PN->addIncoming(icmp_eq, middle_bb);
  /* if the source was the original bb we know that the icmp_np yielded true
   * hence we can hardcode this value */
  PN->addIncoming(ConstantInt::get(Int1Ty, 1), bb);
  /* replace the old IcmpInst with our new and shiny PHI inst */
  BasicBlock::iterator ii(IcmpInst);
  ReplaceInstWithInst(IcmpInst->getParent()->getInstList(), ii, PN);

  worklist.push_back(icmp_np);
  worklist.push_back(icmp_eq);

  return true;

}

/// Simplify a signed comparison operator by splitting it into a unsigned and
/// bit comparison. add all resulting comparisons to
/// the worklist passed as a reference.
bool SplitComparesTransform::simplifySignedCompare(CmpInst *IcmpInst, Module &M,
                                                   CmpWorklist &worklist) {

  LLVMContext &C = M.getContext();
  IntegerType *Int1Ty = IntegerType::getInt1Ty(C);

  BasicBlock *bb = IcmpInst->getParent();

  auto op0 = IcmpInst->getOperand(0);
  auto op1 = IcmpInst->getOperand(1);

  IntegerType *intTyOp0 = dyn_cast<IntegerType>(op0->getType());
  if (!intTyOp0) { return false; }
  unsigned     bitw = intTyOp0->getBitWidth();
  IntegerType *IntType = IntegerType::get(C, bitw);

  /* get the new predicate */
  auto cmp_inst = dyn_cast<CmpInst>(IcmpInst);
  if (!cmp_inst) { return false; }
  auto               pred = cmp_inst->getPredicate();
  CmpInst::Predicate new_pred;

  if (pred == CmpInst::ICMP_SGT) {

    new_pred = CmpInst::ICMP_UGT;

  } else {

    new_pred = CmpInst::ICMP_ULT;

  }

  BasicBlock *end_bb = bb->splitBasicBlock(BasicBlock::iterator(IcmpInst));

  /* create a 1 bit compare for the sign bit. to do this shift and trunc
   * the original operands so only the first bit remains.*/
  Value *s_op0, *t_op0, *s_op1, *t_op1, *icmp_sign_bit;

  IRBuilder<> IRB(bb->getTerminator());
  s_op0 = IRB.CreateLShr(op0, ConstantInt::get(IntType, bitw - 1));
  t_op0 = IRB.CreateTruncOrBitCast(s_op0, Int1Ty);
  s_op1 = IRB.CreateLShr(op1, ConstantInt::get(IntType, bitw - 1));
  t_op1 = IRB.CreateTruncOrBitCast(s_op1, Int1Ty);
  /* compare of the sign bits */
  icmp_sign_bit = IRB.CreateICmp(CmpInst::ICMP_EQ, t_op0, t_op1);

  /* create a new basic block which is executed if the signedness bit is
   * different */
  CmpInst *   icmp_inv_sig_cmp;
  BasicBlock *sign_bb =
      BasicBlock::Create(C, "sign", end_bb->getParent(), end_bb);
  if (pred == CmpInst::ICMP_SGT) {

    /* if we check for > and the op0 positive and op1 negative then the final
     * result is true. if op0 negative and op1 pos, the cmp must result
     * in false
     */
    icmp_inv_sig_cmp =
        CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_ULT, t_op0, t_op1);

  } else {

    /* just the inverse of the above statement */
    icmp_inv_sig_cmp =
        CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_UGT, t_op0, t_op1);

  }

  sign_bb->getInstList().push_back(icmp_inv_sig_cmp);
  BranchInst::Create(end_bb, sign_bb);

  /* create a new bb which is executed if signedness is equal */
  CmpInst *   icmp_usign_cmp;
  BasicBlock *middle_bb =
      BasicBlock::Create(C, "injected", end_bb->getParent(), end_bb);
  /* we can do a normal unsigned compare now */
  icmp_usign_cmp = CmpInst::Create(Instruction::ICmp, new_pred, op0, op1);

  middle_bb->getInstList().push_back(icmp_usign_cmp);
  BranchInst::Create(end_bb, middle_bb);

  auto term = bb->getTerminator();
  /* if the sign is eq do a normal unsigned cmp, else we have to check the
   * signedness bit */
  BranchInst::Create(middle_bb, sign_bb, icmp_sign_bit, bb);
  term->eraseFromParent();

  PHINode *PN = PHINode::Create(Int1Ty, 2, "");

  PN->addIncoming(icmp_usign_cmp, middle_bb);
  PN->addIncoming(icmp_inv_sig_cmp, sign_bb);

  BasicBlock::iterator ii(IcmpInst);
  ReplaceInstWithInst(IcmpInst->getParent()->getInstList(), ii, PN);

  // save for later
  worklist.push_back(icmp_usign_cmp);

  // signed comparisons are not supported by the splitting code, so we must not
  // add it to the worklist.
  // worklist.push_back(icmp_inv_sig_cmp);

  return true;

}

bool SplitComparesTransform::splitCompare(CmpInst *cmp_inst, Module &M,
                                          CmpWorklist &worklist) {

  auto pred = cmp_inst->getPredicate();
  switch (pred) {

    case CmpInst::ICMP_EQ:
    case CmpInst::ICMP_NE:
    case CmpInst::ICMP_UGT:
    case CmpInst::ICMP_ULT:
      break;
    default:
      // unsupported predicate!
      return false;

  }

  auto op0 = cmp_inst->getOperand(0);
  auto op1 = cmp_inst->getOperand(1);

  // get bitwidth by checking the bitwidth of the first operator
  IntegerType *intTyOp0 = dyn_cast<IntegerType>(op0->getType());
  if (!intTyOp0) {

    // not an integer type
    return false;

  }

  unsigned bitw = intTyOp0->getBitWidth();
  if (bitw == target_bitwidth) {

    // already the target bitwidth so we have to do nothing here.
    return true;

  }

  LLVMContext &C = M.getContext();
  IntegerType *Int1Ty = IntegerType::getInt1Ty(C);
  BasicBlock * bb = cmp_inst->getParent();
  IntegerType *OldIntType = IntegerType::get(C, bitw);
  IntegerType *NewIntType = IntegerType::get(C, bitw / 2);
  BasicBlock * end_bb = bb->splitBasicBlock(BasicBlock::iterator(cmp_inst));
  CmpInst *    icmp_high, *icmp_low;

  /* create the comparison of the top halves of the original operands */
  Value *s_op0, *op0_high, *s_op1, *op1_high;

  IRBuilder<> IRB(bb->getTerminator());

  s_op0 = IRB.CreateBinOp(Instruction::LShr, op0,
                          ConstantInt::get(OldIntType, bitw / 2));
  op0_high = IRB.CreateTruncOrBitCast(s_op0, NewIntType);

  s_op1 = IRB.CreateBinOp(Instruction::LShr, op1,
                          ConstantInt::get(OldIntType, bitw / 2));
  op1_high = IRB.CreateTruncOrBitCast(s_op1, NewIntType);
  icmp_high = cast<CmpInst>(IRB.CreateICmp(pred, op0_high, op1_high));

  PHINode *PN = nullptr;

  /* now we have to destinguish between == != and > < */
  switch (pred) {

    case CmpInst::ICMP_EQ:
    case CmpInst::ICMP_NE: {

      /* transformation for == and != icmps */

      /* create a compare for the lower half of the original operands */
      BasicBlock *cmp_low_bb =
          BasicBlock::Create(C, "" /*"injected"*/, end_bb->getParent(), end_bb);

      Value *     op0_low, *op1_low;
      IRBuilder<> Builder(cmp_low_bb);

      op0_low = Builder.CreateTrunc(op0, NewIntType);
      op1_low = Builder.CreateTrunc(op1, NewIntType);
      icmp_low = cast<CmpInst>(Builder.CreateICmp(pred, op0_low, op1_low));

      BranchInst::Create(end_bb, cmp_low_bb);

      /* dependent on the cmp of the high parts go to the end or go on with
       * the comparison */
      auto term = bb->getTerminator();

      if (pred == CmpInst::ICMP_EQ) {

        BranchInst::Create(cmp_low_bb, end_bb, icmp_high, bb);

      } else {

        // CmpInst::ICMP_NE
        BranchInst::Create(end_bb, cmp_low_bb, icmp_high, bb);

      }

      term->eraseFromParent();

      /* create the PHI and connect the edges accordingly */
      PN = PHINode::Create(Int1Ty, 2, "");
      PN->addIncoming(icmp_low, cmp_low_bb);
      Value *val = nullptr;
      if (pred == CmpInst::ICMP_EQ) {

        val = ConstantInt::get(Int1Ty, 0);

      } else {

        /* CmpInst::ICMP_NE */
        val = ConstantInt::get(Int1Ty, 1);

      }

      PN->addIncoming(val, icmp_high->getParent());
      break;

    }

    case CmpInst::ICMP_UGT:
    case CmpInst::ICMP_ULT: {

      /* transformations for < and > */

      /* create a basic block which checks for the inverse predicate.
       * if this is true we can go to the end if not we have to go to the
       * bb which checks the lower half of the operands */
      Instruction *op0_low, *op1_low;
      CmpInst *    icmp_inv_cmp = nullptr;
      BasicBlock * inv_cmp_bb =
          BasicBlock::Create(C, "inv_cmp", end_bb->getParent(), end_bb);
      if (pred == CmpInst::ICMP_UGT) {

        icmp_inv_cmp = CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_ULT,
                                       op0_high, op1_high);

      } else {

        icmp_inv_cmp = CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_UGT,
                                       op0_high, op1_high);

      }

      inv_cmp_bb->getInstList().push_back(icmp_inv_cmp);
      worklist.push_back(icmp_inv_cmp);

      auto term = bb->getTerminator();
      term->eraseFromParent();
      BranchInst::Create(end_bb, inv_cmp_bb, icmp_high, bb);

      /* create a bb which handles the cmp of the lower halves */
      BasicBlock *cmp_low_bb =
          BasicBlock::Create(C, "" /*"injected"*/, end_bb->getParent(), end_bb);
      op0_low = new TruncInst(op0, NewIntType);
      cmp_low_bb->getInstList().push_back(op0_low);
      op1_low = new TruncInst(op1, NewIntType);
      cmp_low_bb->getInstList().push_back(op1_low);

      icmp_low = CmpInst::Create(Instruction::ICmp, pred, op0_low, op1_low);
      cmp_low_bb->getInstList().push_back(icmp_low);
      BranchInst::Create(end_bb, cmp_low_bb);

      BranchInst::Create(end_bb, cmp_low_bb, icmp_inv_cmp, inv_cmp_bb);

      PN = PHINode::Create(Int1Ty, 3);
      PN->addIncoming(icmp_low, cmp_low_bb);
      PN->addIncoming(ConstantInt::get(Int1Ty, 1), bb);
      PN->addIncoming(ConstantInt::get(Int1Ty, 0), inv_cmp_bb);
      break;

    }

    default:
      return false;

  }

  BasicBlock::iterator ii(cmp_inst);
  ReplaceInstWithInst(cmp_inst->getParent()->getInstList(), ii, PN);

  // We split the comparison into low and high. If this isn't our target
  // bitwidth we recursively split the low and high parts again until we have
  // target bitwidth.
  if ((bitw / 2) > target_bitwidth) {

    worklist.push_back(icmp_high);
    worklist.push_back(icmp_low);

  }

  return true;

}

bool SplitComparesTransform::simplifyAndSplit(CmpInst *I, Module &M) {

  CmpWorklist worklist;

  auto op0 = I->getOperand(0);
  auto op1 = I->getOperand(1);
  if (!op0 || !op1) { return false; }
  auto op0Ty = dyn_cast<IntegerType>(op0->getType());
  if (!op0Ty || !isa<IntegerType>(op1->getType())) { return true; }

  unsigned bitw = op0Ty->getBitWidth();

#ifdef VERIFY_TOO_MUCH
  auto F = I->getParent()->getParent();
#endif

  // we run the comparison simplification on all compares regardless of their
  // bitwidth.
  if (I->getPredicate() == CmpInst::ICMP_UGE ||
      I->getPredicate() == CmpInst::ICMP_SGE ||
      I->getPredicate() == CmpInst::ICMP_ULE ||
      I->getPredicate() == CmpInst::ICMP_SLE) {

    if (!simplifyOrEqualsCompare(I, M, worklist)) {

      reportError(
          "Failed to simplify inequality or equals comparison "
          "(UGE,SGE,ULE,SLE)",
          I, M);

    }

  } else if (I->getPredicate() == CmpInst::ICMP_SGT ||

             I->getPredicate() == CmpInst::ICMP_SLT) {

    if (!simplifySignedCompare(I, M, worklist)) {

      reportError("Failed to simplify signed comparison (SGT,SLT)", I, M);

    }

  }

#ifdef VERIFY_TOO_MUCH
  if (verifyFunction(*F, &errs())) {

    reportError("simpliyfing compare lead to broken function", nullptr, M);

  }

#endif

  // the simplification methods replace the original CmpInst and push the
  // resulting new CmpInst into the worklist. If the worklist is empty then
  // we only have to split the original CmpInst.
  if (worklist.size() == 0) { worklist.push_back(I); }

  while (!worklist.empty()) {

    CmpInst *cmp = worklist.pop_back_val();
    // we split the simplified compares into comparisons with smaller bitwidths
    // if they are larger than our target_bitwidth.
    if (bitw > target_bitwidth) {

      if (!splitCompare(cmp, M, worklist)) {

        reportError("Failed to split comparison", cmp, M);

      }

#ifdef VERIFY_TOO_MUCH
      if (verifyFunction(*F, &errs())) {

        reportError("splitting compare lead to broken function", nullptr, M);

      }

#endif

    }

  }

  count++;
  return true;

}

size_t SplitComparesTransform::nextPowerOfTwo(size_t in) {

  --in;
  in |= in >> 1;
  in |= in >> 2;
  in |= in >> 4;
  //  in |= in >> 8;
  //  in |= in >> 16;
  return in + 1;

}

/* splits fcmps into two nested fcmps with sign compare and the rest */
size_t SplitComparesTransform::splitFPCompares(Module &M) {

  size_t count = 0;

  LLVMContext &C = M.getContext();

#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 7)
  const DataLayout &dl = M.getDataLayout();

  /* define unions with floating point and (sign, exponent, mantissa)  triples
   */
  if (dl.isLittleEndian()) {

  } else if (dl.isBigEndian()) {

  } else {

    return count;

  }

#endif

  std::vector<CmpInst *> fcomps;

  /* get all EQ, NE, GT, and LT fcmps. if the other two
   * functions were executed only these four predicates should exist */
  for (auto &F : M) {

    if (!isInInstrumentList(&F, MNAME)) continue;

    for (auto &BB : F) {

      for (auto &IN : BB) {

        CmpInst *selectcmpInst = nullptr;

        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {

          if (selectcmpInst->getPredicate() == CmpInst::FCMP_OEQ ||
              selectcmpInst->getPredicate() == CmpInst::FCMP_UEQ ||
              selectcmpInst->getPredicate() == CmpInst::FCMP_ONE ||
              selectcmpInst->getPredicate() == CmpInst::FCMP_UNE ||
              selectcmpInst->getPredicate() == CmpInst::FCMP_UGT ||
              selectcmpInst->getPredicate() == CmpInst::FCMP_OGT ||
              selectcmpInst->getPredicate() == CmpInst::FCMP_ULT ||
              selectcmpInst->getPredicate() == CmpInst::FCMP_OLT) {

            auto op0 = selectcmpInst->getOperand(0);
            auto op1 = selectcmpInst->getOperand(1);

            Type *TyOp0 = op0->getType();
            Type *TyOp1 = op1->getType();

            if (TyOp0 != TyOp1) { continue; }

            if (TyOp0->isArrayTy() || TyOp0->isVectorTy()) { continue; }

            fcomps.push_back(selectcmpInst);

          }

        }

      }

    }

  }

  if (!fcomps.size()) { return count; }

  IntegerType *Int1Ty = IntegerType::getInt1Ty(C);

  for (auto &FcmpInst : fcomps) {

    BasicBlock *bb = FcmpInst->getParent();

    auto op0 = FcmpInst->getOperand(0);
    auto op1 = FcmpInst->getOperand(1);

    unsigned op_size;
    op_size = op0->getType()->getPrimitiveSizeInBits();

    if (op_size != op1->getType()->getPrimitiveSizeInBits()) { continue; }

    const unsigned int sizeInBits = op0->getType()->getPrimitiveSizeInBits();

    // BUG FIXME TODO: u64 does not work for > 64 bit ... e.g. 80 and 128 bit
    if (sizeInBits > 64) { continue; }

    IntegerType *      intType = IntegerType::get(C, op_size);
    const unsigned int precision = sizeInBits == 32    ? 24
                                   : sizeInBits == 64  ? 53
                                   : sizeInBits == 128 ? 113
                                   : sizeInBits == 16  ? 11
                                   : sizeInBits == 80  ? 65
                                                       : sizeInBits - 8;

    const unsigned           shiftR_exponent = precision - 1;
    const unsigned long long mask_fraction =
        (1ULL << (shiftR_exponent - 1)) | ((1ULL << (shiftR_exponent - 1)) - 1);
    const unsigned long long mask_exponent =
        (1ULL << (sizeInBits - precision)) - 1;

    // round up sizes to the next power of two
    // this should help with integer compare splitting
    size_t exTySizeBytes = ((sizeInBits - precision + 7) >> 3);
    size_t frTySizeBytes = ((precision - 1ULL + 7) >> 3);

    IntegerType *IntExponentTy =
        IntegerType::get(C, nextPowerOfTwo(exTySizeBytes) << 3);
    IntegerType *IntFractionTy =
        IntegerType::get(C, nextPowerOfTwo(frTySizeBytes) << 3);

    //    errs() << "Fractions: IntFractionTy size " <<
    //     IntFractionTy->getPrimitiveSizeInBits() << ", op_size " << op_size <<
    //     ", mask " << mask_fraction <<
    //     ", precision " << precision << "\n";

    BasicBlock *end_bb = bb->splitBasicBlock(BasicBlock::iterator(FcmpInst));

    /* create the integers from floats directly */
    Instruction *bpre_op0, *bpre_op1;
    bpre_op0 = CastInst::Create(Instruction::BitCast, op0,
                                IntegerType::get(C, op_size));
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()),
                             bpre_op0);

    bpre_op1 = CastInst::Create(Instruction::BitCast, op1,
                                IntegerType::get(C, op_size));
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()),
                             bpre_op1);

    /* Check if any operand is NaN.
     * If so, all comparisons except unequal (which yields true) yield false */

    /* build mask for NaN */
    const unsigned long long NaN_lowend = mask_exponent << precision;
    //    errs() << "Fractions: IntFractionTy size " <<
    //     IntFractionTy->getPrimitiveSizeInBits() << ", op_size " << op_size <<
    //     ", mask_fraction 0x";
    //    errs().write_hex(mask_fraction);
    //    errs() << ", precision " << precision <<
    //     ", NaN_lowend 0x";
    //    errs().write_hex(NaN_lowend); errs() << "\n";

    /* Check op0 for NaN */
    /* Shift left 1 Bit, ignore sign bit */
    Instruction *nan_op0, *nan_op1;
    nan_op0 = BinaryOperator::Create(Instruction::Shl, bpre_op0,
                                     ConstantInt::get(bpre_op0->getType(), 1));
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()),
                             nan_op0);

    /* compare to NaN interval */
    Instruction *is_op0_nan =
        CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_UGT, nan_op0,
                        ConstantInt::get(intType, NaN_lowend));
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()),
                             is_op0_nan);

    /* Check op1 for NaN */
    /* Shift right 1 Bit, ignore sign bit */
    nan_op1 = BinaryOperator::Create(Instruction::Shl, bpre_op1,
                                     ConstantInt::get(bpre_op1->getType(), 1));
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()),
                             nan_op1);

    /* compare to NaN interval */
    Instruction *is_op1_nan =
        CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_UGT, nan_op1,
                        ConstantInt::get(intType, NaN_lowend));
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()),
                             is_op1_nan);

    /* combine checks */
    Instruction *is_nan =
        BinaryOperator::Create(Instruction::Or, is_op0_nan, is_op1_nan);
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()), is_nan);

    /* the result of the comparison, when at least one op is NaN
       is true only for the "NOT EQUAL" predicates. */
    bool NaNcmp_result = FcmpInst->getPredicate() == CmpInst::FCMP_ONE ||
                         FcmpInst->getPredicate() == CmpInst::FCMP_UNE;

    BasicBlock *nonan_bb =
        BasicBlock::Create(C, "noNaN", end_bb->getParent(), end_bb);

    BranchInst::Create(end_bb, nonan_bb);

    auto term = bb->getTerminator();
    /* if no operand is NaN goto nonan_bb else to handleNaN_bb */
    BranchInst::Create(end_bb, nonan_bb, is_nan, bb);
    term->eraseFromParent();

    /*** now working in nonan_bb ***/

    /* Treat -0.0 as equal to +0.0, that is for -0.0 make it +0.0 */
    Instruction *            b_op0, *b_op1;
    Instruction *            isMzero_op0, *isMzero_op1;
    const unsigned long long MinusZero = 1UL << (sizeInBits - 1U);
    const unsigned long long PlusZero = 0;

    isMzero_op0 = CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_EQ, bpre_op0,
                                  ConstantInt::get(intType, MinusZero));
    nonan_bb->getInstList().insert(
        BasicBlock::iterator(nonan_bb->getTerminator()), isMzero_op0);

    isMzero_op1 = CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_EQ, bpre_op1,
                                  ConstantInt::get(intType, MinusZero));
    nonan_bb->getInstList().insert(
        BasicBlock::iterator(nonan_bb->getTerminator()), isMzero_op1);

    b_op0 = SelectInst::Create(isMzero_op0, ConstantInt::get(intType, PlusZero),
                               bpre_op0);
    nonan_bb->getInstList().insert(
        BasicBlock::iterator(nonan_bb->getTerminator()), b_op0);

    b_op1 = SelectInst::Create(isMzero_op1, ConstantInt::get(intType, PlusZero),
                               bpre_op1);
    nonan_bb->getInstList().insert(
        BasicBlock::iterator(nonan_bb->getTerminator()), b_op1);

    /* isolate signs of value of floating point type */

    /* create a 1 bit compare for the sign bit. to do this shift and trunc
     * the original operands so only the first bit remains.*/
    Instruction *s_s0, *t_s0, *s_s1, *t_s1, *icmp_sign_bit;

    s_s0 =
        BinaryOperator::Create(Instruction::LShr, b_op0,
                               ConstantInt::get(b_op0->getType(), op_size - 1));
    nonan_bb->getInstList().insert(
        BasicBlock::iterator(nonan_bb->getTerminator()), s_s0);
    t_s0 = new TruncInst(s_s0, Int1Ty);
    nonan_bb->getInstList().insert(
        BasicBlock::iterator(nonan_bb->getTerminator()), t_s0);

    s_s1 =
        BinaryOperator::Create(Instruction::LShr, b_op1,
                               ConstantInt::get(b_op1->getType(), op_size - 1));
    nonan_bb->getInstList().insert(
        BasicBlock::iterator(nonan_bb->getTerminator()), s_s1);
    t_s1 = new TruncInst(s_s1, Int1Ty);
    nonan_bb->getInstList().insert(
        BasicBlock::iterator(nonan_bb->getTerminator()), t_s1);

    /* compare of the sign bits */
    icmp_sign_bit =
        CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_EQ, t_s0, t_s1);
    nonan_bb->getInstList().insert(
        BasicBlock::iterator(nonan_bb->getTerminator()), icmp_sign_bit);

    /* create a new basic block which is executed if the signedness bits are
     * equal */
    BasicBlock *signequal_bb =
        BasicBlock::Create(C, "signequal", end_bb->getParent(), end_bb);

    BranchInst::Create(end_bb, signequal_bb);

    /* create a new bb which is executed if exponents are satisfying the compare
     */
    BasicBlock *middle_bb =
        BasicBlock::Create(C, "injected", end_bb->getParent(), end_bb);

    BranchInst::Create(end_bb, middle_bb);

    term = nonan_bb->getTerminator();
    /* if the signs are different goto end_bb else to signequal_bb */
    BranchInst::Create(signequal_bb, end_bb, icmp_sign_bit, nonan_bb);
    term->eraseFromParent();

    /* insert code for equal signs */

    /* isolate the exponents */
    Instruction *s_e0, *m_e0, *t_e0, *s_e1, *m_e1, *t_e1;

    s_e0 = BinaryOperator::Create(
        Instruction::LShr, b_op0,
        ConstantInt::get(b_op0->getType(), shiftR_exponent));
    s_e1 = BinaryOperator::Create(
        Instruction::LShr, b_op1,
        ConstantInt::get(b_op1->getType(), shiftR_exponent));
    signequal_bb->getInstList().insert(
        BasicBlock::iterator(signequal_bb->getTerminator()), s_e0);
    signequal_bb->getInstList().insert(
        BasicBlock::iterator(signequal_bb->getTerminator()), s_e1);

    t_e0 = new TruncInst(s_e0, IntExponentTy);
    t_e1 = new TruncInst(s_e1, IntExponentTy);
    signequal_bb->getInstList().insert(
        BasicBlock::iterator(signequal_bb->getTerminator()), t_e0);
    signequal_bb->getInstList().insert(
        BasicBlock::iterator(signequal_bb->getTerminator()), t_e1);

    if (sizeInBits - precision < exTySizeBytes * 8) {

      m_e0 = BinaryOperator::Create(
          Instruction::And, t_e0,
          ConstantInt::get(t_e0->getType(), mask_exponent));
      m_e1 = BinaryOperator::Create(
          Instruction::And, t_e1,
          ConstantInt::get(t_e1->getType(), mask_exponent));
      signequal_bb->getInstList().insert(
          BasicBlock::iterator(signequal_bb->getTerminator()), m_e0);
      signequal_bb->getInstList().insert(
          BasicBlock::iterator(signequal_bb->getTerminator()), m_e1);

    } else {

      m_e0 = t_e0;
      m_e1 = t_e1;

    }

    /* compare the exponents of the operands */
    Instruction *icmp_exponents_equal;
    Instruction *icmp_exponent_result;
    BasicBlock * signequal2_bb = signequal_bb;
    switch (FcmpInst->getPredicate()) {

      case CmpInst::FCMP_UEQ:
      case CmpInst::FCMP_OEQ:
        icmp_exponent_result =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_EQ, m_e0, m_e1);
        break;
      case CmpInst::FCMP_ONE:
      case CmpInst::FCMP_UNE:
        icmp_exponent_result =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_NE, m_e0, m_e1);
        break;
      /* compare the exponents of the operands (signs are equal)
       * if exponents are equal -> proceed to mantissa comparison
       * else get result depending on sign
       */
      case CmpInst::FCMP_OGT:
      case CmpInst::FCMP_UGT:
        Instruction *icmp_exponent;
        icmp_exponents_equal =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_EQ, m_e0, m_e1);
        signequal_bb->getInstList().insert(
            BasicBlock::iterator(signequal_bb->getTerminator()),
            icmp_exponents_equal);

        // shortcut for unequal exponents
        signequal2_bb = signequal_bb->splitBasicBlock(
            BasicBlock::iterator(signequal_bb->getTerminator()));

        /* if the exponents are equal goto middle_bb else to signequal2_bb */
        term = signequal_bb->getTerminator();
        BranchInst::Create(middle_bb, signequal2_bb, icmp_exponents_equal,
                           signequal_bb);
        term->eraseFromParent();

        icmp_exponent =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_UGT, m_e0, m_e1);
        signequal2_bb->getInstList().insert(
            BasicBlock::iterator(signequal2_bb->getTerminator()),
            icmp_exponent);
        icmp_exponent_result =
            BinaryOperator::Create(Instruction::Xor, icmp_exponent, t_s0);
        break;
      case CmpInst::FCMP_OLT:
      case CmpInst::FCMP_ULT:
        icmp_exponents_equal =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_EQ, m_e0, m_e1);
        signequal_bb->getInstList().insert(
            BasicBlock::iterator(signequal_bb->getTerminator()),
            icmp_exponents_equal);

        // shortcut for unequal exponents
        signequal2_bb = signequal_bb->splitBasicBlock(
            BasicBlock::iterator(signequal_bb->getTerminator()));

        /* if the exponents are equal goto middle_bb else to signequal2_bb */
        term = signequal_bb->getTerminator();
        BranchInst::Create(middle_bb, signequal2_bb, icmp_exponents_equal,
                           signequal_bb);
        term->eraseFromParent();

        icmp_exponent =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_ULT, m_e0, m_e1);
        signequal2_bb->getInstList().insert(
            BasicBlock::iterator(signequal2_bb->getTerminator()),
            icmp_exponent);
        icmp_exponent_result =
            BinaryOperator::Create(Instruction::Xor, icmp_exponent, t_s0);
        break;
      default:
        continue;

    }

    signequal2_bb->getInstList().insert(
        BasicBlock::iterator(signequal2_bb->getTerminator()),
        icmp_exponent_result);

    {

      term = signequal2_bb->getTerminator();

      switch (FcmpInst->getPredicate()) {

        case CmpInst::FCMP_UEQ:
        case CmpInst::FCMP_OEQ:
          /* if the exponents are satifying the compare do a fraction cmp in
           * middle_bb */
          BranchInst::Create(middle_bb, end_bb, icmp_exponent_result,
                             signequal2_bb);
          break;
        case CmpInst::FCMP_ONE:
        case CmpInst::FCMP_UNE:
          /* if the exponents are satifying the compare do a fraction cmp in
           * middle_bb */
          BranchInst::Create(end_bb, middle_bb, icmp_exponent_result,
                             signequal2_bb);
          break;
        case CmpInst::FCMP_OGT:
        case CmpInst::FCMP_UGT:
        case CmpInst::FCMP_OLT:
        case CmpInst::FCMP_ULT:
          BranchInst::Create(end_bb, signequal2_bb);
          break;
        default:
          continue;

      }

      term->eraseFromParent();

    }

    /* isolate the mantissa aka fraction */
    Instruction *t_f0, *t_f1;
    bool         needTrunc = IntFractionTy->getPrimitiveSizeInBits() < op_size;

    if (precision - 1 < frTySizeBytes * 8) {

      Instruction *m_f0, *m_f1;
      m_f0 = BinaryOperator::Create(
          Instruction::And, b_op0,
          ConstantInt::get(b_op0->getType(), mask_fraction));
      m_f1 = BinaryOperator::Create(
          Instruction::And, b_op1,
          ConstantInt::get(b_op1->getType(), mask_fraction));
      middle_bb->getInstList().insert(
          BasicBlock::iterator(middle_bb->getTerminator()), m_f0);
      middle_bb->getInstList().insert(
          BasicBlock::iterator(middle_bb->getTerminator()), m_f1);

      if (needTrunc) {

        t_f0 = new TruncInst(m_f0, IntFractionTy);
        t_f1 = new TruncInst(m_f1, IntFractionTy);
        middle_bb->getInstList().insert(
            BasicBlock::iterator(middle_bb->getTerminator()), t_f0);
        middle_bb->getInstList().insert(
            BasicBlock::iterator(middle_bb->getTerminator()), t_f1);

      } else {

        t_f0 = m_f0;
        t_f1 = m_f1;

      }

    } else {

      if (needTrunc) {

        t_f0 = new TruncInst(b_op0, IntFractionTy);
        t_f1 = new TruncInst(b_op1, IntFractionTy);
        middle_bb->getInstList().insert(
            BasicBlock::iterator(middle_bb->getTerminator()), t_f0);
        middle_bb->getInstList().insert(
            BasicBlock::iterator(middle_bb->getTerminator()), t_f1);

      } else {

        t_f0 = b_op0;
        t_f1 = b_op1;

      }

    }

    /* compare the fractions of the operands */
    Instruction *icmp_fraction_result;
    BasicBlock * middle2_bb = middle_bb;
    PHINode *    PN2 = nullptr;
    switch (FcmpInst->getPredicate()) {

      case CmpInst::FCMP_UEQ:
      case CmpInst::FCMP_OEQ:
        icmp_fraction_result =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_EQ, t_f0, t_f1);
        middle2_bb->getInstList().insert(
            BasicBlock::iterator(middle2_bb->getTerminator()),
            icmp_fraction_result);

        break;
      case CmpInst::FCMP_UNE:
      case CmpInst::FCMP_ONE:
        icmp_fraction_result =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_NE, t_f0, t_f1);
        middle2_bb->getInstList().insert(
            BasicBlock::iterator(middle2_bb->getTerminator()),
            icmp_fraction_result);

        break;
      case CmpInst::FCMP_OGT:
      case CmpInst::FCMP_UGT:
      case CmpInst::FCMP_OLT:
      case CmpInst::FCMP_ULT: {

        Instruction *icmp_fraction_result2;

        middle2_bb = middle_bb->splitBasicBlock(
            BasicBlock::iterator(middle_bb->getTerminator()));

        BasicBlock *negative_bb = BasicBlock::Create(
            C, "negative_value", middle2_bb->getParent(), middle2_bb);
        BasicBlock *positive_bb = BasicBlock::Create(
            C, "positive_value", negative_bb->getParent(), negative_bb);

        if (FcmpInst->getPredicate() == CmpInst::FCMP_OGT ||
            FcmpInst->getPredicate() == CmpInst::FCMP_UGT) {

          negative_bb->getInstList().push_back(
              icmp_fraction_result = CmpInst::Create(
                  Instruction::ICmp, CmpInst::ICMP_ULT, t_f0, t_f1));
          positive_bb->getInstList().push_back(
              icmp_fraction_result2 = CmpInst::Create(
                  Instruction::ICmp, CmpInst::ICMP_UGT, t_f0, t_f1));

        } else {

          negative_bb->getInstList().push_back(
              icmp_fraction_result = CmpInst::Create(
                  Instruction::ICmp, CmpInst::ICMP_UGT, t_f0, t_f1));
          positive_bb->getInstList().push_back(
              icmp_fraction_result2 = CmpInst::Create(
                  Instruction::ICmp, CmpInst::ICMP_ULT, t_f0, t_f1));

        }

        BranchInst::Create(middle2_bb, negative_bb);
        BranchInst::Create(middle2_bb, positive_bb);

        term = middle_bb->getTerminator();
        BranchInst::Create(negative_bb, positive_bb, t_s0, middle_bb);
        term->eraseFromParent();

        PN2 = PHINode::Create(Int1Ty, 2, "");
        PN2->addIncoming(icmp_fraction_result, negative_bb);
        PN2->addIncoming(icmp_fraction_result2, positive_bb);
        middle2_bb->getInstList().insert(
            BasicBlock::iterator(middle2_bb->getTerminator()), PN2);

      } break;

      default:
        continue;

    }

    PHINode *PN = PHINode::Create(Int1Ty, 4, "");

    switch (FcmpInst->getPredicate()) {

      case CmpInst::FCMP_UEQ:
      case CmpInst::FCMP_OEQ:
        /* unequal signs cannot be equal values */
        /* goto false branch */
        PN->addIncoming(ConstantInt::get(Int1Ty, 0), nonan_bb);
        /* unequal exponents cannot be equal values, too */
        PN->addIncoming(ConstantInt::get(Int1Ty, 0), signequal_bb);
        /* fractions comparison */
        PN->addIncoming(icmp_fraction_result, middle2_bb);
        /* NaNs */
        PN->addIncoming(ConstantInt::get(Int1Ty, NaNcmp_result), bb);
        break;
      case CmpInst::FCMP_ONE:
      case CmpInst::FCMP_UNE:
        /* unequal signs are unequal values */
        /* goto true branch */
        PN->addIncoming(ConstantInt::get(Int1Ty, 1), nonan_bb);
        /* unequal exponents are unequal values, too */
        PN->addIncoming(icmp_exponent_result, signequal_bb);
        /* fractions comparison */
        PN->addIncoming(icmp_fraction_result, middle2_bb);
        /* NaNs */
        PN->addIncoming(ConstantInt::get(Int1Ty, NaNcmp_result), bb);
        break;
      case CmpInst::FCMP_OGT:
      case CmpInst::FCMP_UGT:
        /* if op1 is negative goto true branch,
           else go on comparing */
        PN->addIncoming(t_s1, nonan_bb);
        PN->addIncoming(icmp_exponent_result, signequal2_bb);
        PN->addIncoming(PN2, middle2_bb);
        /* NaNs */
        PN->addIncoming(ConstantInt::get(Int1Ty, NaNcmp_result), bb);
        break;
      case CmpInst::FCMP_OLT:
      case CmpInst::FCMP_ULT:
        /* if op0 is negative goto true branch,
           else go on comparing */
        PN->addIncoming(t_s0, nonan_bb);
        PN->addIncoming(icmp_exponent_result, signequal2_bb);
        PN->addIncoming(PN2, middle2_bb);
        /* NaNs */
        PN->addIncoming(ConstantInt::get(Int1Ty, NaNcmp_result), bb);
        break;
      default:
        continue;

    }

    BasicBlock::iterator ii(FcmpInst);
    ReplaceInstWithInst(FcmpInst->getParent()->getInstList(), ii, PN);
    ++count;

  }

  return count;

}

#if LLVM_MAJOR >= 11
PreservedAnalyses SplitComparesTransform::run(Module &               M,
                                              ModuleAnalysisManager &MAM) {

#else
bool SplitComparesTransform::runOnModule(Module &M) {

#endif

  char *bitw_env = getenv("AFL_LLVM_LAF_SPLIT_COMPARES_BITW");
  if (!bitw_env) bitw_env = getenv("LAF_SPLIT_COMPARES_BITW");
  if (bitw_env) { target_bitwidth = atoi(bitw_env); }

  enableFPSplit = getenv("AFL_LLVM_LAF_SPLIT_FLOATS") != NULL;

  if ((isatty(2) && getenv("AFL_QUIET") == NULL) ||
      getenv("AFL_DEBUG") != NULL) {

    errs() << "Split-compare-newpass by laf.intel@gmail.com, extended by "
              "heiko@hexco.de (splitting icmp to "
           << target_bitwidth << " bit)\n";

    if (getenv("AFL_DEBUG") != NULL && !debug) { debug = 1; }

  } else {

    be_quiet = 1;

  }

#if LLVM_MAJOR >= 11
  auto PA = PreservedAnalyses::all();
#endif

  if (enableFPSplit) {

    simplifyFPCompares(M);
    count = splitFPCompares(M);

    if (!be_quiet && !debug) {

      errs() << "Split-floatingpoint-compare-pass: " << count
             << " FP comparisons splitted\n";

    }

  }

  std::vector<CmpInst *> worklist;
  /* iterate over all functions, bbs and instruction search for all integer
   * compare instructions. Save them into the worklist for later. */
  for (auto &F : M) {

    if (!isInInstrumentList(&F, MNAME)) continue;

    for (auto &BB : F) {

      for (auto &IN : BB) {

        if (auto CI = dyn_cast<CmpInst>(&IN)) {

          auto op0 = CI->getOperand(0);
          auto op1 = CI->getOperand(1);
          if (!op0 || !op1) {

#if LLVM_MAJOR >= 11
            return PA;
#else
            return false;
#endif

          }

          auto iTy1 = dyn_cast<IntegerType>(op0->getType());
          if (iTy1 && isa<IntegerType>(op1->getType())) {

            unsigned bitw = iTy1->getBitWidth();
            if (isSupportedBitWidth(bitw)) { worklist.push_back(CI); }

          }

        }

      }

    }

  }

  // now that we have a list of all integer comparisons we can start replacing
  // them with the splitted alternatives.
  for (auto CI : worklist) {

    simplifyAndSplit(CI, M);

  }

  bool brokenDebug = false;
  if (verifyModule(M, &errs()
#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR >= 9)
                          ,
                   &brokenDebug  // 9th May 2016
#endif
                   )) {

    reportError(
        "Module Verifier failed! Consider reporting a bug with the AFL++ "
        "project.",
        nullptr, M);

  }

  if (brokenDebug) {

    reportError("Module Verifier reported broken Debug Infos - Stripping!",
                nullptr, M);
    StripDebugInfo(M);

  }

  if ((isatty(2) && getenv("AFL_QUIET") == NULL) ||
      getenv("AFL_DEBUG") != NULL) {

    errs() << count << " comparisons found\n";

  }

#if LLVM_MAJOR >= 11
  /*  if (modified) {

      PA.abandon<XX_Manager>();

    }*/

  return PA;
#else
  return true;
#endif

}

#if LLVM_MAJOR < 11                                 /* use old pass manager */

static void registerSplitComparesPass(const PassManagerBuilder &,
                                      legacy::PassManagerBase &PM) {

  PM.add(new SplitComparesTransform());

}

static RegisterStandardPasses RegisterSplitComparesPass(
    PassManagerBuilder::EP_OptimizerLast, registerSplitComparesPass);

static RegisterStandardPasses RegisterSplitComparesTransPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerSplitComparesPass);

  #if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterSplitComparesTransPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    registerSplitComparesPass);
  #endif

static RegisterPass<SplitComparesTransform> X("splitcompares",
                                              "AFL++ split compares",
                                              true /* Only looks at CFG */,
                                              true /* Analysis Pass */);
#endif

