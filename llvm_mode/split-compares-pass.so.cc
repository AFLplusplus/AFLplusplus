/*
 * Copyright 2016 laf-intel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/Module.h"

#include "llvm/IR/IRBuilder.h"

using namespace llvm;

namespace {
  class SplitComparesTransform : public ModulePass {
    public:
      static char ID;
      SplitComparesTransform() : ModulePass(ID) {}

      bool runOnModule(Module &M) override;
#if LLVM_VERSION_MAJOR >= 4
      StringRef getPassName() const override {
#else
      const char * getPassName() const override {
#endif
        return "simplifies and splits ICMP instructions";
      }
    private:
      bool splitCompares(Module &M, unsigned bitw);
      bool simplifyCompares(Module &M);
      bool simplifySignedness(Module &M);

  };
}

char SplitComparesTransform::ID = 0;

/* This function splits ICMP instructions with xGE or xLE predicates into two 
 * ICMP instructions with predicate xGT or xLT and EQ */
bool SplitComparesTransform::simplifyCompares(Module &M) {
  LLVMContext &C = M.getContext();
  std::vector<Instruction*> icomps;
  IntegerType *Int1Ty = IntegerType::getInt1Ty(C);

  /* iterate over all functions, bbs and instruction and add
   * all integer comparisons with >= and <= predicates to the icomps vector */
  for (auto &F : M) {
    for (auto &BB : F) {
      for (auto &IN: BB) {
        CmpInst* selectcmpInst = nullptr;

        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {

          if (selectcmpInst->getPredicate() != CmpInst::ICMP_UGE &&
              selectcmpInst->getPredicate() != CmpInst::ICMP_SGE &&
              selectcmpInst->getPredicate() != CmpInst::ICMP_ULE &&
              selectcmpInst->getPredicate() != CmpInst::ICMP_SLE ) {
            continue;
          }

          auto op0 = selectcmpInst->getOperand(0);
          auto op1 = selectcmpInst->getOperand(1);

          IntegerType* intTyOp0 = dyn_cast<IntegerType>(op0->getType());
          IntegerType* intTyOp1 = dyn_cast<IntegerType>(op1->getType());

          /* this is probably not needed but we do it anyway */
          if (!intTyOp0 || !intTyOp1) {
            continue;
          }

          icomps.push_back(selectcmpInst);
        }
      }
    }
  }

  if (!icomps.size()) {
    return false;
  }


  for (auto &IcmpInst: icomps) {
    BasicBlock* bb = IcmpInst->getParent();

    auto op0 = IcmpInst->getOperand(0);
    auto op1 = IcmpInst->getOperand(1);

    /* find out what the new predicate is going to be */
    auto pred = dyn_cast<CmpInst>(IcmpInst)->getPredicate();
    CmpInst::Predicate new_pred;
    switch(pred) {
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
      default: // keep the compiler happy
        continue;
    }

    /* split before the icmp instruction */
    BasicBlock* end_bb = bb->splitBasicBlock(BasicBlock::iterator(IcmpInst));

    /* the old bb now contains a unconditional jump to the new one (end_bb)
     * we need to delete it later */

    /* create the ICMP instruction with new_pred and add it to the old basic
     * block bb it is now at the position where the old IcmpInst was */
    Instruction* icmp_np;
    icmp_np = CmpInst::Create(Instruction::ICmp, new_pred, op0, op1);
    bb->getInstList().insert(bb->getTerminator()->getIterator(), icmp_np);

    /* create a new basic block which holds the new EQ icmp */
    Instruction *icmp_eq;
    /* insert middle_bb before end_bb */
    BasicBlock* middle_bb =  BasicBlock::Create(C, "injected",
      end_bb->getParent(), end_bb);
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
  }

  return true;
}

/* this function transforms signed compares to equivalent unsigned compares */
bool SplitComparesTransform::simplifySignedness(Module &M) {
  LLVMContext &C = M.getContext();
  std::vector<Instruction*> icomps;
  IntegerType *Int1Ty = IntegerType::getInt1Ty(C);

  /* iterate over all functions, bbs and instruction and add
   * all signed compares to icomps vector */
  for (auto &F : M) {
    for (auto &BB : F) {
      for(auto &IN: BB) {
        CmpInst* selectcmpInst = nullptr;

        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {

          if (selectcmpInst->getPredicate() != CmpInst::ICMP_SGT &&
             selectcmpInst->getPredicate() != CmpInst::ICMP_SLT
             ) {
            continue;
          }

          auto op0 = selectcmpInst->getOperand(0);
          auto op1 = selectcmpInst->getOperand(1);

          IntegerType* intTyOp0 = dyn_cast<IntegerType>(op0->getType());
          IntegerType* intTyOp1 = dyn_cast<IntegerType>(op1->getType());

          /* see above */
          if (!intTyOp0 || !intTyOp1) {
            continue;
          }

          /* i think this is not possible but to lazy to look it up */
          if (intTyOp0->getBitWidth() != intTyOp1->getBitWidth()) {
            continue;
          }

          icomps.push_back(selectcmpInst);
        }
      }
    }
  }

  if (!icomps.size()) {
    return false;
  }

  for (auto &IcmpInst: icomps) {
    BasicBlock* bb = IcmpInst->getParent();

    auto op0 = IcmpInst->getOperand(0);
    auto op1 = IcmpInst->getOperand(1);

    IntegerType* intTyOp0 = dyn_cast<IntegerType>(op0->getType());
    unsigned bitw = intTyOp0->getBitWidth();
    IntegerType *IntType = IntegerType::get(C, bitw);


    /* get the new predicate */
    auto pred = dyn_cast<CmpInst>(IcmpInst)->getPredicate();
    CmpInst::Predicate new_pred;
    if (pred == CmpInst::ICMP_SGT) {
      new_pred = CmpInst::ICMP_UGT;
    } else {
      new_pred = CmpInst::ICMP_ULT;
    }

    BasicBlock* end_bb = bb->splitBasicBlock(BasicBlock::iterator(IcmpInst));

    /* create a 1 bit compare for the sign bit. to do this shift and trunc
     * the original operands so only the first bit remains.*/
    Instruction *s_op0, *t_op0, *s_op1, *t_op1, *icmp_sign_bit;

    s_op0 = BinaryOperator::Create(Instruction::LShr, op0, ConstantInt::get(IntType, bitw - 1));
    bb->getInstList().insert(bb->getTerminator()->getIterator(), s_op0);
    t_op0 = new TruncInst(s_op0, Int1Ty);
    bb->getInstList().insert(bb->getTerminator()->getIterator(), t_op0);

    s_op1 = BinaryOperator::Create(Instruction::LShr, op1, ConstantInt::get(IntType, bitw - 1));
    bb->getInstList().insert(bb->getTerminator()->getIterator(), s_op1);
    t_op1 = new TruncInst(s_op1, Int1Ty);
    bb->getInstList().insert(bb->getTerminator()->getIterator(), t_op1);

    /* compare of the sign bits */
    icmp_sign_bit = CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_EQ, t_op0, t_op1);
    bb->getInstList().insert(bb->getTerminator()->getIterator(), icmp_sign_bit);

    /* create a new basic block which is executed if the signedness bit is
     * different */ 
    Instruction *icmp_inv_sig_cmp;
    BasicBlock* sign_bb = BasicBlock::Create(C, "sign", end_bb->getParent(), end_bb);
    if (pred == CmpInst::ICMP_SGT) {
      /* if we check for > and the op0 positive and op1 negative then the final
       * result is true. if op0 negative and op1 pos, the cmp must result
       * in false
       */
      icmp_inv_sig_cmp = CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_ULT, t_op0, t_op1);
    } else {
      /* just the inverse of the above statement */
      icmp_inv_sig_cmp = CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_UGT, t_op0, t_op1);
    }
    sign_bb->getInstList().push_back(icmp_inv_sig_cmp);
    BranchInst::Create(end_bb, sign_bb);

    /* create a new bb which is executed if signedness is equal */
    Instruction *icmp_usign_cmp;
    BasicBlock* middle_bb =  BasicBlock::Create(C, "injected", end_bb->getParent(), end_bb);
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
  }

  return true;
}

/* splits icmps of size bitw into two nested icmps with bitw/2 size each */
bool SplitComparesTransform::splitCompares(Module &M, unsigned bitw) {
  LLVMContext &C = M.getContext();

  IntegerType *Int1Ty = IntegerType::getInt1Ty(C);
  IntegerType *OldIntType = IntegerType::get(C, bitw);
  IntegerType *NewIntType = IntegerType::get(C, bitw / 2);

  std::vector<Instruction*> icomps;

  if (bitw % 2) {
    return false;
  }

  /* not supported yet */
  if (bitw > 64) {
    return false;
  }

  /* get all EQ, NE, UGT, and ULT icmps of width bitw. if the other two 
   * unctions were executed only these four predicates should exist */
  for (auto &F : M) {
    for (auto &BB : F) {
      for(auto &IN: BB) {
        CmpInst* selectcmpInst = nullptr;

        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {

          if(selectcmpInst->getPredicate() != CmpInst::ICMP_EQ &&
             selectcmpInst->getPredicate() != CmpInst::ICMP_NE &&
             selectcmpInst->getPredicate() != CmpInst::ICMP_UGT &&
             selectcmpInst->getPredicate() != CmpInst::ICMP_ULT
             ) {
            continue;
          }

          auto op0 = selectcmpInst->getOperand(0);
          auto op1 = selectcmpInst->getOperand(1);

          IntegerType* intTyOp0 = dyn_cast<IntegerType>(op0->getType());
          IntegerType* intTyOp1 = dyn_cast<IntegerType>(op1->getType());

          if (!intTyOp0 || !intTyOp1) {
            continue;
          }

          /* check if the bitwidths are the one we are looking for */
          if (intTyOp0->getBitWidth() != bitw || intTyOp1->getBitWidth() != bitw) {
            continue;
          }

          icomps.push_back(selectcmpInst);
        }
      }
    }
  }

  if (!icomps.size()) {
    return false;
  }

  for (auto &IcmpInst: icomps) {
    BasicBlock* bb = IcmpInst->getParent();

    auto op0 = IcmpInst->getOperand(0);
    auto op1 = IcmpInst->getOperand(1);

    auto pred = dyn_cast<CmpInst>(IcmpInst)->getPredicate();

    BasicBlock* end_bb = bb->splitBasicBlock(BasicBlock::iterator(IcmpInst));

    /* create the comparison of the top halves of the original operands */
    Instruction *s_op0, *op0_high, *s_op1, *op1_high, *icmp_high;

    s_op0 = BinaryOperator::Create(Instruction::LShr, op0, ConstantInt::get(OldIntType, bitw / 2));
    bb->getInstList().insert(bb->getTerminator()->getIterator(), s_op0);
    op0_high = new TruncInst(s_op0, NewIntType);
    bb->getInstList().insert(bb->getTerminator()->getIterator(), op0_high);

    s_op1 = BinaryOperator::Create(Instruction::LShr, op1, ConstantInt::get(OldIntType, bitw / 2));
    bb->getInstList().insert(bb->getTerminator()->getIterator(), s_op1);
    op1_high = new TruncInst(s_op1, NewIntType);
    bb->getInstList().insert(bb->getTerminator()->getIterator(), op1_high);

    icmp_high = CmpInst::Create(Instruction::ICmp, pred, op0_high, op1_high);
    bb->getInstList().insert(bb->getTerminator()->getIterator(), icmp_high);

    /* now we have to destinguish between == != and > < */
    if (pred == CmpInst::ICMP_EQ || pred == CmpInst::ICMP_NE) {
      /* transformation for == and != icmps */

      /* create a compare for the lower half of the original operands */
      Instruction *op0_low, *op1_low, *icmp_low;
      BasicBlock* cmp_low_bb = BasicBlock::Create(C, "injected", end_bb->getParent(), end_bb);

      op0_low = new TruncInst(op0, NewIntType);
      cmp_low_bb->getInstList().push_back(op0_low);

      op1_low = new TruncInst(op1, NewIntType);
      cmp_low_bb->getInstList().push_back(op1_low);

      icmp_low = CmpInst::Create(Instruction::ICmp, pred, op0_low, op1_low);
      cmp_low_bb->getInstList().push_back(icmp_low);
      BranchInst::Create(end_bb, cmp_low_bb);

      /* dependent on the cmp of the high parts go to the end or go on with
       * the comparison */
      auto term = bb->getTerminator();
      if (pred == CmpInst::ICMP_EQ) {
        BranchInst::Create(cmp_low_bb, end_bb, icmp_high, bb);
      } else {
        /* CmpInst::ICMP_NE */
        BranchInst::Create(end_bb, cmp_low_bb, icmp_high, bb);
      }
      term->eraseFromParent();

      /* create the PHI and connect the edges accordingly */
      PHINode *PN = PHINode::Create(Int1Ty, 2, "");
      PN->addIncoming(icmp_low, cmp_low_bb);
      if (pred == CmpInst::ICMP_EQ) {
        PN->addIncoming(ConstantInt::get(Int1Ty, 0), bb);
      } else {
        /* CmpInst::ICMP_NE */
        PN->addIncoming(ConstantInt::get(Int1Ty, 1), bb);
      }

      /* replace the old icmp with the new PHI */
      BasicBlock::iterator ii(IcmpInst);
      ReplaceInstWithInst(IcmpInst->getParent()->getInstList(), ii, PN);

    } else {
      /* CmpInst::ICMP_UGT and CmpInst::ICMP_ULT */
      /* transformations for < and > */

      /* create a basic block which checks for the inverse predicate. 
       * if this is true we can go to the end if not we have to got to the
       * bb which checks the lower half of the operands */
      Instruction *icmp_inv_cmp, *op0_low, *op1_low, *icmp_low;
      BasicBlock* inv_cmp_bb = BasicBlock::Create(C, "inv_cmp", end_bb->getParent(), end_bb);
      if (pred == CmpInst::ICMP_UGT) {
        icmp_inv_cmp = CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_ULT, op0_high, op1_high);
      } else {
        icmp_inv_cmp = CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_UGT, op0_high, op1_high);
      }
      inv_cmp_bb->getInstList().push_back(icmp_inv_cmp);

      auto term = bb->getTerminator();
      term->eraseFromParent();
      BranchInst::Create(end_bb, inv_cmp_bb, icmp_high, bb);

      /* create a bb which handles the cmp of the lower halves */
      BasicBlock* cmp_low_bb = BasicBlock::Create(C, "injected", end_bb->getParent(), end_bb);
      op0_low = new TruncInst(op0, NewIntType);
      cmp_low_bb->getInstList().push_back(op0_low);
      op1_low = new TruncInst(op1, NewIntType);
      cmp_low_bb->getInstList().push_back(op1_low);

      icmp_low = CmpInst::Create(Instruction::ICmp, pred, op0_low, op1_low);
      cmp_low_bb->getInstList().push_back(icmp_low);
      BranchInst::Create(end_bb, cmp_low_bb);

      BranchInst::Create(end_bb, cmp_low_bb, icmp_inv_cmp, inv_cmp_bb);

      PHINode *PN = PHINode::Create(Int1Ty, 3);
      PN->addIncoming(icmp_low, cmp_low_bb);
      PN->addIncoming(ConstantInt::get(Int1Ty, 1), bb);
      PN->addIncoming(ConstantInt::get(Int1Ty, 0), inv_cmp_bb);

      BasicBlock::iterator ii(IcmpInst);
      ReplaceInstWithInst(IcmpInst->getParent()->getInstList(), ii, PN);
    }
  }
  return  true;
}

bool SplitComparesTransform::runOnModule(Module &M) {
  int bitw = 64;

  char* bitw_env = getenv("LAF_SPLIT_COMPARES_BITW");
  if (!bitw_env)
    bitw_env = getenv("AFL_LLVM_LAF_SPLIT_COMPARES_BITW");
  if (bitw_env) {
    bitw = atoi(bitw_env);
  }

  simplifyCompares(M);

  simplifySignedness(M);

  if (getenv("AFL_QUIET") == NULL)
    errs() << "Split-compare-pass by laf.intel@gmail.com\n"; 

  switch (bitw) {
    case 64:
      errs() << "Running split-compare-pass " << 64 << "\n"; 
      splitCompares(M, 64);

      [[clang::fallthrough]];
      /* fallthrough */
    case 32:
      errs() << "Running split-compare-pass " << 32 << "\n"; 
      splitCompares(M, 32);

      [[clang::fallthrough]];
      /* fallthrough */
    case 16:
      errs() << "Running split-compare-pass " << 16 << "\n"; 
      splitCompares(M, 16);
      break;

    default:
      errs() << "NOT Running split-compare-pass \n"; 
      return false;
      break;
  }

  verifyModule(M);
  return true;
}

static void registerSplitComparesPass(const PassManagerBuilder &,
                         legacy::PassManagerBase &PM) {
  PM.add(new SplitComparesTransform());
}

static RegisterStandardPasses RegisterSplitComparesPass(
    PassManagerBuilder::EP_OptimizerLast, registerSplitComparesPass);

static RegisterStandardPasses RegisterSplitComparesTransPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerSplitComparesPass);
