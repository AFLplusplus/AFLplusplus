/*
 * Copyright 2016 laf-intel
 * extended for floating point by Heiko Eißfeldt
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>

#include "llvm/Config/llvm-config.h"

#include "llvm/Pass.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/Module.h"

#include "llvm/IR/IRBuilder.h"
#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
#include "llvm/IR/Verifier.h"
#include "llvm/IR/DebugInfo.h"
#else
#include "llvm/Analysis/Verifier.h"
#include "llvm/DebugInfo.h"
#define nullptr 0
#endif

using namespace llvm;

namespace {

class SplitComparesTransform : public ModulePass {

 public:
  static char ID;
  SplitComparesTransform() : ModulePass(ID) {

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
#if LLVM_VERSION_MAJOR >= 4
  StringRef getPassName() const override {

#else
  const char *getPassName() const override {

#endif
    return "simplifies and splits ICMP instructions";

  }

 protected:
  std::list<std::string> myWhitelist;
  int                    be_quiet = 0;

 private:
  int enableFPSplit;

  size_t splitIntCompares(Module &M, unsigned bitw);
  size_t splitFPCompares(Module &M);
  bool   simplifyCompares(Module &M);
  bool   simplifyIntSignedness(Module &M);
  size_t nextPowerOfTwo(size_t in);

};

}  // namespace

char SplitComparesTransform::ID = 0;

/* This function splits ICMP instructions with xGE or xLE predicates into two
 * ICMP instructions with predicate xGT or xLT and EQ */
bool SplitComparesTransform::simplifyCompares(Module &M) {

  LLVMContext &              C = M.getContext();
  std::vector<Instruction *> icomps;
  std::vector<Instruction *> fcomps;
  IntegerType *              Int1Ty = IntegerType::getInt1Ty(C);

  /* iterate over all functions, bbs and instruction and add
   * all integer comparisons with >= and <= predicates to the icomps vector */
  for (auto &F : M) {

    if (isBlacklisted(&F)) continue;

    for (auto &BB : F) {

      if (!myWhitelist.empty()) {

        bool instrumentBlock = false;

        BasicBlock::iterator IP = BB.getFirstInsertionPt();

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

      for (auto &IN : BB) {

        CmpInst *selectcmpInst = nullptr;

        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {

          if (selectcmpInst->getPredicate() == CmpInst::ICMP_UGE ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_SGE ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_ULE ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_SLE) {

            auto op0 = selectcmpInst->getOperand(0);
            auto op1 = selectcmpInst->getOperand(1);

            IntegerType *intTyOp0 = dyn_cast<IntegerType>(op0->getType());
            IntegerType *intTyOp1 = dyn_cast<IntegerType>(op1->getType());

            /* this is probably not needed but we do it anyway */
            if (!intTyOp0 || !intTyOp1) { continue; }

            icomps.push_back(selectcmpInst);

          }

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

  if (!icomps.size() && !fcomps.size()) { return false; }

  for (auto &IcmpInst : icomps) {

    BasicBlock *bb = IcmpInst->getParent();

    auto op0 = IcmpInst->getOperand(0);
    auto op1 = IcmpInst->getOperand(1);

    /* find out what the new predicate is going to be */
    auto               pred = dyn_cast<CmpInst>(IcmpInst)->getPredicate();
    CmpInst::Predicate new_pred;
    switch (pred) {

      case CmpInst::ICMP_UGE: new_pred = CmpInst::ICMP_UGT; break;
      case CmpInst::ICMP_SGE: new_pred = CmpInst::ICMP_SGT; break;
      case CmpInst::ICMP_ULE: new_pred = CmpInst::ICMP_ULT; break;
      case CmpInst::ICMP_SLE: new_pred = CmpInst::ICMP_SLT; break;
      default:  // keep the compiler happy
        continue;

    }

    /* split before the icmp instruction */
    BasicBlock *end_bb = bb->splitBasicBlock(BasicBlock::iterator(IcmpInst));

    /* the old bb now contains a unconditional jump to the new one (end_bb)
     * we need to delete it later */

    /* create the ICMP instruction with new_pred and add it to the old basic
     * block bb it is now at the position where the old IcmpInst was */
    Instruction *icmp_np;
    icmp_np = CmpInst::Create(Instruction::ICmp, new_pred, op0, op1);
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()),
                             icmp_np);

    /* create a new basic block which holds the new EQ icmp */
    Instruction *icmp_eq;
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

  }

  /* now for floating point */
  for (auto &FcmpInst : fcomps) {

    BasicBlock *bb = FcmpInst->getParent();

    auto op0 = FcmpInst->getOperand(0);
    auto op1 = FcmpInst->getOperand(1);

    /* find out what the new predicate is going to be */
    auto               pred = dyn_cast<CmpInst>(FcmpInst)->getPredicate();
    CmpInst::Predicate new_pred;
    switch (pred) {

      case CmpInst::FCMP_UGE: new_pred = CmpInst::FCMP_UGT; break;
      case CmpInst::FCMP_OGE: new_pred = CmpInst::FCMP_OGT; break;
      case CmpInst::FCMP_ULE: new_pred = CmpInst::FCMP_ULT; break;
      case CmpInst::FCMP_OLE: new_pred = CmpInst::FCMP_OLT; break;
      default:  // keep the compiler happy
        continue;

    }

    /* split before the icmp instruction */
    BasicBlock *end_bb = bb->splitBasicBlock(BasicBlock::iterator(FcmpInst));

    /* the old bb now contains a unconditional jump to the new one (end_bb)
     * we need to delete it later */

    /* create the ICMP instruction with new_pred and add it to the old basic
     * block bb it is now at the position where the old IcmpInst was */
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
     * new_pred icmp. True goes to end, false to the middle (injected) bb */
    auto term = bb->getTerminator();
    BranchInst::Create(end_bb, middle_bb, fcmp_np, bb);
    term->eraseFromParent();

    /* replace the old IcmpInst (which is the first inst in end_bb) with a PHI
     * inst to wire up the loose ends */
    PHINode *PN = PHINode::Create(Int1Ty, 2, "");
    /* the first result depends on the outcome of icmp_eq */
    PN->addIncoming(fcmp_eq, middle_bb);
    /* if the source was the original bb we know that the icmp_np yielded true
     * hence we can hardcode this value */
    PN->addIncoming(ConstantInt::get(Int1Ty, 1), bb);
    /* replace the old IcmpInst with our new and shiny PHI inst */
    BasicBlock::iterator ii(FcmpInst);
    ReplaceInstWithInst(FcmpInst->getParent()->getInstList(), ii, PN);

  }

  return true;

}

/* this function transforms signed compares to equivalent unsigned compares */
bool SplitComparesTransform::simplifyIntSignedness(Module &M) {

  LLVMContext &              C = M.getContext();
  std::vector<Instruction *> icomps;
  IntegerType *              Int1Ty = IntegerType::getInt1Ty(C);

  /* iterate over all functions, bbs and instructions and add
   * all signed compares to icomps vector */
  for (auto &F : M) {

    for (auto &BB : F) {

      for (auto &IN : BB) {

        CmpInst *selectcmpInst = nullptr;

        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {

          if (selectcmpInst->getPredicate() == CmpInst::ICMP_SGT ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_SLT) {

            auto op0 = selectcmpInst->getOperand(0);
            auto op1 = selectcmpInst->getOperand(1);

            IntegerType *intTyOp0 = dyn_cast<IntegerType>(op0->getType());
            IntegerType *intTyOp1 = dyn_cast<IntegerType>(op1->getType());

            /* see above */
            if (!intTyOp0 || !intTyOp1) { continue; }

            /* i think this is not possible but to lazy to look it up */
            if (intTyOp0->getBitWidth() != intTyOp1->getBitWidth()) {

              continue;

            }

            icomps.push_back(selectcmpInst);

          }

        }

      }

    }

  }

  if (!icomps.size()) { return false; }

  for (auto &IcmpInst : icomps) {

    BasicBlock *bb = IcmpInst->getParent();

    auto op0 = IcmpInst->getOperand(0);
    auto op1 = IcmpInst->getOperand(1);

    IntegerType *intTyOp0 = dyn_cast<IntegerType>(op0->getType());
    unsigned     bitw = intTyOp0->getBitWidth();
    IntegerType *IntType = IntegerType::get(C, bitw);

    /* get the new predicate */
    auto               pred = dyn_cast<CmpInst>(IcmpInst)->getPredicate();
    CmpInst::Predicate new_pred;
    if (pred == CmpInst::ICMP_SGT) {

      new_pred = CmpInst::ICMP_UGT;

    } else {

      new_pred = CmpInst::ICMP_ULT;

    }

    BasicBlock *end_bb = bb->splitBasicBlock(BasicBlock::iterator(IcmpInst));

    /* create a 1 bit compare for the sign bit. to do this shift and trunc
     * the original operands so only the first bit remains.*/
    Instruction *s_op0, *t_op0, *s_op1, *t_op1, *icmp_sign_bit;

    s_op0 = BinaryOperator::Create(Instruction::LShr, op0,
                                   ConstantInt::get(IntType, bitw - 1));
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()), s_op0);
    t_op0 = new TruncInst(s_op0, Int1Ty);
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()), t_op0);

    s_op1 = BinaryOperator::Create(Instruction::LShr, op1,
                                   ConstantInt::get(IntType, bitw - 1));
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()), s_op1);
    t_op1 = new TruncInst(s_op1, Int1Ty);
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()), t_op1);

    /* compare of the sign bits */
    icmp_sign_bit =
        CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_EQ, t_op0, t_op1);
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()),
                             icmp_sign_bit);

    /* create a new basic block which is executed if the signedness bit is
     * different */
    Instruction *icmp_inv_sig_cmp;
    BasicBlock * sign_bb =
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
    Instruction *icmp_usign_cmp;
    BasicBlock * middle_bb =
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

  }

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

#if LLVM_VERSION_MAJOR > 3 || \
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

    for (auto &BB : F) {

      for (auto &IN : BB) {

        CmpInst *selectcmpInst = nullptr;

        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {

          if (selectcmpInst->getPredicate() == CmpInst::FCMP_OEQ ||
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
    const unsigned int precision =
        sizeInBits == 32
            ? 24
            : sizeInBits == 64
                  ? 53
                  : sizeInBits == 128 ? 113
                                      : sizeInBits == 16 ? 11
                                                         /* sizeInBits == 80 */
                                                         : 65;

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
    Instruction *b_op0, *b_op1;
    b_op0 = CastInst::Create(Instruction::BitCast, op0,
                             IntegerType::get(C, op_size));
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()), b_op0);

    b_op1 = CastInst::Create(Instruction::BitCast, op1,
                             IntegerType::get(C, op_size));
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()), b_op1);

    /* isolate signs of value of floating point type */

    /* create a 1 bit compare for the sign bit. to do this shift and trunc
     * the original operands so only the first bit remains.*/
    Instruction *s_s0, *t_s0, *s_s1, *t_s1, *icmp_sign_bit;

    s_s0 =
        BinaryOperator::Create(Instruction::LShr, b_op0,
                               ConstantInt::get(b_op0->getType(), op_size - 1));
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()), s_s0);
    t_s0 = new TruncInst(s_s0, Int1Ty);
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()), t_s0);

    s_s1 =
        BinaryOperator::Create(Instruction::LShr, b_op1,
                               ConstantInt::get(b_op1->getType(), op_size - 1));
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()), s_s1);
    t_s1 = new TruncInst(s_s1, Int1Ty);
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()), t_s1);

    /* compare of the sign bits */
    icmp_sign_bit =
        CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_EQ, t_s0, t_s1);
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()),
                             icmp_sign_bit);

    /* create a new basic block which is executed if the signedness bits are
     * equal */
    BasicBlock *signequal_bb =
        BasicBlock::Create(C, "signequal", end_bb->getParent(), end_bb);

    BranchInst::Create(end_bb, signequal_bb);

    /* create a new bb which is executed if exponents are equal */
    BasicBlock *middle_bb =
        BasicBlock::Create(C, "injected", end_bb->getParent(), end_bb);

    BranchInst::Create(end_bb, middle_bb);

    auto term = bb->getTerminator();
    /* if the signs are different goto end_bb else to signequal_bb */
    BranchInst::Create(signequal_bb, end_bb, icmp_sign_bit, bb);
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
    Instruction *icmp_exponent_result;
    switch (FcmpInst->getPredicate()) {

      case CmpInst::FCMP_OEQ:
        icmp_exponent_result =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_EQ, m_e0, m_e1);
        break;
      case CmpInst::FCMP_ONE:
      case CmpInst::FCMP_UNE:
        icmp_exponent_result =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_NE, m_e0, m_e1);
        break;
      case CmpInst::FCMP_OGT:
      case CmpInst::FCMP_UGT:
        Instruction *icmp_exponent;
        icmp_exponent =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_UGT, m_e0, m_e1);
        signequal_bb->getInstList().insert(
            BasicBlock::iterator(signequal_bb->getTerminator()), icmp_exponent);
        icmp_exponent_result =
            BinaryOperator::Create(Instruction::Xor, icmp_exponent, t_s0);
        break;
      case CmpInst::FCMP_OLT:
      case CmpInst::FCMP_ULT:
        icmp_exponent =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_ULT, m_e0, m_e1);
        signequal_bb->getInstList().insert(
            BasicBlock::iterator(signequal_bb->getTerminator()), icmp_exponent);
        icmp_exponent_result =
            BinaryOperator::Create(Instruction::Xor, icmp_exponent, t_s0);
        break;
      default: continue;

    }

    signequal_bb->getInstList().insert(
        BasicBlock::iterator(signequal_bb->getTerminator()),
        icmp_exponent_result);

    {

      auto term = signequal_bb->getTerminator();
      /* if the exponents are different do a fraction cmp */
      BranchInst::Create(middle_bb, end_bb, icmp_exponent_result, signequal_bb);
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
    switch (FcmpInst->getPredicate()) {

      case CmpInst::FCMP_OEQ:
        icmp_fraction_result =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_EQ, t_f0, t_f1);
        break;
      case CmpInst::FCMP_UNE:
      case CmpInst::FCMP_ONE:
        icmp_fraction_result =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_NE, t_f0, t_f1);
        break;
      case CmpInst::FCMP_OGT:
      case CmpInst::FCMP_UGT:
        Instruction *icmp_fraction;
        icmp_fraction =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_UGT, t_f0, t_f1);
        middle_bb->getInstList().insert(
            BasicBlock::iterator(middle_bb->getTerminator()), icmp_fraction);
        icmp_fraction_result =
            BinaryOperator::Create(Instruction::Xor, icmp_fraction, t_s0);
        break;
      case CmpInst::FCMP_OLT:
      case CmpInst::FCMP_ULT:
        icmp_fraction =
            CmpInst::Create(Instruction::ICmp, CmpInst::ICMP_ULT, t_f0, t_f1);
        middle_bb->getInstList().insert(
            BasicBlock::iterator(middle_bb->getTerminator()), icmp_fraction);
        icmp_fraction_result =
            BinaryOperator::Create(Instruction::Xor, icmp_fraction, t_s0);
        break;
      default: continue;

    }

    middle_bb->getInstList().insert(
        BasicBlock::iterator(middle_bb->getTerminator()), icmp_fraction_result);

    PHINode *PN = PHINode::Create(Int1Ty, 3, "");

    switch (FcmpInst->getPredicate()) {

      case CmpInst::FCMP_OEQ:
        /* unequal signs cannot be equal values */
        /* goto false branch */
        PN->addIncoming(ConstantInt::get(Int1Ty, 0), bb);
        /* unequal exponents cannot be equal values, too */
        PN->addIncoming(ConstantInt::get(Int1Ty, 0), signequal_bb);
        /* fractions comparison */
        PN->addIncoming(icmp_fraction_result, middle_bb);
        break;
      case CmpInst::FCMP_ONE:
      case CmpInst::FCMP_UNE:
        /* unequal signs are unequal values */
        /* goto true branch */
        PN->addIncoming(ConstantInt::get(Int1Ty, 1), bb);
        /* unequal exponents are unequal values, too */
        PN->addIncoming(ConstantInt::get(Int1Ty, 1), signequal_bb);
        /* fractions comparison */
        PN->addIncoming(icmp_fraction_result, middle_bb);
        break;
      case CmpInst::FCMP_OGT:
      case CmpInst::FCMP_UGT:
        /* if op1 is negative goto true branch,
           else go on comparing */
        PN->addIncoming(t_s1, bb);
        PN->addIncoming(icmp_exponent_result, signequal_bb);
        PN->addIncoming(icmp_fraction_result, middle_bb);
        break;
      case CmpInst::FCMP_OLT:
      case CmpInst::FCMP_ULT:
        /* if op0 is negative goto true branch,
           else go on comparing */
        PN->addIncoming(t_s0, bb);
        PN->addIncoming(icmp_exponent_result, signequal_bb);
        PN->addIncoming(icmp_fraction_result, middle_bb);
        break;
      default: continue;

    }

    BasicBlock::iterator ii(FcmpInst);
    ReplaceInstWithInst(FcmpInst->getParent()->getInstList(), ii, PN);
    ++count;

  }

  return count;

}

/* splits icmps of size bitw into two nested icmps with bitw/2 size each */
size_t SplitComparesTransform::splitIntCompares(Module &M, unsigned bitw) {

  size_t count = 0;

  LLVMContext &C = M.getContext();

  IntegerType *Int1Ty = IntegerType::getInt1Ty(C);
  IntegerType *OldIntType = IntegerType::get(C, bitw);
  IntegerType *NewIntType = IntegerType::get(C, bitw / 2);

  std::vector<Instruction *> icomps;

  if (bitw % 2) { return 0; }

  /* not supported yet */
  if (bitw > 64) { return 0; }

  /* get all EQ, NE, UGT, and ULT icmps of width bitw. if the
   * functions simplifyCompares() and simplifyIntSignedness()
   * were executed only these four predicates should exist */
  for (auto &F : M) {

    for (auto &BB : F) {

      for (auto &IN : BB) {

        CmpInst *selectcmpInst = nullptr;

        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {

          if (selectcmpInst->getPredicate() == CmpInst::ICMP_EQ ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_NE ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_UGT ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_ULT) {

            auto op0 = selectcmpInst->getOperand(0);
            auto op1 = selectcmpInst->getOperand(1);

            IntegerType *intTyOp0 = dyn_cast<IntegerType>(op0->getType());
            IntegerType *intTyOp1 = dyn_cast<IntegerType>(op1->getType());

            if (!intTyOp0 || !intTyOp1) { continue; }

            /* check if the bitwidths are the one we are looking for */
            if (intTyOp0->getBitWidth() != bitw ||
                intTyOp1->getBitWidth() != bitw) {

              continue;

            }

            icomps.push_back(selectcmpInst);

          }

        }

      }

    }

  }

  if (!icomps.size()) { return 0; }

  for (auto &IcmpInst : icomps) {

    BasicBlock *bb = IcmpInst->getParent();

    auto op0 = IcmpInst->getOperand(0);
    auto op1 = IcmpInst->getOperand(1);

    auto pred = dyn_cast<CmpInst>(IcmpInst)->getPredicate();

    BasicBlock *end_bb = bb->splitBasicBlock(BasicBlock::iterator(IcmpInst));

    /* create the comparison of the top halves of the original operands */
    Instruction *s_op0, *op0_high, *s_op1, *op1_high, *icmp_high;

    s_op0 = BinaryOperator::Create(Instruction::LShr, op0,
                                   ConstantInt::get(OldIntType, bitw / 2));
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()), s_op0);
    op0_high = new TruncInst(s_op0, NewIntType);
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()),
                             op0_high);

    s_op1 = BinaryOperator::Create(Instruction::LShr, op1,
                                   ConstantInt::get(OldIntType, bitw / 2));
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()), s_op1);
    op1_high = new TruncInst(s_op1, NewIntType);
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()),
                             op1_high);

    icmp_high = CmpInst::Create(Instruction::ICmp, pred, op0_high, op1_high);
    bb->getInstList().insert(BasicBlock::iterator(bb->getTerminator()),
                             icmp_high);

    /* now we have to destinguish between == != and > < */
    if (pred == CmpInst::ICMP_EQ || pred == CmpInst::ICMP_NE) {

      /* transformation for == and != icmps */

      /* create a compare for the lower half of the original operands */
      Instruction *op0_low, *op1_low, *icmp_low;
      BasicBlock * cmp_low_bb =
          BasicBlock::Create(C, "injected", end_bb->getParent(), end_bb);

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
       * if this is true we can go to the end if not we have to go to the
       * bb which checks the lower half of the operands */
      Instruction *icmp_inv_cmp, *op0_low, *op1_low, *icmp_low;
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

      auto term = bb->getTerminator();
      term->eraseFromParent();
      BranchInst::Create(end_bb, inv_cmp_bb, icmp_high, bb);

      /* create a bb which handles the cmp of the lower halves */
      BasicBlock *cmp_low_bb =
          BasicBlock::Create(C, "injected", end_bb->getParent(), end_bb);
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

    ++count;

  }

  return count;

}

bool SplitComparesTransform::runOnModule(Module &M) {

  int bitw = 64;

  char *bitw_env = getenv("AFL_LLVM_LAF_SPLIT_COMPARES_BITW");
  if (!bitw_env) bitw_env = getenv("LAF_SPLIT_COMPARES_BITW");
  if (bitw_env) { bitw = atoi(bitw_env); }

  enableFPSplit = getenv("AFL_LLVM_LAF_SPLIT_FLOATS") != NULL;

  simplifyCompares(M);

  simplifyIntSignedness(M);

  if ((isatty(2) && getenv("AFL_QUIET") == NULL) ||
      getenv("AFL_DEBUG") != NULL) {

    errs() << "Split-compare-pass by laf.intel@gmail.com, extended by "
              "heiko@hexco.de\n";

    if (enableFPSplit)
      errs() << "Split-floatingpoint-compare-pass: " << splitFPCompares(M)
             << " FP comparisons splitted\n";

  } else

    be_quiet = 1;

  switch (bitw) {

    case 64:
      if (!be_quiet)
        errs() << "Split-integer-compare-pass " << bitw
               << "bit: " << splitIntCompares(M, bitw) << " splitted\n";

      bitw >>= 1;
#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 7)
      [[clang::fallthrough]]; /*FALLTHRU*/                   /* FALLTHROUGH */
#endif
    case 32:
      if (!be_quiet)
        errs() << "Split-integer-compare-pass " << bitw
               << "bit: " << splitIntCompares(M, bitw) << " splitted\n";

      bitw >>= 1;
#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 7)
      [[clang::fallthrough]]; /*FALLTHRU*/                   /* FALLTHROUGH */
#endif
    case 16:
      if (!be_quiet)
        errs() << "Split-integer-compare-pass " << bitw
               << "bit: " << splitIntCompares(M, bitw) << " splitted\n";

      bitw >>= 1;
      break;

    default:
      if (!be_quiet) errs() << "NOT Running split-compare-pass \n";
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

