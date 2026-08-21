/*
   american fuzzy lop++ - LLVM CmpLog instrumentation
   --------------------------------------------------

   Written by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <cstdint>
#include <iostream>
#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>

#include "llvm/Config/llvm-config.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#if defined(__has_include) && __has_include("llvm/Plugins/PassPlugin.h")
  #include "llvm/Plugins/PassPlugin.h"
#else
  #include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#if LLVM_MAJOR <= 15
  #include "llvm/ADT/Triple.h"
#endif

#include <set>
#include "afl-llvm-common.h"
#include "cmplog.h"
#include "value-profile-attrs.h"

static bool is_64_arch = false;

using namespace llvm;

static bool isSignedOrderedICmp(CmpInst::Predicate Pred) {

  switch (Pred) {

    case CmpInst::ICMP_SGT:
    case CmpInst::ICMP_SGE:
    case CmpInst::ICMP_SLT:
    case CmpInst::ICMP_SLE:
      return true;
    default:
      return false;

  }

}

static Value *createFloatOrderKey(IRBuilder<> &IRB, Value *fp_value,
                                  unsigned bit_width) {

  IntegerType *IntTy = IntegerType::get(IRB.getContext(), bit_width);
  Value       *Raw = IRB.CreateBitCast(fp_value, IntTy);
  Value       *SignSpread = IRB.CreateAShr(Raw, bit_width - 1);
  Value       *Flip = IRB.CreateOr(
      SignSpread, ConstantInt::get(IntTy, APInt::getSignedMinValue(bit_width)));

  return IRB.CreateXor(Raw, Flip);

}

namespace {

using LoopInfoCallback = function_ref<LoopInfo *(Function &F)>;
using ScalarEvolutionCallback = function_ref<ScalarEvolution &(Function &F)>;
class CompareObserverPromotePass
    : public PassInfoMixin<CompareObserverPromotePass> {

 public:
  explicit CompareObserverPromotePass(bool opt_zero) : opt_zero_(opt_zero) {

    initInstrumentList();

  }

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM) {

    if (F.empty()) { return PreservedAnalyses::all(); }
    if (!isInInstrumentList(&F, FMNAME)) { return PreservedAnalyses::all(); }
    // Clang marks every function optnone at -O0, so honour it only above -O0
    if (F.hasOptNone() && !opt_zero_) { return PreservedAnalyses::all(); }

    SmallVector<AllocaInst *, 16> Allocas;
    for (Instruction &I : F.getEntryBlock()) {

      auto *AI = dyn_cast<AllocaInst>(&I);
      if (!AI) { continue; }
      if (!AI->isStaticAlloca()) { continue; }
      if (!isAllocaPromotable(AI)) { continue; }
      Allocas.push_back(AI);

    }

    if (Allocas.empty()) { return PreservedAnalyses::all(); }

    DominatorTree   &DT = FAM.getResult<DominatorTreeAnalysis>(F);
    AssumptionCache &AC = FAM.getResult<AssumptionAnalysis>(F);
    PromoteMemToReg(Allocas, DT, &AC);
    return PreservedAnalyses();

  }

  static bool isRequired() {

    return true;

  }

 private:
  bool opt_zero_;

};

class CmpLogInstructions : public PassInfoMixin<CmpLogInstructions> {

 public:
  explicit CmpLogInstructions(CompareObserverMode mode) : mode_(mode) {

    initInstrumentList();

  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

 private:
  CompareObserverMode mode_;
  bool                hookInstrs(Module &M, LoopInfoCallback LICallback,
                                 ScalarEvolutionCallback SECallback);

};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {

      LLVM_PLUGIN_API_VERSION, "cmploginstructions", "v0.1",
      /* lambda to insert our pass into the pass pipeline. */
      [](PassBuilder &PB) {

#if LLVM_VERSION_MAJOR <= 13
        using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
        PB.registerOptimizerLastEPCallback([](ModulePassManager &MPM,
                                              OptimizationLevel  OL
#if LLVM_VERSION_MAJOR >= 20
                                              ,
                                              ThinOrFullLTOPhase Phase
#endif
                                           ) {

          CompareObserverMode Mode = getCompareObserverModeFromEnv();

          if (isValueProfileMode(Mode) &&
              !getenv("AFL_LLVM_NO_COMPARE_MEM2REG")) {

            FunctionPassManager FPM;
            FPM.addPass(
                CompareObserverPromotePass(OL == OptimizationLevel::O0));
            MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));

          }

          MPM.addPass(CmpLogInstructions(Mode));

        });

      }};

}

template <class Iterator>
Iterator Unique(Iterator first, Iterator last) {

  while (first != last) {

    Iterator next(first);
    last = std::remove(++next, last, *first);
    first = next;

  }

  return last;

}

// Check if a compare instruction is a loop condition that should be skipped.
// Returns true if the branch is the loop iteration (induction / back-edge)
// condition for any containing loop: the loop header, the latch, or - for
// bottom-tested loops whose back-edge the coverage pass split off into a
// separate latch block - an exiting branch whose in-loop successor is the
// header or that latch. The split-back-edge case is only applied when the
// header itself is not the loop's exit test, so early-break data comparisons
// in top-tested loops (e.g. `if (x != y) break;`) stay instrumented.
static bool IsLoopCondition(BranchInst *BR, LoopInfo *LI) {

  if (!BR->isConditional()) return false;

  BasicBlock *BranchBB = BR->getParent();

  for (Loop *L = LI->getLoopFor(BranchBB); L; L = L->getParentLoop()) {

    if (L->getHeader() == BranchBB) return true;  // Loop header condition
    if (L->isLoopLatch(BranchBB)) return true;    // Back-edge source

    if (!L->isLoopExiting(L->getHeader()) && L->isLoopExiting(BranchBB)) {

      for (unsigned i = 0, e = BR->getNumSuccessors(); i < e; ++i) {

        BasicBlock *Succ = BR->getSuccessor(i);
        if (!L->contains(Succ)) continue;
        if (Succ == L->getHeader() || L->isLoopLatch(Succ)) return true;

      }

    }

  }

  return false;

}

static const SCEVAddRecExpr *getAffineLoopAddRec(const SCEV *Expr,
                                                 const Loop *L) {

  while (Expr) {

    if (const auto *AR = dyn_cast<SCEVAddRecExpr>(Expr)) {

      return (AR->getLoop() == L && AR->isAffine()) ? AR : nullptr;

    }

    if (const auto *Cast = dyn_cast<SCEVCastExpr>(Expr)) {

      Expr = Cast->getOperand();
      continue;

    }

    break;

  }

  return nullptr;

}

static bool predicateMatchesLoopStep(CmpInst::Predicate Pred,
                                     const APInt       &Step) {

  switch (Pred) {

    case CmpInst::ICMP_NE:
      return Step.isOne() || Step.isAllOnes();
    case CmpInst::ICMP_ULT:
    case CmpInst::ICMP_ULE:
    case CmpInst::ICMP_SLT:
    case CmpInst::ICMP_SLE:
      return !Step.isNegative();
    case CmpInst::ICMP_UGT:
    case CmpInst::ICMP_UGE:
    case CmpInst::ICMP_SGT:
    case CmpInst::ICMP_SGE:
      return Step.isNegative();
    default:
      return false;

  }

}

static bool isPlainLoopBoundAtomImpl(const SCEV                    *Expr,
                                     SmallPtrSetImpl<const SCEV *> &Visited) {

  if (!Visited.insert(Expr).second) { return true; }

  if (isa<SCEVConstant>(Expr)) { return true; }

  if (const auto *Unknown = dyn_cast<SCEVUnknown>(Expr)) {

    const Value *V = Unknown->getValue();
    if (isa<Argument>(V) || isa<Constant>(V) || isa<GlobalValue>(V)) {

      return true;

    }

    // Non-cast instructions, especially loop-local min/max/select values, can
    // encode semantic exits that LLVM folded into the trip count.
    return false;

  }

  if (const auto *Cast = dyn_cast<SCEVCastExpr>(Expr)) {

    return isPlainLoopBoundAtomImpl(Cast->getOperand(), Visited);

  }

  return false;

}

static bool isPlainLoopBoundAtom(const SCEV *Expr) {

  SmallPtrSet<const SCEV *, 8> Visited;
  return isPlainLoopBoundAtomImpl(Expr, Visited);

}

static bool isSimpleLoopControlBoundSCEV(
    const SCEV *Expr, SmallPtrSetImpl<const SCEV *> &Visited) {

  if (isPlainLoopBoundAtom(Expr)) { return true; }

  if (const auto *Cast = dyn_cast<SCEVCastExpr>(Expr)) {

    return isSimpleLoopControlBoundSCEV(Cast->getOperand(), Visited);

  }

  if (const auto *Add = dyn_cast<SCEVAddExpr>(Expr)) {

    for (const SCEV *Op : Add->operands())
      if (!isSimpleLoopControlBoundSCEV(Op, Visited)) { return false; }
    return true;

  }

  if (const auto *Mul = dyn_cast<SCEVMulExpr>(Expr)) {

    for (const SCEV *Op : Mul->operands())
      if (!isSimpleLoopControlBoundSCEV(Op, Visited)) { return false; }
    return true;

  }

  if (const auto *MinMax = dyn_cast<SCEVMinMaxExpr>(Expr)) {

    for (const SCEV *Op : MinMax->operands())
      if (!isPlainLoopBoundAtom(Op)) { return false; }

    return true;

  }

  return false;

}

static bool isSimpleLoopControlBound(Value *BoundCandidate, const Loop *L,
                                     ScalarEvolution &SE) {

  const SCEV *Bound = SE.getSCEV(BoundCandidate);
  if (!SE.isLoopInvariant(Bound, L)) { return false; }

  SmallPtrSet<const SCEV *, 8> Visited;
  return isSimpleLoopControlBoundSCEV(Bound, Visited);

}

static bool matchesCanonicalLoopControl(Value             *IVCandidate,
                                        Value             *BoundCandidate,
                                        CmpInst::Predicate ContinuePred,
                                        const Loop *L, ScalarEvolution &SE) {

  const auto *AddRec = getAffineLoopAddRec(SE.getSCEV(IVCandidate), L);
  if (!AddRec) { return false; }

  const auto *Step = dyn_cast<SCEVConstant>(AddRec->getStepRecurrence(SE));
  if (!Step || Step->getAPInt().isZero()) { return false; }

  if (!isSimpleLoopControlBound(BoundCandidate, L, SE)) { return false; }

  return predicateMatchesLoopStep(ContinuePred, Step->getAPInt());

}

struct CanonicalConditionUse {

  BranchInst *RootBranch = nullptr;
  const Loop *L = nullptr;
  bool        ContinueOnCmpTrue = false;
  bool        IsLoopContinuationControl = false;

};

class ConditionCanonicalizer {

 public:
  explicit ConditionCanonicalizer(LoopInfo *LI) : LI(LI) {

  }

  bool collectLoopContinuationUses(
      CmpInst *Cmp, SmallVectorImpl<CanonicalConditionUse> &Uses) const {

    if (!Cmp || !LI) { return false; }
    if (!Cmp->isIntPredicate()) { return false; }

    SmallVector<unsigned, 4> PathOps;
    BranchInst              *BR = nullptr;
    if (!findRootBranch(Cmp, PathOps, BR)) { return false; }
    if (!BR || !BR->isConditional()) { return false; }

    BasicBlock *BranchBB = BR->getParent();
    bool        Found = false;

    for (Loop *L = LI->getLoopFor(BranchBB); L; L = L->getParentLoop()) {

      bool ContinueOnTrue = false;
      if (!branchCanContinueLoop(L, BR, ContinueOnTrue)) { continue; }

      bool ContinueOnCmpTrue = false;
      if (!conditionRequiresCompareValue(PathOps, ContinueOnTrue,
                                         ContinueOnCmpTrue)) {

        continue;

      }

      if (Cmp->getFunction()->hasOptNone() && !ContinueOnCmpTrue &&
          !L->isLoopLatch(BranchBB) &&
          isEqualityPredicate(Cmp->getPredicate())) {

        continue;

      }

      CanonicalConditionUse Use;
      Use.RootBranch = BR;
      Use.L = L;
      Use.ContinueOnCmpTrue = ContinueOnCmpTrue;
      Use.IsLoopContinuationControl = true;
      Uses.push_back(Use);
      Found = true;

    }

    return Found;

  }

 private:
  LoopInfo *LI = nullptr;

  static int getKnownEdgeCondition(BasicBlock *BB, BasicBlock *Pred,
                                   Value *Condition) {

    if (auto *CI = dyn_cast<ConstantInt>(Condition)) {

      if (CI->getType()->isIntegerTy(1)) { return CI->isZero() ? 0 : 1; }

    }

    if (!Pred) { return -1; }

    auto *PN = dyn_cast<PHINode>(Condition);
    if (!PN || PN->getParent() != BB) { return -1; }

    Value *Incoming = PN->getIncomingValueForBlock(Pred);
    auto  *CI = dyn_cast<ConstantInt>(Incoming);
    if (!CI || !CI->getType()->isIntegerTy(1)) { return -1; }

    return CI->isZero() ? 0 : 1;

  }

  static bool reachesLoopBackedge(const Loop *L, BasicBlock *BB,
                                  BasicBlock                    *Pred,
                                  SmallPtrSetImpl<BasicBlock *> &Visited) {

    if (!L->contains(BB)) { return false; }
    if (!Visited.insert(BB).second) { return false; }
    if (L->isLoopLatch(BB)) { return true; }

    if (auto *BR = dyn_cast<BranchInst>(BB->getTerminator())) {

      if (BR->isConditional()) {

        int KnownCondition =
            getKnownEdgeCondition(BB, Pred, BR->getCondition());
        if (KnownCondition != -1) {

          return reachesLoopBackedge(
              L, BR->getSuccessor(KnownCondition ? 0 : 1), BB, Visited);

        }

      }

    }

    for (BasicBlock *Succ : successors(BB)) {

      if (reachesLoopBackedge(L, Succ, BB, Visited)) { return true; }

    }

    return false;

  }

  static bool branchCanContinueLoop(const Loop *L, BranchInst *BR,
                                    bool &ContinueOnTrue) {

    bool Succ0InLoop = L->contains(BR->getSuccessor(0));
    bool Succ1InLoop = L->contains(BR->getSuccessor(1));

    SmallPtrSet<BasicBlock *, 16> Visited;
    bool                          Succ0Continues =
        Succ0InLoop &&
        reachesLoopBackedge(L, BR->getSuccessor(0), BR->getParent(), Visited);

    Visited.clear();
    bool Succ1Continues =
        Succ1InLoop &&
        reachesLoopBackedge(L, BR->getSuccessor(1), BR->getParent(), Visited);

    if (Succ0Continues == Succ1Continues) { return false; }

    ContinueOnTrue = Succ0Continues;
    return true;

  }

  static Instruction *getSingleNonAflSkipUser(Value *V) {

    Instruction *Found = nullptr;

    for (User *U : V->users()) {

      auto *I = dyn_cast<Instruction>(U);
      if (!I) { return nullptr; }
      if (I->getMetadata("afl.skip")) { continue; }
      if (Found && Found != I) { return nullptr; }
      Found = I;

    }

    return Found;

  }

  static bool findRootBranch(Value                     *Condition,
                             SmallVectorImpl<unsigned> &PathOps,
                             BranchInst               *&BR) {

    SmallPtrSet<Value *, 8> Visited;

    while (Condition) {

      if (!Visited.insert(Condition).second) { return false; }

      Instruction *User = getSingleNonAflSkipUser(Condition);
      if (!User) { return false; }

      if ((BR = dyn_cast<BranchInst>(User))) {

        return BR->isConditional() && BR->getCondition() == Condition;

      }

      if (auto *BO = dyn_cast<BinaryOperator>(User)) {

        if (!BO->getType()->isIntegerTy(1)) { return false; }
        if (BO->getOpcode() != Instruction::And &&
            BO->getOpcode() != Instruction::Or) {

          return false;

        }

        PathOps.push_back(BO->getOpcode());
        Condition = BO;
        continue;

      }

      if (auto *Freeze = dyn_cast<FreezeInst>(User)) {

        Condition = Freeze;
        continue;

      }

      if (auto *PN = dyn_cast<PHINode>(User)) {

        if (!PN->getType()->isIntegerTy(1)) { return false; }

        Instruction *ConditionInst = dyn_cast<Instruction>(Condition);
        if (!ConditionInst) { return false; }

        bool FoundIncoming = false;
        for (unsigned I = 0, E = PN->getNumIncomingValues(); I != E; ++I) {

          if (PN->getIncomingValue(I) == Condition) {

            if (PN->getIncomingBlock(I) != ConditionInst->getParent()) {

              return false;

            }

            FoundIncoming = true;

          }

        }

        if (!FoundIncoming) { return false; }

        Condition = PN;
        continue;

      }

      return false;

    }

    return false;

  }

  static bool conditionRequiresCompareValue(
      const SmallVectorImpl<unsigned> &PathOps, bool ContinueOnRootTrue,
      bool &ContinueOnCmpTrue) {

    bool RequiredValue = ContinueOnRootTrue;

    for (auto It = PathOps.rbegin(); It != PathOps.rend(); ++It) {

      switch (*It) {

        case Instruction::And:
          if (!RequiredValue) { return false; }
          RequiredValue = true;
          break;
        case Instruction::Or:
          if (RequiredValue) { return false; }
          RequiredValue = false;
          break;
        default:
          return false;

      }

    }

    ContinueOnCmpTrue = RequiredValue;
    return true;

  }

  static bool isEqualityPredicate(CmpInst::Predicate Pred) {

    return Pred == CmpInst::ICMP_EQ || Pred == CmpInst::ICMP_NE;

  }

};

// Skip only canonical loop-control compares: a proven affine induction
// recurrence against a loop-invariant bound on the loop continue/exit branch.
static bool IsCanonicalLoopCondition(CmpInst *Cmp, LoopInfo *LI,
                                     ScalarEvolutionCallback SECallback) {

  if (!Cmp || !LI) { return false; }
  if (!Cmp->isIntPredicate()) { return false; }

  SmallVector<CanonicalConditionUse, 4> Uses;
  ConditionCanonicalizer                Canonicalizer(LI);
  if (!Canonicalizer.collectLoopContinuationUses(Cmp, Uses)) { return false; }

  for (const CanonicalConditionUse &Use : Uses) {

    if (!Use.IsLoopContinuationControl || !Use.L) { continue; }
    ScalarEvolution &SE = SECallback(*Cmp->getFunction());
    auto             ContinuePred = Use.ContinueOnCmpTrue
                                        ? Cmp->getPredicate()
                                        : CmpInst::getInversePredicate(Cmp->getPredicate());

    if (matchesCanonicalLoopControl(Cmp->getOperand(0), Cmp->getOperand(1),
                                    ContinuePred, Use.L, SE) ||
        matchesCanonicalLoopControl(Cmp->getOperand(1), Cmp->getOperand(0),
                                    CmpInst::getSwappedPredicate(ContinuePred),
                                    Use.L, SE)) {

      return true;

    }

  }

  return false;

}

static constexpr unsigned kVpInputDepDepthLimit = 32;

static bool isValueProfileInputDerived(Value *V, SmallPtrSetImpl<Value *> &Seen,
                                       unsigned Depth) {

  if (!V) { return false; }
  if (Depth >= kVpInputDepDepthLimit) { return true; }
  if (!Seen.insert(V).second) { return false; }

  if (isa<Argument>(V)) { return true; }
  if (isa<Constant>(V)) { return false; }

  auto *I = dyn_cast<Instruction>(V);
  if (!I) { return true; }

  switch (I->getOpcode()) {

    case Instruction::Alloca:
      return false;

    case Instruction::Load:
    case Instruction::AtomicRMW:
    case Instruction::AtomicCmpXchg:
    case Instruction::Call:
    case Instruction::Invoke:
    case Instruction::CallBr:
    case Instruction::VAArg:
    case Instruction::LandingPad:
      return true;

    case Instruction::PHI:
    case Instruction::Select:
    case Instruction::GetElementPtr:
    case Instruction::ExtractValue:
    case Instruction::InsertValue:
    case Instruction::ExtractElement:
    case Instruction::InsertElement:
    case Instruction::ShuffleVector:
    case Instruction::Freeze:
    case Instruction::ICmp:
    case Instruction::FCmp:
      break;

    default:
      if (!I->isUnaryOp() && !I->isBinaryOp() && !isa<CastInst>(I)) {

        return true;

      }

      break;

  }

  for (Value *Op : I->operands()) {

    if (isValueProfileInputDerived(Op, Seen, Depth + 1)) { return true; }

  }

  return false;

}

static bool comparesRoutineResult(CmpInst *Cmp) {

  for (Value *Op : Cmp->operands()) {

    Value *V = Op;
    for (;;) {

      if (auto *Cast = dyn_cast<CastInst>(V)) {

        V = Cast->getOperand(0);
        continue;

      }

      if (auto *Frozen = dyn_cast<FreezeInst>(V)) {

        V = Frozen->getOperand(0);
        continue;

      }

      break;

    }

    auto *Call = dyn_cast<CallInst>(V);
    if (!Call) { continue; }

    Function *Callee = Call->getCalledFunction();
    if (!Callee) { continue; }
    if (isCompareResultRoutineName(Callee->getName())) { return true; }

  }

  return false;

}

static bool hasValueProfileInputDependence(CmpInst *Cmp) {

  for (Value *Op : Cmp->operands()) {

    SmallPtrSet<Value *, 32> Seen;
    if (isValueProfileInputDerived(Op, Seen, 0)) { return true; }

  }

  return false;

}

bool CmpLogInstructions::hookInstrs(Module &M, LoopInfoCallback LICallback,
                                    ScalarEvolutionCallback SECallback) {

  std::vector<Instruction *> icomps;
  LLVMContext               &C = M.getContext();
  bool                       vp_mode = isValueProfileMode(mode_);

  Type        *VoidTy = Type::getVoidTy(C);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
  IntegerType *Int128Ty = IntegerType::getInt128Ty(C);
  Type        *floatTy = Type::getFloatTy(C);
  Type        *doubleTy = Type::getDoubleTy(C);

#if LLVM_MAJOR >= 20
  Type *PtrTy = PointerType::getUnqual(C);
#else
  Type *PtrTy = PointerType::get(Int8Ty, 0);
#endif

  FunctionCallee hookIns1 = nullptr;
  FunctionCallee hookIns2 = nullptr;
  FunctionCallee hookIns4 = nullptr;
  FunctionCallee hookIns8 = nullptr;
  FunctionCallee hookIns16 = nullptr;
  FunctionCallee hookInsN = nullptr;
  FunctionCallee hookFloat = nullptr;
  FunctionCallee hookDouble = nullptr;

  if (vp_mode) {

    hookIns1 = M.getOrInsertFunction("__valueprofile_hook1", VoidTy, Int8Ty,
                                     Int8Ty, Int8Ty, Int64Ty);

    hookIns2 = M.getOrInsertFunction("__valueprofile_hook2", VoidTy, Int16Ty,
                                     Int16Ty, Int8Ty, Int64Ty);

    hookIns4 = M.getOrInsertFunction("__valueprofile_hook4", VoidTy, Int32Ty,
                                     Int32Ty, Int8Ty, Int64Ty);

    hookIns8 = M.getOrInsertFunction("__valueprofile_hook8", VoidTy, Int64Ty,
                                     Int64Ty, Int8Ty, Int64Ty);

    if (is_64_arch) {

      hookIns16 = M.getOrInsertFunction("__valueprofile_hook16", VoidTy,
                                        Int128Ty, Int128Ty, Int8Ty, Int64Ty);
      hookInsN = M.getOrInsertFunction("__valueprofile_hookN", VoidTy, Int128Ty,
                                       Int128Ty, Int8Ty, Int8Ty, Int64Ty);

    }

    hookFloat = M.getOrInsertFunction("__valueprofile_hook_float", VoidTy,
                                      floatTy, floatTy, Int8Ty, Int64Ty);
    hookDouble = M.getOrInsertFunction("__valueprofile_hook_double", VoidTy,
                                       doubleTy, doubleTy, Int8Ty, Int64Ty);

  } else {

    hookIns1 = M.getOrInsertFunction("__cmplog_ins_hook1", VoidTy, Int8Ty,
                                     Int8Ty, Int8Ty);

    hookIns2 = M.getOrInsertFunction("__cmplog_ins_hook2", VoidTy, Int16Ty,
                                     Int16Ty, Int8Ty);

    hookIns4 = M.getOrInsertFunction("__cmplog_ins_hook4", VoidTy, Int32Ty,
                                     Int32Ty, Int8Ty);

    hookIns8 = M.getOrInsertFunction("__cmplog_ins_hook8", VoidTy, Int64Ty,
                                     Int64Ty, Int8Ty);

    if (is_64_arch) {

      hookIns16 = M.getOrInsertFunction("__cmplog_ins_hook16", VoidTy, Int128Ty,
                                        Int128Ty, Int8Ty);
      hookInsN = M.getOrInsertFunction("__cmplog_ins_hookN", VoidTy, Int128Ty,
                                       Int128Ty, Int8Ty, Int8Ty);

    }

  }

  GlobalVariable *AFLCmplogPtr =
      getOrCreateExternalWeakPtrGlobal(M, PtrTy, "__afl_cmp_map");

  GlobalVariable *AFLVpEnabledPtr = nullptr;
  if (vp_mode) {

    AFLVpEnabledPtr =
        getOrCreateExternalPtrGlobal(M, PtrTy, "__afl_vp_enabled_ptr");

  }

  /* iterate over all functions, bbs and instruction and add suitable calls */
  for (auto &F : M) {

    if (!isInInstrumentList(&F, MNAME)) continue;
    if (F.empty()) continue;
    LoopInfo *LI = LICallback(F);

    for (auto &BB : F) {

      for (auto &IN : BB) {

        CmpInst *selectcmpInst = nullptr;
        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {

          if (selectcmpInst->getMetadata("afl.skip")) continue;
          if (vp_mode) {

            // Preserve VP's canonical loop-control filter: semantic compares
            // in loop headers and latches remain visible unless they are
            // proven affine induction control.
            if (IsCanonicalLoopCondition(selectcmpInst, LI, SECallback)) {

              continue;

            }

            if (!hasValueProfileInputDependence(selectcmpInst)) { continue; }
            if (comparesRoutineResult(selectcmpInst)) { continue; }

          } else if (selectcmpInst->hasOneUse()) {

            // Preserve upstream CmpLog loop filtering.
            if (auto BR = dyn_cast<BranchInst>(selectcmpInst->user_back()))
              if (IsLoopCondition(BR, LI)) continue;

          }

          icomps.push_back(selectcmpInst);

        }

      }

    }

  }

  if (icomps.size()) {

    constexpr uint64_t                   kVpInstructionSiteSalt = 0x49565350ULL;
    DenseMap<const Function *, uint64_t> vp_site_fallback_ordinal;
    DenseMap<const Function *, DenseMap<uint64_t, uint64_t>>
        vp_site_debug_disambiguator;

    // if (!be_quiet) errs() << "Hooking " << icomps.size() <<
    //                          " cmp instructions\n";

    auto getHookInsertPoint = [&](Instruction *InsertBefore) -> Instruction * {

      if (vp_mode) {

        IRBuilder<> IRB2(InsertBefore->getParent());
        IRB2.SetInsertPoint(InsertBefore);
        Value *is_enabled = createValueProfileEnabledGuard(
            IRB2, AFLVpEnabledPtr, PtrTy, Int8Ty);

        Instruction *ThenTerm = SplitBlockAndInsertIfThen(
            is_enabled, InsertBefore, false,
            createValueProfileGuardWeights(M.getContext()));
        markAflSyntheticBlock(ThenTerm->getParent());
        return ThenTerm;

      }

      IRBuilder<> IRB2(InsertBefore->getParent());
      IRB2.SetInsertPoint(InsertBefore);
      Value *is_not_null =
          createMapPtrNotNullGuard(IRB2, M, AFLCmplogPtr, PtrTy);

      return SplitBlockAndInsertIfThen(is_not_null, InsertBefore, false);

    };

    for (auto &selectcmpInst : icomps) {

      uint64_t site_disambiguator = 0;

      if (vp_mode) {

        if (selectcmpInst->getDebugLoc()) {

          uint64_t debug_site_key = getValueProfileDebugSiteKey(*selectcmpInst);
          site_disambiguator =
              vp_site_debug_disambiguator[selectcmpInst->getFunction()]
                                         [debug_site_key]++;

        } else {

          site_disambiguator =
              vp_site_fallback_ordinal[selectcmpInst->getFunction()]++;

        }

      }

      Value *op0 = selectcmpInst->getOperand(0);
      Value *op1 = selectcmpInst->getOperand(1);
      Value *op0_saved = op0, *op1_saved = op1;
      auto   ty0 = op0->getType();
      auto   ty1 = op1->getType();

      IntegerType *intTyOp0 = NULL;
      IntegerType *intTyOp1 = NULL;
      unsigned     max_size = 0, cast_size = 0;
      unsigned     vector_cnt = 0, is_fp = 0;
      CmpInst     *cmpInst = dyn_cast<CmpInst>(selectcmpInst);

      if (!cmpInst) { continue; }
      unsigned attr = (unsigned)cmpInst->getPredicate();

      if (selectcmpInst->getOpcode() == Instruction::FCmp) {

        if (ty0->isVectorTy()) {

          VectorType *tt = dyn_cast<VectorType>(ty0);
          if (!tt) {

            fprintf(stderr, "Warning: cmplog cmp vector is not a vector!\n");
            continue;

          }

          vector_cnt = tt->getElementCount().getKnownMinValue();
          ty0 = tt->getElementType();

        }

        if (ty0->isHalfTy() || ty0->isBFloatTy())
          max_size = 16;
        else if (ty0->isFloatTy())
          max_size = 32;
        else if (ty0->isDoubleTy())
          max_size = 64;
        else if (ty0->isX86_FP80Ty())
          max_size = 80;
        else if (ty0->isFP128Ty() || ty0->isPPC_FP128Ty())
          max_size = 128;
        else if (ty0->getTypeID() != llvm::Type::PointerTyID && !be_quiet)
          fprintf(stderr, "Warning: unsupported cmp type for cmplog: %u!\n",
                  ty0->getTypeID());

        is_fp = 1;
        // fprintf(stderr, "HAVE FP %u!\n", vector_cnt);

      } else {

        if (ty0->isVectorTy()) {

          VectorType *tt = dyn_cast<VectorType>(ty0);
          if (!tt) {

            fprintf(stderr, "Warning: cmplog cmp vector is not a vector!\n");
            continue;

          }

          vector_cnt = tt->getElementCount().getKnownMinValue();
          ty1 = ty0 = tt->getElementType();

        }

        intTyOp0 = dyn_cast<IntegerType>(ty0);
        intTyOp1 = dyn_cast<IntegerType>(ty1);

        if (intTyOp0 && intTyOp1) {

          max_size = intTyOp0->getBitWidth() > intTyOp1->getBitWidth()
                         ? intTyOp0->getBitWidth()
                         : intTyOp1->getBitWidth();

        } else {

          if (ty0->getTypeID() != llvm::Type::PointerTyID && !be_quiet) {

            fprintf(stderr, "Warning: unsupported cmp type for cmplog: %u\n",
                    ty0->getTypeID());

          }

        }

      }

      if (!max_size || max_size < 13 /*||
          (max_size == 8 && !isa<Constant>(op0_saved) &&
           !isa<Constant>(op1_saved))*/) {

        // fprintf(stderr, "too small\n");
        continue;

      }

      if (max_size % 8) { max_size = (((max_size / 8) + 1) * 8); }

      if (max_size > 128) {

        if (!be_quiet) {

          fprintf(stderr,
                  "Cannot handle this compare bit size: %u (truncating)\n",
                  max_size);

        }

        max_size = 128;

      }

      // do we need to cast?
      switch (max_size) {

        case 8:
          cast_size = 8;
          break;
        case 16:
          cast_size = 16;
          break;
        case 17 ... 32:
          cast_size = 32;
          break;
        case 33 ... 64:
          cast_size = 64;
          break;
        default:
          // 9-15 + 65-128 bit values are handled via 128-bit hooks.
          cast_size = 128;

      }

      bool is_native = max_size == 8 || max_size == 16 || max_size == 32 ||
                       max_size == 64 || max_size == 128;
      bool use_hookN =
          is_64_arch &&
          (vp_mode ? (cast_size == 128 && cast_size != max_size) : !is_native);
      if (use_hookN) { cast_size = 128; }

      // XXX FIXME BUG TODO
      if (is_fp && vector_cnt) { continue; }

      /* Half and bfloat widen to float exactly, so they can share the float
         hook. x86_fp80, fp128 and ppc_fp128 have no exact widening target and
         are scored on their bit encoding through the 128-bit integer hooks,
         which only exist on 64-bit hosts. Decide that here, before the enabled
         guard splits the block, so an unsupported type does not leave an empty
         guarded block behind. */
      if (vp_mode && is_fp && cast_size == 128 && !is_64_arch) { continue; }

      IRBuilder<> IRB(getHookInsertPoint(selectcmpInst));

      uint64_t cur = 0, last_val0 = 0, last_val1 = 0, cur_val;

      while (1) {

        std::vector<Value *> args;
        bool                 skip = false;

        if (vector_cnt) {

          op0 = IRB.CreateExtractElement(op0_saved, cur);
          op1 = IRB.CreateExtractElement(op1_saved, cur);
          /*
          std::string errMsg;
          raw_string_ostream os(errMsg);
          op0_saved->print(os);
          fprintf(stderr, "X: %s\n", os.str().c_str());
          */
          if (is_fp) {

            /*
                        ConstantFP *i0 = dyn_cast<ConstantFP>(op0);
                        ConstantFP *i1 = dyn_cast<ConstantFP>(op1);
                        // BUG FIXME TODO: this is null ... but why?
                        // fprintf(stderr, "%p %p\n", i0, i1);
                        if (i0) {

                          cur_val =
               (uint64_t)i0->getValue().convertToDouble(); if (last_val0 &&
               last_val0 == cur_val) { skip = true;

               } last_val0 = cur_val;

                        }

                        if (i1) {

                          cur_val =
               (uint64_t)i1->getValue().convertToDouble(); if (last_val1 &&
               last_val1 == cur_val) { skip = true;

               } last_val1 = cur_val;

                        }

            */

          } else {

            ConstantInt *i0 = dyn_cast<ConstantInt>(op0);
            ConstantInt *i1 = dyn_cast<ConstantInt>(op1);
            if (i0 && i0->uge(0xffffffffffffffff) == false) {

              cur_val = i0->getZExtValue();
              if (last_val0 && last_val0 == cur_val) { skip = true; }
              last_val0 = cur_val;

            }

            if (i1 && i1->uge(0xffffffffffffffff) == false) {

              cur_val = i1->getZExtValue();
              if (last_val1 && last_val1 == cur_val) { skip = true; }
              last_val1 = cur_val;

            }

          }

        }

        if (!skip) {

          ConstantInt *attribute = ConstantInt::get(Int8Ty, attr);
          ConstantInt *siteToken = nullptr;
          if (vp_mode) {

            siteToken = ConstantInt::get(
                Int64Ty, computeValueProfileSiteToken(*selectcmpInst,
                                                      kVpInstructionSiteSalt,
                                                      site_disambiguator, cur));

          }

          if (vp_mode && is_fp) {

            if (cast_size == 16) {

              args.push_back(IRB.CreateFPExt(op0, floatTy));
              args.push_back(IRB.CreateFPExt(op1, floatTy));
              args.push_back(attribute);
              args.push_back(siteToken);
              IRB.CreateCall(hookFloat, args);
              goto next_vec_elem;

            }

            if (cast_size == 32 || cast_size == 64) {

              args.push_back(op0);
              args.push_back(op1);
              args.push_back(attribute);
              args.push_back(siteToken);
              if (cast_size == 32) {

                IRB.CreateCall(hookFloat, args);

              } else {

                IRB.CreateCall(hookDouble, args);

              }

              goto next_vec_elem;

            }

            op0 = createFloatOrderKey(IRB, op0, ty0->getPrimitiveSizeInBits());
            op1 = createFloatOrderKey(IRB, op1, ty1->getPrimitiveSizeInBits());

          }

          // errs() << "[CMPLOG] cmp  " << *cmpInst << "(in function " <<
          // cmpInst->getFunction()->getName() << ")\n";

          // first bitcast to integer type of the same bitsize as the original
          // type (this is a nop, if already integer)
          Value *op0_i = IRB.CreateBitCast(
              op0, IntegerType::get(C, ty0->getPrimitiveSizeInBits()));
          bool sign_extend = isSignedOrderedICmp(cmpInst->getPredicate());
          // then create a int cast, which does extend, trunc or bitcast. In
          // our case usually extend to the next larger supported type (this
          // is a nop if already the right type)
          Value *V0 = IRB.CreateIntCast(op0_i, IntegerType::get(C, cast_size),
                                        sign_extend);
          args.push_back(V0);
          Value *op1_i = IRB.CreateBitCast(
              op1, IntegerType::get(C, ty1->getPrimitiveSizeInBits()));
          Value *V1 = IRB.CreateIntCast(op1_i, IntegerType::get(C, cast_size),
                                        sign_extend);
          args.push_back(V1);

          // errs() << "[CMPLOG] casted parameters:\n0: " << *V0 << "\n1: " <<
          // *V1
          // << "\n";

          args.push_back(attribute);

          if (use_hookN) {

            ConstantInt *bitsize = ConstantInt::get(Int8Ty, (max_size / 8) - 1);
            args.push_back(bitsize);

          }

          if (vp_mode) { args.push_back(siteToken); }

          // fprintf(stderr, "_ExtInt(%u) castTo %u with attr %u didcast
          // %u\n",
          //         max_size, cast_size, attr);

          switch (cast_size) {

            case 8:
              IRB.CreateCall(hookIns1, args);
              break;
            case 16:
              IRB.CreateCall(hookIns2, args);
              break;
            case 32:
              IRB.CreateCall(hookIns4, args);
              break;
            case 64:
              IRB.CreateCall(hookIns8, args);
              break;
            case 128:
              if (is_64_arch) {

                if (use_hookN) {

                  IRB.CreateCall(hookInsN, args);

                } else {

                  IRB.CreateCall(hookIns16, args);

                }

              }

              break;

          }

        }

        /* else fprintf(stderr, "skipped\n"); */

      next_vec_elem:
        ++cur;
        if (cur >= vector_cnt) { break; }

      }

    }

  }

  if (icomps.size())
    return true;
  else
    return false;

}

PreservedAnalyses CmpLogInstructions::run(Module                &M,
                                          ModuleAnalysisManager &MAM) {

  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  auto  LICallback = [&FAM](Function &F) -> LoopInfo  *{

    return &FAM.getResult<LoopAnalysis>(F);

  };

  auto SECallback = [&FAM](Function &F) -> ScalarEvolution & {

    return FAM.getResult<ScalarEvolutionAnalysis>(F);

  };

#if LLVM_MAJOR <= 20
  auto triple = Triple(M.getTargetTriple());
#else
  auto triple = M.getTargetTriple();
#endif
  if (triple.isArch64Bit()) { is_64_arch = true; }
  bool vp_mode = isValueProfileMode(mode_);

  if (vp_mode) { markInstrumentedMarker(M, "__afl_vp_instrumented"); }

  if (getenv("AFL_QUIET") != NULL) {

    be_quiet = 1;

  } else if (vp_mode) {

    printf("Running valueprofile-instructions-pass by AFL++ team\n");

  } else {

    printf("Running cmplog-instructions-pass by andreafioraldi@gmail.com\n");

  }

  bool ret = hookInstrs(M, LICallback, SECallback);

  verifyModule(M);
  if (ret || vp_mode) { return PreservedAnalyses::none(); }
  return PreservedAnalyses::all();

}

