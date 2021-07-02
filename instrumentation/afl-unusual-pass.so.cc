#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"
#include "unusual.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <list>
#include <string>
#include <fstream>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <sys/time.h>

#include "llvm/Config/llvm-config.h"
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 5
typedef long double max_align_t;
#endif

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Dominators.h"
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

#include "afl-llvm-common.h"
#include "RangeAnalysis.h"

using namespace llvm;
using namespace RangeAnalysis;

/*
static size_t TypeSizeToSizeIndex(uint32_t TypeSize) {

  if (TypeSize == 1) TypeSize = 8;
  size_t Res = countTrailingZeros(TypeSize / 8);
  return Res;

}

*/

namespace {

struct AFLUnusual {

  AFLUnusual(Module &_M, Function &_F, DominatorTree &_DT,
             IntraProceduralRA<Cousot> &_RA)
      : M(_M), F(_F), DT(_DT), RA(_RA) {

    initialize();

  }

  static bool isBlacklisted(const Function *F) {

    static const char *Blacklist[] = {

        "asan.", "llvm.",      "sancov.", "__ubsan_handle_", "ign.", "__afl_",
        "_fini", "__libc_csu", "__asan",  "__msan",          "msan."

    };

    for (auto const &BlacklistFunc : Blacklist) {

      if (F->getName().startswith(BlacklistFunc)) return true;

    }

    // if (F->getName() == "main") return true;
    if (F->getName() == "_start") return true;

    return false;

  }

  void initialize();
  bool instrumentFunction();

  Type *VoidTy, *Int8Ty, *Int16Ty, *Int32Ty, *Int64Ty, *FloatTy, *DoubleTy,
      *StructTy, *Int8PTy, *Int16PTy, *Int32PTy, *Int64PTy, *FloatPTy,
      *DoublePTy, *StructPTy, *FuncTy;
  Type *IntTypeSized[4];

  Function *dbgDeclareFn;

  FunctionCallee unusualValuesFns[6];
  FunctionCallee unusualValuesPtrFn;
  FunctionCallee unusualValuesLogFn;

  bool noSingle = false;
  bool noPtrs = false;

  LLVMContext *C;
  Module &     M;
  Function &   F;

  DominatorTree &            DT;
  IntraProceduralRA<Cousot> &RA;

  int LongSize;

  std::map<Value *, int> Comp;
  int                    CompID = 0;

  std::vector<DILocalVariable *> DbgVars;

};

}  // namespace

void AFLUnusual::initialize() {

  C = &(M.getContext());

  LongSize = M.getDataLayout().getPointerSizeInBits();

  VoidTy = Type::getVoidTy(*C);

  Int8Ty = IntegerType::get(*C, 8);
  Int16Ty = IntegerType::get(*C, 16);
  Int32Ty = IntegerType::get(*C, 32);
  Int64Ty = IntegerType::get(*C, 64);

  FloatTy = Type::getFloatTy(*C);
  DoubleTy = Type::getDoubleTy(*C);

  StructTy = StructType::create(*C);

  Int8PTy = PointerType::get(Int8Ty, 0);
  Int16PTy = PointerType::get(Int16Ty, 0);
  Int32PTy = PointerType::get(Int32Ty, 0);
  Int64PTy = PointerType::get(Int64Ty, 0);

  FloatPTy = PointerType::get(FloatTy, 0);
  DoublePTy = PointerType::get(DoubleTy, 0);

  StructPTy = PointerType::get(StructTy, 0);

  FuncTy = FunctionType::get(VoidTy, true);

  dbgDeclareFn = M.getFunction("llvm.dbg.declare");

  IntTypeSized[0] = Int8Ty;
  IntTypeSized[1] = Int16Ty;
  IntTypeSized[2] = Int32Ty;
  IntTypeSized[3] = Int64Ty;

  unusualValuesFns[0] = M.getOrInsertFunction("__afl_unusual_values_1", Int32Ty,
                                              Int32Ty, Int64Ty, Int8Ty);
  unusualValuesFns[1] = M.getOrInsertFunction("__afl_unusual_values_2", Int32Ty,
                                              Int32Ty, Int64Ty, Int64Ty);
  unusualValuesFns[2] = M.getOrInsertFunction(
      "__afl_unusual_values_3", Int32Ty, Int32Ty, Int64Ty, Int64Ty, Int64Ty);

  unusualValuesPtrFn = M.getOrInsertFunction("__afl_unusual_values_ptr", Int32Ty, Int32Ty, Int8PTy, Int8Ty);

  unusualValuesLogFn =
      M.getOrInsertFunction("__afl_unusual_values_log", VoidTy, Int32Ty);

  /* Show a banner */

  setvbuf(stdout, NULL, _IONBF, 0);

  if (getenv("AFL_DEBUG")) debug = 1;

  if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {

    SAYF(cCYA "afl-unusual-pass" VERSION cRST
              " by <andreafioraldi@gmail.com>\n");

  } else

    be_quiet = 1;

  noSingle = !!getenv("AFL_NO_SINGLE_UNUSUAL_VALUES");
  noPtrs = !!getenv("AFL_NO_PTR_UNUSUAL_VALUES");

}

static void AddComp(std::map<Value *, int> &Comp, int &CompID, Value *A) {

  bool hasA = Comp.find(A) != Comp.end();

  if (!hasA) {

    Comp[A] = CompID;
    ++CompID;

  }

}

static void MergeComp(std::map<Value *, int> &Comp, int &CompID, Value *A,
                      Value *B) {

  bool hasA = Comp.find(A) != Comp.end();
  bool hasB = Comp.find(B) != Comp.end();

  if (hasA && !hasB)
    Comp[B] = Comp[A];
  else if (!hasA && hasB)
    Comp[A] = Comp[B];
  else if (!hasA && !hasB) {

    Comp[A] = CompID;
    Comp[B] = CompID;
    ++CompID;

  } else {

    int AID = Comp[A];
    int BID = Comp[B];
    for (auto &K : Comp) {

      if (K.second == BID) K.second = AID;

    }

  }

}

static bool IsAlloca(Value* V) {

  // we assume it is a ptr instruction
  if (isa<AllocaInst>(V)) return true;
  if (auto C = dyn_cast<CastInst>(V)) {
    return IsAlloca(C->getOperand(0));
  }
  
  return false;

}

bool AFLUnusual::instrumentFunction() {

  bool FunctionModified = false;

  if (isBlacklisted(&F)) return FunctionModified;  // not supported

  struct timeval  tv;
  struct timezone tz;
  /* Setup random() so we get Actually Random(TM) outputs from AFL_R() */
  gettimeofday(&tv, &tz);
  AFL_SR(tv.tv_sec ^ tv.tv_usec ^ getpid());

  std::set<Value *>         LocVals;
  std::vector<BasicBlock *> Blocks;

  unsigned Calls1 = 0, Calls2 = 0;
  unsigned Key = 0;

  for (Function::arg_iterator it = F.arg_begin(); it != F.arg_end(); ++it) {

    Argument *A = &*it;
    Value *   V = static_cast<Value *>(A);

    if (LocVals.find(V) == LocVals.end()) LocVals.insert(V);
    AddComp(Comp, CompID, V);

  }

  std::function<void(BasicBlock *)> VisitBlock = [&](BasicBlock *BB) {

    Blocks.push_back(BB);
    SmallVector<BasicBlock *, 3> Doms;
    DT.getDescendants(BB, Doms);
    for (auto DBB : Doms) {

      if (std::find(Blocks.begin(), Blocks.end(), DBB) == Blocks.end())
        VisitBlock(DBB);

    }

  };

  VisitBlock(&F.getEntryBlock());

  for (auto BB : Blocks) {

    for (auto &I : *BB) {

      if (auto *L = dyn_cast<LoadInst>(&I)) {

        AddComp(Comp, CompID, L);
        AddComp(Comp, CompID, L->getPointerOperand());

      } else if (auto ST = dyn_cast<StoreInst>(&I)) {

        AddComp(Comp, CompID, ST->getPointerOperand());
        AddComp(Comp, CompID, ST->getValueOperand());

      } else if (auto *DbgValue = dyn_cast<DbgValueInst>(&I)) {

        Value *V = DbgValue->getValue();
        if (V && !isa<Constant>(V)) {

          if (LocVals.find(V) == LocVals.end()) LocVals.insert(V);
          AddComp(Comp, CompID, V);

        }

      } else if (auto *RI = dyn_cast<ReturnInst>(&I)) {

        Value *V = RI->getReturnValue();
        if (V && !isa<Constant>(V)) {

          if (LocVals.find(V) == LocVals.end()) LocVals.insert(V);
          AddComp(Comp, CompID, V);

        }

      }

    }

  }

  for (auto BB : Blocks) {

    for (auto &I : *BB) {

      if (UnaryOperator *O = dyn_cast<UnaryOperator>(&I)) {

        MergeComp(Comp, CompID, O, O->getOperand(0));

      } else if (BinaryOperator *O = dyn_cast<BinaryOperator>(&I)) {

        MergeComp(Comp, CompID, O->getOperand(0), O->getOperand(1));
        MergeComp(Comp, CompID, O, O->getOperand(1));

      } else if (CastInst *C = dyn_cast<CastInst>(&I)) {

        MergeComp(Comp, CompID, C, C->getOperand(0));

      } else if (GetElementPtrInst *G = dyn_cast<GetElementPtrInst>(&I)) {

        MergeComp(Comp, CompID, G, G->getPointerOperand());
        Value *First = nullptr;
        for (auto Idx = G->idx_begin(); Idx != G->idx_end(); ++Idx) {

          if (Idx->get() && !isa<ConstantInt>(Idx->get())) {

            if (First)
              MergeComp(Comp, CompID, First, Idx->get());
            else
              First = Idx->get();

          }

        }

      }

    }

  }

  std::set<Value *>                     Dumpeds1;
  std::set<std::pair<Value *, Value *>> Dumpeds2;

  for (auto &BB : Blocks) {

    std::map<int, std::set<Value *>> CompArgs;
    
    std::set<Value *> Rets;
    Value* Hash = nullptr;

    IRBuilder<> IRB(BB->getTerminator());

    auto GroupVar = [&](Value *V) {

      Type *T = V->getType();
      int   CompID = -1;
      if (Comp.find(V) != Comp.end()) CompID = Comp[V];

      if (T->getTypeID() == Type::IntegerTyID) {

        TypeSize BitsNum = T->getPrimitiveSizeInBits();
        if (BitsNum <= 64) {

          // Value *I = IRB.CreateSExtOrBitCast(V, Int64Ty);
          // CompArgs[CompID].insert(I);
          CompArgs[CompID].insert(V);
          return true;

        }

      } else if (!noPtrs && T->getTypeID() == Type::PointerTyID) {
      
        //if (!AA.pointsToConstantMemory(V)) {
        
          // TODO get pointer values but avoid to emit checks that compare
          // pointers to integers
          // to check single invariants on pointers emit a different check
          // routine that see if it is NULL or a stack or heap ptr

          CompArgs[CompID].insert(V);
          return true;
        
        //}

      }

      return false;

    };

    for (auto &I : *BB) {

      if (I.getMetadata(M.getMDKindID("nosanitize"))) continue;

      if (isa<PHINode>(&I)) continue;

      for (auto op = I.op_begin(); op != I.op_end(); ++op) {

        Value *V = op->get();
        if (LocVals.find(V) != LocVals.end()) GroupVar(V);

      }

      // ATM remove GEP as interesting instruction
      /* if (auto GEP = dyn_cast<GetElementPtrInst>(&I)) {

        if (!isa<PointerType>(GEP->getSourceElementType())) continue;
        if (!GEP->hasIndices()) continue;

        GroupVar(GEP->getPointerOperand());

        for (auto Idx = GEP->idx_begin(); Idx != GEP->idx_end(); ++Idx) {

          if (Idx->get() && !isa<ConstantInt>(Idx->get())) GroupVar(Idx->get());

        }

      } else */
      
      if (auto LD = dyn_cast<LoadInst>(&I)) {

        GroupVar(LD->getPointerOperand());
        GroupVar(LD);

      } else if (auto ST = dyn_cast<StoreInst>(&I)) {

        GroupVar(ST->getPointerOperand());
        GroupVar(ST->getValueOperand());

      }

    }
    
    int SingleCnt = 0;

    for (auto P : CompArgs) {

      // if (P.first == -1) continue;

      // if (P.second.size() <= 1) continue;

      for (auto X : P.second) {

        Value *XB = nullptr;

        if (isa<Constant>(X)) {

          // errs() << "COSNT VAL  " << *X << "\n";
          Dumpeds1.insert(X);

        }
        
        if (X->getType()->getTypeID() == Type::PointerTyID && IsAlloca(X)) {
          
          Dumpeds1.insert(X);
          
        }

        /*if (LoadInst *L = dyn_cast<LoadInst>(X)) {

          // Skip load from constant mem
          if (AA.pointsToConstantMemory(L->getPointerOperand())) {

            // errs() << "COSNT MEM  " << *L << "\n";
            Dumpeds1.insert(X);

          }

        }*/

        if (!noSingle && Dumpeds1.find(X) == Dumpeds1.end()) {

          Range Rng = RA.getRange(X);

          bool MustCheck = false;
          u8   always_true = INV_ALL;
          u8   always_ptr_true = INV_ALL;

          if (!Rng.isUnknown() && !Rng.isEmpty()) {

            bool HasMin = Rng.getLower().getActiveBits() <= 64;
            bool HasMax = Rng.getUpper().getActiveBits() <= 64;

            if (HasMin && HasMax) {

              int64_t A = (int64_t)Rng.getLower().getSExtValue();
              int64_t B = (int64_t)Rng.getUpper().getSExtValue();

              // errs() << "Range " << A << " - " << B << "\n";

              if (A > 0 && B > 0) always_true = INV_GT;
              if (A >= 0 && B > 0) always_true = INV_GE;
              if (A < 0 && B < 0) always_true = INV_LT;
              if (A < 0 && B <= 0) always_true = INV_LE;
              
              if ((uint64_t)A >= 4096) always_ptr_true = INV_GE_PAGE;

              // if (!((A > 0 && B > 0) || (A < 0 && B < 0) || (A == B))) {

              if (A != B) { MustCheck = true; }  // else

              // errs() << "SKIP " << A << " - " << B << "\n";

            }

          } else {

            MustCheck = true;

          }

          if (MustCheck) {

            CallInst *CI;
            Key = AFL_R(UNUSUAL_MAP_SIZE);
            
            if (X->getType()->getTypeID() == Type::IntegerTyID) {

              XB = IRB.CreateSExtOrBitCast(X, Int64Ty);
              //XB->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));

              CI = IRB.CreateCall(
                  unusualValuesFns[0],
                  ArrayRef<Value *>{ConstantInt::get(Int32Ty, Key, true), XB,
                                    ConstantInt::get(Int8Ty, always_true, true)});
                                    
            } else { // Pointer
            
              auto* XP = IRB.CreateBitCast(X, Int8PTy);
              //XP->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
            
              CI = IRB.CreateCall(
                  unusualValuesPtrFn,
                  ArrayRef<Value *>{ConstantInt::get(Int32Ty, Key, true), XP,
                                    ConstantInt::get(Int8Ty, always_ptr_true, true)});
            
            }

            CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
            ++Calls1;
            ++SingleCnt;

            Rets.insert(CI);
            if (Hash == nullptr) Hash = CI;
            else Hash = IRB.CreateXor(Hash, CI);

          }

          Dumpeds1.insert(X);

        }

        // if (P.first == -1) continue;

        for (auto O : CompArgs) {

          if (P.first != -1 && P.first != O.first) continue;

          for (auto Y : O.second) {

            if (X == Y ||
                X->getType()->getTypeID() != Y->getType()->getTypeID() ||
                Dumpeds2.find(std::make_pair(X, Y)) != Dumpeds2.end() ||
                Dumpeds2.find(std::make_pair(Y, X)) != Dumpeds2.end())
              continue;
            
            if (X->getType()->getTypeID() == Type::PointerTyID && IsAlloca(X) && IsAlloca(Y)) continue;
            
            CallInst *CI;
            Key = AFL_R(UNUSUAL_MAP_SIZE);

            if (XB == nullptr) {
              XB = IRB.CreateSExtOrBitCast(X, Int64Ty);
              //XB->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
            }

            auto *YB = IRB.CreateSExtOrBitCast(Y, Int64Ty);

            CI = IRB.CreateCall(
                unusualValuesFns[1],
                ArrayRef<Value *>{ConstantInt::get(Int32Ty, Key, true), XB,
                                  YB});

            CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
            ++Calls2;

            Rets.insert(CI);
            if (Hash == nullptr) Hash = CI;
            else Hash = IRB.CreateXor(Hash, CI);

            Dumpeds2.insert(std::make_pair(X, Y));

          }

        }

      }

    }

    if (Rets.size() && !(SingleCnt == 1 && Rets.size() == 1)) {
    
      FunctionModified = true;

      CallInst *CI =
          IRB.CreateCall(unusualValuesLogFn, ArrayRef<Value *>{Hash});
      CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));

    }

  }

  if (FunctionModified && !be_quiet) {

    OKF("Inserted %d calls to log single values, %d to log pairs.", Calls1,
        Calls2);

  }

  return FunctionModified;

}

class AFLUnusualFunctionPass : public FunctionPass {

 public:
  static char ID;

  explicit AFLUnusualFunctionPass() : FunctionPass(ID) {

  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {

    AU.setPreservesCFG();
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<IntraProceduralRA<Cousot>>();
    //AU.addRequired<AAResultsWrapperPass>();

  }

  StringRef getPassName() const override {

    return "AFLUnusualPass";

  }

  bool runOnFunction(Function &F) override {

    Module &       M = *F.getParent();
    DominatorTree &DT = getAnalysis<DominatorTreeWrapperPass>().getDomTree();
    IntraProceduralRA<Cousot> &RA = getAnalysis<IntraProceduralRA<Cousot>>();
    AFLUnusual     DI(M, F, DT, RA);
    bool           r = DI.instrumentFunction();
    // verifyFunction(F);
    return r;

  }

};

char AFLUnusualFunctionPass::ID = 0;

// For RangeAnalysis
template <class CGT>
char IntraProceduralRA<CGT>::ID;

static void registerAFLUnusualPass(const PassManagerBuilder &,
                                   legacy::PassManagerBase &PM) {

  PM.add(new AFLUnusualFunctionPass());

}

static RegisterStandardPasses RegisterAFLUnusualPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLUnusualPass);

static RegisterStandardPasses RegisterAFLUnusualPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLUnusualPass);

static RegisterPass<AFLUnusualFunctionPass> X("afl-unusual", "AFLUnusualPass",
                                              false, false);

