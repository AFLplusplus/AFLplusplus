#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Triple.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Comdat.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/ScopedPrinter.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/ASanStackFrameLayout.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <climits>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <tuple>
#include <fstream>

using namespace llvm;

static size_t TypeSizeToSizeIndex(uint32_t TypeSize) {
  if (TypeSize == 1) TypeSize = 8;
  size_t Res = countTrailingZeros(TypeSize / 8);
  return Res;
}

struct BBInfo {

  std::string Name;

  std::vector< Value* > Locals;
  std::vector< std::vector<Value*> > GEPs;
  std::vector< std::vector<Value*> > LDs;
  std::vector< std::vector<Value*> > STs;

};

struct AFLUnusual {

  AFLUnusual(Module& _M, Function &_F) : M(_M), F(_F) {
    initialize();
  }
  
  static bool isBlacklisted(const Function *F) {

    static const char *Blacklist[] = {

        "asan.", "llvm.", "sancov.", "__ubsan_handle_", "ign.", "__afl_",
        "_fini", "__libc_csu", "__asan",  "__msan", "msan."

    };

    for (auto const &BlacklistFunc : Blacklist) {

      if (F->getName().startswith(BlacklistFunc)) return true;

    }
    
    //if (F->getName() == "main") return true;
    if (F->getName() == "_start") return true;

    return false;

  }
  
  void initialize();
  bool instrumentFunction();
  
  bool dumpVariable(IRBuilder<> &IRB, std::map<int, std::vector<Value*>> &CompArgs, Value* V);

  Type *VoidTy, *Int8Ty, *Int16Ty, *Int32Ty, *Int64Ty, *FloatTy, *DoubleTy,
       *StructTy, *Int8PTy, *Int16PTy, *Int32PTy, *Int64PTy, *FloatPTy,
       *DoublePTy, *StructPTy, *FuncTy;
  Type *IntTypeSized[4];

  Function* dbgDeclareFn;

  FunctionCallee unusualValuesFns[6];
  
  LLVMContext *C;
  Module& M;
  Function &F;
  int LongSize;
  
  std::vector<DILocalVariable*> DbgVars;
};

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
  
  Int8PTy  = PointerType::get(Int8Ty, 0);
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

  unusualValuesFns[0] = M.getOrInsertFunction("__afl_unusual_values_1", VoidTy, Int64Ty);
  unusualValuesFns[1] = M.getOrInsertFunction("__afl_unusual_values_2", VoidTy, Int64Ty, Int64Ty);
  unusualValuesFns[2] = M.getOrInsertFunction("__afl_unusual_values_3", VoidTy, Int64Ty, Int64Ty, Int64Ty);
  unusualValuesFns[3] = M.getOrInsertFunction("__afl_unusual_values_4", VoidTy, Int64Ty, Int64Ty, Int64Ty, Int64Ty);
  unusualValuesFns[4] = M.getOrInsertFunction("__afl_unusual_values_5", VoidTy, Int64Ty, Int64Ty, Int64Ty, Int64Ty, Int64Ty);
  unusualValuesFns[5] = M.getOrInsertFunction("__afl_unusual_values_6", VoidTy, Int64Ty, Int64Ty, Int64Ty, Int64Ty, Int64Ty, Int64Ty);
  
}

bool AFLUnusual::dumpVariable(IRBuilder<> &IRB, std::map<int, std::vector<Value*>> &CompArgs, Value* V) {

  Type *T = V->getType();
  /*int CompID = -1;
    if (Comp.find(V) != Comp.end())
      CompID = Comp[V];*/
  
  switch (T->getTypeID()) {
    case Type::IntegerTyID: {
      TypeSize BitsNum = T->getPrimitiveSizeInBits();
      if (BitsNum > 64) break;
      
      //if (BitsNum == 1)
      //  V = IRB.CreateIntCast(V, Int8Ty, true);
      
      Value *I = IRB.CreateZExtOrBitCast(V, Int64Ty);
      CompArgs[0].push_back(I);
      return true;
    }
    case Type::FloatTyID: {
      break;
    }
    case Type::DoubleTyID: {
      break;
    }
    case Type::PointerTyID: {
      break;
    }
    // case Type::ArrayTyID:
    // case Type::VectorTyID:
    // break;

    default:
      break;
  }

  return false;

}

static void AddComp(std::map<Value*, int>& Comp, int& CompID, Value* A) {

  bool hasA = Comp.find(A) != Comp.end();

  if (!hasA) {
    Comp[A] = CompID;
    ++CompID;
  }

}

static void MergeComp(std::map<Value*, int>& Comp, int& CompID, Value* A, Value* B) {

  bool hasA = Comp.find(A) != Comp.end();
  bool hasB = Comp.find(B) != Comp.end();

  if (hasA && !hasB)
    Comp[B] = Comp[A];
  else if(!hasA && hasB)
    Comp[A] = Comp[B];
  else if (!hasA && !hasB) {
    Comp[A] = CompID;
    Comp[B] = CompID;
    ++CompID;
  } else {
    int AID = Comp[A];
    int BID = Comp[B];
    for (auto& K : Comp) {
      if (K.second == BID)
        K.second = AID;
    }
  }

}

bool AFLUnusual::instrumentFunction() {

  bool FunctionModified = false;

  if (isBlacklisted(&F)) return FunctionModified; // not supported
  
  std::vector<BasicBlock*> BBs;
  std::set<Value*> DbgVals;

  std::map<Value*, int> Comp;
  int CompID = 0;
  
  for(Function::arg_iterator it = F.arg_begin(); it != F.arg_end(); ++it) {
    Argument *A = &*it;
    Value *V = static_cast<Value*>(A);
    
    if (DbgVals.find(V) == DbgVals.end())
      DbgVals.insert(V);
    
  }

  for (auto &BB : F) {
    BBs.push_back(&BB);
    for (auto &Inst : BB) {
    
      if (UnaryOperator* O = dyn_cast<UnaryOperator>(&Inst)) {
        MergeComp(Comp, CompID, O, O->getOperand(0));
      } else if (BinaryOperator* O = dyn_cast<BinaryOperator>(&Inst)) {
        MergeComp(Comp, CompID, O->getOperand(0), O->getOperand(1));
        MergeComp(Comp, CompID, O, O->getOperand(1));
      } else if (CastInst* C = dyn_cast<CastInst>(&Inst)) {
        MergeComp(Comp, CompID, C, C->getOperand(0));
      } else if (GetElementPtrInst* G = dyn_cast<GetElementPtrInst>(&Inst)) {
        MergeComp(Comp, CompID, G, G->getPointerOperand());
        Value* First = nullptr;
        for (auto Idx = G->idx_begin(); Idx != G->idx_end(); ++Idx) {
          if (Idx->get() && !isa<ConstantInt>(Idx->get())) {
            if (First) MergeComp(Comp, CompID, First, Idx->get());
            else First = Idx->get();
          }
        }
      } else if (LoadInst* L = dyn_cast<LoadInst>(&Inst)) {
        AddComp(Comp, CompID, L);
      }
    
      if (DbgValueInst* DbgValue = dyn_cast<DbgValueInst>(&Inst)) {

        if (DbgValue->getValue()&& !isa<Constant>(DbgValue->getValue()) && 
            DbgVals.find(DbgValue->getValue()) == DbgVals.end())
          DbgVals.insert(DbgValue->getValue());

      } else if(ReturnInst* RI = dyn_cast<ReturnInst>(&Inst)) {
      
        Value* RV = RI->getReturnValue();
        if (RV && DbgVals.find(RV) == DbgVals.end())
          DbgVals.insert(RV);
      
      }

    }
  }
  
  std::map<BasicBlock*, BBInfo> Infos;
  
  for (auto BB : BBs) {
  
    for (auto &Inst : *BB) {
    
      if (Inst.getMetadata(M.getMDKindID("nosanitize")))
        continue;
      
      if (isa<PHINode>(&Inst)) continue;
      
      for (auto op = Inst.op_begin(); op != Inst.op_end(); ++op) {
        Value* V = op->get();
        if (DbgVals.find(V) != DbgVals.end()) {
          if (std::find(Infos[BB].Locals.begin(), Infos[BB].Locals.end(), V) == Infos[BB].Locals.end())
            Infos[BB].Locals.push_back(V);
        }
      }
    
      if(auto GEP = dyn_cast<GetElementPtrInst>(&Inst)) {

        if(!isa<PointerType>(GEP->getSourceElementType()))
          continue;
        if (!GEP->hasIndices())
          continue;

        std::vector<Value*> OP;
        OP.push_back(GEP->getPointerOperand());
        for (auto Idx = GEP->idx_begin(); Idx != GEP->idx_end(); ++Idx) {
          if (Idx->get() && !isa<ConstantInt>(Idx->get()))
            OP.push_back(Idx->get());
        }
        
        if (OP.size() > 1)
          Infos[BB].GEPs.push_back(OP);

      } else if (auto LD = dyn_cast<LoadInst>(&Inst)) {
        
        std::vector<Value*> OP;
        OP.push_back(LD->getPointerOperand());
        OP.push_back(LD);
        
        Infos[BB].LDs.push_back(OP);
        
      } else if (auto ST = dyn_cast<StoreInst>(&Inst)) {
        
        std::vector<Value*> OP;
        OP.push_back(ST->getPointerOperand());
        OP.push_back(ST->getValueOperand());
        
        Infos[BB].STs.push_back(OP);
        
      }
    }
  
  }
  
  for (auto BB : BBs) {
  
    std::map<int, std::vector<Value*>> CompArgs;
  
    std::set<Value*> Dumpeds;
    IRBuilder<> IRB(BB->getTerminator());
  
    for (size_t i = 0; i < Infos[BB].Locals.size(); ++i) {
    
      if (Dumpeds.find(Infos[BB].Locals[i]) == Dumpeds.end()) {
        dumpVariable(IRB, CompArgs, Infos[BB].Locals[i]);
        Dumpeds.insert(Infos[BB].Locals[i]);
      }
    
    }
    
    for (size_t i = 0; i < Infos[BB].GEPs.size(); ++i) {
    
      if (!isa<Constant>(Infos[BB].GEPs[i][0]) &&
          Dumpeds.find(Infos[BB].GEPs[i][0]) == Dumpeds.end()) {
        dumpVariable(IRB, CompArgs, Infos[BB].GEPs[i][0]);
        Dumpeds.insert(Infos[BB].GEPs[i][0]);
      }

      for (size_t j = 1; j < Infos[BB].GEPs[i].size(); ++j) {
        if (Dumpeds.find(Infos[BB].GEPs[i][j]) == Dumpeds.end()) {
          dumpVariable(IRB, CompArgs, Infos[BB].GEPs[i][j]);
          Dumpeds.insert(Infos[BB].GEPs[i][j]);
        }
      }

    }
    
    for (size_t i = 0; i < Infos[BB].LDs.size(); ++i) {
    
      if (!isa<Constant>(Infos[BB].LDs[i][0]) &&
          Dumpeds.find(Infos[BB].LDs[i][0]) == Dumpeds.end()) {
        dumpVariable(IRB, CompArgs, Infos[BB].LDs[i][0]);
        Dumpeds.insert(Infos[BB].LDs[i][0]);
      }
      if (!isa<Constant>(Infos[BB].LDs[i][1]) &&
          Dumpeds.find(Infos[BB].LDs[i][1]) == Dumpeds.end()) {
        dumpVariable(IRB, CompArgs, Infos[BB].LDs[i][1]);
        Dumpeds.insert(Infos[BB].LDs[i][1]);
      }

    }
    
    for (size_t i = 0; i < Infos[BB].STs.size(); ++i) {
    
      if (!isa<Constant>(Infos[BB].STs[i][0]) &&
          Dumpeds.find(Infos[BB].STs[i][0]) == Dumpeds.end()) {
        dumpVariable(IRB, CompArgs, Infos[BB].STs[i][0]);
        Dumpeds.insert(Infos[BB].STs[i][0]);
      }
      if (!isa<Constant>(Infos[BB].STs[i][1]) &&
          Dumpeds.find(Infos[BB].STs[i][1]) == Dumpeds.end()) {
        dumpVariable(IRB, CompArgs, Infos[BB].STs[i][1]);
        Dumpeds.insert(Infos[BB].STs[i][1]);
      }

    }
    
    if (CompArgs[0].size() == 0) continue;
    
    // if (CompArgs[0].size() > 6) CompArgs[0].resize(6); // TODO
    
    // CallInst* CI = IRB.CreateCall(unusualValuesFns[CompArgs[0].size() -1], ArrayRef<Value*>(CompArgs[0]));
    // CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    
    for (auto V : CompArgs[0]) {
      CallInst* CI = IRB.CreateCall(unusualValuesFns[0], ArrayRef<Value*>{V});
      CI->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(*C, None));
    }
    
    FunctionModified = true;

  }

  return FunctionModified;
  
}

class AFLUnusualFunctionPass : public FunctionPass {
public:
  static char ID;

  explicit AFLUnusualFunctionPass() : FunctionPass(ID) {}

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesCFG();
  }

  StringRef getPassName() const override {
    return "AFLUnusualPass";
  }

  bool runOnFunction(Function &F) override {
    Module &M = *F.getParent();
    AFLUnusual DI(M, F);
    bool r = DI.instrumentFunction();
    verifyFunction(F);
    return r;
  }
};


char AFLUnusualFunctionPass::ID = 0;

static void registerAFLUnusualPass(const PassManagerBuilder &,
                               legacy::PassManagerBase &PM) {

  PM.add(new AFLUnusualFunctionPass());

}

static RegisterStandardPasses RegisterAFLUnusualPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLUnusualPass);

static RegisterStandardPasses RegisterAFLUnusualPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLUnusualPass);

static RegisterPass<AFLUnusualFunctionPass>
    X("afl-unusual", "AFLUnusualPass",
      false,
      false
    );
