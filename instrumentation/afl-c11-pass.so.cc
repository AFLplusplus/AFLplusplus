#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#if defined(__has_include) && __has_include("llvm/Plugins/PassPlugin.h")
  #include "llvm/Plugins/PassPlugin.h"
#else
  #include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include "afl-llvm-common.h"

using namespace llvm;

static void setNoInstrumentMetadata(Value *V) {

  if (auto *I = dyn_cast<Instruction>(V)) {

    MDNode *Empty = MDNode::get(I->getContext(), {});
    I->setMetadata("afl.skip", Empty);
    I->setMetadata(LLVMContext::MD_nosanitize, Empty);

  }

}

// C11: number of local variables, approximated as alloca count (IR-level).
// Counted before mem2reg/SROA so the allocas still reflect source-level locals.
static uint32_t computeC11(const Function &F) {

  uint32_t locals = 0;
  for (const BasicBlock &BB : F)
    for (const Instruction &I : BB)
      if (isa<AllocaInst>(&I)) ++locals;
  return locals;

}

struct C11Instr : PassInfoMixin<C11Instr> {

  C11Instr() {

    initInstrumentList();

  }

  PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {

    if (F.isDeclaration()) return PreservedAnalyses::all();

    // Honor AFL_LLVM_ALLOWLIST / AFL_LLVM_DENYLIST: skip functions that are
    // not on the allow list or that are on the deny list.
    if (!isInInstrumentList(&F, FMNAME)) return PreservedAnalyses::all();

    unsigned int locals = computeC11(F);

    if (locals < 4) return PreservedAnalyses::all();

    Module      &M = *F.getParent();
    LLVMContext &Ctx = M.getContext();
    Type        *I8Ty = Type::getInt8Ty(Ctx);
    Type        *I32Ty = Type::getInt32Ty(Ctx);
    Type        *PtrTy = PointerType::getUnqual(Ctx);

    GlobalVariable *Map = M.getGlobalVariable("__afl_area_ptr");
    if (!Map)
      Map = new GlobalVariable(M, PtrTy, false, GlobalValue::ExternalLinkage, 0,
                               "__afl_area_ptr");

    BasicBlock  &Entry = F.getEntryBlock();
    Instruction *InsertPt = &*Entry.getFirstInsertionPt();
    IRBuilder<>  IRB(InsertPt);

    ConstantInt *C11 = IRB.getInt32(locals);

    // base = __afl_area_ptr;  P = (unsigned int *)&base[1]  -- byte offset 1
    LoadInst *Base = IRB.CreateLoad(PtrTy, Map, "c11_base");
    setNoInstrumentMetadata(Base);
    Value *P = IRB.CreateGEP(I8Ty, Base, IRB.getInt64(1), "c11_slot");

    // cur = *(unsigned int *)&base[1]
    LoadInst *Cur = IRB.CreateAlignedLoad(I32Ty, P, Align(1), "c11_cur");
    setNoInstrumentMetadata(Cur);

    // if (unlikely(c11 > cur)) *(unsigned int *)&base[1] = c11;
    Value *Cond = IRB.CreateICmpUGT(C11, Cur, "c11_gt");
    setNoInstrumentMetadata(Cond);
    MDNode      *Unlikely = MDBuilder(Ctx).createBranchWeights(1, 1u << 20);
    Instruction *Then =
        SplitBlockAndInsertIfThen(Cond, InsertPt->getIterator(),
                                  /*Unreachable=*/false, Unlikely);

    IRB.SetInsertPoint(Then);
    StoreInst *St = IRB.CreateAlignedStore(C11, P, Align(1));
    setNoInstrumentMetadata(St);

    return PreservedAnalyses::none();  // CFG changed

  }

};

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "C11Instr", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {

            // Run before mem2reg/SROA: PipelineStartEP is the earliest
            // extension point, ahead of the simplification pipeline that
            // promotes allocas away (which would zero out the C11 metric).
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {

                  MPM.addPass(createModuleToFunctionPassAdaptor(C11Instr()));

                });

            // Keep manual invocation working too: -passes="c11-instr".
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {

                  if (Name == "c11-instr") {

                    FPM.addPass(C11Instr());
                    return true;

                  }

                  return false;

                });

          }};

}

