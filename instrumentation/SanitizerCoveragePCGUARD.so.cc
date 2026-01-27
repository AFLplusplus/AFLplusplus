//===-- SanitizerCoverage.cpp - coverage instrumentation for sanitizers ---===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Coverage instrumentation done on LLVM IR level, works with Sanitizers.
//
//===----------------------------------------------------------------------===//

#if defined(__clang__)
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wdeprecated-copy-with-dtor"
#elif defined(__GNUC__)
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wdeprecated-copy"
  #pragma GCC diagnostic ignored "-Wformat-truncation="
#endif

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
// #include "llvm/IR/IntrinsicInst.h"
// #include "llvm/IR/IntrinsicEnums.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"
#include "llvm/Passes/PassBuilder.h"
#if LLVM_MAJOR >= 22
  #include "llvm/Plugins/PassPlugin.h"
#else
  #include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Transforms/Instrumentation/SanitizerCoverage.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

// Version-specific includes
#if LLVM_MAJOR < 15
  #include "llvm/Analysis/EHPersonalities.h"
  #include "llvm/InitializePasses.h"
  #include "llvm/IR/CFG.h"
  #include "llvm/IR/DebugInfo.h"
  #include "llvm/IR/InlineAsm.h"
  #include "llvm/IR/MDBuilder.h"
  #include "llvm/IR/Mangler.h"
  #include "llvm/Support/raw_ostream.h"
  #include "llvm/Transforms/Instrumentation.h"
#elif LLVM_MAJOR < 17
  #include "llvm/ADT/Triple.h"
  #include "llvm/Analysis/EHPersonalities.h"
  #include "llvm/IR/Constants.h"
  #include "llvm/IR/ValueSymbolTable.h"
#elif LLVM_MAJOR >= 17
  #include "llvm/IR/EHPersonalities.h"
  #include "llvm/TargetParser/Triple.h"
#else
  #include "llvm/Analysis/EHPersonalities.h"
#endif

#if LLVM_MAJOR >= 20
  #include "llvm/Transforms/Utils/Instrumentation.h"
#endif

#include "config.h"
#include "debug.h"
#include "afl-llvm-common.h"

using namespace llvm;

#define DEBUG_TYPE "sancov"

// Constants
static const uint64_t SanCtorAndDtorPriority = 2;
const char            SanCovTracePCName[] = "__sanitizer_cov_trace_pc";

const char SanCovModuleCtorTracePcGuardName[] =
    "sancov.module_ctor_trace_pc_guard";
const char SanCovTracePCGuardInitName[] = "__sanitizer_cov_trace_pc_guard_init";

const char SanCovTracePCGuardName[] = "__sanitizer_cov_trace_pc_guard";

const char SanCovGuardsSectionName[] = "sancov_guards";
const char SanCovCountersSectionName[] = "sancov_cntrs";
const char SanCovBoolFlagSectionName[] = "sancov_bools";
const char SanCovPCsSectionName[] = "sancov_pcs";

const char SanCovLowestStackName[] = "__sancov_lowest_stack";

static const char *skip_nozero;
static const char *use_threadsafe_counters;
static const char *ijon_enabled;

namespace {

SanitizerCoverageOptions OverrideFromCL(SanitizerCoverageOptions Options) {

  Options.CoverageType = SanitizerCoverageOptions::SCK_Edge;
  Options.TracePCGuard = true;  // TracePCGuard is default.
  return Options;

}

using DomTreeCallback = function_ref<const DominatorTree *(Function &F)>;
using PostDomTreeCallback =
    function_ref<const PostDominatorTree *(Function &F)>;

class ModuleSanitizerCoverageAFL
    : public PassInfoMixin<ModuleSanitizerCoverageAFL> {

 public:
  ModuleSanitizerCoverageAFL(
      const SanitizerCoverageOptions &Options = SanitizerCoverageOptions())
      : Options(OverrideFromCL(Options)) {

  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
  bool              instrumentModule(Module &M, DomTreeCallback DTCallback,
                                     PostDomTreeCallback PDTCallback);

 private:
  void            instrumentFunction(Function &F, DomTreeCallback DTCallback,
                                     PostDomTreeCallback PDTCallback);
  bool            InjectCoverage(Function &F, ArrayRef<BasicBlock *> AllBlocks);
  GlobalVariable *CreateFunctionLocalArrayInSection(size_t    NumElements,
                                                    Function &F, Type *Ty,
                                                    const char *Section);
  void CreateFunctionLocalArrays(Function &F, ArrayRef<BasicBlock *> AllBlocks,
                                 uint32_t special);
  void InjectCoverageAtBlock(Function &F, BasicBlock &BB, size_t Idx);
  Function *CreateInitCallsForSections(Module &M, const char *CtorName,
                                       const char *InitFunctionName, Type *Ty,
                                       const char *Section);
  std::pair<Value *, Value *> CreateSecStartEnd(Module &M, const char *Section,
                                                Type *Ty);

  // Helper functions for cleaner code
  bool   isInstructionInteresting(Instruction &IN);
  bool   isAflInterestingCall(Instruction &IN);
  void   initializeVersionSpecificTypes(IRBuilder<> &IRB);
  void   setupEnvironmentVariables();
  void   setupIJONSymbols(Module &M, bool uses_ijon_state);
  Value *createGuardPointer(IRBuilder<> &IRB, uint32_t index);
  void   updateCoverageBitmap(IRBuilder<> &IRB, Value *CoverageIndex,
                              LoadInst *MapPtr);
  void   printDebugInfo(Instruction &IN);
  Value *instrumentVectorSelect(IRBuilder<> &IRB, Value *condition,
                                FixedVectorType *tt, uint32_t &local_selects,
                                uint32_t cnt_cov, uint32_t skip_blocks,
                                uint32_t               special,
                                ArrayRef<BasicBlock *> AllBlocks);
  void   updateCoverageForSelect(IRBuilder<> &IRB, Value *result,
                                 LoadInst *MapPtr, uint32_t &vector_cnt);

  void SetNoSanitizeMetadata(Instruction *I) {

#if LLVM_MAJOR >= 19
    I->setNoSanitizeMetadata();
#elif LLVM_MAJOR >= 16
    I->setMetadata(LLVMContext::MD_nosanitize, MDNode::get(*C, std::nullopt));
#else
    I->setMetadata(I->getModule()->getMDKindID("nosanitize"),
                   MDNode::get(*C, None));
#endif

  }

  std::string     getSectionName(const std::string &Section) const;
  std::string     getSectionStart(const std::string &Section) const;
  std::string     getSectionEnd(const std::string &Section) const;
  FunctionCallee  SanCovTracePC, SanCovTracePCGuard;
  GlobalVariable *SanCovLowestStack;
  Type *IntptrTy, *IntptrPtrTy, *Int64Ty, *Int64PtrTy, *Int32Ty, *Int32PtrTy,
      *Int16Ty, *Int8Ty, *Int8PtrTy, *Int1Ty, *Int1PtrTy, *PtrTy;
  Module           *CurModule;
  std::string       CurModuleUniqueId;
  Triple            TargetTriple;
  LLVMContext      *C;
  const DataLayout *DL;

  GlobalVariable                *FunctionGuardArray;  // for trace-pc-guard.
  SmallVector<GlobalValue *, 20> GlobalsToAppendToUsed;
  SmallVector<GlobalValue *, 20> GlobalsToAppendToCompilerUsed;

  SanitizerCoverageOptions Options;

  uint32_t instr = 0, selects = 0, unhandled = 0, skippedbb = 0, dump_cc = 0;
  GlobalVariable *AFLMapPtr = NULL;
  GlobalVariable *AFLCovMapSize = NULL;
  GlobalVariable *AFLIJONState = NULL;
  ConstantInt    *One = NULL;
  ConstantInt    *Zero = NULL;
  bool            deny_exec = false;

};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "SanitizerCoveragePCGUARD", "v0.2",
          [](PassBuilder &PB) {

#if LLVM_MAJOR >= 16
            PB.registerOptimizerEarlyEPCallback([](ModulePassManager &MPM,
                                                   OptimizationLevel  OL
  #if LLVM_MAJOR >= 20
                                                   ,
                                                   ThinOrFullLTOPhase Phase
  #endif
                                                ) {

  #if LLVM_MAJOR >= 20
              // Only add the pass for non-LTO phases to avoid conflicts
              if (Phase != ThinOrFullLTOPhase::ThinLTOPreLink &&
                  Phase != ThinOrFullLTOPhase::FullLTOPreLink) {

                MPM.addPass(ModuleSanitizerCoverageAFL());

              }

  #else
              MPM.addPass(ModuleSanitizerCoverageAFL());
  #endif

            });

#else
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(ModuleSanitizerCoverageAFL());

                });

#endif

          }};

}

PreservedAnalyses ModuleSanitizerCoverageAFL::run(Module                &M,
                                                  ModuleAnalysisManager &MAM) {

  ModuleSanitizerCoverageAFL ModuleSancov(Options);
  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  auto  DTCallback = [&FAM](Function &F) -> const DominatorTree  *{

    return &FAM.getResult<DominatorTreeAnalysis>(F);

  };

  auto PDTCallback = [&FAM](Function &F) -> const PostDominatorTree * {

    return &FAM.getResult<PostDominatorTreeAnalysis>(F);

  };

  // TODO: Support LTO or llvm classic?
  // Note we still need afl-compiler-rt so we just disable the instrumentation
  // here.
  if (!getenv("AFL_LLVM_ONLY_FSRV")) {

    if (ModuleSancov.instrumentModule(M, DTCallback, PDTCallback))
      return PreservedAnalyses::none();

  } else {

    if (getenv("AFL_DEBUG")) { DEBUGF("Instrumentation disabled\n"); }

  }

  return PreservedAnalyses::all();

}

std::pair<Value *, Value *> ModuleSanitizerCoverageAFL::CreateSecStartEnd(
    Module &M, const char *Section, Type *Ty) {

  // Use ExternalWeak so that if all sections are discarded due to section
  // garbage collection, the linker will not report undefined symbol errors.
  // Windows defines the start/stop symbols in compiler-rt so no need for
  // ExternalWeak.
  GlobalValue::LinkageTypes Linkage = TargetTriple.isOSBinFormatCOFF()
                                          ? GlobalVariable::ExternalLinkage
                                          : GlobalVariable::ExternalWeakLinkage;
  GlobalVariable *SecStart = new GlobalVariable(M, Ty, false, Linkage, nullptr,
                                                getSectionStart(Section));
  SecStart->setVisibility(GlobalValue::HiddenVisibility);
  GlobalVariable *SecEnd = new GlobalVariable(M, Ty, false, Linkage, nullptr,
                                              getSectionEnd(Section));
  SecEnd->setVisibility(GlobalValue::HiddenVisibility);
  IRBuilder<> IRB(M.getContext());
  if (!TargetTriple.isOSBinFormatCOFF())
    return std::make_pair(SecStart, SecEnd);

#if LLVM_MAJOR >= 19
  auto GEP =
      IRB.CreatePtrAdd(SecStart, ConstantInt::get(IntptrTy, sizeof(uint64_t)));
  return std::make_pair(GEP, SecEnd);
#else
  auto SecStartI8Ptr = IRB.CreatePointerCast(SecStart, Int8PtrTy);
  auto GEP = IRB.CreateGEP(Int8Ty, SecStartI8Ptr,
                           ConstantInt::get(IntptrTy, sizeof(uint64_t)));
  return std::make_pair(IRB.CreatePointerCast(GEP, PointerType::getUnqual(Ty)),
                        SecEnd);
#endif

}

bool ModuleSanitizerCoverageAFL::isInstructionInteresting(Instruction &I) {

  return isAflCovInterestingInstruction(I);

}

bool ModuleSanitizerCoverageAFL::isAflInterestingCall(Instruction &IN) {

  CallInst *callInst = dyn_cast<CallInst>(&IN);
  if (!callInst) return false;

  Function *Callee = callInst->getCalledFunction();
  if (!Callee) return false;
  if (callInst->getCallingConv() != llvm::CallingConv::C) return false;

  StringRef FuncName = Callee->getName();
  return !FuncName.compare(StringRef("__afl_coverage_interesting"));

}

void ModuleSanitizerCoverageAFL::initializeVersionSpecificTypes(
    IRBuilder<> &IRB) {

  PtrTy = PointerType::getUnqual(*C);
#if LLVM_MAJOR >= 20
  IntptrPtrTy = Int64PtrTy = Int32PtrTy = Int8PtrTy = Int1PtrTy = PtrTy;
#else
  IntptrPtrTy = PointerType::getUnqual(IntptrTy);
  Int64PtrTy = PointerType::getUnqual(IRB.getInt64Ty());
  Int32PtrTy = PointerType::getUnqual(IRB.getInt32Ty());
  Int8PtrTy = PointerType::getUnqual(IRB.getInt8Ty());
  Int1PtrTy = PointerType::getUnqual(IRB.getInt1Ty());
#endif

}

void ModuleSanitizerCoverageAFL::setupEnvironmentVariables() {

  setvbuf(stdout, NULL, _IONBF, 0);

  if (getenv("AFL_DEBUG")) { debug = 1; }
  if (getenv("AFL_DUMP_CYCLOMATIC_COMPLEXITY")) { dump_cc = 1; }

  if ((isatty(2) && !getenv("AFL_QUIET")) || debug) {

    SAYF(cCYA "SanitizerCoveragePCGUARD" VERSION cRST "\n");

  } else {

    be_quiet = 1;

  }

  skip_nozero = getenv("AFL_LLVM_SKIP_NEVERZERO");
  use_threadsafe_counters = getenv("AFL_LLVM_THREADSAFE_INST");
  ijon_enabled = getenv("AFL_LLVM_IJON");
  if (getenv("AFL_LLVM_DENY_EXEC")) { deny_exec = true; }

}

Value *ModuleSanitizerCoverageAFL::createGuardPointer(IRBuilder<> &IRB,
                                                      uint32_t     index) {

  return IRB.CreateIntToPtr(
      IRB.CreateAdd(IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                    ConstantInt::get(IntptrTy, index * 4)),
      Int32PtrTy);

}

void ModuleSanitizerCoverageAFL::updateCoverageBitmap(IRBuilder<> &IRB,
                                                      Value    *CoverageIndex,
                                                      LoadInst *MapPtr) {

  Value *MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, CoverageIndex);

  if (use_threadsafe_counters) {

    auto instr = IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx,
                                     One, llvm::MaybeAlign(1),
                                     llvm::AtomicOrdering::Monotonic);
    auto        *INSTR = llvm::cast<llvm::Instruction>(instr);
    LLVMContext &Ctx = INSTR->getContext();
    MDNode      *Tag = MDNode::get(Ctx, {});
    INSTR->setMetadata("afl.skip", Tag);

  } else {

    LoadInst *Counter = IRB.CreateLoad(IRB.getInt8Ty(), MapPtrIdx);
    SetNoSanitizeMetadata(Counter);

    Value *Incr = IRB.CreateAdd(Counter, One);

    if (skip_nozero == NULL) {

      auto         cf = IRB.CreateICmpEQ(Incr, Zero);
      auto        *CF = llvm::cast<llvm::Instruction>(cf);
      LLVMContext &Ctx = CF->getContext();
      MDNode      *Tag = MDNode::get(Ctx, {});
      CF->setMetadata("afl.skip", Tag);
      auto carry = IRB.CreateZExt(cf, Int8Ty);
      Incr = IRB.CreateAdd(Incr, carry);

    }

    StoreInst *StoreCtx = IRB.CreateStore(Incr, MapPtrIdx);
    SetNoSanitizeMetadata(StoreCtx);

  }

}

void ModuleSanitizerCoverageAFL::printDebugInfo(Instruction &IN) {

  if (DILocation *Loc = IN.getDebugLoc()) {

    llvm::errs() << "DEBUG " << Loc->getFilename() << ":" << Loc->getLine()
                 << ":";
    std::string path =
        Loc->getDirectory().str() + "/" + Loc->getFilename().str();
    std::ifstream sourceFile(path);
    std::string   lineContent;
    for (unsigned line = 1; line <= Loc->getLine(); ++line)
      std::getline(sourceFile, lineContent);
    llvm::errs() << lineContent << "\n";

  }

  errs() << *(&IN) << "\n";

}

Value *ModuleSanitizerCoverageAFL::instrumentVectorSelect(
    IRBuilder<> &IRB, Value *condition, FixedVectorType *tt,
    uint32_t &local_selects, uint32_t cnt_cov, uint32_t skip_blocks,
    uint32_t special, ArrayRef<BasicBlock *> AllBlocks) {

  uint32_t elements = tt->getElementCount().getFixedValue();
  if (!elements) return nullptr;

  FixedVectorType *GuardPtr1Type = FixedVectorType::get(Int32PtrTy, elements);
  FixedVectorType *GuardPtr2Type = FixedVectorType::get(Int32PtrTy, elements);

  // Create first vector element
  Value *val1 = createGuardPointer(IRB, cnt_cov + special + local_selects++ +
                                            AllBlocks.size() - skip_blocks);
  Value *x = IRB.CreateInsertElement(GuardPtr1Type, val1, (uint64_t)0);

  // Create second vector element
  Value *val2 = createGuardPointer(IRB, cnt_cov + special + local_selects++ +
                                            AllBlocks.size() - skip_blocks);
  Value *y = IRB.CreateInsertElement(GuardPtr2Type, val2, (uint64_t)0);

  // Fill remaining elements
  for (uint64_t i = 1; i < elements; i++) {

    val1 = createGuardPointer(IRB, cnt_cov + special + local_selects++ +
                                       AllBlocks.size() - skip_blocks);
    x = IRB.CreateInsertElement(x, val1, i);

    val2 = createGuardPointer(IRB, cnt_cov + special + local_selects++ +
                                       AllBlocks.size() - skip_blocks);
    y = IRB.CreateInsertElement(y, val2, i);

  }

  return IRB.CreateSelect(condition, x, y);

}

void ModuleSanitizerCoverageAFL::updateCoverageForSelect(IRBuilder<> &IRB,
                                                         Value       *result,
                                                         LoadInst    *MapPtr,
                                                         uint32_t &vector_cnt) {

  uint32_t vector_cur = 0;

  while (true) {

    Value *MapPtrIdx = nullptr;

    if (!vector_cnt) {

      LoadInst *CurLoc = IRB.CreateLoad(IRB.getInt32Ty(), result);
      SetNoSanitizeMetadata(CurLoc);
      MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, CurLoc);

    } else {

      auto element = IRB.CreateExtractElement(result, vector_cur++);
      auto elementptr = IRB.CreateIntToPtr(element, Int32PtrTy);
      auto elementld = IRB.CreateLoad(IRB.getInt32Ty(), elementptr);
      SetNoSanitizeMetadata(elementld);
      MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, elementld);

    }

    if (use_threadsafe_counters) {

      auto         instr = IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add,
                                               MapPtrIdx, One, llvm::MaybeAlign(1),
                                               llvm::AtomicOrdering::Monotonic);
      auto        *INSTR = llvm::cast<llvm::Instruction>(instr);
      LLVMContext &Ctx = INSTR->getContext();
      MDNode      *Tag = MDNode::get(Ctx, {});
      INSTR->setMetadata("afl.skip", Tag);

    } else {

      LoadInst *Counter = IRB.CreateLoad(IRB.getInt8Ty(), MapPtrIdx);
      SetNoSanitizeMetadata(Counter);

      Value *Incr = IRB.CreateAdd(Counter, One);

      if (skip_nozero == NULL) {

        auto         cf = IRB.CreateICmpEQ(Incr, Zero);
        auto        *CF = llvm::cast<llvm::Instruction>(cf);
        LLVMContext &Ctx = CF->getContext();
        MDNode      *Tag = MDNode::get(Ctx, {});
        CF->setMetadata("afl.skip", Tag);
        auto carry = IRB.CreateZExt(cf, Int8Ty);
        Incr = IRB.CreateAdd(Incr, carry);

      }

      StoreInst *StoreCtx = IRB.CreateStore(Incr, MapPtrIdx);
      SetNoSanitizeMetadata(StoreCtx);

    }

    if (!vector_cnt) {

      vector_cnt = 2;
      break;

    } else if (vector_cnt == vector_cur) {

      break;

    }

  }

}

void ModuleSanitizerCoverageAFL::setupIJONSymbols(Module &M,
                                                  bool    uses_ijon_state) {

  createIJONEnabledGlobal(M, Int32Ty);
  AFLIJONState = createIJONStateGlobal(M, Int32Ty, uses_ijon_state);

}

Function *ModuleSanitizerCoverageAFL::CreateInitCallsForSections(
    Module &M, const char *CtorName, const char *InitFunctionName, Type *Ty,
    const char *Section) {

  auto      SecStartEnd = CreateSecStartEnd(M, Section, Ty);
  auto      SecStart = SecStartEnd.first;
  auto      SecEnd = SecStartEnd.second;
  Function *CtorFunc;
  std::tie(CtorFunc, std::ignore) = createSanitizerCtorAndInitFunctions(
      M, CtorName, InitFunctionName, {PtrTy, PtrTy}, {SecStart, SecEnd});

  if (TargetTriple.supportsCOMDAT()) {

    // Use comdat to dedup CtorFunc.
    CtorFunc->setComdat(M.getOrInsertComdat(CtorName));
    appendToGlobalCtors(M, CtorFunc, SanCtorAndDtorPriority, CtorFunc);

  } else {

    appendToGlobalCtors(M, CtorFunc, SanCtorAndDtorPriority);

  }

  if (TargetTriple.isOSBinFormatCOFF()) {

    // In COFF files, if the constructors are set as COMDAT (they are because
    // COFF supports COMDAT) and the linker flag /OPT:REF (strip unreferenced
    // functions and data) is used, the constructors get stripped. To prevent
    // this, give the constructors weak ODR linkage and ensure the linker knows
    // to include the sancov constructor. This way the linker can deduplicate
    // the constructors but always leave one copy.
    CtorFunc->setLinkage(GlobalValue::WeakODRLinkage);

  }

  return CtorFunc;

}

bool ModuleSanitizerCoverageAFL::instrumentModule(
    Module &M, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {

  setupEnvironmentVariables();

  // If IJON is enabled, check if the module actually uses any IJON functions
  bool uses_ijon_functions = false;
  bool uses_ijon_state = false;
  if (ijon_enabled) {

    std::tie(uses_ijon_functions, uses_ijon_state) = detectIJONUsage(M);
    if (!uses_ijon_functions) { ijon_enabled = nullptr; }

  }

  initInstrumentList();
  scanForDangerousFunctions(&M);

  C = &(M.getContext());
  DL = &M.getDataLayout();
  CurModule = &M;
  CurModuleUniqueId = getUniqueModuleId(CurModule);
  TargetTriple = Triple(M.getTargetTriple());
  FunctionGuardArray = nullptr;
  // Initialize basic types
  IntptrTy = Type::getIntNTy(*C, DL->getPointerSizeInBits());
  Type       *VoidTy = Type::getVoidTy(*C);
  IRBuilder<> IRB(*C);

  // Initialize version-specific types
  initializeVersionSpecificTypes(IRB);

  // Initialize integer types
  Int64Ty = IRB.getInt64Ty();
  Int32Ty = IRB.getInt32Ty();
  Int16Ty = IRB.getInt16Ty();
  Int8Ty = IRB.getInt8Ty();
  Int1Ty = IRB.getInt1Ty();

  LLVMContext &Ctx = M.getContext();
  AFLMapPtr = new GlobalVariable(M, PtrTy, false, GlobalValue::ExternalLinkage,
                                 0, "__afl_area_ptr");
  AFLCovMapSize = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_cov_map_size");

  One = ConstantInt::get(IntegerType::getInt8Ty(Ctx), 1);
  Zero = ConstantInt::get(IntegerType::getInt8Ty(Ctx), 0);

  // Initialize IJON symbols based on what functions are used
  if (ijon_enabled) { setupIJONSymbols(M, uses_ijon_state); }

  Constant *SanCovLowestStackConstant =
      M.getOrInsertGlobal(SanCovLowestStackName, IntptrTy);
  SanCovLowestStack = dyn_cast<GlobalVariable>(SanCovLowestStackConstant);
  if (!SanCovLowestStack || SanCovLowestStack->getValueType() != IntptrTy) {

    C->emitError(StringRef("'") + SanCovLowestStackName +
                 "' should not be declared by the user");
    return true;

  }

  SanCovLowestStack->setThreadLocalMode(
      GlobalValue::ThreadLocalMode::InitialExecTLSModel);

  SanCovTracePC = M.getOrInsertFunction(SanCovTracePCName, VoidTy);
  SanCovTracePCGuard =
      M.getOrInsertFunction(SanCovTracePCGuardName, VoidTy, Int32PtrTy);

  for (auto &F : M)
    instrumentFunction(F, DTCallback, PDTCallback);

  Function *Ctor = nullptr;

  if (FunctionGuardArray)
    Ctor = CreateInitCallsForSections(M, SanCovModuleCtorTracePcGuardName,
                                      SanCovTracePCGuardInitName, Int32PtrTy,
                                      SanCovGuardsSectionName);

  if (Ctor && debug) {

    fprintf(stderr, "SANCOV: installed pcguard_init in ctor\n");

  }

  appendToUsed(M, GlobalsToAppendToUsed);
  appendToCompilerUsed(M, GlobalsToAppendToCompilerUsed);

  if (!be_quiet) {

    if (!instr) {

      WARNF("No instrumentation targets found.");

    } else {

      char modeline[128];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_TSAN") ? ", TSAN" : "",
               getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
      char buf[32] = "";
      if (skippedbb) {

        snprintf(buf, sizeof(buf), " %u instrumentation%s saved.", skippedbb,
                 skippedbb == 1 ? "" : "s");

      }

      OKF("Instrumented %u locations with no collisions (%s mode) of which are "
          "%u handled and %u unhandled special instructions.%s",
          instr, modeline, selects, unhandled, buf);

      if (getenv("AFL_LLVM_IJON")) {

        if (ijon_enabled) {

          if (uses_ijon_state) {

            OKF("IJON state-aware coverage enabled for all instrumented "
                "locations (IJON_STATE detected).");

          } else {

            OKF("IJON data tracking enabled for instrumented locations "
                "(IJON_DATA detected, no state-aware coverage).");

          }

        } else {

          OKF("IJON enabled but no IJON calls detected - using regular "
              "coverage.");

        }

      }

    }

  }

  return true;

}

// True if block has successors and it dominates all of them.
static bool isFullDominator(const BasicBlock *BB, const DominatorTree *DT) {

  if (succ_empty(BB)) return false;

  return llvm::all_of(successors(BB), [&](const BasicBlock *SUCC) {

    return DT->dominates(BB, SUCC);

  });

}

// True if block has predecessors and it postdominates all of them.
static bool isFullPostDominator(const BasicBlock        *BB,
                                const PostDominatorTree *PDT) {

  if (pred_empty(BB)) return false;

  return llvm::all_of(predecessors(BB), [&](const BasicBlock *PRED) {

    return PDT->dominates(BB, PRED);

  });

}

static bool shouldInstrumentBlock(const Function &F, const BasicBlock *BB,
                                  const DominatorTree            *DT,
                                  const PostDominatorTree        *PDT,
                                  const SanitizerCoverageOptions &Options) {

  // Don't insert coverage for blocks containing nothing but unreachable: we
  // will never call __sanitizer_cov() for them, so counting them in
  // NumberOfInstrumentedBlocks() might complicate calculation of code coverage
  // percentage. Also, unreachable instructions frequently have no debug
  // locations.
  if (isa<UnreachableInst>(BB->getFirstNonPHIOrDbgOrLifetime())) return false;

  // Don't insert coverage into blocks without a valid insertion point
  // (catchswitch blocks).
  if (BB->getFirstInsertionPt() == BB->end()) return false;

  if (Options.NoPrune || &F.getEntryBlock() == BB) return true;

  // Do not instrument full dominators, or full post-dominators with multiple
  // predecessors.
  return !isFullDominator(BB, DT) &&
         !(isFullPostDominator(BB, PDT) && !BB->getSinglePredecessor());

}

void ModuleSanitizerCoverageAFL::instrumentFunction(
    Function &F, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {

  if (F.empty()) return;
  if (!isInInstrumentList(&F, FMNAME)) return;
  if (F.getName().contains(".module_ctor"))
    return;  // Should not instrument sanitizer init functions.
#if LLVM_MAJOR >= 18
  if (F.getName().starts_with("__sanitizer_"))
#else
  if (F.getName().startswith("__sanitizer_"))
#endif
    return;  // Don't instrument __sanitizer_* callbacks.
  // Don't touch available_externally functions, their actual body is elewhere.
  if (F.getLinkage() == GlobalValue::AvailableExternallyLinkage) return;
  // Don't instrument MSVC CRT configuration helpers. They may run before normal
  // initialization.
  if (F.getName() == "__local_stdio_printf_options" ||
      F.getName() == "__local_stdio_scanf_options")
    return;
  if (isa<UnreachableInst>(F.getEntryBlock().getTerminator())) return;
  // Don't instrument functions using SEH for now. Splitting basic blocks like
  // we do for coverage breaks WinEHPrepare.
  // FIXME: Remove this when SEH no longer uses landingpad pattern matching.
  if (F.hasPersonalityFn() &&
      isAsynchronousEHPersonality(classifyEHPersonality(F.getPersonalityFn())))
    return;
  if (F.hasFnAttribute(Attribute::NoSanitizeCoverage)) return;
#if LLVM_MAJOR >= 19
  if (F.hasFnAttribute(Attribute::DisableSanitizerInstrumentation)) return;
#endif
  if (Options.CoverageType >= SanitizerCoverageOptions::SCK_Edge)
    SplitAllCriticalEdges(
        F, CriticalEdgeSplittingOptions().setIgnoreUnreachableDests());
  SmallVector<BasicBlock *, 16> BlocksToInstrument;

  const DominatorTree     *DT = DTCallback(F);
  const PostDominatorTree *PDT = PDTCallback(F);

  // AFL++ START
  if (deny_exec) {

    FunctionCallee AbortFn = F.getParent()->getOrInsertFunction(
        "abort", AttributeList{}, Type::getVoidTy(*C));
    for (auto &BB : F) {

      for (auto &IN : BB) {

        if (isExecCall(&IN)) {

          IRBuilder<> IRB(&IN);
          IRB.CreateCall(AbortFn);

        }

      }

    }

  }

  // AFL++ END
  for (auto &BB : F) {

    if (shouldInstrumentBlock(F, &BB, DT, PDT, Options))
      BlocksToInstrument.push_back(&BB);

  }

  if (debug) {

    fprintf(stderr, "SanitizerCoveragePCGUARD: instrumenting %s in %s\n",
            F.getName().str().c_str(), F.getParent()->getName().str().c_str());

  }

  InjectCoverage(F, BlocksToInstrument);

  if (dump_cc) { calcCyclomaticComplexity(&F); }

}

GlobalVariable *ModuleSanitizerCoverageAFL::CreateFunctionLocalArrayInSection(
    size_t NumElements, Function &F, Type *Ty, const char *Section) {

  ArrayType *ArrayTy = ArrayType::get(Ty, NumElements);
  auto       Array = new GlobalVariable(
      *CurModule, ArrayTy, false, GlobalVariable::PrivateLinkage,
      Constant::getNullValue(ArrayTy), "__sancov_gen_");

  if (TargetTriple.supportsCOMDAT() &&
      (TargetTriple.isOSBinFormatELF() || !F.isInterposable()))
    if (auto Comdat = getOrCreateFunctionComdat(F, TargetTriple))
      Array->setComdat(Comdat);
  Array->setSection(getSectionName(Section));
#if LLVM_MAJOR >= 16
  Array->setAlignment(Align(DL->getTypeStoreSize(Ty).getFixedValue()));
#else
  Array->setAlignment(Align(DL->getTypeStoreSize(Ty).getFixedSize()));
#endif

  // sancov_pcs parallels the other metadata section(s). Optimizers (e.g.
  // GlobalOpt/ConstantMerge) may not discard sancov_pcs and the other
  // section(s) as a unit, so we conservatively retain all unconditionally in
  // the compiler.
  //
  // With comdat (COFF/ELF), the linker can guarantee the associated sections
  // will be retained or discarded as a unit, so llvm.compiler.used is
  // sufficient. Otherwise, conservatively make all of them retained by the
  // linker.
  if (Array->hasComdat())
    GlobalsToAppendToCompilerUsed.push_back(Array);
  else
    GlobalsToAppendToUsed.push_back(Array);

  return Array;

}

void ModuleSanitizerCoverageAFL::CreateFunctionLocalArrays(
    Function &F, ArrayRef<BasicBlock *> AllBlocks, uint32_t special) {

  if (Options.TracePCGuard)
    FunctionGuardArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size() + special, F, Int32Ty, SanCovGuardsSectionName);

}

bool ModuleSanitizerCoverageAFL::InjectCoverage(
    Function &F, ArrayRef<BasicBlock *> AllBlocks) {

  if (AllBlocks.empty()) return false;

  uint32_t cnt_cov = 0, cnt_sel = 0, cnt_sel_inc = 0, skip_blocks = 0,
           cnt_special = 0;
  static uint32_t first = 1;

  for (auto &BB : F) {

    bool block_is_instrumented = false;

    for (auto &IN : BB) {

      // Check for dlopen warnings
      if (auto *callInst = dyn_cast<CallInst>(&IN)) {

        Function *Callee = callInst->getCalledFunction();
        if (!Callee) continue;
        if (callInst->getCallingConv() != llvm::CallingConv::C) continue;

        StringRef FuncName = Callee->getName();
        if (!FuncName.compare(StringRef("dlopen")) ||
            !FuncName.compare(StringRef("_dlopen"))) {

          WARNF(
              "dlopen() detected. To have coverage for a library that your "
              "target dlopen()'s this must either happen before __AFL_INIT() "
              "or you must use AFL_PRELOAD to preload all dlopen()'ed "
              "libraries!\n");
          continue;

        }

        if (!FuncName.compare(StringRef("__afl_coverage_interesting"))) {

          cnt_cov++;
          block_is_instrumented = true;
          continue;

        }

      }

      // Check for AFL coverage interesting calls first
      if (isAflInterestingCall(IN)) {

        cnt_special++;
        continue;

      }

      bool instrumentInst = isInstructionInteresting(IN);

      if (instrumentInst) {

        SelectInst *selectInst;

        ICmpInst          *icmp = dyn_cast<ICmpInst>(&IN);
        FCmpInst          *fcmp = dyn_cast<FCmpInst>(&IN);
        AtomicCmpXchgInst *cxchg = dyn_cast<AtomicCmpXchgInst>(&IN);
        AtomicRMWInst     *rmw = dyn_cast<AtomicRMWInst>(&IN);

        if (icmp) {

          if (icmp->getType()->isIntegerTy(1)) {

            block_is_instrumented = true;
            cnt_sel++;
            cnt_sel_inc += 2;

          } else {

            unhandled++;

          }

        } else if (fcmp) {

          if (fcmp->getType()->isIntegerTy(1)) {

            block_is_instrumented = true;
            cnt_sel++;
            cnt_sel_inc += 2;

          } else {

            unhandled++;

          }

        } else if (cxchg) {

          if (cxchg->getType()->isIntegerTy(1)) {

            block_is_instrumented = true;
            cnt_sel++;
            cnt_sel_inc += 2;

          } else {

            unhandled++;

          }

        } else if (rmw) {

          if (rmw->getType()->isIntegerTy(1)) {

            block_is_instrumented = true;
            cnt_sel++;
            cnt_sel_inc += 2;

          } else {

            unhandled++;

          }

        } else if ((selectInst = dyn_cast<SelectInst>(&IN))) {

          Value *c = selectInst->getCondition();
          auto   t = c->getType();
          if (t->getTypeID() == llvm::Type::IntegerTyID) {

            block_is_instrumented = true;
            cnt_sel++;
            cnt_sel_inc += 2;

          } else if (t->getTypeID() == llvm::Type::FixedVectorTyID) {

            FixedVectorType *tt = dyn_cast<FixedVectorType>(t);
            if (tt) {

              block_is_instrumented = true;
              cnt_sel++;
              cnt_sel_inc += (tt->getElementCount().getKnownMinValue() * 2);

            }

          } else {

            if (!be_quiet) {

              WARNF("unknown select ID type: %u\n", t->getTypeID());

            }

          }

        }

      }

    }

    if (block_is_instrumented && /*&BB != &BB.getParent()->getEntryBlock() &&*/
        llvm::is_contained(AllBlocks, &BB)) {

      Instruction *instr = &*BB.begin();
      LLVMContext &Ctx = BB.getContext();
      MDNode      *md = MDNode::get(Ctx, MDString::get(Ctx, "skipinstrument"));
      instr->setMetadata("skipinstrument", md);
      skip_blocks++;

    }

  }

  uint32_t xtra = 0;
  if (skip_blocks < first + cnt_cov + cnt_sel_inc + cnt_special) {

    xtra = first + cnt_cov + cnt_sel_inc + cnt_special - skip_blocks;

  }

  CreateFunctionLocalArrays(F, AllBlocks, xtra);

  if (!FunctionGuardArray) {

    WARNF(
        "SANCOV: FunctionGuardArray is NULL, failed to emit instrumentation.");
    return false;

  }

  if (first) { first = 0; }
  selects += cnt_sel;

  uint32_t special = 0, local_selects = 0;

  for (auto &BB : F) {

    for (auto &IN : BB) {

      if (IN.getMetadata("afl.skip")) {

        // This is a synthetic AFL code we need to ignore
        continue;

      }

      // Check for AFL coverage interesting calls first
      if (isAflInterestingCall(IN)) {

#if LLVM_MAJOR >= 20
        InstrumentationIRBuilder IRB(&IN);
#else
        IRBuilder<> IRB(&IN);
#endif

        Value *GuardPtr = createGuardPointer(
            IRB, special++ + local_selects + AllBlocks.size() - skip_blocks);
        LoadInst *Idx = IRB.CreateLoad(IRB.getInt32Ty(), GuardPtr);
        SetNoSanitizeMetadata(Idx);

        auto *callInst = dyn_cast<CallInst>(&IN);
        callInst->setOperand(1, Idx);
        continue;

      }

      // printDebugInfo(IN);

      // Check if we should instrument this instruction for coverage
      bool instrumentInst = isInstructionInteresting(IN);

      if (instrumentInst) {

        Value      *result = nullptr;
        uint32_t    vector_cnt = 0;
        SelectInst *selectInst;
        IRBuilder<> IRB(IN.getNextNode());

        ICmpInst          *icmp = dyn_cast<ICmpInst>(&IN);
        FCmpInst          *fcmp = dyn_cast<FCmpInst>(&IN);
        AtomicCmpXchgInst *cxchg = dyn_cast<AtomicCmpXchgInst>(&IN);
        AtomicRMWInst     *rmw = dyn_cast<AtomicRMWInst>(&IN);

        if (icmp) {

          if (!icmp->getType()->isIntegerTy(1)) { continue; }

          if (debug) printDebugInfo(IN);

          auto   res = icmp;
          Value *GuardPtr1 =
              createGuardPointer(IRB, cnt_cov + special + local_selects++ +
                                          AllBlocks.size() - skip_blocks);
          Value *GuardPtr2 =
              createGuardPointer(IRB, cnt_cov + special + local_selects++ +
                                          AllBlocks.size() - skip_blocks);
          continue;
          result = IRB.CreateSelect(res, GuardPtr1, GuardPtr2);

          auto        *RES = llvm::cast<llvm::Instruction>(result);
          LLVMContext &Ctx = RES->getContext();
          MDNode      *Tag = MDNode::get(Ctx, {});
          RES->setMetadata("afl.skip", Tag);
          // fprintf(stderr, "Icmp!\n");

        } else if (fcmp) {

          if (!fcmp->getType()->isIntegerTy(1)) { continue; }

          if (debug) printDebugInfo(IN);

          auto   res = fcmp;
          Value *GuardPtr1 =
              createGuardPointer(IRB, cnt_cov + special + local_selects++ +
                                          AllBlocks.size() - skip_blocks);
          Value *GuardPtr2 =
              createGuardPointer(IRB, cnt_cov + special + local_selects++ +
                                          AllBlocks.size() - skip_blocks);
          result = IRB.CreateSelect(res, GuardPtr1, GuardPtr2);
          auto        *RES = llvm::cast<llvm::Instruction>(result);
          LLVMContext &Ctx = RES->getContext();
          MDNode      *Tag = MDNode::get(Ctx, {});
          RES->setMetadata("afl.skip", Tag);
          // fprintf(stderr, "Fcmp!\n");

        } else if (cxchg) {

          if (!cxchg->getType()->isIntegerTy(1)) { continue; }

          if (debug) printDebugInfo(IN);

          Value      *pair = cxchg;
          IRBuilder<> IRB(cxchg->getNextNode());
          Value      *res = IRB.CreateExtractValue(pair, 1);
          Value      *GuardPtr1 =
              createGuardPointer(IRB, cnt_cov + special + local_selects++ +
                                          AllBlocks.size() - skip_blocks);
          Value *GuardPtr2 =
              createGuardPointer(IRB, cnt_cov + special + local_selects++ +
                                          AllBlocks.size() - skip_blocks);
          result = IRB.CreateSelect(res, GuardPtr1, GuardPtr2);
          auto        *RES = llvm::cast<llvm::Instruction>(result);
          LLVMContext &Ctx = RES->getContext();
          MDNode      *Tag = MDNode::get(Ctx, {});
          RES->setMetadata("afl.skip", Tag);
          // fprintf(stderr, "Cxchg!\n");

        } else if (rmw) {

          AtomicRMWInst::BinOp Op = rmw->getOperation();
          if (Op != AtomicRMWInst::Min && Op != AtomicRMWInst::Max &&
              Op != AtomicRMWInst::UMin && Op != AtomicRMWInst::UMax)
            continue;

          IRBuilder<> IRB(rmw->getNextNode());
          Value      *OldVal = rmw;  // result of atomicrmw: old value
          Value *NewVal = rmw->getValOperand();  // value passed to atomicrmw

          if (OldVal->getType() != NewVal->getType()) {

            // should not be needed
            if (NewVal->getType()->isIntegerTy() &&
                OldVal->getType()->isIntegerTy()) {

              unsigned OldBW = OldVal->getType()->getIntegerBitWidth();
              unsigned NewBW = NewVal->getType()->getIntegerBitWidth();
              if (NewBW < OldBW)
                NewVal = IRB.CreateSExt(NewVal, OldVal->getType(), "rmw.ext");
              else if (NewBW > OldBW)
                NewVal =
                    IRB.CreateTrunc(NewVal, OldVal->getType(), "rmw.trunc");

            }

          }

          CmpInst::Predicate Pred;
          switch (Op) {

            case AtomicRMWInst::Min:
              Pred = CmpInst::ICMP_SLT;  // NewVal < OldVal  -> update
              break;
            case AtomicRMWInst::Max:
              Pred = CmpInst::ICMP_SGT;  // NewVal > OldVal  -> update
              break;
            case AtomicRMWInst::UMin:
              Pred = CmpInst::ICMP_ULT;  // NewVal <_u OldVal -> update
              break;
            case AtomicRMWInst::UMax:
              Pred = CmpInst::ICMP_UGT;  // NewVal >_u OldVal -> update
              break;
            default:
              continue;

          }

          Value *res = IRB.CreateICmp(Pred, NewVal, OldVal, "rmw.cov");
          Value *GuardPtr1 =
              createGuardPointer(IRB, cnt_cov + special + local_selects++ +
                                          AllBlocks.size() - skip_blocks);
          Value *GuardPtr2 =
              createGuardPointer(IRB, cnt_cov + special + local_selects++ +
                                          AllBlocks.size() - skip_blocks);
          result = IRB.CreateSelect(res, GuardPtr1, GuardPtr2);
          auto        *RES = llvm::cast<llvm::Instruction>(result);
          LLVMContext &Ctx = RES->getContext();
          MDNode      *Tag = MDNode::get(Ctx, {});
          RES->setMetadata("afl.skip", Tag);
          // fprintf(stderr, "Rmw!\n");

        } else if ((selectInst = dyn_cast<SelectInst>(&IN))) {

          Value *condition = selectInst->getCondition();
          auto   t = condition->getType();

          if (t->getTypeID() == llvm::Type::IntegerTyID) {

            Value *GuardPtr1 =
                createGuardPointer(IRB, cnt_cov + special + local_selects++ +
                                            AllBlocks.size() - skip_blocks);
            Value *GuardPtr2 =
                createGuardPointer(IRB, cnt_cov + special + local_selects++ +
                                            AllBlocks.size() - skip_blocks);
            result = IRB.CreateSelect(condition, GuardPtr1, GuardPtr2);
            auto        *RES = llvm::cast<llvm::Instruction>(result);
            LLVMContext &Ctx = RES->getContext();
            MDNode      *Tag = MDNode::get(Ctx, {});
            RES->setMetadata("afl.skip", Tag);

          } else

              if (t->getTypeID() == llvm::Type::FixedVectorTyID) {

            FixedVectorType *tt = dyn_cast<FixedVectorType>(t);
            if (tt) {

              vector_cnt = tt->getElementCount().getFixedValue();
              result = instrumentVectorSelect(IRB, condition, tt, local_selects,
                                              cnt_cov, skip_blocks, special,
                                              AllBlocks);
              auto        *RES = llvm::cast<llvm::Instruction>(result);
              LLVMContext &Ctx = RES->getContext();
              MDNode      *Tag = MDNode::get(Ctx, {});
              RES->setMetadata("afl.skip", Tag);

            }

          } else

          {

            if (!be_quiet) {

              WARNF("Warning: Unhandled ID type: %u\n", t->getTypeID());

            }

            unhandled++;
            continue;

          }

        }

        // Load SHM pointer and update coverage bitmap
        LoadInst *MapPtr = IRB.CreateLoad(PtrTy, AFLMapPtr);
        SetNoSanitizeMetadata(MapPtr);

        updateCoverageForSelect(IRB, result, MapPtr, vector_cnt);
        instr += vector_cnt;

      }

    }

  }

  if (AllBlocks.empty() && !special && !local_selects) return false;

  uint32_t skipped = 0;

  if (AllBlocks.size() < skipped) { abort(); }  // assert

  if (!AllBlocks.empty()) {

    size_t counter = 0;

    for (size_t i = 0, N = AllBlocks.size(); i < N; i++) {

      auto instr = AllBlocks[i]->begin();
      if (instr->getMetadata("skipinstrument")) {

        skipped++;

      } else {

        InjectCoverageAtBlock(F, *AllBlocks[i], counter++);

      }

    }

  }

  skippedbb += skipped;

  return true;

}

void ModuleSanitizerCoverageAFL::InjectCoverageAtBlock(Function   &F,
                                                       BasicBlock &BB,
                                                       size_t      Idx) {

  BasicBlock::iterator IP = BB.getFirstInsertionPt();
  bool                 IsEntryBB = &BB == &F.getEntryBlock();
  DebugLoc             EntryLoc;

  if (IsEntryBB) {

    if (auto SP = F.getSubprogram())
      EntryLoc = DILocation::get(SP->getContext(), SP->getScopeLine(), 0, SP);
    // Keep static allocas and llvm.localescape calls in the entry block.  Even
    // if we aren't splitting the block, it's nice for allocas to be before
    // calls.
    IP = PrepareToSplitEntryBlock(BB, IP);
#if LLVM_MAJOR < 15

  } else {

    EntryLoc = IP->getDebugLoc();
    if (!EntryLoc)
      if (auto *SP = F.getSubprogram())
        EntryLoc = DILocation::get(SP->getContext(), 0, 0, SP);
#endif

  }

#if LLVM_MAJOR >= 16
  InstrumentationIRBuilder IRB(&*IP);
#else
  IRBuilder<> IRB(&*IP);
#endif
  if (EntryLoc) IRB.SetCurrentDebugLocation(EntryLoc);
  if (Options.TracePCGuard) {

    /* Get CurLoc */

    Value *GuardPtr = createGuardPointer(IRB, Idx);

    LoadInst *CurLoc = IRB.CreateLoad(IRB.getInt32Ty(), GuardPtr);
    ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(CurLoc);

    /* Load SHM pointer */

    LoadInst *MapPtr = IRB.CreateLoad(PtrTy, AFLMapPtr);
    ModuleSanitizerCoverageAFL::SetNoSanitizeMetadata(MapPtr);

    /* Load counter for CurLoc */

    Value *CoverageIndex = CurLoc;

    // Apply IJON state-aware coverage if enabled
    if (ijon_enabled && AFLIJONState) {

      LoadInst *IJONStateVal = IRB.CreateLoad(Int32Ty, AFLIJONState);
      SetNoSanitizeMetadata(IJONStateVal);
      // Apply IJON formula: state XOR coverage_index
      Value *XorResult = IRB.CreateXor(IJONStateVal, CoverageIndex);
      // Ensure result stays within map bounds to prevent buffer overruns
      LoadInst *CovMapSize = IRB.CreateLoad(Int32Ty, AFLCovMapSize);
      SetNoSanitizeMetadata(CovMapSize);
      CoverageIndex = IRB.CreateURem(XorResult, CovMapSize);

    }

    updateCoverageBitmap(IRB, CoverageIndex, MapPtr);

    // done :)

    ++instr;

  }

}

std::string ModuleSanitizerCoverageAFL::getSectionName(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatCOFF()) {

    if (Section == SanCovCountersSectionName) return ".SCOV$CM";
    if (Section == SanCovBoolFlagSectionName) return ".SCOV$BM";
    if (Section == SanCovPCsSectionName) return ".SCOVP$M";
    return ".SCOV$GM";  // For SanCovGuardsSectionName.

  }

  if (TargetTriple.isOSBinFormatMachO()) return "__DATA,__" + Section;
  return "__" + Section;

}

std::string ModuleSanitizerCoverageAFL::getSectionStart(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatMachO())
    return "\1section$start$__DATA$__" + Section;
  return "__start___" + Section;

}

std::string ModuleSanitizerCoverageAFL::getSectionEnd(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatMachO())
    return "\1section$end$__DATA$__" + Section;
  return "__stop___" + Section;

}

