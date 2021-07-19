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

#include "llvm/Transforms/Instrumentation/SanitizerCoverage.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/EHPersonalities.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Mangler.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/SpecialCaseList.h"
#if LLVM_MAJOR > 10 || (LLVM_MAJOR == 10 && LLVM_MINOR > 0)
  #include "llvm/Support/VirtualFileSystem.h"
#endif
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "config.h"
#include "debug.h"
#include "afl-llvm-common.h"

using namespace llvm;

#define DEBUG_TYPE "sancov"

const char SanCovTracePCIndirName[] = "__sanitizer_cov_trace_pc_indir";
const char SanCovTracePCName[] = "__sanitizer_cov_trace_pc";
const char SanCovTraceCmp1[] = "__sanitizer_cov_trace_cmp1";
const char SanCovTraceCmp2[] = "__sanitizer_cov_trace_cmp2";
const char SanCovTraceCmp4[] = "__sanitizer_cov_trace_cmp4";
const char SanCovTraceCmp8[] = "__sanitizer_cov_trace_cmp8";
const char SanCovTraceConstCmp1[] = "__sanitizer_cov_trace_const_cmp1";
const char SanCovTraceConstCmp2[] = "__sanitizer_cov_trace_const_cmp2";
const char SanCovTraceConstCmp4[] = "__sanitizer_cov_trace_const_cmp4";
const char SanCovTraceConstCmp8[] = "__sanitizer_cov_trace_const_cmp8";
const char SanCovTraceDiv4[] = "__sanitizer_cov_trace_div4";
const char SanCovTraceDiv8[] = "__sanitizer_cov_trace_div8";
const char SanCovTraceGep[] = "__sanitizer_cov_trace_gep";
const char SanCovTraceSwitchName[] = "__sanitizer_cov_trace_switch";
const char SanCovModuleCtorTracePcGuardName[] =
    "sancov.module_ctor_trace_pc_guard";
const char SanCovModuleCtor8bitCountersName[] =
    "sancov.module_ctor_8bit_counters";
const char SanCovModuleCtorBoolFlagName[] = "sancov.module_ctor_bool_flag";
static const uint64_t SanCtorAndDtorPriority = 2;

const char SanCovTracePCGuardName[] = "__sanitizer_cov_trace_pc_guard";
const char SanCovTracePCGuardInitName[] = "__sanitizer_cov_trace_pc_guard_init";
const char SanCov8bitCountersInitName[] = "__sanitizer_cov_8bit_counters_init";
const char SanCovBoolFlagInitName[] = "__sanitizer_cov_bool_flag_init";
const char SanCovPCsInitName[] = "__sanitizer_cov_pcs_init";

const char SanCovGuardsSectionName[] = "sancov_guards";
const char SanCovCountersSectionName[] = "sancov_cntrs";
const char SanCovBoolFlagSectionName[] = "sancov_bools";
const char SanCovPCsSectionName[] = "sancov_pcs";

const char SanCovLowestStackName[] = "__sancov_lowest_stack";

static const char *skip_nozero;
static const char *use_threadsafe_counters;

namespace {

SanitizerCoverageOptions OverrideFromCL(SanitizerCoverageOptions Options) {

  // Sets CoverageType and IndirectCalls.
  // SanitizerCoverageOptions CLOpts = getOptions(ClCoverageLevel);
  Options.CoverageType =
      SanitizerCoverageOptions::SCK_Edge;  // std::max(Options.CoverageType,
                                           // CLOpts.CoverageType);
  Options.IndirectCalls = false;           // CLOpts.IndirectCalls;
  Options.TraceCmp = false;                //|= ClCMPTracing;
  Options.TraceDiv = false;                //|= ClDIVTracing;
  Options.TraceGep = false;                //|= ClGEPTracing;
  Options.TracePC = false;                 //|= ClTracePC;
  Options.TracePCGuard = true;             // |= ClTracePCGuard;
  Options.Inline8bitCounters = 0;          //|= ClInline8bitCounters;
  // Options.InlineBoolFlag = 0; //|= ClInlineBoolFlag;
  Options.PCTable = false;     //|= ClCreatePCTable;
  Options.NoPrune = false;     //|= !ClPruneBlocks;
  Options.StackDepth = false;  //|= ClStackDepth;
  if (!Options.TracePCGuard && !Options.TracePC &&
      !Options.Inline8bitCounters && !Options.StackDepth /*&&
      !Options.InlineBoolFlag*/)
    Options.TracePCGuard = true;  // TracePCGuard is default.

  return Options;

}

using DomTreeCallback = function_ref<const DominatorTree *(Function &F)>;
using PostDomTreeCallback =
    function_ref<const PostDominatorTree *(Function &F)>;

class ModuleSanitizerCoverage {

 public:
  ModuleSanitizerCoverage(
      const SanitizerCoverageOptions &Options = SanitizerCoverageOptions()
#if LLVM_MAJOR > 10
          ,
      const SpecialCaseList *Allowlist = nullptr,
      const SpecialCaseList *Blocklist = nullptr
#endif
      )
      : Options(OverrideFromCL(Options)) {

  }

  bool instrumentModule(Module &M, DomTreeCallback DTCallback,
                        PostDomTreeCallback PDTCallback);

 private:
  void instrumentFunction(Function &F, DomTreeCallback DTCallback,
                          PostDomTreeCallback PDTCallback);
  void InjectCoverageForIndirectCalls(Function &              F,
                                      ArrayRef<Instruction *> IndirCalls);
  void InjectTraceForCmp(Function &F, ArrayRef<Instruction *> CmpTraceTargets);
  void InjectTraceForDiv(Function &                 F,
                         ArrayRef<BinaryOperator *> DivTraceTargets);
  void InjectTraceForGep(Function &                    F,
                         ArrayRef<GetElementPtrInst *> GepTraceTargets);
  void InjectTraceForSwitch(Function &              F,
                            ArrayRef<Instruction *> SwitchTraceTargets);
  bool InjectCoverage(Function &F, ArrayRef<BasicBlock *> AllBlocks,
                      bool IsLeafFunc = true);
  GlobalVariable *CreateFunctionLocalArrayInSection(size_t    NumElements,
                                                    Function &F, Type *Ty,
                                                    const char *Section);
  GlobalVariable *CreatePCArray(Function &F, ArrayRef<BasicBlock *> AllBlocks);
  void CreateFunctionLocalArrays(Function &F, ArrayRef<BasicBlock *> AllBlocks,
                                 uint32_t special);
  void InjectCoverageAtBlock(Function &F, BasicBlock &BB, size_t Idx,
                             bool IsLeafFunc = true);
  Function *CreateInitCallsForSections(Module &M, const char *CtorName,
                                       const char *InitFunctionName, Type *Ty,
                                       const char *Section);
  std::pair<Value *, Value *> CreateSecStartEnd(Module &M, const char *Section,
                                                Type *Ty);

  void SetNoSanitizeMetadata(Instruction *I) {

    I->setMetadata(I->getModule()->getMDKindID("nosanitize"),
                   MDNode::get(*C, None));

  }

  std::string     getSectionName(const std::string &Section) const;
  std::string     getSectionStart(const std::string &Section) const;
  std::string     getSectionEnd(const std::string &Section) const;
  FunctionCallee  SanCovTracePCIndir;
  FunctionCallee  SanCovTracePC, SanCovTracePCGuard;
  FunctionCallee  SanCovTraceCmpFunction[4];
  FunctionCallee  SanCovTraceConstCmpFunction[4];
  FunctionCallee  SanCovTraceDivFunction[2];
  FunctionCallee  SanCovTraceGepFunction;
  FunctionCallee  SanCovTraceSwitchFunction;
  GlobalVariable *SanCovLowestStack;
  Type *IntptrTy, *IntptrPtrTy, *Int64Ty, *Int64PtrTy, *Int32Ty, *Int32PtrTy,
      *Int16Ty, *Int8Ty, *Int8PtrTy, *Int1Ty, *Int1PtrTy;
  Module *          CurModule;
  std::string       CurModuleUniqueId;
  Triple            TargetTriple;
  LLVMContext *     C;
  const DataLayout *DL;

  GlobalVariable *FunctionGuardArray;        // for trace-pc-guard.
  GlobalVariable *Function8bitCounterArray;  // for inline-8bit-counters.
  GlobalVariable *FunctionBoolArray;         // for inline-bool-flag.
  GlobalVariable *FunctionPCsArray;          // for pc-table.
  SmallVector<GlobalValue *, 20> GlobalsToAppendToUsed;
  SmallVector<GlobalValue *, 20> GlobalsToAppendToCompilerUsed;

  SanitizerCoverageOptions Options;

  uint32_t        instr = 0;
  GlobalVariable *AFLMapPtr = NULL;
  ConstantInt *   One = NULL;
  ConstantInt *   Zero = NULL;

};

class ModuleSanitizerCoverageLegacyPass : public ModulePass {

 public:
  ModuleSanitizerCoverageLegacyPass(
      const SanitizerCoverageOptions &Options = SanitizerCoverageOptions()
#if LLVM_VERSION_MAJOR > 10
          ,
      const std::vector<std::string> &AllowlistFiles =
          std::vector<std::string>(),
      const std::vector<std::string> &BlocklistFiles =
          std::vector<std::string>()
#endif
          )
      : ModulePass(ID), Options(Options) {

    initializeModuleSanitizerCoverageLegacyPassPass(
        *PassRegistry::getPassRegistry());

  }

  bool runOnModule(Module &M) override {

    ModuleSanitizerCoverage ModuleSancov(Options
#if LLVM_MAJOR > 10
                                         ,
                                         Allowlist.get(), Blocklist.get()
#endif
    );
    auto DTCallback = [this](Function &F) -> const DominatorTree * {

      return &this->getAnalysis<DominatorTreeWrapperPass>(F).getDomTree();

    };

    auto PDTCallback = [this](Function &F) -> const PostDominatorTree * {

      return &this->getAnalysis<PostDominatorTreeWrapperPass>(F)
                  .getPostDomTree();

    };

    return ModuleSancov.instrumentModule(M, DTCallback, PDTCallback);

  }

  static char ID;  // Pass identification, replacement for typeid
  StringRef   getPassName() const override {

    return "ModuleSanitizerCoverage";

  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {

    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<PostDominatorTreeWrapperPass>();

  }

 private:
  SanitizerCoverageOptions Options;

  std::unique_ptr<SpecialCaseList> Allowlist;
  std::unique_ptr<SpecialCaseList> Blocklist;

};

}  // namespace

PreservedAnalyses ModuleSanitizerCoveragePass::run(Module &               M,
                                                   ModuleAnalysisManager &MAM) {

  ModuleSanitizerCoverage ModuleSancov(Options
#if LLVM_MAJOR > 10
                                       ,
                                       Allowlist.get(), Blocklist.get()
#endif
  );
  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  auto  DTCallback = [&FAM](Function &F) -> const DominatorTree * {

    return &FAM.getResult<DominatorTreeAnalysis>(F);

  };

  auto PDTCallback = [&FAM](Function &F) -> const PostDominatorTree * {

    return &FAM.getResult<PostDominatorTreeAnalysis>(F);

  };

  if (ModuleSancov.instrumentModule(M, DTCallback, PDTCallback))
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();

}

std::pair<Value *, Value *> ModuleSanitizerCoverage::CreateSecStartEnd(
    Module &M, const char *Section, Type *Ty) {

  GlobalVariable *SecStart = new GlobalVariable(
      M, Ty->getPointerElementType(), false,
      GlobalVariable::ExternalWeakLinkage, nullptr, getSectionStart(Section));
  SecStart->setVisibility(GlobalValue::HiddenVisibility);
  GlobalVariable *SecEnd = new GlobalVariable(
      M, Ty->getPointerElementType(), false,
      GlobalVariable::ExternalWeakLinkage, nullptr, getSectionEnd(Section));
  SecEnd->setVisibility(GlobalValue::HiddenVisibility);
  IRBuilder<> IRB(M.getContext());
  if (!TargetTriple.isOSBinFormatCOFF())
    return std::make_pair(SecStart, SecEnd);

  // Account for the fact that on windows-msvc __start_* symbols actually
  // point to a uint64_t before the start of the array.
  auto SecStartI8Ptr = IRB.CreatePointerCast(SecStart, Int8PtrTy);
  auto GEP = IRB.CreateGEP(Int8Ty, SecStartI8Ptr,
                           ConstantInt::get(IntptrTy, sizeof(uint64_t)));
  return std::make_pair(IRB.CreatePointerCast(GEP, Ty), SecEnd);

}

Function *ModuleSanitizerCoverage::CreateInitCallsForSections(
    Module &M, const char *CtorName, const char *InitFunctionName, Type *Ty,
    const char *Section) {

  auto      SecStartEnd = CreateSecStartEnd(M, Section, Ty);
  auto      SecStart = SecStartEnd.first;
  auto      SecEnd = SecStartEnd.second;
  Function *CtorFunc;
  std::tie(CtorFunc, std::ignore) = createSanitizerCtorAndInitFunctions(
      M, CtorName, InitFunctionName, {Ty, Ty}, {SecStart, SecEnd});
  assert(CtorFunc->getName() == CtorName);

  if (TargetTriple.supportsCOMDAT()) {

    // Use comdat to dedup CtorFunc.
    CtorFunc->setComdat(M.getOrInsertComdat(CtorName));
    appendToGlobalCtors(M, CtorFunc, SanCtorAndDtorPriority, CtorFunc);

  } else {

    appendToGlobalCtors(M, CtorFunc, SanCtorAndDtorPriority);

  }

  if (TargetTriple.isOSBinFormatCOFF()) {

    // In COFF files, if the contructors are set as COMDAT (they are because
    // COFF supports COMDAT) and the linker flag /OPT:REF (strip unreferenced
    // functions and data) is used, the constructors get stripped. To prevent
    // this, give the constructors weak ODR linkage and ensure the linker knows
    // to include the sancov constructor. This way the linker can deduplicate
    // the constructors but always leave one copy.
    CtorFunc->setLinkage(GlobalValue::WeakODRLinkage);
    appendToUsed(M, CtorFunc);

  }

  return CtorFunc;

}

bool ModuleSanitizerCoverage::instrumentModule(
    Module &M, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {

  setvbuf(stdout, NULL, _IONBF, 0);
  if (getenv("AFL_DEBUG")) debug = 1;

  if ((isatty(2) && !getenv("AFL_QUIET")) || debug) {

    SAYF(cCYA "SanitizerCoveragePCGUARD" VERSION cRST "\n");

  } else

    be_quiet = 1;

  skip_nozero = getenv("AFL_LLVM_SKIP_NEVERZERO");
  use_threadsafe_counters = getenv("AFL_LLVM_THREADSAFE_INST");

  initInstrumentList();
  scanForDangerousFunctions(&M);

  if (debug) {

    fprintf(stderr,
            "SANCOV: covtype:%u indirect:%d stack:%d noprune:%d "
            "createtable:%d tracepcguard:%d tracepc:%d\n",
            Options.CoverageType, Options.IndirectCalls == true ? 1 : 0,
            Options.StackDepth == true ? 1 : 0, Options.NoPrune == true ? 1 : 0,
            // Options.InlineBoolFlag == true ? 1 : 0,
            Options.PCTable == true ? 1 : 0,
            Options.TracePCGuard == true ? 1 : 0,
            Options.TracePC == true ? 1 : 0);

  }

  if (Options.CoverageType == SanitizerCoverageOptions::SCK_None) return false;
  C = &(M.getContext());
  DL = &M.getDataLayout();
  CurModule = &M;
  CurModuleUniqueId = getUniqueModuleId(CurModule);
  TargetTriple = Triple(M.getTargetTriple());
  FunctionGuardArray = nullptr;
  Function8bitCounterArray = nullptr;
  FunctionBoolArray = nullptr;
  FunctionPCsArray = nullptr;
  IntptrTy = Type::getIntNTy(*C, DL->getPointerSizeInBits());
  IntptrPtrTy = PointerType::getUnqual(IntptrTy);
  Type *      VoidTy = Type::getVoidTy(*C);
  IRBuilder<> IRB(*C);
  Int64PtrTy = PointerType::getUnqual(IRB.getInt64Ty());
  Int32PtrTy = PointerType::getUnqual(IRB.getInt32Ty());
  Int8PtrTy = PointerType::getUnqual(IRB.getInt8Ty());
  Int1PtrTy = PointerType::getUnqual(IRB.getInt1Ty());
  Int64Ty = IRB.getInt64Ty();
  Int32Ty = IRB.getInt32Ty();
  Int16Ty = IRB.getInt16Ty();
  Int8Ty = IRB.getInt8Ty();
  Int1Ty = IRB.getInt1Ty();
  LLVMContext &Ctx = M.getContext();

  AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
  One = ConstantInt::get(IntegerType::getInt8Ty(Ctx), 1);
  Zero = ConstantInt::get(IntegerType::getInt8Ty(Ctx), 0);

  SanCovTracePCIndir =
      M.getOrInsertFunction(SanCovTracePCIndirName, VoidTy, IntptrTy);
  // Make sure smaller parameters are zero-extended to i64 if required by the
  // target ABI.
  AttributeList SanCovTraceCmpZeroExtAL;
  SanCovTraceCmpZeroExtAL =
      SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 0, Attribute::ZExt);
  SanCovTraceCmpZeroExtAL =
      SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 1, Attribute::ZExt);

  SanCovTraceCmpFunction[0] =
      M.getOrInsertFunction(SanCovTraceCmp1, SanCovTraceCmpZeroExtAL, VoidTy,
                            IRB.getInt8Ty(), IRB.getInt8Ty());
  SanCovTraceCmpFunction[1] =
      M.getOrInsertFunction(SanCovTraceCmp2, SanCovTraceCmpZeroExtAL, VoidTy,
                            IRB.getInt16Ty(), IRB.getInt16Ty());
  SanCovTraceCmpFunction[2] =
      M.getOrInsertFunction(SanCovTraceCmp4, SanCovTraceCmpZeroExtAL, VoidTy,
                            IRB.getInt32Ty(), IRB.getInt32Ty());
  SanCovTraceCmpFunction[3] =
      M.getOrInsertFunction(SanCovTraceCmp8, VoidTy, Int64Ty, Int64Ty);

  SanCovTraceConstCmpFunction[0] = M.getOrInsertFunction(
      SanCovTraceConstCmp1, SanCovTraceCmpZeroExtAL, VoidTy, Int8Ty, Int8Ty);
  SanCovTraceConstCmpFunction[1] = M.getOrInsertFunction(
      SanCovTraceConstCmp2, SanCovTraceCmpZeroExtAL, VoidTy, Int16Ty, Int16Ty);
  SanCovTraceConstCmpFunction[2] = M.getOrInsertFunction(
      SanCovTraceConstCmp4, SanCovTraceCmpZeroExtAL, VoidTy, Int32Ty, Int32Ty);
  SanCovTraceConstCmpFunction[3] =
      M.getOrInsertFunction(SanCovTraceConstCmp8, VoidTy, Int64Ty, Int64Ty);

  {

    AttributeList AL;
    AL = AL.addParamAttribute(*C, 0, Attribute::ZExt);
    SanCovTraceDivFunction[0] =
        M.getOrInsertFunction(SanCovTraceDiv4, AL, VoidTy, IRB.getInt32Ty());

  }

  SanCovTraceDivFunction[1] =
      M.getOrInsertFunction(SanCovTraceDiv8, VoidTy, Int64Ty);
  SanCovTraceGepFunction =
      M.getOrInsertFunction(SanCovTraceGep, VoidTy, IntptrTy);
  SanCovTraceSwitchFunction =
      M.getOrInsertFunction(SanCovTraceSwitchName, VoidTy, Int64Ty, Int64PtrTy);

  Constant *SanCovLowestStackConstant =
      M.getOrInsertGlobal(SanCovLowestStackName, IntptrTy);
  SanCovLowestStack = dyn_cast<GlobalVariable>(SanCovLowestStackConstant);
  if (!SanCovLowestStack) {

    C->emitError(StringRef("'") + SanCovLowestStackName +
                 "' should not be declared by the user");
    return true;

  }

  SanCovLowestStack->setThreadLocalMode(
      GlobalValue::ThreadLocalMode::InitialExecTLSModel);
  if (Options.StackDepth && !SanCovLowestStack->isDeclaration())
    SanCovLowestStack->setInitializer(Constant::getAllOnesValue(IntptrTy));

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
  if (Function8bitCounterArray)
    Ctor = CreateInitCallsForSections(M, SanCovModuleCtor8bitCountersName,
                                      SanCov8bitCountersInitName, Int8PtrTy,
                                      SanCovCountersSectionName);
  if (FunctionBoolArray) {

    Ctor = CreateInitCallsForSections(M, SanCovModuleCtorBoolFlagName,
                                      SanCovBoolFlagInitName, Int1PtrTy,
                                      SanCovBoolFlagSectionName);

  }

  if (Ctor && Options.PCTable) {

    auto SecStartEnd = CreateSecStartEnd(M, SanCovPCsSectionName, IntptrPtrTy);
    FunctionCallee InitFunction = declareSanitizerInitFunction(
        M, SanCovPCsInitName, {IntptrPtrTy, IntptrPtrTy});
    IRBuilder<> IRBCtor(Ctor->getEntryBlock().getTerminator());
    IRBCtor.CreateCall(InitFunction, {SecStartEnd.first, SecStartEnd.second});

  }

  // We don't reference these arrays directly in any of our runtime functions,
  // so we need to prevent them from being dead stripped.
  if (TargetTriple.isOSBinFormatMachO()) appendToUsed(M, GlobalsToAppendToUsed);
  appendToCompilerUsed(M, GlobalsToAppendToCompilerUsed);

  if (!be_quiet) {

    if (!instr)
      WARNF("No instrumentation targets found.");
    else {

      char modeline[100];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
      OKF("Instrumented %u locations with no collisions (%s mode).", instr,
          modeline);

    }

  }

  return true;

}

// True if block has successors and it dominates all of them.
bool isFullDominator(const BasicBlock *BB, const DominatorTree *DT) {

  if (succ_begin(BB) == succ_end(BB)) return false;

  for (const BasicBlock *SUCC : make_range(succ_begin(BB), succ_end(BB))) {

    if (!DT->dominates(BB, SUCC)) return false;

  }

  return true;

}

// True if block has predecessors and it postdominates all of them.
bool isFullPostDominator(const BasicBlock *BB, const PostDominatorTree *PDT) {

  if (pred_begin(BB) == pred_end(BB)) return false;

  for (const BasicBlock *PRED : make_range(pred_begin(BB), pred_end(BB))) {

    if (!PDT->dominates(BB, PRED)) return false;

  }

  return true;

}

bool shouldInstrumentBlock(const Function &F, const BasicBlock *BB,
                           const DominatorTree *           DT,
                           const PostDominatorTree *       PDT,
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

  if (Options.CoverageType == SanitizerCoverageOptions::SCK_Function &&
      &F.getEntryBlock() != BB)
    return false;

  // Do not instrument full dominators, or full post-dominators with multiple
  // predecessors.
  return !isFullDominator(BB, DT) &&
         !(isFullPostDominator(BB, PDT) && !BB->getSinglePredecessor());

}

// Returns true iff From->To is a backedge.
// A twist here is that we treat From->To as a backedge if
//   * To dominates From or
//   * To->UniqueSuccessor dominates From
bool IsBackEdge(BasicBlock *From, BasicBlock *To, const DominatorTree *DT) {

  if (DT->dominates(To, From)) return true;
  if (auto Next = To->getUniqueSuccessor())
    if (DT->dominates(Next, From)) return true;
  return false;

}

// Prunes uninteresting Cmp instrumentation:
//   * CMP instructions that feed into loop backedge branch.
//
// Note that Cmp pruning is controlled by the same flag as the
// BB pruning.
bool IsInterestingCmp(ICmpInst *CMP, const DominatorTree *DT,
                      const SanitizerCoverageOptions &Options) {

  if (!Options.NoPrune)
    if (CMP->hasOneUse())
      if (auto BR = dyn_cast<BranchInst>(CMP->user_back()))
        for (BasicBlock *B : BR->successors())
          if (IsBackEdge(BR->getParent(), B, DT)) return false;
  return true;

}

void ModuleSanitizerCoverage::instrumentFunction(
    Function &F, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {

  if (F.empty()) return;
  if (!isInInstrumentList(&F)) return;

  if (F.getName().find(".module_ctor") != std::string::npos)
    return;  // Should not instrument sanitizer init functions.
  if (F.getName().startswith("__sanitizer_"))
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
  if (Options.CoverageType >= SanitizerCoverageOptions::SCK_Edge)
    SplitAllCriticalEdges(
        F, CriticalEdgeSplittingOptions().setIgnoreUnreachableDests());
  SmallVector<Instruction *, 8>       IndirCalls;
  SmallVector<BasicBlock *, 16>       BlocksToInstrument;
  SmallVector<Instruction *, 8>       CmpTraceTargets;
  SmallVector<Instruction *, 8>       SwitchTraceTargets;
  SmallVector<BinaryOperator *, 8>    DivTraceTargets;
  SmallVector<GetElementPtrInst *, 8> GepTraceTargets;

  const DominatorTree *    DT = DTCallback(F);
  const PostDominatorTree *PDT = PDTCallback(F);
  bool                     IsLeafFunc = true;

  for (auto &BB : F) {

    if (shouldInstrumentBlock(F, &BB, DT, PDT, Options))
      BlocksToInstrument.push_back(&BB);
    for (auto &Inst : BB) {

      if (Options.IndirectCalls) {

        CallBase *CB = dyn_cast<CallBase>(&Inst);
        if (CB && !CB->getCalledFunction()) IndirCalls.push_back(&Inst);

      }

      if (Options.TraceCmp) {

        if (ICmpInst *CMP = dyn_cast<ICmpInst>(&Inst))
          if (IsInterestingCmp(CMP, DT, Options))
            CmpTraceTargets.push_back(&Inst);
        if (isa<SwitchInst>(&Inst)) SwitchTraceTargets.push_back(&Inst);

      }

      if (Options.TraceDiv)
        if (BinaryOperator *BO = dyn_cast<BinaryOperator>(&Inst))
          if (BO->getOpcode() == Instruction::SDiv ||
              BO->getOpcode() == Instruction::UDiv)
            DivTraceTargets.push_back(BO);
      if (Options.TraceGep)
        if (GetElementPtrInst *GEP = dyn_cast<GetElementPtrInst>(&Inst))
          GepTraceTargets.push_back(GEP);
      if (Options.StackDepth)
        if (isa<InvokeInst>(Inst) ||
            (isa<CallInst>(Inst) && !isa<IntrinsicInst>(Inst)))
          IsLeafFunc = false;

    }

  }

  InjectCoverage(F, BlocksToInstrument, IsLeafFunc);
  InjectCoverageForIndirectCalls(F, IndirCalls);
  InjectTraceForCmp(F, CmpTraceTargets);
  InjectTraceForSwitch(F, SwitchTraceTargets);
  InjectTraceForDiv(F, DivTraceTargets);
  InjectTraceForGep(F, GepTraceTargets);

}

GlobalVariable *ModuleSanitizerCoverage::CreateFunctionLocalArrayInSection(
    size_t NumElements, Function &F, Type *Ty, const char *Section) {

  ArrayType *ArrayTy = ArrayType::get(Ty, NumElements);
  auto       Array = new GlobalVariable(
      *CurModule, ArrayTy, false, GlobalVariable::PrivateLinkage,
      Constant::getNullValue(ArrayTy), "__sancov_gen_");

#if LLVM_VERSION_MAJOR > 12
  if (TargetTriple.supportsCOMDAT() &&
      (TargetTriple.isOSBinFormatELF() || !F.isInterposable()))
    if (auto Comdat = getOrCreateFunctionComdat(F, TargetTriple))
      Array->setComdat(Comdat);
#else
  if (TargetTriple.supportsCOMDAT() && !F.isInterposable())
    if (auto Comdat =
            GetOrCreateFunctionComdat(F, TargetTriple, CurModuleUniqueId))
      Array->setComdat(Comdat);
#endif

  Array->setSection(getSectionName(Section));
#if LLVM_MAJOR > 10 || (LLVM_MAJOR == 10 && LLVM_MINOR > 0)
  Array->setAlignment(Align(DL->getTypeStoreSize(Ty).getFixedSize()));
#else
  Array->setAlignment(Align(4));  // cheating
#endif
  GlobalsToAppendToUsed.push_back(Array);
  GlobalsToAppendToCompilerUsed.push_back(Array);
  MDNode *MD = MDNode::get(F.getContext(), ValueAsMetadata::get(&F));
  Array->addMetadata(LLVMContext::MD_associated, *MD);

  return Array;

}

GlobalVariable *ModuleSanitizerCoverage::CreatePCArray(
    Function &F, ArrayRef<BasicBlock *> AllBlocks) {

  size_t N = AllBlocks.size();
  assert(N);
  SmallVector<Constant *, 32> PCs;
  IRBuilder<>                 IRB(&*F.getEntryBlock().getFirstInsertionPt());
  for (size_t i = 0; i < N; i++) {

    if (&F.getEntryBlock() == AllBlocks[i]) {

      PCs.push_back((Constant *)IRB.CreatePointerCast(&F, IntptrPtrTy));
      PCs.push_back((Constant *)IRB.CreateIntToPtr(
          ConstantInt::get(IntptrTy, 1), IntptrPtrTy));

    } else {

      PCs.push_back((Constant *)IRB.CreatePointerCast(
          BlockAddress::get(AllBlocks[i]), IntptrPtrTy));
      PCs.push_back((Constant *)IRB.CreateIntToPtr(
          ConstantInt::get(IntptrTy, 0), IntptrPtrTy));

    }

  }

  auto *PCArray = CreateFunctionLocalArrayInSection(N * 2, F, IntptrPtrTy,
                                                    SanCovPCsSectionName);
  PCArray->setInitializer(
      ConstantArray::get(ArrayType::get(IntptrPtrTy, N * 2), PCs));
  PCArray->setConstant(true);

  return PCArray;

}

void ModuleSanitizerCoverage::CreateFunctionLocalArrays(
    Function &F, ArrayRef<BasicBlock *> AllBlocks, uint32_t special) {

  if (Options.TracePCGuard)
    FunctionGuardArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size() + special, F, Int32Ty, SanCovGuardsSectionName);

  if (Options.Inline8bitCounters)
    Function8bitCounterArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size(), F, Int8Ty, SanCovCountersSectionName);
  /*
    if (Options.InlineBoolFlag)
      FunctionBoolArray = CreateFunctionLocalArrayInSection(
          AllBlocks.size(), F, Int1Ty, SanCovBoolFlagSectionName);
  */
  if (Options.PCTable) FunctionPCsArray = CreatePCArray(F, AllBlocks);

}

bool ModuleSanitizerCoverage::InjectCoverage(Function &             F,
                                             ArrayRef<BasicBlock *> AllBlocks,
                                             bool IsLeafFunc) {

  if (AllBlocks.empty()) return false;

  uint32_t special = 0;
  for (auto &BB : F) {

    for (auto &IN : BB) {

      CallInst *callInst = nullptr;

      if ((callInst = dyn_cast<CallInst>(&IN))) {

        Function *Callee = callInst->getCalledFunction();
        if (!Callee) continue;
        if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
        StringRef FuncName = Callee->getName();
        if (FuncName.compare(StringRef("__afl_coverage_interesting"))) continue;

        uint32_t id = 1 + instr + (uint32_t)AllBlocks.size() + special++;
        Value *  val = ConstantInt::get(Int32Ty, id);
        callInst->setOperand(1, val);

      }

    }

  }

  CreateFunctionLocalArrays(F, AllBlocks, special);
  for (size_t i = 0, N = AllBlocks.size(); i < N; i++)
    InjectCoverageAtBlock(F, *AllBlocks[i], i, IsLeafFunc);

  instr += special;

  return true;

}

// On every indirect call we call a run-time function
// __sanitizer_cov_indir_call* with two parameters:
//   - callee address,
//   - global cache array that contains CacheSize pointers (zero-initialized).
//     The cache is used to speed up recording the caller-callee pairs.
// The address of the caller is passed implicitly via caller PC.
// CacheSize is encoded in the name of the run-time function.
void ModuleSanitizerCoverage::InjectCoverageForIndirectCalls(
    Function &F, ArrayRef<Instruction *> IndirCalls) {

  if (IndirCalls.empty()) return;
  assert(Options.TracePC || Options.TracePCGuard ||
         Options.Inline8bitCounters /*|| Options.InlineBoolFlag*/);
  for (auto I : IndirCalls) {

    IRBuilder<> IRB(I);
    CallBase &  CB = cast<CallBase>(*I);
    Value *     Callee = CB.getCalledOperand();
    if (isa<InlineAsm>(Callee)) continue;
    IRB.CreateCall(SanCovTracePCIndir, IRB.CreatePointerCast(Callee, IntptrTy));

  }

}

// For every switch statement we insert a call:
// __sanitizer_cov_trace_switch(CondValue,
//      {NumCases, ValueSizeInBits, Case0Value, Case1Value, Case2Value, ... })

void ModuleSanitizerCoverage::InjectTraceForSwitch(
    Function &, ArrayRef<Instruction *> SwitchTraceTargets) {

  for (auto I : SwitchTraceTargets) {

    if (SwitchInst *SI = dyn_cast<SwitchInst>(I)) {

      IRBuilder<>                 IRB(I);
      SmallVector<Constant *, 16> Initializers;
      Value *                     Cond = SI->getCondition();
      if (Cond->getType()->getScalarSizeInBits() >
          Int64Ty->getScalarSizeInBits())
        continue;
      Initializers.push_back(ConstantInt::get(Int64Ty, SI->getNumCases()));
      Initializers.push_back(
          ConstantInt::get(Int64Ty, Cond->getType()->getScalarSizeInBits()));
      if (Cond->getType()->getScalarSizeInBits() <
          Int64Ty->getScalarSizeInBits())
        Cond = IRB.CreateIntCast(Cond, Int64Ty, false);
      for (auto It : SI->cases()) {

        Constant *C = It.getCaseValue();
        if (C->getType()->getScalarSizeInBits() <
            Int64Ty->getScalarSizeInBits())
          C = ConstantExpr::getCast(CastInst::ZExt, It.getCaseValue(), Int64Ty);
        Initializers.push_back(C);

      }

      llvm::sort(drop_begin(Initializers, 2),
                 [](const Constant *A, const Constant *B) {

                   return cast<ConstantInt>(A)->getLimitedValue() <
                          cast<ConstantInt>(B)->getLimitedValue();

                 });

      ArrayType *ArrayOfInt64Ty = ArrayType::get(Int64Ty, Initializers.size());
      GlobalVariable *GV = new GlobalVariable(
          *CurModule, ArrayOfInt64Ty, false, GlobalVariable::InternalLinkage,
          ConstantArray::get(ArrayOfInt64Ty, Initializers),
          "__sancov_gen_cov_switch_values");
      IRB.CreateCall(SanCovTraceSwitchFunction,
                     {Cond, IRB.CreatePointerCast(GV, Int64PtrTy)});

    }

  }

}

void ModuleSanitizerCoverage::InjectTraceForDiv(
    Function &, ArrayRef<BinaryOperator *> DivTraceTargets) {

  for (auto BO : DivTraceTargets) {

    IRBuilder<> IRB(BO);
    Value *     A1 = BO->getOperand(1);
    if (isa<ConstantInt>(A1)) continue;
    if (!A1->getType()->isIntegerTy()) continue;
    uint64_t TypeSize = DL->getTypeStoreSizeInBits(A1->getType());
    int      CallbackIdx = TypeSize == 32 ? 0 : TypeSize == 64 ? 1 : -1;
    if (CallbackIdx < 0) continue;
    auto Ty = Type::getIntNTy(*C, TypeSize);
    IRB.CreateCall(SanCovTraceDivFunction[CallbackIdx],
                   {IRB.CreateIntCast(A1, Ty, true)});

  }

}

void ModuleSanitizerCoverage::InjectTraceForGep(
    Function &, ArrayRef<GetElementPtrInst *> GepTraceTargets) {

  for (auto GEP : GepTraceTargets) {

    IRBuilder<> IRB(GEP);
    for (Use &Idx : GEP->indices())
      if (!isa<ConstantInt>(Idx) && Idx->getType()->isIntegerTy())
        IRB.CreateCall(SanCovTraceGepFunction,
                       {IRB.CreateIntCast(Idx, IntptrTy, true)});

  }

}

void ModuleSanitizerCoverage::InjectTraceForCmp(
    Function &, ArrayRef<Instruction *> CmpTraceTargets) {

  for (auto I : CmpTraceTargets) {

    if (ICmpInst *ICMP = dyn_cast<ICmpInst>(I)) {

      IRBuilder<> IRB(ICMP);
      Value *     A0 = ICMP->getOperand(0);
      Value *     A1 = ICMP->getOperand(1);
      if (!A0->getType()->isIntegerTy()) continue;
      uint64_t TypeSize = DL->getTypeStoreSizeInBits(A0->getType());
      int      CallbackIdx = TypeSize == 8    ? 0
                             : TypeSize == 16 ? 1
                             : TypeSize == 32 ? 2
                             : TypeSize == 64 ? 3
                                              : -1;
      if (CallbackIdx < 0) continue;
      // __sanitizer_cov_trace_cmp((type_size << 32) | predicate, A0, A1);
      auto CallbackFunc = SanCovTraceCmpFunction[CallbackIdx];
      bool FirstIsConst = isa<ConstantInt>(A0);
      bool SecondIsConst = isa<ConstantInt>(A1);
      // If both are const, then we don't need such a comparison.
      if (FirstIsConst && SecondIsConst) continue;
      // If only one is const, then make it the first callback argument.
      if (FirstIsConst || SecondIsConst) {

        CallbackFunc = SanCovTraceConstCmpFunction[CallbackIdx];
        if (SecondIsConst) std::swap(A0, A1);

      }

      auto Ty = Type::getIntNTy(*C, TypeSize);
      IRB.CreateCall(CallbackFunc, {IRB.CreateIntCast(A0, Ty, true),
                                    IRB.CreateIntCast(A1, Ty, true)});

    }

  }

}

void ModuleSanitizerCoverage::InjectCoverageAtBlock(Function &F, BasicBlock &BB,
                                                    size_t Idx,
                                                    bool   IsLeafFunc) {

  BasicBlock::iterator IP = BB.getFirstInsertionPt();
  bool                 IsEntryBB = &BB == &F.getEntryBlock();

  if (IsEntryBB) {

    // Keep allocas and llvm.localescape calls in the entry block.  Even
    // if we aren't splitting the block, it's nice for allocas to be before
    // calls.
    IP = PrepareToSplitEntryBlock(BB, IP);

  }

  IRBuilder<> IRB(&*IP);

  if (Options.TracePC) {

    IRB.CreateCall(SanCovTracePC);
    //        ->setCannotMerge();  // gets the PC using GET_CALLER_PC.

  }

  if (Options.TracePCGuard) {

    /* Get CurLoc */

    Value *GuardPtr = IRB.CreateIntToPtr(
        IRB.CreateAdd(IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                      ConstantInt::get(IntptrTy, Idx * 4)),
        Int32PtrTy);

    LoadInst *CurLoc = IRB.CreateLoad(GuardPtr);

    /* Load SHM pointer */

    LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);

    /* Load counter for CurLoc */

    Value *MapPtrIdx = IRB.CreateGEP(MapPtr, CurLoc);

    if (use_threadsafe_counters) {

      IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                          llvm::MaybeAlign(1),
#endif
                          llvm::AtomicOrdering::Monotonic);

    } else {

      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      /* Update bitmap */

      Value *Incr = IRB.CreateAdd(Counter, One);

      if (skip_nozero == NULL) {

        auto cf = IRB.CreateICmpEQ(Incr, Zero);
        auto carry = IRB.CreateZExt(cf, Int8Ty);
        Incr = IRB.CreateAdd(Incr, carry);

      }

      IRB.CreateStore(Incr, MapPtrIdx);

    }

    // done :)

    //    IRB.CreateCall(SanCovTracePCGuard, Offset)->setCannotMerge();
    //    IRB.CreateCall(SanCovTracePCGuard, GuardPtr)->setCannotMerge();
    ++instr;

  }

  if (Options.Inline8bitCounters) {

    auto CounterPtr = IRB.CreateGEP(
        Function8bitCounterArray->getValueType(), Function8bitCounterArray,
        {ConstantInt::get(IntptrTy, 0), ConstantInt::get(IntptrTy, Idx)});
    auto Load = IRB.CreateLoad(Int8Ty, CounterPtr);
    auto Inc = IRB.CreateAdd(Load, ConstantInt::get(Int8Ty, 1));
    auto Store = IRB.CreateStore(Inc, CounterPtr);
    SetNoSanitizeMetadata(Load);
    SetNoSanitizeMetadata(Store);

  }

  /*
    if (Options.InlineBoolFlag) {

      auto FlagPtr = IRB.CreateGEP(
          FunctionBoolArray->getValueType(), FunctionBoolArray,
          {ConstantInt::get(IntptrTy, 0), ConstantInt::get(IntptrTy, Idx)});
      auto Load = IRB.CreateLoad(Int1Ty, FlagPtr);
      auto ThenTerm =
          SplitBlockAndInsertIfThen(IRB.CreateIsNull(Load), &*IP, false);
      IRBuilder<> ThenIRB(ThenTerm);
      auto Store = ThenIRB.CreateStore(ConstantInt::getTrue(Int1Ty), FlagPtr);
      SetNoSanitizeMetadata(Load);
      SetNoSanitizeMetadata(Store);

    }

  */

  if (Options.StackDepth && IsEntryBB && !IsLeafFunc) {

    // Check stack depth.  If it's the deepest so far, record it.
    Module *  M = F.getParent();
    Function *GetFrameAddr = Intrinsic::getDeclaration(
        M, Intrinsic::frameaddress,
        IRB.getInt8PtrTy(M->getDataLayout().getAllocaAddrSpace()));
    auto FrameAddrPtr =
        IRB.CreateCall(GetFrameAddr, {Constant::getNullValue(Int32Ty)});
    auto        FrameAddrInt = IRB.CreatePtrToInt(FrameAddrPtr, IntptrTy);
    auto        LowestStack = IRB.CreateLoad(IntptrTy, SanCovLowestStack);
    auto        IsStackLower = IRB.CreateICmpULT(FrameAddrInt, LowestStack);
    auto        ThenTerm = SplitBlockAndInsertIfThen(IsStackLower, &*IP, false);
    IRBuilder<> ThenIRB(ThenTerm);
    auto        Store = ThenIRB.CreateStore(FrameAddrInt, SanCovLowestStack);
    SetNoSanitizeMetadata(LowestStack);
    SetNoSanitizeMetadata(Store);

  }

}

std::string ModuleSanitizerCoverage::getSectionName(
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

std::string ModuleSanitizerCoverage::getSectionStart(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatMachO())
    return "\1section$start$__DATA$__" + Section;
  return "__start___" + Section;

}

std::string ModuleSanitizerCoverage::getSectionEnd(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatMachO())
    return "\1section$end$__DATA$__" + Section;
  return "__stop___" + Section;

}

char ModuleSanitizerCoverageLegacyPass::ID = 0;

INITIALIZE_PASS_BEGIN(ModuleSanitizerCoverageLegacyPass, "sancov",
                      "Pass for instrumenting coverage on functions", false,
                      false)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTreeWrapperPass)
INITIALIZE_PASS_END(ModuleSanitizerCoverageLegacyPass, "sancov",
                    "Pass for instrumenting coverage on functions", false,
                    false)

ModulePass *llvm::createModuleSanitizerCoverageLegacyPassPass(
    const SanitizerCoverageOptions &Options
#if LLVM_MAJOR > 10
    ,
    const std::vector<std::string> &AllowlistFiles,
    const std::vector<std::string> &BlocklistFiles
#endif
) {

  return new ModuleSanitizerCoverageLegacyPass(Options
#if LLVM_MAJOR > 10
                                               ,
                                               AllowlistFiles, BlocklistFiles
#endif
  );

}

void registerPCGUARDPass(const PassManagerBuilder &,
                         legacy::PassManagerBase &PM) {

  auto p = new ModuleSanitizerCoverageLegacyPass();
  PM.add(p);

}

RegisterStandardPasses RegisterCompTransPass(
    PassManagerBuilder::EP_OptimizerLast, registerPCGUARDPass);

RegisterStandardPasses RegisterCompTransPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerPCGUARDPass);

