// SanitizerCoverage.cpp ported to AFL++ LTO; derived from the LLVM Project.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
/* SanitizeCoverage.cpp ported to AFL++ LTO :-) */

#define AFL_LLVM_PASS

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

#include <list>
#include <string>
#include <fstream>
#include <set>
#include <iostream>

#include "llvm/Transforms/Instrumentation/SanitizerCoverage.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#if LLVM_VERSION_MAJOR < 17
  #include "llvm/ADT/Triple.h"
  #include "llvm/Analysis/EHPersonalities.h"
#else
  #include "llvm/IR/EHPersonalities.h"
#endif
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Mangler.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/Support/raw_ostream.h"
#if LLVM_VERSION_MAJOR < 20
  #include "llvm/Transforms/Instrumentation.h"
#else
  #include "llvm/Transforms/Utils/Instrumentation.h"
#endif
#if LLVM_VERSION_MAJOR < 17
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#if defined(__has_include) && __has_include("llvm/Plugins/PassPlugin.h")
  #include "llvm/Plugins/PassPlugin.h"
#else
  #include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"

#include "config.h"
#include "debug.h"
#include "afl-llvm-common.h"
#include "PathCoverage.h"

using namespace llvm;

#define DEBUG_TYPE "sancov"

const char SanCovTracePCName[] = "__sanitizer_cov_trace_pc";
// const char SanCovTracePCGuardName =
//    "__sanitizer_cov_trace_pc_guard";
const char SanCovGuardsSectionName[] = "sancov_guards";

static cl::opt<int> ClCoverageLevel(
    "lto-coverage-level",
    cl::desc("Sanitizer Coverage. 0: none, 1: entry block, 2: all blocks, "
             "3: all blocks and critical edges"),
    cl::Hidden, cl::init(3));

static cl::opt<bool> ClTracePC("lto-coverage-trace-pc",
                               cl::desc("Experimental pc tracing"), cl::Hidden,
                               cl::init(false));

static cl::opt<bool> ClTracePCGuard("lto-coverage-trace-pc-guard",
                                    cl::desc("pc tracing with a guard"),
                                    cl::Hidden, cl::init(false));

// If true, we create a global variable that contains PCs of all instrumented
// BBs, put this global into a named section, and pass this section's bounds
// to __sanitizer_cov_pcs_init.
// This way the coverage instrumentation does not need to acquire the PCs
// at run-time. Works with trace-pc-guard, inline-8bit-counters, and
// inline-bool-flag.
static cl::opt<bool> ClCreatePCTable("lto-coverage-pc-table",
                                     cl::desc("create a static PC table"),
                                     cl::Hidden, cl::init(false));

static cl::opt<bool> ClInline8bitCounters(
    "lto-coverage-inline-8bit-counters",
    cl::desc("increments 8-bit counter for every edge"), cl::Hidden,
    cl::init(false));

static cl::opt<bool> ClInlineBoolFlag(
    "lto-coverage-inline-bool-flag",
    cl::desc("sets a boolean flag for every edge"), cl::Hidden,
    cl::init(false));

static cl::opt<bool> ClPruneBlocks(
    "lto-coverage-prune-blocks",
    cl::desc("Reduce the number of instrumented blocks"), cl::Hidden,
    cl::init(true));

namespace llvm {

void initializeModuleSanitizerCoverageLTOLegacyPassPass(PassRegistry &PB);

}

namespace {

SanitizerCoverageOptions getOptions(int LegacyCoverageLevel) {

  SanitizerCoverageOptions Res;
  switch (LegacyCoverageLevel) {

    case 0:
      Res.CoverageType = SanitizerCoverageOptions::SCK_None;
      break;
    case 1:
      Res.CoverageType = SanitizerCoverageOptions::SCK_Function;
      break;
    case 2:
      Res.CoverageType = SanitizerCoverageOptions::SCK_BB;
      break;
    case 3:
      Res.CoverageType = SanitizerCoverageOptions::SCK_Edge;
      break;
    case 4:
      Res.CoverageType = SanitizerCoverageOptions::SCK_Edge;
      Res.IndirectCalls = true;
      break;

  }

  return Res;

}

SanitizerCoverageOptions OverrideFromCL(SanitizerCoverageOptions Options) {

  // Sets CoverageType and IndirectCalls.
  SanitizerCoverageOptions CLOpts = getOptions(ClCoverageLevel);
  Options.CoverageType = std::max(Options.CoverageType, CLOpts.CoverageType);
  Options.TracePC |= ClTracePC;
  Options.TracePCGuard |= ClTracePCGuard;
  Options.NoPrune |= !ClPruneBlocks;
  if (!Options.TracePCGuard && !Options.TracePC &&
      !Options.Inline8bitCounters && !Options.InlineBoolFlag)
    Options.TracePCGuard = true;  // TracePCGuard is default.
  return Options;

}

using DomTreeCallback = function_ref<const DominatorTree *(Function &F)>;
using PostDomTreeCallback =
    function_ref<const PostDominatorTree *(Function &F)>;

class ModuleSanitizerCoverageLTO
    : public PassInfoMixin<ModuleSanitizerCoverageLTO> {

 public:
  ModuleSanitizerCoverageLTO(
      const SanitizerCoverageOptions &Options = SanitizerCoverageOptions())
      : Options(OverrideFromCL(Options)) {

  }

  bool instrumentModule(Module &M, DomTreeCallback DTCallback,
                        PostDomTreeCallback PDTCallback);

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

 private:
  void instrumentFunction(Function &F, DomTreeCallback DTCallback,
                          PostDomTreeCallback PDTCallback);
  bool InjectCoverage(Function &F, ArrayRef<BasicBlock *> AllBlocks,
                      bool IsLeafFunc = true);
  bool Fake_InjectCoverage(Function &F, ArrayRef<BasicBlock *> AllBlocks,
                           bool IsLeafFunc = true);
  GlobalVariable *CreateFunctionLocalArrayInSection(size_t    NumElements,
                                                    Function &F, Type *Ty,
                                                    const char *Section);
  void CreateFunctionLocalArrays(Function &F, ArrayRef<BasicBlock *> AllBlocks);
  void InjectCoverageAtBlock(Function &F, BasicBlock &BB, size_t Idx,
                             bool IsLeafFunc = true);

  /* Ball-Larus path coverage (AFL_LLVM_LTO_PATH).  Inserts a per-function
     path register, edge increments on non-back edges, and a bitmap write
     at every exit point.  No-op if path_mode == false or function is
     ineligible.  Returns the number of slots reserved (0 if skipped).    */
  /* Analyse the function's CFG *before* InjectCoverage mutates it (so
     isGuardOnlyBB sees the source-level BBs, not BBs polluted by edge-
     counter stores).  Stores per-function results in path* members. */
  bool     analyzePathCoverage(Function &F);
  uint64_t instrumentPathCoverage(Function &F, const DominatorTree *DT,
                                  uint32_t call_counter, LoadInst *PrevCtxLoad);

  std::string    getSectionName(const std::string &Section) const;
  FunctionCallee SanCovTracePC /*, SanCovTracePCGuard*/;
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

  // AFL++ START
  // const SpecialCaseList *          Allowlist;
  // const SpecialCaseList *          Blocklist;
  uint32_t autodictionary = 1;
  uint32_t autodictionary_no_main = 0;
  uint32_t inst = 0;
  uint32_t afl_global_id = 0;
  uint32_t unhandled = 0;
  uint32_t decision_cnt = 0;
  uint32_t instrument_ctx = 0;
  uint32_t instrument_ctx_max_depth = 0;
  uint32_t extra_ctx_inst = 0;
  bool     path_mode = false;       // Ball-Larus path
  uint32_t path_mode_level = 0;     // 1=relaxed, 2=restricted, 3=strict
  uint64_t extra_path_inst = 0;     // sum of paths
  uint32_t path_skipped_funcs = 0;  // skipped funcs
  uint64_t path_max_paths = 100000;
  /* Populated by analyzePathCoverage() before InjectCoverage runs and
     consumed by instrumentPathCoverage() afterwards.  See PathCoverage.h. */
  llvm::DenseMap<llvm::BasicBlock *, uint64_t> pathNumPaths;
  llvm::DenseMap<std::pair<llvm::BasicBlock *, llvm::BasicBlock *>, uint64_t>
                                                                  pathEdgeVal;
  std::vector<std::pair<llvm::BasicBlock *, llvm::Instruction *>> pathExits;
  uint64_t                         pathNumEntry = 0;
  uint64_t                         map_addr = 0;
  const char                      *skip_nozero = NULL;
  const char                      *use_threadsafe_counters = nullptr;
  std::vector<BasicBlock *>        BlockList;
  DenseMap<Value *, std::string *> valueMap;
  std::vector<std::string>         dictionary;
  IntegerType                     *Int8Tyi = NULL;
  IntegerType                     *Int32Tyi = NULL;
  IntegerType                     *Int64Tyi = NULL;
  ConstantInt                     *Zero = NULL;
  ConstantInt                     *Zero32 = NULL;
  ConstantInt                     *One = NULL;
  LLVMContext                     *Ct = NULL;
  Module                          *Mo = NULL;
  GlobalVariable                  *AFLContext = NULL;
  GlobalVariable                  *AFLMapPtr = NULL;
  GlobalVariable                  *AFLCovMapSize = NULL;
  GlobalVariable                  *AFLIJONState = NULL;
  const char                      *ijon_enabled = nullptr;
  Value                           *MapPtrFixed = NULL;
  Value                           *HoistedMapPtr = NULL;
  AllocaInst                      *CTX_add = NULL;
  std::ofstream                    dFile;
  size_t                           found = 0;
  bool                             deny_exec = false;
  // AFL++ END

};

class ModuleSanitizerCoverageLTOLegacyPass : public ModulePass {

 public:
  static char ID;
  StringRef   getPassName() const override {

    return "sancov-lto";

  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {

    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<PostDominatorTreeWrapperPass>();

  }

  ModuleSanitizerCoverageLTOLegacyPass(
      const SanitizerCoverageOptions &Options = SanitizerCoverageOptions())
      : ModulePass(ID), Options(Options) {

    initializeModuleSanitizerCoverageLTOLegacyPassPass(
        *PassRegistry::getPassRegistry());

  }

  bool runOnModule(Module &M) override {

    ModuleSanitizerCoverageLTO ModuleSancov(Options);
    auto DTCallback = [this](Function &F) -> const DominatorTree * {

      return &this->getAnalysis<DominatorTreeWrapperPass>(F).getDomTree();

    };

    auto PDTCallback = [this](Function &F) -> const PostDominatorTree * {

      return &this->getAnalysis<PostDominatorTreeWrapperPass>(F)
                  .getPostDomTree();

    };

    if (!getenv("AFL_LLVM_ONLY_FSRV")) {

      return ModuleSancov.instrumentModule(M, DTCallback, PDTCallback);

    } else {

      if (getenv("AFL_DEBUG")) { DEBUGF("Instrumentation disabled\n"); }
      return false;

    }

  }

 private:
  SanitizerCoverageOptions Options;

};

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "SanitizerCoverageLTO", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

#if LLVM_VERSION_MAJOR >= 15
            PB.registerFullLinkTimeOptimizationLastEPCallback(
#else
            PB.registerOptimizerLastEPCallback(
#endif
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(ModuleSanitizerCoverageLTO());

                });

          }};

}

PreservedAnalyses ModuleSanitizerCoverageLTO::run(Module                &M,
                                                  ModuleAnalysisManager &MAM) {

  ModuleSanitizerCoverageLTO ModuleSancov(Options);
  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  auto  DTCallback = [&FAM](Function &F) -> const DominatorTree  *{

    return &FAM.getResult<DominatorTreeAnalysis>(F);

  };

  auto PDTCallback = [&FAM](Function &F) -> const PostDominatorTree * {

    return &FAM.getResult<PostDominatorTreeAnalysis>(F);

  };

  if (!getenv("AFL_LLVM_ONLY_FSRV")) {

    if (ModuleSancov.instrumentModule(M, DTCallback, PDTCallback))
      return PreservedAnalyses::none();

  } else {

    if (debug) { DEBUGF("Instrumentation disabled\n"); }

  }

  return PreservedAnalyses::all();

}

bool ModuleSanitizerCoverageLTO::instrumentModule(
    Module &M, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {

  if (Options.CoverageType == SanitizerCoverageOptions::SCK_None) return false;
  /*
    if (Allowlist &&
        !Allowlist->inSection("coverage", "src", MNAME))
      return false;
    if (Blocklist &&
        Blocklist->inSection("coverage", "src", MNAME))
      return false;
  */
  BlockList.clear();
  for (auto &kv : valueMap)
    delete kv.second;
  valueMap.clear();
  dictionary.clear();
  GlobalsToAppendToUsed.clear();
  GlobalsToAppendToCompilerUsed.clear();
  C = &(M.getContext());
  DL = &M.getDataLayout();
  CurModule = &M;
  CurModuleUniqueId = getUniqueModuleId(CurModule);
  TargetTriple = Triple(M.getTargetTriple());
  FunctionGuardArray = nullptr;
  IntptrTy = Type::getIntNTy(*C, DL->getPointerSizeInBits());
  Type       *VoidTy = Type::getVoidTy(*C);
  IRBuilder<> IRB(*C);
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
  Int64Ty = IRB.getInt64Ty();
  Int32Ty = IRB.getInt32Ty();
  Int16Ty = IRB.getInt16Ty();
  Int8Ty = IRB.getInt8Ty();
  Int1Ty = IRB.getInt1Ty();

  /* AFL++ START */
  char        *ptr;
  LLVMContext &Ctx = M.getContext();
  Ct = &Ctx;
  Int8Tyi = IntegerType::getInt8Ty(Ctx);
  Int32Tyi = IntegerType::getInt32Ty(Ctx);
  Int64Tyi = IntegerType::getInt64Ty(Ctx);

  // Check if IJON state-aware coverage is enabled
  ijon_enabled = getenv("AFL_LLVM_IJON");
  if (getenv("AFL_LLVM_DENY_EXEC")) deny_exec = true;

  // If IJON is enabled, check if the module actually uses any IJON functions
  bool uses_ijon_functions = false;
  bool uses_ijon_state = false;

  if (ijon_enabled) {

    std::tie(uses_ijon_functions, uses_ijon_state) = detectIJONUsage(M);
    if (!uses_ijon_functions) { ijon_enabled = nullptr; }

  }

  // Initialize IJON symbols based on what functions are used
  if (ijon_enabled) {

    createIJONEnabledGlobal(M, Int32Ty);
    AFLIJONState = createIJONStateGlobal(M, Int32Tyi, uses_ijon_state);

  }

  /* Show a banner */
  setvbuf(stdout, NULL, _IONBF, 0);
  if (getenv("AFL_DEBUG")) { debug = 1; }
  if (getenv("AFL_LLVM_DICT2FILE_NO_MAIN")) { autodictionary_no_main = 1; }
  if (getenv("AFL_LLVM_CALLER") || getenv("AFL_LLVM_CTX") ||
      getenv("AFL_LLVM_LTO_CALLER") || getenv("AFL_LLVM_LTO_CTX")) {

    instrument_ctx = 1;

  }

  if (getenv("AFL_LLVM_LTO_CALLER_DEPTH")) {

    instrument_ctx_max_depth = atoi(getenv("AFL_LLVM_LTO_CALLER_DEPTH"));

  } else if (getenv("AFL_LLVM_LTO_CTX_DEPTH")) {

    instrument_ctx_max_depth = atoi(getenv("AFL_LLVM_LTO_CTX_DEPTH"));

  } else if (getenv("AFL_LLVM_CALLER_DEPTH")) {

    instrument_ctx_max_depth = atoi(getenv("AFL_LLVM_CALLER_DEPTH"));

  } else if (getenv("AFL_LLVM_CTX_DEPTH")) {

    instrument_ctx_max_depth = atoi(getenv("AFL_LLVM_CTX_DEPTH"));

  }

  /* AFL_LLVM_LTO_PATH (and aliases AFL_LLVM_PATH / AFL_LLVM_PATH_MODE):
     Ball-Larus per-function path coverage on top of edge coverage.
     Levels:
       (unset/"0") — disabled.
       "1" / ""    — relaxed: collapse every guard-only basic block (no
                     calls, no stores, no atomics) via max(succ) instead
                     of sum(succ).  Short-circuit `&&`/`||`, pure-condition
                     chains, and switch-on-loaded-value collapse to a
                     single decision.  Smallest map.
       "2"         — restricted: like "1" but only collapse 2-successor
                     guard-only BBs.  Switches and indirect branches
                     remain as sum-merged decisions.  Slightly larger
                     map than "1".
       "3"         — strict Ball-Larus: every IR-level acyclic path has
                     its own slot.  Largest map; matches the literal
                     "every possible path is a unique route" reading.
     Other values are rejected. */
  {

    const char *p = getenv("AFL_LLVM_LTO_PATH");
    if (!p) p = getenv("AFL_LLVM_PATH");
    if (!p) p = getenv("AFL_LLVM_PATH_MODE");
    if (p) {

      if (*p == 0) {

        /* Reject the empty value rather than silently enabling level 1 —
           users who want level 1 should pass "1". */
        FATAL(
            "AFL_LLVM_LTO_PATH/AFL_LLVM_PATH/AFL_LLVM_PATH_MODE was set to "
            "an empty value. Use \"1\" (relaxed), \"2\" (restricted), "
            "\"3\" (strict), or \"0\" (off).");

      } else if (strcmp(p, "1") == 0) {

        path_mode_level = 1;

      } else if (strcmp(p, "2") == 0) {

        path_mode_level = 2;

      } else if (strcmp(p, "3") == 0) {

        path_mode_level = 3;

      } else if (strcmp(p, "0") == 0) {

        path_mode_level = 0;

      } else {

        FATAL(
            "AFL_LLVM_LTO_PATH/AFL_LLVM_PATH/AFL_LLVM_PATH_MODE only "
            "accepts \"0\" (off), \"1\" (relaxed), \"2\" (restricted), or "
            "\"3\" (strict). Got %s.",
            p);

      }

      path_mode = (path_mode_level > 0);

    }

  }

  if (const char *mp = getenv("AFL_LLVM_PATH_MAX_PATHS")) {

    char              *end = nullptr;
    unsigned long long v = strtoull(mp, &end, 10);
    if (!end || *end || v < 2 || v > (unsigned long long)INT32_MAX) {

      /* INT32_MAX upper bound: the IR path index is held in a signed
         i32 register, so any value beyond that would let path_base +
         path_reg overflow the bitmap GEP. */
      FATAL("AFL_LLVM_PATH_MAX_PATHS must be an integer in [2, %d] (got %s).",
            INT32_MAX, mp);

    }

    path_max_paths = (uint64_t)v;

  }

  /* CTX_DEPTH > 1 + PATH would compute
       idx = path_base + path_reg + cid * NumPaths
     in i32, but `cid` is the AFLContext XOR-stack value which is *not*
     bounded by call_counter when depth > 1. The result can fall outside
     the reserved [path_base, path_base + numPaths * call_counter) range
     and either alias another function's slots or write out-of-bounds.
     Refuse the combination loudly rather than silently corrupt coverage. */
  if (path_mode && instrument_ctx_max_depth > 1) {

    FATAL(
        "AFL_LLVM_CTX_DEPTH/AFL_LLVM_CALLER_DEPTH > 1 cannot be combined "
        "with AFL_LLVM_PATH: at depth > 1 AFLContext is an XOR-stack of "
        "caller IDs and is not bounded by call_counter, so the path "
        "index math (path_base + cid * NumPaths + path) cannot stay in "
        "range. Use depth = 1 with PATH, or disable PATH.");

  }

  if ((isatty(2) && !getenv("AFL_QUIET")) || debug) {

    char        buf[160] = {};
    const char *path_label;
    switch (path_mode_level) {

      case 1:
        path_label = "PATH mode (relaxed)";
        break;
      case 2:
        path_label = "PATH mode (restricted)";
        break;
      case 3:
        path_label = "PATH mode (strict)";
        break;
      default:
        path_label = "PATH mode";
        break;

    }

    if (instrument_ctx && path_mode) {

      snprintf(buf, sizeof(buf), " (CTX mode, depth %u, %s)",
               instrument_ctx_max_depth, path_label);

    } else if (instrument_ctx) {

      snprintf(buf, sizeof(buf), " (CTX mode, depth %u)",
               instrument_ctx_max_depth);

    } else if (path_mode) {

      snprintf(buf, sizeof(buf), " (%s)", path_label);

    }

    SAYF(cCYA "afl-llvm-lto" VERSION cRST
              "%s by Marc \"vanHauser\" Heuse <mh@mh-sec.de>\n",
         buf);

  } else {

    be_quiet = 1;

  }

  skip_nozero = getenv("AFL_LLVM_SKIP_NEVERZERO");
  use_threadsafe_counters = getenv("AFL_LLVM_THREADSAFE_INST");

  if ((ptr = getenv("AFL_LLVM_LTO_STARTID")) != NULL) {

    int val = atoi(ptr);
    if (val < 0)
      FATAL("AFL_LLVM_LTO_STARTID value of \"%s\" is negative\n", ptr);
    afl_global_id = (uint32_t)val;

  }

  if (afl_global_id < 4) { afl_global_id = 4; }

  if ((ptr = getenv("AFL_LLVM_DOCUMENT_IDS")) != NULL) {

    dFile.open(ptr, std::ofstream::out | std::ofstream::app);
    if (!dFile.is_open()) WARNF("Cannot access document file %s", ptr);

  }

  // we make this the default as the fixed map has problems with
  // deferred forkserver, early constructors, ifuncs and maybe more
  map_addr = 0;

  if ((ptr = getenv("AFL_LLVM_MAP_ADDR"))) {

    uint64_t val;
    if (!*ptr || !strcmp(ptr, "0") || !strcmp(ptr, "0x0")) {

      map_addr = 0;

    } else if (strncmp(ptr, "0x", 2) != 0) {

      map_addr = 0x10000;  // the default

    } else {

      val = strtoull(ptr, NULL, 16);
      if (val < 0x100 || val > 0xffffffff00000000) {

        FATAL(
            "AFL_LLVM_MAP_ADDR must be a value between 0x100 and "
            "0xffffffff00000000");

      }

      map_addr = val;

    }

  }

  /* Get/set the globals for the SHM region. */

  if (!map_addr) {

    // may already exist: the C11 pass creates it earlier at PipelineStartEP
    AFLMapPtr = M.getGlobalVariable("__afl_area_ptr");
    if (!AFLMapPtr)
      AFLMapPtr = new GlobalVariable(
          M, PtrTy, false, GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  } else {

    ConstantInt *MapAddr = ConstantInt::get(Int64Tyi, map_addr);
    MapPtrFixed = ConstantExpr::getIntToPtr(MapAddr, PtrTy);

  }

  AFLCovMapSize =
      new GlobalVariable(M, Int32Tyi, false, GlobalValue::ExternalLinkage, 0,
                         "__afl_cov_map_size");

  AFLContext = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_ctx", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);

  Zero = ConstantInt::get(Int8Tyi, 0);
  Zero32 = ConstantInt::get(Int32Tyi, 0);
  One = ConstantInt::get(Int8Tyi, 1);

  initInstrumentList();
  scanForDangerousFunctions(&M);
  Mo = &M;

  if (autodictionary) {

    for (auto &F : M) {

      if (!isInInstrumentList(&F, MNAME) || !F.size()) { continue; }

      if (autodictionary_no_main &&
          (!F.getName().compare("main") || !F.getName().compare("_main"))) {

        continue;

      }

      for (auto &BB : F) {

        for (auto &IN : BB) {

          CallInst *callInst = nullptr;
          CmpInst  *cmpInst = nullptr;

          if ((cmpInst = dyn_cast<CmpInst>(&IN))) {

            Value       *op = cmpInst->getOperand(1);
            ConstantInt *ilen = dyn_cast<ConstantInt>(op);

            if (ilen && ilen->uge(0xffffffffffffffff) == false) {

              u64 val2 = 0, val = ilen->getZExtValue();
              u32 len = 0;
              if (val > 0x10000 && val < 0xffffffff) len = 4;
              if (val > 0x100000001 && val < 0xffffffffffffffff) len = 8;

              if (len) {

                auto c = cmpInst->getPredicate();

                switch (c) {

                  case CmpInst::FCMP_OGT:  // fall through
                  case CmpInst::FCMP_OLE:  // fall through
                  case CmpInst::ICMP_SLE:  // fall through
                  case CmpInst::ICMP_SGT:

                    // signed comparison and it is a negative constant
                    if ((len == 4 && (val & 0x80000000)) ||
                        (len == 8 && (val & 0x8000000000000000))) {

                      if ((val & 0xffff) != 1) val2 = val - 1;
                      break;

                    }

                    // fall through

                  case CmpInst::FCMP_UGT:  // fall through
                  case CmpInst::FCMP_ULE:  // fall through
                  case CmpInst::ICMP_UGT:  // fall through
                  case CmpInst::ICMP_ULE:
                    if ((val & 0xffff) != 0xfffe) val2 = val + 1;
                    break;

                  case CmpInst::FCMP_OLT:  // fall through
                  case CmpInst::FCMP_OGE:  // fall through
                  case CmpInst::ICMP_SLT:  // fall through
                  case CmpInst::ICMP_SGE:

                    // signed comparison and it is a negative constant
                    if ((len == 4 && (val & 0x80000000)) ||
                        (len == 8 && (val & 0x8000000000000000))) {

                      if ((val & 0xffff) != 1) val2 = val - 1;
                      break;

                    }

                    // fall through

                  case CmpInst::FCMP_ULT:  // fall through
                  case CmpInst::FCMP_UGE:  // fall through
                  case CmpInst::ICMP_ULT:  // fall through
                  case CmpInst::ICMP_UGE:
                    if ((val & 0xffff) != 1) val2 = val - 1;
                    break;

                  default:
                    val2 = 0;

                }

                dictionary.push_back(std::string((char *)&val, len));
                ++found;

                if (val2) {

                  dictionary.push_back(std::string((char *)&val2, len));
                  ++found;

                }

              }

            }

          }

          if ((callInst = dyn_cast<CallInst>(&IN))) {

            bool   isStrcmp = true;
            bool   isMemcmp = true;
            bool   isStrncmp = true;
            bool   isStrcasecmp = true;
            bool   isStrncasecmp = true;
            bool   isIntMemcpy = true;
            bool   isStdString = true;
            bool   isStrstr = true;
            bool   isGStrstrLen = true;
            size_t optLen = 0;

            Function *Callee = callInst->getCalledFunction();
            if (!Callee) continue;
            if (Callee->isIntrinsic()) continue;
            if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
            std::string FuncName = Callee->getName().str();

            isStrcmp &= (!FuncName.compare("strcmp") ||
                         !FuncName.compare("xmlStrcmp") ||
                         !FuncName.compare("xmlStrEqual") ||
                         !FuncName.compare("g_strcmp0") ||
                         !FuncName.compare("curl_strequal") ||
                         !FuncName.compare("strcsequal"));
            isMemcmp &=
                (!FuncName.compare("memcmp") || !FuncName.compare("bcmp") ||
                 !FuncName.compare("CRYPTO_memcmp") ||
                 !FuncName.compare("OPENSSL_memcmp") ||
                 !FuncName.compare("memcmp_const_time") ||
                 !FuncName.compare("memcmpct"));
            isStrncmp &= (!FuncName.compare("strncmp") ||
                          !FuncName.compare("xmlStrncmp") ||
                          !FuncName.compare("curl_strnequal"));
            isStrcasecmp &= (!FuncName.compare("strcasecmp") ||
                             !FuncName.compare("stricmp") ||
                             !FuncName.compare("ap_cstr_casecmp") ||
                             !FuncName.compare("OPENSSL_strcasecmp") ||
                             !FuncName.compare("xmlStrcasecmp") ||
                             !FuncName.compare("g_strcasecmp") ||
                             !FuncName.compare("g_ascii_strcasecmp") ||
                             !FuncName.compare("Curl_strcasecompare") ||
                             !FuncName.compare("Curl_safe_strcasecompare") ||
                             !FuncName.compare("cmsstrcasecmp"));
            isStrncasecmp &= (!FuncName.compare("strncasecmp") ||
                              !FuncName.compare("strnicmp") ||
                              !FuncName.compare("ap_cstr_casecmpn") ||
                              !FuncName.compare("OPENSSL_strncasecmp") ||
                              !FuncName.compare("xmlStrncasecmp") ||
                              !FuncName.compare("g_ascii_strncasecmp") ||
                              !FuncName.compare("Curl_strncasecompare") ||
                              !FuncName.compare("g_strncasecmp"));

            isIntMemcpy &= !FuncName.compare("llvm.memcpy.p0i8.p0i8.i64");
            isStdString &=
                ((FuncName.find("basic_string") != std::string::npos &&
                  FuncName.find("compare") != std::string::npos) ||
                 (FuncName.find("basic_string") != std::string::npos &&
                  FuncName.find("find") != std::string::npos));
            isStrstr &= (!FuncName.compare("strstr") ||
                         !FuncName.compare("strcasestr") ||
                         !FuncName.compare("ap_strcasestr") ||
                         !FuncName.compare("xmlStrstr") ||
                         !FuncName.compare("xmlStrcasestr"));
            isGStrstrLen &= !FuncName.compare("g_strstr_len");

            /* we do something different here, putting this BB and the
               successors in a block map */
            if (!FuncName.compare("__afl_persistent_loop")) {

              BlockList.push_back(&BB);
              for (succ_iterator SI = succ_begin(&BB), SE = succ_end(&BB);
                   SI != SE; ++SI) {

                BasicBlock *succ = *SI;
                BlockList.push_back(succ);

              }

            }

            if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
                !isStrncasecmp && !isIntMemcpy && !isStdString && !isStrstr &&
                !isGStrstrLen)
              continue;

            /* Verify the strcmp/memcmp/strncmp/strcasecmp/strncasecmp/strstr
             * function prototype */
            FunctionType *FT = Callee->getFunctionType();

            isStrcmp &= FT->getNumParams() == 2 &&
                        FT->getReturnType()->isIntegerTy(32) &&
                        FT->getParamType(0) == FT->getParamType(1) &&
#if LLVM_MAJOR >= 17
                        FT->getParamType(0)->isPointerTy();
#else
                        FT->getParamType(0) ==
                            IntegerType::getInt8Ty(M.getContext())
                                ->getPointerTo(0);
#endif
            isStrcasecmp &= FT->getNumParams() == 2 &&
                            FT->getReturnType()->isIntegerTy(32) &&
                            FT->getParamType(0) == FT->getParamType(1) &&
#if LLVM_MAJOR >= 17
                            FT->getParamType(0)->isPointerTy();
#else
                            FT->getParamType(0) ==
                                IntegerType::getInt8Ty(M.getContext())
                                    ->getPointerTo(0);
#endif
            isMemcmp &= FT->getNumParams() == 3 &&
                        FT->getReturnType()->isIntegerTy(32) &&
                        FT->getParamType(0)->isPointerTy() &&
                        FT->getParamType(1)->isPointerTy() &&
                        FT->getParamType(2)->isIntegerTy();
            isStrncmp &= FT->getNumParams() == 3 &&
                         FT->getReturnType()->isIntegerTy(32) &&
                         FT->getParamType(0) == FT->getParamType(1) &&
#if LLVM_MAJOR >= 17
                         FT->getParamType(0)->isPointerTy() &&
#else
                         FT->getParamType(0) ==
                             IntegerType::getInt8Ty(M.getContext())
                                 ->getPointerTo(0) &&
#endif
                         FT->getParamType(2)->isIntegerTy();
            isStrncasecmp &= FT->getNumParams() == 3 &&
                             FT->getReturnType()->isIntegerTy(32) &&
                             FT->getParamType(0) == FT->getParamType(1) &&
#if LLVM_MAJOR >= 17
                             FT->getParamType(0)->isPointerTy() &&
#else
                             FT->getParamType(0) ==
                                 IntegerType::getInt8Ty(M.getContext())
                                     ->getPointerTo(0) &&
#endif
                             FT->getParamType(2)->isIntegerTy();
            isStdString &= FT->getNumParams() >= 2 &&
                           FT->getParamType(0)->isPointerTy() &&
                           FT->getParamType(1)->isPointerTy();
            isStrstr &= FT->getNumParams() == 2 &&
                        FT->getReturnType()->isPointerTy() &&
                        FT->getParamType(0)->isPointerTy() &&
                        FT->getParamType(1)->isPointerTy();
            // g_strstr_len: gchar* (const gchar *haystack, gssize haystack_len,
            //                       const gchar *needle)
            isGStrstrLen &= FT->getNumParams() == 3 &&
                            FT->getReturnType()->isPointerTy() &&
                            FT->getParamType(0)->isPointerTy() &&
                            FT->getParamType(1)->isIntegerTy() &&
                            FT->getParamType(2)->isPointerTy();

            if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
                !isStrncasecmp && !isIntMemcpy && !isStdString && !isStrstr &&
                !isGStrstrLen)
              continue;

            /* is a str{n,}{case,}cmp/memcmp/strstr, check if we have
             * str{case,}cmp(x, "const") or str{case,}cmp("const", x)
             * strn{case,}cmp(x, "const", ..) or strn{case,}cmp("const", x, ..)
             * memcmp(x, "const", ..) or memcmp("const", x, ..)
             * strstr(x, "const") or g_strstr_len(x, len, "const") */
            Value *Str1P = callInst->getArgOperand(0),
                  // g_strstr_len needle is arg2; all others use arg1
                *Str2P = isGStrstrLen ? callInst->getArgOperand(2)
                                      : callInst->getArgOperand(1);
            std::string Str1, Str2;
            StringRef   TmpStr;
            bool        HasStr1 = getConstantStringInfo(Str1P, TmpStr);
            if (TmpStr.empty())
              HasStr1 = false;
            else
              Str1 = TmpStr.str();
            bool HasStr2 = getConstantStringInfo(Str2P, TmpStr);
            if (TmpStr.empty())
              HasStr2 = false;
            else
              Str2 = TmpStr.str();

            /*if (debug)
              fprintf(stderr, "F:%s %p(%s)->\"%s\"(%s) %p(%s)->\"%s\"(%s)\n",
                      FuncName.c_str(), Str1P, Str1P->getName().str().c_str(),
                      Str1.c_str(), HasStr1 == true ? "true" : "false", Str2P,
                      Str2P->getName().str().c_str(), Str2.c_str(),
                      HasStr2 == true ? "true" : "false");*/

            // we handle the 2nd parameter first because of llvm memcpy
            if (!HasStr2) {

              auto *Ptr = dyn_cast<ConstantExpr>(Str2P);
              if (Ptr && Ptr->getOpcode() == Instruction::GetElementPtr) {

                if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {

                  if (Var->hasInitializer()) {

                    if (auto *Array = dyn_cast<ConstantDataArray>(
                            Var->getInitializer())) {

                      HasStr2 = true;
                      Str2 = Array->getRawDataValues().str();

                    }

                  }

                }

              }

            }

            // for the internal memcpy routine we only care for the second
            // parameter and are not reporting anything.
            if (isIntMemcpy == true) {

              if (HasStr2 == true) {

                Value       *op2 = callInst->getArgOperand(2);
                ConstantInt *ilen = dyn_cast<ConstantInt>(op2);
                if (ilen) {

                  uint64_t literalLength = Str2.size();
                  uint64_t optLength = ilen->getZExtValue();
                  if (optLength > literalLength + 1) {

                    optLength = Str2.length() + 1;

                  }

                  if (literalLength + 1 == optLength) {

                    Str2.append("\0", 1);  // add null byte

                  }

                }

                valueMap[Str1P] = new std::string(Str2);

                if (debug)
                  fprintf(stderr, "Saved: %s for %p\n", Str2.c_str(), Str1P);
                continue;

              }

              continue;

            }

            // Neither a literal nor a global variable?
            // maybe it is a local variable that we saved
            if (!HasStr2) {

              std::string *strng = valueMap[Str2P];
              if (strng && !strng->empty()) {

                Str2 = *strng;
                HasStr2 = true;
                if (debug)
                  fprintf(stderr, "Filled2: %s for %p\n", strng->c_str(),
                          Str2P);

              }

            }

            if (!HasStr1) {

              auto Ptr = dyn_cast<ConstantExpr>(Str1P);

              if (Ptr && Ptr->getOpcode() == Instruction::GetElementPtr) {

                if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {

                  if (Var->hasInitializer()) {

                    if (auto *Array = dyn_cast<ConstantDataArray>(
                            Var->getInitializer())) {

                      HasStr1 = true;
                      Str1 = Array->getRawDataValues().str();

                    }

                  }

                }

              }

            }

            // Neither a literal nor a global variable?
            // maybe it is a local variable that we saved
            if (!HasStr1) {

              std::string *strng = valueMap[Str1P];
              if (strng && !strng->empty()) {

                Str1 = *strng;
                HasStr1 = true;
                if (debug)
                  fprintf(stderr, "Filled1: %s for %p\n", strng->c_str(),
                          Str1P);

              }

            }

            /* handle cases of one string is const, one string is variable */
            if (!(HasStr1 ^ HasStr2)) continue;

            std::string thestring;

            if (HasStr1)
              thestring = Str1;
            else
              thestring = Str2;

            optLen = thestring.length();
            if (optLen < 2 || (optLen == 2 && !thestring[1])) { continue; }

            if (isMemcmp || isStrncmp || isStrncasecmp) {

              Value       *op2 = callInst->getArgOperand(2);
              ConstantInt *ilen = dyn_cast<ConstantInt>(op2);

              if (ilen) {

                uint64_t literalLength = optLen;
                optLen = ilen->getZExtValue();
                if (optLen > thestring.length() + 1) {

                  optLen = thestring.length() + 1;

                }

                if (optLen < 2) { continue; }
                if (literalLength + 1 == optLen) {  // add null byte

                  thestring.append("\0", 1);

                }

              }

            }

            // add null byte if this is a string compare function and a null
            // was not already added
            if (!isMemcmp) {

              /*
                            if (addedNull == false && thestring[optLen - 1] !=
                 '\0') {

                              thestring.append("\0", 1);  // add null byte
                              ++optLen;

                            }

              */
              if (!isStdString &&
                  thestring.find('\0', 0) != std::string::npos) {

                // ensure we do not have garbage
                size_t offset = thestring.find('\0', 0);
                if (offset + 1 < optLen) optLen = offset + 1;
                thestring = thestring.substr(0, optLen);

              }

            }

            if (!be_quiet) {

              std::string outstring;
              fprintf(stderr, "%s: length %zu/%zu \"", FuncName.c_str(), optLen,
                      thestring.length());
              for (uint16_t i = 0; i < (uint16_t)thestring.length(); i++) {

                uint8_t c = thestring[i];
                if (c <= 32 || c >= 127)
                  fprintf(stderr, "\\x%02x", c);
                else
                  fprintf(stderr, "%c", c);

              }

              fprintf(stderr, "\"\n");

            }

            // we take the longer string, even if the compare was to a
            // shorter part. Note that depending on the optimizer of the
            // compiler this can be wrong, but it is more likely that this
            // is helping the fuzzer
            if (optLen != thestring.length()) optLen = thestring.length();
            if (optLen > MAX_AUTO_EXTRA) optLen = MAX_AUTO_EXTRA;
            if (optLen < MIN_AUTO_EXTRA)  // too short? skip
              continue;

            dictionary.push_back(thestring.substr(0, optLen));

          }

        }

      }

    }

  }

  // AFL++ END

  // Make sure smaller parameters are zero-extended to i64 as required by the
  // x86_64 ABI.
  AttributeList SanCovTraceCmpZeroExtAL;
  if (TargetTriple.getArch() == Triple::x86_64) {

    SanCovTraceCmpZeroExtAL =
        SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 0, Attribute::ZExt);
    SanCovTraceCmpZeroExtAL =
        SanCovTraceCmpZeroExtAL.addParamAttribute(*C, 1, Attribute::ZExt);

  }

  SanCovTracePC = M.getOrInsertFunction(SanCovTracePCName, VoidTy);

  // SanCovTracePCGuard =
  //    M.getOrInsertFunction(SanCovTracePCGuardName, VoidTy, Int32PtrTy);

  for (auto &F : M)
    instrumentFunction(F, DTCallback, PDTCallback);

  // AFL++ START
  if (dFile.is_open()) dFile.close();

  if (!getenv("AFL_LLVM_LTO_SKIPINIT") &&
      (!getenv("AFL_LLVM_LTO_DONTWRITEID") || dictionary.size() || map_addr)) {

    // yes we could create our own function, insert it into ctors ...
    // but this would be a pain in the butt ... so we use afl-llvm-rt-lto.o

    Function *f = M.getFunction("__afl_auto_init_globals");

    if (!f) {

      fprintf(stderr,
              "Error: init function could not be found (this should not "
              "happen)\n");
      exit(-1);

    }

    BasicBlock *bb = &f->getEntryBlock();
    if (!bb) {

      fprintf(stderr,
              "Error: init function does not have an EntryBlock (this should "
              "not happen)\n");
      exit(-1);

    }

    BasicBlock::iterator IP = bb->getFirstInsertionPt();
    IRBuilder<>          IRB(&(*IP));

    if (map_addr) {

      GlobalVariable *AFLMapAddrFixed =
          new GlobalVariable(M, Int64Tyi, false, GlobalValue::ExternalLinkage,
                             0, "__afl_map_addr");
      ConstantInt *MapAddr = ConstantInt::get(Int64Tyi, map_addr);
      StoreInst   *StoreMapAddr = IRB.CreateStore(MapAddr, AFLMapAddrFixed);
      setNoSanitizeMetadata(StoreMapAddr);

    }

    if (getenv("AFL_LLVM_LTO_DONTWRITEID") == NULL) {

      uint32_t write_loc = afl_global_id;

      write_loc = (((afl_global_id + 8) >> 3) << 3);

      // Define __afl_final_loc as a strong global with a static initializer
      // (load-time value) instead of a runtime store inside a constructor.
      // afl-compiler-rt.o has a tentative (common) definition that gets
      // overridden at link time. This guarantees the value is set before any
      // constructor runs, which matters on macOS where mod_init_func ordering
      // does not honor cross-translation-unit constructor priorities.
      ConstantInt *const_loc = ConstantInt::get(Int32Tyi, write_loc);
      new GlobalVariable(M, Int32Tyi, false, GlobalValue::ExternalLinkage,
                         const_loc, "__afl_final_loc");

    }

    if (dictionary.size()) {

      size_t memlen = 0, count = 0, offset = 0;

      // sort and unique the dictionary
      std::sort(dictionary.begin(), dictionary.end());
      auto last = std::unique(dictionary.begin(), dictionary.end());
      dictionary.erase(last, dictionary.end());

      for (auto token : dictionary) {

        memlen += token.length();
        ++count;

      }

      if (!be_quiet)
        printf("AUTODICTIONARY: %zu string%s found\n", count,
               count == 1 ? "" : "s");

      if (count) {

        auto ptrhld = std::unique_ptr<char[]>(new char[memlen + count]);

        count = 0;

        for (auto token : dictionary) {

          if (offset + token.length() < 0xfffff0 && count < MAX_AUTO_EXTRAS) {

            ptrhld.get()[offset++] = (uint8_t)token.length();
            memcpy(ptrhld.get() + offset, token.c_str(), token.length());
            offset += token.length();
            ++count;

          }

        }

        GlobalVariable *AFLDictionaryLen =
            new GlobalVariable(M, Int32Tyi, false, GlobalValue::ExternalLinkage,
                               0, "__afl_dictionary_len");
        ConstantInt *const_len = ConstantInt::get(Int32Tyi, offset);
        StoreInst *StoreDictLen = IRB.CreateStore(const_len, AFLDictionaryLen);
        setNoSanitizeMetadata(StoreDictLen);

        ArrayType *ArrayTy = ArrayType::get(IntegerType::get(Ctx, 8), offset);
        ArrayRef<char>  DictData(ptrhld.get(), offset);
        GlobalVariable *AFLInternalDictionary = new GlobalVariable(
            M, ArrayTy, true, GlobalValue::ExternalLinkage,
            ConstantDataArray::get(Ctx, DictData), "__afl_internal_dictionary");
        AFLInternalDictionary->setInitializer(
            ConstantDataArray::get(Ctx, DictData));
        AFLInternalDictionary->setConstant(true);

        GlobalVariable *AFLDictionary =
            new GlobalVariable(M, PtrTy, false, GlobalValue::ExternalLinkage, 0,
                               "__afl_dictionary");

        Value *AFLDictOff = IRB.CreateGEP(Int8Ty, AFLInternalDictionary, Zero);
        Value *AFLDictPtr = IRB.CreatePointerCast(AFLDictOff, PtrTy);
        StoreInst *StoreDict = IRB.CreateStore(AFLDictPtr, AFLDictionary);
        setNoSanitizeMetadata(StoreDict);

      }

    }

  }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst)
      WARNF("No instrumentation targets found.");
    else {

      char modeline[128];
      snprintf(modeline, sizeof(modeline), "%s%s%s%s%s%s",
               getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
               getenv("AFL_USE_ASAN") ? ", ASAN" : "",
               getenv("AFL_USE_MSAN") ? ", MSAN" : "",
               getenv("AFL_USE_TSAN") ? ", TSAN" : "",
               getenv("AFL_USE_CFISAN") ? ", CFISAN" : "",
               getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");
      char   buf[160] = {};
      char  *p = buf;
      size_t left = sizeof(buf);
      if (instrument_ctx) {

        int n = snprintf(p, left, " with %u extra map entries for CTX",
                         extra_ctx_inst);
        if (n > 0 && (size_t)n < left) {

          p += n;
          left -= n;

        }

      }

      if (path_mode) {

        int n = snprintf(p, left, " with %llu extra map entries for PATH",
                         (unsigned long long)extra_path_inst);
        if (n > 0 && (size_t)n < left) {

          p += n;
          left -= n;

        }

        if (path_skipped_funcs) {

          n = snprintf(p, left, " (%u funcs skipped)", path_skipped_funcs);
          if (n > 0 && (size_t)n < left) {

            p += n;
            left -= n;

          }

        }

      }

      OKF("Instrumented %u locations (%u branchless)%s (%s mode).", inst,
          decision_cnt, buf, modeline);

      if (getenv("AFL_LLVM_IJON")) {

        if (uses_ijon_functions) {

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

  // AFL++ END

  // We don't reference these arrays directly in any of our runtime functions,
  // so we need to prevent them from being dead stripped.
  if (TargetTriple.isOSBinFormatMachO()) appendToUsed(M, GlobalsToAppendToUsed);
  appendToCompilerUsed(M, GlobalsToAppendToCompilerUsed);
  return true;

}

// True if block has successors and it dominates all of them.
static bool isFullDominator(const BasicBlock *BB, const DominatorTree *DT) {

  if (succ_begin(BB) == succ_end(BB)) return false;

  for (const BasicBlock *SUCC : make_range(succ_begin(BB), succ_end(BB))) {

    if (!DT->dominates(BB, SUCC)) return false;

  }

  return true;

}

// True if block has predecessors and it postdominates all of them.
static bool isFullPostDominator(const BasicBlock        *BB,
                                const PostDominatorTree *PDT) {

  if (pred_begin(BB) == pred_end(BB)) return false;

  for (const BasicBlock *PRED : make_range(pred_begin(BB), pred_end(BB))) {

    if (!PDT->dominates(BB, PRED)) return false;

  }

  return true;

}

static void markPersistentLoopEdges(Function &F) {

  SmallVector<BasicBlock *, 8> edges;

  for (auto &BB : F) {

    bool calls_loop = false;
    for (auto &IN : BB) {

      CallInst *call = dyn_cast<CallInst>(&IN);
      if (!call) continue;
      Function *callee = call->getCalledFunction();
      if (callee && callee->getName() == "__afl_persistent_loop") {

        calls_loop = true;
        break;

      }

    }

    if (!calls_loop) continue;

    for (BasicBlock *succ : successors(&BB)) {

      if (succ->getSinglePredecessor() != &BB) continue;
      Instruction *term = succ->getTerminator();
      BranchInst  *br = dyn_cast<BranchInst>(term);
      if (!br || !br->isUnconditional()) continue;
      if (&*succ->getFirstNonPHIOrDbg() != term) continue;
      edges.push_back(succ);

    }

  }

  for (BasicBlock *BB : edges)
    BB->getTerminator()->setMetadata("afl.skip",
                                     MDNode::get(BB->getContext(), {}));

}

static bool shouldInstrumentBlock(const Function &F, const BasicBlock *BB,
                                  const DominatorTree            *DT,
                                  const PostDominatorTree        *PDT,
                                  const SanitizerCoverageOptions &Options) {

  if (const Instruction *term = BB->getTerminator())
    if (term->getMetadata("afl.skip")) return false;

  // Don't insert coverage for blocks containing nothing but unreachable: we
  // will never call __sanitizer_cov() for them, so counting them in
  // NumberOfInstrumentedBlocks() might complicate calculation of code coverage
  // percentage. Also, unreachable instructions frequently have no debug
  // locations.
  if (isa<UnreachableInst>(BB->getFirstNonPHIOrDbgOrLifetime())) return false;

  // Don't insert coverage into blocks without a valid insertion point
  // (catchswitch blocks).
  if (BB->getFirstInsertionPt() == BB->end()) return false;

  if (&F.getEntryBlock() != BB && isFullyArtificialBlock(BB)) return false;

  // AFL++ START
  if (!Options.NoPrune && &F.getEntryBlock() == BB && F.size() > 1)
    return false;
  // AFL++ END

  if (Options.NoPrune || &F.getEntryBlock() == BB) return true;

  if (Options.CoverageType == SanitizerCoverageOptions::SCK_Function &&
      &F.getEntryBlock() != BB)
    return false;

  // Do not instrument full dominators, or full post-dominators with multiple
  // predecessors.
  return !isFullDominator(BB, DT) &&
         !(isFullPostDominator(BB, PDT) && !BB->getSinglePredecessor());

}

/// return the number of calls to this function
u32 countCallers(Function *F) {

  u32 callers = 0;

  if (!F) { return 0; }

  for (auto *U : F->users()) {

    if (isa<CallInst>(U) || isa<InvokeInst>(U)) { ++callers; }

  }

  return callers;

}

/// return the calling function of a function - only if there is a single caller
Function *returnOnlyCaller(Function *F) {

  Function *caller = NULL;

  if (!F) { return NULL; }

  for (auto *U : F->users()) {

    if (auto *CB = dyn_cast<CallBase>(U)) {

      if (caller == NULL) {

        caller = CB->getParent()->getParent();

      } else {

        return NULL;

      }

    }

  }

  return caller;

}

void ModuleSanitizerCoverageLTO::instrumentFunction(
    Function &F, DomTreeCallback DTCallback, PostDomTreeCallback PDTCallback) {

  if (F.empty()) return;
  if (F.getName().contains(".module_ctor"))
    return;  // Should not instrument sanitizer init functions.
#if LLVM_VERSION_MAJOR >= 18
  if (F.getName().starts_with("__sanitizer_"))
#else
  if (F.getName().startswith("__sanitizer_"))
#endif
    return;  // Don't instrument __sanitizer_* callbacks.
  // Don't touch available_externally functions, their actual body is elsewhere.
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
#if LLVM_VERSION_MAJOR >= 19
  if (F.hasFnAttribute(Attribute::DisableSanitizerInstrumentation)) return;
#endif
  // if (Allowlist && !Allowlist->inSection("coverage", "fun", F.getName()))
  //  return;
  // if (Blocklist && Blocklist->inSection("coverage", "fun", F.getName()))
  // return;

  // AFL++ START
  if (!F.size()) return;

  LLVMContext &Context = F.getContext();
  MDNode      *N = MDNode::get(Context, MDString::get(Context, "nosanitize"));

  if (instrument_ctx) {

    // we have to set __afl_ctx 0 for all indirect calls in all functions, even
    // those not to be instrumented.

    // AFL++ START
    if (deny_exec) {

      FunctionCallee AbortFn = F.getParent()->getOrInsertFunction(
          "abort", AttributeList{}, Type::getVoidTy(Context));
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

      for (auto &IN : BB) {

        if (auto *Call = dyn_cast<CallInst>(&IN)) {

          if (Call->isIndirectCall()) {

            IRBuilder<> Builder(IN.getContext());
            Builder.SetInsertPoint(IN.getParent(), IN.getIterator());
            StoreInst *StoreCtx = Builder.CreateStore(Zero32, AFLContext);
            StoreCtx->setMetadata("nosanitize", N);

          }

        }

      }

    }

  }

  if (!isInInstrumentList(&F, FMNAME)) return;
  // AFL++ END

  if (Options.CoverageType >= SanitizerCoverageOptions::SCK_Edge)
    SplitAllCriticalEdges(
        F, CriticalEdgeSplittingOptions().setIgnoreUnreachableDests());

  markPersistentLoopEdges(F);

  SmallVector<Instruction *, 8> IndirCalls;
  SmallVector<BasicBlock *, 16> BlocksToInstrument;

  const DominatorTree     *DT = DTCallback(F);
  const PostDominatorTree *PDT = PDTCallback(F);
  bool                     IsLeafFunc = true;
  uint32_t                 call_counter = 0, call_depth = 0;
  uint32_t                 inst_save = inst, save_global = afl_global_id;
  uint32_t                 inst_in_this_func = 0;
  Function                *caller = NULL;
  LoadInst                *PrevCtxLoad = NULL;

  CTX_add = NULL;

  if (debug) fprintf(stderr, "Function: %s\n", F.getName().str().c_str());

  if (instrument_ctx) {

    caller = &F;
    call_counter = countCallers(caller);
    Function *callee = caller;

    if (call_counter == 1 && instrument_ctx_max_depth) {

      ++call_depth;

      // returnOnlyCaller() returns non-NULL only when callee has exactly
      // one caller, so the loop walks up the chain through single-caller
      // functions and stops at the first ancestor with !=1 callers or
      // when the depth budget is exhausted.
      while (instrument_ctx_max_depth >= call_depth &&
             (caller = returnOnlyCaller(callee)) != NULL) {

        if (debug)
          fprintf(stderr, "DEBUG: another depth: %s <- %s [%u]\n",
                  callee->getName().str().c_str(),
                  caller->getName().str().c_str(), call_depth);
        ++call_depth;
        callee = caller;

      }

      if (!caller && callee) { caller = callee; }

      // Refresh call_counter for the function we actually landed on; on
      // depth-limit exit it would otherwise still hold the previous
      // ancestor's count (always 1, which is what allowed us to keep
      // walking), causing the call_counter==1 reset below to wipe a
      // perfectly good multi-caller ancestor.
      if (caller) call_counter = countCallers(caller);

      if (debug)
        fprintf(stderr, "DEBUG: depth found: %s <- %s [count=%u, depth=%u]\n",
                caller ? caller->getName().str().c_str() : "(null)",
                F.getName().str().c_str(), call_counter, call_depth);

    }

    if (debug && call_counter < 2) {

      fprintf(stderr, "Function %s only %u (%s)\n", F.getName().str().c_str(),
              call_counter, caller->getName().str().c_str());

    }

    if (call_counter == 1) {

      call_counter = 0;
      caller = NULL;

    }

    if (debug) {

      fprintf(stderr, "DEBUG: result: Function=%s callers=%u depth=%u\n",
              F.getName().str().c_str(), call_counter, call_depth);

    }

    if (call_counter > 1) {

      // Fake instrumentation so we can count how many instrumentations there
      // will be in this function
      for (auto &BB : F) {

        for (auto &IN : BB) {

          CallInst *callInst = nullptr;

          if ((callInst = dyn_cast<CallInst>(&IN))) {

            Function *Callee = callInst->getCalledFunction();
            if (!Callee) continue;
            if (Callee->isIntrinsic()) continue;
            if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
            StringRef FuncName = Callee->getName();

            if (FuncName.compare(StringRef("__afl_coverage_interesting")))
              continue;

            ++inst;

          }

          if (!isAflCovInterestingInstruction(IN)) continue;

          if (auto *selectInst = dyn_cast<SelectInst>(&IN)) {

            Value *condition = selectInst->getCondition();
            auto   t = condition->getType();

            if (t->getTypeID() == llvm::Type::IntegerTyID) {

              inst += 2;

            } else

                if (t->getTypeID() == llvm::Type::FixedVectorTyID) {

              FixedVectorType *tt = dyn_cast<FixedVectorType>(t);
              if (tt) {

                uint32_t elements = tt->getElementCount().getFixedValue();
                inst += elements * 2;

              }

            } else

                if (t->getTypeID() == llvm::Type::ScalableVectorTyID) {

              // Scalable vectors: OR-reduce to scalar at instrumentation time
              inst += 2;

            } else

            {

              continue;

            }

          } else if (auto *icmp = dyn_cast<ICmpInst>(&IN)) {

            if (icmp->getType()->isIntegerTy(1)) inst += 2;

          } else if (auto *fcmp = dyn_cast<FCmpInst>(&IN)) {

            if (fcmp->getType()->isIntegerTy(1)) inst += 2;

          } else if (dyn_cast<AtomicCmpXchgInst>(&IN)) {

            inst += 2;

          } else if (auto *rmw = dyn_cast<AtomicRMWInst>(&IN)) {

            auto Op = rmw->getOperation();
            if (Op == AtomicRMWInst::Min || Op == AtomicRMWInst::Max ||
                Op == AtomicRMWInst::UMin || Op == AtomicRMWInst::UMax)
              inst += 2;

          }

        }

        if (shouldInstrumentBlock(F, &BB, DT, PDT, Options))
          BlocksToInstrument.push_back(&BB);

      }

      Fake_InjectCoverage(F, BlocksToInstrument, IsLeafFunc);

      if (debug)
        fprintf(stderr, "DEBUG: CTX: %u instrumentations\n", inst - inst_save);

      // we only instrument functions that have more than one instrumented block
      if (inst > inst_save + 1) {

        inst_in_this_func = inst - inst_save;
        bool done = false;

        // in rare occasions there can be multiple entry points per function
        for (auto &BB : F) {

          if (&BB == &F.getEntryBlock() && done == false) {

            // we insert a CTX value in all our callers:
            IRBuilder<> Builder(Context);
            CallInst   *CI = NULL;
            Function   *F2 = NULL;
            uint32_t    instrumented_calls = 0;

            for (auto *U : caller->users()) {

              if ((CI = dyn_cast<CallInst>(U))) {

                F2 = CI->getParent()->getParent();
                if (debug)
                  fprintf(stderr,
                          "DEBUG: CTX call insert %s [%u/%u] -> %s/%s\n",
                          F2->getName().str().c_str(), instrumented_calls + 1,
                          call_counter, caller->getName().str().c_str(),
                          F.getName().str().c_str());

                Builder.SetInsertPoint(CI);
                StoreInst *StoreCtx = Builder.CreateStore(
                    ConstantInt::get(Type::getInt32Ty(Context),
                                     instrumented_calls++),
                    AFLContext);
                StoreCtx->setMetadata("nosanitize", N);

              }

            }

            if (instrumented_calls != call_counter) {

              fprintf(stderr, "BUG! %s/%s <=> %u vs %u\n",
                      caller->getName().str().c_str(),
                      F.getName().str().c_str(), instrumented_calls,
                      call_counter);
              exit(-1);

            }

            done = true;

          }

          // in all entrypoints we have to load the CTX value
          if (&BB == &F.getEntryBlock()) {

            Value               *CTX_offset;
            BasicBlock::iterator IP = BB.getFirstInsertionPt();
            IRBuilder<>          IRB(&(*IP));

            PrevCtxLoad = IRB.CreateLoad(IRB.getInt32Ty(), AFLContext);
            PrevCtxLoad->setMetadata("nosanitize", N);

            CTX_offset = IRB.CreateMul(
                ConstantInt::get(Type::getInt32Ty(Context), inst_in_this_func),
                PrevCtxLoad, "CTXmul", false, true);

            CTX_add =
                IRB.CreateAlloca(Type::getInt32Ty(Context), nullptr, "CTX_add");
            auto nosan = IRB.CreateStore(CTX_offset, CTX_add);
            nosan->setMetadata("nosanitize", N);

            if (debug)
              fprintf(
                  stderr, "DEBUG: extra CTX instrumentations for %s: %u * %u\n",
                  F.getName().str().c_str(), inst - inst_save, call_counter);

          }

          for (auto &IN : BB) {

            // check all calls and where callee count == 1 instrument
            // our current caller_id to __afl_ctx
            if (auto callInst = dyn_cast<CallInst>(&IN)) {

              Function *Callee = callInst->getCalledFunction();
              if (!Callee) continue;
              if (Callee->isIntrinsic()) continue;
              if (countCallers(Callee) == 1) {

                if (debug)
                  fprintf(stderr, "DEBUG: %s call to %s with only one caller\n",
                          F.getName().str().c_str(),
                          Callee->getName().str().c_str());

                IRBuilder<> Builder(IN.getContext());
                Builder.SetInsertPoint(callInst);
                StoreInst *StoreCtx =
                    Builder.CreateStore(PrevCtxLoad, AFLContext);
                StoreCtx->setMetadata("nosanitize", N);

              }

            }

          }

        }

      }

    }

    inst = inst_save;

    /* if (debug)
       fprintf(stderr, "Next instrumentation (%u-%u=%u %u-%u=%u)\n", inst,
               inst_save, inst - inst_save, afl_global_id, save_global,
               afl_global_id - save_global);*/

  }

  auto applyCtxOffset = [&](IRBuilder<> &IRB, Value *V) -> Value * {

    if (!CTX_add) return V;
    LoadInst *CTX_load = IRB.CreateLoad(IRB.getInt32Ty(), CTX_add);
    setNoSanitizeMetadata(CTX_load);
    return IRB.CreateAdd(V, CTX_load);

  };

  auto markAflSkip = [&](Value *V) {

    if (auto *InstV = dyn_cast<Instruction>(V)) {

      LLVMContext &Ctx = InstV->getContext();
      InstV->setMetadata("afl.skip", MDNode::get(Ctx, {}));

    }

  };

  auto updateBitmapForResult = [&](IRBuilder<> &IRB, Value *Result,
                                   uint32_t vector_cnt) {

    Value *EffMapPtr = HoistedMapPtr;
    if (!EffMapPtr) {

      auto *L = IRB.CreateLoad(PtrTy, AFLMapPtr);
      setNoSanitizeMetadata(L);
      EffMapPtr = L;

    }

    uint32_t vector_cur = 0;

    while (1) {

      Value *MapPtrIdx = nullptr;
      Value *CoverageIndex = nullptr;

      if (!vector_cnt) {

        CoverageIndex = Result;

      } else {

        CoverageIndex = IRB.CreateExtractElement(Result, vector_cur++);

      }

      // Apply IJON state-aware coverage if enabled
      if (ijon_enabled && AFLIJONState) {

        LoadInst *IJONStateVal = IRB.CreateLoad(Int32Tyi, AFLIJONState);
        setNoSanitizeMetadata(IJONStateVal);
        Value    *XorResult = IRB.CreateXor(IJONStateVal, CoverageIndex);
        LoadInst *CovMapSize = IRB.CreateLoad(Int32Tyi, AFLCovMapSize);
        setNoSanitizeMetadata(CovMapSize);
        CoverageIndex = IRB.CreateURem(XorResult, CovMapSize);

      }

      MapPtrIdx = IRB.CreateGEP(Int8Ty, EffMapPtr, CoverageIndex);

      if (use_threadsafe_counters) {

        auto result = IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add,
                                          MapPtrIdx, One, llvm::MaybeAlign(1),
                                          llvm::AtomicOrdering::Monotonic);

        markAflSkip(result);

      } else {

        LoadInst *Counter = IRB.CreateLoad(IRB.getInt8Ty(), MapPtrIdx);
        setNoSanitizeMetadata(Counter);

        Value *Incr = IRB.CreateAdd(Counter, One);

        if (skip_nozero == NULL) {

          Incr = IRB.CreateBinaryIntrinsic(Intrinsic::umax, Incr, One);

        }

        auto nosan = IRB.CreateStore(Incr, MapPtrIdx);
        setNoSanitizeMetadata(nosan);

      }

      if (!vector_cnt || vector_cnt == vector_cur) break;

    }

  };

  /* Set up HoistedMapPtr before the select/switch instrumentation loop,
     because updateBitmapForResult uses it.  InjectCoverage (called later)
     will reuse the same value.
     hoistMapPointerLoad inserts a new entry block (preamble) — never
     instrument that block with code that uses HoistedMapPtr.
     IMPORTANT: do NOT hoist for coroutines.  This pass runs before
     CoroSplitPass.  A hoisted load that is used across suspend points gets
     spilled into the coroutine frame; in the .destroy path the frame is
     freed first and the spilled value is then read from freed memory →
     heap-use-after-free. */
  if (map_addr) {

    HoistedMapPtr = MapPtrFixed;

  } else {

    bool isCoro = false;
    for (auto &BB : F) {

      for (auto &I : BB) {

        if (auto *II = dyn_cast<IntrinsicInst>(&I)) {

          auto iid = II->getIntrinsicID();
          if (iid == Intrinsic::coro_id || iid == Intrinsic::coro_id_retcon ||
              iid == Intrinsic::coro_id_retcon_once ||
              iid == Intrinsic::coro_id_async) {

            isCoro = true;
            break;

          }

        }

      }

      if (isCoro) break;

    }

    if (!isCoro) {

      HoistedMapPtr = hoistMapPointerLoad(F, AFLMapPtr, PtrTy);

    } else {

      HoistedMapPtr = NULL;

    }

  }

  for (auto &BB : F) {

    for (auto &IN : BB) {

      if (IN.getMetadata("afl.skip")) continue;

      if (auto *callInst = dyn_cast<CallInst>(&IN)) {

        Function *Callee = callInst->getCalledFunction();
        if (!Callee) continue;
        if (Callee->isIntrinsic()) continue;
        if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
        StringRef FuncName = Callee->getName();
        if (!FuncName.compare(StringRef("dlopen")) ||
            !FuncName.compare(StringRef("_dlopen"))) {

          fprintf(stderr,
                  "WARNING: dlopen() detected. To have coverage for a library "
                  "that your target dlopen()'s this must either happen before "
                  "__AFL_INIT() or you must use AFL_PRELOAD to preload all "
                  "dlopen()'ed libraries!\n");
          continue;

        }

        if (FuncName.compare(StringRef("__afl_coverage_interesting"))) continue;

        IRBuilder<> Builder(callInst);
        Value      *val =
            applyCtxOffset(Builder, ConstantInt::get(Int32Ty, ++afl_global_id));

        callInst->setOperand(1, val);
        ++inst;

      }

      if (!isAflCovInterestingInstruction(IN)) continue;

#if 0
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
#endif

      if (auto *selectInst = dyn_cast<SelectInst>(&IN)) {

        uint32_t    vector_cnt = 0;
        Value      *condition = selectInst->getCondition();
        Value      *result = nullptr;
        auto        t = condition->getType();
        IRBuilder<> IRB(selectInst->getNextNode());

        if (t->getTypeID() == llvm::Type::IntegerTyID) {

          Value *frozen_cond = IRB.CreateFreeze(condition);
          markAflSkip(frozen_cond);
          Value *val1 =
              applyCtxOffset(IRB, ConstantInt::get(Int32Ty, ++afl_global_id));
          Value *val2 =
              applyCtxOffset(IRB, ConstantInt::get(Int32Ty, ++afl_global_id));
          result = IRB.CreateSelect(frozen_cond, val1, val2);
          inst += 2;

        } else

            if (t->getTypeID() == llvm::Type::FixedVectorTyID) {

          FixedVectorType *tt = dyn_cast<FixedVectorType>(t);
          if (tt) {

            uint32_t elements = tt->getElementCount().getFixedValue();
            vector_cnt = elements;
            inst += vector_cnt * 2;
            if (elements) {

              FixedVectorType *GuardPtr1 =
                  FixedVectorType::get(Int32Ty, elements);
              FixedVectorType *GuardPtr2 =
                  FixedVectorType::get(Int32Ty, elements);
              Value *x, *y;

              Value *val1 = applyCtxOffset(
                  IRB, ConstantInt::get(Int32Ty, ++afl_global_id));
              Value *val2 = applyCtxOffset(
                  IRB, ConstantInt::get(Int32Ty, ++afl_global_id));

              x = IRB.CreateInsertElement(GuardPtr1, val1, (uint64_t)0);
              y = IRB.CreateInsertElement(GuardPtr2, val2, (uint64_t)0);

              for (uint64_t i = 1; i < elements; i++) {

                val1 = applyCtxOffset(
                    IRB, ConstantInt::get(Int32Ty, ++afl_global_id));
                val2 = applyCtxOffset(
                    IRB, ConstantInt::get(Int32Ty, ++afl_global_id));

                x = IRB.CreateInsertElement(x, val1, i);
                y = IRB.CreateInsertElement(y, val2, i);

              }

              Value *frozen_cond = IRB.CreateFreeze(condition);
              markAflSkip(frozen_cond);
              result = IRB.CreateSelect(frozen_cond, x, y);

            }

          }

        } else

            if (t->getTypeID() == llvm::Type::ScalableVectorTyID) {

          // Scalable vectors (SVE/RISC-V V): OR-reduce to scalar i1
          // since the vector length is runtime-dependent.
          Value *frozen_cond = IRB.CreateFreeze(condition);
          markAflSkip(frozen_cond);
          Value *reduced = IRB.CreateOrReduce(frozen_cond);
          markAflSkip(reduced);
          Value *val1 =
              applyCtxOffset(IRB, ConstantInt::get(Int32Ty, ++afl_global_id));
          Value *val2 =
              applyCtxOffset(IRB, ConstantInt::get(Int32Ty, ++afl_global_id));
          result = IRB.CreateSelect(reduced, val1, val2);
          inst += 2;

        } else

        {

          ++unhandled;
          continue;

        }

        if (!result) continue;
        markAflSkip(result);
        updateBitmapForResult(IRB, result, vector_cnt);
        decision_cnt++;

      } else {

        uint32_t    vector_cnt = 0;
        Value      *result = nullptr;
        IRBuilder<> IRB(IN.getNextNode());

        if (auto *icmp = dyn_cast<ICmpInst>(&IN)) {

          if (!icmp->getType()->isIntegerTy(1)) continue;

          Value *res = IRB.CreateFreeze(icmp);
          markAflSkip(res);
          Value *val1 =
              applyCtxOffset(IRB, ConstantInt::get(Int32Ty, ++afl_global_id));
          Value *val2 =
              applyCtxOffset(IRB, ConstantInt::get(Int32Ty, ++afl_global_id));
          result = IRB.CreateSelect(res, val1, val2);
          markAflSkip(result);
          inst += 2;

        } else if (auto *fcmp = dyn_cast<FCmpInst>(&IN)) {

          if (!fcmp->getType()->isIntegerTy(1)) continue;

          Value *res = IRB.CreateFreeze(fcmp);
          markAflSkip(res);
          Value *val1 =
              applyCtxOffset(IRB, ConstantInt::get(Int32Ty, ++afl_global_id));
          Value *val2 =
              applyCtxOffset(IRB, ConstantInt::get(Int32Ty, ++afl_global_id));
          result = IRB.CreateSelect(res, val1, val2);
          markAflSkip(result);
          inst += 2;

        } else if (auto *cxchg = dyn_cast<AtomicCmpXchgInst>(&IN)) {

          Value *extracted = IRB.CreateExtractValue(cxchg, 1);
          markAflSkip(extracted);
          Value *res = IRB.CreateFreeze(extracted);
          markAflSkip(res);
          Value *val1 =
              applyCtxOffset(IRB, ConstantInt::get(Int32Ty, ++afl_global_id));
          Value *val2 =
              applyCtxOffset(IRB, ConstantInt::get(Int32Ty, ++afl_global_id));
          result = IRB.CreateSelect(res, val1, val2);
          markAflSkip(result);
          inst += 2;

        } else if (auto *rmw = dyn_cast<AtomicRMWInst>(&IN)) {

          AtomicRMWInst::BinOp Op = rmw->getOperation();
          if (Op != AtomicRMWInst::Min && Op != AtomicRMWInst::Max &&
              Op != AtomicRMWInst::UMin && Op != AtomicRMWInst::UMax)
            continue;

          Value *OldVal = rmw;  // result of atomicrmw: old value
          Value *NewVal = rmw->getValOperand();  // value passed to atomicrmw

          if (OldVal->getType() != NewVal->getType()) {

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
              Pred = CmpInst::ICMP_SLT;
              break;
            case AtomicRMWInst::Max:
              Pred = CmpInst::ICMP_SGT;
              break;
            case AtomicRMWInst::UMin:
              Pred = CmpInst::ICMP_ULT;
              break;
            case AtomicRMWInst::UMax:
              Pred = CmpInst::ICMP_UGT;
              break;
            default:
              continue;

          }

          Value *cmp = IRB.CreateICmp(Pred, NewVal, OldVal, "rmw.cov");
          markAflSkip(cmp);
          Value *res = IRB.CreateFreeze(cmp);
          markAflSkip(res);
          Value *val1 =
              applyCtxOffset(IRB, ConstantInt::get(Int32Ty, ++afl_global_id));
          Value *val2 =
              applyCtxOffset(IRB, ConstantInt::get(Int32Ty, ++afl_global_id));
          result = IRB.CreateSelect(res, val1, val2);
          markAflSkip(result);
          inst += 2;

        }

        if (!result) continue;

        markAflSkip(result);
        updateBitmapForResult(IRB, result, vector_cnt);
        decision_cnt++;

      }

    }

    if (!instrument_ctx || call_counter <= 1)
      if (shouldInstrumentBlock(F, &BB, DT, PDT, Options))
        BlocksToInstrument.push_back(&BB);

  }

  /* PATH analysis must run BEFORE InjectCoverage so that the guard-only
     classification sees the source-level CFG, not the post-instrumented
     CFG where most BBs have an edge-counter store at their head. */
  if (path_mode) { analyzePathCoverage(F); }

  InjectCoverage(F, BlocksToInstrument, IsLeafFunc);
  // InjectCoverageForIndirectCalls(F, IndirCalls);

  /*if (debug)
    fprintf(stderr, "Done instrumentation (%u-%u=%u %u-%u=%u)\n", inst,
            inst_save, inst - inst_save, afl_global_id, save_global,
            afl_global_id - save_global);*/

  if (inst_in_this_func && call_counter > 1) {

    if (inst_in_this_func != afl_global_id - save_global) {

      fprintf(
          stderr,
          "BUG! inst_in_this_func %u != afl_global_id %u - save_global %u\n",
          inst_in_this_func, afl_global_id, save_global);
      exit(-1);

    }

    uint32_t extra_ctx_inst_in_this_func =
        inst_in_this_func * (call_counter - 1);

    extra_ctx_inst += extra_ctx_inst_in_this_func;
    afl_global_id += extra_ctx_inst_in_this_func;

  }

  if (path_mode) { instrumentPathCoverage(F, DT, call_counter, PrevCtxLoad); }

}

GlobalVariable *ModuleSanitizerCoverageLTO::CreateFunctionLocalArrayInSection(
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
  Array->setAlignment(Align(DL->getTypeStoreSize(Ty).getFixedValue()));
  GlobalsToAppendToUsed.push_back(Array);
  GlobalsToAppendToCompilerUsed.push_back(Array);
  MDNode *MD = MDNode::get(F.getContext(), ValueAsMetadata::get(&F));
  Array->addMetadata(LLVMContext::MD_associated, *MD);

  return Array;

}

void ModuleSanitizerCoverageLTO::CreateFunctionLocalArrays(
    Function &F, ArrayRef<BasicBlock *> AllBlocks) {

  if (Options.TracePCGuard)
    FunctionGuardArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size(), F, Int32Ty, SanCovGuardsSectionName);

}

bool ModuleSanitizerCoverageLTO::InjectCoverage(
    Function &F, ArrayRef<BasicBlock *> AllBlocks, bool IsLeafFunc) {

  if (AllBlocks.empty()) return false;
  CreateFunctionLocalArrays(F, AllBlocks);

  for (size_t i = 0, N = AllBlocks.size(); i < N; i++) {

    // AFL++ START
    if (BlockList.size()) {

      int skip = 0;
      for (uint32_t k = 0; k < BlockList.size(); k++) {

        if (AllBlocks[i] == BlockList[k]) {

          if (debug)
            fprintf(stderr,
                    "DEBUG: Function %s skipping BB with/after __afl_loop\n",
                    F.getName().str().c_str());
          skip = 1;

        }

      }

      if (skip) continue;

    }

    // AFL++ END

    InjectCoverageAtBlock(F, *AllBlocks[i], i, IsLeafFunc);

  }

  return true;

}

bool ModuleSanitizerCoverageLTO::Fake_InjectCoverage(
    Function &F, ArrayRef<BasicBlock *> AllBlocks, bool IsLeafFunc) {

  if (AllBlocks.empty()) return false;

  for (size_t i = 0, N = AllBlocks.size(); i < N; i++) {

    if (BlockList.size()) {

      int skip = 0;
      for (uint32_t k = 0; k < BlockList.size(); k++) {

        if (AllBlocks[i] == BlockList[k]) { skip = 1; }

      }

      if (skip) continue;

    }

    ++inst;  // InjectCoverageAtBlock()

  }

  return true;

}

void ModuleSanitizerCoverageLTO::InjectCoverageAtBlock(Function   &F,
                                                       BasicBlock &BB,
                                                       size_t      Idx,
                                                       bool        IsLeafFunc) {

  BasicBlock::iterator IP = BB.getFirstInsertionPt();
  bool                 IsEntryBB = &BB == &F.getEntryBlock();

  if (IsEntryBB) {

    // Keep static allocas and llvm.localescape calls in the entry block.  Even
    // if we aren't splitting the block, it's nice for allocas to be before
    // calls.
    IP = PrepareToSplitEntryBlock(BB, IP);

  }

  IRBuilder<> IRB(&*IP);
  if (Options.TracePC) {

    IRB.CreateCall(SanCovTracePC)
        ->setCannotMerge();  // gets the PC using GET_CALLER_PC.

  }

  if (Options.TracePCGuard) {

    // AFL++ START
    ++afl_global_id;

    if (dFile.is_open()) {

      unsigned long long int moduleID =
          (((unsigned long long int)(rand() & 0xffffffff)) << 32) | getpid();
      dFile << "ModuleID=" << moduleID << " Function=" << F.getName().str()
            << " edgeID=" << afl_global_id << "\n";

    }

    /* Set the ID of the inserted basic block */

    ConstantInt *CurLoc = ConstantInt::get(Int32Tyi, afl_global_id);
    Value       *val = CurLoc;

    if (CTX_add) {

      LoadInst *CTX_load = IRB.CreateLoad(IRB.getInt32Ty(), CTX_add);
      setNoSanitizeMetadata(CTX_load);
      val = IRB.CreateAdd(CurLoc, CTX_load);

    }

    // Apply IJON state-aware coverage if enabled
    if (ijon_enabled && AFLIJONState) {

      LoadInst *IJONStateVal = IRB.CreateLoad(Int32Tyi, AFLIJONState);
      setNoSanitizeMetadata(IJONStateVal);
      // Apply IJON formula: state XOR coverage_index
      Value *XorResult = IRB.CreateXor(IJONStateVal, val);
      // Ensure result stays within map bounds to prevent buffer overruns
      LoadInst *CovMapSize = IRB.CreateLoad(Int32Tyi, AFLCovMapSize);
      setNoSanitizeMetadata(CovMapSize);
      val = IRB.CreateURem(XorResult, CovMapSize);

    }

    /* GEP into the SHM map (pointer loaded once in preamble) */

    Value *EffMapPtr = HoistedMapPtr;
    if (!EffMapPtr) {

      auto *L = IRB.CreateLoad(PtrTy, AFLMapPtr);
      setNoSanitizeMetadata(L);
      EffMapPtr = L;

    }

    Value *MapPtrIdx = IRB.CreateGEP(Int8Ty, EffMapPtr, val);

    /* Update bitmap */
    if (use_threadsafe_counters) {                                /* Atomic */

      IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
                          llvm::MaybeAlign(1), llvm::AtomicOrdering::Monotonic);

    } else {

      LoadInst *Counter = IRB.CreateLoad(IRB.getInt8Ty(), MapPtrIdx);
      setNoSanitizeMetadata(Counter);

      Value *Incr = IRB.CreateAdd(Counter, One);

      if (skip_nozero == NULL) {

        Incr = IRB.CreateBinaryIntrinsic(Intrinsic::umax, Incr, One);

      }

      auto nosan = IRB.CreateStore(Incr, MapPtrIdx);
      setNoSanitizeMetadata(nosan);

    }

    // done :)

    ++inst;
    // AFL++ END

    /*
        auto GuardPtr = IRB.CreateIntToPtr(
            IRB.CreateAdd(IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                          ConstantInt::get(IntptrTy, Idx * 4)),
            Int32PtrTy);

        IRB.CreateCall(SanCovTracePCGuard, GuardPtr)->setCannotMerge();
    */

  }

}

/* Ball-Larus path coverage — analysis phase.

   Runs BEFORE InjectCoverage(F) so isGuardOnlyBB() sees the pristine
   source-level CFG (edge-coverage stores added later would make most
   BBs ineligible for the PATH=1 collapse).  Persists the analysis
   results in per-function members consumed by instrumentPathCoverage(). */
bool ModuleSanitizerCoverageLTO::analyzePathCoverage(Function &F) {

  pathNumPaths.clear();
  pathEdgeVal.clear();
  pathExits.clear();
  pathNumEntry = 0;

  if (!path_mode || F.empty()) return false;
  if (F.hasFnAttribute(llvm::Attribute::NoSanitizeCoverage)) return false;
#if LLVM_VERSION_MAJOR >= 19
  if (F.hasFnAttribute(llvm::Attribute::DisableSanitizerInstrumentation))
    return false;
#endif
  if (!isInInstrumentList(&F, FMNAME)) return false;

  afl::PathAnalysis       PA(path_mode_level, path_max_paths);
  afl::PathAnalysisResult R = PA.analyze(F);

  if (R.overCap) {

    WARNF(
        "Function %s has too many paths (>%llu) even after simplification; "
        "skipping PATH instrumentation in this function.",
        F.getName().str().c_str(), (unsigned long long)path_max_paths);
    ++path_skipped_funcs;
    return false;

  }

  if (R.simplified) {

    WARNF(
        "Function %s simplified for PATH (multi-way branches collapsed): "
        "%llu paths.",
        F.getName().str().c_str(), (unsigned long long)R.numPaths);

  }

  if (R.numPaths == 0) return false;

  pathExits = std::move(R.exits);
  pathNumPaths = std::move(R.numPathsAtBB);
  pathEdgeVal = std::move(R.edgeValues);
  pathNumEntry = R.numPaths;
  return true;

}

/* Ball-Larus path coverage — emission phase.
   Consumes the per-function state stashed by analyzePathCoverage and
   emits IR after InjectCoverage has finished.
   - Reserves afl_global_id range (NumPaths or NumPaths * call_counter
     under CTX composition).
   - Allocates a per-function i32 path register.
   - Inserts `path_reg += edge_val` on each forward edge with edge_val != 0.
   - At every exit point writes the path id into the reserved bitmap range.
     CTX composition adds cid * NumPaths to the index. */
uint64_t ModuleSanitizerCoverageLTO::instrumentPathCoverage(
    Function &F, const DominatorTree *DT, uint32_t call_counter,
    LoadInst *PrevCtxLoad) {

  (void)DT;
  if (!path_mode) return 0;
  if (pathNumEntry == 0) return 0;  // analyzePathCoverage said skip

  LLVMContext &Ctx = F.getContext();
  IntegerType *Int32 = Type::getInt32Ty(Ctx);
  MDNode      *NoSan = MDNode::get(Ctx, MDString::get(Ctx, "nosanitize"));

  uint64_t    numEntry = pathNumEntry;
  const auto &Exits = pathExits;
  const auto &NumPaths = pathNumPaths;
  const auto &EdgeVal = pathEdgeVal;

  /* 5. Reserve afl_global_id range.  When CTX expanded this function,
     reserve NumPaths * call_counter so each (call_id, path) tuple has
     its own slot.  Otherwise reserve NumPaths.                         */
  bool     ctx_active = (call_counter > 1) && PrevCtxLoad != nullptr;
  uint64_t reservation =
      ctx_active ? numEntry * (uint64_t)call_counter : numEntry;
  /* The IR uses a signed i32 for the path index. The GEP into the
     bitmap sign-extends i32 → pointer-width, so any index >= 2^31
     becomes a large negative byte offset and writes OOB. Cap at
     INT32_MAX rather than UINT32_MAX. */
  if (reservation > (uint64_t)INT32_MAX ||
      (uint64_t)afl_global_id + reservation > (uint64_t)INT32_MAX) {

    WARNF(
        "Function %s would push afl_global_id past 2^31 "
        "(current=%u, reservation=%llu); skipping PATH instrumentation.",
        F.getName().str().c_str(), afl_global_id,
        (unsigned long long)reservation);
    ++path_skipped_funcs;
    return 0;

  }

  uint32_t path_base = afl_global_id;
  afl_global_id += (uint32_t)reservation;
  extra_path_inst += reservation;

  if (debug) {

    fprintf(stderr,
            "DEBUG: PATH function=%s paths=%llu reservation=%llu base=%u%s\n",
            F.getName().str().c_str(), (unsigned long long)numEntry,
            (unsigned long long)reservation, path_base,
            ctx_active ? " (CTX-composed)" : "");

  }

  /* 6. IR insertion: alloca path_reg + edge increments via the shared
     emitter; exit-point writes follow below (LTO-specific). */
  AllocaInst *path_reg = afl::emitPathCoverageEdges(
      F, EdgeVal,
      /*setMD=*/[&](Instruction *I) { I->setMetadata("nosanitize", NoSan); });

  /* 6c. Path-ID writes at every exit point in DAG-reachable BBs.
     E.first is the BB; E.second is the instruction to insert before. */
  for (auto &E : Exits) {

    if (!NumPaths.count(E.first)) continue;  // unreachable in DAG
    IRBuilder<> IRB(E.second);

    LoadInst *p = IRB.CreateLoad(Int32, path_reg);
    p->setMetadata("nosanitize", NoSan);

    Value *idx = IRB.CreateAdd(p, ConstantInt::get(Int32, path_base));

    if (ctx_active) {

      LoadInst *cid = IRB.CreateLoad(Int32, AFLContext);
      cid->setMetadata("nosanitize", NoSan);
      Value *ctxOff =
          IRB.CreateMul(cid, ConstantInt::get(Int32, (uint32_t)numEntry));
      idx = IRB.CreateAdd(idx, ctxOff);

    }

    /* Zero-extend to i64 before the GEP so the byte offset is unsigned —
       GEP otherwise sign-extends an i32 index and a value >= 2^31 would
       become a large negative offset. */
    Value *idx64 = IRB.CreateZExt(idx, IntegerType::getInt64Ty(Ctx));

    /* Bitmap update (mirrors InjectCoverageAtBlock, minus the CTX_add
       handling — the path index already includes the per-call offset). */
    Value *EffMapPtr = HoistedMapPtr;
    if (!EffMapPtr) {

      auto *L = IRB.CreateLoad(PtrTy, AFLMapPtr);
      L->setMetadata("nosanitize", NoSan);
      EffMapPtr = L;

    }

    Value *MapPtrIdx = IRB.CreateGEP(Int8Ty, EffMapPtr, idx64);

    if (use_threadsafe_counters) {

      IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
                          llvm::MaybeAlign(1), llvm::AtomicOrdering::Monotonic);

    } else {

      LoadInst *Counter =
          IRB.CreateLoad(IntegerType::getInt8Ty(Ctx), MapPtrIdx);
      Counter->setMetadata("nosanitize", NoSan);
      Value *Incr = IRB.CreateAdd(Counter, One);
      if (skip_nozero == NULL) {

        Incr = IRB.CreateBinaryIntrinsic(Intrinsic::umax, Incr, One);

      }

      StoreInst *st = IRB.CreateStore(Incr, MapPtrIdx);
      st->setMetadata("nosanitize", NoSan);

    }

  }

  return reservation;

}

std::string ModuleSanitizerCoverageLTO::getSectionName(
    const std::string &Section) const {

  if (TargetTriple.isOSBinFormatCOFF()) {

    return ".SCOV$GM";  // For SanCovGuardsSectionName.

  }

  if (TargetTriple.isOSBinFormatMachO()) return "__DATA,__" + Section;
  return "__" + Section;

}

char ModuleSanitizerCoverageLTOLegacyPass::ID = 0;

INITIALIZE_PASS_BEGIN(ModuleSanitizerCoverageLTOLegacyPass, "sancov-lto",
                      "Pass for instrumenting coverage on functions", false,
                      false)
INITIALIZE_PASS_DEPENDENCY(DominatorTreeWrapperPass)
INITIALIZE_PASS_DEPENDENCY(PostDominatorTreeWrapperPass)
INITIALIZE_PASS_END(ModuleSanitizerCoverageLTOLegacyPass, "sancov-lto",
                    "Pass for instrumenting coverage on functions", false,
                    false)

#if LLVM_VERSION_MAJOR < 16
static void registerLTOPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  auto p = new ModuleSanitizerCoverageLTOLegacyPass();
  PM.add(p);

}

static RegisterStandardPasses RegisterCompTransPass(
    PassManagerBuilder::EP_OptimizerLast, registerLTOPass);

static RegisterStandardPasses RegisterCompTransPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerLTOPass);

static RegisterStandardPasses RegisterCompTransPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast, registerLTOPass);
#endif

