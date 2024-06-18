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
#include "llvm/Transforms/Instrumentation.h"
#if LLVM_VERSION_MAJOR < 17
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"

#include "config.h"
#include "debug.h"
#include "afl-llvm-common.h"

using namespace llvm;

#define DEBUG_TYPE "sancov"

const char SanCovTracePCIndirName[] = "__sanitizer_cov_trace_pc_indir";
const char SanCovTracePCName[] = "__sanitizer_cov_trace_pc";
// const char SanCovTracePCGuardName =
//    "__sanitizer_cov_trace_pc_guard";
const char SanCovGuardsSectionName[] = "sancov_guards";
const char SanCovCountersSectionName[] = "sancov_cntrs";
const char SanCovBoolFlagSectionName[] = "sancov_bools";
const char SanCovPCsSectionName[] = "sancov_pcs";

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
  Options.IndirectCalls |= CLOpts.IndirectCalls;
  Options.TracePC |= ClTracePC;
  Options.TracePCGuard |= ClTracePCGuard;
  Options.Inline8bitCounters |= ClInline8bitCounters;
  Options.InlineBoolFlag |= ClInlineBoolFlag;
  Options.PCTable |= ClCreatePCTable;
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
  /*  void            InjectCoverageForIndirectCalls(Function               &F,
                                                   ArrayRef<Instruction *>
     IndirCalls);*/
  bool InjectCoverage(Function &F, ArrayRef<BasicBlock *> AllBlocks,
                      bool IsLeafFunc = true);
  bool Fake_InjectCoverage(Function &F, ArrayRef<BasicBlock *> AllBlocks,
                           bool IsLeafFunc = true);
  GlobalVariable *CreateFunctionLocalArrayInSection(size_t    NumElements,
                                                    Function &F, Type *Ty,
                                                    const char *Section);
  GlobalVariable *CreatePCArray(Function &F, ArrayRef<BasicBlock *> AllBlocks);
  void CreateFunctionLocalArrays(Function &F, ArrayRef<BasicBlock *> AllBlocks);
  void InjectCoverageAtBlock(Function &F, BasicBlock &BB, size_t Idx,
                             bool IsLeafFunc = true);
  //  std::pair<Value *, Value *> CreateSecStartEnd(Module &M, const char
  //  *Section,
  //                                                Type *Ty);

  void SetNoSanitizeMetadata(Instruction *I) {

#if LLVM_VERSION_MAJOR >= 19
    I->setNoSanitizeMetadata();
#else
    I->setMetadata(I->getModule()->getMDKindID("nosanitize"),
                   MDNode::get(*C, None));
#endif

  }

  std::string getSectionName(const std::string &Section) const;
  //  std::string    getSectionStart(const std::string &Section) const;
  //  std::string    getSectionEnd(const std::string &Section) const;
  FunctionCallee SanCovTracePCIndir;
  FunctionCallee SanCovTracePC /*, SanCovTracePCGuard*/;
  Type *IntptrTy, *IntptrPtrTy, *Int64Ty, *Int64PtrTy, *Int32Ty, *Int32PtrTy,
      *Int16Ty, *Int8Ty, *Int8PtrTy, *Int1Ty, *Int1PtrTy, *PtrTy;
  Module           *CurModule;
  std::string       CurModuleUniqueId;
  Triple            TargetTriple;
  LLVMContext      *C;
  const DataLayout *DL;

  GlobalVariable *FunctionGuardArray;        // for trace-pc-guard.
  GlobalVariable *Function8bitCounterArray;  // for inline-8bit-counters.
  GlobalVariable *FunctionBoolArray;         // for inline-bool-flag.
  GlobalVariable *FunctionPCsArray;          // for pc-table.
  SmallVector<GlobalValue *, 20> GlobalsToAppendToUsed;
  SmallVector<GlobalValue *, 20> GlobalsToAppendToCompilerUsed;

  SanitizerCoverageOptions Options;

  // AFL++ START
  // const SpecialCaseList *          Allowlist;
  // const SpecialCaseList *          Blocklist;
  uint32_t                         autodictionary = 1;
  uint32_t                         autodictionary_no_main = 0;
  uint32_t                         inst = 0;
  uint32_t                         afl_global_id = 0;
  uint32_t                         unhandled = 0;
  uint32_t                         select_cnt = 0;
  uint32_t                         instrument_ctx = 0;
  uint32_t                         instrument_ctx_max_depth = 0;
  uint32_t                         extra_ctx_inst = 0;
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
  Value                           *MapPtrFixed = NULL;
  AllocaInst                      *CTX_add = NULL;
  std::ofstream                    dFile;
  size_t                           found = 0;
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

    return ModuleSancov.instrumentModule(M, DTCallback, PDTCallback);

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

#if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
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

  if (ModuleSancov.instrumentModule(M, DTCallback, PDTCallback))
    return PreservedAnalyses::none();

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
  valueMap.clear();
  dictionary.clear();
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
  Type       *VoidTy = Type::getVoidTy(*C);
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
  PtrTy = PointerType::getUnqual(*C);

  /* AFL++ START */
  char        *ptr;
  LLVMContext &Ctx = M.getContext();
  Ct = &Ctx;
  Int8Tyi = IntegerType::getInt8Ty(Ctx);
  Int32Tyi = IntegerType::getInt32Ty(Ctx);
  Int64Tyi = IntegerType::getInt64Ty(Ctx);

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

  if ((isatty(2) && !getenv("AFL_QUIET")) || debug) {

    char buf[64] = {};
    if (instrument_ctx) {

      snprintf(buf, sizeof(buf), " (CTX mode, depth %u)\n",
               instrument_ctx_max_depth);

    }

    SAYF(cCYA "afl-llvm-lto" VERSION cRST
              "%s by Marc \"vanHauser\" Heuse <mh@mh-sec.de>\n",
         buf);

  } else {

    be_quiet = 1;

  }

  skip_nozero = getenv("AFL_LLVM_SKIP_NEVERZERO");
  use_threadsafe_counters = getenv("AFL_LLVM_THREADSAFE_INST");

  if ((ptr = getenv("AFL_LLVM_LTO_STARTID")) != NULL)
    if ((afl_global_id = atoi(ptr)) < 0)
      FATAL("AFL_LLVM_LTO_STARTID value of \"%s\" is negative\n", ptr);

  if (afl_global_id < 4) { afl_global_id = 4; }

  if ((ptr = getenv("AFL_LLVM_DOCUMENT_IDS")) != NULL) {

    dFile.open(ptr, std::ofstream::out | std::ofstream::app);
    if (!dFile.is_open()) WARNF("Cannot access document file %s", ptr);

  }

  // we make this the default as the fixed map has problems with
  // defered forkserver, early constructors, ifuncs and maybe more
  /*if (getenv("AFL_LLVM_MAP_DYNAMIC"))*/
  map_addr = 0;

  if ((ptr = getenv("AFL_LLVM_MAP_ADDR"))) {

    uint64_t val;
    if (!*ptr || !strcmp(ptr, "0") || !strcmp(ptr, "0x0")) {

      map_addr = 0;

    } else if (getenv("AFL_LLVM_MAP_DYNAMIC")) {

      FATAL(
          "AFL_LLVM_MAP_ADDR and AFL_LLVM_MAP_DYNAMIC cannot be used together");

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

    AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Tyi, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  } else {

    ConstantInt *MapAddr = ConstantInt::get(Int64Tyi, map_addr);
    MapPtrFixed =
        ConstantExpr::getIntToPtr(MapAddr, PointerType::getUnqual(Int8Tyi));

  }

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
                    if ((len == 4 && (val & 80000000)) ||
                        (len == 8 && (val & 8000000000000000))) {

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
                    if ((len == 4 && (val & 80000000)) ||
                        (len == 8 && (val & 8000000000000000))) {

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
            size_t optLen = 0;

            Function *Callee = callInst->getCalledFunction();
            if (!Callee) continue;
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
                !isStrncasecmp && !isIntMemcpy && !isStdString)
              continue;

            /* Verify the strcmp/memcmp/strncmp/strcasecmp/strncasecmp function
             * prototype */
            FunctionType *FT = Callee->getFunctionType();

            isStrcmp &=
                FT->getNumParams() == 2 &&
                FT->getReturnType()->isIntegerTy(32) &&
                FT->getParamType(0) == FT->getParamType(1) &&
                FT->getParamType(0) ==
                    IntegerType::getInt8Ty(M.getContext())->getPointerTo(0);
            isStrcasecmp &=
                FT->getNumParams() == 2 &&
                FT->getReturnType()->isIntegerTy(32) &&
                FT->getParamType(0) == FT->getParamType(1) &&
                FT->getParamType(0) ==
                    IntegerType::getInt8Ty(M.getContext())->getPointerTo(0);
            isMemcmp &= FT->getNumParams() == 3 &&
                        FT->getReturnType()->isIntegerTy(32) &&
                        FT->getParamType(0)->isPointerTy() &&
                        FT->getParamType(1)->isPointerTy() &&
                        FT->getParamType(2)->isIntegerTy();
            isStrncmp &=
                FT->getNumParams() == 3 &&
                FT->getReturnType()->isIntegerTy(32) &&
                FT->getParamType(0) == FT->getParamType(1) &&
                FT->getParamType(0) ==
                    IntegerType::getInt8Ty(M.getContext())->getPointerTo(0) &&
                FT->getParamType(2)->isIntegerTy();
            isStrncasecmp &=
                FT->getNumParams() == 3 &&
                FT->getReturnType()->isIntegerTy(32) &&
                FT->getParamType(0) == FT->getParamType(1) &&
                FT->getParamType(0) ==
                    IntegerType::getInt8Ty(M.getContext())->getPointerTo(0) &&
                FT->getParamType(2)->isIntegerTy();
            isStdString &= FT->getNumParams() >= 2 &&
                           FT->getParamType(0)->isPointerTy() &&
                           FT->getParamType(1)->isPointerTy();

            if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
                !isStrncasecmp && !isIntMemcpy && !isStdString)
              continue;

            /* is a str{n,}{case,}cmp/memcmp, check if we have
             * str{case,}cmp(x, "const") or str{case,}cmp("const", x)
             * strn{case,}cmp(x, "const", ..) or strn{case,}cmp("const", x, ..)
             * memcmp(x, "const", ..) or memcmp("const", x, ..) */
            Value *Str1P = callInst->getArgOperand(0),
                  *Str2P = callInst->getArgOperand(1);
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

  SanCovTracePCIndir =
      M.getOrInsertFunction(SanCovTracePCIndirName, VoidTy, IntptrTy);
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

      GlobalVariable *AFLMapAddrFixed = new GlobalVariable(
          M, Int64Tyi, true, GlobalValue::ExternalLinkage, 0, "__afl_map_addr");
      ConstantInt *MapAddr = ConstantInt::get(Int64Tyi, map_addr);
      StoreInst   *StoreMapAddr = IRB.CreateStore(MapAddr, AFLMapAddrFixed);
      ModuleSanitizerCoverageLTO::SetNoSanitizeMetadata(StoreMapAddr);

    }

    if (getenv("AFL_LLVM_LTO_DONTWRITEID") == NULL) {

      uint32_t write_loc = afl_global_id;

      write_loc = (((afl_global_id + 8) >> 3) << 3);

      GlobalVariable *AFLFinalLoc =
          new GlobalVariable(M, Int32Tyi, true, GlobalValue::ExternalLinkage, 0,
                             "__afl_final_loc");
      ConstantInt *const_loc = ConstantInt::get(Int32Tyi, write_loc);
      StoreInst   *StoreFinalLoc = IRB.CreateStore(const_loc, AFLFinalLoc);
      ModuleSanitizerCoverageLTO::SetNoSanitizeMetadata(StoreFinalLoc);

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
        ModuleSanitizerCoverageLTO::SetNoSanitizeMetadata(StoreDictLen);

        ArrayType *ArrayTy = ArrayType::get(IntegerType::get(Ctx, 8), offset);
        GlobalVariable *AFLInternalDictionary = new GlobalVariable(
            M, ArrayTy, true, GlobalValue::ExternalLinkage,
            ConstantDataArray::get(Ctx,
                                   *(new ArrayRef<char>(ptrhld.get(), offset))),
            "__afl_internal_dictionary");
        AFLInternalDictionary->setInitializer(ConstantDataArray::get(
            Ctx, *(new ArrayRef<char>(ptrhld.get(), offset))));
        AFLInternalDictionary->setConstant(true);

        GlobalVariable *AFLDictionary = new GlobalVariable(
            M, PointerType::get(Int8Tyi, 0), false,
            GlobalValue::ExternalLinkage, 0, "__afl_dictionary");

        Value *AFLDictOff = IRB.CreateGEP(Int8Ty, AFLInternalDictionary, Zero);
        Value *AFLDictPtr =
            IRB.CreatePointerCast(AFLDictOff, PointerType::get(Int8Tyi, 0));
        StoreInst *StoreDict = IRB.CreateStore(AFLDictPtr, AFLDictionary);
        ModuleSanitizerCoverageLTO::SetNoSanitizeMetadata(StoreDict);

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
      char buf[64] = {};
      if (instrument_ctx) {

        snprintf(buf, sizeof(buf), " with %u extra map entries for CTX",
                 extra_ctx_inst);

      }

      OKF("Instrumented %u locations (%u selects)%s (%s mode).", inst,
          select_cnt, buf, modeline);

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

    if (auto *CI = dyn_cast<CallInst>(U)) {

      ++callers;
      (void)(CI);

    }

  }

  return callers;

}

/// return the calling function of a function - only if there is a single caller
Function *returnOnlyCaller(Function *F) {

  Function *caller = NULL;

  if (!F) { return NULL; }

  for (auto *U : F->users()) {

    if (auto *CI = dyn_cast<CallInst>(U)) {

      if (caller == NULL) {

        caller = CI->getParent()->getParent();

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
  SmallVector<Instruction *, 8> IndirCalls;
  SmallVector<BasicBlock *, 16> BlocksToInstrument;

  const DominatorTree     *DT = DTCallback(F);
  const PostDominatorTree *PDT = PDTCallback(F);
  bool                     IsLeafFunc = true;
  uint32_t                 skip_next = 0;
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

      while (instrument_ctx_max_depth >= call_depth &&
             ((caller = returnOnlyCaller(callee)) || 1 == 1) &&
             (call_counter = countCallers(callee)) == 1) {

        if (debug && caller && callee)
          fprintf(stderr, "DEBUG: another depth: %s <- %s [%u]\n",
                  callee->getName().str().c_str(),
                  caller->getName().str().c_str(), call_depth);
        ++call_depth;
        callee = caller;

      }

      if (!caller && callee) {

        caller = callee;
        if (debug)
          fprintf(stderr, "DEBUG: depth found: %s <- %s [count=%u, depth=%u]\n",
                  caller->getName().str().c_str(), F.getName().str().c_str(),
                  call_counter, call_depth);

      }

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
            if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
            StringRef FuncName = Callee->getName();

            if (FuncName.compare(StringRef("__afl_coverage_interesting")))
              continue;

            ++inst;

          }

          SelectInst *selectInst = nullptr;

          if ((selectInst = dyn_cast<SelectInst>(&IN))) {

            Value *condition = selectInst->getCondition();
            auto   t = condition->getType();

            if (t->getTypeID() == llvm::Type::IntegerTyID) {

              inst += 2;

            } else

#if LLVM_VERSION_MAJOR >= 14
                if (t->getTypeID() == llvm::Type::FixedVectorTyID) {

              FixedVectorType *tt = dyn_cast<FixedVectorType>(t);
              if (tt) {

                uint32_t elements = tt->getElementCount().getFixedValue();
                inst += elements * 2;

              }

            } else

#endif
            {

              continue;

            }

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

            PrevCtxLoad = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
                IRB.getInt32Ty(),
#endif
                AFLContext);
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

  for (auto &BB : F) {

    skip_next = 0;

    /*
        uint32_t j = 0;
        fprintf(stderr, "BB %p ============================================\n",
                CTX_add);*/

    for (auto &IN : BB) {

      /*      j++;
            uint32_t           i = 1;
            std::string        errMsg;
            raw_string_ostream os(errMsg);
            IN.print(os);
            fprintf(stderr, "Next instruction, BB size now %zu: %02u %s\n",
         BB.size(), j, os.str().c_str()); for (auto &IN2 : BB) {

              std::string        errMsg2;
              raw_string_ostream os2(errMsg2);
              IN2.print(os2);
              fprintf(
                  stderr, "%s %02u: %s\n",
                  strcmp(os.str().c_str(), os2.str().c_str()) == 0 ? ">>>" : "
         ", i++, os2.str().c_str());

            }*/

      CallInst *callInst = nullptr;

      if ((callInst = dyn_cast<CallInst>(&IN))) {

        Function *Callee = callInst->getCalledFunction();
        if (!Callee) continue;
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

        Value *val = ConstantInt::get(Int32Ty, ++afl_global_id);
        if (CTX_add) {

          IRBuilder<> Builder(Context);
          LoadInst   *CTX_load = Builder.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
              Builder.getInt32Ty(),
#endif
              CTX_add);
          ModuleSanitizerCoverageLTO::SetNoSanitizeMetadata(CTX_load);
          val = Builder.CreateAdd(val, CTX_load);

        }

        callInst->setOperand(1, val);
        ++inst;

      }

      SelectInst *selectInst = nullptr;

      if ((selectInst = dyn_cast<SelectInst>(&IN))) {

        if (!skip_next) {

          // fprintf(stderr, "Select in\n");

          uint32_t    vector_cnt = 0;
          Value      *condition = selectInst->getCondition();
          Value      *result;
          auto        t = condition->getType();
          IRBuilder<> IRB(selectInst->getNextNode());

          ++select_cnt;

          if (t->getTypeID() == llvm::Type::IntegerTyID) {

            Value *val1 = ConstantInt::get(Int32Ty, ++afl_global_id);
            Value *val2 = ConstantInt::get(Int32Ty, ++afl_global_id);
            if (CTX_add) {

              LoadInst *CTX_load = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
                  IRB.getInt32Ty(),
#endif
                  CTX_add);
              val1 = IRB.CreateAdd(val1, CTX_load);
              val2 = IRB.CreateAdd(val2, CTX_load);

            }

            result = IRB.CreateSelect(condition, val1, val2);
            skip_next = 1;
            inst += 2;

          } else

#if LLVM_VERSION_MAJOR >= 14
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

                Value *val1 = ConstantInt::get(Int32Ty, ++afl_global_id);
                Value *val2 = ConstantInt::get(Int32Ty, ++afl_global_id);
                if (CTX_add) {

                  LoadInst *CTX_load = IRB.CreateLoad(
  #if LLVM_VERSION_MAJOR >= 14
                      IRB.getInt32Ty(),
  #endif
                      CTX_add);
                  val1 = IRB.CreateAdd(val1, CTX_load);
                  val2 = IRB.CreateAdd(val2, CTX_load);

                }

                x = IRB.CreateInsertElement(GuardPtr1, val1, (uint64_t)0);
                y = IRB.CreateInsertElement(GuardPtr2, val2, (uint64_t)0);

                for (uint64_t i = 1; i < elements; i++) {

                  val1 = ConstantInt::get(Int32Ty, ++afl_global_id);
                  val2 = ConstantInt::get(Int32Ty, ++afl_global_id);
                  /*if (CTX_add) { // already loaded I guess

                    LoadInst *CTX_load = IRB.CreateLoad(
    #if LLVM_VERSION_MAJOR >= 14
                        IRB.getInt32Ty(),
    #endif
                        CTX_add);
                    val1 = IRB.CreateAdd(val1, CTX_load);
                    val2 = IRB.CreateAdd(val2, CTX_load);

                  }*/

                  x = IRB.CreateInsertElement(GuardPtr1, val1, i);
                  y = IRB.CreateInsertElement(GuardPtr2, val2, i);

                }

                result = IRB.CreateSelect(condition, x, y);
                skip_next = 1;

              }

            }

          } else

#endif
          {

            ++unhandled;
            continue;

          }

          uint32_t vector_cur = 0;
          /* Load SHM pointer */
          LoadInst *MapPtr =
              IRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr);
          ModuleSanitizerCoverageLTO::SetNoSanitizeMetadata(MapPtr);

          while (1) {

            /* Get CurLoc */
            Value *MapPtrIdx = nullptr;

            /* Load counter for CurLoc */
            if (!vector_cnt) {

              MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, result);

            } else {

              auto element = IRB.CreateExtractElement(result, vector_cur++);
              MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, element);

            }

            if (use_threadsafe_counters) {

              IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx,
                                  One,
#if LLVM_VERSION_MAJOR >= 13
                                  llvm::MaybeAlign(1),
#endif
                                  llvm::AtomicOrdering::Monotonic);

            } else {

              LoadInst *Counter = IRB.CreateLoad(IRB.getInt8Ty(), MapPtrIdx);
              ModuleSanitizerCoverageLTO::SetNoSanitizeMetadata(Counter);

              /* Update bitmap */

              Value *Incr = IRB.CreateAdd(Counter, One);

              if (skip_nozero == NULL) {

                auto cf = IRB.CreateICmpEQ(Incr, Zero);
                auto carry = IRB.CreateZExt(cf, Int8Ty);
                Incr = IRB.CreateAdd(Incr, carry);

              }

              auto nosan = IRB.CreateStore(Incr, MapPtrIdx);
              ModuleSanitizerCoverageLTO::SetNoSanitizeMetadata(nosan);

            }

            if (!vector_cnt || vector_cnt == vector_cur) { break; }

          }

          skip_next = 1;
          // fprintf(stderr, "Select out\n");

        } else {

          // fprintf(stderr, "Select skip\n");
          skip_next = 0;

        }

      }

    }

    if (!instrument_ctx)
      if (shouldInstrumentBlock(F, &BB, DT, PDT, Options))
        BlocksToInstrument.push_back(&BB);

    /*
        for (auto &Inst : BB) {

          if (Options.IndirectCalls) {

            CallBase *CB = dyn_cast<CallBase>(&Inst);
            if (CB && !CB->getCalledFunction()) IndirCalls.push_back(&Inst);

          }

        }*/

  }

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

    extra_ctx_inst += inst_in_this_func * (call_counter - 1);
    afl_global_id += extra_ctx_inst;

  }

}

GlobalVariable *ModuleSanitizerCoverageLTO::CreateFunctionLocalArrayInSection(
    size_t NumElements, Function &F, Type *Ty, const char *Section) {

  ArrayType *ArrayTy = ArrayType::get(Ty, NumElements);
  auto       Array = new GlobalVariable(
      *CurModule, ArrayTy, false, GlobalVariable::PrivateLinkage,
      Constant::getNullValue(ArrayTy), "__sancov_gen_");

#if LLVM_VERSION_MAJOR >= 13
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
  Array->setAlignment(Align(DL->getTypeStoreSize(Ty).getFixedValue()));
  GlobalsToAppendToUsed.push_back(Array);
  GlobalsToAppendToCompilerUsed.push_back(Array);
  MDNode *MD = MDNode::get(F.getContext(), ValueAsMetadata::get(&F));
  Array->addMetadata(LLVMContext::MD_associated, *MD);

  return Array;

}

GlobalVariable *ModuleSanitizerCoverageLTO::CreatePCArray(
    Function &F, ArrayRef<BasicBlock *> AllBlocks) {

  size_t N = AllBlocks.size();
  assert(N);
  SmallVector<Constant *, 32> PCs;
  IRBuilder<>                 IRB(&*F.getEntryBlock().getFirstInsertionPt());
  for (size_t i = 0; i < N; i++) {

    if (&F.getEntryBlock() == AllBlocks[i]) {

      PCs.push_back((Constant *)IRB.CreatePointerCast(&F, PtrTy));
      PCs.push_back(
          (Constant *)IRB.CreateIntToPtr(ConstantInt::get(IntptrTy, 1), PtrTy));

    } else {

      PCs.push_back((Constant *)IRB.CreatePointerCast(
          BlockAddress::get(AllBlocks[i]), PtrTy));
#if LLVM_VERSION_MAJOR >= 16
      PCs.push_back(Constant::getNullValue(PtrTy));
#else
      PCs.push_back(
          (Constant *)IRB.CreateIntToPtr(ConstantInt::get(IntptrTy, 0), PtrTy));
#endif

    }

  }

  auto *PCArray = CreateFunctionLocalArrayInSection(N * 2, F, IntptrPtrTy,
                                                    SanCovPCsSectionName);
  PCArray->setInitializer(
      ConstantArray::get(ArrayType::get(IntptrPtrTy, N * 2), PCs));
  PCArray->setConstant(true);

  return PCArray;

}

void ModuleSanitizerCoverageLTO::CreateFunctionLocalArrays(
    Function &F, ArrayRef<BasicBlock *> AllBlocks) {

  if (Options.TracePCGuard)
    FunctionGuardArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size(), F, Int32Ty, SanCovGuardsSectionName);
  if (Options.Inline8bitCounters)
    Function8bitCounterArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size(), F, Int8Ty, SanCovCountersSectionName);
  if (Options.InlineBoolFlag)
    FunctionBoolArray = CreateFunctionLocalArrayInSection(
        AllBlocks.size(), F, Int1Ty, SanCovBoolFlagSectionName);
  if (Options.PCTable) FunctionPCsArray = CreatePCArray(F, AllBlocks);

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

// On every indirect call we call a run-time function
// __sanitizer_cov_indir_call* with two parameters:
//   - callee address,
//   - global cache array that contains CacheSize pointers (zero-initialized).
//     The cache is used to speed up recording the caller-callee pairs.
// The address of the caller is passed implicitly via caller PC.
// CacheSize is encoded in the name of the run-time function.
/*
void ModuleSanitizerCoverageLTO::InjectCoverageForIndirectCalls(
    Function &F, ArrayRef<Instruction *> IndirCalls) {

  if (IndirCalls.empty()) return;
  assert(Options.TracePC || Options.TracePCGuard ||
         Options.Inline8bitCounters || Options.InlineBoolFlag);
  for (auto I : IndirCalls) {

    IRBuilder<> IRB(I);
    CallBase   &CB = cast<CallBase>(*I);
    Value      *Callee = CB.getCalledOperand();
    if (isa<InlineAsm>(Callee)) continue;
    IRB.CreateCall(SanCovTracePCIndir, IRB.CreatePointerCast(Callee, IntptrTy));

  }

}

*/

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
#if LLVM_VERSION_MAJOR >= 12
        ->setCannotMerge();  // gets the PC using GET_CALLER_PC.
#else
        ->cannotMerge();  // gets the PC using GET_CALLER_PC.
#endif

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

      LoadInst *CTX_load = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
          IRB.getInt32Ty(),
#endif
          CTX_add);
      ModuleSanitizerCoverageLTO::SetNoSanitizeMetadata(CTX_load);
      val = IRB.CreateAdd(CurLoc, CTX_load);

    }

    /* Load SHM pointer */

    Value *MapPtrIdx;

    if (map_addr) {

      MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtrFixed, val);

    } else {

      LoadInst *MapPtr = IRB.CreateLoad(PointerType::get(Int8Ty, 0), AFLMapPtr);
      ModuleSanitizerCoverageLTO::SetNoSanitizeMetadata(MapPtr);
      MapPtrIdx = IRB.CreateGEP(Int8Ty, MapPtr, val);

    }

    /* Update bitmap */
    if (use_threadsafe_counters) {                                /* Atomic */

      IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Add, MapPtrIdx, One,
#if LLVM_VERSION_MAJOR >= 13
                          llvm::MaybeAlign(1),
#endif
                          llvm::AtomicOrdering::Monotonic);

    } else {

      LoadInst *Counter = IRB.CreateLoad(IRB.getInt8Ty(), MapPtrIdx);
      ModuleSanitizerCoverageLTO::SetNoSanitizeMetadata(Counter);

      Value *Incr = IRB.CreateAdd(Counter, One);

      if (skip_nozero == NULL) {

        auto cf = IRB.CreateICmpEQ(Incr, Zero);
        auto carry = IRB.CreateZExt(cf, Int8Tyi);
        Incr = IRB.CreateAdd(Incr, carry);

      }

      auto nosan = IRB.CreateStore(Incr, MapPtrIdx);
      ModuleSanitizerCoverageLTO::SetNoSanitizeMetadata(nosan);

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

}

std::string ModuleSanitizerCoverageLTO::getSectionName(
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

  #if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterCompTransPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast, registerLTOPass);
  #endif
#endif

