/*
   american fuzzy lop++ - LLVM bug-finding instrumentation pass
   ------------------------------------------------------------

   Originally based on AFL by Michal "lcamtuf" Zalewski.
   Now maintained by the AFLplusplus project.

   Copyright 2024-2026 AFLplusplus Project. All rights reserved.

   This file is part of AFL++ and, unlike the original Apache-2.0 source files,
   is licensed under the GNU Affero General Public License as published by the
   Free Software Foundation, either version 3 of the License, or (at your
   option) any later version.

   AFL++ is distributed in the hope that it will be useful, but WITHOUT ANY
   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
   FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
   details: https://www.gnu.org/licenses/agpl-3.0.html

   A commercial license is available for organizations that cannot use the
   AGPL; see LICENSE.COMMERCIAL.

   SPDX-License-Identifier: AGPL-3.0-or-later

 */

// instrumentation/afl-llvm-bug-pass.so.cc
//
// AFL++ bug-finding pass: implements five independent oracles plus
// ALLOCSIZE_DERIVE CmpLog assistance, each gated by its own
// AFL_LLVM_BUG_<NAME>=1 (or all together with AFL_LLVM_BUG=1):
//   - SCALAR   : max-value-per-arithmetic-site coverage + loop iter counts
//   - BUDGET   : ptr += func() write-extent contract
//   - SIZEFILL : NULL-means-size idiom self-consistency
//   - SLACK    : |op0 - op1| per icmp site, fed as inverse-bucket MAX
//   - ALLOCSIZE: malloc/free rewrite + per-store OOB oracle
//
// Important: This ignores a ALLOW/DENY list, because for some bug analysis
// this would break tracking!
//
// Modeled on cmplog-instructions-pass.cc.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <set>
#include <vector>

#include "llvm/Config/llvm-config.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Support/raw_ostream.h"
#if defined(__has_include) && __has_include("llvm/Plugins/PassPlugin.h")
  #include "llvm/Plugins/PassPlugin.h"
#else
  #include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/PassManager.h"

#include "afl-llvm-common.h"
#include "../include/bug-pass.h"

using namespace llvm;

namespace {

struct BugPassConfig {

  bool scalar = false;
  bool budget = false;
  bool sizefill = false;
  bool allocsize = false;
  bool slack = false;
  bool derive = false;
  // Stack-alloca tracking under ALLOCSIZE. Default on; opt out with
  // AFL_LLVM_BUG_ALLOCSIZE_STACK=0. Only active when `allocsize` is also true.
  bool allocsize_stack = true;
  // Opt-in: restricts SCALAR to BinaryOperators that flow into a memory-
  // size sink. Off by default — turning it on improves signal-to-noise
  // on huge targets but silences pure-compute accumulator patterns
  // (libwebp-style `total_size += table_size` works either way because
  // total_size feeds a malloc, but hash-builders, counters, and
  // non-memory sums are filtered out).
  bool                     scalar_slice = false;
  std::vector<std::string> custom_alloc_funcs;
  std::vector<std::string> custom_free_funcs;
  bool                     any() const {

    return scalar || budget || sizefill || allocsize || slack || derive;

  }

};

static BugPassConfig parseEnv() {

  BugPassConfig c;
  if (const char *all = getenv(AFL_BUG_ENV_ALL)) {

    if (*all && strcmp(all, "0") != 0) {

      c.scalar = c.budget = c.sizefill = c.allocsize = c.slack = true;
      c.derive = true;

    }

  }

  if (getenv(AFL_BUG_ENV_SCALAR)) c.scalar = true;
  if (getenv(AFL_BUG_ENV_BUDGET)) c.budget = true;
  if (getenv(AFL_BUG_ENV_SIZEFILL)) c.sizefill = true;
  if (getenv(AFL_BUG_ENV_ALLOCSIZE)) c.allocsize = true;
  if (getenv(AFL_BUG_ENV_SLACK)) c.slack = true;
  if (getenv(AFL_BUG_ENV_ALLOCSIZE_DERIVE)) {

    c.derive = true;
    c.allocsize = true;

  }

  // Stack-alloca tracking: default on; user disables with explicit "0".
  // Any other value (including empty string) keeps the default.
  if (const char *v = getenv(AFL_BUG_ENV_ALLOCSIZE_STACK)) {

    if (strcmp(v, "0") == 0) c.allocsize_stack = false;

  }

  // Slice filter is purely additive on top of SCALAR — it's a no-op
  // unless SCALAR is also enabled.
  if (getenv(AFL_BUG_ENV_SCALAR_SLICE)) {

    /* The slice filter is purely additive on top of SCALAR — it would
       be a no-op on its own.  Setting the env implies SCALAR. */
    c.scalar_slice = true;
    c.scalar = true;

  }

  if (const char *list = getenv(AFL_BUG_ENV_ALLOCSIZE_FUNCS)) {

    c.allocsize = true;
    std::string s(list);
    size_t      i = 0;
    while (i < s.size()) {

      size_t j = s.find_first_of(",;: ", i);
      if (j == std::string::npos) j = s.size();
      if (j > i) c.custom_alloc_funcs.emplace_back(s.substr(i, j - i));
      i = j + 1;

    }

  }

  if (const char *list = getenv(AFL_BUG_ENV_ALLOCSIZE_FREE_FUNCS)) {

    c.allocsize = true;
    std::string s(list);
    size_t      i = 0;
    while (i < s.size()) {

      size_t j = s.find_first_of(",;: ", i);
      if (j == std::string::npos) j = s.size();
      if (j > i) c.custom_free_funcs.emplace_back(s.substr(i, j - i));
      i = j + 1;

    }

  }

  return c;

}

// Per-module state shared by optional mode helpers. Held in BugPass (not file
// scope) so Function* keys can't dangle across modules. Cleared at the start
// of every BugPass::run().
struct BugPassState {

  bool scalar_slice = false;
  // Shared set populated from AFL_LLVM_BUG_ALLOCSIZE_FUNCS. Used by
  // ALLOCSIZE (registers them), SIZEFILL (recovers buffer size from
  // the call's size arg), and SCALAR_SLICE (treats their size args as
  // sinks).
  std::set<std::string> custom_allocs;

};

class BugPass : public PassInfoMixin<BugPass> {

 public:
  BugPass() {

    initInstrumentList();

  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

 private:
  BugPassState state_;

};

// Forward decls.
bool runScalarMode(Module &M, ModuleAnalysisManager &MAM, BugPassState &S);
bool runBudgetMode(Module &M, ModuleAnalysisManager &MAM,
                   bool out_param_enabled);
bool runSizefillMode(Module &M, ModuleAnalysisManager &MAM,
                     const BugPassState &S);
bool runSlackMode(Module &M, ModuleAnalysisManager &MAM, const BugPassState &S);
bool runAllocSizeMode(Module &M, ModuleAnalysisManager &MAM,
                      const std::vector<std::string> &custom,
                      const std::vector<std::string> &custom_free,
                      bool                            stack_enabled);
static bool     ptrStoreReachesArg(StoreInst                *S,
                                   const std::set<unsigned> &arg_indices);
static unsigned instrumentArgReachingStores(
    Function &F, FunctionCallee hook, const std::set<unsigned> &arg_indices,
    Type *PtrTy, IntegerType *I32, const DataLayout &DL, bool libc_exact_only);
static void inheritDebugLoc(IRBuilder<> &B, Instruction *Source);

// Mode salts for siteSlotId() — fed into the hash so the same site index
// in different modes lands in different map slots (a SLACK id-0 site
// would otherwise share its slot with SCALAR id-0 and they'd MAX over
// each other unpredictably).
enum : uint32_t {

  BUG_MODE_SALT_SCALAR_ARITH = 0x53415243u,  // 'SARC'
  BUG_MODE_SALT_SCALAR_LOOP = 0x534C4F50u,   // 'SLOP'
  BUG_MODE_SALT_SLACK = 0x534C434Bu,         // 'SLCK'

};

// FNV-1a-style hash producing a slot index in [0, MAP_SIZE_BUG_ENTRIES).
// Hashes (function name, site index, mode salt) so that a single mod-
// space collision pattern across sites can't pile up on the same slot,
// and so that the same site index across functions/modes lands
// elsewhere. Stable across builds of the same function — no PRNG.
//
// The bug map is shared MAX-rule between SCALAR/loop (max-channel
// semantics) and SLACK (inverse-bucket MIN-disguised-as-max).  Without
// partitioning, a collision lets the larger of (scalar_value,
// INV(slack)) win and the two channels overwrite each other silently.
// Partition the slot space: SCALAR/loop in the lower half, SLACK in the
// upper half.  Halves the per-channel capacity but eliminates cross-
// channel collisions.  ALLOCSIZE's runtime-side hash still maps over
// the full map and can collide with either half — separate concern.
static uint32_t siteSlotId(StringRef func_name, uint32_t site_idx,
                           uint32_t mode_salt) {

  uint32_t h = 0x811c9dc5u;  // FNV offset basis
  for (char c : func_name) {

    h ^= (uint8_t)c;
    h *= 0x01000193u;  // FNV prime

  }

  h ^= site_idx;
  h *= 0x01000193u;
  h ^= mode_salt;
  h *= 0x01000193u;
  // Mix once more — small inputs (short names, low ids) otherwise leave
  // the upper bits poorly distributed for a tiny mask.
  h ^= h >> 16;

  constexpr uint32_t half = MAP_SIZE_BUG_ENTRIES / 2;
  if (mode_salt == BUG_MODE_SALT_SLACK) {

    return half + (h & (half - 1));  // upper half

  }

  return h & (half - 1);  // lower half (scalar + loop)

}

static Type *pointerTyTo(LLVMContext &C, Type *ElemTy) {

#if LLVM_MAJOR >= 20
  (void)ElemTy;
  return PointerType::getUnqual(C);
#else
  return PointerType::getUnqual(ElemTy);
#endif

}

// BasicBlock::getFirstNonPHI() returning Instruction* is deprecated in
// LLVM 18+ and removed in LLVM 22+; getFirstNonPHIIt() returns an
// iterator instead.  Wrap once so call sites stay short.
static inline Instruction *firstNonPHI(BasicBlock *BB) {

#if LLVM_MAJOR >= 20
  return &*BB->getFirstNonPHIIt();
#else
  return BB->getFirstNonPHI();
#endif

}

static Value *castToPtrTy(IRBuilder<> &B, Value *V, Type *PtrTy) {

  if (!V || V->getType() == PtrTy) return V;
  return B.CreateBitOrPointerCast(V, PtrTy);

}

// Bug-pass runtime hooks never throw and always return.  Mark hook
// declarations nounwind (so EH machinery doesn't grow phantom unwind
// edges at every instrumented store) and willreturn (so the optimizer
// can keep reasoning about side-effects).
static void markBugHookAttrs(FunctionCallee FC) {

  if (!FC.getCallee()) return;
  auto *F = dyn_cast<Function>(FC.getCallee()->stripPointerCasts());
  if (!F) return;
  F->addFnAttr(Attribute::NoUnwind);
  F->addFnAttr(Attribute::WillReturn);

}

static void emitBugModeGlobal(Module &M, const BugPassConfig &cfg) {

  uint32_t mode = 0;
  if (cfg.scalar) mode |= AFL_BUG_MODE_SCALAR;
  if (cfg.budget) mode |= AFL_BUG_MODE_BUDGET;
  if (cfg.sizefill) mode |= AFL_BUG_MODE_SIZEFILL;
  if (cfg.allocsize) mode |= AFL_BUG_MODE_ALLOCSIZE;
  if (cfg.slack) mode |= AFL_BUG_MODE_SLACK;
  if (cfg.derive) mode |= AFL_BUG_MODE_DERIVE;

  LLVMContext    &C = M.getContext();
  auto           *I32 = IntegerType::getInt32Ty(C);
  auto           *Existing = M.getGlobalVariable("__afl_bug_mode");
  GlobalVariable *ModeGlobal = nullptr;
  if (Existing) {

    if (Existing->hasInitializer()) {

      if (auto *Old = dyn_cast<ConstantInt>(Existing->getInitializer()))
        mode |= (uint32_t)Old->getZExtValue();

    }

    Existing->setConstant(false);
    Existing->setLinkage(GlobalValue::WeakAnyLinkage);
    Existing->setInitializer(ConstantInt::get(I32, mode));
    ModeGlobal = Existing;

  } else {

    ModeGlobal =
        new GlobalVariable(M, I32, false, GlobalValue::WeakAnyLinkage,
                           ConstantInt::get(I32, mode), "__afl_bug_mode");
    ModeGlobal->setVisibility(GlobalValue::DefaultVisibility);

  }

  if (!mode) return;

  // Do not rely on weak data coalescing to preserve the non-zero mode
  // initializer: on Mach-O the runtime's weak zero definition can win.
  // A priority-1 constructor runs before the pass-added sancov constructor
  // in the same translation unit and ORs this TU's bits into the final
  // runtime variable. Multiple instrumented TUs compose naturally.
  FunctionType *FT = FunctionType::get(Type::getVoidTy(C), false);
  Function     *Ctor = Function::Create(FT, GlobalValue::InternalLinkage,
                                        "__afl_bug_mode_ctor", M);
  BasicBlock   *BB = BasicBlock::Create(C, "entry", Ctor);
  IRBuilder<>   B(BB);
  Value        *Old = B.CreateLoad(I32, ModeGlobal);
  Value        *New = B.CreateOr(Old, ConstantInt::get(I32, mode));
  B.CreateStore(New, ModeGlobal);
  B.CreateRetVoid();
  appendToGlobalCtors(M, Ctor, 1);

}

// Return a safe insertion point for instrumentation that consumes a call's
// result after normal completion. For invokes whose normal destination has
// other predecessors, split the normal edge so the invoke result dominates
// the inserted hook and PHI incoming blocks stay valid.
static Instruction *postCallInsertionPoint(CallBase *CB, LLVMContext &C,
                                           const Twine &Suffix) {

  if (auto *CI = dyn_cast<CallInst>(CB)) return CI->getNextNode();

  auto *II = dyn_cast<InvokeInst>(CB);
  if (!II) return nullptr;

  BasicBlock *Parent = II->getParent();
  BasicBlock *NormalDest = II->getNormalDest();
  if (NormalDest->getUniquePredecessor() == Parent)
    return &*NormalDest->getFirstInsertionPt();

  BasicBlock *EdgeBB = BasicBlock::Create(C, Parent->getName() + Suffix,
                                          II->getFunction(), NormalDest);
  BranchInst *Br = BranchInst::Create(NormalDest, EdgeBB);
  II->setNormalDest(EdgeBB);

  for (PHINode &PN : NormalDest->phis()) {

    int idx = PN.getBasicBlockIndex(Parent);
    while (idx >= 0) {

      PN.setIncomingBlock((unsigned)idx, EdgeBB);
      idx = PN.getBasicBlockIndex(Parent);

    }

  }

  return Br;

}

PreservedAnalyses BugPass::run(Module &M, ModuleAnalysisManager &MAM) {

  BugPassConfig cfg = parseEnv();
  if (!cfg.any()) return PreservedAnalyses::all();

  if (getenv("AFL_QUIET") == nullptr) {

    errs() << "[afl-bug] enabled modes:" << (cfg.scalar ? " SCALAR" : "")
           << (cfg.budget ? " BUDGET" : "") << (cfg.sizefill ? " SIZEFILL" : "")
           << (cfg.allocsize ? " ALLOCSIZE" : "") << (cfg.slack ? " SLACK" : "")
           << "\n";

  }

  // Fresh state per module. Function* keys and module-local names are only
  // valid for the lifetime of THIS Module.
  state_.scalar_slice = cfg.scalar_slice;
  state_.custom_allocs.clear();
  for (const std::string &name : cfg.custom_alloc_funcs)
    state_.custom_allocs.insert(name);
  emitBugModeGlobal(M, cfg);

  bool changed = true;
  if (cfg.scalar) changed |= runScalarMode(M, MAM, state_);
  if (cfg.budget)
    changed |= runBudgetMode(M, MAM, /*out_param_enabled=*/cfg.sizefill);
  if (cfg.sizefill) changed |= runSizefillMode(M, MAM, state_);
  if (cfg.slack) changed |= runSlackMode(M, MAM, state_);
  if (cfg.allocsize)
    changed |=
        runAllocSizeMode(M, MAM, cfg.custom_alloc_funcs, cfg.custom_free_funcs,
                         /*stack_enabled=*/cfg.allocsize_stack);
  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();

}

// Detect: I is the back-edge update of a loop-header PHI, with a step that
// is loop-invariant. Catches `i++`, `i += stride_const`, `step <<= 1`, etc.
// — patterns whose max value is trivially the loop trip count and would
// saturate the IJON-Max channel without conveying data-dependent signal.
//
// Critically: a binary op like libwebp's `total_size += table_size` is NOT
// rejected here, because `table_size` is computed inside the loop body
// and is therefore NOT loop-invariant. Such data-dependent accumulators
// are exactly what we want to track.
//
// Also walks through ONE level of zext/sext/trunc between the BinOp
// and its PHI user, catching `i_next = i + 1; i_w = sext i_next`
// patterns that appear under -O0 + indvar-widening.
static bool isInductionVariableUpdate(BinaryOperator *I, LoopInfo &LI) {

  // Build the set of users to inspect: direct users plus values that are
  // a single cast away. Bounded by 1 cast level — anything deeper isn't
  // a simple IV anyway and should be tracked.
  SmallVector<User *, 4> candidates;
  for (User *U : I->users())
    candidates.push_back(U);
  for (User *U : I->users()) {

    if (auto *Cast = dyn_cast<CastInst>(U)) {

      Instruction::CastOps op = Cast->getOpcode();
      if (op == Instruction::ZExt || op == Instruction::SExt ||
          op == Instruction::Trunc) {

        for (User *UU : Cast->users())
          candidates.push_back(UU);

      }

    }

  }

  for (User *U : candidates) {

    auto *PN = dyn_cast<PHINode>(U);
    if (!PN) continue;
    BasicBlock *PB = PN->getParent();
    Loop       *L = LI.getLoopFor(PB);
    if (!L) continue;
    if (L->getHeader() != PB) continue;
    if (I->getOperand(0) != PN && I->getOperand(1) != PN) continue;
    Value *Other =
        (I->getOperand(0) == PN) ? I->getOperand(1) : I->getOperand(0);
    if (L->isLoopInvariant(Other)) return true;

  }

  return false;

}

// Enhancement A: backward-slice helper for SCALAR's data-flow gate.
// Walks back from every allocator-size argument, every GEP index, and
// every memcpy/memmove/memset length, collecting all Values that feed
// any of them. SCALAR then only instruments BinaryOperators in this set
// — drastically reducing map pollution on large targets where most
// arithmetic is unrelated to memory layout.
//
// Sinks intentionally include all OpenMP/Clang-emitted size args (the
// AllocKind table's allocator names match the post-rewrite forms too,
// so this works whether ALLOCSIZE has already run or not).
static void computeScalarSinkSlice(Function                    &F,
                                   const std::set<std::string> &customs,
                                   SmallPtrSetImpl<Value *>    &out) {

  SmallVector<Value *, 32> work;
  auto                     pushIfInt = [&](Value *V) {

    if (!V) return;
    if (!V->getType()->isIntegerTy()) return;
    work.push_back(V);

  };

  // Allocator size arguments. Matched by name to avoid hard-coding the
  // AllocKind table layout here; this is a small subset (the size-arg
  // positions) of what runAllocSizeMode consumes.
  // User-listed custom allocators (AFL_LLVM_BUG_ALLOCSIZE_FUNCS) count
  // as sinks too, so slice-filtered SCALAR picks up the size
  // computations feeding them.
  auto isAllocSizeCallee = [&](StringRef n) -> bool {

    if (!customs.empty() && customs.count(n.str())) return true;
    return n == "malloc" || n == "calloc" || n == "realloc" ||
           n == "reallocarray" || n == "posix_memalign" ||
           n == "aligned_alloc" || n == "strndup" ||
           n == "__afl_track_malloc" || n == "__afl_track_calloc" ||
           n == "__afl_track_realloc" || n == "__afl_track_reallocarray" ||
           n == "__afl_track_posix_memalign" ||
           n == "__afl_track_aligned_alloc" || n == "__afl_track_strndup" ||
           n == "_Znwm" || n == "_Znam" || n == "_Znwj" || n == "_Znaj" ||
           n == "_ZnwmSt11align_val_t" || n == "_ZnamSt11align_val_t" ||
           n == "_ZnwjSt11align_val_t" || n == "_ZnajSt11align_val_t";

  };

  for (BasicBlock &BB : F) {

    for (Instruction &I : BB) {

      // GEP indices (all of them; the first index is the array stride,
      // subsequent ones are nested-aggregate offsets — all interesting).
      if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {

        for (auto idx = GEP->idx_begin(), e = GEP->idx_end(); idx != e; ++idx)
          pushIfInt(idx->get());
        continue;

      }

      // memcpy / memmove / memset lengths.
      if (auto *MI = dyn_cast<MemIntrinsic>(&I)) {

        pushIfInt(MI->getLength());
        continue;

      }

      // Allocator size args.
      if (auto *Call = dyn_cast<CallBase>(&I)) {

        Function *cf = Call->getCalledFunction();
        if (!cf) continue;
        if (!isAllocSizeCallee(cf->getName())) continue;
        // Pull every integer arg as a sink. The position-specific size
        // arg is only one of them, but we don't need to distinguish:
        // tracking too much is safe (we already filter by BinaryOperator
        // and IV-update); tracking too little is the failure mode A
        // exists to avoid.
        for (Use &U : Call->args())
          pushIfInt(U.get());
        continue;

      }

    }

  }

  // Backward BFS. Bounded by visited-set; cycles (PHIs) handled by
  // SmallPtrSet's insert returning false on dup.
  while (!work.empty()) {

    Value *v = work.pop_back_val();
    if (!out.insert(v).second) continue;

    if (auto *Op = dyn_cast<Operator>(v)) {

      for (Use &U : Op->operands()) {

        Value *o = U.get();
        if (!o->getType()->isIntegerTy()) continue;
        if (out.count(o)) continue;
        // Stop at function arguments (they're sources, not transforms).
        // Constants short-circuit naturally via Operator-check below.
        if (isa<Constant>(o)) continue;
        work.push_back(o);

      }

    }

  }

}

// Heuristic filter: skip values that are clearly addresses, sizes-of-input,
// or loop-induction. Conservative — we'd rather miss a site than spam the map.
static bool ScalarSiteWorthInstrumenting(BinaryOperator *I, LoopInfo &LI) {

  auto isAflInternalValue = [](Value *Root) -> bool {

    SmallVector<Value *, 8>  work;
    SmallPtrSet<Value *, 16> seen;
    work.push_back(Root);
    unsigned depth = 0;
    while (!work.empty() && depth++ < 32) {

      Value *V = work.pop_back_val();
      if (!V || !seen.insert(V).second) continue;
      if (auto *Inst = dyn_cast<Instruction>(V)) {

        if (Inst->hasMetadata("nosanitize")) return true;

      }

      if (auto *GV = dyn_cast<GlobalValue>(V->stripPointerCasts())) {

        StringRef N = GV->getName();
#if LLVM_VERSION_MAJOR >= 18
        if (N.starts_with("__afl_") || N.starts_with("__sancov_")) return true;
#else
        if (N.startswith("__afl_") || N.startswith("__sancov_")) return true;
#endif

      }

      if (auto *Op = dyn_cast<Operator>(V)) {

        for (Use &U : Op->operands())
          work.push_back(U.get());
        continue;

      }

      if (auto *Ld = dyn_cast<LoadInst>(V)) {

        work.push_back(Ld->getPointerOperand());
        continue;

      }

    }

    return false;

  };

  if (isAflInternalValue(I)) return false;
  // Reject pure induction-variable updates first — cheap structural check.
  if (isInductionVariableUpdate(I, LI)) return false;
  // Skip if any operand is the result of a GEP (address-arithmetic).
  for (Use &U : I->operands())
    if (isa<GetElementPtrInst>(U.get())) return false;
  // Skip pointer-to-int casts (also address-arithmetic).
  for (Use &U : I->operands())
    if (isa<PtrToIntInst>(U.get())) return false;
  // Require scalar integer of useful width. Vector / float / i1 / wide
  // (i128) types either can't be zext'd to i64 cleanly or aren't worth
  // tracking. NEON intrinsics surface as <N x iM> add/sub/mul; rejecting
  // non-IntegerType is critical to avoid backend crashes.
  auto *IT = dyn_cast<IntegerType>(I->getType());
  if (!IT) return false;
  if (IT->getBitWidth() < 8 || IT->getBitWidth() > 64) return false;
  // Skip if used only as a branch condition.
  bool any_non_br = false;
  for (User *U : I->users())
    if (!isa<BranchInst>(U) && !isa<ICmpInst>(U)) {

      any_non_br = true;
      break;

    }

  if (!any_non_br) return false;
  return true;

}

// (Cross-mode dedup map moved into BugPassState; see top of namespace.)

bool runScalarMode(Module &M, ModuleAnalysisManager &, BugPassState &S) {

  LLVMContext &C = M.getContext();
  Type        *VoidTy = Type::getVoidTy(C);
  IntegerType *I32 = IntegerType::getInt32Ty(C);
  IntegerType *I64 = IntegerType::getInt64Ty(C);

  FunctionCallee scalarHook =
      M.getOrInsertFunction("__afl_bug_scalar_max", VoidTy, I32, I64);
  markBugHookAttrs(scalarHook);
  FunctionCallee loopFlush =
      M.getOrInsertFunction("__afl_bug_loop_iter_flush", VoidTy, I32, I32);
  markBugHookAttrs(loopFlush);

  // No per-site active-flag guard. The earlier Enhancement J emitted
  // load/icmp/branch around every SCALAR call, which inflates IR
  // dramatically (3+ extra instructions × thousands of sites) and gives
  // LLVM no way to CSE the load (global loads alias everything by
  // default). The runtime hook already starts with `if (!__afl_bug_active)
  // return;` — the saved fuzzing-OFF call overhead doesn't justify the
  // per-site IR cost.

  uint32_t arith_sites = 0, loop_sites = 0;
  bool     changed = false;
  bool     dump_summary = getenv(AFL_BUG_ENV_DUMP_SUMMARY) != nullptr;
  std::map<Function *, std::pair<uint32_t, uint32_t>> per_func;

  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    // Build DT + LoopInfo once per function and use it for both the
    // arithmetic-site walk (IV-filter) and the loop-counter walk below.
    DominatorTree DT(F);
    LoopInfo      LI(DT);
    StringRef     func_name = F.getName();
    uint32_t      site_idx = 0;
    uint32_t      pf_arith_start = arith_sites;
    uint32_t      pf_loop_start = loop_sites;

    // Optional size-sink slice (AFL_LLVM_BUG_SCALAR_SLICE). Off by
    // default — turning it on silences pure-compute accumulators like
    // hash builders or non-memory counters, which is exactly the
    // libwebp-class signal SCALAR otherwise captures. Useful only for
    // very large targets where map pollution outweighs lost coverage.
    SmallPtrSet<Value *, 32> slice;
    if (S.scalar_slice) computeScalarSinkSlice(F, S.custom_allocs, slice);

    for (BasicBlock &BB : F) {

      for (Instruction &I : BB) {

        auto *Bin = dyn_cast<BinaryOperator>(&I);
        if (!Bin) continue;
        switch (Bin->getOpcode()) {

          case Instruction::Add:
          case Instruction::Sub:
          case Instruction::Mul:
          case Instruction::Shl:
          case Instruction::LShr:
          case Instruction::AShr:
          // Division/remainder are size-relevant in decoders
          // (chunk_size = total / count, align_off = addr % stride).
          // The map-MAX rule still applies.
          case Instruction::UDiv:
          case Instruction::SDiv:
          case Instruction::URem:
          case Instruction::SRem:
            break;
          default:
            continue;

        }

        if (!ScalarSiteWorthInstrumenting(Bin, LI)) continue;
        // Optional slice filter: skip if the BinOp doesn't reach any
        // size sink. Only active when the user explicitly opts in via
        // AFL_LLVM_BUG_SCALAR_SLICE — otherwise we trust the IV-filter
        // plus the per-site worth-instrumenting heuristic above.
        if (S.scalar_slice && !slice.count(Bin)) continue;

        IRBuilder<> B(Bin->getNextNode());
        inheritDebugLoc(B, Bin);
        Value   *v64 = B.CreateZExtOrTrunc(Bin, I64);
        uint32_t id =
            siteSlotId(func_name, site_idx++, BUG_MODE_SALT_SCALAR_ARITH);
        B.CreateCall(scalarHook, {ConstantInt::get(I32, id), v64});
        ++arith_sites;
        changed = true;

      }

    }

    // *WithOverflow intrinsic results: `__builtin_mul_overflow` and
    // friends lower to `llvm.{u,s}{add,sub,mul}.with.overflow.iN`,
    // whose `{value, overflow}` aggregate is consumed via extractvalue.
    // The value (index 0) carries the same MAX-channel signal as a
    // plain Add/Mul/Sub but slips past the BinaryOperator filter.
    // Only the value extract is interesting — a 1-bit overflow flag
    // never grows past bucket 1.
    auto isOverflowIntrinsic = [](Intrinsic::ID iid) -> bool {

      switch (iid) {

        case Intrinsic::uadd_with_overflow:
        case Intrinsic::sadd_with_overflow:
        case Intrinsic::usub_with_overflow:
        case Intrinsic::ssub_with_overflow:
        case Intrinsic::umul_with_overflow:
        case Intrinsic::smul_with_overflow:
          return true;
        default:
          return false;

      }

    };

    for (BasicBlock &BB : F) {

      for (Instruction &I : BB) {

        auto *EV = dyn_cast<ExtractValueInst>(&I);
        if (!EV) continue;
        if (EV->getNumIndices() != 1 || EV->getIndices()[0] != 0) continue;
        auto *Call = dyn_cast<IntrinsicInst>(EV->getAggregateOperand());
        if (!Call) continue;
        if (!isOverflowIntrinsic(Call->getIntrinsicID())) continue;
        auto *IT = dyn_cast<IntegerType>(EV->getType());
        if (!IT) continue;
        if (IT->getBitWidth() < 8 || IT->getBitWidth() > 64) continue;
        // Optional slice filter: only instrument if the value reaches a
        // size sink (the overflow intrinsic's slice membership was
        // computed for ITS operands; the extractvalue inherits via the
        // backward-BFS through the Operator chain).
        if (S.scalar_slice && !slice.count(EV)) continue;
        IRBuilder<> B(EV->getNextNode());
        inheritDebugLoc(B, EV);
        Value   *v64 = B.CreateZExtOrTrunc(EV, I64);
        uint32_t id =
            siteSlotId(func_name, site_idx++, BUG_MODE_SALT_SCALAR_ARITH);
        B.CreateCall(scalarHook, {ConstantInt::get(I32, id), v64});
        ++arith_sites;
        changed = true;

      }

    }

    // SelectInst with a ConstantInt arm: a `cond ? K : x` size-decision
    // pattern is a strong fuzzer signal (the clamp arm hides the
    // original value, but the OTHER arm still grows).  Without this
    // sites like `size = (n > MAX) ? MAX : n` are invisible to SCALAR
    // unless the underlying icmp/sub gets covered — which it often is
    // not at -O0.  Restricted to selects with at least one ConstantInt
    // operand to keep noise low: pure runtime-vs-runtime selects rarely
    // carry size signal.
    for (BasicBlock &BB : F) {

      for (Instruction &I : BB) {

        auto *Sel = dyn_cast<SelectInst>(&I);
        if (!Sel) continue;
        auto *IT = dyn_cast<IntegerType>(Sel->getType());
        if (!IT) continue;
        if (IT->getBitWidth() < 8 || IT->getBitWidth() > 64) continue;
        if (!isa<ConstantInt>(Sel->getTrueValue()) &&
            !isa<ConstantInt>(Sel->getFalseValue()))
          continue;
        // Skip address-arithmetic operands (mirrors the BinaryOperator
        // filter — selects on GEP-derived addresses produce noise).
        bool addr_arith = false;
        for (Use &U : Sel->operands())
          if (isa<GetElementPtrInst>(U.get()) || isa<PtrToIntInst>(U.get())) {

            addr_arith = true;
            break;

          }

        if (addr_arith) continue;
        // Skip if used only as a branch / icmp condition (no value flow).
        bool any_non_br = false;
        for (User *U : Sel->users())
          if (!isa<BranchInst>(U) && !isa<ICmpInst>(U)) {

            any_non_br = true;
            break;

          }

        if (!any_non_br) continue;
        if (S.scalar_slice && !slice.count(Sel)) continue;
        IRBuilder<> B(Sel->getNextNode());
        inheritDebugLoc(B, Sel);
        Value   *v64 = B.CreateZExtOrTrunc(Sel, I64);
        uint32_t id =
            siteSlotId(func_name, site_idx++, BUG_MODE_SALT_SCALAR_ARITH);
        B.CreateCall(scalarHook, {ConstantInt::get(I32, id), v64});
        ++arith_sites;
        changed = true;

      }

    }

    // Loop-header iteration counters in the SAME function — re-use the
    // DT/LoopInfo we just built. Each loop gets a salted (function,
    // site) hash so arithmetic site indices and loop site indices in
    // the same function don't collide on the shared bug map.
    if (LI.empty()) continue;
    uint32_t loop_idx = 0;
    for (Loop *L : LI.getLoopsInPreorder()) {

      // Need a simplified loop (single preheader + single latch) so the
      // header PHI has exactly two incoming edges. Irreducible / multi-
      // entry loops are skipped — better to miss the signal than to emit
      // a malformed PHI.
      BasicBlock *Preheader = L->getLoopPreheader();
      BasicBlock *Latch = L->getLoopLatch();
      BasicBlock *Header = L->getHeader();
      if (!Preheader || !Latch || !Header) continue;

      uint32_t id =
          siteSlotId(func_name, loop_idx++, BUG_MODE_SALT_SCALAR_LOOP);
      ++loop_sites;

      // SSA-form counter: PHI in the header taking 0 from preheader and
      // (cnt+1) from the latch. This avoids per-iteration load/add/store
      // through an alloca — which would survive optimizer-last since
      // mem2reg has already run. Codegen lowers this to a register
      // increment, ~3x faster in tight loops than the alloca form.
      PHINode *cnt = PHINode::Create(I32, 2, "afl.loopcnt", &*Header->begin());
#if LLVM_MAJOR >= 20
      cnt->dropDbgRecords();
#endif
      cnt->setDebugLoc(firstNonPHI(Header)->getDebugLoc());
      IRBuilder<> HB(firstNonPHI(Header));
      inheritDebugLoc(HB, firstNonPHI(Header));
      Value *inc =
          HB.CreateAdd(cnt, ConstantInt::get(I32, 1), "afl.loopcnt.inc");
      cnt->addIncoming(ConstantInt::get(I32, 0), Preheader);
      cnt->addIncoming(inc, Latch);

      // Validate the PHI is well-formed.  The standard case has
      // exactly 2 incomings under the simplified-form preconditions
      // (preheader + latch + header all non-null and distinct).
      // Degenerate cases (latch == preheader for a single-block loop,
      // or a header reached from outside the loop via an unexpected
      // edge) yield wrong/extra incomings and feed garbage into the
      // iteration counter.  Roll back rather than emit corrupt IR.
      if (cnt->getNumIncomingValues() != 2 ||
          cnt->getIncomingBlock(0) == cnt->getIncomingBlock(1)) {

        cnt->replaceAllUsesWith(ConstantInt::get(I32, 0));
        cnt->eraseFromParent();
        if (auto *IncInst = dyn_cast<Instruction>(inc))
          if (IncInst->use_empty()) IncInst->eraseFromParent();
        continue;

      }

      // Flush at every unique exit block via an LCSSA-style PHI: pick up
      // `inc` (the count INCLUDING the exit iteration) along edges that
      // come from inside the loop, and 0 along any edge that bypasses
      // the loop entirely. SmallPtrSet dedups exit blocks reached by
      // multiple edges.
      //
      // When multiple loops share an exit block, each loop inserts its
      // own xphi at top and its own flush after the PHIs.  New PHIs go
      // ABOVE any previously-inserted xphi (because they're inserted at
      // &*Exit->begin()), preserving the PHIs-at-top invariant.  Flush
      // order is "newest-loop flush precedes older-loop flush" — the
      // reverse of pre-order Loop iteration.  Code relying on flush
      // order should switch to a stable anchor (the terminator).
      SmallVector<BasicBlock *, 4> Exits;
      L->getExitBlocks(Exits);
      SmallPtrSet<BasicBlock *, 4> seenExits;
      for (BasicBlock *Exit : Exits) {

        if (!seenExits.insert(Exit).second) continue;
        // Skip EH landing-pad / cleanup-pad exit blocks: a CallInst
        // before a LandingPad is invalid IR, and `getExitBlocks` returns
        // exit blocks reached via in-loop invoke unwind edges in C++
        // -fexceptions code.
        if (Exit->isEHPad() || firstNonPHI(Exit)->isEHPad()) continue;
        PHINode *xphi =
            PHINode::Create(I32, 0, "afl.loopcnt.lcssa", &*Exit->begin());
#if LLVM_MAJOR >= 20
        xphi->dropDbgRecords();
#endif
        for (BasicBlock *Pred : predecessors(Exit)) {

          if (L->contains(Pred))
            xphi->addIncoming(inc, Pred);
          else
            xphi->addIncoming(ConstantInt::get(I32, 0), Pred);

        }

        // Insert the flush AFTER all PHIs in the exit block. Using
        // xphi->getNextNode() would land between PHIs when multiple
        // loops share an exit block (we insert a new PHI for each loop
        // and the next inserted-PHI would then sit AFTER a non-PHI flush
        // call, breaking the "PHIs at top" invariant).
        Instruction *FlushAt = firstNonPHI(Exit);
        IRBuilder<>  XB(FlushAt);
        inheritDebugLoc(XB, FlushAt);
        XB.CreateCall(loopFlush, {ConstantInt::get(I32, id), xphi});

      }

    }

    // (Function-return flush removed: exit-block flushes above are
    // sufficient and avoid conflating multiple loop runs in one call.)

    changed = true;
    if (dump_summary &&
        (arith_sites > pf_arith_start || loop_sites > pf_loop_start)) {

      per_func[&F] = {arith_sites - pf_arith_start, loop_sites - pf_loop_start};

    }

  }

  if (getenv("AFL_QUIET") == nullptr)
    errs() << "[afl-bug] SCALAR instrumented " << arith_sites
           << " arithmetic sites, " << loop_sites << " loops\n";
  if (dump_summary) {

    for (auto &kv : per_func)
      errs() << "[afl-bug-summary] SCALAR " << kv.first->getName()
             << " arith=" << kv.second.first << " loop=" << kv.second.second
             << "\n";

  }

  return changed;

}

// Recognize: ptr_after = gep(ptr_before, call_result), where ptr_before was
// passed as one of the call args. Returns the matched call + the pointer arg
// index, or {nullptr,0,0}.
//
// A second shape — `ptr_after = gep(ptr_before, *out_n)` — is matched
// when `out_param_enabled` is true (BUDGET+SIZEFILL both on).  For
// that shape `RetSize` holds the LoadInst whose value is the size and
// `Call` is the call that filled the out-param.  For the original GEP
// shape `RetSize` is nullptr and the emitter uses the call's return
// value as the size.
struct BudgetMatch {

  CallBase *Call;
  unsigned  PtrArgIdx;
  Value    *PtrBefore;
  LoadInst *RetSize;                   /* nullptr = use Call's return value */

};

// Forward decl — out-param matching shares findOutSizeParam's per-arg
// preconditions (pointer-to-integer arg written through by callee, etc.).
static int findOutSizeParam(Function &F, int sentinel_idx, int *out_bits,
                            bool *out_is_inout);

static std::vector<BudgetMatch> findBudgetCalls(Function &F,
                                                bool      out_param_enabled) {

  std::vector<BudgetMatch> out;
  for (BasicBlock &BB : F) {

    for (Instruction &I : BB) {

      // GEP form (most common in modern LLVM): getelementptr ptr, call_result.
      // Accept multi-index GEPs whose final index is the call result and
      // all preceding indices are constant-zero (typed-pointer struct
      // walks land here in pre-opaque-pointer IR, e.g. `gep [N x T]*,
      // ptr, 0, idx`). Without this the BUDGET oracle silently misses
      // every such site under -O0/-Og or older LLVM.
      if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {

        unsigned n = GEP->getNumIndices();
        if (n < 1) continue;
        bool leading_zero_ok = true;
        for (unsigned k = 1; k + 1 < GEP->getNumOperands(); ++k) {

          auto *Ci = dyn_cast<ConstantInt>(GEP->getOperand(k));
          if (!Ci || !Ci->isZero()) {

            leading_zero_ok = false;
            break;

          }

        }

        if (!leading_zero_ok) continue;
        Value *base = GEP->getPointerOperand();
        Value *idx = GEP->getOperand(GEP->getNumOperands() - 1);
        // Look through zero/sign-extending casts: clang produces
        // `zext i32 %ret to i64` between the call and the GEP.  Also
        // walk through alloca-spill on the index — at -O0 / -Og clang
        // stores the call result to a stack slot and reloads it,
        // hiding it from a cast-only walk.  Mirrors the 2-level
        // single-store-alloca walk used for base resolution below.
        //
        // Remember the FIRST LoadInst the cast-walk produces: the
        // spill walk's single-store substitution replaces idx with the
        // alloca's initializer when there is one (e.g. `size_t n = 0;`),
        // turning the call-filled-out-param shape into a constant 0 and
        // hiding the load from the out-param matcher below.
        LoadInst *first_load_idx = nullptr;
        for (int spill = 0; spill < 3; ++spill) {

          while (auto *Cast = dyn_cast<CastInst>(idx)) {

            if (Cast->getOpcode() == Instruction::ZExt ||
                Cast->getOpcode() == Instruction::SExt ||
                Cast->getOpcode() == Instruction::Trunc)
              idx = Cast->getOperand(0);
            else
              break;

          }

          auto *Ld = dyn_cast<LoadInst>(idx);
          if (!Ld) break;
          if (!first_load_idx) first_load_idx = Ld;
          auto *AI = dyn_cast<AllocaInst>(Ld->getPointerOperand());
          if (!AI) break;
          // Single-store source — multiple stores or non-int stores make
          // the origin ambiguous; treat as a hard stop.
          Value   *src = nullptr;
          unsigned nstore = 0;
          bool     ambig = false;
          for (User *U : AI->users()) {

            auto *St = dyn_cast<StoreInst>(U);
            if (!St || St->getPointerOperand() != AI) continue;
            ++nstore;
            Value *sv = St->getValueOperand();
            if (src && src != sv) {

              ambig = true;
              break;

            }

            src = sv;

          }

          if (ambig || !src || nstore != 1) break;
          idx = src;

        }

        auto *Call = dyn_cast<CallBase>(idx);

        // `returned` attribute: when the callee's parameter is marked
        // `returned`, opt substitutes the parameter for the call
        // result at use sites — so `p += call(buf, n)` becomes `p += n`
        // in IR when the callee does `return n`.  The call result is
        // gone; rediscover it by walking from `idx` (which is now the
        // parameter value) to a CallBase that uses idx as a
        // returned-tagged operand.
        //
        // Constants don't have a tracked user-list (LLVM asserts on
        // user_begin for ConstantInt et al.), so skip the walk when
        // idx is a plain constant.  Also skip Arguments: no call
        // inside this function can have a Function::Argument of this
        // same function as its returned-arg substitute (the optimizer
        // would have folded earlier).
#if LLVM_VERSION_MAJOR >= 21
        if (!Call && !isa<Constant>(idx) && idx->hasUseList()) {

#else
        if (!Call && !isa<Constant>(idx)) {

#endif

          unsigned probes = 0;
          for (User *U : idx->users()) {

            if (++probes > 32) break;
            auto *CB = dyn_cast<CallBase>(U);
            if (!CB || (!isa<CallInst>(CB) && !isa<InvokeInst>(CB))) continue;
            Function *Callee = CB->getCalledFunction();
            if (!Callee) continue;
            // The same value can appear at multiple arg positions of
            // the same call; accept any position that carries
            // `returned` AND must match the call's own returned-arg
            // (LLVM only allows one returned attribute per signature).
            for (unsigned k = 0; k < CB->arg_size(); ++k) {

              if (CB->getArgOperand(k) != idx) continue;
              if (k >= Callee->arg_size()) continue;
              if (!Callee->getArg(k)->hasAttribute(Attribute::Returned))
                continue;
              Call = CB;
              break;

            }

            if (Call) break;

          }

        }

        // BUDGET out-param shape: when the existing walks haven't bound
        // Call, see whether the GEP index is a load from an alloca
        // that some preceding call's out-size param wrote into.
        // Real-world: `void fill(buf, size_t *out_n); fill(p, &n);
        // p += n;` (iconv/libxml2 streaming parsers).
        //
        // Gated to require BOTH BUDGET and SIZEFILL be enabled —
        // inherits SIZEFILL's "int* is an out-size" heuristic and its
        // FP surface.  Validation hand-off is via
        // findOutSizeParam(callee, -1).
        LoadInst *out_param_size = nullptr;
        if (!Call && out_param_enabled && first_load_idx) {

          LoadInst *LdSize = first_load_idx;
          auto     *AI = dyn_cast<AllocaInst>(LdSize->getPointerOperand());
          if (AI) {

            // Find a CallBase that takes &AI as one of its args AND
            // precedes LdSize in the same basic block (cheap dominance
            // proxy — the canonical pattern lives in one BB at -O0).
            // Cross-BB dominance would need a DominatorTree; defer.
            for (User *U : AI->users()) {

              auto *CB = dyn_cast<CallBase>(U);
              if (!CB) continue;
              if (!isa<CallInst>(CB) && !isa<InvokeInst>(CB)) continue;
              if (CB->getParent() != LdSize->getParent()) continue;
              // Order check: CB must come before LdSize in this BB.
              bool cb_first = false;
              for (Instruction &II : *CB->getParent()) {

                if (&II == CB) {

                  cb_first = true;
                  break;

                }

                if (&II == LdSize) break;

              }

              if (!cb_first) continue;
              Function *Callee = CB->getCalledFunction();
              if (!Callee || Callee->isDeclaration()) continue;
              // Which arg position of CB is AI?
              int cb_arg_pos = -1;
              for (unsigned k = 0; k < CB->arg_size(); ++k) {

                if (CB->getArgOperand(k) == AI) {

                  cb_arg_pos = (int)k;
                  break;

                }

              }

              if (cb_arg_pos < 0) continue;
              // Validate via the same helper SIZEFILL uses: the callee
              // must have a qualifying out-size param at this position.
              int  out_bits = 0;
              bool out_is_inout = false;
              int  validated =
                  findOutSizeParam(*Callee, -1, &out_bits, &out_is_inout);
              if (validated != cb_arg_pos) continue;
              // Match. Promote CB to Call so the existing arg-matching
              // loop below identifies the buf-arg position via the
              // same alloca-aliasing logic the GEP-shape uses.
              Call = CB;
              out_param_size = LdSize;
              break;

            }

          }

        }

        if (!Call || (!isa<CallInst>(Call) && !isa<InvokeInst>(Call))) continue;
        // Match base against any pointer arg of the call, peering
        // through up to TWO levels of alloca-spill (a single level
        // catches optnone code; two catches post-Inlining-without-
        // mem2reg IR where the inlined callee re-spills its arg into
        // a second slot).  Walk allocas with MULTIPLE stores too —
        // the canonical `p += s` pattern stores once with the initial
        // value and once with the post-GEP update.  DFS over every
        // possible source value; if ANY source matches the call's
        // pointer arg, accept.  Wrong-frame match risk is bounded
        // because the runtime check uses the matched ptr_before to
        // find its frame and silently no-ops on mismatch.
        auto matches_arg = [&](Value *arg_val, Value *needle) -> bool {

          // Normalize each side to either its source SSA value or its
          // backing alloca: two loads from the same alloca alias to
          // the same logical variable (e.g. `p` at -O0 is loaded
          // separately at the call site and at the GEP — different
          // SSA, same alloca).  The DFS then accepts (alloca ==
          // alloca) or any store-source overlap.
          auto stripped = [](Value *v) {

            return v ? v->stripPointerCasts() : v;

          };

          auto loadAlloca = [&](Value *v) -> AllocaInst * {

            if (auto *Ld = dyn_cast<LoadInst>(v))
              return dyn_cast<AllocaInst>(Ld->getPointerOperand());
            return nullptr;

          };

          Value      *a = stripped(arg_val);
          AllocaInst *a_alloca = loadAlloca(a);

          SmallVector<Value *, 8>  work;
          SmallPtrSet<Value *, 16> seen;
          work.push_back(stripped(needle));
          unsigned iters = 0;
          while (!work.empty()) {

            if (++iters > 32) break;
            Value *b = work.pop_back_val();
            b = stripped(b);
            if (!seen.insert(b).second) continue;
            if (a == b) return true;
            // Same alloca on both sides — aliased load.
            if (a_alloca && a_alloca == loadAlloca(b)) return true;
            auto *Ld = dyn_cast<LoadInst>(b);
            if (!Ld) continue;
            auto *AI = dyn_cast<AllocaInst>(Ld->getPointerOperand());
            if (!AI) continue;
            // Push every store source — multi-store allocas (the `p =
            // call_or_init; p += s` idiom) yield multiple candidates.
            for (User *U : AI->users()) {

              auto *St = dyn_cast<StoreInst>(U);
              if (!St || St->getPointerOperand() != AI) continue;
              Value *sv = St->getValueOperand()->stripPointerCasts();
              work.push_back(sv);

            }

          }

          return false;

        };

        for (unsigned i = 0; i < Call->arg_size(); ++i) {

          if (matches_arg(Call->getArgOperand(i), base)) {

            // Use the call's actual pointer arg as PtrBefore, not the
            // GEP's base.  The call arg DOMINATES the call (it's the
            // call's own operand); the GEP base may not — under -O0
            // it's a separate load that post-dates the call, and
            // using it at the pre-call ws_begin site emits IR that
            // reads an SSA value before its definition.  The two
            // values are equal at runtime in the canonical pattern
            // (no store to the backing alloca between the call and
            // the GEP).
            out.push_back({Call, i, Call->getArgOperand(i), out_param_size});
            break;

          }

        }

        continue;

      }

      // Integer-add form (legacy / pre-opaque-pointer):
      // a = ptrtoint p; b = a + ret; ...
      auto *Add = dyn_cast<BinaryOperator>(&I);
      if (!Add || Add->getOpcode() != Instruction::Add) continue;
      Value *L = Add->getOperand(0), *R = Add->getOperand(1);
      auto  *Call = dyn_cast<CallBase>(L);
      Value *Ptr = R;
      if (!Call || (!isa<CallInst>(Call) && !isa<InvokeInst>(Call))) {

        Call = dyn_cast<CallBase>(R);
        Ptr = L;

      }

      if (!Call || (!isa<CallInst>(Call) && !isa<InvokeInst>(Call))) continue;
      auto *P2I = dyn_cast<PtrToIntInst>(Ptr);
      if (!P2I) continue;
      Value *base = P2I->getOperand(0);
      for (unsigned i = 0; i < Call->arg_size(); ++i) {

        if (Call->getArgOperand(i)->stripPointerCasts() ==
            base->stripPointerCasts()) {

          out.push_back({Call, i, base, /*RetSize=*/nullptr});
          break;

        }

      }

    }

  }

  return out;

}

bool runBudgetMode(Module &M, ModuleAnalysisManager &, bool out_param_enabled) {

  LLVMContext &C = M.getContext();
  Type        *VoidTy = Type::getVoidTy(C);
  IntegerType *I32 = IntegerType::getInt32Ty(C);
  IntegerType *I64 = IntegerType::getInt64Ty(C);
#if LLVM_MAJOR >= 20
  Type *PtrTy = PointerType::getUnqual(C);
#else
  Type *PtrTy = PointerType::get(IntegerType::getInt8Ty(C), 0);
#endif

  FunctionCallee wsBegin =
      M.getOrInsertFunction("__afl_bug_ws_begin", VoidTy, PtrTy);
  markBugHookAttrs(wsBegin);
  FunctionCallee wsCheck =
      M.getOrInsertFunction("__afl_bug_ws_check_budget", VoidTy, PtrTy, I64);
  markBugHookAttrs(wsCheck);
  FunctionCallee wsStore =
      M.getOrInsertFunction("__afl_bug_ws_store", VoidTy, PtrTy, I32);
  markBugHookAttrs(wsStore);

  // Per-callee set of argument indices that are budget-traced. A store
  // inside such a callee only counts toward __afl_bug_ws_max_off if it
  // reaches one of these specific args — not just any pointer arg. This
  // prevents false positives when the callee has unrelated pointer args
  // (e.g., a status-out pointer) whose writes happen to land past the
  // tracked buffer head.
  std::map<Function *, std::set<unsigned>> callee_arg_indices;

  bool changed = false;
  bool dump_summary = getenv(AFL_BUG_ENV_DUMP_SUMMARY) != nullptr;
  std::map<Function *, uint32_t> per_func_sites;
  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    for (auto &m : findBudgetCalls(F, out_param_enabled)) {

      Function *callee = m.Call->getCalledFunction();
      if (!callee || callee->isDeclaration()) continue;  // intra-module only
      /* The size value differs by shape:
           GEP shape (m.RetSize == nullptr): size is the call's return,
             which must be integer-typed. Defensive check below — pass
             ordering with ASan and unusual optimisation pipelines can
             produce surprises.
           Out-param shape (m.RetSize != nullptr): size is the loaded
             value; LoadInst always has a typed result, and the matcher
             enforced int-ness via findOutSizeParam. */
      if (!m.RetSize && !m.Call->getType()->isIntegerTy()) continue;
      if (m.PtrArgIdx >= callee->arg_size()) continue;

      IRBuilder<> Pre(m.Call);
      inheritDebugLoc(Pre, m.Call);
      Value *ptrCast = castToPtrTy(Pre, m.PtrBefore, PtrTy);
      Pre.CreateCall(wsBegin, {ptrCast});

      Instruction *PostAt;
      Value       *sizeValue;
      if (m.RetSize) {

        /* Out-param shape: insert immediately after the load so the
           size value is in scope. The load lives in the same BB as the
           call by construction (matcher enforces same-BB ordering). */
        PostAt = m.RetSize->getNextNode();
        sizeValue = m.RetSize;

      } else {

        PostAt = postCallInsertionPoint(m.Call, C, ".budget.edge");
        sizeValue = m.Call;

      }

      if (!PostAt) continue;
      IRBuilder<> Post(PostAt);
      inheritDebugLoc(Post, m.Call);
      Value *ret64 = Post.CreateZExtOrTrunc(sizeValue, I64);
      Value *ptrCast2 = castToPtrTy(Post, m.PtrBefore, PtrTy);
      Post.CreateCall(wsCheck, {ptrCast2, ret64});

      callee_arg_indices[callee].insert(m.PtrArgIdx);
      changed = true;
      if (dump_summary) ++per_func_sites[&F];

    }

  }

  // Instrument stores whose pointer traces to the SPECIFIC budget-traced
  // argument. Stores via stack locals, globals, or other pointer args are
  // skipped to keep the tracked max_off honest. Skip callees the user
  // excluded via AFL_LLVM_DENYLIST etc. — otherwise excluded code still
  // gets per-store instrumentation when it happens to receive a tracked
  // arg from an instrumented caller.
  IntegerType *I32_for_store = IntegerType::getInt32Ty(C);
  for (auto &kv : callee_arg_indices) {

    Function                 *F = kv.first;
    const std::set<unsigned> &arg_indices = kv.second;
    // BUDGET aborts when `max_off > ret_size` — over-reporting writes
    // via bounded-libc functions (snprintf, read, ...) would FP.
    // Restrict to deterministic-write libc functions only.
    instrumentArgReachingStores(*F, wsStore, arg_indices, PtrTy, I32_for_store,
                                M.getDataLayout(),
                                /*libc_exact_only=*/true);

  }

  if (getenv("AFL_QUIET") == nullptr)
    errs() << "[afl-bug] BUDGET instrumented " << callee_arg_indices.size()
           << " callees\n";
  if (dump_summary) {

    for (auto &kv : per_func_sites)
      errs() << "[afl-bug-summary] BUDGET " << kv.first->getName()
             << " sites=" << kv.second << "\n";

  }

  return changed;

}

// Describes a sentinel-style API:
//   sentinel_idx   : the pointer arg branched on null; pre-pass returns
//                    the buffer's claimed size without writing.
//   out_size_idx   : -1 if the size comes from the integer return value;
//                    otherwise the index of a pointer-to-integer arg
//                    through which the function writes the size. Caller-
//                    visible after the call as `*args[out_size_idx]`.
//   out_size_bits  : width in bits of the value stored through
//                    args[out_size_idx]. Unused when out_size_idx == -1.
//                    Critical: loading wider than the actual pointee
//                    reads adjacent caller-stack garbage and almost
//                    always trips the SIZEFILL `ret_size > buf_size`
//                    check spuriously.
struct SentinelDesc {

  int sentinel_idx;
  int out_size_idx;
  int out_size_bits;
  // True if the callee reads through args[out_size_idx] (in/out
  // param).  Caller MUST skip the pre-call zero on these — otherwise
  // the zero clobbers an initial value the callee expects.
  bool out_is_inout;

};

// Scan F for an out-size argument: a pointer-to-integer arg through
// which F writes a value before returning.
//
// Returns the arg index AND the bit width of the value stored (via
// `*out_bits`), or -1 if no qualifying arg. Also returns via
// `*out_is_inout` whether the callee READS through the param anywhere
// (any load through the arg, its spill-loads, a one-step GEP, or any
// CallBase escape). In/out semantics means the caller-side pre-zero
// would clobber an initial value the callee depends on; the caller
// MUST honor this flag.
//
// Preconditions guarding against `parse(buf, int *err_code)`-style
// error-code out-params:
//   (a) Function must have at least one non-pointer integer arg BEFORE
//       the candidate out-param (the typical `parse(buf, size_t len,
//       size_t *out)` shape). Any width is accepted — clang doesn't
//       preserve arg names on IR Argument values even under -g (names
//       live in DILocalVariable metadata), so a name-based filter is
//       unreliable.
//   (b) Stored value's width must be pointer-wide (`size_t`-class).
//       Nearly all size_t APIs use pointer-width integers, while
//       error-code out-params are int (smaller than pointer width on
//       64-bit).  On 32-bit targets the distinction collapses; a
//       small false-positive rate is acceptable.
//
// This catches `int parse(const buf*, size_t len, size_t *out)` and
// `void parse(buf, size_t len, size_t *out)` patterns, while rejecting
// `parse(buf, int *err_code)`.
static int findOutSizeParam(Function &F, int sentinel_idx, int *out_bits,
                            bool *out_is_inout) {

  if (out_bits) *out_bits = 0;
  if (out_is_inout) *out_is_inout = false;

  const DataLayout &DL = F.getParent()->getDataLayout();
  unsigned          ptr_bits = DL.getPointerSizeInBits();

  for (Argument &A : F.args()) {

    if ((int)A.getArgNo() == sentinel_idx) continue;
    if (!A.getType()->isPointerTy()) continue;

    // Precondition (a): at least one non-pointer integer arg appears
    // earlier in the signature. Excludes the `parse(buf, &err)` shape.
    //
    // 2-arg signatures `parse(buf, size_t *out)` are also valid
    // SIZEFILL targets (zlib, libpng, OpenSSL EVP variants).  They
    // have no int arg at all.  Allowed when the stored value through
    // the out-param is pointer-wide — a stronger signal of "size_t"
    // than has_int_arg_before.  `parse(buf, int *err)` fails this
    // because `int` is < ptr_bits on 64-bit.  On 32-bit targets where
    // int == ptr_bits the distinction collapses; FP risk on `&err` is
    // accepted.
    bool has_int_arg_before = false;
    for (Argument &B : F.args()) {

      if (B.getArgNo() >= A.getArgNo()) break;
      if (B.getType()->isIntegerTy()) {

        has_int_arg_before = true;
        break;

      }

    }

    bool is_two_arg_form = (F.arg_size() == 2);
    if (!has_int_arg_before && !is_two_arg_form) continue;

    // Walk users (including spill-load idiom) for a store of an integer
    // through this arg.
    std::vector<Value *> roots;
    roots.push_back(&A);
    for (User *U : A.users()) {

      auto *St = dyn_cast<StoreInst>(U);
      if (!St) continue;
      auto *AI = dyn_cast<AllocaInst>(St->getPointerOperand());
      if (!AI) continue;
      for (User *UU : AI->users())
        if (auto *L = dyn_cast<LoadInst>(UU)) roots.push_back(L);

    }

    // Scan for in/out semantics: the callee READS the param's initial
    // value through any of:
    //   - a direct LoadInst with pointer operand == root
    //   - a one-step GEP from root whose result is then loaded (struct
    //     out-param fields read)
    //   - root being passed as a CallBase argument (escape — the
    //     callee may dereference it, we can't prove otherwise)
    // We accumulate this before deciding to accept the arg — the caller
    // uses it to gate the pre-call zero. Conservative: prefer FN on a
    // truly write-only param with an unrelated escape over clobbering
    // an in/out hint.
    bool is_inout = false;
    for (Value *root : roots) {

      for (User *U : root->users()) {

        if (auto *L = dyn_cast<LoadInst>(U)) {

          if (L->getPointerOperand() == root) {

            is_inout = true;
            break;

          }

        } else if (auto *G = dyn_cast<GetElementPtrInst>(U)) {

          if (G->getPointerOperand() == root) {

            for (User *GU : G->users()) {

              if (auto *L2 = dyn_cast<LoadInst>(GU)) {

                if (L2->getPointerOperand() == G) {

                  is_inout = true;
                  break;

                }

              }

            }

            if (is_inout) break;

          }

        } else if (auto *Call = dyn_cast<CallBase>(U)) {

          // Escape into a callee. Be conservative regardless of which
          // arg position root occupies — once it's passed out, we lose
          // visibility into what the callee does with it.
          (void)Call;
          is_inout = true;
          break;

        }

      }

      if (is_inout) break;

    }

    for (Value *root : roots) {

      for (User *U : root->users()) {

        auto *St = dyn_cast<StoreInst>(U);
        if (!St || St->getPointerOperand() != root) continue;
        Type *VT = St->getValueOperand()->getType();
        if (!VT->isIntegerTy()) continue;
        unsigned bits = VT->getIntegerBitWidth();
        if (bits < 16 || bits > 64) continue;

        // Width threshold depends on signature shape.  In the 3-arg+
        // `parse(buf, len, *out)` shape the int-arg signals "real
        // parser API, not error-code-only" so 32-bit out widths
        // (uint32_t *outlen — libpng/libxml2/OpenSSL) are safe.  In
        // the 2-arg form `parse(buf, *out)` there's no int arg to
        // disambiguate, so still require ptr-width to reject
        // `parse(buf, *err)`.
        unsigned min_bits = is_two_arg_form ? ptr_bits : 32;
        if (bits < min_bits) continue;

        if (out_bits) *out_bits = (int)bits;
        if (out_is_inout) *out_is_inout = is_inout;
        return (int)A.getArgNo();

      }

    }

  }

  return -1;

}

// A pointer parameter is "sentinel-checked" if the function has a basic
// block branched on (param == null) where the null branch reaches a
// Return without any store through the parameter. Returns the index of
// the matching parameter, or -1.
//
// The forward walk uses a visited-set with a generous depth cap so
// null branches passing through cleanup code, debug-logging blocks,
// or fall-through error labels still reach the return.
static int findSentinelParam(Function &F) {

  for (Argument &A : F.args()) {

    if (!A.getType()->isPointerTy()) continue;
    bool found_null_branch = false;
    // The user list of `A` may also contain spill-loads. Walk through
    // load-from-alloca-of-arg as well so optnone code is matched.
    std::vector<Value *> roots;
    roots.push_back(&A);
    for (User *U : A.users()) {

      auto *St = dyn_cast<StoreInst>(U);
      if (!St) continue;
      auto *AI = dyn_cast<AllocaInst>(St->getPointerOperand());
      if (!AI) continue;
      // Add loads from this alloca as additional comparison roots.
      for (User *UU : AI->users())
        if (auto *L = dyn_cast<LoadInst>(UU)) roots.push_back(L);

    }

    for (Value *root : roots) {

      for (User *U : root->users()) {

        auto *Cmp = dyn_cast<ICmpInst>(U);
        if (!Cmp || !Cmp->isEquality()) continue;
        Value *other = (Cmp->getOperand(0) == root) ? Cmp->getOperand(1)
                                                    : Cmp->getOperand(0);
        if (!isa<ConstantPointerNull>(other)) continue;
        for (User *CU : Cmp->users()) {

          auto *Br = dyn_cast<BranchInst>(CU);
          if (!Br || !Br->isConditional()) continue;
          BasicBlock *NullBB = (Cmp->getPredicate() == ICmpInst::ICMP_EQ)
                                   ? Br->getSuccessor(0)
                                   : Br->getSuccessor(1);
          // Forward CFG walk from NullBB. Look for any reachable Return
          // along a path that contains no store through `root`. Cap by
          // both visited-set size and a depth budget; that handles
          // pathological CFGs (large dispatch jump-tables on the null
          // path) without scanning unboundedly.
          //
          // We don't require the null path to be ONLY uncond branches —
          // cleanup blocks often have conditional branches (e.g.
          // `if (logger) log_error()`) before reaching the return. We
          // do prune any successor whose entry instruction is a store
          // through `root` — that's by definition NOT a null-path.
          SmallPtrSet<BasicBlock *, 16> visited;
          SmallVector<BasicBlock *, 16> work;
          work.push_back(NullBB);
          bool reached_return_clean = false;
          // Depth cap: 64 distinct blocks on the null path is plenty.
          // libwebp's typical null-path is 1-3 blocks; OpenSSL idioms
          // around 5-8; nothing legitimate hits 64.
          while (!work.empty() && visited.size() < 64) {

            BasicBlock *cur = work.pop_back_val();
            if (!visited.insert(cur).second) continue;
            bool stores_via_arg_here = false;
            bool returns_here = false;
            for (Instruction &I : *cur) {

              if (auto *S = dyn_cast<StoreInst>(&I)) {

                Value *p = S->getPointerOperand();
                for (int d = 0; d < 4; ++d) {

                  if (auto *G = dyn_cast<GetElementPtrInst>(p)) {

                    p = G->getPointerOperand();
                    continue;

                  }

                  break;

                }

                if (p == root) {

                  stores_via_arg_here = true;
                  break;  // this BB taints; treat as pruned

                }

              }

              if (isa<ReturnInst>(&I)) {

                returns_here = true;
                break;

              }

            }

            if (stores_via_arg_here) continue;  // prune this branch
            if (returns_here) {

              reached_return_clean = true;
              break;

            }

            // Enqueue all successors of cur's terminator.
            Instruction *T = cur->getTerminator();
            for (unsigned i = 0, e = T->getNumSuccessors(); i < e; ++i)
              work.push_back(T->getSuccessor(i));

          }

          if (reached_return_clean) { found_null_branch = true; }

          if (found_null_branch) break;

        }

        if (found_null_branch) break;

      }

      if (found_null_branch) break;

    }

    if (found_null_branch) return (int)A.getArgNo();

  }

  return -1;

}

// Trace a store's pointer back to its origin and decide whether it
// reaches one of the function arguments named in `arg_indices`. If
// `arg_indices` is empty, ANY argument satisfies (BUDGET legacy
// behavior). Walks GEP/BitCast/PHI/Select chains and one level of
// alloca-spill, capped by `max_depth` to keep cycles bounded.
//
// Returns true if every traced root that we found is an Argument whose
// index is in `arg_indices` (or any Argument when the set is empty). A
// store via a stack-local alloca, a global, or a pointer through a
// different arg returns false.
static bool ptrValueReachesArg(Value                    *Root,
                               const std::set<unsigned> &arg_indices) {

  auto argAcceptable = [&](Argument *Arg) -> bool {

    return arg_indices.empty() || arg_indices.count(Arg->getArgNo());

  };

  // Resolve the common -O0 spill idiom only when the stack slot has exactly
  // one direct store. Multiple stores, non-pointer stores, or stores through
  // aliases make the origin ambiguous; treat those as untrusted roots.
  auto singleAllocaSpillSource = [&](AllocaInst *AI) -> Value * {

    Value   *source = nullptr;
    unsigned stores = 0;
    for (User *U : AI->users()) {

      auto *St = dyn_cast<StoreInst>(U);
      if (!St || St->getPointerOperand() != AI) continue;
      ++stores;
      if (stores > 1) return nullptr;
      source = St->getValueOperand();
      if (!source->getType()->isPointerTy()) return nullptr;

    }

    return stores == 1 ? source : nullptr;

  };

  SmallVector<Value *, 8>  work;
  SmallPtrSet<Value *, 16> seen;
  work.push_back(Root);

  bool     saw_acceptable_root = false;
  unsigned iters = 0;
  while (!work.empty()) {

    if (++iters > 64) return false;

    Value *ptr = work.pop_back_val();
    if (!ptr) return false;
    ptr = ptr->stripPointerCasts();
    if (!seen.insert(ptr).second) continue;

    if (auto *Arg = dyn_cast<Argument>(ptr)) {

      if (!argAcceptable(Arg)) return false;
      saw_acceptable_root = true;
      continue;

    }

    if (auto *GEP = dyn_cast<GetElementPtrInst>(ptr)) {

      work.push_back(GEP->getPointerOperand());
      continue;

    }

    if (auto *Cast = dyn_cast<CastInst>(ptr)) {

      if (Cast->getOperand(0)->getType()->isPointerTy()) {

        work.push_back(Cast->getOperand(0));
        continue;

      }

      return false;

    }

    if (auto *PN = dyn_cast<PHINode>(ptr)) {

      for (Value *Inc : PN->incoming_values())
        work.push_back(Inc);
      continue;

    }

    if (auto *Sel = dyn_cast<SelectInst>(ptr)) {

      work.push_back(Sel->getTrueValue());
      work.push_back(Sel->getFalseValue());
      continue;

    }

    if (auto *Ld = dyn_cast<LoadInst>(ptr)) {

      auto *AI = dyn_cast<AllocaInst>(Ld->getPointerOperand());
      if (!AI) return false;
      Value *source = singleAllocaSpillSource(AI);
      if (!source) return false;
      work.push_back(source);
      continue;

    }

    // A constant, call result, global, alloca base, or any other terminal
    // value is not proven to be the traced argument. Reject the store rather
    // than attributing writes from mixed PHI/select paths to the buffer.
    return false;

  }

  return saw_acceptable_root;

}

static bool ptrStoreReachesArg(StoreInst                *S,
                               const std::set<unsigned> &arg_indices) {

  return ptrValueReachesArg(S->getPointerOperand(), arg_indices);

}

// `exact_only` selects between deterministic-write libc functions
// (memset / memcpy / strncpy — the runtime can use `len` as the
// definitive write count) and bounded-write libc functions
// (snprintf / read / recv — `len` is the upper bound; actual writes
// may be smaller, so recording `len` as the write extent over-reports).
// BUDGET aborts when `max_off > ret_size` and is sensitive to
// over-reporting, so it asks for exact_only=true.  SIZEFILL aborts
// only on writes past the buffer end (clamped by sf_cap), so it is
// robust to over-reporting and asks for exact_only=false.
static bool getLibcMemoryWriteDestAndSize(CallBase *CB, Value *&Dest,
                                          Value *&Len, bool exact_only) {

  Function *Callee = CB ? CB->getCalledFunction() : nullptr;
  if (!Callee) return false;
  StringRef Name = Callee->getName();
#if LLVM_VERSION_MAJOR >= 18
  if (Name.starts_with("\01")) Name = Name.drop_front();
#else
  if (Name.startswith("\01")) Name = Name.drop_front();
#endif

  auto useArgs = [&](unsigned DestIdx, unsigned LenIdx) -> bool {

    if (CB->arg_size() <= std::max(DestIdx, LenIdx)) return false;
    Dest = CB->getArgOperand(DestIdx);
    Len = CB->getArgOperand(LenIdx);
    return Dest && Len && Dest->getType()->isPointerTy() &&
           Len->getType()->isIntegerTy();

  };

  // --- Exact writers: byte count == arg.  Always safe ---
  if (Name == "memset" || Name == "__memset_chk" || Name == "memcpy" ||
      Name == "__memcpy_chk" || Name == "memmove" || Name == "__memmove_chk" ||
      Name == "mempcpy" || Name == "__mempcpy_chk")
    return useArgs(0, 2);

  if (Name == "bzero" || Name == "explicit_bzero") return useArgs(0, 1);

  // BSD bcopy has source/dest/length argument order.
  if (Name == "bcopy") return useArgs(1, 2);

  // strncpy always writes exactly `n` bytes (NUL-pads short src,
  // truncates long src — never fewer than n).
  if (Name == "strncpy" || Name == "__strncpy_chk") return useArgs(0, 2);

  if (exact_only) return false;

  // --- Bounded writers: byte count <= arg.  SIZEFILL-only ---
  // strncat: appends up to `n` chars + 1 NUL.  Upper bound n+1.
  // We use `n` as a slightly under-estimating bound (the runtime
  // adds 1 byte slack via sf_cap; SIZEFILL is robust to this).
  if (Name == "strncat" || Name == "__strncat_chk") return useArgs(0, 2);

  // BSD strlcpy/strlcat: at most `size` bytes total.
  if (Name == "strlcpy" || Name == "strlcat") return useArgs(0, 2);

  // (v)snprintf: at most `size` bytes (incl NUL) when size>0.
  if (Name == "snprintf" || Name == "__snprintf_chk" || Name == "vsnprintf" ||
      Name == "__vsnprintf_chk")
    return useArgs(0, 1);

  // fgets: writes at most `size` bytes (incl NUL) into dest.
  if (Name == "fgets") return useArgs(0, 1);

  // read / pread: write up to `count` bytes into buf.
  if (Name == "read" || Name == "pread" || Name == "__read_chk" ||
      Name == "__pread_chk" || Name == "__pread64_chk" || Name == "pread64")
    return useArgs(1, 2);

  // recv: buf at arg1, len at arg2.  recvfrom shares the same shape
  // for those two args (extra trailing args are immaterial).
  if (Name == "recv" || Name == "recvfrom" || Name == "__recv_chk" ||
      Name == "__recvfrom_chk")
    return useArgs(1, 2);

  return false;

}

// Copy the source instruction's DebugLoc onto `IB`'s recently-inserted
// instructions so crashes / backtraces resolve to the user's source line
// rather than the no-location bug-pass synthetic IR. If Source has no
// debug loc, leave the builder's existing loc untouched — otherwise we'd
// silently clear it and subsequent inserts would surface as <unknown>.
static void inheritDebugLoc(IRBuilder<> &B, Instruction *Source) {

  if (!Source) return;
  if (DebugLoc DL = Source->getDebugLoc()) B.SetCurrentDebugLocation(DL);

}

// Enhancement E (pass-side scope): the per-store instrumentation walk
// is identical in shape between BUDGET and SIZEFILL — same pointer-
// origin tracing via ptrStoreReachesArg, same filter against an
// arg-index set, same hook call emission. Factored here so the
// duplication doesn't drift; a future runtime-side unification (one
// tracked-region hook) would change only this one helper.
//
// PRECONDITION (load-bearing): callers MUST verify F is in the user's
// instrument list before invoking this helper. The helper instruments
// every qualifying StoreInst in F unconditionally — it does not
// re-check isInInstrumentList. The two current callers
// (runBudgetMode, runSizefillMode) honor this; any new caller must
// do the same or risk leaking hook calls into user-excluded code.
//
// `hook` must be void-returning with signature (i8*, i32).
static bool isConstantTooWideForBugStoreHook(Value *Len) {

  auto *CI = dyn_cast<ConstantInt>(Len);
  if (!CI) return false;
  return CI->getValue().ugt(UINT32_MAX);

}

static unsigned instrumentArgReachingStores(
    Function &F, FunctionCallee hook, const std::set<unsigned> &arg_indices,
    Type *PtrTy, IntegerType *I32, const DataLayout &DL, bool libc_exact_only) {

  unsigned count = 0;
  for (BasicBlock &BB : F) {

    for (Instruction &I : BB) {

      if (auto *MI = dyn_cast<MemIntrinsic>(&I)) {

        Value *dest = MI->getRawDest();
        Value *len = MI->getLength();
        if (!dest || !len) continue;
        if (isConstantTooWideForBugStoreHook(len)) continue;
        if (!ptrValueReachesArg(dest, arg_indices)) continue;
        IRBuilder<> MB(MI);
        inheritDebugLoc(MB, MI);
        Value *addr = castToPtrTy(MB, dest, PtrTy);
        Value *sz = MB.CreateZExtOrTrunc(len, I32);
        MB.CreateCall(hook, {addr, sz});
        ++count;
        continue;

      }

      if (auto *CB = dyn_cast<CallBase>(&I)) {

        Value *dest = nullptr;
        Value *len = nullptr;
        if (getLibcMemoryWriteDestAndSize(CB, dest, len, libc_exact_only)) {

          if (isConstantTooWideForBugStoreHook(len)) continue;
          if (!ptrValueReachesArg(dest, arg_indices)) continue;
          IRBuilder<> MB(CB);
          inheritDebugLoc(MB, CB);
          Value *addr = castToPtrTy(MB, dest, PtrTy);
          Value *sz = MB.CreateZExtOrTrunc(len, I32);
          MB.CreateCall(hook, {addr, sz});
          ++count;
          continue;

        }

      }

      auto *S = dyn_cast<StoreInst>(&I);
      if (!S) continue;
      if (!ptrStoreReachesArg(S, arg_indices)) continue;
      IRBuilder<> SB(S);
      inheritDebugLoc(SB, S);
      Value   *addr = castToPtrTy(SB, S->getPointerOperand(), PtrTy);
      uint64_t sz = DL.getTypeStoreSize(S->getValueOperand()->getType());
      if (sz > UINT32_MAX) continue;
      SB.CreateCall(hook, {addr, ConstantInt::get(I32, (uint32_t)sz)});
      ++count;

    }

  }

  return count;

}

static bool functionHasStoreThroughArg(Function &F, unsigned arg_idx) {

  std::set<unsigned> args;
  args.insert(arg_idx);
  for (BasicBlock &BB : F)
    for (Instruction &I : BB) {

      if (auto *MI = dyn_cast<MemIntrinsic>(&I))
        if (ptrValueReachesArg(MI->getRawDest(), args)) return true;
      if (auto *CB = dyn_cast<CallBase>(&I)) {

        Value *dest = nullptr;
        Value *len = nullptr;
        // Heuristic — accept the bounded set so we don't miss callees
        // whose only write to the arg is via read()/recv()/snprintf().
        if (getLibcMemoryWriteDestAndSize(CB, dest, len,
                                          /*exact_only=*/false) &&
            ptrValueReachesArg(dest, args))
          return true;

      }

      if (auto *S = dyn_cast<StoreInst>(&I))
        if (ptrStoreReachesArg(S, args)) return true;

    }

  return false;

}

// Try to recover the allocation size of a buffer at a use-site. Returns
// either a ConstantInt (statically known) or an SSA Value* representing
// the runtime size, both as i64. Returns nullptr if no anchor.
//
// Recognizes:
//   - alloca of constant array type                         -> ConstantInt
//   - alloca with runtime array size (C99 VLA / clang LTO
//     stack-promoted dynamic allocas)                       -> SSA mul
//   - global var with constant array type                   -> ConstantInt
//   - malloc / __afl_track_malloc / new                     -> size arg
//   - calloc / __afl_track_calloc                           -> N*S (sat'd)
//   - realloc / __afl_track_realloc                         -> new size
//   - reallocarray / __afl_track_reallocarray               -> N*S (sat'd)
//   - posix_memalign / __afl_track_posix_memalign           -> size arg
//   - aligned_alloc (C11)                                   -> size arg
//   - __afl_track_aligned_alloc                             -> size arg
//   - _ZnwmSt11align_val_t / _ZnamSt11align_val_t etc.      -> size arg
//   - strndup / __afl_track_strndup                         -> n+1 (worst case)
//   - PHI / Select where all incomings yield a size         -> MIN (see below)
//
// `B` is an IRBuilder positioned where the resulting Value must be
// available. ZExt/Mul/Select instructions for runtime sizes are inserted
// at B's insertion point. SSA dominance is automatic: a malloc-call's
// size operand dominates the malloc, which dominates any use of its
// return.
//
// PHI/Select join semantics: take the MIN of incoming sizes, not the
// MAX.  SIZEFILL's question — "did the function write past the buffer
// end?" — is answered correctly only with the SMALLEST possible buffer
// on any reaching path: writes between the small and large arm's
// sizes are OOB on the small-arm path and must be flagged.  Taking
// MAX under-reports.
//
// When both PHI arms have a Value* (constant or not), emit a PHI of
// those Values at the original PHI's location.  Dominance is
// guaranteed because each per-arm size is derived from a malloc/
// alloca that itself dominates the original PHI's edge.  Same for
// Select — emit a Select of the two sizes.
//
// Critically, this is what catches the libwebp-1.3.2-style idiom:
//   size = sentinel_fn(NULL, ...);   // returns runtime size
//   buf  = malloc(size);             // size flows through SSA
//   sentinel_fn(buf, ...);           // we instrument here
// — the runtime size of `buf` is recoverable from the malloc arg.
// Internal recursive helper. `visited` guards against cyclic PHIs that
// can occur with loop-carried pointers (e.g. a header phi feeding back
// into itself via realloc). Cycles can only form through PHI and
// SelectInst — the only join nodes in SSA. We therefore insert ONLY
// those node kinds into the visited set; non-join values (LoadInst,
// CallInst, AllocaInst, etc.) revisits are common and benign on DAG
// inputs (two PHI arms sharing a common ancestor malloc, for instance)
// and tracking them here would block legitimate joins.
static Value *inferBufferSizeValueImpl(Value *V, IRBuilder<> &B,
                                       const DataLayout            &DL,
                                       const std::set<std::string> &customs,
                                       SmallPtrSetImpl<Value *>    &visited);

// Emit `N * S` with saturating semantics: on overflow, returns
// UINT64_MAX so downstream SIZEFILL comparisons (`ret > buf_size`)
// can't be tripped by a wrapped product.  Shared between calloc/
// reallocarray and the VLA path.
static Value *emitSaturatingMul(IRBuilder<> &B, Value *N, Value *S,
                                IntegerType *I64) {

  Value *uo = B.CreateIntrinsic(Intrinsic::umul_with_overflow, {I64}, {N, S});
  Value *prod = B.CreateExtractValue(uo, 0);
  Value *ovf = B.CreateExtractValue(uo, 1);
  Value *maxU = ConstantInt::get(I64, UINT64_MAX);
  return B.CreateSelect(ovf, maxU, prod);

}

static Value *inferBufferSizeValue(Value *V, IRBuilder<> &B,
                                   const DataLayout            &DL,
                                   const std::set<std::string> &customs) {

  SmallPtrSet<Value *, 16> visited;
  return inferBufferSizeValueImpl(V, B, DL, customs, visited);

}

static Value *inferBufferSizeValueImpl(Value *V, IRBuilder<> &B,
                                       const DataLayout            &DL,
                                       const std::set<std::string> &customs,
                                       SmallPtrSetImpl<Value *>    &visited) {

  IntegerType *I64 = IntegerType::getInt64Ty(B.getContext());
  if (!V) return nullptr;
  V = V->stripPointerCasts();
  // Peel through one level of spill (the optnone / -O0 idiom):
  //   p_slot = alloca ptr
  //   p = call malloc(sz)
  //   store p, p_slot        ; spill
  //   p2 = load p_slot       ; reload (this is V)
  //   foo(p2)
  // Only follow when every store to the alloca writes the same SSA value
  // (so the load is guaranteed to return that value) — null-init-then-
  // assign and other mixed-source spills bail out via the `multi` flag.
  //
  // The spill source can be any kind of value, not just a CallInst —
  // chained spills (clang at -O0 stores a PHI into an alloca, then
  // reloads it later) need to walk through the PHI on the recursive
  // call. Restricting to CallInst would silently drop those sites.
  if (auto *Ld = dyn_cast<LoadInst>(V)) {

    if (auto *AI = dyn_cast<AllocaInst>(Ld->getPointerOperand())) {

      Value *unique_src = nullptr;
      bool   multi = false;
      for (User *U : AI->users()) {

        auto *St = dyn_cast<StoreInst>(U);
        if (!St || St->getPointerOperand() != AI) continue;
        Value *sv = St->getValueOperand()->stripPointerCasts();
        if (unique_src && unique_src != sv) {

          multi = true;
          break;

        }

        unique_src = sv;

      }

      if (!multi && unique_src) V = unique_src;

    }

  }

  // PHI join: emit a PHI of the per-arm sizes if every arm yields a Value.
  // MIN semantics: pick the smallest reaching size so SIZEFILL flags writes
  // that exceed the smaller arm's buffer.
  if (auto *PN = dyn_cast<PHINode>(V)) {

    // Cycle guard: only block re-entry on the SAME PHI. Distinct PHIs
    // whose subtrees share a value are not cycles — they're DAG joins
    // and must be allowed to recurse independently.
    if (!visited.insert(PN).second) return nullptr;
    SmallVector<std::pair<Value *, BasicBlock *>, 4> arms;
    bool                                             ok = true;
    bool                                             all_const = true;
    uint64_t                                         min_const = UINT64_MAX;
    for (unsigned i = 0, e = PN->getNumIncomingValues(); i < e; ++i) {

      Value      *Inc = PN->getIncomingValue(i);
      BasicBlock *Pred = PN->getIncomingBlock(i);
      // Emit per-arm size at the END of the predecessor (just before its
      // terminator) so the value dominates the join point. This is safe
      // even when the arm's malloc/alloca is conditional: the per-arm
      // recursive call walks back to ITS malloc, which dominates the
      // terminator (it's in this same predecessor or an ancestor).
      IRBuilder<> PB(Pred->getTerminator());
      Value      *s = inferBufferSizeValueImpl(Inc, PB, DL, customs, visited);
      if (!s) {

        ok = false;
        break;

      }

      arms.push_back({s, Pred});
      auto *Ci = dyn_cast<ConstantInt>(s);
      if (Ci) {

        if (Ci->getZExtValue() < min_const) min_const = Ci->getZExtValue();

      } else {

        all_const = false;

      }

    }

    if (!ok || arms.empty()) return nullptr;
    if (all_const) return ConstantInt::get(I64, min_const);

    // Emit a PHI of sizes at the original PHI's location, sharing its
    // incoming-block structure. IRBuilder doesn't help here — direct
    // PHINode::Create lets us insert before all non-PHIs in the block.
    PHINode *NewPN =
        PHINode::Create(I64, (unsigned)arms.size(), "afl.bufsz.phi", PN);
#if LLVM_MAJOR >= 20
    NewPN->dropDbgRecords();
#endif
    for (auto &kv : arms)
      NewPN->addIncoming(kv.first, kv.second);
    return NewPN;

  }

  // Select join: same MIN semantics. If both arms have sizes (constant or
  // not), emit a Select choosing the smaller. Operands must dominate B's
  // insertion point — they always do if the arms came from sub-recursive
  // calls because those operate at B (or at earlier dominating positions).
  if (auto *Sel = dyn_cast<SelectInst>(V)) {

    if (!visited.insert(Sel).second) return nullptr;
    Value *st =
        inferBufferSizeValueImpl(Sel->getTrueValue(), B, DL, customs, visited);
    Value *sf =
        inferBufferSizeValueImpl(Sel->getFalseValue(), B, DL, customs, visited);
    if (!st || !sf) return nullptr;
    auto *Ct = dyn_cast<ConstantInt>(st);
    auto *Cf = dyn_cast<ConstantInt>(sf);
    if (Ct && Cf) {

      uint64_t m = std::min(Ct->getZExtValue(), Cf->getZExtValue());
      return ConstantInt::get(I64, m);

    }

    Value *isLt = B.CreateICmpULT(st, sf);
    return B.CreateSelect(isLt, st, sf);

  }

  if (auto *A = dyn_cast<AllocaInst>(V)) {

    Value   *arrSize = A->getArraySize();
    uint64_t eltBytes = DL.getTypeStoreSize(A->getAllocatedType());
    if (auto *Cst = dyn_cast<ConstantInt>(arrSize)) {

      // Saturate the constant fold too: arrSize * eltBytes overflowing
      // i64 would otherwise wrap silently to a tiny size and trip a
      // bogus SIZEFILL abort.
      __uint128_t prod =
          (__uint128_t)Cst->getZExtValue() * (__uint128_t)eltBytes;
      if (prod > (__uint128_t)UINT64_MAX)
        return ConstantInt::get(I64, UINT64_MAX);
      return ConstantInt::get(I64, (uint64_t)prod);

    }

    // Enhancement F: VLA / dynamic-sized alloca — emit `arrSize * eltBytes`.
    // arrSize dominates the alloca, which dominates any use of its result,
    // so emitting at B's position (a use-site) is dominance-safe.  Use the
    // saturating mul so an attacker-controlled arrSize that wraps the
    // product cannot synthesize a tiny "buffer size" and FP-abort.
    Value *n64 = B.CreateZExtOrTrunc(arrSize, I64);
    return emitSaturatingMul(B, n64, ConstantInt::get(I64, eltBytes), I64);

  }

  // Global with a constant-sized type (string literals, static arrays).
  if (auto *GV = dyn_cast<GlobalVariable>(V)) {

    if (GV->hasInitializer() && GV->getValueType()->isSized()) {

      uint64_t bytes = DL.getTypeAllocSize(GV->getValueType());
      return ConstantInt::get(I64, bytes);

    }

    return nullptr;

  }

  if (auto *Call = dyn_cast<CallInst>(V)) {

    Function *cf = Call->getCalledFunction();
    if (!cf) return nullptr;
    StringRef name = cf->getName();
    /* The size-arg is always integer; CreateZExtOrTrunc to i64. The arg's
       Value at the Call site dominates any use of the Call's return. */

    // Helper bound to this builder; emitSaturatingMul does the real work.
    auto satMul = [&](Value *N, Value *S) -> Value * {

      return emitSaturatingMul(B, N, S, I64);

    };

    // Single-size-arg allocators. The size arg index varies by ABI:
    //   arg0: malloc, __afl_track_malloc, operator new variants,
    //         strndup-arg-1 (handled separately), realloc-arg-1 (sep.)
    //   arg1: realloc family (ptr, size), strndup (str, n)
    //   arg-of-aligned-alloc: see below
    if ((name == "malloc" || name == "__afl_track_malloc" || name == "_Znwm" ||
         name == "_Znam" || name == "_Znwj" || name == "_Znaj") &&
        Call->arg_size() >= 1 &&
        Call->getArgOperand(0)->getType()->isIntegerTy()) {

      return B.CreateZExtOrTrunc(Call->getArgOperand(0), I64);

    }

    // C++17 aligned new — (size, align_val_t). Size is arg0.
    if ((name == "_ZnwmSt11align_val_t" || name == "_ZnamSt11align_val_t" ||
         name == "_ZnwjSt11align_val_t" || name == "_ZnajSt11align_val_t") &&
        Call->arg_size() >= 2 &&
        Call->getArgOperand(0)->getType()->isIntegerTy()) {

      return B.CreateZExtOrTrunc(Call->getArgOperand(0), I64);

    }

    // __afl_track_aligned_alloc signature: (size, align, id). Size = arg0.
    if (name == "__afl_track_aligned_alloc" && Call->arg_size() >= 3 &&
        Call->getArgOperand(0)->getType()->isIntegerTy()) {

      return B.CreateZExtOrTrunc(Call->getArgOperand(0), I64);

    }

    // C11 aligned_alloc(align, size). Size = arg1.
    if (name == "aligned_alloc" && Call->arg_size() >= 2 &&
        Call->getArgOperand(1)->getType()->isIntegerTy()) {

      return B.CreateZExtOrTrunc(Call->getArgOperand(1), I64);

    }

    // posix_memalign(memptr, align, size): size = arg2. The tracked
    // variant matches the same shape but with a trailing id arg.
    if ((name == "posix_memalign" || name == "__afl_track_posix_memalign") &&
        Call->arg_size() >= 3 &&
        Call->getArgOperand(2)->getType()->isIntegerTy()) {

      return B.CreateZExtOrTrunc(Call->getArgOperand(2), I64);

    }

    if ((name == "calloc" || name == "__afl_track_calloc") &&
        Call->arg_size() >= 2 &&
        Call->getArgOperand(0)->getType()->isIntegerTy() &&
        Call->getArgOperand(1)->getType()->isIntegerTy()) {

      Value *N = B.CreateZExtOrTrunc(Call->getArgOperand(0), I64);
      Value *S = B.CreateZExtOrTrunc(Call->getArgOperand(1), I64);
      return satMul(N, S);

    }

    if ((name == "realloc" || name == "__afl_track_realloc") &&
        Call->arg_size() >= 2 &&
        Call->getArgOperand(1)->getType()->isIntegerTy()) {

      return B.CreateZExtOrTrunc(Call->getArgOperand(1), I64);

    }

    // reallocarray(ptr, nmemb, size): NEW size = nmemb*size (saturated).
    if ((name == "reallocarray" || name == "__afl_track_reallocarray") &&
        Call->arg_size() >= 3 &&
        Call->getArgOperand(1)->getType()->isIntegerTy() &&
        Call->getArgOperand(2)->getType()->isIntegerTy()) {

      Value *N = B.CreateZExtOrTrunc(Call->getArgOperand(1), I64);
      Value *S = B.CreateZExtOrTrunc(Call->getArgOperand(2), I64);
      return satMul(N, S);

    }

    // strndup(s, n): result is at most n+1 bytes (includes NUL). Worst
    // case for buffer-size inference.
    if ((name == "strndup" || name == "__afl_track_strndup") &&
        Call->arg_size() >= 2 &&
        Call->getArgOperand(1)->getType()->isIntegerTy()) {

      Value *n = B.CreateZExtOrTrunc(Call->getArgOperand(1), I64);
      return B.CreateAdd(n, ConstantInt::get(I64, 1));

    }

    // User-listed custom allocators (AFL_LLVM_BUG_ALLOCSIZE_FUNCS).
    // The ALLOCSIZE block picks the widest integer arg as the size;
    // mirror that heuristic here so SIZEFILL recognizes a buf
    // allocated by `MyAlloc(n)` and can range-check writes against it.
    if (!customs.empty() && customs.count(name.str())) {

      Value   *sizeArg = nullptr;
      unsigned bestBits = 0;
      for (unsigned i = 0; i < Call->arg_size(); ++i) {

        auto *AIT = dyn_cast<IntegerType>(Call->getArgOperand(i)->getType());
        if (!AIT) continue;
        if (AIT->getBitWidth() >= bestBits) {

          bestBits = AIT->getBitWidth();
          sizeArg = Call->getArgOperand(i);

        }

      }

      if (sizeArg) return B.CreateZExtOrTrunc(sizeArg, I64);

    }

  }

  return nullptr;

}

bool runSizefillMode(Module             &M, ModuleAnalysisManager &,
                     const BugPassState &S) {

  LLVMContext &C = M.getContext();
  Type        *VoidTy = Type::getVoidTy(C);
  IntegerType *I64 = IntegerType::getInt64Ty(C);
#if LLVM_MAJOR >= 20
  Type *PtrTy = PointerType::getUnqual(C);
#else
  Type *PtrTy = PointerType::get(IntegerType::getInt8Ty(C), 0);
#endif

  FunctionCallee sfCheck = M.getOrInsertFunction("__afl_bug_sizefill_check",
                                                 VoidTy, PtrTy, I64, I64);
  markBugHookAttrs(sfCheck);
  // sfBegin takes (ptr, size) so the runtime can range-check every
  // store as `addr < base + size`.  A bare `addr >= base` check
  // would pollute a tracked buffer's max-off with writes through
  // unrelated higher-address buffers.
  FunctionCallee sfBegin =
      M.getOrInsertFunction("__afl_bug_sf_begin", VoidTy, PtrTy, I64);
  markBugHookAttrs(sfBegin);
  FunctionCallee sfStore = M.getOrInsertFunction(
      "__afl_bug_sf_store", VoidTy, PtrTy, IntegerType::getInt32Ty(C));
  markBugHookAttrs(sfStore);

  // 1) Find sentinel-param functions in this module. Each may declare its
  // size either via the integer return value (legacy path) or via a
  // pointer-to-integer output argument (the very common
  // `int parse(buf, len, &out_size)` idiom — invisible to the
  // integer-return-only check).
  std::map<Function *, SentinelDesc> sentinel;
  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    int idx = findSentinelParam(F);
    if (idx < 0) continue;
    int  out_idx = -1;
    int  out_bits = 0;
    bool out_is_inout = false;
    bool return_size_ok = false;
    if (F.getReturnType()->isIntegerTy()) {

      auto    *RT = cast<IntegerType>(F.getReturnType());
      unsigned ret_bits = RT->getBitWidth();
      if (ret_bits >= 16 && ret_bits <= 64 &&
          functionHasStoreThroughArg(F, (unsigned)idx))
        return_size_ok = true;

    }

    // Prefer output-param convention when present, even for integer-
    // returning functions. Many real APIs return an int status and write the
    // size through `size_t *out`; treating the status as a size causes both
    // false positives (errno/status > buffer size) and false negatives
    // (status 0 while *out reports overflow).
    out_idx = findOutSizeParam(F, idx, &out_bits, &out_is_inout);
    if (out_idx < 0 && !return_size_ok) continue;

    sentinel[&F] = {idx, out_idx, out_bits, out_is_inout};

  }

  if (sentinel.empty()) {

    if (getenv("AFL_QUIET") == nullptr)
      errs() << "[afl-bug] SIZEFILL: no sentinel-param functions found\n";
    return false;

  }

  // 2) For every call to such a function with a non-null pointer arg whose
  // buffer size we can infer, instrument sf_begin + post-call check, and
  // mark the callee for store-instrumentation.
  bool     changed = false;
  unsigned instrumented = 0;
  bool     dump_summary = getenv(AFL_BUG_ENV_DUMP_SUMMARY) != nullptr;
  std::map<Function *, uint32_t> per_func_sites;
  // Per-callee set of arg indices that are sentinel-traced.  Stores
  // in the callee only count toward the SIZEFILL max-off if they
  // reach one of these specific args; the callee's own write to
  // *out_size doesn't get counted against the buffer's frame.
  std::map<Function *, std::set<unsigned>> callee_sentinel_args;
  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    for (BasicBlock &BB : F) {

      for (Instruction &I : BB) {

        auto *Call = dyn_cast<CallBase>(&I);
        if (!Call || (!isa<CallInst>(Call) && !isa<InvokeInst>(Call))) continue;
        Function *cf = Call->getCalledFunction();
        if (!cf) continue;
        auto it = sentinel.find(cf);
        if (it == sentinel.end()) continue;
        unsigned pi = (unsigned)it->second.sentinel_idx;
        int      oi = it->second.out_size_idx;
        int      obits = it->second.out_size_bits;
        bool     is_inout = it->second.out_is_inout;
        if (pi >= Call->arg_size()) continue;
        Value *p = Call->getArgOperand(pi);
        if (isa<ConstantPointerNull>(p->stripPointerCasts())) continue;

        IRBuilder<> Pre(Call);
        inheritDebugLoc(Pre, Call);
        Value *bufsz =
            inferBufferSizeValue(p, Pre, M.getDataLayout(), S.custom_allocs);
        if (!bufsz) continue;

        // Defensively zero the out-param BEFORE the call.  If the
        // callee returns early without writing it (an internal error
        // path), the post-call load would otherwise pick up garbage
        // from the caller's stack and almost certainly trip the
        // SIZEFILL abort.  Zero is the only safe pre-call value: it
        // under-reports rather than over-reports, so any abort signal
        // is real.  Zero at the exact width discovered by
        // findOutSizeParam to avoid clobbering a neighboring field.
        //
        // CRITICAL: skip the zero when the callee reads through this
        // arg (in/out semantics). Some APIs pass a max-size or hint via
        // the same pointer the function later writes its actual count
        // into; zeroing that destroys the input. `out_is_inout` is set
        // by findOutSizeParam when any LoadInst through the arg or its
        // spill-loads is detected. Conservative — false negatives on
        // "wrote but also dead-loaded" are preferable to clobbering a
        // legitimate input.
        if (oi >= 0 && (unsigned)oi < Call->arg_size() &&
            Call->getArgOperand(oi)->getType()->isPointerTy() && obits > 0 &&
            !is_inout) {

          IntegerType *outTy = IntegerType::get(C, (unsigned)obits);
          Type        *outPtrTy = pointerTyTo(C, outTy);
          Value       *outPtrZ =
              Pre.CreateBitOrPointerCast(Call->getArgOperand(oi), outPtrTy);
          Pre.CreateAlignedStore(ConstantInt::get(outTy, 0), outPtrZ,
                                 llvm::MaybeAlign(1));

        }

        Value *ptrCast = castToPtrTy(Pre, p, PtrTy);
        Pre.CreateCall(sfBegin, {ptrCast, bufsz});

        Instruction *PostAt = postCallInsertionPoint(Call, C, ".sizefill.edge");
        if (!PostAt) continue;
        IRBuilder<> Post(PostAt);
        inheritDebugLoc(Post, Call);
        // Source the returned-size value: from the integer return if
        // out_idx < 0, otherwise by loading through the out-param at
        // the EXACT width discovered.  Loading wider than the pointee
        // reads adjacent caller-stack garbage.
        Value *ret64 = nullptr;
        if (oi < 0) {

          ret64 = Post.CreateZExtOrTrunc(Call, I64);

        } else if ((unsigned)oi < Call->arg_size() &&

                   Call->getArgOperand(oi)->getType()->isPointerTy() &&
                   obits > 0) {

          Value       *outPtr = Call->getArgOperand(oi);
          IntegerType *outIntTy = IntegerType::get(C, (unsigned)obits);
          Type        *outPtrTy = pointerTyTo(C, outIntTy);
          Value       *castPtr = Post.CreateBitOrPointerCast(outPtr, outPtrTy);
          Value       *narrow = Post.CreateAlignedLoad(
              outIntTy, castPtr, llvm::MaybeAlign(1), "afl.sf.outsize");
          ret64 = Post.CreateZExtOrTrunc(narrow, I64);

        } else {

          continue;

        }

        Value *pcast = castToPtrTy(Post, p, PtrTy);
        Post.CreateCall(sfCheck, {pcast, ret64, bufsz});
        ++instrumented;
        callee_sentinel_args[cf].insert(pi);
        changed = true;
        if (dump_summary) ++per_func_sites[&F];

      }

    }

  }

  // Instrument stores in candidate callees: only stores that reach
  // the sentinel arg (the buffer), NOT every pointer arg.  The
  // callee's own write to *out_size, *status, etc. would otherwise
  // be counted against the buffer's max-off and trip a false-positive
  // abort.  Honor the user's instrument-list blocklist on the callee
  // too — otherwise excluded code still gets its stores instrumented
  // when it happens to be a sentinel callee.
  IntegerType *I32 = IntegerType::getInt32Ty(C);
  for (auto &kv : callee_sentinel_args) {

    Function                 *F = kv.first;
    const std::set<unsigned> &args = kv.second;
    // SIZEFILL caps every recorded write by sf_cap (buffer end + slack),
    // so bounded-libc over-reporting cannot cause an FP — accept the
    // wider model.
    instrumentArgReachingStores(*F, sfStore, args, PtrTy, I32,
                                M.getDataLayout(),
                                /*libc_exact_only=*/false);

  }

  if (getenv("AFL_QUIET") == nullptr)
    errs() << "[afl-bug] SIZEFILL instrumented " << instrumented
           << " call sites across " << sentinel.size() << " callees\n";
  if (dump_summary) {

    for (auto &kv : per_func_sites)
      errs() << "[afl-bug-summary] SIZEFILL " << kv.first->getName()
             << " sites=" << kv.second << "\n";

  }

  return changed;

}

// SLACK mode: at every integer ICmpInst, compute |op1 - op2| and feed it
// to the runtime as a per-site IJON-Min channel. Inputs that simultaneously
// minimize slack on multiple predicates (the "tight intersection") are
// promoted by the queue scheduler. Directly addresses chained-validator
// patterns like libwebp's `count[len] <= (1 << len)`, `num_open >= 0`,
// `num_nodes == 2*offset[15]-1` — the triggering input sits at the tight
// edge of all four simultaneously, and edge-coverage alone cannot
// distinguish "barely passed" from "passed with room to spare".
bool runSlackMode(Module &M, ModuleAnalysisManager &, const BugPassState &S) {

  (void)S;
  LLVMContext &C = M.getContext();
  Type        *VoidTy = Type::getVoidTy(C);
  IntegerType *I32 = IntegerType::getInt32Ty(C);
  IntegerType *I64 = IntegerType::getInt64Ty(C);

  FunctionCallee slackHook =
      M.getOrInsertFunction("__afl_bug_slack_min", VoidTy, I32, I64);
  markBugHookAttrs(slackHook);

  uint32_t sites = 0;
  bool     changed = false;
  bool     dump_summary = getenv(AFL_BUG_ENV_DUMP_SUMMARY) != nullptr;
  std::map<Function *, uint32_t> per_func_sites;

  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    uint32_t pf_start = sites;

    // Collect first, instrument afterwards — avoid the iterator visiting
    // our own inserted Sub/Neg/Select instructions. Keep SLACK even when
    // SCALAR is also enabled: SCALAR's growth signal and SLACK's distance-
    // to-constant signal are complementary, especially for equality checks.

    std::vector<ICmpInst *>   targets;
    std::vector<FCmpInst *>   fp_targets;
    std::vector<SwitchInst *> sw_targets;
    for (BasicBlock &BB : F) {

      for (Instruction &I : BB) {

        // SwitchInst: clang emits `switch` rather than a chain of
        // icmps for dispatchers larger than a few cases.  Without
        // coverage here a 256-case opcode parser gets zero
        // "near magic value" gradient.  Computes `|cond - case_i|`
        // per case below.
        if (auto *SW = dyn_cast<SwitchInst>(&I)) {

          Type *CT = SW->getCondition()->getType();
          auto *IT = dyn_cast<IntegerType>(CT);
          if (!IT) continue;
          if (IT->getBitWidth() < 8 || IT->getBitWidth() > 64) continue;
          if (SW->getNumCases() == 0) continue;  // unreachable / default-only
          sw_targets.push_back(SW);
          continue;

        }

        if (auto *Cmp = dyn_cast<ICmpInst>(&I)) {

          Type *OpTy = Cmp->getOperand(0)->getType();
          // Allow pointer ICmps so parsers using `if (p == sentinel)`
          // or `if (p < end)` get a slack gradient.  Vector compares
          // stay unsupported (slack semantics don't lift cleanly to
          // vectors).  Pointer compares are ptrtoint'd at emit time.
          auto *IT = dyn_cast<IntegerType>(OpTy);
          bool  is_ptr_cmp = !IT && OpTy->isPointerTy();
          if (!IT && !is_ptr_cmp) continue;
          // Accept i128 too (crypto code: curve arithmetic, big-int
          // comparisons).  The i128 distance is truncated to i64 with
          // a saturating sticky-bit: if the high 64 bits are non-zero,
          // slack is saturated to UINT64_MAX (= MIN bucket = no
          // signal); else the low 64 bits carry the real gradient.
          if (IT && (IT->getBitWidth() < 8 || IT->getBitWidth() > 128))
            continue;
          // Skip if both operands constant — optimizer would fold; defensive.
          // For pointer compares this also drops `p == NULL` against another
          // null — same intent.
          if (isa<Constant>(Cmp->getOperand(0)) &&
              isa<Constant>(Cmp->getOperand(1)))
            continue;
          targets.push_back(Cmp);
          continue;

        }

        // Enhancement D: FP comparisons. Image/audio codecs and ML
        // inference do tight FP comparisons that are blind to the integer
        // SLACK channel. Float/double only — vectors and other FP types
        // (half/bfloat/x86_fp80) skipped to keep the extension simple
        // and the slack semantics meaningful at f64 precision.
        if (auto *FCmp = dyn_cast<FCmpInst>(&I)) {

          Type *FT = FCmp->getOperand(0)->getType();
          if (!FT->isFloatTy() && !FT->isDoubleTy()) continue;
          // Ordered/unordered: instrument both. NaN-containing operands
          // produce NaN slack, which fptoui rounds to a defined large
          // value below — acceptable; NaN-producing inputs are typically
          // interesting anyway.
          if (isa<Constant>(FCmp->getOperand(0)) &&
              isa<Constant>(FCmp->getOperand(1)))
            continue;
          fp_targets.push_back(FCmp);

        }

      }

    }

    StringRef func_name = F.getName();
    uint32_t  site_idx = 0;
    for (ICmpInst *Cmp : targets) {

      IRBuilder<> B(Cmp);
      inheritDebugLoc(B, Cmp);
      Value *Op0 = Cmp->getOperand(0);
      Value *Op1 = Cmp->getOperand(1);

      // Pointer compares get ptrtoint'd to i64 and treated as unsigned
      // distance.  Heap addresses are within a single 47-bit user
      // range on Linux/x86_64 and the unsigned subtraction is the
      // natural "byte-distance" gradient.  Pointer ICmps never use
      // signed predicates in C, and SExt-defined inference doesn't
      // apply to pointers, so we shortcut directly to the unsigned
      // path.
      if (Op0->getType()->isPointerTy() || Op1->getType()->isPointerTy()) {

        Value   *Op0_64 = B.CreatePtrToInt(Op0, I64);
        Value   *Op1_64 = B.CreatePtrToInt(Op1, I64);
        Value   *lt = B.CreateICmpULT(Op0_64, Op1_64);
        Value   *small = B.CreateSelect(lt, Op0_64, Op1_64);
        Value   *large = B.CreateSelect(lt, Op1_64, Op0_64);
        Value   *slack = B.CreateSub(large, small);
        uint32_t id = siteSlotId(func_name, site_idx++, BUG_MODE_SALT_SLACK);
        B.CreateCall(slackHook, {ConstantInt::get(I32, id), slack});
        ++sites;
        changed = true;
        continue;

      }

      // Sign-extend for signed predicates, zero-extend for unsigned /
      // equality. The choice is load-bearing here: a naive `|diff|` via
      // select-on-sign breaks for i64 unsigned operands whose true
      // distance saturates the sign bit (e.g. 0xFFFF.. vs 0 has signed
      // value −1, neg → 1, but the actual distance is 0xFFFF..). Use the
      // predicate's signedness to pick the subtraction ORDER instead —
      // branch-free, correct at every width, no overflow on the result
      // because `large - small` of same-width nonneg-in-domain values
      // never wraps.
      //
      // Enhancement C: for EQ/NE (which carry no signedness in LLVM)
      // infer signedness from the operand-defining instructions. If
      // either operand is a SExt result, treat the comparison as signed
      // so a tight "-1 vs 0" distance shows as slack=1, not slack≈2^32.
      // Detection: walk through one bitcast (opaque pointers don't
      // affect this), look at the defining SExtInst.
      auto isSExtDefined = [](Value *V) -> bool {

        V = V->stripPointerCasts();
        return isa<SExtInst>(V);

      };

      bool signed_mode = Cmp->isSigned();
      if (Cmp->isEquality() && (isSExtDefined(Op0) || isSExtDefined(Op1))) {

        signed_mode = true;

      }

      // Compute slack at the operand's native width when it exceeds
      // i64 (i.e. i128).  The hook takes an i64 so we truncate; a
      // non-zero high half saturates to UINT64_MAX (= MIN bucket =
      // no-signal, won't overwrite a tight match from another path).
      Type *NativeTy = Op0->getType();
      bool  wide = NativeTy->isIntegerTy() &&
                  cast<IntegerType>(NativeTy)->getBitWidth() > 64;
      Value *Op0_n, *Op1_n;
      Value *lt;
      if (wide) {

        // Always zext for wide-mode and use unsigned ordering; signed
        // i128 distance isn't a common pattern and the unsigned bucket
        // collapses sign-mismatched cases to the saturated bucket
        // which is the conservative "no signal" choice.
        Op0_n = B.CreateZExtOrTrunc(Op0, NativeTy);
        Op1_n = B.CreateZExtOrTrunc(Op1, NativeTy);
        lt = B.CreateICmpULT(Op0_n, Op1_n);

      } else if (signed_mode) {

        Op0_n = B.CreateSExtOrTrunc(Op0, I64);
        Op1_n = B.CreateSExtOrTrunc(Op1, I64);
        lt = B.CreateICmpSLT(Op0_n, Op1_n);

      } else {

        Op0_n = B.CreateZExtOrTrunc(Op0, I64);
        Op1_n = B.CreateZExtOrTrunc(Op1, I64);
        lt = B.CreateICmpULT(Op0_n, Op1_n);

      }

      Value *small = B.CreateSelect(lt, Op0_n, Op1_n);
      Value *large = B.CreateSelect(lt, Op1_n, Op0_n);
      Value *slack_n = B.CreateSub(large, small);
      Value *slack;
      if (wide) {

        // Truncate to i64 with sticky saturation: if any high bit is
        // set, force slack to UINT64_MAX.
        Value *lo = B.CreateTrunc(slack_n, I64);
        Value *hi = B.CreateTrunc(
            B.CreateLShr(slack_n, ConstantInt::get(NativeTy, 64)), I64);
        Value *anyHi = B.CreateICmpNE(hi, ConstantInt::get(I64, 0));
        slack = B.CreateSelect(anyHi, ConstantInt::get(I64, (uint64_t)-1), lo);

      } else {

        slack = slack_n;

      }

      // Pass-side hash. With a 16K-slot map and many sites per TU, the
      // old `next_id++ & MASK` produced deterministic wrap-collisions
      // (sites K and K + 16384 always shared a slot). siteSlotId mixes
      // function name + index + mode salt so collisions are spread,
      // and id=0 in SLACK no longer collapses to SCALAR's slot 0.
      uint32_t id = siteSlotId(func_name, site_idx++, BUG_MODE_SALT_SLACK);
      B.CreateCall(slackHook, {ConstantInt::get(I32, id), slack});
      ++sites;
      changed = true;

    }

    // Enhancement D: FP slack. Compute |fpext(a) - fpext(b)| at f64,
    // SCALE by 2^20 to retain ~20 bits of sub-unit precision, then
    // convert to i64 via a saturating fptoui. Without scaling,
    // fptoui_sat truncates any |diff| in [0, 1) to 0 — `0.0 == 0.0`
    // and `0.0 vs 0.5` would both produce slack=0 and inv=64 (max
    // bucket), erasing the gradient near zero that fuzzing needs.
    //
    // Scale factor 2^20 (= 1 << 20) chosen so:
    //   - |diff| = 1.0   → slack = 2^20         (log_slack = 21)
    //   - |diff| = 0.5   → slack = 524288       (log_slack = 20)
    //   - |diff| = 1e-6  → slack = 1            (log_slack = 1)
    //   - |diff| = 0.0   → slack = 0            (log_slack = 0)
    // Distinct bucket values across the sub-unit range while keeping
    // large |diff| (up to ~2^44) within i64 range pre-saturation.
    //
    // NaN handling is the load-bearing detail here: LLVM's
    // `llvm.fptoui.sat.i64.f64` returns **0** on NaN — feeding 0 to
    // slackHook would put the slot at its MAX inv bucket (tight
    // match), drowning real-signal updates. Detect NaN via `fcmp uno`
    // and substitute UINT64_MAX so the slack hook's MAX update rule
    // treats NaN as "no signal" (inv = 0, no overwrite).
    Type     *F64 = Type::getDoubleTy(C);
    Constant *u64_max = ConstantInt::get(I64, (uint64_t)-1);
    Constant *scale = ConstantFP::get(F64, (double)(1u << 20));
    for (FCmpInst *FCmp : fp_targets) {

      IRBuilder<> B(FCmp);
      inheritDebugLoc(B, FCmp);
      Value *Op0 = FCmp->getOperand(0);
      Value *Op1 = FCmp->getOperand(1);
      Value *Op0d = (Op0->getType() == F64) ? Op0 : B.CreateFPExt(Op0, F64);
      Value *Op1d = (Op1->getType() == F64) ? Op1 : B.CreateFPExt(Op1, F64);
      Value *diff = B.CreateFSub(Op0d, Op1d);
      // |diff| via FAbs intrinsic (well-supported across LLVM versions).
      Value *absD = B.CreateUnaryIntrinsic(Intrinsic::fabs, diff);
      // NaN test BEFORE the saturating cast — `fcmp uno x, x` is true
      // iff x is NaN (relies only on the standard floating-point
      // unordered semantics, no target intrinsic needed).
      Value *isNaN = B.CreateFCmpUNO(absD, absD);
      // Scale to preserve sub-unit precision, then saturating cast.
      // FMul of NaN stays NaN; that's still caught by isNaN above.
      Value *scaled = B.CreateFMul(absD, scale);
      Value *slack_sat =
          B.CreateIntrinsic(Intrinsic::fptoui_sat, {I64, F64}, {scaled});
      Value   *slack_fp = B.CreateSelect(isNaN, u64_max, slack_sat);
      uint32_t id = siteSlotId(func_name, site_idx++, BUG_MODE_SALT_SLACK);
      B.CreateCall(slackHook, {ConstantInt::get(I32, id), slack_fp});
      ++sites;
      changed = true;

    }

    // SwitchInst slack: for each case, emit `|cond - case_i|` as a
    // separate hook with its own site id.  Each case has the same
    // MIN-disguised-as-MAX semantics as an ICmp EQ — an input that
    // approaches one of the cases lights up that case's slot.
    // Multiple simultaneously-tight cases produce a richer gradient
    // than a single shared site.
    //
    // Unsigned distance: switch cases in LLVM IR are always integer
    // constants and the case value's signedness is opaque (no signed/
    // unsigned bit on `switch`). We use unsigned ordered subtraction —
    // a tight EQ produces slack=0 regardless of signedness.
    //
    // Cost: one hook per case per switch site. A 256-case dispatcher
    // adds 256 hooks — the same dispatcher pattern an icmp-chain
    // pass would miss entirely.
    for (SwitchInst *SW : sw_targets) {

      Value      *Cond = SW->getCondition();
      IRBuilder<> B(SW);
      inheritDebugLoc(B, SW);
      Value *Cond_64 = B.CreateZExtOrTrunc(Cond, I64);
      for (auto It = SW->case_begin(), E = SW->case_end(); It != E; ++It) {

        ConstantInt *CaseV = It->getCaseValue();
        Value       *CV64 = ConstantInt::get(I64, CaseV->getZExtValue());
        // |Cond - CaseV| via unsigned ordered subtraction.
        Value   *lt = B.CreateICmpULT(Cond_64, CV64);
        Value   *small = B.CreateSelect(lt, Cond_64, CV64);
        Value   *large = B.CreateSelect(lt, CV64, Cond_64);
        Value   *slack = B.CreateSub(large, small);
        uint32_t id = siteSlotId(func_name, site_idx++, BUG_MODE_SALT_SLACK);
        B.CreateCall(slackHook, {ConstantInt::get(I32, id), slack});
        ++sites;

      }

      changed = true;

    }

    // `*.with.overflow.*` flag bit (extractvalue index 1).  SCALAR
    // covers the value (index 0); the flag is an i1 binary signal —
    // "did this arithmetic overflow?" — that fuzzers want as
    // dedicated coverage.  Encode as a SLACK slot so an overflow
    // (flag=1) → slack=0 → inv=64 (max bucket = tightest match),
    // and no-overflow (flag=0) → slack=UINT64_MAX → inv=0 (no
    // overwrite).  An input that newly triggers overflow at a site
    // dominates the slot.
    auto isOverflowIntrinsicS = [](Intrinsic::ID iid) -> bool {

      switch (iid) {

        case Intrinsic::uadd_with_overflow:
        case Intrinsic::sadd_with_overflow:
        case Intrinsic::usub_with_overflow:
        case Intrinsic::ssub_with_overflow:
        case Intrinsic::umul_with_overflow:
        case Intrinsic::smul_with_overflow:
          return true;
        default:
          return false;

      }

    };

    for (BasicBlock &BB : F) {

      for (Instruction &I : BB) {

        auto *EV = dyn_cast<ExtractValueInst>(&I);
        if (!EV) continue;
        if (EV->getNumIndices() != 1 || EV->getIndices()[0] != 1) continue;
        auto *Call = dyn_cast<IntrinsicInst>(EV->getAggregateOperand());
        if (!Call || !isOverflowIntrinsicS(Call->getIntrinsicID())) continue;
        if (!EV->getType()->isIntegerTy(1)) continue;
        IRBuilder<> B(EV->getNextNode());
        inheritDebugLoc(B, EV);
        Value   *u64_max = ConstantInt::get(I64, (uint64_t)-1);
        Value   *zero = ConstantInt::get(I64, 0);
        Value   *slack = B.CreateSelect(EV, zero, u64_max);
        uint32_t id = siteSlotId(func_name, site_idx++, BUG_MODE_SALT_SLACK);
        B.CreateCall(slackHook, {ConstantInt::get(I32, id), slack});
        ++sites;
        changed = true;

      }

    }

    if (dump_summary && sites > pf_start) per_func_sites[&F] = sites - pf_start;

  }

  if (getenv("AFL_QUIET") == nullptr)
    errs() << "[afl-bug] SLACK instrumented " << sites << " icmp sites\n";
  if (dump_summary) {

    for (auto &kv : per_func_sites)
      errs() << "[afl-bug-summary] SLACK " << kv.first->getName()
             << " sites=" << kv.second << "\n";

  }

  return changed;

}

// Allocator-call rewrite kinds. Each kind encodes the libc/ABI signature
// shape (arg count, arg types) and which runtime hook to dispatch to.
enum class AllocKind : uint8_t {

  Malloc,            // size_t                                   -> ptr
  Calloc,            // size_t nmemb, size_t size                -> ptr
  Realloc,           // ptr, size_t                              -> ptr
  PosixMemalign,     // ptr*, size_t align, size_t size          -> int
  AlignedAlloc,      // size_t align, size_t size                -> ptr (C11)
  Free,              // ptr                                      -> void
  AlignedNew,        // size_t size, align_val_t                 -> ptr (C++17)
  AlignedDelete,     // ptr, align_val_t                         -> void
  SizedFree,         // ptr, size_t                              -> void (C++14)
  SizedAlignedFree,  // ptr, size_t, align_val_t                 -> void
  NothrowNew,        // size_t, const nothrow_t&                 -> ptr
  NothrowDelete,     // ptr, const nothrow_t&                    -> void
  AlignedNothrowNew,     // size_t, align_val_t, const nothrow_t&    -> ptr
  AlignedNothrowDelete,  // ptr, align_val_t, const nothrow_t&    -> void
  Strdup,                // const char*                              -> ptr
  Strndup,               // const char*, size_t                      -> ptr
  Reallocarray,          // ptr, size_t, size_t                      -> ptr

};

struct AllocRewriteSpec {

  StringRef libc;
  StringRef tracked;
  AllocKind kind;

};

// Itanium C++ ABI (Linux/macOS) operator new/delete routed through the
// same malloc/free runtime hooks; signatures match (size_t -> ptr,
// ptr -> void).
//
// SEMANTICS NOTE: the *throwing* operator new (_Znwm/_Znam et al.) is
// replaced with __afl_track_malloc, which returns NULL on allocator
// failure rather than throwing std::bad_alloc. C++ code that assumes
// `new` never returns NULL will null-deref under fuzzer-triggered OOM —
// generally fine for fuzzing (more crashes = more signal) but a real
// observable behavior change. Build with -fno-exceptions for cleanest
// matching, or disable AFL_LLVM_BUG_ALLOCSIZE for production-mode runs.
//
// MSVC mangling is included so Windows targets get the same coverage as
// Itanium. _K is size_t on x64; I is uint on x86.
static const AllocRewriteSpec kRewriteSpecs[] = {

    {"malloc", "__afl_track_malloc", AllocKind::Malloc},
    {"calloc", "__afl_track_calloc", AllocKind::Calloc},
    {"realloc", "__afl_track_realloc", AllocKind::Realloc},
    {"reallocarray", "__afl_track_reallocarray", AllocKind::Reallocarray},
    {"posix_memalign", "__afl_track_posix_memalign", AllocKind::PosixMemalign},
    {"aligned_alloc", "__afl_track_aligned_alloc", AllocKind::AlignedAlloc},
    {"free", "__afl_track_free", AllocKind::Free},
    {"strdup", "__afl_track_strdup", AllocKind::Strdup},
    {"strndup", "__afl_track_strndup", AllocKind::Strndup},
    // Itanium C++ ABI.
    {"_Znwm", "__afl_track_malloc", AllocKind::Malloc},
    {"_Znam", "__afl_track_malloc", AllocKind::Malloc},
    {"_Znwj", "__afl_track_malloc", AllocKind::Malloc},       /* 32-bit ABI */
    {"_Znaj", "__afl_track_malloc", AllocKind::Malloc},
    {"_ZdlPv", "__afl_track_free", AllocKind::Free},
    {"_ZdaPv", "__afl_track_free", AllocKind::Free},
    // C++14 sized delete: (ptr, size_t). Hand off as plain free (size arg
    // is advisory for allocator hint only).
    {"_ZdlPvm", "__afl_track_free", AllocKind::SizedFree},
    {"_ZdaPvm", "__afl_track_free", AllocKind::SizedFree},
    {"_ZdlPvj", "__afl_track_free", AllocKind::SizedFree},        /* 32-bit */
    {"_ZdaPvj", "__afl_track_free", AllocKind::SizedFree},
    // C++17 aligned new / delete. Routed to __afl_track_aligned_alloc
    // (posix_memalign-backed) so the alignment contract is preserved;
    // rewriting to plain malloc would hand out an under-aligned buffer
    // and any SIMD/over-aligned access would fault, manufacturing
    // crashes that don't reflect real bugs in the target.
    {"_ZnwmSt11align_val_t", "__afl_track_aligned_alloc",
     AllocKind::AlignedNew},
    {"_ZnamSt11align_val_t", "__afl_track_aligned_alloc",
     AllocKind::AlignedNew},
    {"_ZnwjSt11align_val_t", "__afl_track_aligned_alloc",
     AllocKind::AlignedNew},
    {"_ZnajSt11align_val_t", "__afl_track_aligned_alloc",
     AllocKind::AlignedNew},
    {"_ZdlPvSt11align_val_t", "__afl_track_free", AllocKind::AlignedDelete},
    {"_ZdaPvSt11align_val_t", "__afl_track_free", AllocKind::AlignedDelete},
    // Sized + aligned delete (C++17).
    {"_ZdlPvmSt11align_val_t", "__afl_track_free", AllocKind::SizedAlignedFree},
    {"_ZdaPvmSt11align_val_t", "__afl_track_free", AllocKind::SizedAlignedFree},
    {"_ZdlPvjSt11align_val_t", "__afl_track_free", AllocKind::SizedAlignedFree},
    {"_ZdaPvjSt11align_val_t", "__afl_track_free", AllocKind::SizedAlignedFree},
    // MSVC mangling. x64 (_K = size_t = u64), x86 (I = uint = u32).
    {"??2@YAPEAX_K@Z", "__afl_track_malloc", AllocKind::Malloc}, /* new   x64 */
    {"??_U@YAPEAX_K@Z", "__afl_track_malloc",
     AllocKind::Malloc},                                        /* new[] x64 */
    {"??2@YAPAXI@Z", "__afl_track_malloc", AllocKind::Malloc},  /* new   x86 */
    {"??_U@YAPAXI@Z", "__afl_track_malloc", AllocKind::Malloc}, /* new[] x86 */
    {"??3@YAXPEAX@Z", "__afl_track_free", AllocKind::Free},     /* del   x64 */
    {"??_V@YAXPEAX@Z", "__afl_track_free", AllocKind::Free},    /* del[] x64 */
    {"??3@YAXPAX@Z", "__afl_track_free", AllocKind::Free},      /* del   x86 */
    {"??_V@YAXPAX@Z", "__afl_track_free", AllocKind::Free},     /* del[] x86 */

    // glibc internal symbols (visible in thinLTO and direct-bind
    // builds), legacy POSIX allocators, and nothrow C++ ABI overloads.

    // glibc internal allocator names (sometimes called directly by libc
    // itself in static-linked targets or by user code that uses dlsym).
    {"__libc_malloc", "__afl_track_malloc", AllocKind::Malloc},
    {"__libc_calloc", "__afl_track_calloc", AllocKind::Calloc},
    {"__libc_realloc", "__afl_track_realloc", AllocKind::Realloc},
    {"__libc_free", "__afl_track_free", AllocKind::Free},
    {"__libc_valloc", "__afl_track_malloc", AllocKind::Malloc},
    {"__libc_pvalloc", "__afl_track_malloc", AllocKind::Malloc},
    {"__libc_memalign", "__afl_track_aligned_alloc", AllocKind::AlignedAlloc},
    {"__GI___libc_malloc", "__afl_track_malloc", AllocKind::Malloc},
    {"__GI___libc_calloc", "__afl_track_calloc", AllocKind::Calloc},
    {"__GI___libc_realloc", "__afl_track_realloc", AllocKind::Realloc},
    {"__GI___libc_free", "__afl_track_free", AllocKind::Free},

    // Legacy POSIX allocators. Treated as malloc (1-arg) since the
    // alignment/granularity is internal to the allocator and the runtime
    // shadow only cares about (base, size).
    {"valloc", "__afl_track_malloc", AllocKind::Malloc},
    {"pvalloc", "__afl_track_malloc", AllocKind::Malloc},
    {"memalign", "__afl_track_aligned_alloc",
     AllocKind::AlignedAlloc},                             /* (align, size) */

    // Nothrow new variants (`new(std::nothrow) T`). The pass already wraps
    // throwing-new, but the runtime-equivalent nothrow forms have distinct
    // mangled names and were silently missed.
    {"_ZnwmRKSt9nothrow_t", "__afl_track_malloc",
     AllocKind::NothrowNew},                       /* new       nothrow x64 */
    {"_ZnamRKSt9nothrow_t", "__afl_track_malloc",
     AllocKind::NothrowNew},                       /* new[]     nothrow x64 */
    {"_ZnwjRKSt9nothrow_t", "__afl_track_malloc",
     AllocKind::NothrowNew},                       /* new       nothrow x86 */
    {"_ZnajRKSt9nothrow_t", "__afl_track_malloc",
     AllocKind::NothrowNew},                       /* new[]     nothrow x86 */
    {"_ZdlPvRKSt9nothrow_t", "__afl_track_free",
     AllocKind::NothrowDelete},                        /* delete    nothrow */
    {"_ZdaPvRKSt9nothrow_t", "__afl_track_free",
     AllocKind::NothrowDelete},                        /* delete[]  nothrow */

    // Aligned + nothrow new/delete (C++17).
    {"_ZnwmSt11align_val_tRKSt9nothrow_t", "__afl_track_aligned_alloc",
     AllocKind::AlignedNothrowNew},
    {"_ZnamSt11align_val_tRKSt9nothrow_t", "__afl_track_aligned_alloc",
     AllocKind::AlignedNothrowNew},
    {"_ZnwjSt11align_val_tRKSt9nothrow_t", "__afl_track_aligned_alloc",
     AllocKind::AlignedNothrowNew},
    {"_ZnajSt11align_val_tRKSt9nothrow_t", "__afl_track_aligned_alloc",
     AllocKind::AlignedNothrowNew},
    {"_ZdlPvSt11align_val_tRKSt9nothrow_t", "__afl_track_free",
     AllocKind::AlignedNothrowDelete},
    {"_ZdaPvSt11align_val_tRKSt9nothrow_t", "__afl_track_free",
     AllocKind::AlignedNothrowDelete},

};

bool runAllocSizeMode(Module &M, ModuleAnalysisManager &,
                      const std::vector<std::string> &custom,
                      const std::vector<std::string> &custom_free,
                      bool                            stack_enabled) {

  LLVMContext &C = M.getContext();
  IntegerType *I32 = IntegerType::getInt32Ty(C);
  IntegerType *I64 = IntegerType::getInt64Ty(C);
  Type        *VoidTy = Type::getVoidTy(C);
#if LLVM_MAJOR >= 20
  Type *PtrTy = PointerType::getUnqual(C);
#else
  Type *PtrTy = PointerType::get(IntegerType::getInt8Ty(C), 0);
#endif

  FunctionCallee trackMalloc =
      M.getOrInsertFunction("__afl_track_malloc", PtrTy, I64, I32);
  markBugHookAttrs(trackMalloc);
  FunctionCallee trackCalloc =
      M.getOrInsertFunction("__afl_track_calloc", PtrTy, I64, I64, I32);
  markBugHookAttrs(trackCalloc);
  FunctionCallee trackRealloc =
      M.getOrInsertFunction("__afl_track_realloc", PtrTy, PtrTy, I64, I32);
  markBugHookAttrs(trackRealloc);
  FunctionCallee trackReallocarray = M.getOrInsertFunction(
      "__afl_track_reallocarray", PtrTy, PtrTy, I64, I64, I32);
  markBugHookAttrs(trackReallocarray);
  FunctionCallee trackPmemalign = M.getOrInsertFunction(
      "__afl_track_posix_memalign", I32, PtrTy, I64, I64, I32);
  markBugHookAttrs(trackPmemalign);
  // aligned_alloc / aligned-new share the same runtime hook. The hook
  // takes (size, align) — note the order matches the underlying
  // posix_memalign-based runtime, NOT C11's (align, size).
  FunctionCallee trackAlignedAlloc =
      M.getOrInsertFunction("__afl_track_aligned_alloc", PtrTy, I64, I64, I32);
  markBugHookAttrs(trackAlignedAlloc);
  FunctionCallee trackStrdup =
      M.getOrInsertFunction("__afl_track_strdup", PtrTy, PtrTy, I32);
  markBugHookAttrs(trackStrdup);
  FunctionCallee trackStrndup =
      M.getOrInsertFunction("__afl_track_strndup", PtrTy, PtrTy, I64, I32);
  markBugHookAttrs(trackStrndup);
  FunctionCallee trackFree =
      M.getOrInsertFunction("__afl_track_free", VoidTy, PtrTy);
  markBugHookAttrs(trackFree);
  FunctionCallee allocReg =
      M.getOrInsertFunction("__afl_alloc_register", VoidTy, PtrTy, I64, I32);
  markBugHookAttrs(allocReg);
  FunctionCallee allocUnreg =
      M.getOrInsertFunction("__afl_alloc_unregister", VoidTy, PtrTy);
  markBugHookAttrs(allocUnreg);

  uint32_t next_alloc_id = 1;
  uint32_t rewrites = 0, custom_inserts = 0, custom_frees = 0;
  bool     dump_summary = getenv(AFL_BUG_ENV_DUMP_SUMMARY) != nullptr;
  struct AllocSummary {

    uint32_t rewrites = 0;
    uint32_t customs = 0;
    uint32_t stores = 0;
    uint32_t mems = 0;
    uint32_t stack_regs = 0;

  };

  std::map<Function *, AllocSummary> per_func;
  std::set<std::string>              custom_set(custom.begin(), custom.end());
  std::set<std::string> custom_free_set(custom_free.begin(), custom_free.end());

  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    std::vector<Instruction *> dead;
    uint32_t                   pf_rew_start = rewrites;
    uint32_t                   pf_cust_start = custom_inserts + custom_frees;
    for (BasicBlock &BB : F) {

      // Manual advance-before-process iteration: rewriting an InvokeInst
      // erases the BB's terminator inline, which invalidates a range-for
      // iterator that still points to it. Advancing `it` first keeps the
      // iterator pointing at the next instruction (or end()) regardless.
      for (auto it = BB.begin(); it != BB.end();) {

        Instruction &I = *it++;
        // Accept both CallInst (the common case) and InvokeInst (used by
        // throwing C++ operator new under -fexceptions). Without invoke
        // handling, every aligned-new and throwing-new in exception-
        // enabled C++ code would silently bypass instrumentation.
        auto *Call = dyn_cast<CallBase>(&I);
        if (!Call || (!isa<CallInst>(Call) && !isa<InvokeInst>(Call))) continue;
        Function *cf = Call->getCalledFunction();
        if (!cf) continue;
        // nobuiltin means the user told the compiler "treat this as an
        // ordinary function call, not as the libc primitive" — rewriting
        // would violate that contract.
        if (Call->isNoBuiltin()) continue;
        StringRef name = cf->getName();
        // Strip clang's leading 0x01 escape (used for asm-name aliases)
        // so `\01_malloc` resolves the same as `malloc`.
        if (!name.empty() && name[0] == '\x01') name = name.drop_front();
        // 1) Direct rewrite for libc allocators.
        bool matched = false;
        for (const AllocRewriteSpec &spec : kRewriteSpecs) {

          if (name != spec.libc) continue;
          /* Defensive signature check: only rewrite calls whose args match
             the expected libc shape. With AFL_USE_ASAN=1 + CmpLog,
             user code that shadows malloc/etc. with a different signature
             would otherwise hit IRBuilder asserts. */
          unsigned expected_args = 0;
          switch (spec.kind) {

            case AllocKind::Free:
            case AllocKind::Malloc:
            case AllocKind::Strdup:
              expected_args = 1;
              break;
            case AllocKind::Calloc:
            case AllocKind::Realloc:
            case AllocKind::AlignedAlloc:
            case AllocKind::AlignedNew:
            case AllocKind::AlignedDelete:
            case AllocKind::NothrowNew:
            case AllocKind::NothrowDelete:
            case AllocKind::SizedFree:
            case AllocKind::Strndup:
              expected_args = 2;
              break;
            case AllocKind::PosixMemalign:
            case AllocKind::Reallocarray:
            case AllocKind::SizedAlignedFree:
            case AllocKind::AlignedNothrowNew:
            case AllocKind::AlignedNothrowDelete:
              expected_args = 3;
              break;

          }

          if (Call->arg_size() != expected_args) continue;
          // Type-shape gate keyed by kind. P = pointer, I = integer.
          auto isP = [&](unsigned i) {

            return Call->getArgOperand(i)->getType()->isPointerTy();

          };

          auto isI = [&](unsigned i) {

            return Call->getArgOperand(i)->getType()->isIntegerTy();

          };

          bool ok = false;
          switch (spec.kind) {

            case AllocKind::Free:
              ok = isP(0);
              break;
            case AllocKind::Malloc:
              ok = isI(0);
              break;
            case AllocKind::Strdup:
              ok = isP(0);
              break;
            case AllocKind::Realloc:
              ok = isP(0) && isI(1);
              break;
            case AllocKind::Calloc:
              ok = isI(0) && isI(1);
              break;
            case AllocKind::AlignedAlloc:
              ok = isI(0) && isI(1);
              break;
            case AllocKind::AlignedNew:
              ok = isI(0) && isI(1);
              break;
            case AllocKind::AlignedDelete:
              ok = isP(0) && isI(1);
              break;
            case AllocKind::NothrowNew:
              ok = isI(0) && isP(1);
              break;
            case AllocKind::NothrowDelete:
              ok = isP(0) && isP(1);
              break;
            case AllocKind::SizedFree:
              ok = isP(0) && isI(1);
              break;
            case AllocKind::Strndup:
              ok = isP(0) && isI(1);
              break;
            case AllocKind::PosixMemalign:
              ok = isP(0) && isI(1) && isI(2);
              break;
            case AllocKind::Reallocarray:
              ok = isP(0) && isI(1) && isI(2);
              break;
            case AllocKind::SizedAlignedFree:
              ok = isP(0) && isI(1) && isI(2);
              break;
            case AllocKind::AlignedNothrowNew:
              ok = isI(0) && isI(1) && isP(2);
              break;
            case AllocKind::AlignedNothrowDelete:
              ok = isP(0) && isI(1) && isP(2);
              break;

          }

          if (!ok) continue;

          IRBuilder<> B(Call);
          inheritDebugLoc(B, Call);
          uint32_t     id = next_alloc_id++;
          ConstantInt *idC = ConstantInt::get(I32, id);
          CallBase    *NewCall = nullptr;
          switch (spec.kind) {

            case AllocKind::Free:
            case AllocKind::SizedFree:
            case AllocKind::AlignedDelete:
            case AllocKind::NothrowDelete:
            case AllocKind::AlignedNothrowDelete:
            case AllocKind::SizedAlignedFree:
              // All deallocator variants collapse to plain free; size /
              // alignment args are advisory only.
              NewCall = B.CreateCall(
                  trackFree, {castToPtrTy(B, Call->getArgOperand(0), PtrTy)});
              break;
            case AllocKind::Malloc:
            case AllocKind::NothrowNew:
              NewCall = B.CreateCall(
                  trackMalloc,
                  {B.CreateZExtOrTrunc(Call->getArgOperand(0), I64), idC});
              break;
            case AllocKind::Calloc:
              NewCall = B.CreateCall(
                  trackCalloc,
                  {B.CreateZExtOrTrunc(Call->getArgOperand(0), I64),
                   B.CreateZExtOrTrunc(Call->getArgOperand(1), I64), idC});
              break;
            case AllocKind::Realloc:
              NewCall = B.CreateCall(
                  trackRealloc,
                  {castToPtrTy(B, Call->getArgOperand(0), PtrTy),
                   B.CreateZExtOrTrunc(Call->getArgOperand(1), I64), idC});
              break;
            case AllocKind::Reallocarray:
              NewCall = B.CreateCall(
                  trackReallocarray,
                  {castToPtrTy(B, Call->getArgOperand(0), PtrTy),
                   B.CreateZExtOrTrunc(Call->getArgOperand(1), I64),
                   B.CreateZExtOrTrunc(Call->getArgOperand(2), I64), idC});
              break;
            case AllocKind::PosixMemalign:
              NewCall = B.CreateCall(
                  trackPmemalign,
                  {castToPtrTy(B, Call->getArgOperand(0), PtrTy),
                   B.CreateZExtOrTrunc(Call->getArgOperand(1), I64),
                   B.CreateZExtOrTrunc(Call->getArgOperand(2), I64), idC});
              break;
            case AllocKind::AlignedAlloc:
              // C11 aligned_alloc(align, size). Runtime hook signature is
              // (size, align) — swap arg order on rewrite.
              NewCall = B.CreateCall(
                  trackAlignedAlloc,
                  {B.CreateZExtOrTrunc(Call->getArgOperand(1), I64),
                   B.CreateZExtOrTrunc(Call->getArgOperand(0), I64), idC});
              break;
            case AllocKind::AlignedNew:
            case AllocKind::AlignedNothrowNew:
              // C++17 operator new(size, align_val_t). Runtime hook
              // already takes (size, align) — pass through.
              NewCall = B.CreateCall(
                  trackAlignedAlloc,
                  {B.CreateZExtOrTrunc(Call->getArgOperand(0), I64),
                   B.CreateZExtOrTrunc(Call->getArgOperand(1), I64), idC});
              break;
            case AllocKind::Strdup:
              NewCall = B.CreateCall(
                  trackStrdup,
                  {castToPtrTy(B, Call->getArgOperand(0), PtrTy), idC});
              break;
            case AllocKind::Strndup:
              NewCall = B.CreateCall(
                  trackStrndup,
                  {castToPtrTy(B, Call->getArgOperand(0), PtrTy),
                   B.CreateZExtOrTrunc(Call->getArgOperand(1), I64), idC});
              break;

          }

          if (!Call->use_empty()) {

            Value *Replacement = NewCall;
            if (NewCall->getType() != Call->getType()) {

              Instruction *InsertBefore = nullptr;
              if (auto *NCInst = dyn_cast<Instruction>(NewCall))
                InsertBefore = NCInst->getNextNode();
              if (!InsertBefore) InsertBefore = cast<Instruction>(Call);
              IRBuilder<> CastB(InsertBefore);
              inheritDebugLoc(CastB, Call);
              Replacement =
                  CastB.CreateBitOrPointerCast(NewCall, Call->getType());

            }

            Call->replaceAllUsesWith(Replacement);

          }

          if (auto *II = dyn_cast<InvokeInst>(Call)) {

            // Invoke is a terminator with normal + unwind successors.
            // The replacement call doesn't throw, so we re-route the
            // normal successor via a plain branch and detach the unwind
            // edge (also fixes up PHIs in the unwind dest). The new
            // branch is inserted BEFORE the invoke; erasing the invoke
            // immediately after restores valid IR.
            BasicBlock *NormalDest = II->getNormalDest();
            BasicBlock *UnwindDest = II->getUnwindDest();
            BasicBlock *Parent = II->getParent();
            UnwindDest->removePredecessor(Parent);
            BranchInst::Create(NormalDest, II);
            II->eraseFromParent();

          } else {

            dead.push_back(cast<CallInst>(Call));

          }

          ++rewrites;
          matched = true;
          break;

        }

        if (matched) continue;
        // Anonymous mmap returns a fresh region invisible to the
        // malloc family.  Detect the canonical anonymous form by
        // `fd == -1` (a ConstantInt) and register the result against
        // the size arg.  File-backed mmaps (fd != -1) are NOT tracked
        // — they alias existing storage and shadow-painting them
        // risks false OOBs against the caller's view of the file.
        // munmap is paired unconditionally (free is safe to no-op on
        // untracked regions).
        if (name == "mmap") {

          if (Call->arg_size() == 6 &&
              Call->getArgOperand(1)->getType()->isIntegerTy() &&
              Call->getArgOperand(4)->getType()->isIntegerTy() &&
              Call->getType()->isPointerTy()) {

            auto *FdC = dyn_cast<ConstantInt>(Call->getArgOperand(4));
            if (FdC && FdC->isMinusOne()) {

              Instruction *PostAt =
                  postCallInsertionPoint(Call, C, ".mmap.edge");
              if (PostAt) {

                IRBuilder<> Post(PostAt);
                inheritDebugLoc(Post, Call);
                uint32_t id = next_alloc_id++;
                Post.CreateCall(allocReg, {castToPtrTy(Post, Call, PtrTy),
                                           Post.CreateZExtOrTrunc(
                                               Call->getArgOperand(1), I64),
                                           ConstantInt::get(I32, id)});
                ++custom_inserts;

              }

            }

          }

          continue;

        }

        if (name == "munmap") {

          if (Call->arg_size() >= 1 &&
              Call->getArgOperand(0)->getType()->isPointerTy()) {

            IRBuilder<> MB(Call);
            inheritDebugLoc(MB, Call);
            MB.CreateCall(allocUnreg,
                          {castToPtrTy(MB, Call->getArgOperand(0), PtrTy)});
            ++custom_frees;

          }

          continue;

        }

        // 2) Manual unregister for user-listed custom deallocators.
        if (custom_free_set.count(name.str())) {

          if (Call->arg_size() < 1) continue;
          if (!Call->getArgOperand(0)->getType()->isPointerTy()) continue;
          IRBuilder<> FB(Call);
          inheritDebugLoc(FB, Call);
          FB.CreateCall(allocUnreg,
                        {castToPtrTy(FB, Call->getArgOperand(0), PtrTy)});
          ++custom_frees;
          continue;

        }

        // 2) Manual register for user-listed custom allocators.
        if (!custom_set.count(name.str())) continue;
        /* Custom allocator must return a pointer — its result is passed to
           __afl_alloc_register's first arg (PtrTy). Reject void/int/etc. */
        if (!cf->getReturnType()->isPointerTy()) continue;
        // Position the post-call register: for a CallInst that's the
        // next instruction; for an InvokeInst it's the top of the
        // normal-dest block.
        //
        // CRITICAL: when InvokeInst's NormalDest has multiple predecessors,
        // II's SSA result does NOT strictly dominate non-PHI instructions
        // in NormalDest — other preds can reach NormalDest without going
        // through II. Inserting __afl_alloc_register(II, ...) there would
        // be invalid IR. Split the critical edge so the new register call
        // lives in a unique block reached only from this invoke.
        Instruction *PostInsertAt =
            postCallInsertionPoint(Call, C, ".alloc.edge");
        if (!PostInsertAt) continue;
        IRBuilder<> Post(PostInsertAt);
        inheritDebugLoc(Post, Call);
        // Pick the widest integer arg as the size. `size_t` is pointer-
        // width on the target, so for a signature like
        // `void *alloc(int flags, size_t size)` this avoids grabbing the
        // narrower `flags` int. Ties favor the later operand, matching
        // the C convention of "options first, size last".
        Value   *sizeArg = nullptr;
        unsigned bestBits = 0;
        for (unsigned i = 0; i < Call->arg_size(); ++i) {

          auto *IT = dyn_cast<IntegerType>(Call->getArgOperand(i)->getType());
          if (!IT) continue;
          if (IT->getBitWidth() >= bestBits) {

            bestBits = IT->getBitWidth();
            sizeArg = Call->getArgOperand(i);

          }

        }

        if (!sizeArg) continue;
        uint32_t id = next_alloc_id++;
        Post.CreateCall(allocReg, {castToPtrTy(Post, Call, PtrTy),
                                   Post.CreateZExtOrTrunc(sizeArg, I64),
                                   ConstantInt::get(I32, id)});
        ++custom_inserts;

      }

    }

    for (auto *I : dead)
      I->eraseFromParent();
    if (dump_summary) {

      uint32_t r = rewrites - pf_rew_start;
      uint32_t cu = (custom_inserts + custom_frees) - pf_cust_start;
      if (r || cu) {

        per_func[&F].rewrites = r;
        per_func[&F].customs = cu;

      }

    }

  }

  // Phase 2: instrument stores and bulk memory writes broadly. The runtime
  // shadow lookup is the filter: untracked stack/global/foreign pointers are
  // cheap no-ops, while tracked allocations remain visible even after being
  // passed through helper functions.
  FunctionCallee oracle =
      M.getOrInsertFunction("__afl_alloc_oracle", VoidTy, PtrTy, I32);
  markBugHookAttrs(oracle);
  // Enhancement I: separate hook with i64 length for memcpy/memmove/memset.
  // Integer-overflow bugs that wrap a memcpy length to a small value
  // (e.g., size_t computed from input where the high bits got truncated)
  // are exactly the bug class where ALLOCSIZE wants the full length —
  // the i32 hook used to silently truncate, hiding the overflow.
  FunctionCallee oracle_n =
      M.getOrInsertFunction("__afl_alloc_oracle_n", VoidTy, PtrTy, I64);
  markBugHookAttrs(oracle_n);
  // Enhancement H: type-confusion signal. The runtime tracks the first
  // (elem_size, alignment-class) pair seen at each allocation; a later
  // store with a mismatched element size is reported as a type-confusion
  // smell. Useful for catching UAF-with-realloc-confusion patterns and
  // C++ type-punning bugs where a `Foo[]` allocation later sees a
  // `Bar*` store of different size.
  FunctionCallee oracle_typed = M.getOrInsertFunction(
      "__afl_alloc_oracle_typed", VoidTy, PtrTy, I32, I32);
  markBugHookAttrs(oracle_typed);

  uint32_t store_sites = 0;
  uint32_t mem_sites = 0;
  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    uint32_t pf_store_start = store_sites;
    uint32_t pf_mem_start = mem_sites;
    // Walk every store in the function, not just loop-internal ones. The
    // oracle runtime is cheap on shadow miss, and OOB writes happen
    // outside loops too (e.g., one-shot `arr[computed_idx] = x`).
    for (BasicBlock &BB : F) {

      for (Instruction &I : BB) {

        // memcpy / memmove / memset: clang emits these for struct copies
        // and aggregate inits. Without this branch, a 4 KB memcpy into a
        // 32-byte tracked buffer is invisible. Feed (dest, len) to the
        // oracle. Enhancement I: pass length as i64 to the dedicated
        // oracle_n hook so an integer-overflow that wraps a memcpy's
        // length to a small i32 value is still visible to the oracle.
        if (auto *MI = dyn_cast<MemIntrinsic>(&I)) {

          Value *dest = MI->getRawDest();
          Value *len = MI->getLength();
          if (!dest || !len) continue;
          IRBuilder<> MB(MI);
          inheritDebugLoc(MB, MI);
          Value *addr = castToPtrTy(MB, dest, PtrTy);
          Value *lenI64 = MB.CreateZExtOrTrunc(len, I64);
          MB.CreateCall(oracle_n, {addr, lenI64});
          ++mem_sites;
          continue;

        }

        auto *S = dyn_cast<StoreInst>(&I);
        if (!S) continue;
        IRBuilder<> SB(S);
        inheritDebugLoc(SB, S);
        Value   *addr = castToPtrTy(SB, S->getPointerOperand(), PtrTy);
        uint64_t sz =
            M.getDataLayout().getTypeStoreSize(S->getValueOperand()->getType());
        SB.CreateCall(oracle, {addr, ConstantInt::get(I32, (uint32_t)sz)});
        // Enhancement H: feed a type-confusion signal. The runtime
        // remembers the first (element-size, alignment) pair observed
        // at each tracked allocation; a later store with a different
        // element-size triggers a one-shot warning. Useful for catching
        // realloc-with-different-type and C++ type-punning patterns
        // where the same buffer is later treated as a different type.
        // Skip when sz==0 (zero-sized struct stores) — no type signal.
        if (sz) {

          // Element size and alignment together form the type
          // fingerprint. `getAlign().value() == 0` only happens on
          // malformed IR, but defend anyway (alignment of 1 means
          // "byte-aligned" which is also a valid fingerprint value).
          unsigned align = S->getAlign().value();
          if (align == 0) align = 1;
          SB.CreateCall(oracle_typed,
                        {addr, ConstantInt::get(I32, (uint32_t)sz),
                         ConstantInt::get(I32, align)});

        }

        ++store_sites;

      }

    }

    if (dump_summary) {

      uint32_t s = store_sites - pf_store_start;
      uint32_t m = mem_sites - pf_mem_start;
      if (s || m) {

        per_func[&F].stores += s;
        per_func[&F].mems += m;

      }

    }

  }

  // Phase 3: stack-alloca tracking.  Phase 1 rewrites heap allocators
  // and Phase 2 inserts the per-store oracle, which acts as a no-op
  // on untracked addresses.  Registering stack allocas makes that
  // same oracle a stack-OOB tripwire.  Gated by
  // AFL_LLVM_BUG_ALLOCSIZE_STACK (default on when ALLOCSIZE is
  // enabled; set to "0" to opt out).
  //
  // Strategy: try lifetime intrinsics first (clang emits these under
  // -O2+ and they precisely bound the live range); fall back to
  // entry/exit instrumentation otherwise.  Per-function caps cap
  // multi-exit fanout cost.
  uint32_t stack_regs = 0, stack_unregs = 0, stack_funcs = 0;
  if (stack_enabled) {

    constexpr unsigned kStackAllocaMax = 16;
    // The ALLOCSIZE shadow is granule-resolved (64 bytes). To avoid the
    // granule-aliasing FP class — stores into an unrelated stack
    // neighbour that shares a partial granule with a registered alloca
    // get attributed to the registered alloca and reported as OOB —
    // we restrict stack registration to allocas that occupy WHOLE
    // granules: size >= 64 AND multiple of 64.  We additionally force
    // the alloca's alignment to 64 so it starts on a granule boundary;
    // together these constraints make the painted granules exactly
    // the alloca's bytes.  Smaller stack arrays (< 64 bytes) are not
    // covered by this oracle — a known limitation; users wanting fine-
    // grained stack-OOB detection can pair with -fsanitize=address.
    constexpr uint64_t kStackGranuleBytes = 64;
    const DataLayout  &DL = M.getDataLayout();
    for (Function &F : M) {

      if (F.isDeclaration()) continue;
        // Defensive: avoid recursing into our own runtime hooks if any
        // got linked into this module by accident.
#if LLVM_VERSION_MAJOR >= 18
      if (F.getName().starts_with("__afl_")) continue;
#else
      if (F.getName().startswith("__afl_")) continue;
#endif

      // Collect candidate allocas from the entry block (clang places
      // local-variable allocas there even at -O2; later blocks see
      // them via SSA, not as new AllocaInst).
      std::vector<AllocaInst *> candidates;
      for (Instruction &I : F.getEntryBlock()) {

        auto *AI = dyn_cast<AllocaInst>(&I);
        if (!AI) continue;
          // Reject dynamic-size (VLA) — no compile-time bound to register.
#if LLVM_VERSION_MAJOR >= 16
        auto opt_size = AI->getAllocationSize(DL);
        if (!opt_size) continue;
        if (opt_size->isScalable()) continue;
        uint64_t bytes = opt_size->getFixedValue();
#else
        auto opt_size_bits = AI->getAllocationSizeInBits(DL);
        if (!opt_size_bits) continue;
        if (opt_size_bits->isScalable()) continue;
        uint64_t bytes = opt_size_bits->getFixedValue() / 8;
#endif
        if (bytes < kStackGranuleBytes) continue;
        if (bytes % kStackGranuleBytes) continue;
        if (AI->use_empty()) continue;                       /* dead alloca */
        // Force alignment to granule boundary so the painted granules
        // line up exactly with the alloca.  Llvm honors this in the
        // backend's prologue/spill placement.
        if (AI->getAlign().value() < kStackGranuleBytes)
          AI->setAlignment(Align(kStackGranuleBytes));
        candidates.push_back(AI);
        if (candidates.size() >= kStackAllocaMax) {

          if (getenv("AFL_QUIET") == nullptr)
            errs() << "[afl-bug] ALLOCSIZE: stack cap reached in "
                   << F.getName() << " (more allocas not instrumented)\n";
          break;

        }

      }

      if (candidates.empty()) continue;
      ++stack_funcs;
      uint32_t pf_stack_start = stack_regs;
      // Collect function-level exit insertion points once for the
      // fallback path (used per-alloca when no lifetime intrinsic is
      // available).  Return / Resume cover normal return and C++
      // exception propagation; Unreachable terminators follow
      // noreturn calls (process is dead, no unregister needed).
      std::vector<Instruction *> exit_points;
      for (BasicBlock &BB : F) {

        Instruction *T = BB.getTerminator();
        if (!T) continue;
        if (isa<ReturnInst>(T) || isa<ResumeInst>(T)) exit_points.push_back(T);

      }

      for (AllocaInst *AI : candidates) {

        uint32_t id = next_alloc_id++;
#if LLVM_VERSION_MAJOR >= 16
        uint64_t bytes = AI->getAllocationSize(DL)->getFixedValue();
#else
        uint64_t bytes = AI->getAllocationSizeInBits(DL)->getFixedValue() / 8;
#endif
        Value *sizeV = ConstantInt::get(I64, bytes);
        Value *idV = ConstantInt::get(I32, id);

        // Look for paired llvm.lifetime.start/end intrinsics on AI.
        // When present (typical for -O2 clang), they bound the alloca's
        // live range more tightly than the function's prologue/exits.
        std::vector<IntrinsicInst *> starts, ends;
        for (User *U : AI->users()) {

          auto *II = dyn_cast<IntrinsicInst>(U);
          if (!II) continue;
          Intrinsic::ID id_ii = II->getIntrinsicID();
          if (id_ii == Intrinsic::lifetime_start)
            starts.push_back(II);
          else if (id_ii == Intrinsic::lifetime_end)
            ends.push_back(II);

        }

        bool lifetime_path = !starts.empty() && !ends.empty();

        Value *ptrCast = nullptr;
        if (lifetime_path) {

          for (IntrinsicInst *S : starts) {

            IRBuilder<> B(S->getNextNode());
            inheritDebugLoc(B, S);
            Value *p = castToPtrTy(B, AI, PtrTy);
            B.CreateCall(allocReg, {p, sizeV, idV});
            ++stack_regs;
            ptrCast = p;

          }

          for (IntrinsicInst *E : ends) {

            IRBuilder<> B(E);
            inheritDebugLoc(B, E);
            Value *p = castToPtrTy(B, AI, PtrTy);
            B.CreateCall(allocUnreg, {p});
            ++stack_unregs;

          }

        } else {

          // Fallback: register right after the alloca (still in the
          // entry block, so the call dominates every use), and
          // unregister before every exit terminator.  Note: a tail
          // exit that's NEVER reached (e.g., after _exit) gets no
          // unregister but the process is dead anyway.
          IRBuilder<> AB(AI->getNextNode());
          inheritDebugLoc(AB, AI);
          Value *p = castToPtrTy(AB, AI, PtrTy);
          AB.CreateCall(allocReg, {p, sizeV, idV});
          ++stack_regs;

          for (Instruction *T : exit_points) {

            IRBuilder<> EB(T);
            inheritDebugLoc(EB, T);
            Value *up = castToPtrTy(EB, AI, PtrTy);
            EB.CreateCall(allocUnreg, {up});
            ++stack_unregs;

          }

        }

        (void)ptrCast;

      }

      if (dump_summary) {

        uint32_t s = stack_regs - pf_stack_start;
        if (s) per_func[&F].stack_regs += s;

      }

    }

  }

  if (getenv("AFL_QUIET") == nullptr)
    errs() << "[afl-bug] ALLOCSIZE rewrote " << rewrites
           << " libc allocator calls, " << custom_inserts
           << " custom-allocator registrations, " << custom_frees
           << " custom-free unregisters, " << store_sites << " stores, "
           << mem_sites << " mem intrinsics instrumented; " << stack_regs
           << " stack registers / " << stack_unregs << " unregisters across "
           << stack_funcs << " functions\n";
  if (dump_summary) {

    for (auto &kv : per_func)
      errs() << "[afl-bug-summary] ALLOCSIZE " << kv.first->getName()
             << " rew=" << kv.second.rewrites << " cust=" << kv.second.customs
             << " stores=" << kv.second.stores << " mem=" << kv.second.mems
             << " stack=" << kv.second.stack_regs << "\n";

  }

  return rewrites > 0 || custom_inserts > 0 || custom_frees > 0 ||
         store_sites > 0 || mem_sites > 0 || stack_regs > 0;

}

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "afl-bug-pass", "v0.1", [](PassBuilder &PB) {

            PB.registerOptimizerLastEPCallback([](ModulePassManager &MPM,
                                                  OptimizationLevel
#if LLVM_MAJOR >= 20
                                                  ,
                                                  ThinOrFullLTOPhase
#endif
                                               ) { MPM.addPass(BugPass()); });

          }};

}

