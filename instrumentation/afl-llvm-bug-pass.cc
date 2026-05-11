// instrumentation/afl-llvm-bug-pass.cc
//
// AFL++ bug-finding pass: implements five independent oracles, each gated
// by its own AFL_LLVM_BUG_<NAME>=1 (or AFL_LLVM_BUG=all):
//   - SCALAR   : max-value-per-arithmetic-site coverage + loop iter counts
//   - BUDGET   : ptr += func() write-extent contract
//   - SIZEFILL : NULL-means-size idiom self-consistency
//   - SLACK    : |op0 - op1| per icmp site, fed as inverse-bucket MAX
//   - ALLOCSIZE: malloc/free rewrite + per-store OOB oracle
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
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Support/raw_ostream.h"
#if LLVM_MAJOR >= 22
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
  std::vector<std::string> custom_alloc_funcs;
  bool any() const {

    return scalar || budget || sizefill || allocsize || slack;

  }

};

static BugPassConfig parseEnv() {

  BugPassConfig c;
  if (const char *all = getenv(AFL_BUG_ENV_ALL)) {

    if (*all && strcmp(all, "0") != 0) {

      c.scalar = c.budget = c.sizefill = c.allocsize = c.slack = true;

    }

  }

  if (getenv(AFL_BUG_ENV_SCALAR)) c.scalar = true;
  if (getenv(AFL_BUG_ENV_BUDGET)) c.budget = true;
  if (getenv(AFL_BUG_ENV_SIZEFILL)) c.sizefill = true;
  if (getenv(AFL_BUG_ENV_ALLOCSIZE)) c.allocsize = true;
  if (getenv(AFL_BUG_ENV_SLACK)) c.slack = true;
  if (const char *list = getenv(AFL_BUG_ENV_ALLOCSIZE_FUNCS)) {

    std::string s(list);
    size_t      i = 0;
    while (i < s.size()) {

      size_t j = s.find_first_of(",;: ", i);
      if (j == std::string::npos) j = s.size();
      if (j > i) c.custom_alloc_funcs.emplace_back(s.substr(i, j - i));
      i = j + 1;

    }

  }

  return c;

}

class BugPass : public PassInfoMixin<BugPass> {

 public:
  BugPass() { initInstrumentList(); }
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

};

// Forward decls.
bool runScalarMode(Module &M, ModuleAnalysisManager &MAM);
bool runBudgetMode(Module &M, ModuleAnalysisManager &MAM);
bool runSizefillMode(Module &M, ModuleAnalysisManager &MAM);
bool runSlackMode(Module &M, ModuleAnalysisManager &MAM);
bool runAllocSizeMode(Module &M, ModuleAnalysisManager &MAM,
                      const std::vector<std::string> &custom);
static bool ptrStoreReachesArg(StoreInst                 *S,
                               const std::set<unsigned> &arg_indices);
static void inheritDebugLoc(IRBuilder<> &B, Instruction *Source);

PreservedAnalyses BugPass::run(Module &M, ModuleAnalysisManager &MAM) {

  BugPassConfig cfg = parseEnv();
  if (!cfg.any()) return PreservedAnalyses::all();

  if (getenv("AFL_QUIET") == nullptr) {

    errs() << "[afl-bug] enabled modes:" << (cfg.scalar ? " SCALAR" : "")
           << (cfg.budget ? " BUDGET" : "")
           << (cfg.sizefill ? " SIZEFILL" : "")
           << (cfg.allocsize ? " ALLOCSIZE" : "")
           << (cfg.slack ? " SLACK" : "") << "\n";

  }

  bool changed = false;
  if (cfg.scalar) changed |= runScalarMode(M, MAM);
  if (cfg.budget) changed |= runBudgetMode(M, MAM);
  if (cfg.sizefill) changed |= runSizefillMode(M, MAM);
  if (cfg.slack) changed |= runSlackMode(M, MAM);
  if (cfg.allocsize)
    changed |= runAllocSizeMode(M, MAM, cfg.custom_alloc_funcs);
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
static bool isInductionVariableUpdate(BinaryOperator *I, LoopInfo &LI) {

  for (User *U : I->users()) {

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

// Heuristic filter: skip values that are clearly addresses, sizes-of-input,
// or loop-induction. Conservative — we'd rather miss a site than spam the map.
static bool ScalarSiteWorthInstrumenting(BinaryOperator *I, LoopInfo &LI) {

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

bool runScalarMode(Module &M, ModuleAnalysisManager &) {

  LLVMContext &C = M.getContext();
  Type        *VoidTy = Type::getVoidTy(C);
  IntegerType *I32 = IntegerType::getInt32Ty(C);
  IntegerType *I64 = IntegerType::getInt64Ty(C);

  FunctionCallee scalarHook =
      M.getOrInsertFunction("__afl_bug_scalar_max", VoidTy, I32, I64);

  uint32_t next_id = 0;
  bool     changed = false;

  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    if (!isInInstrumentList(&F, F.getName().str())) continue;
    // LoopInfo is needed both here (for IV-filter) and below (for loop
    // iteration counters). Build once per function.
    DominatorTree DT(F);
    LoopInfo      LI(DT);
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
            break;
          default:
            continue;

        }

        if (!ScalarSiteWorthInstrumenting(Bin, LI)) continue;
        IRBuilder<> B(Bin->getNextNode());
        inheritDebugLoc(B, Bin);
        Value   *v64 = B.CreateZExtOrTrunc(Bin, I64);
        uint32_t id = (next_id++) & (MAP_SIZE_BUG_ENTRIES - 1);
        B.CreateCall(scalarHook, {ConstantInt::get(I32, id), v64});
        changed = true;

      }

    }

  }

  // Loop-header iteration counters. Use local DominatorTree + LoopInfo
  // (constructable directly), avoiding the analysis-manager API which varies
  // across LLVM versions.
  FunctionCallee loopFlush =
      M.getOrInsertFunction("__afl_bug_loop_iter_flush", VoidTy, I32, I32);

  uint32_t loop_sites = 0;
  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    if (!isInInstrumentList(&F, F.getName().str())) continue;
    DominatorTree DT(F);
    LoopInfo      LI(DT);
    if (LI.empty()) continue;

    for (Loop *L : LI.getLoopsInPreorder()) {

      // Need a simplified loop (single preheader + single latch) so the
      // header PHI has exactly two incoming edges. Irreducible / multi-
      // entry loops are skipped — better to miss the signal than to emit
      // a malformed PHI.
      BasicBlock *Preheader = L->getLoopPreheader();
      BasicBlock *Latch = L->getLoopLatch();
      BasicBlock *Header = L->getHeader();
      if (!Preheader || !Latch || !Header) continue;

      uint32_t id = (next_id++) & (MAP_SIZE_BUG_ENTRIES - 1);
      ++loop_sites;

      // SSA-form counter: PHI in the header taking 0 from preheader and
      // (cnt+1) from the latch. This avoids per-iteration load/add/store
      // through an alloca — which would survive optimizer-last since
      // mem2reg has already run. Codegen lowers this to a register
      // increment, ~3x faster in tight loops than the alloca form.
      PHINode *cnt = PHINode::Create(I32, 2, "afl.loopcnt",
                                     &*Header->begin());
      cnt->setDebugLoc(Header->getFirstNonPHI()->getDebugLoc());
      IRBuilder<> HB(Header->getFirstNonPHI());
      inheritDebugLoc(HB, Header->getFirstNonPHI());
      Value      *inc = HB.CreateAdd(cnt, ConstantInt::get(I32, 1),
                                     "afl.loopcnt.inc");
      cnt->addIncoming(ConstantInt::get(I32, 0), Preheader);
      cnt->addIncoming(inc, Latch);

      // Flush at every unique exit block via an LCSSA-style PHI: pick up
      // `inc` (the count INCLUDING the exit iteration) along edges that
      // come from inside the loop, and 0 along any edge that bypasses
      // the loop entirely. SmallPtrSet dedups exit blocks reached by
      // multiple edges.
      SmallVector<BasicBlock *, 4> Exits;
      L->getExitBlocks(Exits);
      SmallPtrSet<BasicBlock *, 4> seenExits;
      for (BasicBlock *Exit : Exits) {

        if (!seenExits.insert(Exit).second) continue;
        PHINode *xphi = PHINode::Create(
            I32, 0, "afl.loopcnt.lcssa", &*Exit->begin());
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
        Instruction *FlushAt = Exit->getFirstNonPHI();
        IRBuilder<> XB(FlushAt);
        inheritDebugLoc(XB, FlushAt);
        XB.CreateCall(loopFlush, {ConstantInt::get(I32, id), xphi});

      }

    }

    // (Function-return flush removed: exit-block flushes above are
    // sufficient and avoid conflating multiple loop runs in one call.)

    changed = true;

  }

  if (getenv("AFL_QUIET") == nullptr)
    errs() << "[afl-bug] SCALAR instrumented " << (next_id - loop_sites)
           << " arithmetic sites, " << loop_sites << " loops\n";
  return changed;

}

// Recognize: ptr_after = gep(ptr_before, call_result), where ptr_before was
// passed as one of the call args. Returns the matched call + the pointer arg
// index, or {nullptr,0,0}.
struct BudgetMatch {

  CallInst *Call;
  unsigned  PtrArgIdx;
  Value    *PtrBefore;

};

static std::vector<BudgetMatch> findBudgetCalls(Function &F) {

  std::vector<BudgetMatch> out;
  for (BasicBlock &BB : F) {

    for (Instruction &I : BB) {

      // GEP form (most common in modern LLVM): getelementptr ptr, call_result.
      if (auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {

        if (GEP->getNumIndices() != 1) continue;
        Value *base = GEP->getPointerOperand();
        Value *idx = GEP->getOperand(1);
        // Look through zero/sign-extending casts: clang produces
        // `zext i32 %ret to i64` between the call and the GEP.
        while (auto *Cast = dyn_cast<CastInst>(idx)) {

          if (Cast->getOpcode() == Instruction::ZExt ||
              Cast->getOpcode() == Instruction::SExt ||
              Cast->getOpcode() == Instruction::Trunc)
            idx = Cast->getOperand(0);
          else
            break;

        }

        auto *Call = dyn_cast<CallInst>(idx);
        if (!Call) continue;
        for (unsigned i = 0; i < Call->arg_size(); ++i) {

          if (Call->getArgOperand(i)->stripPointerCasts() ==
              base->stripPointerCasts()) {

            out.push_back({Call, i, base});
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
      auto  *Call = dyn_cast<CallInst>(L);
      Value *Ptr = R;
      if (!Call) {

        Call = dyn_cast<CallInst>(R);
        Ptr = L;

      }

      if (!Call) continue;
      auto *P2I = dyn_cast<PtrToIntInst>(Ptr);
      if (!P2I) continue;
      Value *base = P2I->getOperand(0);
      for (unsigned i = 0; i < Call->arg_size(); ++i) {

        if (Call->getArgOperand(i)->stripPointerCasts() ==
            base->stripPointerCasts()) {

          out.push_back({Call, i, base});
          break;

        }

      }

    }

  }

  return out;

}

bool runBudgetMode(Module &M, ModuleAnalysisManager &) {

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
  FunctionCallee wsCheck =
      M.getOrInsertFunction("__afl_bug_ws_check_budget", VoidTy, PtrTy, I64);
  FunctionCallee wsStore =
      M.getOrInsertFunction("__afl_bug_ws_store", VoidTy, PtrTy, I32);

  // Per-callee set of argument indices that are budget-traced. A store
  // inside such a callee only counts toward __afl_bug_ws_max_off if it
  // reaches one of these specific args — not just any pointer arg. This
  // prevents false positives when the callee has unrelated pointer args
  // (e.g., a status-out pointer) whose writes happen to land past the
  // tracked buffer head.
  std::map<Function *, std::set<unsigned>> callee_arg_indices;

  bool changed = false;
  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    if (!isInInstrumentList(&F, F.getName().str())) continue;
    for (auto &m : findBudgetCalls(F)) {

      Function *callee = m.Call->getCalledFunction();
      if (!callee || callee->isDeclaration()) continue;  // intra-module only
      /* Defensive: if the matched call's return isn't integer, the post-call
         CreateZExtOrTrunc would assert. Valid IR for `gep ptr, idx` and
         `add p2i, idx` always has integer idx, but pass ordering with ASan
         and unusual optimisation pipelines can produce surprises. */
      if (!m.Call->getType()->isIntegerTy()) continue;
      if (m.PtrArgIdx >= callee->arg_size()) continue;

      IRBuilder<> Pre(m.Call);
      inheritDebugLoc(Pre, m.Call);
      Value *ptrCast = Pre.CreateBitOrPointerCast(m.PtrBefore, PtrTy);
      Pre.CreateCall(wsBegin, {ptrCast});

      IRBuilder<> Post(m.Call->getNextNode());
      inheritDebugLoc(Post, m.Call);
      Value *ret64 = Post.CreateZExtOrTrunc(m.Call, I64);
      Value *ptrCast2 = Post.CreateBitOrPointerCast(m.PtrBefore, PtrTy);
      Post.CreateCall(wsCheck, {ptrCast2, ret64});

      callee_arg_indices[callee].insert(
          callee->getArg(m.PtrArgIdx)->getArgNo());
      changed = true;

    }

  }

  // Instrument stores whose pointer traces to the SPECIFIC budget-traced
  // argument. Stores via stack locals, globals, or other pointer args are
  // skipped to keep the tracked max_off honest.
  for (auto &kv : callee_arg_indices) {

    Function                  *F = kv.first;
    const std::set<unsigned>  &arg_indices = kv.second;
    for (BasicBlock &BB : *F) {

      for (Instruction &I : BB) {

        auto *S = dyn_cast<StoreInst>(&I);
        if (!S) continue;
        // Skip the spill itself (storing the argument into its alloca).
        if (isa<Argument>(S->getValueOperand())) continue;
        if (!ptrStoreReachesArg(S, arg_indices)) continue;
        IRBuilder<> SB(S);
        inheritDebugLoc(SB, S);
        Value *addr =
            SB.CreateBitOrPointerCast(S->getPointerOperand(), PtrTy);
        uint64_t sz = M.getDataLayout().getTypeStoreSize(
            S->getValueOperand()->getType());
        SB.CreateCall(wsStore, {addr, ConstantInt::get(I32, (uint32_t)sz)});

      }

    }

  }

  if (getenv("AFL_QUIET") == nullptr)
    errs() << "[afl-bug] BUDGET instrumented " << callee_arg_indices.size()
           << " callees\n";
  return changed;

}

// A pointer parameter is "sentinel-checked" if the function has a basic
// block branched on (param == null) where the null branch returns without
// any store through the parameter. Returns the index of the matching
// parameter, or -1.
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
          // Walk forward from NullBB through unconditional branches until
          // we hit a Return. Flag if we get there without seeing a store
          // through the parameter.
          bool       seen_store_via_arg = false;
          bool       reached_return = false;
          BasicBlock *cur = NullBB;
          for (int hop = 0; hop < 4 && cur; ++hop) {

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

                // Stores into the function's own return-slot alloca are
                // fine; only stores that actually go through the parameter
                // count.
                if (p == root) seen_store_via_arg = true;

              }

              if (isa<ReturnInst>(&I)) {

                reached_return = true;
                break;

              }

            }

            if (reached_return) break;
            // Walk through one unconditional branch.
            auto *T = dyn_cast<BranchInst>(cur->getTerminator());
            if (!T || !T->isUnconditional()) break;
            cur = T->getSuccessor(0);

          }

          if (reached_return && !seen_store_via_arg) {

            found_null_branch = true;

          }

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
static bool ptrStoreReachesArg(StoreInst                 *S,
                               const std::set<unsigned> &arg_indices) {

  // Spill helper: alloca written exactly once with an Argument whose
  // index is acceptable. Cheap and safe.
  auto allocaSpillsAcceptableArg = [&](AllocaInst *AI) -> bool {

    for (const User *U : AI->users()) {

      auto *St = dyn_cast<StoreInst>(U);
      if (!St || St->getPointerOperand() != AI) continue;
      auto *Arg = dyn_cast<Argument>(St->getValueOperand());
      if (!Arg) continue;
      if (arg_indices.empty() || arg_indices.count(Arg->getArgNo()))
        return true;

    }

    return false;

  };

  // Iterative DFS over the alias tree with a small visited-set guard.
  SmallVector<Value *, 8>     work;
  SmallPtrSet<Value *, 16>    seen;
  work.push_back(S->getPointerOperand());
  unsigned                    iters = 0;
  while (!work.empty() && iters++ < 32) {

    Value *ptr = work.pop_back_val();
    if (!seen.insert(ptr).second) continue;

    if (auto *Arg = dyn_cast<Argument>(ptr)) {

      if (arg_indices.empty() || arg_indices.count(Arg->getArgNo()))
        return true;
      continue;

    }

    if (auto *GEP = dyn_cast<GetElementPtrInst>(ptr)) {

      work.push_back(GEP->getPointerOperand());
      continue;

    }

    if (auto *BC = dyn_cast<BitCastInst>(ptr)) {

      work.push_back(BC->getOperand(0));
      continue;

    }

    if (auto *PN = dyn_cast<PHINode>(ptr)) {

      for (Value *Inc : PN->incoming_values()) work.push_back(Inc);
      continue;

    }

    if (auto *Sel = dyn_cast<SelectInst>(ptr)) {

      work.push_back(Sel->getTrueValue());
      work.push_back(Sel->getFalseValue());
      continue;

    }

    if (auto *Ld = dyn_cast<LoadInst>(ptr)) {

      if (auto *AI = dyn_cast<AllocaInst>(Ld->getPointerOperand()))
        if (allocaSpillsAcceptableArg(AI)) return true;
      continue;

    }

    // Stop at anything else (constant, call, intrinsic, etc).

  }

  return false;

}

// Copy the source instruction's DebugLoc onto `IB`'s recently-inserted
// instructions so crashes / backtraces resolve to the user's source line
// rather than the no-location bug-pass synthetic IR.
static void inheritDebugLoc(IRBuilder<> &B, Instruction *Source) {

  if (!Source) return;
  B.SetCurrentDebugLocation(Source->getDebugLoc());

}

// Try to recover the allocation size of a buffer at a use-site. Returns
// either a ConstantInt (statically known) or an SSA Value* representing
// the runtime size, both as i64. Returns nullptr if no anchor.
//
// Recognizes:
//   - alloca of constant array type            -> ConstantInt
//   - call malloc(N) / __afl_track_malloc(N)   -> Value* of N
//   - call calloc(N,S) / __afl_track_calloc    -> Value* of N*S
//   - call realloc(_,N) / __afl_track_realloc  -> Value* of N
//   - call _Znwm / _Znam (C++ operator new)    -> Value* of size arg
//
// `B` is an IRBuilder positioned where the resulting Value must be
// available. ZExt/Mul instructions for runtime sizes are inserted at B's
// insertion point. SSA dominance is automatic: a malloc-call's size
// operand dominates the malloc, which dominates any use of its return.
//
// Critically, this is what catches the libwebp-1.3.2-style idiom:
//   size = sentinel_fn(NULL, ...);   // returns runtime size
//   buf  = malloc(size);             // size flows through SSA
//   sentinel_fn(buf, ...);           // we instrument here
// — the runtime size of `buf` is recoverable from the malloc arg.
static Value *inferBufferSizeValue(Value *V, IRBuilder<> &B,
                                   const DataLayout &DL) {

  IntegerType *I64 = IntegerType::getInt64Ty(B.getContext());
  V = V->stripPointerCasts();
  // Peel through one level of spill (the optnone / -O0 idiom):
  //   p_slot = alloca ptr
  //   p = call malloc(sz)
  //   store p, p_slot        ; spill
  //   p2 = load p_slot       ; reload (this is V)
  //   foo(p2)
  // Only follow when there's exactly ONE store to the alloca and its value
  // is a call — otherwise the load could return a different value (e.g.,
  // null-init followed by lazy assign) and we'd report the wrong size.
  if (auto *Ld = dyn_cast<LoadInst>(V)) {

    if (auto *AI = dyn_cast<AllocaInst>(Ld->getPointerOperand())) {

      CallInst *unique_src = nullptr;
      bool      multi = false;
      for (User *U : AI->users()) {

        auto *St = dyn_cast<StoreInst>(U);
        if (!St || St->getPointerOperand() != AI) continue;
        auto *C = dyn_cast<CallInst>(
            St->getValueOperand()->stripPointerCasts());
        if (!C) {

          multi = true;
          break;

        }

        if (unique_src && unique_src != C) {

          multi = true;
          break;

        }

        unique_src = C;

      }

      if (!multi && unique_src) V = unique_src;

    }

  }

  if (auto *A = dyn_cast<AllocaInst>(V)) {

    if (auto *Cst = dyn_cast<ConstantInt>(A->getArraySize())) {

      uint64_t bytes =
          Cst->getZExtValue() * DL.getTypeStoreSize(A->getAllocatedType());
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
    if ((name == "malloc" || name == "__afl_track_malloc") &&
        Call->arg_size() >= 1 &&
        Call->getArgOperand(0)->getType()->isIntegerTy()) {

      return B.CreateZExtOrTrunc(Call->getArgOperand(0), I64);

    }

    if ((name == "calloc" || name == "__afl_track_calloc") &&
        Call->arg_size() >= 2 &&
        Call->getArgOperand(0)->getType()->isIntegerTy() &&
        Call->getArgOperand(1)->getType()->isIntegerTy()) {

      Value *N = B.CreateZExtOrTrunc(Call->getArgOperand(0), I64);
      Value *S = B.CreateZExtOrTrunc(Call->getArgOperand(1), I64);
      // Guard against N*S overflow: emit llvm.umul.with.overflow.i64, and
      // on overflow saturate to UINT64_MAX so the SIZEFILL `ret_size >
      // buf_size` check can't trip a false-positive abort. libc calloc
      // returns NULL on overflow anyway, so any access to the buffer
      // would null-deref before our check runs — saturating-to-max
      // intentionally suppresses our oracle on that path.
      Value *uoCall =
          B.CreateIntrinsic(Intrinsic::umul_with_overflow, {I64}, {N, S});
      Value *prod = B.CreateExtractValue(uoCall, 0);
      Value *ovf = B.CreateExtractValue(uoCall, 1);
      Value *maxU = ConstantInt::get(I64, UINT64_MAX);
      return B.CreateSelect(ovf, maxU, prod);

    }

    if ((name == "realloc" || name == "__afl_track_realloc") &&
        Call->arg_size() >= 2 &&
        Call->getArgOperand(1)->getType()->isIntegerTy()) {

      return B.CreateZExtOrTrunc(Call->getArgOperand(1), I64);

    }

    // C++ operator new — plain, array, and C++17 aligned variants. The
    // alignment arg of the aligned forms is irrelevant to the buffer size.
    if ((name == "_Znwm" || name == "_Znam" ||
         name == "_ZnwmSt11align_val_t" ||
         name == "_ZnamSt11align_val_t") &&
        Call->arg_size() >= 1 &&
        Call->getArgOperand(0)->getType()->isIntegerTy()) {

      return B.CreateZExtOrTrunc(Call->getArgOperand(0), I64);

    }

  }

  return nullptr;

}

bool runSizefillMode(Module &M, ModuleAnalysisManager &) {

  LLVMContext &C = M.getContext();
  Type        *VoidTy = Type::getVoidTy(C);
  IntegerType *I64 = IntegerType::getInt64Ty(C);
#if LLVM_MAJOR >= 20
  Type *PtrTy = PointerType::getUnqual(C);
#else
  Type *PtrTy = PointerType::get(IntegerType::getInt8Ty(C), 0);
#endif

  FunctionCallee sfCheck = M.getOrInsertFunction(
      "__afl_bug_sizefill_check", VoidTy, PtrTy, I64, I64);
  // Dedicated SIZEFILL begin/store hooks (do NOT reuse __afl_bug_ws_*),
  // so BUDGET and SIZEFILL can coexist under AFL_LLVM_BUG=all.
  FunctionCallee sfBegin =
      M.getOrInsertFunction("__afl_bug_sf_begin", VoidTy, PtrTy);
  FunctionCallee sfStore =
      M.getOrInsertFunction("__afl_bug_sf_store", VoidTy, PtrTy,
                            IntegerType::getInt32Ty(C));

  // 1) Find sentinel-param functions in this module.
  std::map<Function *, int> sentinel;
  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    int idx = findSentinelParam(F);
    if (idx >= 0) sentinel[&F] = idx;

  }

  if (sentinel.empty()) {

    if (getenv("AFL_QUIET") == nullptr)
      errs() << "[afl-bug] SIZEFILL: no sentinel-param functions found\n";
    return false;

  }

  // 2) For every call to such a function with a non-null pointer arg whose
  // buffer size we can infer, instrument ws_begin + post-call check, and
  // mark the callee for store-instrumentation.
  bool                 changed = false;
  unsigned             instrumented = 0;
  std::set<Function *> callees_to_instrument;
  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    for (BasicBlock &BB : F) {

      for (Instruction &I : BB) {

        auto *Call = dyn_cast<CallInst>(&I);
        if (!Call) continue;
        Function *cf = Call->getCalledFunction();
        if (!cf) continue;
        auto it = sentinel.find(cf);
        if (it == sentinel.end()) continue;
        unsigned pi = (unsigned)it->second;
        if (pi >= Call->arg_size()) continue;
        Value *p = Call->getArgOperand(pi);
        if (isa<ConstantPointerNull>(p->stripPointerCasts())) continue;
        /* Sentinel-arg functions returning void / pointer / float can't be
           checked here — sfCheck takes the returned size as i64. */
        if (!cf->getReturnType()->isIntegerTy()) continue;

        IRBuilder<> Pre(Call);
        inheritDebugLoc(Pre, Call);
        Value *bufsz = inferBufferSizeValue(p, Pre, M.getDataLayout());
        if (!bufsz) continue;

        Value *ptrCast = Pre.CreateBitOrPointerCast(p, PtrTy);
        Pre.CreateCall(sfBegin, {ptrCast});

        IRBuilder<> Post(Call->getNextNode());
        inheritDebugLoc(Post, Call);
        Value *ret64 = Post.CreateZExtOrTrunc(Call, I64);
        Value *pcast = Post.CreateBitOrPointerCast(p, PtrTy);
        Post.CreateCall(sfCheck, {pcast, ret64, bufsz});
        ++instrumented;
        callees_to_instrument.insert(cf);
        changed = true;

      }

    }

  }

  // Instrument stores in candidate callees. SIZEFILL doesn't have a
  // single budget-traced arg (the sentinel-arg discovery is per-callee
  // not per-call-site), so pass an empty arg_indices set — equivalent to
  // "any arg counts". Same robust walk as BUDGET via the shared helper.
  IntegerType                          *I32 = IntegerType::getInt32Ty(C);
  const std::set<unsigned>              any_arg;
  for (Function *F : callees_to_instrument) {

    for (BasicBlock &BB : *F) {

      for (Instruction &I : BB) {

        auto *S = dyn_cast<StoreInst>(&I);
        if (!S) continue;
        if (isa<Argument>(S->getValueOperand())) continue;
        if (!ptrStoreReachesArg(S, any_arg)) continue;
        IRBuilder<> SB(S);
        inheritDebugLoc(SB, S);
        Value *addr =
            SB.CreateBitOrPointerCast(S->getPointerOperand(), PtrTy);
        uint64_t sz = M.getDataLayout().getTypeStoreSize(
            S->getValueOperand()->getType());
        SB.CreateCall(sfStore, {addr, ConstantInt::get(I32, (uint32_t)sz)});

      }

    }

  }

  if (getenv("AFL_QUIET") == nullptr)
    errs() << "[afl-bug] SIZEFILL instrumented " << instrumented
           << " call sites across " << sentinel.size() << " callees\n";
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
bool runSlackMode(Module &M, ModuleAnalysisManager &) {

  LLVMContext &C = M.getContext();
  Type        *VoidTy = Type::getVoidTy(C);
  IntegerType *I32 = IntegerType::getInt32Ty(C);
  IntegerType *I64 = IntegerType::getInt64Ty(C);

  FunctionCallee slackHook =
      M.getOrInsertFunction("__afl_bug_slack_min", VoidTy, I32, I64);

  uint32_t next_id = 0;
  uint32_t sites = 0;
  bool     changed = false;

  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    if (!isInInstrumentList(&F, F.getName().str())) continue;

    // Collect first, instrument afterwards — avoid the iterator visiting
    // our own inserted Sub/Neg/Select instructions.
    std::vector<ICmpInst *> targets;
    for (BasicBlock &BB : F) {

      for (Instruction &I : BB) {

        auto *Cmp = dyn_cast<ICmpInst>(&I);
        if (!Cmp) continue;
        Type *OpTy = Cmp->getOperand(0)->getType();
        auto *IT = dyn_cast<IntegerType>(OpTy);
        if (!IT) continue;  // skip pointer / vector / fp comparisons
        if (IT->getBitWidth() < 8 || IT->getBitWidth() > 64) continue;
        // Skip if both operands constant — optimizer would fold; defensive.
        if (isa<Constant>(Cmp->getOperand(0)) &&
            isa<Constant>(Cmp->getOperand(1)))
          continue;
        targets.push_back(Cmp);

      }

    }

    for (ICmpInst *Cmp : targets) {

      IRBuilder<> B(Cmp);
      inheritDebugLoc(B, Cmp);
      Value *Op0 = Cmp->getOperand(0);
      Value *Op1 = Cmp->getOperand(1);
      // Sign-extend for signed predicates, zero-extend for unsigned /
      // equality. The choice is load-bearing here: a naive `|diff|` via
      // select-on-sign breaks for i64 unsigned operands whose true
      // distance saturates the sign bit (e.g. 0xFFFF.. vs 0 has signed
      // value −1, neg → 1, but the actual distance is 0xFFFF..). Use the
      // predicate's signedness to pick the subtraction ORDER instead —
      // branch-free, correct at every width, no overflow on the result
      // because `large - small` of same-width nonneg-in-domain values
      // never wraps.
      Value *Op0_64, *Op1_64;
      Value *lt;
      if (Cmp->isSigned()) {

        Op0_64 = B.CreateSExtOrTrunc(Op0, I64);
        Op1_64 = B.CreateSExtOrTrunc(Op1, I64);
        lt = B.CreateICmpSLT(Op0_64, Op1_64);

      } else {

        Op0_64 = B.CreateZExtOrTrunc(Op0, I64);
        Op1_64 = B.CreateZExtOrTrunc(Op1, I64);
        lt = B.CreateICmpULT(Op0_64, Op1_64);

      }

      Value *small = B.CreateSelect(lt, Op0_64, Op1_64);
      Value *large = B.CreateSelect(lt, Op1_64, Op0_64);
      Value *slack = B.CreateSub(large, small);

      uint32_t id = (next_id++) & (MAP_SIZE_BUG_ENTRIES - 1);
      B.CreateCall(slackHook, {ConstantInt::get(I32, id), slack});
      ++sites;
      changed = true;

    }

  }

  if (getenv("AFL_QUIET") == nullptr)
    errs() << "[afl-bug] SLACK instrumented " << sites << " icmp sites\n";
  return changed;

}

// Direct-call signature pairs we know how to rewrite. The pair members are:
//   { libc_name, replacement_name, is_calloc, is_realloc, is_free,
//     is_posix_memalign }
struct AllocRewriteSpec {

  StringRef libc;
  StringRef tracked;
  bool      is_calloc;
  bool      is_realloc;
  bool      is_free;
  bool      is_posix_memalign;
  // Aligned-new (C++17): (size_t, std::align_val_t) -> ptr. We ignore the
  // alignment when feeding the tracker — alignment is a constraint, not a
  // size — and rewrite as malloc(size). Aligned-delete: (ptr, align_val_t).
  bool      is_aligned_new;
  bool      is_aligned_delete;

};

static const AllocRewriteSpec kRewriteSpecs[] = {
    {"malloc", "__afl_track_malloc", false, false, false, false, false,
     false},
    {"calloc", "__afl_track_calloc", true, false, false, false, false,
     false},
    {"realloc", "__afl_track_realloc", false, true, false, false, false,
     false},
    {"posix_memalign", "__afl_track_posix_memalign", false, false, false,
     true, false, false},
    {"free", "__afl_track_free", false, false, true, false, false, false},
    // Itanium C++ ABI (Linux/macOS). Routed to the same malloc/free runtime
    // hooks; signatures match (size_t -> ptr, ptr -> void).
    //
    // SEMANTICS NOTE: the *throwing* operator new (_Znwm/_Znam) is replaced
    // with __afl_track_malloc, which returns NULL on allocator failure
    // rather than throwing std::bad_alloc. C++ code that assumes `new`
    // never returns NULL will null-deref under fuzzer-triggered OOM —
    // generally fine for fuzzing (more crashes = more signal) but a real
    // observable behavior change. Build with -fno-exceptions for cleanest
    // matching, or disable AFL_LLVM_BUG_ALLOCSIZE for production-mode runs.
    //
    // Sized delete (_ZdlPvm/_ZdaPvm) is intentionally omitted — its 2-arg
    // signature would fail the is_free=1-arg guard in Phase 1. Compile
    // C++ targets with -fno-sized-deallocation to ensure full coverage,
    // or extend the spec with an is_sized_free flag.
    {"_Znwm", "__afl_track_malloc", false, false, false, false, false,
     false},
    {"_Znam", "__afl_track_malloc", false, false, false, false, false,
     false},
    {"_ZdlPv", "__afl_track_free", false, false, true, false, false,
     false},
    {"_ZdaPv", "__afl_track_free", false, false, true, false, false,
     false},
    // C++17 aligned new / delete. The `tracked` name is
    // __afl_track_aligned_alloc (NOT plain __afl_track_malloc) so the
    // posix_memalign-backed allocation honors the requested alignment;
    // see Phase 1 rewrite + runtime hook for the rationale.
    {"_ZnwmSt11align_val_t", "__afl_track_aligned_alloc", false, false,
     false, false, true, false},
    {"_ZnamSt11align_val_t", "__afl_track_aligned_alloc", false, false,
     false, false, true, false},
    {"_ZdlPvSt11align_val_t", "__afl_track_free", false, false, false,
     false, false, true},
    {"_ZdaPvSt11align_val_t", "__afl_track_free", false, false, false,
     false, false, true},
};

bool runAllocSizeMode(Module &M, ModuleAnalysisManager &,
                      const std::vector<std::string> &custom) {

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
  FunctionCallee trackCalloc =
      M.getOrInsertFunction("__afl_track_calloc", PtrTy, I64, I64, I32);
  FunctionCallee trackRealloc = M.getOrInsertFunction(
      "__afl_track_realloc", PtrTy, PtrTy, I64, I32);
  FunctionCallee trackPmemalign = M.getOrInsertFunction(
      "__afl_track_posix_memalign", I32, PtrTy, I64, I64, I32);
  FunctionCallee trackAlignedAlloc = M.getOrInsertFunction(
      "__afl_track_aligned_alloc", PtrTy, I64, I64, I32);
  FunctionCallee trackFree =
      M.getOrInsertFunction("__afl_track_free", VoidTy, PtrTy);
  FunctionCallee allocReg = M.getOrInsertFunction(
      "__afl_alloc_register", VoidTy, PtrTy, I64, I32);

  uint32_t              next_alloc_id = 1;
  uint32_t              rewrites = 0, custom_inserts = 0;
  std::set<std::string> custom_set(custom.begin(), custom.end());

  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    if (!isInInstrumentList(&F, F.getName().str())) continue;
    std::vector<Instruction *> dead;
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
        if (!Call || (!isa<CallInst>(Call) && !isa<InvokeInst>(Call)))
          continue;
        Function *cf = Call->getCalledFunction();
        if (!cf) continue;
        StringRef name = cf->getName();
        // 1) Direct rewrite for libc allocators.
        bool matched = false;
        for (const AllocRewriteSpec &spec : kRewriteSpecs) {

          if (name != spec.libc) continue;
          /* Defensive signature check: only rewrite calls whose args match
             the expected libc shape. With AFL_USE_ASAN=1 + CmpLog,
             user code that shadows malloc/etc. with a different signature
             would otherwise hit IRBuilder asserts. */
          unsigned expected_args =
              spec.is_free                   ? 1
              : (spec.is_realloc)            ? 2
              : (spec.is_calloc)             ? 2
              : (spec.is_posix_memalign)     ? 3
              : (spec.is_aligned_new)        ? 2
              : (spec.is_aligned_delete)     ? 2
                                             : 1;  /* malloc */
          if (Call->arg_size() != expected_args) continue;
          if (spec.is_free) {

            if (!Call->getArgOperand(0)->getType()->isPointerTy()) continue;

          } else if (spec.is_realloc) {

            if (!Call->getArgOperand(0)->getType()->isPointerTy() ||
                !Call->getArgOperand(1)->getType()->isIntegerTy())
              continue;

          } else if (spec.is_calloc) {

            if (!Call->getArgOperand(0)->getType()->isIntegerTy() ||
                !Call->getArgOperand(1)->getType()->isIntegerTy())
              continue;

          } else if (spec.is_posix_memalign) {

            if (!Call->getArgOperand(0)->getType()->isPointerTy() ||
                !Call->getArgOperand(1)->getType()->isIntegerTy() ||
                !Call->getArgOperand(2)->getType()->isIntegerTy())
              continue;

          } else if (spec.is_aligned_new) {

            if (!Call->getArgOperand(0)->getType()->isIntegerTy() ||
                !Call->getArgOperand(1)->getType()->isIntegerTy())
              continue;

          } else if (spec.is_aligned_delete) {

            if (!Call->getArgOperand(0)->getType()->isPointerTy() ||
                !Call->getArgOperand(1)->getType()->isIntegerTy())
              continue;

          } else { /* malloc */

            if (!Call->getArgOperand(0)->getType()->isIntegerTy()) continue;

          }

          IRBuilder<> B(Call);
          inheritDebugLoc(B, Call);
          uint32_t     id = next_alloc_id++;
          ConstantInt *idC = ConstantInt::get(I32, id);
          CallInst    *NewCall = nullptr;
          if (spec.is_free) {

            NewCall = B.CreateCall(trackFree, {Call->getArgOperand(0)});

          } else if (spec.is_realloc) {

            NewCall = B.CreateCall(
                trackRealloc,
                {Call->getArgOperand(0),
                 B.CreateZExtOrTrunc(Call->getArgOperand(1), I64), idC});

          } else if (spec.is_calloc) {

            NewCall = B.CreateCall(
                trackCalloc,
                {B.CreateZExtOrTrunc(Call->getArgOperand(0), I64),
                 B.CreateZExtOrTrunc(Call->getArgOperand(1), I64), idC});

          } else if (spec.is_posix_memalign) {

            NewCall = B.CreateCall(
                trackPmemalign,
                {Call->getArgOperand(0),
                 B.CreateZExtOrTrunc(Call->getArgOperand(1), I64),
                 B.CreateZExtOrTrunc(Call->getArgOperand(2), I64), idC});

          } else if (spec.is_aligned_new) {

            // Preserve the alignment by routing through
            // __afl_track_aligned_alloc (which calls posix_memalign).
            // Rewriting to plain __afl_track_malloc would hand out an
            // under-aligned buffer; subsequent SIMD/over-aligned access
            // would fault, manufacturing crashes that don't reflect real
            // bugs in the target.
            NewCall = B.CreateCall(
                trackAlignedAlloc,
                {B.CreateZExtOrTrunc(Call->getArgOperand(0), I64),
                 B.CreateZExtOrTrunc(Call->getArgOperand(1), I64), idC});

          } else if (spec.is_aligned_delete) {

            NewCall = B.CreateCall(trackFree, {Call->getArgOperand(0)});

          } else { /* malloc */

            NewCall = B.CreateCall(
                trackMalloc,
                {B.CreateZExtOrTrunc(Call->getArgOperand(0), I64), idC});

          }

          if (!Call->use_empty()) Call->replaceAllUsesWith(NewCall);
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
        // 2) Manual register for user-listed custom allocators.
        if (!custom_set.count(name.str())) continue;
        /* Custom allocator must return a pointer — its result is passed to
           __afl_alloc_register's first arg (PtrTy). Reject void/int/etc. */
        if (!cf->getReturnType()->isPointerTy()) continue;
        // Position the post-call register: for a CallInst that's the
        // next instruction; for an InvokeInst it's the top of the
        // normal-dest block (after any leading PHIs).
        Instruction *PostInsertAt = nullptr;
        if (auto *II = dyn_cast<InvokeInst>(Call))
          PostInsertAt = &*II->getNormalDest()->getFirstInsertionPt();
        else
          PostInsertAt = Call->getNextNode();
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

          auto *IT =
              dyn_cast<IntegerType>(Call->getArgOperand(i)->getType());
          if (!IT) continue;
          if (IT->getBitWidth() >= bestBits) {

            bestBits = IT->getBitWidth();
            sizeArg = Call->getArgOperand(i);

          }

        }

        if (!sizeArg) continue;
        uint32_t id = next_alloc_id++;
        Post.CreateCall(allocReg,
                        {Call, Post.CreateZExtOrTrunc(sizeArg, I64),
                         ConstantInt::get(I32, id)});
        ++custom_inserts;

      }

    }

    for (auto *I : dead) I->eraseFromParent();

  }

  // Phase 2: instrument every store inside a loop whose pointer base is a
  // call to one of our tracked allocators (post-rewrite name OR custom).
  // Signature is (addr, write_size_bytes); the write_size lets the runtime
  // check `off + sz > alloc_size` instead of just `off < alloc_size`, so a
  // 4-byte store at the last 1 byte of the buffer is flagged correctly.
  FunctionCallee oracle =
      M.getOrInsertFunction("__afl_alloc_oracle", VoidTy, PtrTy, I32);

  std::set<StringRef> tracked_callee_names;
  for (const AllocRewriteSpec &s : kRewriteSpecs) {

    // Skip dealloc specs — their `tracked` is __afl_track_free, which
    // doesn't return a pointer and isn't a candidate for store-tracking.
    if (s.is_free || s.is_aligned_delete) continue;
    tracked_callee_names.insert(s.tracked);

  }

  for (const std::string &n : custom) tracked_callee_names.insert(n);

  // Resolve a pointer to the set of allocator-call sources that could
  // back it. Walks GEP/BitCast/PHI/Select/spill-load chains with a cycle
  // guard. Returns true if EVERY traced root is a call to one of our
  // tracked allocators — otherwise we'd be checking a stack/global/other
  // address against an allocator's bookkeeping, producing noise.
  auto pointerOnlyTouchesTrackedAlloc = [&](Value *p) -> bool {

    SmallPtrSet<Value *, 16> seen;
    SmallVector<Value *, 8>  work;
    work.push_back(p);
    bool any = false;
    unsigned iters = 0;
    while (!work.empty() && iters++ < 64) {

      Value *v = work.pop_back_val();
      if (!seen.insert(v).second) continue;
      v = v->stripPointerCasts();

      if (auto *GEP = dyn_cast<GetElementPtrInst>(v)) {

        work.push_back(GEP->getPointerOperand());
        continue;

      }

      if (auto *PN = dyn_cast<PHINode>(v)) {

        for (Value *Inc : PN->incoming_values()) work.push_back(Inc);
        continue;

      }

      if (auto *Sel = dyn_cast<SelectInst>(v)) {

        work.push_back(Sel->getTrueValue());
        work.push_back(Sel->getFalseValue());
        continue;

      }

      // Direct call to a tracked allocator.
      if (auto *Call = dyn_cast<CallBase>(v)) {

        Function *callee = Call->getCalledFunction();
        if (callee && tracked_callee_names.count(callee->getName())) {

          any = true;
          continue;

        }

        return false;

      }

      // Spilled call result: alloca written exactly once with a tracked
      // allocator call.
      if (auto *Ld = dyn_cast<LoadInst>(v)) {

        if (auto *AI = dyn_cast<AllocaInst>(Ld->getPointerOperand())) {

          bool   resolved = false;
          for (const User *U : AI->users()) {

            auto *St = dyn_cast<StoreInst>(U);
            if (!St || St->getPointerOperand() != AI) continue;
            auto *C2 = dyn_cast<CallBase>(
                St->getValueOperand()->stripPointerCasts());
            if (!C2) {

              resolved = false;
              break;

            }

            Function *callee = C2->getCalledFunction();
            if (!callee ||
                !tracked_callee_names.count(callee->getName())) {

              resolved = false;
              break;

            }

            resolved = true;

          }

          if (resolved) {

            any = true;
            continue;

          }

        }

        return false;

      }

      // Anything else (alloca, global, argument, undef) — not ours.
      return false;

    }

    return any;

  };

  uint32_t store_sites = 0;
  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    if (!isInInstrumentList(&F, F.getName().str())) continue;
    // Walk every store in the function, not just loop-internal ones. The
    // oracle runtime is cheap on shadow miss, and OOB writes happen
    // outside loops too (e.g., one-shot `arr[computed_idx] = x`).
    for (BasicBlock &BB : F) {

      for (Instruction &I : BB) {

        auto *S = dyn_cast<StoreInst>(&I);
        if (!S) continue;
        if (!pointerOnlyTouchesTrackedAlloc(S->getPointerOperand()))
          continue;
        IRBuilder<> SB(S);
        inheritDebugLoc(SB, S);
        Value *addr =
            SB.CreateBitOrPointerCast(S->getPointerOperand(), PtrTy);
        uint64_t sz = M.getDataLayout().getTypeStoreSize(
            S->getValueOperand()->getType());
        SB.CreateCall(oracle, {addr, ConstantInt::get(I32, (uint32_t)sz)});
        ++store_sites;

      }

    }

  }

  if (getenv("AFL_QUIET") == nullptr)
    errs() << "[afl-bug] ALLOCSIZE rewrote " << rewrites
           << " libc allocator calls, " << custom_inserts
           << " custom-allocator registrations, " << store_sites
           << " stores instrumented\n";
  return rewrites > 0 || custom_inserts > 0 || store_sites > 0;

}

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "afl-bug-pass", "v0.1",
          [](PassBuilder &PB) {

#if LLVM_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel
#if LLVM_MAJOR >= 20
                   ,
                   ThinOrFullLTOPhase
#endif
                ) { MPM.addPass(BugPass()); });

          }};

}
