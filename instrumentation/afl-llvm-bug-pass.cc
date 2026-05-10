// instrumentation/afl-llvm-bug-pass.cc
//
// AFL++ bug-finding pass: implements three independent oracles:
//   - SCALAR  : max-value-per-arithmetic-site coverage  (#2 from design)
//   - BUDGET  : ptr += func() write-extent contract     (#3)
//   - SIZEFILL: NULL-means-size idiom self-consistency  (#4)
//
// Each is enabled by AFL_LLVM_BUG_<name>=1 (or AFL_LLVM_BUG=all).
//
// Modeled on cmplog-instructions-pass.cc.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <set>
#include <vector>

#include "llvm/Config/llvm-config.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
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
  std::vector<std::string> custom_alloc_funcs;
  bool any() const { return scalar || budget || sizefill || allocsize; }

};

static BugPassConfig parseEnv() {

  BugPassConfig c;
  if (const char *all = getenv(AFL_BUG_ENV_ALL)) {

    if (*all && strcmp(all, "0") != 0) {

      c.scalar = c.budget = c.sizefill = c.allocsize = true;

    }

  }

  if (getenv(AFL_BUG_ENV_SCALAR)) c.scalar = true;
  if (getenv(AFL_BUG_ENV_BUDGET)) c.budget = true;
  if (getenv(AFL_BUG_ENV_SIZEFILL)) c.sizefill = true;
  if (getenv(AFL_BUG_ENV_ALLOCSIZE)) c.allocsize = true;
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

// Forward decls: implemented in later tasks.
bool runScalarMode(Module &M, ModuleAnalysisManager &MAM);
bool runBudgetMode(Module &M, ModuleAnalysisManager &MAM);
bool runSizefillMode(Module &M, ModuleAnalysisManager &MAM);
bool runAllocSizeMode(Module &M, ModuleAnalysisManager &MAM,
                      const std::vector<std::string> &custom);

PreservedAnalyses BugPass::run(Module &M, ModuleAnalysisManager &MAM) {

  BugPassConfig cfg = parseEnv();
  if (!cfg.any()) return PreservedAnalyses::all();

  if (getenv("AFL_QUIET") == nullptr) {

    errs() << "[afl-bug] enabled modes:" << (cfg.scalar ? " SCALAR" : "")
           << (cfg.budget ? " BUDGET" : "")
           << (cfg.sizefill ? " SIZEFILL" : "")
           << (cfg.allocsize ? " ALLOCSIZE" : "") << "\n";

  }

  bool changed = false;
  if (cfg.scalar) changed |= runScalarMode(M, MAM);
  if (cfg.budget) changed |= runBudgetMode(M, MAM);
  if (cfg.sizefill) changed |= runSizefillMode(M, MAM);
  if (cfg.allocsize)
    changed |= runAllocSizeMode(M, MAM, cfg.custom_alloc_funcs);
  return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();

}

// Heuristic filter: skip values that are clearly addresses, sizes-of-input,
// or loop-induction. Conservative — we'd rather miss a site than spam the map.
static bool ScalarSiteWorthInstrumenting(BinaryOperator *I) {

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
  if (IT->getBitWidth() < 16 || IT->getBitWidth() > 64) return false;
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

        if (!ScalarSiteWorthInstrumenting(Bin)) continue;
        IRBuilder<> B(Bin->getNextNode());
        Value      *v64 = B.CreateZExtOrTrunc(Bin, I64);
        uint32_t    id = (next_id++) & (MAP_SIZE_BUG_ENTRIES - 1);
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

    IRBuilder<>                                EB(&*F.getEntryBlock().getFirstInsertionPt());
    std::vector<std::pair<AllocaInst *, uint32_t>> counters;
    for (Loop *L : LI.getLoopsInPreorder()) {

      AllocaInst *cnt = EB.CreateAlloca(I32);
      EB.CreateStore(ConstantInt::get(I32, 0), cnt);
      uint32_t id = (next_id++) & (MAP_SIZE_BUG_ENTRIES - 1);
      ++loop_sites;
      // Increment at the loop header.
      IRBuilder<> HB(&*L->getHeader()->getFirstInsertionPt());
      Value      *cur = HB.CreateLoad(I32, cnt);
      Value      *inc = HB.CreateAdd(cur, ConstantInt::get(I32, 1));
      HB.CreateStore(inc, cnt);
      counters.emplace_back(cnt, id);

    }

    // Flush at every return.
    for (BasicBlock &BB : F) {

      auto *Ret = dyn_cast<ReturnInst>(BB.getTerminator());
      if (!Ret) continue;
      IRBuilder<> RB(Ret);
      for (auto &kv : counters) {

        Value *v = RB.CreateLoad(I32, kv.first);
        RB.CreateCall(loopFlush, {ConstantInt::get(I32, kv.second), v});

      }

    }

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

  // Collect callees that need their stores instrumented.
  std::set<Function *> callees_to_instrument;

  bool changed = false;
  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    if (!isInInstrumentList(&F, F.getName().str())) continue;
    for (auto &m : findBudgetCalls(F)) {

      Function *callee = m.Call->getCalledFunction();
      if (!callee || callee->isDeclaration()) continue;  // intra-module only

      IRBuilder<> Pre(m.Call);
      Value      *ptrCast = Pre.CreateBitOrPointerCast(m.PtrBefore, PtrTy);
      Pre.CreateCall(wsBegin, {ptrCast});

      IRBuilder<> Post(m.Call->getNextNode());
      Value      *ret64 = Post.CreateZExtOrTrunc(m.Call, I64);
      Value      *ptrCast2 = Post.CreateBitOrPointerCast(m.PtrBefore, PtrTy);
      Post.CreateCall(wsCheck, {ptrCast2, ret64});

      callees_to_instrument.insert(callee);
      changed = true;

    }

  }

  // Instrument stores whose pointer traces to a function argument. Stack-
  // local stores (alloca-derived) and global stores are skipped to avoid
  // tracking unrelated writes that happen to land near the buffer.
  for (Function *F : callees_to_instrument) {

    for (BasicBlock &BB : *F) {

      for (Instruction &I : BB) {

        auto *S = dyn_cast<StoreInst>(&I);
        if (!S) continue;
        // Trace the store's pointer operand back to its origin: either
        // directly a function argument, or through a parameter-spill
        // (load from an alloca that was written the arg). Stores that
        // don't reach an arg this way (stack locals, the spill store
        // itself, etc.) are skipped.
        Value *ptr = S->getPointerOperand();
        bool   reaches_arg = false;
        for (int depth = 0; depth < 8; ++depth) {

          if (auto *GEP = dyn_cast<GetElementPtrInst>(ptr)) {

            ptr = GEP->getPointerOperand();
            continue;

          }

          if (auto *BC = dyn_cast<BitCastInst>(ptr)) {

            ptr = BC->getOperand(0);
            continue;

          }

          if (auto *L = dyn_cast<LoadInst>(ptr)) {

            auto *AI = dyn_cast<AllocaInst>(L->getPointerOperand());
            if (!AI) break;
            for (const User *U : AI->users()) {

              auto *St = dyn_cast<StoreInst>(U);
              if (!St || St->getPointerOperand() != AI) continue;
              if (isa<Argument>(St->getValueOperand())) {

                reaches_arg = true;
                break;

              }

            }

            break;

          }

          if (isa<Argument>(ptr)) {

            reaches_arg = true;
            break;

          }

          break;

        }

        if (!reaches_arg) continue;
        // Defensive: skip the spill itself (storing the argument into its
        // alloca).
        if (isa<Argument>(S->getValueOperand())) continue;
        IRBuilder<> SB(S);
        Value      *addr =
            SB.CreateBitOrPointerCast(S->getPointerOperand(), PtrTy);
        uint64_t sz = M.getDataLayout().getTypeStoreSize(
            S->getValueOperand()->getType());
        SB.CreateCall(wsStore, {addr, ConstantInt::get(I32, (uint32_t)sz)});

      }

    }

  }

  if (getenv("AFL_QUIET") == nullptr)
    errs() << "[afl-bug] BUDGET instrumented " << callees_to_instrument.size()
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

// Try to recover the allocation size of a buffer at a use-site. Recognizes:
//   - alloca of constant array type
//   - call to malloc(C) or calloc(N, C) with constant args
// Returns 0 if unknown.
static uint64_t inferBufferSize(Value *V, const DataLayout &DL) {

  V = V->stripPointerCasts();
  if (auto *A = dyn_cast<AllocaInst>(V)) {

    if (auto *C = dyn_cast<ConstantInt>(A->getArraySize()))
      return C->getZExtValue() * DL.getTypeStoreSize(A->getAllocatedType());

  }

  if (auto *Call = dyn_cast<CallInst>(V)) {

    Function *cf = Call->getCalledFunction();
    if (!cf) return 0;
    StringRef name = cf->getName();
    if (name == "malloc" && Call->arg_size() == 1) {

      if (auto *C = dyn_cast<ConstantInt>(Call->getArgOperand(0)))
        return C->getZExtValue();

    }

    if (name == "calloc" && Call->arg_size() == 2) {

      auto *N = dyn_cast<ConstantInt>(Call->getArgOperand(0));
      auto *S = dyn_cast<ConstantInt>(Call->getArgOperand(1));
      if (N && S) return N->getZExtValue() * S->getZExtValue();

    }

  }

  return 0;

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
  FunctionCallee wsBegin =
      M.getOrInsertFunction("__afl_bug_ws_begin", VoidTy, PtrTy);
  FunctionCallee wsStore =
      M.getOrInsertFunction("__afl_bug_ws_store", VoidTy, PtrTy,
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
        uint64_t bufsz = inferBufferSize(p, M.getDataLayout());
        if (!bufsz) continue;

        IRBuilder<> Pre(Call);
        Value      *ptrCast = Pre.CreateBitOrPointerCast(p, PtrTy);
        Pre.CreateCall(wsBegin, {ptrCast});

        IRBuilder<> Post(Call->getNextNode());
        Value      *ret64 = Post.CreateZExtOrTrunc(Call, I64);
        Value      *pcast = Post.CreateBitOrPointerCast(p, PtrTy);
        Post.CreateCall(sfCheck,
                        {pcast, ret64, ConstantInt::get(I64, bufsz)});
        ++instrumented;
        callees_to_instrument.insert(cf);
        changed = true;

      }

    }

  }

  // Instrument stores in candidate callees (same logic as BUDGET).
  IntegerType *I32 = IntegerType::getInt32Ty(C);
  for (Function *F : callees_to_instrument) {

    for (BasicBlock &BB : *F) {

      for (Instruction &I : BB) {

        auto *S = dyn_cast<StoreInst>(&I);
        if (!S) continue;
        Value *ptr = S->getPointerOperand();
        bool   reaches_arg = false;
        for (int depth = 0; depth < 8; ++depth) {

          if (auto *GEP = dyn_cast<GetElementPtrInst>(ptr)) {

            ptr = GEP->getPointerOperand();
            continue;

          }

          if (auto *BC = dyn_cast<BitCastInst>(ptr)) {

            ptr = BC->getOperand(0);
            continue;

          }

          if (auto *L = dyn_cast<LoadInst>(ptr)) {

            auto *AI = dyn_cast<AllocaInst>(L->getPointerOperand());
            if (!AI) break;
            for (const User *U : AI->users()) {

              auto *St = dyn_cast<StoreInst>(U);
              if (!St || St->getPointerOperand() != AI) continue;
              if (isa<Argument>(St->getValueOperand())) {

                reaches_arg = true;
                break;

              }

            }

            break;

          }

          if (isa<Argument>(ptr)) {

            reaches_arg = true;
            break;

          }

          break;

        }

        if (!reaches_arg) continue;
        if (isa<Argument>(S->getValueOperand())) continue;
        IRBuilder<> SB(S);
        Value      *addr =
            SB.CreateBitOrPointerCast(S->getPointerOperand(), PtrTy);
        uint64_t sz = M.getDataLayout().getTypeStoreSize(
            S->getValueOperand()->getType());
        SB.CreateCall(wsStore, {addr, ConstantInt::get(I32, (uint32_t)sz)});

      }

    }

  }

  if (getenv("AFL_QUIET") == nullptr)
    errs() << "[afl-bug] SIZEFILL instrumented " << instrumented
           << " call sites across " << sentinel.size() << " callees\n";
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

};

static const AllocRewriteSpec kRewriteSpecs[] = {
    {"malloc", "__afl_track_malloc", false, false, false, false},
    {"calloc", "__afl_track_calloc", true, false, false, false},
    {"realloc", "__afl_track_realloc", false, true, false, false},
    {"posix_memalign", "__afl_track_posix_memalign", false, false, false,
     true},
    {"free", "__afl_track_free", false, false, true, false},
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

      for (Instruction &I : BB) {

        auto *Call = dyn_cast<CallInst>(&I);
        if (!Call) continue;
        Function *cf = Call->getCalledFunction();
        if (!cf) continue;
        StringRef name = cf->getName();
        // 1) Direct rewrite for libc allocators.
        bool matched = false;
        for (const AllocRewriteSpec &spec : kRewriteSpecs) {

          if (name != spec.libc) continue;
          IRBuilder<>  B(Call);
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

          } else { /* malloc */

            NewCall = B.CreateCall(
                trackMalloc,
                {B.CreateZExtOrTrunc(Call->getArgOperand(0), I64), idC});

          }

          if (!Call->use_empty()) Call->replaceAllUsesWith(NewCall);
          dead.push_back(Call);
          ++rewrites;
          matched = true;
          break;

        }

        if (matched) continue;
        // 2) Manual register for user-listed custom allocators.
        if (!custom_set.count(name.str())) continue;
        if (cf->getReturnType() == VoidTy) continue;
        IRBuilder<> Post(Call->getNextNode());
        Value      *sizeArg = nullptr;
        for (unsigned i = 0; i < Call->arg_size(); ++i) {

          if (Call->getArgOperand(i)->getType()->isIntegerTy()) {

            sizeArg = Call->getArgOperand(i);
            break;

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
  FunctionCallee oracle =
      M.getOrInsertFunction("__afl_alloc_oracle", VoidTy, PtrTy);

  std::set<StringRef> tracked_callee_names;
  for (const AllocRewriteSpec &s : kRewriteSpecs) {

    if (s.is_free) continue;
    tracked_callee_names.insert(s.tracked);

  }

  for (const std::string &n : custom) tracked_callee_names.insert(n);

  uint32_t store_sites = 0;
  for (Function &F : M) {

    if (F.isDeclaration()) continue;
    if (!isInInstrumentList(&F, F.getName().str())) continue;
    DominatorTree DT(F);
    LoopInfo      LI(DT);
    if (LI.empty()) continue;
    for (Loop *L : LI.getLoopsInPreorder()) {

      for (BasicBlock *BB : L->blocks()) {

        for (Instruction &I : *BB) {

          auto *S = dyn_cast<StoreInst>(&I);
          if (!S) continue;
          const Value    *uo = getUnderlyingObject(S->getPointerOperand());
          const CallInst *src_call = dyn_cast<CallInst>(uo);
          if (!src_call) {

            if (auto *AI = dyn_cast<AllocaInst>(uo)) {

              for (const User *U : AI->users()) {

                auto *St = dyn_cast<StoreInst>(U);
                if (!St || St->getPointerOperand() != AI) continue;
                if (auto *C2 = dyn_cast<CallInst>(St->getValueOperand())) {

                  src_call = C2;
                  break;

                }

              }

            }

          }

          if (!src_call) continue;
          Function *callee = src_call->getCalledFunction();
          if (!callee) continue;
          if (!tracked_callee_names.count(callee->getName())) continue;
          IRBuilder<> SB(S);
          Value      *addr =
              SB.CreateBitOrPointerCast(S->getPointerOperand(), PtrTy);
          SB.CreateCall(oracle, {addr});
          ++store_sites;

        }

      }

    }

  }

  if (getenv("AFL_QUIET") == nullptr)
    errs() << "[afl-bug] ALLOCSIZE rewrote " << rewrites
           << " libc allocator calls, " << custom_inserts
           << " custom-allocator registrations, " << store_sites
           << " in-loop stores instrumented\n";
  return rewrites > 0 || custom_inserts > 0 || store_sites > 0;

}

}  // namespace

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "afl-bug-pass", "v0.1",
          [](PassBuilder &PB) {

#if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel
#if LLVM_VERSION_MAJOR >= 20
                   ,
                   ThinOrFullLTOPhase
#endif
                ) { MPM.addPass(BugPass()); });

          }};

}
