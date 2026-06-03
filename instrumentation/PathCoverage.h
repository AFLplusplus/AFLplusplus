/*
   american fuzzy lop++ - part of the AFL++ project
   ------------------------------------------------

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

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

/*
   AFL++ Ball-Larus path coverage — shared analysis.

   Used by both SanitizerCoverageLTO.so.cc and SanitizerCoveragePCGUARD.so.cc.
   Computes per-function:
     - exit points (return, resume, unreachable, before noreturn calls)
     - acyclic path count (back-edges stripped via iterative DFS)
     - Ball-Larus prefix-sum edge values

   Modes (level_):
     1 = relaxed    : collapse every guard-only BB (more than one successor)
                      via max() instead of sum() — short-circuit && / ||,
                      pure-condition chains, switch-on-loaded-value collapse
                      to a single decision. Smallest map.
     2 = restricted : collapse only 2-successor guard-only BBs; switches and
                      indirect branches keep their full multiplying effect.
     3 = strict     : full Ball-Larus, every IR-level acyclic path is unique.

   The IR-emit halves stay in the two passes: LTO emits with absolute
   afl_global_id slots and CTX composition; PCGUARD emits through
   FunctionGuardArray indirection with optional IJON state mixing.

   The back-edge DFS and the NumPaths walk are both iterative — a recursive
   formulation can blow the host stack on deeply chained CFGs (the `clang`
   process driving the pass does not have a comfortable stack reserve).
   Forward successors per BB are cached once per analysis to keep
   NumPaths and edge-value passes linear in CFG size.

   Stability note: path IDs are deterministic within a single build but
   NOT stable across LLVM major versions or optimisation-pass changes.
   Both the back-edge DFS order and SwitchInst case iteration can shift
   between LLVM versions, producing different Ball-Larus prefix sums and
   therefore different per-path map slots. Two corpora collected against
   binaries built with different toolchains cannot be merged on the basis
   of PATH coverage alone.

   LTO caveat: the LTO build runs afl-llvm-bug-pass (SCALAR/SLACK/etc.)
   UPSTREAM of SanitizerCoverageLTO, which adds stores/calls to many BBs
   before this analysis ever runs. PATH=1's guard-only collapse therefore
   sees a more polluted CFG under LTO than under PCGUARD, and collapses
   fewer branches in practice. The two passes produce different totals
   for the same source — that is expected, not a bug.
*/

#ifndef AFL_PATH_COVERAGE_H
#define AFL_PATH_COVERAGE_H

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"

#include <cstdint>
#include <utility>
#include <vector>

namespace afl {

struct PathAnalysisResult {

  /* NumPaths(entry). 0 means "skip this function" (no exits, single-path,
     or over-cap). */
  uint64_t numPaths = 0;
  /* Exit points and where to insert the path-id write. */
  std::vector<std::pair<llvm::BasicBlock *, llvm::Instruction *>> exits;
  /* Per-BB path counts (only populated for reachable forward-DAG BBs). */
  llvm::DenseMap<llvm::BasicBlock *, uint64_t> numPathsAtBB;
  /* Edge values for prefix-sum path-id reconstruction; absent or 0 means
     the edge contributes nothing to the path id. */
  llvm::DenseMap<std::pair<llvm::BasicBlock *, llvm::BasicBlock *>, uint64_t>
      edgeValues;
  /* True if multi-way branches had to be collapsed to bring NumPaths(entry)
     under maxPaths_. */
  bool simplified = false;
  /* True if NumPaths(entry) stayed above maxPaths_ even after collapsing
     multi-way branches; the function is skipped (no slots reserved). */
  bool overCap = false;

};

class PathAnalysis {

 public:
  PathAnalysis(unsigned level, uint64_t maxPaths)
      : level_(level), maxPaths_(maxPaths) {

  }

  PathAnalysisResult analyze(llvm::Function &F) const {

    using namespace llvm;
    PathAnalysisResult R;
    if (F.empty()) return R;

    /* path_reg is a stack alloca initialised once at function entry.
       longjmp() back into a setjmp target leaves locals modified since
       setjmp() with indeterminate values (C99 7.13.2.1), so the next
       exit-point write would index outside the reserved bitmap range.
       Skip any function that contains a setjmp / sigsetjmp call (or any
       callee marked `returns_twice`). */
    if (callsSetjmp(F)) return R;

    /* Same alloca-pattern problem for C++20 coroutines: CoroSplitPass
       moves locals across suspend points into the coroutine frame, and
       the .destroy companion reads spilled values after the frame is
       freed → heap-use-after-free.  Skip ramp + split companions. */
    if (isCoroutineFunction(F)) return R;

    /* 1. Exit points: first ReturnInst / ResumeInst / UnreachableInst /
       noreturn call in each BB.  Anything after a noreturn is unreachable. */
    DenseSet<BasicBlock *> exitBBs;
    for (auto &BB : F) {

      Instruction *firstExit = nullptr;
      for (auto &I : BB) {

        if (isa<ReturnInst>(&I) || isa<ResumeInst>(&I) ||
            isa<UnreachableInst>(&I)) {

          firstExit = &I;
          break;

        }

        if (auto *Call = dyn_cast<CallBase>(&I)) {

          if (Call->doesNotReturn()) {

            firstExit = Call;
            break;

          }

        }

      }

      if (firstExit) {

        R.exits.push_back({&BB, firstExit});
        exitBBs.insert(&BB);

      }

    }

    if (R.exits.empty()) return R;

    /* 2. Back-edges via iterative DFS — recursion would blow the host
       stack on deep CFGs. */
    auto backEdges = findBackEdges(F);

    /* 3. Cache forward successors per BB once. */
    DenseMap<BasicBlock *, SmallVector<BasicBlock *, 4>> fwdSuccs;
    for (auto &BB : F) {

      SmallVector<BasicBlock *, 4> out;
      if (!exitBBs.count(&BB)) {

        for (auto *S : successors(&BB)) {

          if (backEdges.count({&BB, S})) continue;
          out.push_back(S);

        }

      }

      fwdSuccs[&BB] = std::move(out);

    }

    /* 4. NumPaths bottom-up — iterative two-state worklist. */
    R.numPaths = computeNumPaths(F, exitBBs, fwdSuccs,
                                 /*simplifyMultiWay=*/false, R.numPathsAtBB);

    if (R.numPaths > maxPaths_) {

      R.numPathsAtBB.clear();
      R.numPaths = computeNumPaths(F, exitBBs, fwdSuccs,
                                   /*simplifyMultiWay=*/true, R.numPathsAtBB);
      R.simplified = true;
      if (R.numPaths > maxPaths_) {

        R.overCap = true;
        R.numPathsAtBB.clear();
        R.exits.clear();
        R.numPaths = 0;
        return R;

      }

    }

    if (R.numPaths <= 1) {

      R.numPathsAtBB.clear();
      R.exits.clear();
      R.numPaths = 0;
      return R;

    }

    /* 5. Ball-Larus prefix-sum edge values.  Collapsed branches get 0
       so both arms produce identical path ids. */
    for (auto &BB : F) {

      if (exitBBs.count(&BB)) continue;
      auto numIt = R.numPathsAtBB.find(&BB);
      if (numIt == R.numPathsAtBB.end()) continue;
      auto succIt = fwdSuccs.find(&BB);
      if (succIt == fwdSuccs.end() || succIt->second.empty()) continue;
      const auto &succs = succIt->second;
      if (shouldMaxMerge(&BB, succs, R.simplified)) {

        for (auto *S : succs)
          R.edgeValues[{&BB, S}] = 0;
        continue;

      }

      uint64_t prefix = 0;
      for (auto *S : succs) {

        R.edgeValues[{&BB, S}] = prefix;
        auto it = R.numPathsAtBB.find(S);
        if (it != R.numPathsAtBB.end()) prefix += it->second;

      }

    }

    return R;

  }

  /* Any function that is part of an LLVM coroutine — either the original
     ramp (has `coro.id`) or one of the post-split `.resume`/`.destroy`
     companions (have `coro.suspend`/`coro.end`/`coro.frame`/etc.).  PATH
     instrumentation must skip these because `path_reg` is a stack alloca:
     in the destroy path the coroutine frame is freed before CoroSplitPass's
     spilled reload runs, producing a heap-use-after-free.  We detect by
     scanning for *any* `llvm.coro.*` intrinsic (covers both pre- and
     post-split shapes — CoroSplitPass typically runs before
     SanitizerCoverageLTO under `afl-clang-lto`). */
  /* CoroSplitPass typically runs BEFORE SanitizerCoverage under
     `afl-clang-lto` / `afl-clang-fast`, so by the time we look at the IR
     all the `llvm.coro.*` intrinsics have been lowered away.  We detect
     the three split companions by the name suffixes CoroSplitPass uses
     (`.resume`, `.destroy`, `.cleanup`, `.async_resume`) and the
     remaining ramp by the existence of a sibling `<name>.resume` in the
     same module. */
  static bool isCoroutineFunction(llvm::Function &F) {

    using namespace llvm;
    StringRef name = F.getName();
    auto      endsWith = [&](StringRef s) {

#if LLVM_VERSION_MAJOR >= 18
      return name.ends_with(s);
#else
      return name.endswith(s);
#endif

    };

    if (endsWith(".resume") || endsWith(".destroy") || endsWith(".cleanup") ||
        endsWith(".async_resume"))
      return true;

    if (Module *M = F.getParent()) {

      SmallString<128> ramp(name);
      ramp.append(".resume");
      if (M->getFunction(ramp)) return true;

    }

    return false;

  }

  static bool callsSetjmp(llvm::Function &F) {

    using namespace llvm;
    for (auto &BB : F) {

      for (auto &I : BB) {

        auto *Call = dyn_cast<CallBase>(&I);
        if (!Call) continue;
        if (Call->hasFnAttr(Attribute::ReturnsTwice)) return true;
        Function *Callee = Call->getCalledFunction();
        if (!Callee) continue;
        StringRef N = Callee->getName();
        if (N == "setjmp" || N == "_setjmp" || N == "sigsetjmp" ||
            N == "__sigsetjmp" || N == "__builtin_setjmp" ||
            N == "__sigsetjmp14")
          return true;

      }

    }

    return false;

  }

  static bool isGuardOnlyBB(llvm::BasicBlock *BB) {

    using namespace llvm;
    for (auto &I : *BB) {

      if (I.isTerminator()) continue;
      if (isa<LoadInst>(&I)) continue;
      if (isa<CastInst>(&I)) continue;
      if (isa<GetElementPtrInst>(&I)) continue;
      if (isa<CmpInst>(&I)) continue;
      if (isa<PHINode>(&I)) continue;
      if (isa<FreezeInst>(&I)) continue;
      if (isa<AllocaInst>(&I)) continue;
      if (isa<SelectInst>(&I)) continue;
      if (isa<BinaryOperator>(&I)) continue;
      if (isa<UnaryOperator>(&I)) continue;
      if (isa<ExtractValueInst>(&I) || isa<InsertValueInst>(&I)) continue;
      /* Anything else (call, store, atomicrmw, cmpxchg, fence, ...) counts
         as "real work" — not guard-only. */
      return false;

    }

    return true;

  }

 private:
  unsigned level_;
  uint64_t maxPaths_;

  bool shouldMaxMerge(llvm::BasicBlock                               *BB,
                      const llvm::SmallVector<llvm::BasicBlock *, 4> &succs,
                      bool simplified) const {

    if (simplified && succs.size() > 2) return true;
    if (level_ == 1 && succs.size() > 1 && isGuardOnlyBB(BB)) return true;
    if (level_ == 2 && succs.size() == 2 && isGuardOnlyBB(BB)) return true;
    return false;

  }

  static llvm::DenseSet<std::pair<llvm::BasicBlock *, llvm::BasicBlock *>>
  findBackEdges(llvm::Function &F) {

    using namespace llvm;
    DenseSet<std::pair<BasicBlock *, BasicBlock *>> backEdges;
    DenseSet<BasicBlock *>                          visited;
    DenseSet<BasicBlock *>                          onStack;
    struct Frame {

      BasicBlock   *bb;
      succ_iterator it;
      succ_iterator end;

    };

    std::vector<Frame> stack;

    auto startAt = [&](BasicBlock *BB) {

      if (visited.count(BB)) return;
      visited.insert(BB);
      onStack.insert(BB);
      stack.push_back({BB, succ_begin(BB), succ_end(BB)});
      while (!stack.empty()) {

        Frame &top = stack.back();
        if (top.it == top.end) {

          onStack.erase(top.bb);
          stack.pop_back();
          continue;

        }

        BasicBlock *S = *top.it;
        ++top.it;
        if (onStack.count(S)) {

          backEdges.insert({top.bb, S});

        } else if (!visited.count(S)) {

          visited.insert(S);
          onStack.insert(S);
          stack.push_back({S, succ_begin(S), succ_end(S)});

        }

      }

    };

    startAt(&F.getEntryBlock());
    /* Walk from any BB unreachable-from-entry so we don't accidentally
       treat their forward edges as back-edges. Rare in practice. */
    for (auto &BB : F)
      if (!visited.count(&BB)) startAt(&BB);
    return backEdges;

  }

  uint64_t computeNumPaths(
      llvm::Function &F, const llvm::DenseSet<llvm::BasicBlock *> &exitBBs,
      const llvm::DenseMap<llvm::BasicBlock *,
                           llvm::SmallVector<llvm::BasicBlock *, 4>> &fwdSuccs,
      bool simplify, llvm::DenseMap<llvm::BasicBlock *, uint64_t> &out) const {

    using namespace llvm;
    out.clear();
    /* Two-state worklist: state 0 = visit children first; state 1 = aggregate
       once children are resolved. Back-edges already stripped so DAG only. */
    struct Frame {

      BasicBlock *bb;
      unsigned    state;

    };

    std::vector<Frame> stack;
    stack.push_back({&F.getEntryBlock(), 0});

    while (!stack.empty()) {

      Frame       top = stack.back();
      BasicBlock *BB = top.bb;
      if (top.state == 0) {

        if (out.count(BB)) {

          stack.pop_back();
          continue;

        }

        /* Sentinel — also blocks re-entry on cycles (defensive; back-edges
           are already stripped). */
        out[BB] = 0;
        stack.back().state = 1;
        if (!exitBBs.count(BB)) {

          auto it = fwdSuccs.find(BB);
          if (it != fwdSuccs.end()) {

            for (auto *S : it->second)
              stack.push_back({S, 0});

          }

        }

        continue;

      }

      /* state == 1: children resolved. */
      uint64_t total = 0;
      if (exitBBs.count(BB)) {

        total = 1;

      } else {

        auto succIt = fwdSuccs.find(BB);
        if (succIt != fwdSuccs.end() && !succIt->second.empty()) {

          if (shouldMaxMerge(BB, succIt->second, simplify)) {

            for (auto *S : succIt->second) {

              auto     cIt = out.find(S);
              uint64_t c = (cIt == out.end()) ? 0 : cIt->second;
              if (c > total) total = c;

            }

          } else {

            for (auto *S : succIt->second) {

              auto     cIt = out.find(S);
              uint64_t c = (cIt == out.end()) ? 0 : cIt->second;
              total += c;

            }

          }

        }

      }

      out[BB] = total;
      stack.pop_back();

    }

    auto entryIt = out.find(&F.getEntryBlock());
    return (entryIt == out.end()) ? 0 : entryIt->second;

  }

};

/* Emit the per-function path register (alloca) and the edge-increment
   instructions on every forward edge that carries a non-zero edge value.
   The exit-point writes are NOT emitted here — those differ between LTO
   (absolute slot index + CTX composition) and PCGUARD (FunctionGuardArray
   indirection + optional IJON state).

   `setMD` is a per-instruction metadata setter — pass-private helpers
   differ between LTO and PCGUARD, so a callback keeps this header free
   of pass-internal knowledge. */
template <typename SetMD>
llvm::AllocaInst *emitPathCoverageEdges(
    llvm::Function                 &F,
    const llvm::DenseMap<std::pair<llvm::BasicBlock *, llvm::BasicBlock *>,
                         uint64_t> &edgeValues,
    SetMD                           setMD) {

  using namespace llvm;
  LLVMContext         &Ctx = F.getContext();
  IntegerType         *Int32 = Type::getInt32Ty(Ctx);
  BasicBlock          &EntryBB = F.getEntryBlock();
  BasicBlock::iterator entryIP = EntryBB.getFirstInsertionPt();
  IRBuilder<>          EntryIRB(&*entryIP);
  AllocaInst *path_reg = EntryIRB.CreateAlloca(Int32, nullptr, "path_reg");
  StoreInst  *initStore =
      EntryIRB.CreateStore(ConstantInt::get(Int32, 0), path_reg);
  setMD(initStore);
  for (auto &kv : edgeValues) {

    BasicBlock *a = kv.first.first;
    BasicBlock *b = kv.first.second;
    uint64_t    val = kv.second;
    if (val == 0) continue;
    /* After SplitAllCriticalEdges, every edge has either |succ(a)| == 1
       (insert at end of a) or |pred(b)| == 1 (insert at top of b). */
    Instruction *insertPt = (a->getTerminator()->getNumSuccessors() > 1)
                                ? &*b->getFirstInsertionPt()
                                : a->getTerminator();
    IRBuilder<>  IRB(insertPt);
    LoadInst    *cur = IRB.CreateLoad(Int32, path_reg);
    setMD(cur);
    Value *next = IRB.CreateAdd(cur, ConstantInt::get(Int32, (uint32_t)val));
    StoreInst *st = IRB.CreateStore(next, path_reg);
    setMD(st);

  }

  return path_reg;

}

}  // namespace afl

#endif  // AFL_PATH_COVERAGE_H

