#include <algorithm>
#include <map>
#include <queue>
#include <set>
#include <vector>

#include "llvm/Config/llvm-config.h"
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 5
typedef long double max_align_t;
#endif

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
#include "llvm/IR/CFG.h"
#else
#include "llvm/Support/CFG.h"
#endif
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

DenseMap<BasicBlock *, uint32_t>    LMap;
std::vector<BasicBlock *>           Blocks;
std::set<uint32_t>                  Marked, Markabove;
std::vector<std::vector<uint32_t> > Succs, Preds;

void reset() {

  LMap.clear();
  Blocks.clear();
  Marked.clear();
  Markabove.clear();

}

uint32_t start_point;

void labelEachBlock(Function *F) {

  // Fake single endpoint;
  LMap[NULL] = Blocks.size();
  Blocks.push_back(NULL);

  // Assign the unique LabelID to each block;
  for (auto I = F->begin(), E = F->end(); I != E; ++I) {

    BasicBlock *BB = &*I;
    LMap[BB] = Blocks.size();
    Blocks.push_back(BB);

  }

  start_point = LMap[&F->getEntryBlock()];

}

void buildCFG(Function *F) {

  Succs.resize(Blocks.size());
  Preds.resize(Blocks.size());
  for (size_t i = 0; i < Succs.size(); i++) {

    Succs[i].clear();
    Preds[i].clear();

  }

  for (auto S = F->begin(), E = F->end(); S != E; ++S) {

    BasicBlock *BB = &*S;
    uint32_t    MyID = LMap[BB];

    for (auto I = succ_begin(BB), E = succ_end(BB); I != E; ++I) {

      Succs[MyID].push_back(LMap[*I]);

    }

  }

}

std::vector<std::vector<uint32_t> > tSuccs;
std::vector<bool>                   tag, indfs;

void DFStree(size_t now_id) {

  if (tag[now_id]) return;
  tag[now_id] = true;
  indfs[now_id] = true;
  for (auto succ : tSuccs[now_id]) {

    if (tag[succ] and indfs[succ]) {

      Marked.insert(succ);
      Markabove.insert(succ);
      continue;

    }

    Succs[now_id].push_back(succ);
    Preds[succ].push_back(now_id);
    DFStree(succ);

  }

  indfs[now_id] = false;

}

void turnCFGintoDAG() {

  tSuccs = Succs;
  tag.resize(Blocks.size());
  indfs.resize(Blocks.size());
  for (size_t i = 0; i < Blocks.size(); ++i) {

    Succs[i].clear();
    tag[i] = false;
    indfs[i] = false;

  }

  DFStree(start_point);
  for (size_t i = 0; i < Blocks.size(); ++i)
    if (Succs[i].empty()) {

      Succs[i].push_back(0);
      Preds[0].push_back(i);

    }

}

uint32_t timeStamp;
namespace DominatorTree {

std::vector<std::vector<uint32_t> > cov;
std::vector<uint32_t>               dfn, nfd, par, sdom, idom, mom, mn;

bool Compare(uint32_t u, uint32_t v) {

  return dfn[u] < dfn[v];

}

uint32_t eval(uint32_t u) {

  if (mom[u] == u) return u;
  uint32_t res = eval(mom[u]);
  if (Compare(sdom[mn[mom[u]]], sdom[mn[u]])) { mn[u] = mn[mom[u]]; }
  return mom[u] = res;

}

void DFS(uint32_t now) {

  timeStamp += 1;
  dfn[now] = timeStamp;
  nfd[timeStamp - 1] = now;
  for (auto succ : Succs[now]) {

    if (dfn[succ] == 0) {

      par[succ] = now;
      DFS(succ);

    }

  }

}

void DominatorTree() {

  if (Blocks.empty()) return;
  uint32_t s = start_point;

  // Initialization
  mn.resize(Blocks.size());
  cov.resize(Blocks.size());
  dfn.resize(Blocks.size());
  nfd.resize(Blocks.size());
  par.resize(Blocks.size());
  mom.resize(Blocks.size());
  sdom.resize(Blocks.size());
  idom.resize(Blocks.size());

  for (uint32_t i = 0; i < Blocks.size(); i++) {

    dfn[i] = 0;
    nfd[i] = Blocks.size();
    cov[i].clear();
    idom[i] = mom[i] = mn[i] = sdom[i] = i;

  }

  timeStamp = 0;
  DFS(s);

  for (uint32_t i = Blocks.size() - 1; i >= 1u; i--) {

    uint32_t now = nfd[i];
    if (now == Blocks.size()) { continue; }
    for (uint32_t pre : Preds[now]) {

      if (dfn[pre]) {

        eval(pre);
        if (Compare(sdom[mn[pre]], sdom[now])) { sdom[now] = sdom[mn[pre]]; }

      }

    }

    cov[sdom[now]].push_back(now);
    mom[now] = par[now];
    for (uint32_t x : cov[par[now]]) {

      eval(x);
      if (Compare(sdom[mn[x]], par[now])) {

        idom[x] = mn[x];

      } else {

        idom[x] = par[now];

      }

    }

  }

  for (uint32_t i = 1; i < Blocks.size(); i += 1) {

    uint32_t now = nfd[i];
    if (now == Blocks.size()) { continue; }
    if (idom[now] != sdom[now]) idom[now] = idom[idom[now]];

  }

}

}  // namespace DominatorTree

std::vector<uint32_t>               Visited, InStack;
std::vector<uint32_t>               TopoOrder, InDeg;
std::vector<std::vector<uint32_t> > t_Succ, t_Pred;

void Go(uint32_t now, uint32_t tt) {

  if (now == tt) return;
  Visited[now] = InStack[now] = timeStamp;

  for (uint32_t nxt : Succs[now]) {

    if (Visited[nxt] == timeStamp and InStack[nxt] == timeStamp) {

      Marked.insert(nxt);

    }

    t_Succ[now].push_back(nxt);
    t_Pred[nxt].push_back(now);
    InDeg[nxt] += 1;
    if (Visited[nxt] == timeStamp) { continue; }
    Go(nxt, tt);

  }

  InStack[now] = 0;

}

void TopologicalSort(uint32_t ss, uint32_t tt) {

  timeStamp += 1;

  Go(ss, tt);

  TopoOrder.clear();
  std::queue<uint32_t> wait;
  wait.push(ss);
  while (not wait.empty()) {

    uint32_t now = wait.front();
    wait.pop();
    TopoOrder.push_back(now);
    for (uint32_t nxt : t_Succ[now]) {

      InDeg[nxt] -= 1;
      if (InDeg[nxt] == 0u) { wait.push(nxt); }

    }

  }

}

std::vector<std::set<uint32_t> > NextMarked;
bool                             Indistinguish(uint32_t node1, uint32_t node2) {

  if (NextMarked[node1].size() > NextMarked[node2].size()) {

    uint32_t _swap = node1;
    node1 = node2;
    node2 = _swap;

  }

  for (uint32_t x : NextMarked[node1]) {

    if (NextMarked[node2].find(x) != NextMarked[node2].end()) { return true; }

  }

  return false;

}

void MakeUniq(uint32_t now) {

  bool StopFlag = false;
  if (Marked.find(now) == Marked.end()) {

    for (uint32_t pred1 : t_Pred[now]) {

      for (uint32_t pred2 : t_Pred[now]) {

        if (pred1 == pred2) continue;
        if (Indistinguish(pred1, pred2)) {

          Marked.insert(now);
          StopFlag = true;
          break;

        }

      }

      if (StopFlag) { break; }

    }

  }

  if (Marked.find(now) != Marked.end()) {

    NextMarked[now].insert(now);

  } else {

    for (uint32_t pred : t_Pred[now]) {

      for (uint32_t x : NextMarked[pred]) {

        NextMarked[now].insert(x);

      }

    }

  }

}

bool MarkSubGraph(uint32_t ss, uint32_t tt) {

  TopologicalSort(ss, tt);
  if (TopoOrder.empty()) return false;

  for (uint32_t i : TopoOrder) {

    NextMarked[i].clear();

  }

  NextMarked[TopoOrder[0]].insert(TopoOrder[0]);
  for (uint32_t i = 1; i < TopoOrder.size(); i += 1) {

    MakeUniq(TopoOrder[i]);

  }

  // Check if there is an empty path.
  if (NextMarked[tt].count(TopoOrder[0]) > 0) return true;
  return false;

}

void MarkVertice() {

  uint32_t s = start_point;

  InDeg.resize(Blocks.size());
  Visited.resize(Blocks.size());
  InStack.resize(Blocks.size());
  t_Succ.resize(Blocks.size());
  t_Pred.resize(Blocks.size());
  NextMarked.resize(Blocks.size());

  for (uint32_t i = 0; i < Blocks.size(); i += 1) {

    Visited[i] = InStack[i] = InDeg[i] = 0;
    t_Succ[i].clear();
    t_Pred[i].clear();

  }

  timeStamp = 0;
  uint32_t t = 0;
  bool     emptyPathExists = true;

  while (s != t) {

    emptyPathExists &= MarkSubGraph(DominatorTree::idom[t], t);
    t = DominatorTree::idom[t];

  }

  if (emptyPathExists) {

    // Mark all exit blocks to catch the empty path.
    Marked.insert(t_Pred[0].begin(), t_Pred[0].end());

  }

}

// return {marked nodes}
std::pair<std::vector<BasicBlock *>, std::vector<BasicBlock *> > markNodes(
    Function *F) {

  assert(F->size() > 0 && "Function can not be empty");

  reset();
  labelEachBlock(F);
  buildCFG(F);
  turnCFGintoDAG();
  DominatorTree::DominatorTree();
  MarkVertice();

  std::vector<BasicBlock *> Result, ResultAbove;
  for (uint32_t x : Markabove) {

    auto it = Marked.find(x);
    if (it != Marked.end()) Marked.erase(it);
    if (x) ResultAbove.push_back(Blocks[x]);

  }

  for (uint32_t x : Marked) {

    if (x == 0) {

      continue;

    } else {

      Result.push_back(Blocks[x]);

    }

  }

  return {Result, ResultAbove};

}

