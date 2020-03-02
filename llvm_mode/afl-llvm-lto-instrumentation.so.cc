/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

/*
 * TODO LIST
 *  * fix: dont fix the index but those where index is predecessor
 *  * callsites follow-up
 *
 */

#define FIND_VALUE_ATTEMPTS 16

#define AFL_LLVM_PASS  // for types.h

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <unordered_set>
#include <list>
#include <string>
#include <fstream>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <list>
#include <string>

#include "llvm/Config/llvm-config.h"
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 5
typedef long double max_align_t;
#endif

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
#include "llvm/IR/CFG.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/DebugInfo.h"
#else
#include "llvm/Support/CFG.h"
#include "llvm/Analysis/Dominators.h"
#include "llvm/DebugInfo.h"
#endif
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "config.h"
#include "types.h"
#include "debug.h"

#include "MarkNodes.h"

#define MAX_ID_CNT 1024

using namespace llvm;

namespace {

enum {

  /* 00 */ STAGE_GETBB,  // STAGE_START
  /* 01 */ STAGE_CFG,
  /* 02 */ STAGE_CALC,
  /* 03 */ STAGE_SETID,
  /* 04 */ STAGE_END

};

DenseMap<BasicBlock *, uint32_t>    LinkMap;
DenseMap<uint32_t, BasicBlock *>    ReverseMap;
DenseMap<BasicBlock *, uint32_t>    MapIDs;
DenseMap<BasicBlock *, uint32_t>    CurrIDs;
std::vector<BasicBlock *>           InsBlocks;
std::vector<BasicBlock *>           SuccessorsCFG;
std::vector<std::vector<uint32_t> > Predecessors;
std::vector<std::vector<uint32_t> > Successors;
std::vector<uint32_t>               Entrypoints;
std::vector<uint32_t>               Exitpoints;
std::vector<uint32_t>               hitcount_successors;
std::vector<uint32_t>               hitcount_predecessors;

class AFLLTOPass : public ModulePass {

 public:
  static char  ID;
  unsigned int cnt = 1;

  AFLLTOPass() : ModulePass(ID) {

    if (getenv("AFL_DEBUG")) debug = 1;

  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {

    AU.addRequired<DominatorTreeWrapperPass>();

  }

  unsigned int reverseBits(unsigned int num) {

    int i, reverse_num = 0;
    for (i = 0; i < MAP_SIZE_POW2; i++)
      if ((num & (1 << i))) reverse_num |= 1 << ((MAP_SIZE_POW2 - 1) - i);
    return reverse_num % MAP_SIZE;

  }

  /*
    unsigned int reverseBitsBits(unsigned int num, unsigned int bits) {

      int i, reverse_num = 0;

      for (i = 0; i < bits; i++)
        if ((num & (1 << i))) reverse_num |= 1 << ((bits - 1) - i);
      return reverse_num % (1 << bits);

    }

  */

  // Calculate the number of average collisions that would occur if all
  // location IDs would be assigned randomly (like normal afl/afl++).
  // This uses the "balls in bins" algorithm.
  unsigned long long int calculateCollisions(unsigned long long int edges) {

    double                 bins = MAP_SIZE;
    double                 balls = edges;
    double                 step1 = 1 - (1 / bins);
    double                 step2 = pow(step1, balls);
    double                 step3 = bins * step2;
    double                 step4 = round(step3);
    unsigned long long int empty = step4;
    unsigned long long int collisions = edges - (MAP_SIZE - empty);
    return collisions;

  }

  // Get the internal llvm name of a basic block
  static std::string getSimpleNodeLabel(const BasicBlock *BB,
                                        const Function *) {

    if (!BB->getName().empty()) return BB->getName().str();

    std::string        Str;
    raw_string_ostream OS(Str);

    BB->printAsOperand(OS, false);
    return OS.str();

  }

  // Should this basic block be instrumented?
  // Only if at least one previous block exists that has at least two or
  // more successors.
  bool shouldBeInstrumented(BasicBlock &BB) {

    for (BasicBlock *Pred : predecessors(&BB)) {

      int count = 0;

      for (BasicBlock *Succ : successors(Pred))
        if (Succ != NULL) count++;

      if (count > 1) return true;

    }

    return false;

  }

  // We skip over blacklisted functions. Obvously.
  bool isBlacklisted(const Function *F) {

    static const SmallVector<std::string, 5> Blacklist = {

        "asan.", "llvm.", "sancov.", "__ubsan_handle_", "ign."

    };

    for (auto const &BlacklistFunc : Blacklist) {

      if (F->getName().startswith(BlacklistFunc)) {

        if (debug)
          SAYF(cMGN "[D] " cRST "ignoring blacklisted function %s\n",
               F->getName().str().c_str());

        return true;

      }

    }

    return false;

  }

 protected:
  uint32_t be_quiet = 0, inst_blocks = 0, inst_funcs = 0, id_cnt = 0, warn = 0,
           best_coll = 0xffffffff, afl_strat = 0, afl_strat_cnt = 0,
           print_strat = 0, increase = 2, global_cur_loc, total_instr = 0,
           selected = 0, debug = 0;
  unsigned long long int edges = 0, collisions = 0, my_edges = 0,
                         cnt_callsites = 0;
  bool            id_strategy = true, assign_strategy = true;
  IntegerType *   Int8Ty;
  IntegerType *   Int32Ty;
  unsigned char   map[MAP_SIZE];
  uint32_t        id_list[MAX_ID_CNT];
  char **         neverZero_counters_str = NULL;
  GlobalVariable *AFLMapPtr, *AFLPrevLoc;

  // Helper functions

  void printDebugLocation(BasicBlock *BB, uint32_t loc) {

    Function *  f = BB->getParent();
    std::string bn = getSimpleNodeLabel(BB, f);
    SAYF(cMGN "[D] " cRST "Setting %s->%s %u\n", f->getName().str().c_str(),
         bn.c_str(), loc);

  }

  void printDebugText(BasicBlock *BB, char *text) {

    Function *  f = BB->getParent();
    std::string bn = getSimpleNodeLabel(BB, f);
    SAYF(cMGN "[D] " cRST "Setting %s->%s %s\n", f->getName().str().c_str(),
         bn.c_str(), text);

  }

  void runInstrim(Module &M, int stage) {

    if (stage != STAGE_GETBB && stage != STAGE_SETID) return;

    time_t before = time(NULL);

#if LLVM_VERSION_MAJOR < 9
    char *neverZero_counters_str;
    if (stage == STAGE_SETID &&
        (neverZero_counters_str = getenv("AFL_LLVM_NOT_ZERO")) != NULL)
      if (!be_quiet) OKF("LLVM neverZero activated (by hexcoder)\n");
#endif

    LLVMContext &C = M.getContext();
    IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

    GlobalVariable *CovMapPtr, *OldPrev;

    if (stage == STAGE_SETID) {

      CovMapPtr = new GlobalVariable(M, PointerType::getUnqual(Int8Ty), false,
                                     GlobalValue::ExternalLinkage, nullptr,
                                     "__afl_area_ptr");

      OldPrev = new GlobalVariable(
          M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
          0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

    }

    ConstantInt *Zero = ConstantInt::get(Int8Ty, 0);
    ConstantInt *One = ConstantInt::get(Int8Ty, 1);
    ConstantInt *One32 = ConstantInt::get(Int32Ty, 1);

    u64 total_rs = 0;
    inst_funcs = 0;

    for (Function &F : M) {

      // if it is external or only contains one basic block: skip it
      if (F.size() < 2) { continue; }

      if (isBlacklisted(&F)) continue;

      inst_funcs++;

      std::unordered_set<BasicBlock *> MS;

      auto Result = markNodes(&F);
      auto RS = Result.first;
      auto HS = Result.second;

      MS.insert(RS.begin(), RS.end());

      MS.insert(HS.begin(), HS.end());
      total_rs += MS.size();

      for (BasicBlock &BB : F) {

        if (MS.find(&BB) == MS.end()) {

          int more_than_one = -1;

          for (pred_iterator PI = pred_begin(&BB), E = pred_end(&BB); PI != E;
               ++PI) {

            BasicBlock *Pred = *PI;
            int         count = 0;

            if (more_than_one == -1) more_than_one = 0;
            for (succ_iterator SI = succ_begin(Pred), E = succ_end(Pred);
                 SI != E; ++SI) {

              BasicBlock *Succ = *SI;
              if (Succ != NULL) count++;

            }

            if (count > 1) more_than_one = 1;

          }

          if (more_than_one != 1) continue;
          for (succ_iterator SI = succ_begin(&BB), E = succ_end(&BB); SI != E;
               ++SI) {

            BasicBlock *Succ = *SI;
            if (Succ != NULL && MS.find(Succ) == MS.end()) {

              int cnt = 0;
              for (succ_iterator SI2 = succ_begin(Succ), E2 = succ_end(Succ);
                   SI2 != E2; ++SI2) {

                BasicBlock *Succ2 = *SI2;
                if (Succ2 != NULL) cnt++;

              }

              if (cnt == 0) {

                MS.insert(Succ);
                total_rs++;

              }

            }

          }

        }

      }

      for (BasicBlock &BB : F) {

        if (MS.find(&BB) == MS.end()) { continue; }

        Value *L = NULL;

        PHINode *PN;

        if (stage == STAGE_SETID)
          PN = PHINode::Create(Int32Ty, 0, "", &*BB.begin());

        DenseMap<BasicBlock *, unsigned> PredMap;

        for (auto PI = pred_begin(&BB), PE = pred_end(&BB); PI != PE; ++PI) {

          BasicBlock *PBB = *PI;
          if (stage == STAGE_GETBB) {

            LinkMap[&*PBB] = InsBlocks.size();
            ReverseMap[InsBlocks.size()] = &*PBB;
            InsBlocks.push_back(&*PBB);
            if (debug) printDebugText(PBB, (char *)"GETBB");
            if (debug) SAYF(cMGN "[D] " cRST "MAP: %u\n", LinkMap[&*PBB]);

          } else {  // STAGE_SETID

            auto     It = PredMap.insert({PBB, MapIDs[&*PBB]});
            unsigned Label = It.first->second;
            PN->addIncoming(ConstantInt::get(Int32Ty, Label), PBB);
            if (debug) printDebugLocation(PBB, MapIDs[&*PBB]);

          }

        }

        L = PN;

        if (stage != STAGE_SETID) continue;

        IRBuilder<> IRB(&*BB.getFirstInsertionPt());

        /* Load prev_loc */
        LoadInst *PrevLoc = IRB.CreateLoad(OldPrev);
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

        /* Load SHM pointer */
        LoadInst *MapPtr = IRB.CreateLoad(CovMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MapPtrIdx =
            IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, L));

        /* Update bitmap */
        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        Value *Incr = IRB.CreateAdd(Counter, One);

#if LLVM_VERSION_MAJOR < 9
        // llvm < 9:  we make do neverZero only by option due to a llvm bug
        if (neverZero_counters_str != NULL)
#else
        if (1)  // llvm 9: neverZero default as the bug in llvm is then fixed
#endif
        {

          /* neverZero implementation */
          auto cf = IRB.CreateICmpEQ(Incr, Zero);
          auto carry = IRB.CreateZExt(cf, Int8Ty);
          Incr = IRB.CreateAdd(Incr, carry);

        }

        IRB.CreateStore(Incr, MapPtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        // save the used location ID to OldPrev
        Value *Shr = IRB.CreateLShr(L, One32);
        IRB.CreateStore(Shr, OldPrev)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        total_instr++;

      }

    }

    if (be_quiet && !print_strat && !debug) return;

    if (stage == STAGE_GETBB) {

      uint32_t diff = (uint32_t)(time(NULL) - before);
      OKF("Stage 1: collected %zu locations to instrument (%u second%s)",
          InsBlocks.size() - 1, diff, diff == 1 ? "" : "s");
      return;

    }

    char modeline[100];
    snprintf(modeline, sizeof(modeline), "%s%s%s%s",
             getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
             getenv("AFL_USE_ASAN") ? ", ASAN" : "",
             getenv("AFL_USE_MSAN") ? ", MSAN" : "",
             getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");

    OKF("Instrumented %u locations in %u functions with %llu edges and "
        "resulting in %u potential collision(s) with strategy 0x%04x "
        "(afl-clang-fast/afl-gcc would have produced %u collision(s) on "
        "average) (%s mode).",
        total_instr, inst_funcs, my_edges, best_coll, selected,
        afl_strat / afl_strat_cnt, modeline);

  }

  // Find a successor that we know to instrument - if *current is not one
  // Note that we descend into further calling functions
  bool findSuccBB(BasicBlock *current) {

    std::string fn = getSimpleNodeLabel(current, current->getParent());

    if (debug) {

      int count = 0;
      SAYF(cMGN "[D] " cRST "Successor: %s->%s[%u] (",
           current->getParent()->getName().str().c_str(), fn.c_str(),
           LinkMap[&*current]);
      for (auto I = succ_begin(current), E = succ_end(current); I != E; ++I) {

        count++;
        BasicBlock *SBB = *I;
        fn = getSimpleNodeLabel(SBB, SBB->getParent());
        SAYF("%s%s", count > 1 ? "|" : "", fn.c_str());

      }

      SAYF(")");

    }

    if (LinkMap[&*current] != 0) {  // yes we instrument "current"

      SuccessorsCFG.push_back(&*current);
      if (debug) SAYF(" [self] success\n");
      return true;

    } else {

      // first check if there are valid function calls
      for (auto &IN : *current) {

        CallInst *callInst = nullptr;
        if ((callInst = dyn_cast<CallInst>(&IN))) {

          Function *Callee = callInst->getCalledFunction();
          if (!Callee || Callee->size() < 2) continue;

          if (debug) SAYF(" Callee! ");

          if (findSuccBB(&Callee->getEntryBlock()) == true) {

            if (debug) SAYF(" success\n");
            return true;  // we only need one!

          }

        }

      }

      // if there is no callsite with a function we instrument we go further
      uint32_t count = 0, found = 0;
      for (auto I = succ_begin(current), E = succ_end(current); I != E; ++I) {

        count++;
        if (debug) {

          BasicBlock *SBB = *I;
          fn = getSimpleNodeLabel(SBB, SBB->getParent());
          SAYF(" succ:%s ", fn.c_str());

        }

        if (findSuccBB(*I) == true) found++;

      }

      if (debug) SAYF(" (%u of %u)", found, count);
      if (found > 0 && found == count) {

        if (debug) SAYF(" success\n");
        return true;

      }

    }

    // if we get here we could not resolve a path
    if (debug) SAYF(" failure\n");
    return false;

  }

  // Find a predecessor that we know to instrument - if *current is not one
  // Note that we ascend up callees
  bool findPrevBB(BasicBlock *origin, BasicBlock *current,
                  std::string *target_func) {

    std::string fn1 = getSimpleNodeLabel(origin, origin->getParent());
    std::string fn2 = getSimpleNodeLabel(current, current->getParent());
    if (debug) {

      SAYF(cMGN "[D] " cRST "Predecessor: %s->%s is %s->%s pred[%u] (%s)? (",
           origin->getParent()->getName().str().c_str(), fn1.c_str(),
           current->getParent()->getName().str().c_str(), fn2.c_str(),
           LinkMap[&*current],
           target_func == nullptr ? "" : target_func->c_str());

      int count = 0;
      for (auto I = pred_begin(current), E = pred_end(current); I != E; ++I) {

        count++;
        BasicBlock *PBB = *I;
        fn1 = getSimpleNodeLabel(PBB, PBB->getParent());
        SAYF("%s%s", count > 1 ? "|" : "", fn1.c_str());

      }

      SAYF(")");

    }

    if (target_func != nullptr && target_func->length() > 0) {

      // Now to make it even more complicated:
      // If the basic block looks like this and we come from this_func:
      //   call foo_func
      //   call this_func
      //   call bar_func
      //   call this_func
      //   call other_func
      // then we need to first descend into bar_func if there is
      // anything instrumented - and get *the*last*line*of*
      // *instrumented*blocks*(!) or do that at the next caller
      // in that function if that happens in the last block or if
      // it is a 1 size block
      // This is very complex. For now we just check if there is
      // such a function and warn if so.
      uint32_t  found = 0, problems = 0;
      Value *   curr_called;
      Function *curr_f;

      if (debug) SAYF(" caller");

      for (BasicBlock::reverse_iterator i = current->rbegin(),
                                        e = current->rend();
           i != e; ++i) {

        if (isa<CallInst>(&(*i)) || isa<InvokeInst>(&(*i))) {

          CallInst *callInst = dyn_cast<CallInst>(&*i);
          if (callInst) {

            curr_called = callInst->getCalledValue()->stripPointerCasts();
            if (curr_called) {

              curr_f = dyn_cast<Function>(curr_called);
              if (curr_f) {

                if (target_func->compare(curr_f->getName().str()))
                  found = 1;
                else if (found)
                  if (curr_f->size() > 0) problems++;

              }

            }

          }

        }

      }

      if (warn == 0 && problems > 1) {

        if (debug) SAYF(" failure\n");
        warn = 1;
        /* TODO
                WARNF(
                    "This basic callee block %s->%s has %d functions that are
           likely " "predecessors that we dont process yet!",
                    target_func->c_str(), fn2.c_str(), problems);
        */
        return false;

      } else if (debug)

        SAYF("-fine");

    }

    if (LinkMap[&*current] != 0) {  // yes we instrument "current"

      Predecessors[LinkMap[&*origin]].push_back(LinkMap[&*current]);
      if (debug) SAYF(" [self] success\n");
      return true;

    } else {

      uint32_t found = 0, count = 0;

      if (debug) SAYF(" descend");

      // if there is no callsite with a function we instrument we go further
      for (auto S = pred_begin(current), E = pred_end(current); S != E; ++S) {

        count++;
        if (findPrevBB(origin, *S, nullptr) == true) found++;

      }

      if (debug) SAYF(" (%u of %u)", found, count);
      if (found > 0 && found == count) {

        if (debug) SAYF(" success\n");
        return true;

      } else if (count == 0) {

        // we are at an entry point so we need to go up the callsites
        uint32_t found_callsites = 0;
        for (auto *U : current->getParent()->users()) {  // Function->users()

          CallSite CS(U);
          auto *   I = CS.getInstruction();

          if (I) {

            found_callsites++;
            /*
            Value *   called = CS.getCalledValue()->stripPointerCasts();
            Function *f = dyn_cast<Function>(called);

            if (f->getName().compare(current->getParent()->getName()) == 0) {

              Function *prev_function =
                  cast<CallInst>(I)->getParent()->getParent();
              BasicBlock *prev_bb = cast<CallInst>(I)->getParent();
              std::string prev_bb_name =
                  getSimpleNodeLabel(prev_bb, prev_function);
              std::string *prev_fname =
                  new std::string(prev_function->getName().str());

              if (isBlacklisted(prev_function)) continue;
              if (prev_function->size() == 0) continue;

              if (debug)
                SAYF(cMGN "[D] " cRST "callsite #%d: %s -> %s\n",
                     found_callsites++, prev_fname->c_str(),
                     prev_bb_name.c_str());

              if (findPrevBB(origin, prev_bb, prev_fname) == true /x&& debugx/)
                SAYF(" success\n");
              else                                              /xif (debug)x/
                SAYF(" failure\n");

            }*/

          }

        }

        /*
                if (found_callsites == 0) {

                  if (debug)
                    SAYF(cMGN "[D] " cRST "Found entrypoint (%d)\n",
           entrypoints); Entrypoints[entrypoints++] = &*current;

                }

        */

      }

    }

    // if we get here we could not resolve a path
    if (debug) SAYF(" failure\n");
    return false;

  }

  uint32_t getNextEmptyMap(uint32_t current, unsigned char *thismap,
                           bool bottomhalf) {

    uint32_t mapsize;

    if (bottomhalf == true)
      mapsize = MAP_SIZE >> 1;
    else
      mapsize = MAP_SIZE;

    if (current < mapsize) current++;

    while (current < mapsize && thismap[current])
      current++;

    return current;

  }

  uint32_t getNextEmptyMapReverse(uint32_t current, unsigned char *thismap,
                                  bool bottomhalf) {

    uint32_t mapsize;

    if (bottomhalf == true)
      mapsize = MAP_SIZE >> 1;
    else
      mapsize = MAP_SIZE;

    if (current == 0) return 0;
    if (current > mapsize)
      current = mapsize - 1;
    else
      current--;

    while (current > 0 && thismap[current])
      current--;

    return current;

  }

  uint32_t getID(bool bottomhalf) {

    uint32_t map_size;

    if (bottomhalf == true)
      map_size = MAP_SIZE >> 1;
    else
      map_size = MAP_SIZE;

    if (id_strategy == true)
      return ((global_cur_loc += increase) % map_size);
    else
      return AFL_R(map_size);

  }

  // select IDs by empty MapIDs and calculate backwards
  uint32_t calcID_2(uint32_t index, bool force) {

    uint32_t i, j, map_id = 0, map_size = MAP_SIZE, colls = 0,
                   curr_id = CurrIDs[ReverseMap[index]];
    std::vector<uint32_t> val, curr;
    time_t                start = time(NULL);
    bool                  bottomhalfmap = false;

    if (Predecessors[index].size() > 0) {

      for (i = 0; i < Predecessors[index].size(); i++)
        if (CurrIDs[ReverseMap[Predecessors[index][i]]] < MAP_SIZE)
          val.push_back(CurrIDs[ReverseMap[Predecessors[index][i]]]);

      if (Predecessors[index].size() - val.size() > 0) {

        curr.resize(Predecessors[index].size() - val.size());
        for (i = 0; i < curr.size(); i++)
          curr[i] = MAP_SIZE;
        bottomhalfmap = true;
        map_size = MAP_SIZE >> 1;

      }

    }

    if (debug) {

      SAYF(cMGN
           "[D] " cRST
           "Handling %u preds:%zu (vals:%zu) loc:%u map_size:%u force:%s (",
           index, Predecessors[index].size(), val.size(), curr_id, map_size,
           force == true ? "true" : "false");
      if (Predecessors[index].size() > 0)
        for (i = 0; i < Predecessors[index].size(); i++)
          SAYF("%s%u:%u", i > 0 ? "|" : "", Predecessors[index][i],
               CurrIDs[ReverseMap[Predecessors[index][i]]]);
      SAYF(")\n");

    }

    if (Predecessors[index].size() == val.size() && curr_id < MAP_SIZE)
      return 0;  // already fully processed
    if (force == false && Predecessors[index].size() == 0)
      return 0;  // no predecessors? skip it for now

    if (curr_id >= map_size) {  // we need to determine the curr_id

      if (val.size() == 1) {

        map_id = getNextEmptyMap(map_id, map, bottomhalfmap);
        if (map_id >= map_size)
          curr_id = getID(bottomhalfmap);  // damn :-(
        else
          curr_id = map_id ^ (val[0] >> 1);

      } else if (val.size() > 1) {  // for this we could use Z3 ...

        uint32_t coll, curr_loc, found = 0, best_loc = MAP_SIZE,
                                 lowest_coll = val.size() + 1;

        do {  // while(map_id < map_size && coll > 0)

          if ((map_id = getNextEmptyMap(map_id, map, bottomhalfmap)) <
              map_size) {

            coll = 0;

            for (i = 0; i < val.size() && found == 0; i++) {

              curr_loc = map_id ^ (val[i] >> 1);

              for (j = 0; j < val.size() && found == 0; j++)
                if (map[curr_loc ^ (val[j] >> 1)]) coll++;

              if (coll < lowest_coll) {

                lowest_coll = coll;
                if (lowest_coll == 0) found = 1;
                best_loc = curr_loc;

              }

            }

          }

        } while (map_id < map_size && coll > 0);

        if (best_loc >= map_size)
          curr_id = getID(bottomhalfmap);  // damn :(
        else
          curr_id = best_loc;

      } else {

        curr_id = getID(bottomhalfmap);  // damn :(

      }

      CurrIDs[ReverseMap[index]] = curr_id;  // now write it

    }  // if (curr_id >= map_size)

    if (debug) {

      SAYF(cMGN "[D] " cRST
                "Continue %u preds:%zu (vals:%zu) loc:%u force:%s (",
           index, Predecessors[index].size(), val.size(), curr_id,
           force == true ? "true" : "false");
      if (Predecessors[index].size() > 0)
        for (i = 0; i < Predecessors[index].size(); i++)
          SAYF("%s%u", i > 0 ? "|" : "", Predecessors[index][i]);
      SAYF(")\n");

    }

    // do we have predecessors without value?
    if (curr.size() > 0) {

      uint32_t ok;
      map_id = 0;

      for (i = 0; i < curr.size(); i++) {  // calculate values

        do {  // while(ok == 0 && map_id < map_size)

          ok = 1;

          if ((map_id = getNextEmptyMap(map_id, map, true)) < map_size) {

            if ((curr[i] = (curr_id ^ map_id) << 1) < MAP_SIZE) {

              if (val.size() > 0)
                for (j = 0; j < val.size() && ok == 1; j++)
                  if ((curr[i] >> 1) == (val[j] >> 1)) ok = 0;
              /*if (ok && i > 0) // not possible
                for (j = 0; j < i; j++)
                  if ((curr[i] >> 1) == (curr[j] >> 1))
                    ok = 0;*/

            }

          }

        } while (ok == 0 && map_id < map_size);

        if (curr[i] >= MAP_SIZE) {

          do {  // while (ok == 0)

            ok = 1;
            curr[i] = getID(false);  // damn :-(

            if (val.size() > 0)
              for (j = 0; j < val.size() && ok == 1; j++)
                if ((curr[i] >> 1) == (val[j] >> 1)) ok = 0;
            if (ok && i > 0)
              for (j = 0; j < i; j++)
                if ((curr[i] >> 1) == (curr[j] >> 1)) ok = 0;

          } while (ok == 0);

        }

      }

      // assign values
      j = 0;
      for (i = 0; i < Predecessors[index].size(); i++) {

        if (CurrIDs[ReverseMap[Predecessors[index][i]]] >= MAP_SIZE)
          CurrIDs[ReverseMap[Predecessors[index][i]]] = curr[j++];
        if (map[curr_id ^ (CurrIDs[ReverseMap[Predecessors[index][i]]] >> 1)])
          colls++;

      }

    }

    if (debug) {

      SAYF(cMGN "[D] " cRST "Done %u colls:<=%u preds:%zu loc:%u force:%s (",
           index, colls, Predecessors[index].size(), curr_id,
           force == true ? "true" : "false");
      if (Predecessors[index].size() > 0)
        for (i = 0; i < Predecessors[index].size(); i++)
          SAYF("%s%u:%u", i > 0 ? "|" : "", Predecessors[index][i],
               CurrIDs[ReverseMap[Predecessors[index][i]]]);
      SAYF(") in %u seconds \n", (unsigned int)(time(NULL) - start));

    }

    return 1;

  }

  // Assign IDs to the current location and/or previous locations
  // as needed, no strategy. disabled because it is not efficient.
  uint32_t calcID_1(uint32_t index, bool force) {

    uint32_t i, curr_id = CurrIDs[ReverseMap[index]], bcol = 0, ccol = 0;
    std::vector<uint32_t> val;

    if (force == false &&
        Predecessors[index].size() == 0)  // no predecessors? skip it for now
      return 0;

    for (i = 0; i < Predecessors[index].size(); i++)
      if (CurrIDs[ReverseMap[Predecessors[index][i]]] < MAP_SIZE)
        val.push_back(CurrIDs[ReverseMap[Predecessors[index][i]]]);

    // if (val.size() == 0 && curr_id >= MAP_SIZE)
    //  return 0;  // no data whatsoever yet, will be set later

    if (curr_id >= MAP_SIZE) {  // we do not have a current location ID yet
      uint32_t curr, best, icnt = 0;
      bcol = val.size() + 1;

      do {  // -> while (ccol > 0 && icnt < FIND_VALUE_ATTEMPTS);

        ccol = 0;
        curr = getID(false);

        if (val.size() > 0)
          for (i = 0; i < val.size(); i++)
            if (map[curr ^ (val[i] >> 1)]) ccol++;

        if (ccol < bcol && curr_id < MAP_SIZE) {

          bcol = ccol;
          best = curr;

        }

        icnt++;

      } while (ccol > 0 && icnt < FIND_VALUE_ATTEMPTS);

      if (best >= MAP_SIZE) best = getID(false);

      CurrIDs[ReverseMap[index]] = curr_id = best;
      if (debug) printDebugLocation(ReverseMap[index], curr_id);

    }

    // if we have unassigned locations - assign them
    if (val.size() < Predecessors[index].size()) {

      uint32_t cnt = 0, icnt, tmp, duplicate, j,
               tcol = Predecessors[index].size() + 1;
      std::vector<uint32_t> best, curr;
      curr.resize(Predecessors[index].size() - val.size());
      best.resize(curr.size());
      do {  // -> while (cnt < FIND_VALUE_ATTEMPTS && ccol > 0);

        ccol = bcol;

        for (i = 0; i < curr.size(); i++) {

          icnt = 0;

          do {  // -> while (icnt < FIND_VALUE_ATTEMPTS && map[(tmp >> 1) ^
                // curr_id]);

            icnt++;

            do {  // -> while (duplicate == 1);

              duplicate = 0;
              // for predecessors it is better to reverse
              tmp = reverseBits(getID(false));
              if (val.size() > 0)
                for (j = 0; j < val.size() && duplicate == 0; j++)
                  if (val[j] == tmp) duplicate = 1;
              if (i > 0)
                for (j = 0; j < i && duplicate == 0; j++)
                  if (curr[i] == tmp) duplicate = 1;

            } while (duplicate == 1);

          } while (icnt < FIND_VALUE_ATTEMPTS && map[(tmp >> 1) ^ curr_id] > 0);

          if (tmp >= MAP_SIZE) { tmp = getID(false); }

          curr[i] = tmp;
          if (map[(tmp >> 1) ^ curr_id]) ccol++;

        }

        if (ccol < tcol) {

          for (i = 0; i < curr.size(); i++)
            best[i] = curr[i];
          tcol = ccol;

        }

        cnt++;

      } while (cnt < FIND_VALUE_ATTEMPTS && ccol > 0);

      j = 0;
      for (uint32_t k = 0; k < Predecessors[index].size(); k++) {

        if (CurrIDs[ReverseMap[Predecessors[index][k]]] >= MAP_SIZE) {

          if (best[j] >= MAP_SIZE) best[j] = getID(false);
          CurrIDs[ReverseMap[Predecessors[index][k]]] = best[j++];
          if (debug)
            printDebugLocation(ReverseMap[Predecessors[index][k]],
                               CurrIDs[ReverseMap[Predecessors[index][k]]]);

        }

      }

    }

    return 1;

  }

  // In this strategy we traverse backwards through predecessors
  void reverseFollowPredecessors(uint32_t index) {

    uint32_t i, res = 0;

    if (Predecessors[index].size() == 0) return;

    // first calculate the next line of predecessors
    for (i = 0; i < Predecessors[index].size(); i++)
      res += calcID_2(Predecessors[index][i], false);
    // if we had no new coverage we are done in this tree
    if (res == 0) return;
    // otherwise we decend into them
    for (i = 0; i < Predecessors[index].size(); i++)
      reverseFollowPredecessors(Predecessors[index][i]);

  }

  // In this strategy we traverse forward through successors
  void forwardFollowSuccessors(uint32_t index) {

    uint32_t i, res = 0;

    if (Successors[index].size() == 0) return;

    // first calculate the next line of successors
    for (i = 0; i < Successors[index].size(); i++)
      res += calcID_2(Successors[index][i], false);
    // if we had no new coverage we are done in this tree
    if (res == 0) return;
    // otherwise we decend into them
    for (i = 0; i < Successors[index].size(); i++)
      forwardFollowSuccessors(Successors[index][i]);

  }

  void calcID(uint32_t index, bool force) {

    uint32_t ret, colls = 0;

    if (assign_strategy == true)
      ret = calcID_2(index, force);
    else
      ret = calcID_1(index, force);
    // FATAL("disabled");

    // ensure everything is fine before we write to the map
    if (!ret) return;
    if (Predecessors[index].size() == 0) return;
    if (CurrIDs[ReverseMap[index]] >= MAP_SIZE) return;
    for (uint32_t i = 0; i < Predecessors[index].size(); i++)
      if (CurrIDs[ReverseMap[Predecessors[index][i]]] < MAP_SIZE)
        if (map[CurrIDs[ReverseMap[index]] ^
                (CurrIDs[ReverseMap[Predecessors[index][i]]] >> 1)]++)
          colls++;
    // if some predecessors are >= MAP_SIZE and some are not we put
    // values in the map that are not true. but this is better than not
    // doing this.

    return;

  }

  // Here we try different approaches to fit the locations into the map
  // We do all approaches until we have 0 collisions, otherwise we choose
  // the one with the lowest
  void runCalc() {

    uint32_t      iteration = 0, i, j, recoll, afl_idx = 1024, do_loop = 1;
    time_t        before, after, stage3_start, stage3_end;
    unsigned char bmap[MAP_SIZE];

    if (InsBlocks.size() < 2)  // nothing to instrument
      return;

    stage3_start = time(NULL);

    for (uint32_t ll = 1; ll < 8; ll++) {  // best_coll != 0

      increase = ll;
      do_loop = 1;
      id_strategy = true;
      assign_strategy = true;

      while (do_loop) {

        // initialize calculation run
        uint32_t idx = 1;
        memset(map, 0, MAP_SIZE);
        map[0] = 1;  // we do not want map[0] as it also has another use
        iteration++;
        for (i = 1; i < InsBlocks.size(); i++)
          CurrIDs[ReverseMap[i]] = MAP_SIZE + 1;  // MAP_SIZE > 31 => problem!
        global_cur_loc = AFL_R(64);

        before = time(NULL);

        if (debug)
          SAYF("runCalc(%u %s %s %u) at %llu\n", iteration,
               id_strategy == true ? "true" : "false",
               assign_strategy == true ? "true" : "false", increase,
               (unsigned long long int)before);

        // different calculations
        if (iteration == idx++) {  // 1

          for (i = 1; i < InsBlocks.size(); i++) {

            calcID(i, false);

          }

        } else if (iteration == idx++) {  // 2

          i = InsBlocks.size();
          do
            calcID(--i, false);
          while (i > 1);

        } else if (iteration == idx++) {  // 3

          if (assign_strategy == true) {

            // we go from blocks with highest number of predecessor to lowest
            i = hitcount_predecessors.size();
            do {

              i--;
              for (j = 1; j < InsBlocks.size(); j++)
                if (Predecessors[j].size() == hitcount_predecessors[i])
                  calcID(j, false);

            } while (i > 0);

          } else {

            // we go from blocks with lowest number of successors to highest
            for (i = 0; i < hitcount_successors.size(); i++)
              for (j = 1; j < InsBlocks.size(); j++)
                if (Successors[j].size() == hitcount_successors[i])
                  calcID(j, false);

          }

        } else if (iteration == idx++) {  // 4

          if (assign_strategy == true) {

            // we traverse reverse from Exitpoints
            for (i = 0; i < Exitpoints.size(); i++)
              calcID(Exitpoints[i], false);
            // next the precedessors of the exitpoints, we use a function
            for (i = 0; i < Exitpoints.size(); i++)
              reverseFollowPredecessors(Exitpoints[i]);

          } else {

            // we traverse forward from Entrypoints
            // for (i = 0; i < Entrypoints.size(); i++)
            //  calcID(Entrypoints[i], false);
            // we use a function a function for forward traversal

            for (i = 0; i < Entrypoints.size(); i++)
              forwardFollowSuccessors(Entrypoints[i]);

          }

          /* XXX
                Successors[Predecessors[i][j]].push_back(i);
                hitcount_successors.push_back(Successors[i].size());
                hitcount_predecessors.push_back(Predecessors[i].size());
                Exitpoints.push_back(i);
                Entrypoints.push_back(i);
          */

          // below are dumb strategies, but sometimes dumb is good

        } else if (iteration == idx++) {  // 5

          afl_idx = idx - 1;

          if (assign_strategy == true) {

            if (id_strategy == true) {

              for (uint32_t i = 1; i < InsBlocks.size(); i++)
                CurrIDs[ReverseMap[i]] = getID(false);

            } else {  // this is basically what afl does (0x013)

              for (uint32_t i = 1; i < InsBlocks.size(); i++)
                CurrIDs[ReverseMap[i]] = getID(false);

            }

          } else {

            if (id_strategy == true) {

              uint32_t z = (MAP_SIZE / my_edges);
              if (z < 3) z = 3;
              if (z % 2 == 0) z++;
              for (uint32_t i = 1; i < InsBlocks.size(); i++)
                CurrIDs[ReverseMap[i]] = (i * z) % MAP_SIZE;

            } else {

              for (uint32_t i = 1; i < InsBlocks.size(); i++)
                CurrIDs[ReverseMap[i]] = (i << 1) % MAP_SIZE;

            }

          }

        } else if (iteration == idx++) {  // 6

          if (assign_strategy == true) {

            if (id_strategy == true) {

              i = InsBlocks.size();
              do
                CurrIDs[ReverseMap[--i]] = getID(false);
              while (i > 1);

            } else {  // this is basically what afl does (0x014)

              i = InsBlocks.size();
              do
                CurrIDs[ReverseMap[--i]] = getID(false);
              while (i > 1);

            }

          } else {

            if (id_strategy == true) {

              i = InsBlocks.size();
              j = 1;
              uint32_t z = (MAP_SIZE / my_edges);
              if (z < 3) z = 3;
              if (z % 2 == 0) z++;
              do
                CurrIDs[ReverseMap[--i]] = (j * z) % MAP_SIZE;
              while (i > 1);

            } else {

              i = InsBlocks.size();
              j = 1;
              do
                CurrIDs[ReverseMap[--i]] = (j << 1) % MAP_SIZE;
              while (i > 1);

            }

          }

        } else {

          if (id_strategy == true) {

            id_strategy = false;  // redo with random assignments
            iteration = 0;

          } else

              if (assign_strategy == true) {

            assign_strategy = false;
            id_strategy = true;
            iteration = 0;

          } else

            do_loop = 0;

        }

        if (iteration > 0 && do_loop == 1) {

          for (i = 1; i < InsBlocks.size(); i++)
            if (CurrIDs[ReverseMap[i]] >= MAP_SIZE) {

              uint32_t fix_id = i;

              if (Successors[i].size() > 0) {

                uint32_t no_of_pred = 0;
                for (j = 0; j < Successors[i].size(); j++) {

                  if (Predecessors[Successors[i][j]].size() > no_of_pred) {

                    no_of_pred = Predecessors[Successors[i][j]].size();
                    fix_id = Successors[i][j];

                  }

                }

                if (fix_id != i)
                  if (debug)
                    SAYF(cMGN "[D] " cRST
                              "Fix ID from %u to %u (%lu succs, %u preds)\n",
                         i, fix_id, Successors[i].size(), no_of_pred);

              }

              if (debug)
                SAYF(cMGN "[D] " cRST "fix index %u %u\n", fix_id,
                     CurrIDs[ReverseMap[fix_id]]);
              calcID(fix_id, true);

            }

          after = time(NULL);

          memset(map, 0, MAP_SIZE);
          map[0] = 1;
          recoll = 0;
          for (i = 1; i < InsBlocks.size(); i++) {

            if (CurrIDs[ReverseMap[i]] >= MAP_SIZE)
              CurrIDs[ReverseMap[i]] = getID(false);

            if (Predecessors[i].size() > 0)
              for (j = 0; j < Predecessors[i].size(); j++) {

                if (CurrIDs[ReverseMap[Predecessors[i][j]]] >= MAP_SIZE)
                  i = getID(false);

                if (map[(CurrIDs[ReverseMap[Predecessors[i][j]]] >> 1) ^
                        CurrIDs[ReverseMap[i]]]++)
                  recoll++;

              }

          }

          if (assign_strategy == true && id_strategy == false &&
              iteration >= afl_idx) {

            afl_strat += recoll;
            afl_strat_cnt++;

          }

          uint32_t diff = (uint32_t)(after - before);
          if (debug || print_strat)
            SAYF(cMGN "[D] " cRST
                      "Strategy %u with id_strategy %s and assign_strategy %s "
                      "increase %u = %u "
                      "collisions for %llu edges in %u second%s%s\n",
                 iteration, id_strategy == true ? "true" : "false",
                 assign_strategy == true ? "true" : "false", increase, recoll,
                 my_edges, diff, diff == 1 ? "" : "s",
                 assign_strategy == true && id_strategy == false &&
                         iteration >= afl_idx
                     ? " [afl strategy]"
                     : "");

          if (recoll < best_coll ||
              (recoll == best_coll && iteration < afl_idx &&
               (selected & 0xf) >= afl_idx)) {

            if (debug)
              SAYF(cMGN "[D] " cRST "Best strategy with %u < %u: %u %s %s\n",
                   recoll, best_coll, iteration,
                   id_strategy == true ? "true" : "false",
                   assign_strategy == true ? "true" : "false");

            for (uint32_t i = 1; i < InsBlocks.size(); i++)
              MapIDs[ReverseMap[i]] = CurrIDs[ReverseMap[i]];
            best_coll = recoll;
            selected = iteration;
            if (id_strategy == true) selected += 0x10;
            if (assign_strategy == true) selected += 0x100;
            selected += (increase << 12);
            memcpy(bmap, map, MAP_SIZE);

          }

          if (debug == 0 && print_strat == 0 && best_coll == 0) do_loop = 0;

        }

      }

    }

    if (!be_quiet || print_strat) {

      stage3_end = time(NULL);

      uint32_t diff = (uint32_t)(stage3_end - stage3_start);
      if (!be_quiet || print_strat)
        OKF("Stage 3: best strategy 0x%04x found %d collisions (%u second%s)",
            selected, best_coll, diff, diff == 1 ? "" : "s");

      if (debug || print_strat) {

        SAYF(cMGN
             "[D] " cRST
             "TIME strategy stage3_start %ld, time %ld, diff %u, before %ld\n",
             stage3_start, time(NULL), diff, before);

        SAYF(
            "================================================================"
            "\n");
        for (i = 0; i < MAP_SIZE; i++) {

          // if (i % 64 == 0) SAYF("  ");
          if (bmap[i] == 0)
            SAYF(".");
          else if (bmap[i] >= 1 && bmap[i] <= 9)
            SAYF("%c", bmap[i] + '0');
          else
            SAYF("X");
          if (i % 64 == 63) SAYF("\n");

        }

        SAYF(
            "================================================================"
            "\n");

      }

    }

    return;

  }

  // This is very simple and just gets the predecessors with locationIDs
  // for a each locationID block. It takes a long time though!
  void generateCFG(Module &M) {

    time_t before = time(NULL);

    Predecessors.resize(InsBlocks.size());

    for (auto &F : M) {

      if (isBlacklisted(&F)) continue;
      if (F.size() < 2) continue;

      auto *EBB = &F.getEntryBlock();
      int   found_callsites = 0;
      warn = 0;
      if (debug)
        SAYF(cMGN "[D] " cRST "Function: %s\n", F.getName().str().c_str());

      // Only at the start of a function:
      // This is a bit complicated to explain.
      // For the first line of basic blocks in a function that are
      // instrumented the predecessors are in the callee - or even deeper
      // callees if the call happens in the entry block of the callee.
      // For this we need to do 2 steps:
      //   1: collect the first line of basic blocks in the function
      //   2: the predecessors in the callees

      // 1: collect the first line of instrumented blocks in the function
      SuccessorsCFG.clear();
      std::string bb_name = getSimpleNodeLabel(EBB, &F);
      if (findSuccBB(EBB) == false) {

        if (debug)
          SAYF(
              cMGN
              "[D] " cRST
              "function %s->%s(entry) has incomplete successors (%zu found).\n",
              F.getName().str().c_str(), bb_name.c_str(), SuccessorsCFG.size());

      } else if (debug)

        SAYF(cMGN "[D] " cRST "function %s->%s(entry) has %zu successors.\n",
             F.getName().str().c_str(), bb_name.c_str(), SuccessorsCFG.size());

      // 2: collect the predecessors to this function that are instrumented
      // should never be 0 as F.size() < 2 break
      if (SuccessorsCFG.size() > 0) {

        for (auto *U : F.users()) {

          CallSite CS(U);
          auto     I = CS.getInstruction();

          if (I != NULL) {

            Value *   called = CS.getCalledValue()->stripPointerCasts();
            Function *f = dyn_cast<Function>(called);

            if (f->getName().compare(F.getName()) == 0) {

              Function *prev_function =
                  cast<CallInst>(I)->getParent()->getParent();
              BasicBlock *prev_bb = cast<CallInst>(I)->getParent();
              std::string prev_bb_name =
                  getSimpleNodeLabel(prev_bb, prev_function);
              std::string *prev_fname =
                  new std::string(prev_function->getName().str());

              if (debug)
                SAYF(cMGN "[D] " cRST "callsite #%d: %s->%s => %s\n",
                     found_callsites++, prev_fname->c_str(),
                     prev_bb_name.c_str(), F.getName().str().c_str());

              if (isBlacklisted(prev_function)) continue;
              if (f->size() == 0) continue;

              // instrumented blocks in this function
              std::string fn = F.getName().str();
              for (uint32_t i = 0; i < SuccessorsCFG.size(); i++)
                findPrevBB(SuccessorsCFG[i], &*prev_bb, &fn);

            }

          }

        }

        if (debug) SAYF(cMGN "[D] " cRST "done callsite pred!\n");

      }

      // for all other basic blocks it is simple:
      // if we instrument a basic block we search for its predecessors.
      uint32_t count = 0, found = 0;
      for (auto &BB : F) {

        for (uint32_t i = 0; i < SuccessorsCFG.size(); i++)
          if (SuccessorsCFG[i] == &BB) continue;

        if (BB.size() > 0 && LinkMap[&BB] > 0) {

          for (BasicBlock *Pred : predecessors(&BB)) {

            if (Pred->size() > 0) {

              count++;
              if (findPrevBB(&BB, &*Pred, nullptr) == true) found++;

            }

          }

          if (debug)
            SAYF(cMGN "[D] " cRST "%d of %d predecessors found\n", found,
                 count);

        }

      }

    }

    // start TEMP

    // Now that we have the predecessors we create the successors from it
    Successors.resize(InsBlocks.size());
    for (uint32_t i = 1; i < InsBlocks.size(); i++) {

      if (Predecessors[i].size() > 0) {

        for (uint32_t j = 0; j < Predecessors[i].size(); j++) {

          Successors[Predecessors[i][j]].push_back(i);

        }

      }

    }

    // Get the hitcounts of successors and predecessors, sort and unique them
    // We also collect the entrypoints and exitpoints
    for (uint32_t i = 1; i < InsBlocks.size(); i++) {

      hitcount_successors.push_back(Successors[i].size());
      hitcount_predecessors.push_back(Predecessors[i].size());
      if (Successors[i].size() == 0) Exitpoints.push_back(i);
      if (Predecessors[i].size() == 0) Entrypoints.push_back(i);

    }

    std::sort(hitcount_successors.begin(), hitcount_successors.end());
    hitcount_successors.erase(
        std::unique(hitcount_successors.begin(), hitcount_successors.end()),
        hitcount_successors.end());
    std::sort(hitcount_predecessors.begin(), hitcount_predecessors.end());
    hitcount_predecessors.erase(
        std::unique(hitcount_predecessors.begin(), hitcount_predecessors.end()),
        hitcount_predecessors.end());

    if (debug || print_strat)
      SAYF(cMGN "[D] " cRST "Entrypoints:%lu Exitpoints:%lu\n",
           Entrypoints.size(), Exitpoints.size());

    // end TEMP

    for (uint32_t i = 1; i < InsBlocks.size(); i++)
      my_edges += Predecessors[i].size();

    if (!be_quiet || print_strat) {

      uint32_t diff = (uint32_t)(time(NULL) - before);
      OKF("Stage 2: identified %llu predecessors/edges (%u second%s)", my_edges,
          diff, diff == 1 ? "" : "s");

    }

  }

  bool runOnModule(Module &M) override {

    if (getenv("AFL_PRINT_STRATEGY") != NULL) print_strat = 1;
    if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL)
      SAYF(cCYA "afl-llvm-lto-instrumentation" VERSION cRST
                " by Marc \"vanHauser\" Heuse <mh@mh-sec.de>\n");
    else if (print_strat == 0)
      be_quiet = 1;
    // if (getenv("AFL_INCREASE") != NULL) increase =
    // atoi(getenv("AFL_INCREASE"));

    // Initialisation
    LinkMap.clear();
    InsBlocks.clear();
    InsBlocks.push_back(NULL);  // needed!
    Predecessors.clear();
    MapIDs.clear();
    AFL_SR(time(NULL) + getpid());

    // Collect basic information
    unsigned long long int cnt_functions = 0, cnt_bbs = 0, total;
    for (auto &F : M) {

      if (F.size() < 1) continue;

      cnt_functions++;
      for (auto *U : F.users()) {

        CallSite CS(U);
        if (CS.getInstruction() != NULL) cnt_callsites++;

      }

      for (auto &BB : F) {

        if (shouldBeInstrumented(BB) == true) edges++;

        if (!BB.getName().empty())  // we just dont want a warning
          cnt_bbs++;
        else
          cnt_bbs++;

      }

    }

    if (!be_quiet || print_strat) {

      OKF("Module has %llu function%s, %llu callsite%s, %llu total basic "
          "block%s and %llu edge%s.",
          cnt_functions, cnt_functions == 1 ? "" : "s", cnt_callsites,
          cnt_callsites == 1 ? "" : "s", cnt_bbs, cnt_bbs == 1 ? "" : "s",
          edges, edges == 1 ? "" : "s");
      total = (cnt_functions + cnt_callsites + cnt_bbs) >> 13;
      if (total > 0) {

        SAYF(cYEL "[!] " cRST "WARNING: this is complex, it will take a l");
        while (total > 0) {

          SAYF("o");
          total = total >> 1;

        }

        SAYF("ng time to instrument!\n");

      }

    }

    // STAGE_START

    // Collect all BBs to instrument
    runInstrim(M, STAGE_GETBB);
    if (InsBlocks.size() <= 1) {

      if (getenv("AFL_QUIET")) WARNF("Nothing to instrument!");
      return false;

    }

    // Get all predecessors for BBs
    generateCFG(M);  // STAGE_CFG

    // different calculations to find the solution with the lowest collisions
    if (my_edges > 0) runCalc();  // STAGE_CALC

    // put the found values to work: instrument the code
    runInstrim(M, STAGE_SETID);

    // STAGE_END

    return false;

  }

};  // namespace

}  // namespace

char AFLLTOPass::ID = 0;

static void registerAFLLTOPass(const PassManagerBuilder &,
                               legacy::PassManagerBase &PM) {

  PM.add(new AFLLTOPass());

}

static RegisterPass<AFLLTOPass> X("afl-lto", "afl++ LTO instrumentation pass",
                                  false, false);

static RegisterStandardPasses RegisterAFLLTOPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLLTOPass);

