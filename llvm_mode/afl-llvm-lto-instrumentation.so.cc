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
 *  * get loc_id of callsites
 *  * ... ?
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
DenseMap<uint32_t, BasicBlock *>    Entrypoints;
DenseMap<BasicBlock *, uint32_t>    MapIDs;
DenseMap<BasicBlock *, uint32_t>    CurrIDs;
std::vector<BasicBlock *>           InsBlocks;
std::vector<BasicBlock *>           Successors;
std::vector<std::vector<uint32_t> > Predecessors;

struct bb_id {

  std::string * function;
  std::string * bb;
  uint32_t      id;
  struct bb_id *next;

};

struct id_id {

  std::string *function;
  std::string *bb;

};

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

  // check if the basic block already has a location ID assigned, if not
  // generate one randomly. Put the location ID in the list for previous IDs.
  void getOrAddNew(std::string *fname, std::string bbname) {

    bb_id *bb_cur = bb_list;
    int    tmp_loc = 0, i, tmp_found = 0;

    if (id_cnt >= MAX_ID_CNT) {

      if (debug)
        SAYF(cMGN "[D] " cRST "prevID list full! (%s->%s)\n", fname->c_str(),
             bbname.c_str());
      return;

    }

    while (bb_cur != NULL && (bbname.compare(*bb_cur->bb) != 0 ||
                              fname->compare(*bb_cur->function) != 0))
      bb_cur = bb_cur->next;

    if (bb_cur != NULL) {  // predecessor has a cur_loc

      for (i = 0; i < id_cnt && tmp_found == 0; i++)
        if (id_info[i].bb->compare(bbname) == 0 &&
            id_info[i].function->compare(*fname) == 0)
          tmp_found = 1;
      if (tmp_found == 0) {

        if (debug)
          SAYF(cMGN "[D] " cRST "predecessor %s of %s has id %u\n",
               bbname.c_str(), fname->c_str(), bb_cur->id);
        id_info[id_cnt].bb = new std::string(bbname);
        id_info[id_cnt].function = fname;
        id_list[id_cnt++] = bb_cur->id;

      }

    } else {  // this predecessor was not instrumented yet

      tmp_loc = reverseBits(global_cur_loc++);

      /*
            int tmp_coll = 0, loop_cnt = 0;
            while (tmp_found == 0) {

              // BUG: this is a potential source of collision.
              // we might randomly select the same ID here that is then found
              // in a different predecessor for the same target BB afterwards!
              tmp_loc = AFL_R(MAP_SIZE);
              loop_cnt++;
              for (i = 0; i < id_cnt; i++)  // may not be in the current list
                if (id_list[i] == tmp_loc) continue;
              // if avoidable it should not be assigned elsewhere
              if (ids[tmp_loc] <= tmp_coll) {

                tmp_found = 1;

              } else if (loop_cnt >= (MAP_SIZE << 2)) {

                loop_cnt = 0;
                tmp_coll++;

              }

            }

      */

      if ((bb_cur = (struct bb_id *)malloc(sizeof(struct bb_id))) == NULL)
        PFATAL("malloc");
      bb_cur->bb = new std::string(bbname);
      bb_cur->function = fname;
      bb_cur->id = tmp_loc;
      bb_cur->next = bb_list;
      bb_list = bb_cur;
      if (debug)
        SAYF(cMGN
             "[D] " cRST
             "predecessor %s of %s does not have an ID yet, assigning %u\n",
             bbname.c_str(), fname->c_str(), tmp_loc);
      // ids[tmp_loc]++;
      id_info[id_cnt].bb = new std::string(bbname);
      id_info[id_cnt].function = fname;
      id_list[id_cnt++] = bb_cur->id;

    }

  }

  // Recurseivly walk previous basic blocks until every path has been
  // followed and their location ID gathered.
  void addPredLocIDs(Function &F, std::string *fname, BasicBlock &BB) {

    for (BasicBlock *Pred : predecessors(&BB))
      if (Pred != NULL) {

        std::string pred_name = getSimpleNodeLabel(Pred, &F);

        if (shouldBeInstrumented(*Pred) == false) {

          if (debug)
            SAYF(cMGN "[D] " cRST
                      "predecessor %s is not instrumented, digging deeper\n",
                 pred_name.c_str());
          addPredLocIDs(F, fname, *Pred);
          continue;

        }

        getOrAddNew(fname, pred_name);

      }

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
  uint32_t be_quiet = 0, inst_blocks = 0, inst_funcs = 0, id_cnt = 0, debug = 0,
           entrypoints = 0;
  uint32_t cur_loc, inst_ratio = 100, global_cur_loc, total_instr, selected = 0;
  unsigned long long int edges = 0, collisions = 0, my_edges = 0,
                         cnt_callsites = 0;
  bool            id_strategy = true, assign_strategy = true;
  IntegerType *   Int8Ty;
  IntegerType *   Int32Ty;
  unsigned char   map[MAP_SIZE];
  uint32_t        id_list[MAX_ID_CNT];
  id_id           id_info[MAX_ID_CNT];
  bb_id *         bb_list;
  char *          inst_ratio_str = NULL, *neverZero_counters_str = NULL;
  GlobalVariable *AFLMapPtr, *AFLPrevLoc;

  void handleFunction(Module &M, Function &F) {

    if (!F.size()) return;

    if (isBlacklisted(&F)) return;

    if (debug)
      SAYF(cMGN "[D] " cRST "Working on function %s\n",
           F.getName().str().c_str());
    inst_funcs++;

    LLVMContext &C = M.getContext();
    char         is_first_bb = 1;

    for (auto &BB : F) {

      std::string *        fname = new std::string(F.getName().str());
      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));
      int found_tmp = 0, max_collisions = 0, cnt_coll = 0, already_exists = 0,
          i;
      std::string bb_name = getSimpleNodeLabel(&BB, &F);

      if (debug) SAYF(cMGN "[D] " cRST "bb name is %s\n", bb_name.c_str());

      if (AFL_R(100) > inst_ratio) continue;

      for (i = 0; i < id_cnt; i++)  // clean up previous run
        delete id_info[i].bb;

      cur_loc = 0, id_cnt = 0, cnt_coll = 0;
      memset((char *)id_list, 0, sizeof(id_list));

      if (is_first_bb) {

        unsigned int found_callsites = 0, processed_callsites = 0;
        is_first_bb = 0;
        if (debug)
          SAYF(cMGN "[D] " cRST "bb %s is the first in the function\n",
               bb_name.c_str());

        // Lets try to get the call sites and setup initial the loc_id
        // BUG: this can go wrong:
        //  a) if this is not the entry bb for the function
        //  b) if there are multiple entry bbs in this function
        for (auto *U : F.users()) {

          CallSite CS(U);
          found_callsites++;
          auto *I = CS.getInstruction();

          if (I) {

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
                SAYF(cMGN "[D] " cRST "callsite #%d: %s -> %s\n",
                     found_callsites, prev_fname->c_str(),
                     prev_bb_name.c_str());

              if (isBlacklisted(prev_function)) continue;

              if (shouldBeInstrumented(*prev_bb) == false) {

                if (debug)
                  SAYF(cMGN
                       "[D] " cRST
                       "callsite is not to be instrumented, digging deeper\n");
                addPredLocIDs(*prev_function, prev_fname, *prev_bb);

              } else {

                if (debug) SAYF(cMGN "[D] " cRST "adding callsite\n");
                getOrAddNew(prev_fname, prev_bb_name);

              }

              processed_callsites++;

            }

          }

        }

        if (debug)
          SAYF(cMGN "[D] " cRST "%d callsites found, %d processed\n",
               found_callsites, processed_callsites);

      } else {

        // only instrument if this basic block is the destination of a previous
        // basic block that has multiple successors
        // this gets rid of ~5-10% of instrumentations that are unnecessary
        // result: a little more speed and less map pollution

        if (shouldBeInstrumented(BB) == false) {

          if (debug)
            SAYF(cMGN "[D] " cRST "bb %s will NOT be instrumented\n",
                 bb_name.c_str());
          continue;

        } else {

          if (debug)
            SAYF(cMGN "[D] " cRST "bb %s will be instrumented\n",
                 bb_name.c_str());

        }

        // so we want to instrument this basic block, so we have to find all
        // previous basic blocks that have an ID, jumping over those
        // that were ignored due the previous step. tedious but necessary.

        addPredLocIDs(F, fname, BB);

      }

      if (id_cnt > 1) {  // Debugging test: check for duplicates

        edges += id_cnt;  // we count the edges for statistics

        if (debug)
          for (int i = 0; i < id_cnt - 1; i++)
            for (int j = i + 1; j < id_cnt; j++)
              if (id_list[i] == id_list[j])
                SAYF(cMGN
                     "[D] "
                     "!!! duplicate IDs ... :-( %d:%u == %d:%u\n",
                     i, id_list[i], j, id_list[j]);

      }

      if (debug) SAYF(cMGN "[D] " cRST "found %d predecessor IDs\n", id_cnt);

      // now for the loc_id of this BB:
      // maybe this BB already got an loc_id preassigned?
      bb_id *bb_cur = bb_list;
      found_tmp = 0;

      while (bb_cur != NULL && found_tmp == 0) {

        if (bb_name.compare(*bb_cur->bb) == 0 &&
            fname->compare(*bb_cur->function) == 0)
          found_tmp = 1;
        else
          bb_cur = bb_cur->next;

      }

      if (found_tmp) {  // BUG: ID was already assigned (potential COLLISION!)

        cur_loc = bb_cur->id;
        already_exists = 1;
        cnt_coll = 0;

        for (int i = 0; i < id_cnt && cnt_coll <= max_collisions; i++)
          if (map[cur_loc ^ (id_list[i] >> 1)] > 0) cnt_coll++;

        if (debug)
          SAYF(cMGN "[D] " cRST
                    "bb %s got preassigned %u (%u collisions, %u prevIDs)\n",
               bb_name.c_str(), cur_loc, cnt_coll, id_cnt);

      } else {  // nope we are free to choose

        if (id_cnt == 0) {  // uh nothing before ???

          cur_loc = reverseBits(global_cur_loc++);

        } else {  // we have predecessors :)

          found_tmp = 0;
          max_collisions = 0;

          while (found_tmp == 0) {

            unsigned int loop_cnt = 0;

            while (found_tmp == 0 && loop_cnt < (MAP_SIZE << 2) + 1) {

              cur_loc = reverseBits(global_cur_loc++);
              cnt_coll = 0;
              loop_cnt++;

              for (int i = 0; i < id_cnt && cnt_coll <= max_collisions; i++) {

                if ((cur_loc ^ (id_list[i] >> 1)) ==
                    0)  // map[0] as last resort
                  cnt_coll++;
                if (map[cur_loc ^ (id_list[i] >> 1)] > 0) cnt_coll++;

              }

              if (cnt_coll <= max_collisions) {

                found_tmp = 1;
                break;

              }

            }

            if (found_tmp == 0) max_collisions++;

          }                                                      /* while() */

        }                                                    /* id_cnt != 0 */

        // add the new cur_loc to the linked list
        if ((bb_cur = (struct bb_id *)malloc(sizeof(struct bb_id))) == NULL)
          PFATAL("malloc");
        bb_cur->bb = new std::string(bb_name);
        bb_cur->function = fname;
        bb_cur->id = cur_loc;
        bb_cur->next = bb_list;
        bb_list = bb_cur;
        // ids[cur_loc]++;
        if (debug)
          SAYF(cMGN "[D] " cRST
                    "bb %s got assigned %u (%u collisions, %u prevID)\n",
               bb_name.c_str(), cur_loc, cnt_coll, id_cnt);

      }                                                   /* else found_tmp */

      // document all new edges in the map
      cnt_coll = 0;
      for (int i = 0; i < id_cnt; i++) {

        if (map[cur_loc ^ (id_list[i] >> 1)]++) cnt_coll++;
        if (debug)
          SAYF(cMGN "[D] " cRST "setting map[%u ^ (%u >> 1)] = map[%u] = %u\n",
               cur_loc, id_list[i], cur_loc ^ (id_list[i] >> 1),
               map[cur_loc ^ (id_list[i] >> 1)]);

      }

      collisions += cnt_coll;  // count collisions

      /*
       * And *finally* we do the instrumentation!
       *
       */

      /* set cur_loc */

      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

      /* Update bitmap */

      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));

#if LLVM_VERSION_MAJOR < 9
      // with llvm 9 we make this the default as the bug in llvm is then fixed
      if (neverZero_counters_str != NULL) {

#endif
        // this is the solution we choose because llvm9 should do the right
        // thing here
        auto cf = IRB.CreateICmpEQ(Incr, ConstantInt::get(Int8Ty, 0));
        auto carry = IRB.CreateZExt(cf, Int8Ty);
        Incr = IRB.CreateAdd(Incr, carry);
#if LLVM_VERSION_MAJOR < 9

      }

#endif

      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      /* Set prev_loc to cur_loc >> 1 */

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      inst_blocks++;

    }

  }

  /*************************************************************************/

  void printDebugLocation(BasicBlock *BB, uint32_t loc) {

    Function *  f = BB->getParent();
    std::string bn = getSimpleNodeLabel(BB, f);
    SAYF(cMGN "[D] " cRST "Setting %s->%s %u\n", f->getName().str().c_str(),
         bn.c_str(), loc);

  }

  void runInstrim(Module &M, int stage) {

    if (stage != STAGE_GETBB && stage != STAGE_SETID) return;

#if LLVM_VERSION_MAJOR < 9
    char *neverZero_counters_str;
    if (stage == STAGE_SETID &&
        (neverZero_counters_str = getenv("AFL_LLVM_NOT_ZERO")) != NULL)
      OKF("LLVM neverZero activated (by hexcoder)\n");
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

    for (Function &F : M) {

      // if it is external or only contains one basic block: skip it
      if (F.size() < 2) { continue; }

      if (isBlacklisted(&F)) continue;

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
                total_rs += 1;

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

          } else {  // STAGE_SETID

            auto     It = PredMap.insert({PBB, MapIDs[&*PBB]});
            unsigned Label = It.first->second;
            PN->addIncoming(ConstantInt::get(Int32Ty, Label), PBB);
            /*if (debug) */ printDebugLocation(PBB, MapIDs[&*PBB]);

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

    if (be_quiet) return;

    if (stage == STAGE_GETBB) {

      OKF("Stage 1 collected %zu locations to instrument", InsBlocks.size());
      return;

    }

    char modeline[100];
    snprintf(modeline, sizeof(modeline), "%s%s%s%s",
             getenv("AFL_HARDEN") ? "hardened" : "non-hardened",
             getenv("AFL_USE_ASAN") ? ", ASAN" : "",
             getenv("AFL_USE_MSAN") ? ", MSAN" : "",
             getenv("AFL_USE_UBSAN") ? ", UBSAN" : "");

    OKF("Instrumented %u/%llu locations in %u functions with %llu edges and "
        "resulting in %llu potential "
        "collision(s) with strategy 0x%02x (afl-clang-fast/afl-gcc would have "
        "produced "
        "%llu collision(s) on average) (%s mode).",
        total_instr, total_rs, inst_funcs, edges, collisions, selected,
        calculateCollisions(edges + cnt_callsites), modeline);

  }

  // Find a successor that we know to instrument - if *current is not one
  // Note that we descend into further calling functions
  bool findSuccBB(BasicBlock *current) {

    // if (debug) {

    std::string fn = getSimpleNodeLabel(current, current->getParent());
    SAYF(cMGN "[D] " cRST "Successor: %s->%s",
         current->getParent()->getName().str().c_str(), fn.c_str());
    //}

    if (LinkMap[&*current] != 0) {  // yes we instrument "current"

      Successors.push_back(&*current);
      // if (debug)
      SAYF(" success\n");
      return true;

    } else {

      // first check if there are valid function calls
      for (auto &IN : *current) {

        CallInst *callInst = nullptr;
        if ((callInst = dyn_cast<CallInst>(&IN))) {

          Function *Callee = callInst->getCalledFunction();
          if (!Callee || Callee->size() < 2) continue;

          if (findSuccBB(&Callee->getEntryBlock()) == true) {

            // if (debug)
            SAYF(" success\n");
            return true;  // we only need one!

          }

        }

      }

      // if there is no callsite with a function we instrument we go further
      uint32_t count = 0, found = 0;
      for (auto I = succ_begin(current), E = succ_end(current); I != E; ++I) {

        count++;
        if (findSuccBB(*I) == true) found++;

      }

      // if (debug)
      SAYF(" (%u of %u)", found, count);
      if (found > 0 && found == count) {

        // if (debug)
        SAYF(" success\n");
        return true;

      }

    }

    // if we get here we could not resolve one path
    // if (debug)
    SAYF(" failure\n");
    return false;

  }

  // Find a predecessor that we know to instrument - if *current is not one
  // Note that we ascend up callees
  bool findPrevBB(BasicBlock *origin, BasicBlock *current,
                  std::string *target_func) {

    // if (debug) {

    std::string fn1 = getSimpleNodeLabel(origin, origin->getParent());
    std::string fn2 = getSimpleNodeLabel(current, current->getParent());
    SAYF(cMGN "[D] " cRST "Predecessor: %s->%s is %s->%s pred (%s)?",
         origin->getParent()->getName().str().c_str(), fn1.c_str(),
         current->getParent()->getName().str().c_str(), fn2.c_str(),
         target_func == nullptr ? "" : target_func->c_str());
    //}

    if (target_func != nullptr && target_func->length() > 0) {

      // Now to make it even more complicated:
      // If the basic block looks like this:
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

      if (problems > 1) {

        // if (debug)
        SAYF(" failure\n");
        WARNF(
            "This basic callee block %s->%s has %d functions that are likely "
            "predecessors that we dont process yet!\n",
            target_func->c_str(), fn2.c_str(), problems);
        return false;

      }

    }

    if (LinkMap[&*current] != 0) {  // yes we instrument "current"

      Predecessors[LinkMap[&*current]].push_back(LinkMap[&*current]);
      // if (debug)
      SAYF(" success\n");
      return true;

    } else {

      uint32_t found = 0, count = 0;

      // if there is no callsite with a function we instrument we go further
      for (auto S = pred_begin(current), E = pred_end(current); S != E; ++S) {

        count++;
        if (findPrevBB(current, *S, nullptr) == true) found++;

      }

      // if (debug)
      SAYF(" (%u of %u)", found, count);
      if (found > 0 && found == count) {

        // if (debug)
        SAYF(" success\n");
        return true;

      } else if (count == 0) {

        // we are at an entry point so we need to go up the callsites
        uint32_t found_callsites = 0;
        for (auto *U : current->getParent()->users()) {  // Function->users()

          CallSite CS(U);
          found_callsites++;
          auto *I = CS.getInstruction();

          if (I) {

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

              if (findPrevBB(origin, prev_bb, prev_fname) == true /*&& debug*/)
                SAYF(" success\n");
              else                                              /*if (debug)*/
                SAYF(" failure\n");

            }

          }

        }

        if (found_callsites == 0) {

          Entrypoints[found_callsites++] = &*current;

        }

      }

    }

    // if we get here we could not resolve one path
    // if (debug)
    SAYF(" failure\n");
    return false;

  }

  uint32_t getNextEmptyMap(uint32_t current) {

    while (current < MAP_SIZE && map[current])
      current++;
    return current;

  }

  uint32_t getID() {

    if (id_strategy == true)
      return (global_cur_loc++ % MAP_SIZE);
    else
      return AFL_R(MAP_SIZE);

  }

  uint32_t calcID_2(uint32_t index) {

    // select IDs by empty MapIDs and calculate backwards
    uint32_t i, curr_id = CurrIDs[ReverseMap[index]], colls = 0, loc, ccol,
                bcol = Predecessors[index].size() + 1, icnt = 0,
                bcurr_id = CurrIDs[ReverseMap[index]];
    std::vector<uint32_t> val;
    unsigned char         tmap[MAP_SIZE];
    std::vector<uint32_t> best, curr;

    if (Predecessors[index].size() == 0)  // no predecessors? skip it for now
      return 0;

    for (uint32_t pre : Predecessors[index])
      if (CurrIDs[ReverseMap[pre]] < MAP_SIZE)
        val.push_back(CurrIDs[ReverseMap[pre]]);

    if (val.size() == 0 && curr_id >= MAP_SIZE)
      return 0;  // no data whatsoever yet, will be set later

    curr.resize(Predecessors[index].size() - val.size());
    best.resize(curr.size());

    do {

      ccol = 0;
      icnt++;
      memcpy(tmap, map, MAP_SIZE);

      if (curr_id >= MAP_SIZE) {  // we do not have a current location ID yet
                                  // but we have prev location IDs
        uint32_t curr, best, ccnt = 0;

        do {

          ccol = 0;
          ccnt++;
          curr = getID();

          for (i = 0; i < val.size(); i++)
            if (tmap[curr_id ^ (val[i] >> 1)]) ccol++;

          if (ccol < bcol) {

            bcol = ccol;
            best = curr;

          }

        } while (ccol > 0 && ccnt < FIND_VALUE_ATTEMPTS);

        curr_id = best;
        ccol = bcol;

      }

      // now count collisions with existing prev location IDs
      if (val.size() > 0) {

        int warn = 0;
        for (i = 0; i < val.size(); i++) {

          loc = curr_id ^ (val[i] >> 1);
          if (tmap[loc]++) ccol++;

          if (warn == 0 && i + 1 < val.size())
            for (uint32_t j = i + 1; j < val.size() && warn == 0; j++)
              if (val[i] == val[j]) {

                warn = 1;
                WARNF("damn, duplicate previous IDs :-(\n");

              }

        }

      }

      uint32_t target = 0;

      // if we have unassigned locations - assign them
      if (curr.size() > 0) {

        for (i = 0; i < curr.size(); i++) {

          target = getNextEmptyMap(target);
          if (target >= MAP_SIZE)
            curr[i] = reverseBits(getID());
          else
            curr[i] = (target ^ curr_id) << 1;

        }

        if (tmap[(curr[i] >> 1) ^ curr_id]++) ccol++;

      }

      if (ccol < bcol) {

        for (i = 0; i < curr.size(); i++)
          best[i] = curr[i];
        bcurr_id = curr_id;
        bcol = ccol;

      }

    } while (ccol > 0 && icnt < FIND_VALUE_ATTEMPTS);

    // now set map, curr_id, preds and colls
    CurrIDs[ReverseMap[index]] = curr_id = bcurr_id;

    for (i = 0; i < val.size(); i++)
      if (map[curr_id ^ (val[i] >> 1)]++) colls++;

    i = 0;
    for (uint32_t pre : Predecessors[index])
      if (CurrIDs[ReverseMap[pre]] >= MAP_SIZE)
        CurrIDs[ReverseMap[pre]] = best[i++];

    for (i = 0; i < best.size(); i++)
      if (map[curr_id ^ (best[i] >> 1)]++) colls++;

    return colls;

  }

  // Assign IDs to the current location and/or previous locations
  // as needed
  uint32_t calcID_1(uint32_t index) {

    uint32_t i, curr_id = CurrIDs[ReverseMap[index]], colls = 0, loc;
    std::vector<uint32_t> val;

    if (Predecessors[index].size() == 0)  // no predecessors? skip it for now
      return 0;

    for (uint32_t pre : Predecessors[index])
      if (CurrIDs[ReverseMap[pre]] < MAP_SIZE)
        val.push_back(CurrIDs[ReverseMap[pre]]);

    if (val.size() == 0 && curr_id >= MAP_SIZE)
      return 0;  // no data whatsoever yet, will be set later

    if (curr_id >= MAP_SIZE) {  // we do not have a current location ID yet
      // but we have prev location IDs
      uint32_t curr, best, bcol = val.size() + 1, ccol, icnt = 0;

      do {

        ccol = 0;
        icnt++;
        curr = getID();

        for (i = 0; i < val.size(); i++)
          if (map[curr_id ^ (val[i] >> 1)]) ccol++;

        if (ccol < bcol) {

          bcol = ccol;
          best = curr;

        }

      } while (ccol > 0 && icnt < FIND_VALUE_ATTEMPTS);

      CurrIDs[ReverseMap[index]] = curr_id = best;

    }

    // now count collisions with existing prev location IDs
    if (val.size() > 0) {

      int warn = 0;
      for (i = 0; i < val.size(); i++) {

        loc = curr_id ^ (val[i] >> 1);
        if (map[loc]++) colls++;

        if (warn == 0 && i + 1 < val.size())
          for (uint32_t j = i + 1; j < val.size() && warn == 0; j++)
            if (val[i] == val[j]) {

              warn = 1;
              WARNF("damn, duplicate previous IDs :-(\n");

            }

      }

    }

    // if we have unassigned locations - assign them
    if (val.size() < Predecessors[index].size()) {

      uint32_t ccol, bcol = val.size() + 1, cnt = 0, icnt, tmp, duplicate, j;
      std::vector<uint32_t> best, curr;
      curr.resize(Predecessors[index].size() - val.size());
      best.resize(curr.size());
      do {

        ccol = 0;

        for (i = 0; i < curr.size(); i++) {

          duplicate = icnt = 0;

          do {

            icnt++;
            do {

              // for predecessors it is better to reverse
              tmp = reverseBits(getID());
              for (j = 0; j < val.size() && !duplicate; j++)
                if (val[j] == tmp) duplicate = 1;
              if (i > 0)
                for (j = 0; j < i && !duplicate; j++)
                  if (curr[i] == tmp) duplicate = 1;

            } while (!duplicate);

          } while (icnt < FIND_VALUE_ATTEMPTS && map[(tmp >> 1) ^ curr_id]);

          curr[i] = tmp;
          if (map[(tmp >> 1) ^ curr_id]) ccol++;

        }

        if (ccol < bcol) {

          for (i = 0; i < curr.size(); i++)
            best[i] = curr[i];
          bcol = ccol;

        }

        cnt++;

      } while (cnt < FIND_VALUE_ATTEMPTS && ccol > 0);

      j = 0;
      for (uint32_t pre : Predecessors[index])
        if (CurrIDs[ReverseMap[pre]] >= MAP_SIZE) {

          CurrIDs[ReverseMap[pre]] = best[j++];

        }

      for (j = 0; j < best.size(); j++)
        if (map[curr_id ^ (best[j] >> 1)]++) colls++;

    }

    return colls;

  }

  uint32_t calcID(uint32_t index) {

    if (assign_strategy == true)
      return calcID_2(index);
    else
      return calcID_1(index);

  }

  // Here we try different approaches to fit the locations into the map
  // We do all approaches until we have 0 collisions, otherwise we choose
  // the one with the lowest
  uint32_t runCalc() {

    int32_t  curr_coll = 0, best_coll = -1;
    uint32_t iteration = 0, i;

    while (1) {

      // initialize calculation run
      uint32_t idx = 1;
      memset(map, 0, MAP_SIZE);
      map[0] = 1;  // we do not want map[0] as it also has another use
      for (i = 0; i < InsBlocks.size(); i++)
        CurrIDs[ReverseMap[i]] = MAP_SIZE + 1;  // MAP_SIZE > 31 => problem!
      curr_coll = 0;
      iteration++;

      // different calculations
      if (iteration == idx++) {

        for (i = 0; i < InsBlocks.size(); i++) {

          curr_coll += calcID(i);

        }

      } else if (iteration == idx++) {

        i = InsBlocks.size();
        do
          curr_coll += calcID(--i);
        while (i > 0);

#if 0

      } else if (iteration == idx++) {

        // entrypoint

      } else if (iteration == idx++) {

        // entrypoint rev

#endif
#ifdef _HAVE_Z3

      } else if (iteration == idx++) {

        // z3

#endif

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

          break;

      }

      /*if (debug)*/
      SAYF(cMGN "[D] " cRST
                "Strategy %u with id_strategy %s and assign_strategy %s = %u "
                "collisions\n",
           iteration, id_strategy == true ? "true" : "false",
           assign_strategy == true ? "true" : "false", curr_coll);

      if (curr_coll < best_coll || best_coll == -1) {

        for (uint32_t i = 0; i < InsBlocks.size(); i++)
          MapIDs[ReverseMap[i]] = CurrIDs[ReverseMap[i]];
        best_coll = curr_coll;
        selected = iteration;
        if (id_strategy == false) selected += 0x10;
        if (assign_strategy == false) selected += 0x100;

      }

      if (best_coll == 0) break;

    }

    // temporary
    for (uint32_t i = 0; i < InsBlocks.size(); i++)
      MapIDs[ReverseMap[i]] = i << 1;

    return (uint32_t)best_coll;

  }

  // This is very simple and just gets the predecessors with locationIDs
  // for a each locationID block
  void generateCFG(Module &M) {

    Predecessors.resize(InsBlocks.size());

    for (auto &F : M) {

      if (isBlacklisted(&F)) continue;
      if (F.size() < 2) continue;

      auto *EBB = &F.getEntryBlock();
      int   found_callsites = 0;

      // Only at the start of a function:
      // This is a bit complicated to explain.
      // For the first line of basic blocks in a function that are
      // instrumented the predecessors are in the callee - or even deeper
      // callees if the callee is a single block function
      // For this we need to do 2 steps, first collect the first line of
      // basic blocks in the function and second the predecessors in the
      // callees

      // 1: collect the first line of instrumented blocks in the function
      Successors.clear();
      if (findSuccBB(EBB) == false /*&& debug*/)
        SAYF(cMGN "[D] " cRST
                  "function %s->entry has incomplete successors (%zu found).\n",
             F.getName().str().c_str(), Successors.size());
      else                                                    /* if (debug) */
        SAYF(cMGN "[D] " cRST "function %s->entry has %zu successors.\n",
             F.getName().str().c_str(), Successors.size());

      // 2: collect the predecessors to this function that are instrumented
      if (Successors.size() > 0) {  // should never be 0 as F.size() < 2 break
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

              // if (debug)
              SAYF(cMGN "[D] " cRST "callsite #%d: %s -> %s\n",
                   found_callsites++, prev_fname->c_str(),
                   prev_bb_name.c_str());

              if (isBlacklisted(prev_function)) continue;
              if (f->size() == 0) continue;

              // instrumented blocks in this function
              std::string fn = F.getName().str();
              for (uint32_t i = 0; i < Successors.size(); i++)
                findPrevBB(Successors[i], &*prev_bb, &fn);

            }

          }

        }

      }

      // for all other basic blocks it is simple:
      // if we instrument a basic block we search for its predecessors.
      uint32_t count = 0, found = 0;
      for (auto &BB : F) {

        for (uint32_t i = 0; i < Successors.size(); i++)
          if (Successors[i] == &BB) continue;

        if (BB.size() > 0 && LinkMap[&BB] > 0) {

          for (BasicBlock *Pred : predecessors(&BB)) {

            if (Pred->size() > 0) {

              count++;
              if (findPrevBB(&BB, &*Pred, nullptr) == true) found++;

            }

          }

          // if (debug)
          SAYF(cMGN "[D] " cRST "%d of %d predecessors found\n", found, count);

        }

      }

    }

    for (uint32_t i = 0; i < InsBlocks.size(); i++)
      my_edges += Predecessors[i].size();

    if (!be_quiet) OKF("Stage 2 identified %llu predecessors/edges", my_edges);

  }

  bool runOnModule(Module &M) override {

    uint32_t lowest_collisions;

    if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL)
      SAYF(cCYA "afl-llvm-lto-instrumentation" VERSION cRST
                " by Marc \"vanHauser\" Heuse <mh@mh-sec.de>\n");
    else
      be_quiet = 1;

    // Initialisation
    LinkMap.clear();
    InsBlocks.clear();
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

    if (!be_quiet) {

      OKF("Module has %llu function%s, %llu callsite%s and %llu total basic "
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

    // Get all predecessors for BBs
    generateCFG(M);  // STAGE_CFG

    // different calculations to find the solution with the lowest collisions
    lowest_collisions = runCalc();  // STAGE_CALC

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

