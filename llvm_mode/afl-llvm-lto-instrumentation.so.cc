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

#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <list>
#include <string>

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#define MAX_ID_CNT 512

struct bb_id {

  std::string * function;
  std::string * bb;
  uint32_t      id;
  struct bb_id *next;

};

using namespace llvm;

namespace {

class AFLLTOPass : public ModulePass {

 public:
  static char ID;
  AFLLTOPass() : ModulePass(ID) {

    if (getenv("AFL_DEBUG")) debug = 1;

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
    int    tmp_loc = 0;

    if (id_cnt >= MAX_ID_CNT)
      if (debug) SAYF(cMGN "[D] " cRST "prevID list full! (%s->%s)\n", fname->c_str(), bbname.c_str());

    while (bb_cur != NULL && (bbname.compare(*bb_cur->bb) != 0 ||
                              fname->compare(*bb_cur->function) != 0))
      bb_cur = bb_cur->next;

    if (bb_cur != NULL) {  // predecessor has a cur_loc

      if (debug)
        SAYF(cMGN "[D] " cRST "predecessor %s of %s has id %u\n",
             bbname.c_str(), fname->c_str(), bb_cur->id);
      id_list[id_cnt++] = bb_cur->id;

    } else {  // this predecessor was not instrumented yet

      int tmp_found = 0, i, tmp_coll = 0, loop_cnt = 0;

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

      if ((bb_cur = (struct bb_id *)malloc(sizeof(struct bb_id))) == NULL)
        PFATAL("malloc");
      bb_cur->bb = new std::string(bbname);
      bb_cur->function = fname;
      bb_cur->id = tmp_loc;
      bb_cur->next = bb_list;
      bb_list = bb_cur;
      if (debug)
        SAYF(cMGN "[D] " cRST
                  "basic block %s does not have an ID yet, assigning %u\n",
             bbname.c_str(), tmp_loc);
      ids[tmp_loc]++;
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

  bool runOnModule(Module &M) override;

  void handleFunction(Module &M, Function &F);

 protected:
  int                    be_quiet = 0, inst_blocks = 0, id_cnt, debug = 0;
  unsigned int           cur_loc, inst_ratio = 100;
  unsigned long long int edges = 0, collisions = 0;
  IntegerType *          Int8Ty;
  IntegerType *          Int32Ty;
  unsigned char *        map, *ids;
  unsigned int           id_list[MAX_ID_CNT];
  bb_id *                bb_list;
  char *                 inst_ratio_str = NULL, *neverZero_counters_str = NULL;
  GlobalVariable *       AFLMapPtr, *AFLPrevLoc;

};

}  // namespace

char AFLLTOPass::ID = 0;

void AFLLTOPass::handleFunction(Module &M, Function &F) {

  if (isBlacklisted(&F)) return;

  if (debug)
    SAYF(cMGN "[D] " cRST "Working on function %s\n",
         F.getName().str().c_str());

  LLVMContext &C = M.getContext();
  char         is_first_bb = 1;

  for (auto &BB : F) {

    std::string *        fname = new std::string(F.getName().str());
    BasicBlock::iterator IP = BB.getFirstInsertionPt();
    IRBuilder<>          IRB(&(*IP));
    int found_tmp = 0, max_collisions = 0, cnt_coll = 0, already_exists = 0;
    std::string bb_name = getSimpleNodeLabel(&BB, &F);

    if (debug) SAYF(cMGN "[D] " cRST "BB name is %s\n", bb_name.c_str());

    if (AFL_R(100) > inst_ratio) continue;

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
              SAYF(cMGN "[D] " cRST "callsite #%d: %s -> %s\n", found_callsites,
                   prev_fname->c_str(), prev_bb_name.c_str());

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

    if (found_tmp) {  // BUG: yes one was already assigned (COLLISION!)

      cur_loc = bb_cur->id;
      already_exists = 1;
      cnt_coll = 0;

      for (int i = 0; i < id_cnt && cnt_coll <= max_collisions; i++)
        if ((cur_loc ^ (id_list[i] >> 1)) == 0)
          cnt_coll += map[0] + 1;  // map[0] as last resort
        else
          cnt_coll += map[cur_loc ^ (id_list[i] >> 1)];

      if (debug)
        SAYF(cMGN "[D] " cRST
                  "BB got preassigned %u (%u collisions, %u prevID)\n",
             cur_loc, cnt_coll, id_cnt);

    } else {  // nope we are free to choose

      if (id_cnt == 0) {  // uh nothing before ???

        cur_loc = AFL_R(MAP_SIZE);  // BUG: potential COLLISION :-(

      } else {  // we have predecessors :)

        found_tmp = 0;
        max_collisions = 0;

        while (found_tmp == 0) {

          int loop_cnt = 0;

          while (found_tmp == 0 && loop_cnt < (MAP_SIZE << 2)) {

            cur_loc = AFL_R(MAP_SIZE);
            cnt_coll = 0;
            loop_cnt++;

            for (int i = 0; i < id_cnt && cnt_coll <= max_collisions; i++)
              if ((cur_loc ^ (id_list[i] >> 1)) == 0)
                cnt_coll += map[0] + 1;  // map[0] as last resort
              else
                cnt_coll += map[cur_loc ^ (id_list[i] >> 1)];

            if (cnt_coll <= max_collisions) {

              found_tmp = 1;
              break;

            }

          }

          if (found_tmp == 0) max_collisions++;

        }                                                        /* while() */

      }                                                      /* id_cnt != 0 */

      // add the new cur_loc to the linked list
      if ((bb_cur = (struct bb_id *)malloc(sizeof(struct bb_id))) == NULL)
        PFATAL("malloc");
      bb_cur->bb = new std::string(bb_name);
      bb_cur->function = fname;
      bb_cur->id = cur_loc;
      bb_cur->next = bb_list;
      bb_list = bb_cur;
      ids[cur_loc]++;
      if (debug)
        SAYF(cMGN "[D] " cRST "BB got assigned %u (%u collisions, %u prevID)\n",
             cur_loc, cnt_coll, id_cnt);

    }                                                     /* else found_tmp */

    // document all new edges in the map
    cnt_coll = 0;
    for (int i = 0; i < id_cnt; i++) {

      if (map[cur_loc ^ (id_list[i] >> 1)]++)
        cnt_coll++;
      if (debug)
        SAYF(cMGN "[D] " cRST "setting map[%u ^ (%u >> 1)] = %u\n", cur_loc,
             id_list[i], map[cur_loc ^ (id_list[i] >> 1)]);

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

bool AFLLTOPass::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();
  Int8Ty = IntegerType::getInt8Ty(C);
  Int32Ty = IntegerType::getInt32Ty(C);

  /* Show a banner */

  if (getenv("AFL_DEBUG") || (isatty(2) && !getenv("AFL_QUIET"))) {

    SAYF(cCYA "afl-llvm-lto-instrumentation" VERSION cRST
              " by Marc \"vanHauser\" Heuse <mh@mh-sec.de>\n");

  } else if (getenv("AFL_QUIET"))

    be_quiet = 1;

  /* Decide instrumentation ratio */

  inst_ratio_str = getenv("AFL_INST_RATIO");

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  if ((map = (unsigned char *)malloc(MAP_SIZE)) == NULL) PFATAL("memory");
  if ((ids = (unsigned char *)malloc(MAP_SIZE)) == NULL) PFATAL("memory");

#if LLVM_VERSION_MAJOR < 9
  neverZero_counters_str = getenv("AFL_LLVM_NOT_ZERO");
#endif

//  if (debug) {
    unsigned long long int cnt_functions = 0, cnt_callsites = 0, cnt_bbs = 0, total;
    for (auto &F : M) {
      cnt_functions++;
      for (auto *U : F.users()) {
        CallSite CS(U);
        if (CS.getInstruction() != NULL)
          cnt_callsites++;
      }
      for (auto &BB : F) {
        if (!BB.getName().empty()) // we just dont want a warning
          cnt_bbs++;
        else
          cnt_bbs++;
      }
    }
    OKF("Module has %llu functions, %llu callsites and %llu total basic blocks.", cnt_functions, cnt_callsites, cnt_bbs);
    total = (cnt_functions + cnt_callsites + cnt_bbs) >> 10;
    if (total > 0) {
      SAYF(cYEL "[!] " cRST "WARNING: this is complex, it will take a l");
      while (total > 0) {
        SAYF("o");
        total = total >> 1;
      }
      SAYF("ng time to instrument!\n");
    }
//  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

#ifdef __ANDROID__
  AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc");
#else
  AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

  /* Instrument all the things! */

  // for easiness we set up a first empty entry in the list
  if ((bb_list = (struct bb_id *)malloc(sizeof(struct bb_id))) == NULL)
    PFATAL("malloc");
  bb_list->bb = new std::string("");
  bb_list->function = new std::string("");
  bb_list->id = 0;
  bb_list->next = NULL;

  /* here the magic happens */
  for (auto &F : M)
    handleFunction(M, F);

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else {

      OKF("Instrumented %u locations with %llu edges and resulting in %llu "
          "collision(s) (%s mode, ratio %u%%).",
          inst_blocks, edges, collisions,
          getenv("AFL_HARDEN")
              ? "hardened"
              : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN"))
                     ? "ASAN/MSAN"
                     : "non-hardened"),
          inst_ratio);

    }

  }

  return true;

}

static void registerAFLLTOPass(const PassManagerBuilder &,
                               legacy::PassManagerBase &PM) {

  PM.add(new AFLLTOPass());

}

static RegisterPass<AFLLTOPass> X("afl-lto", "afl++ LTO instrumentation pass",
                                  false /* Only looks at CFG */,
                                  false /* Analysis Pass */);

static RegisterStandardPasses RegisterAFLLTOPass(
    PassManagerBuilder::EP_OptimizerLast /*EP_FullLinkTimeOptimizationLast*/,
    registerAFLLTOPass);

