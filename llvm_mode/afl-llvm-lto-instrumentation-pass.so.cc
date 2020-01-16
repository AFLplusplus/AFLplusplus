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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <list>
#include <string>
#include <fstream>
#include <cstdlib>
#include <iostream>

#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/CFG.h"

struct bb_id {

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

  static std::string getSimpleNodeLabel(const BasicBlock *BB,
                                        const Function *) {

    if (!BB->getName().empty()) return BB->getName().str();

    std::string        Str;
    raw_string_ostream OS(Str);

    BB->printAsOperand(OS, false);
    return OS.str();

  }

  static bool isBlacklisted(const Function *F) {

    static const SmallVector<std::string, 5> Blacklist = {

        "asan.", "llvm.", "sancov.", "__ubsan_handle_", "ign."

    };

    for (auto const &BlacklistFunc : Blacklist) {

      if (F->getName().startswith(BlacklistFunc)) { return true; }

    }

    return false;

  }

  bool runOnModule(Module &M) override;

  // StringRef getPassName() const override {

  //  return "American Fuzzy Lop Instrumentation";
  // }

 protected:
  int debug = 0;

};

}  // namespace

char AFLLTOPass::ID = 0;

bool AFLLTOPass::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  unsigned int cur_loc = 0;

  /* Show a banner */

  char be_quiet = 0;

  if (debug) fprintf(stderr, "DEBUG: NEW FILE\n");

  if (getenv("AFL_DEBUG") || (isatty(2) && !getenv("AFL_QUIET"))) {

    SAYF(cCYA "afl-llvm-lto-instrumentation-pass" VERSION cRST
              " by Marc \"vanHauser\" Heuse <mh@mh-sec.de>>\n");

  } else if (getenv("AFL_QUIET"))

    be_quiet = 1;

  /* Decide instrumentation ratio */

  char *       inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  unsigned char *map = NULL, *ids = NULL;
  int            collisions = 0, id_cnt;
  unsigned int   id_list[256];
  bb_id *        bb_list = NULL, *bb_cur;

  if ((map = (unsigned char *)malloc(MAP_SIZE)) == NULL) PFATAL("memory");
  if ((ids = (unsigned char *)malloc(MAP_SIZE)) == NULL) PFATAL("memory");

#if LLVM_VERSION_MAJOR < 9
  char *neverZero_counters_str = getenv("AFL_LLVM_NOT_ZERO");
#endif

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

#ifdef __ANDROID__
  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc");
#else
  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc", 0,
      GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M)
    for (auto &BB : F) {

      if (isBlacklisted(&F)) continue;

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<>          IRB(&(*IP));

      if (AFL_R(100) >= inst_ratio) continue;

      /*
              // only instrument if this basic block is the destination of a
         previous
              // basic block that has multiple successors
              // this gets rid of ~5-10% of instrumentations that are
         unnecessary
              // result: a little more speed and less map pollution
              int more_than_one = -1;
              // fprintf(stderr, "BB %u: ", cur_loc);
              for (BasicBlock *Pred : predecessors(&BB)) {

                int count = 0;
                if (more_than_one == -1) more_than_one = 0;
                // fprintf(stderr, " %p=>", Pred);

                for (BasicBlock *Succ : successors(Pred)) {

                  // if (count > 0)
                  //  fprintf(stderr, "|");
                  if (Succ != NULL) count++;
                  // fprintf(stderr, "%p", Succ);

                }

                if (count > 1) more_than_one = 1;

              }

              // fprintf(stderr, " == %d\n", more_than_one);
              if (more_than_one != 1) continue;
      */

      /* Make up cur_loc */

      // if (fn) {  // AFL_LLVM_NON_COLLIDING_COVERAGE

      std::string bb_name = getSimpleNodeLabel(&BB, &F);

      if (debug) std::cerr << "DEBUG: BB name is " << bb_name << std::endl;

      if (bb_list == NULL) {  // very first basic block

        if ((bb_list = (struct bb_id *)malloc(sizeof(struct bb_id))) == NULL)
          PFATAL("malloc");
        bb_list->bb =
            new std::string(bb_name);  // strdup(LLVMGetBasicBlockName(&BB));
        bb_list->id = cur_loc = AFL_R(MAP_SIZE);  // = 1
        bb_list->next = NULL;
        ids[cur_loc]++;

      } else {

        int already_exists = 0;

        cur_loc = 0;
        memset((char *)id_list, 0, sizeof(id_list));
        id_cnt = 0;

        // first we need a list of cur_loc of all direct predecessors of this
        // bb
        for (BasicBlock *Pred : predecessors(&BB)) {

          assert(Pred != NULL);
          bb_cur = bb_list;
          std::string pred_name = getSimpleNodeLabel(Pred, &F);

          if (debug)
            std::cerr << "DEBUG: predecessor " << pred_name << std::endl;

          while (bb_cur != NULL && pred_name.compare(*bb_cur->bb) != 0)
            bb_cur = bb_cur->next;

          if (bb_cur != NULL) {  // predecessor has a cur_loc

            if (debug)
              std::cerr << "DEBUG: predecessor " << pred_name << " has id "
                        << bb_cur->id << std::endl;
            id_list[id_cnt++] = bb_cur->id;

          } else {

            // this can only happen if more_than_one is active and the
            // predecessor was not instrumented - or if there are more than
            // one entry points as this currently must be a second+ entry
            // point:
            unsigned int tmp_loc, tmp_coll = 0, tmp_found = 0, loop_cnt = 0;
            while (tmp_found == 0) {

              loop_cnt++;

              /*
              tmp_loc = 2;

              while (tmp_loc < MAP_SIZE && ids[tmp_loc] > tmp_coll)
                tmp_loc++;

              if (tmp_loc >= MAP_SIZE)
                tmp_coll++;
              else
                tmp_found = 1;
              */

              tmp_loc = AFL_R(MAP_SIZE);
              if (ids[tmp_loc] <= tmp_coll)
                tmp_found = 1;
              else if (loop_cnt >= (MAP_SIZE << 2)) {

                loop_cnt = 0;
                tmp_coll++;

              }

            }

            if ((bb_cur = (struct bb_id *)malloc(sizeof(struct bb_id))) == NULL)
              PFATAL("malloc");
            bb_cur->bb = new std::string(
                pred_name);  // strdup(BB.LLVMGetBasicBlockName());
            bb_cur->id = tmp_loc;
            bb_cur->next = bb_list;
            bb_list = bb_cur;
            if (debug)
              std::cerr << "Warning: basic block " << pred_name
                        << " does not have an ID yet, assigning " << tmp_loc
                        << std::endl;
            ids[tmp_loc]++;
            id_list[id_cnt++] = bb_cur->id;

          }

        }

        /*
        if (id_cnt > 1) { // check for duplicates
          for (int i = 0; i < id_cnt - 1; i++)
            for (int j = i + 1; j < id_cnt; j++)
              if (id_list[i] == id_list[j])
                PFATAL("duplicate IDs ... :-( %d:%u == %d:%u", i,
                       id_list[i], j, id_list[j]); } else {

          // no predecessors? maybe we already assigned something!
        */
        if (id_cnt == 0) {

          bb_cur = bb_list;
          int found_tmp = 0;
          while (bb_cur != NULL && found_tmp == 0) {

            if (bb_name.compare(*bb_cur->bb) == 0)
              found_tmp = 1;
            else
              bb_cur = bb_cur->next;

          }

          if (found_tmp) {

            cur_loc = bb_cur->id;
            already_exists = 1;

          }

        }

        // now we have the cur_loc IDs of all predecessor
        // next we select a cur_loc for this bb that does not collide

        int max_collisions = 0, cnt_coll = 0, ids_coll = 0, found = 0;

        if (debug) fprintf(stderr, "DEBUG: we found %d IDs\n", id_cnt);

        /*          unsigned int loop_det = 0;*/
        if (cur_loc == 0)

          while (found == 0) {

            cur_loc = 1;

            while (found == 0 && cur_loc < MAP_SIZE) {

              /*                loop_det++;
                              if (loop_det % 1000000 == 0)
                                fprintf(
                                    stderr,
                                    "LOOP %u: cur_loc %u, ids[cur_loc] %u <=
                 ids_coll %u, " "cnt_coll %u <= max_collisions %u\n", loop_det,
                 cur_loc, ids[cur_loc], ids_coll, cnt_coll, max_collisions);*/

              while (cur_loc < MAP_SIZE && ids[cur_loc] > ids_coll)
                cur_loc++;

              if (cur_loc >= MAP_SIZE) {

                ids_coll++;

              } else {

                // if (cur_loc == 1884) fprintf(stderr, "DEBUG: 1884: ids_coll
                // %d ids[1884]=%u\n", ids_coll, ids[1884]);

                cnt_coll = 0;

                for (int i = 0; i < id_cnt && cnt_coll <= max_collisions; i++)
                  if ((cur_loc ^ (id_list[i] >> 1)) ==
                      0)  // I dont want to use map[0]
                    cnt_coll = max_collisions + 1;
                  else
                    cnt_coll += map[cur_loc ^ (id_list[i] >> 1)];

                if (cnt_coll <= max_collisions)
                  found = 1;
                else
                  cur_loc++;

              }

            }                                                    /* while() */

            if (found == 0) max_collisions++;

          }                                                      /* while() */

        if (debug)
          fprintf(stderr,
                  "DEBUG: found cur_loc %u with cnt_coll %d and ids_coll %d\n",
                  cur_loc, cnt_coll, ids_coll);

        if (already_exists == 0) {

          // add to the linked list
          if ((bb_cur = (struct bb_id *)malloc(sizeof(struct bb_id))) == NULL)
            PFATAL("malloc");
          bb_cur->bb =
              new std::string(bb_name);  // strdup(BB.LLVMGetBasicBlockName());
          bb_cur->id = cur_loc;
          bb_cur->next = bb_list;
          bb_list = bb_cur;
          ids[cur_loc]++;

          // if the map size is not big enough we might still get collisions,
          // count them
          if (cnt_coll > 0) {

            if (debug)
              fprintf(stderr,
                      "DEBUG: %d collision(s) in the map for this :-(\n",
                      cnt_coll);
            collisions++;

          }

        }

        // document all new edges in the map
        for (int i = 0; i < id_cnt; i++) {

          map[cur_loc ^ (id_list[i] >> 1)]++;
          if (debug)
            fprintf(stderr, "DEBUG: map[%u ^ (%u >> 1)] = %u\n", cur_loc,
                    id_list[i], map[cur_loc ^ (id_list[i] >> 1)]);

        }

      }                                           /* end of bb_list != NULL */

      if (debug) fprintf(stderr, "DEBUG: selected cur_loc = %u\n", cur_loc);

      //}

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
      if (neverZero_counters_str !=
          NULL) {  // with llvm 9 we make this the default as the bug in llvm is
                   // then fixed
#endif
        /* hexcoder: Realize a counter that skips zero during overflow.
         * Once this counter reaches its maximum value, it next increments to 1
         *
         * Instead of
         * Counter + 1 -> Counter
         * we inject now this
         * Counter + 1 -> {Counter, OverflowFlag}
         * Counter + OverflowFlag -> Counter
         */
        /*       // we keep the old solutions just in case
                 // Solution #1
                 if (neverZero_counters_str[0] == '1') {

                   CallInst *AddOv =
           IRB.CreateBinaryIntrinsic(Intrinsic::uadd_with_overflow, Counter,
           ConstantInt::get(Int8Ty, 1));
                   AddOv->setMetadata(M.getMDKindID("nosanitize"),
           MDNode::get(C, None)); Value *SumWithOverflowBit = AddOv; Incr =
           IRB.CreateAdd(IRB.CreateExtractValue(SumWithOverflowBit, 0),  // sum
                                        IRB.CreateZExt( // convert from one bit
           type to 8 bits type IRB.CreateExtractValue(SumWithOverflowBit, 1), //
           overflow Int8Ty));
                  // Solution #2

                  } else if (neverZero_counters_str[0] == '2') {

                     auto cf = IRB.CreateICmpEQ(Counter,
           ConstantInt::get(Int8Ty, 255)); Value *HowMuch =
           IRB.CreateAdd(ConstantInt::get(Int8Ty, 1), cf); Incr =
           IRB.CreateAdd(Counter, HowMuch);
                  // Solution #3

                  } else if (neverZero_counters_str[0] == '3') {

        */
        // this is the solution we choose because llvm9 should do the right
        // thing here
        auto cf = IRB.CreateICmpEQ(Incr, ConstantInt::get(Int8Ty, 0));
        auto carry = IRB.CreateZExt(cf, Int8Ty);
        Incr = IRB.CreateAdd(Incr, carry);
/*
         // Solution #4

         } else if (neverZero_counters_str[0] == '4') {

            auto cf = IRB.CreateICmpULT(Incr, ConstantInt::get(Int8Ty, 1));
            auto carry = IRB.CreateZExt(cf, Int8Ty);
            Incr = IRB.CreateAdd(Incr, carry);

         } else {

            fprintf(stderr, "Error: unknown value for AFL_NZERO_COUNTS: %s
   (valid is 1-4)\n", neverZero_counters_str); exit(-1);

         }

*/
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

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks)
      WARNF("No instrumentation targets found.");
    else {

      OKF("Instrumented %u locations with %d collision(s) (%s mode, ratio "
          "%u%%).",
          inst_blocks, collisions,
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

