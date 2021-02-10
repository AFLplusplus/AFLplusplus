/*
   american fuzzy lop++ - LLVM Dead Function Analysis
   --------------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include <list>
#include <string>
#include <fstream>
#include <regex>

#include "llvm/Config/llvm-config.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/ValueTracking.h"

#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/Verifier.h"
  #include "llvm/IR/DebugInfo.h"
#else
  #include "llvm/Analysis/Verifier.h"
  #include "llvm/DebugInfo.h"
  #define nullptr 0
#endif

#include <set>
#include "config.h"
#include "debug.h"
#include "types.h"
#include "afl-llvm-common.h"

using namespace llvm;

namespace {

class Unreachable : public ModulePass {

 public:
  static char ID;
  Unreachable() : ModulePass(ID) {

    initInstrumentList();

  }

  bool runOnModule(Module &M) override;

#if LLVM_VERSION_MAJOR < 4
  const char *getPassName() const override {

#else
  StringRef getPassName() const override {

#endif
    return "cmplog instructions";

  }

 private:
  bool      hookInstrs(Module &M);
  bool      is_in_function_list(std::string);
  Function *get_next_follow_function(Module &M);
  void      add_to_follow_list(Module &M, std::string func);
  void      remove_from_function_list(std::string fname);
  void      extract_all_plain_constants(std::vector<Value *> *all_constants,
                                        Value *               V);

  std::vector<std::string> all_functions;
  std::vector<std::string> follow;
  int                      debug = 0;

};

}  // namespace

char Unreachable::ID = 0;
bool isIgnoreFunction(const llvm::Function *F);

/* Check if a function is our total function list */
bool Unreachable::is_in_function_list(std::string fname) {

  std::vector<std::string>::iterator it =
      std::find(all_functions.begin(), all_functions.end(), fname);
  if (it != all_functions.end()) {

    return true;

  } else {

    return false;

  }

}

/* Return the next entry in the function list we follow */
Function *Unreachable::get_next_follow_function(Module &M) {

  std::string fname = follow.front();
  follow.erase(follow.begin());
  return M.getFunction(fname);

}

/* Remove an entry from the list of all functions */
void Unreachable::remove_from_function_list(std::string fname) {

  std::vector<std::string>::iterator it =
      std::find(all_functions.begin(), all_functions.end(), fname);
  if (it != all_functions.end()) { all_functions.erase(it); }

}

/* A function that is called in a function we follow - so follow it too */
void Unreachable::add_to_follow_list(Module &M, std::string fname) {

  Function *F = M.getFunction(fname);

  std::vector<std::string>::iterator it =
      std::find(all_functions.begin(), all_functions.end(), fname);
  if (it != all_functions.end()) {

    all_functions.erase(it);
    if (!F || !F->size()) return;
    if (!isInInstrumentList(F)) return;
    follow.push_back(fname);

  }

}

/* GlobalVariables can be structs that contain arrays that contain ...
   This is all broken up here until we only have raw Constant parameters */
void Unreachable::extract_all_plain_constants(
    std::vector<Value *> *all_constants, Value *V) {

  auto         CS = dyn_cast<ConstantStruct>(V);
  auto         CA = dyn_cast<ConstantArray>(V);
  auto         CV = dyn_cast<ConstantVector>(V);
  unsigned int i = 0;
  Constant *   C;

  if (CS) {

    while ((C = CS->getAggregateElement(i++))) {

      extract_all_plain_constants(all_constants,
                                  C->stripPointerCastsAndAliases());

    }

  } else if (CA) {

    while ((C = CA->getAggregateElement(i++))) {

      extract_all_plain_constants(all_constants,
                                  C->stripPointerCastsAndAliases());

    }

  } else if (CV) {

    while ((C = CV->getAggregateElement(i++))) {

      extract_all_plain_constants(all_constants,
                                  C->stripPointerCastsAndAliases());

    }

  } else {

    all_constants->push_back(V);

  }

}

bool Unreachable::hookInstrs(Module &M) {

  /*
    if (debug) {  // needs an llvm debug build!
      int i = 0;
      for (auto &F : M)
        // if (F.getName().compare("foo") == 0)
        for (auto &BB : F)
          for (auto &IN : BB) {

            fprintf(stderr, "%d: ", ++i);
            IN.dump();

          }

    }

  */

  /* Grab all functions */
  for (auto &F : M) {

    if (F.size() && !isIgnoreFunction(&F)) {

      if (debug) fprintf(stderr, "F: %s\n", F.getName().str().c_str());
      all_functions.push_back(F.getName().str());

    }

  }

  /* Add CTORs and DTORs - if they should be followed */
  GlobalVariable *GV = M.getNamedGlobal("llvm.global_ctors");
  if (GV && !GV->isDeclaration() && !GV->hasLocalLinkage()) {

    ConstantArray *InitList = dyn_cast<ConstantArray>(GV->getInitializer());

    if (InitList) {

      for (unsigned i = 0, e = InitList->getNumOperands(); i != e; ++i) {

        if (ConstantStruct *CS =
                dyn_cast<ConstantStruct>(InitList->getOperand(i))) {

          if (CS->getNumOperands() >= 2) {

            if (CS->getOperand(1)->isNullValue())
              break;  // Found a null terminator, stop here.

            Constant *FP = CS->getOperand(1);

            if (ConstantExpr *CE = dyn_cast<ConstantExpr>(FP))
              if (CE->isCast()) FP = CE->getOperand(0);
            if (Function *F = dyn_cast<Function>(FP)) {

              if (!F->isDeclaration()) {

                if (debug)
                  fprintf(stderr, "Adding CTOR: %s\n",
                          F->getName().str().c_str());
                add_to_follow_list(M, F->getName().str());

              }

            }

          }

        }

      }

    }

  }

  GV = M.getNamedGlobal("llvm.global_dtors");
  if (GV && !GV->isDeclaration() && !GV->hasLocalLinkage()) {

    ConstantArray *InitList = dyn_cast<ConstantArray>(GV->getInitializer());

    if (InitList) {

      for (unsigned i = 0, e = InitList->getNumOperands(); i != e; ++i) {

        if (ConstantStruct *CS =
                dyn_cast<ConstantStruct>(InitList->getOperand(i))) {

          if (CS->getNumOperands() >= 2) {

            if (CS->getOperand(1)->isNullValue())
              break;  // Found a null terminator, stop here.

            Constant *FP = CS->getOperand(1);

            if (ConstantExpr *CE = dyn_cast<ConstantExpr>(FP))
              if (CE->isCast()) FP = CE->getOperand(0);

            if (Function *F = dyn_cast<Function>(FP)) {

              if (!F->isDeclaration()) {

                if (debug)
                  fprintf(stderr, "Adding DTOR: %s\n",
                          F->getName().str().c_str());
                add_to_follow_list(M, F->getName().str());

              }

            }

          }

        }

      }

    }

  }

  /* Search and add starter functions */
  if (is_in_function_list("LLVMFuzzerTestOneInput")) {

    add_to_follow_list(M, "LLVMFuzzerTestOneInput");
    if (is_in_function_list("LLVMFuzzerInitialize"))
      add_to_follow_list(M, "LLVMFuzzerInitialize");

  } else if (is_in_function_list("main")) {

    add_to_follow_list(M, "main");

  } else {

    fprintf(stderr, "Error: no main() or LLVMFuzzerTestOneInput() found!\n");
    return 0;

  }

  /* Here happens the magic -> static analysis of all functions to follow */
  while (follow.size()) {

    Function *F = get_next_follow_function(M);
    if (!F || !F->size()) { continue; }

    if (debug) fprintf(stderr, "Following: %s\n", F->getName().str().c_str());

    for (auto &BB : *F) {

      for (auto &IN : BB) {

        auto SI = dyn_cast<StoreInst>(&IN);
        if (SI) {

          auto V = SI->getValueOperand()->stripPointerCastsAndAliases();
          if (V) {

            auto T = V->getType();
            if (T && T->isPointerTy()) {

              // This is C++ class + virtual function support
              auto  VV = V->stripInBoundsOffsets();
              auto *G = dyn_cast<GlobalVariable>(VV);
              if (G && G->hasInitializer()) {

                Constant *           GV = G->getInitializer();
                std::vector<Value *> all_constants;
                Value *              VV = dyn_cast<Value>(GV);
                extract_all_plain_constants(&all_constants, VV);
                for (auto C : all_constants) {

                  Function *f = dyn_cast<Function>(C);
                  if (f) {

                    if (debug)
                      fprintf(stderr, "F:%s Store isFunction %s",
                              F->getName().str().c_str(),
                              f->getName().str().c_str());
                    // this is wrong here, needs static analysis
                    add_to_follow_list(M, f->getName().str());

                  }

                }

              }

              if (isa<FunctionType>(T->getPointerElementType())) {

                if (debug)
                  fprintf(stderr, "F:%s Store isFunction",
                          F->getName().str().c_str());
                Function *f = dyn_cast<Function>(V);
                if (f) {

                  if (debug)
                    fprintf(stderr, " \"%s\"\n", f->getName().str().c_str());
                  // this is wrong here, needs static analysis
                  add_to_follow_list(M, f->getName().str());

                } else {

                  if (debug) fprintf(stderr, " <unknown>\n");

                }

              }

            }

          }

        }

        auto CI = dyn_cast<CallInst>(&IN);
        if (CI) {

          Function *Callee = CI->getCalledFunction();
          if (Callee) add_to_follow_list(M, Callee->getName().str());

          for (int i = 0; i < CI->getNumArgOperands(); i++) {

            auto O = CI->getArgOperand(i);
            auto T = O->getType();
            if (T && T->isPointerTy()) {

              if (isa<FunctionType>(T->getPointerElementType())) {

                if (debug)
                  fprintf(stderr, "F:%s call %s ", F->getName().str().c_str(),
                          Callee->getName().str().c_str());
                if (debug) fprintf(stderr, "isFunctionPtr[%d]", i);
                Function *f =
                    dyn_cast<Function>(O->stripPointerCastsAndAliases());
                if (f) {

                  if (debug)
                    fprintf(stderr, " \"%s\"\n", f->getName().str().c_str());
                  add_to_follow_list(M, f->getName().str());

                } else {

                  if (debug) fprintf(stderr, " <unknown>\n");

                }

              }

            }

          }

        }

      }

    }

  }

  // print all functions not visited, however drop __clang*, __gnu and std::
  std::regex re1("(^__*[A-Z0-9][A-Z0-9]*_*)([a-z]*)(.*)");
  for (auto func : all_functions) {

    std::string rest = std::regex_replace(func, re1, "$2");
    if (rest.empty() || (rest.compare("t") && rest.compare(0, 3, "gnu") &&
                         rest.compare(0, 7, "__clang")))
      fprintf(stderr, "UNREACHABLE FUNCTION: %s\n", func.c_str());

  }

  return true;

}

bool Unreachable::runOnModule(Module &M) {

  if (getenv("AFL_DEBUG")) debug = 1;
  if (!getenv("AFL_QUIET") || debug)
    printf("Running afl-llvm-unreachable by Marc Heuse, mh@mh-sec.de\n");
  else
    be_quiet = 1;

  hookInstrs(M);
  verifyModule(M);

  if (!be_quiet) printf("Unreachable analysis finished.\n");

  return true;

}

static void registerUnreachablePass(const PassManagerBuilder &,
                                    legacy::PassManagerBase &PM) {

  auto p = new Unreachable();
  PM.add(p);

}

static RegisterStandardPasses RegisterUnreachablePass(
    PassManagerBuilder::EP_OptimizerLast, registerUnreachablePass);

static RegisterStandardPasses RegisterUnreachablePass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerUnreachablePass);

#if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterUnreachablePassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationEarly,
    registerUnreachablePass);
#endif

