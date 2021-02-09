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

#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>
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
#include "afl-llvm-common.h"

using namespace llvm;

namespace {

class Callgraph : public ModulePass {

 public:
  static char ID;
  Callgraph() : ModulePass(ID) {

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

  std::vector<std::string> all_functions;
  std::vector<std::string> follow;

};

}  // namespace

char Callgraph::ID = 0;
bool isIgnoreFunction(const llvm::Function *F);

template <class Iterator>
Iterator Unique(Iterator first, Iterator last) {

  while (first != last) {

    Iterator next(first);
    last = std::remove(++next, last, *first);
    first = next;

  }

  return last;

}

bool Callgraph::is_in_function_list(std::string fname) {

  std::vector<std::string>::iterator it =
      std::find(all_functions.begin(), all_functions.end(), fname);
  if (it != all_functions.end()) {

    return true;

  } else {

    return false;

  }

}

Function *Callgraph::get_next_follow_function(Module &M) {

  std::string fname = follow.front();
  follow.erase(follow.begin());
  return M.getFunction(fname);

}

void Callgraph::remove_from_function_list(std::string fname) {

  std::vector<std::string>::iterator it =
      std::find(all_functions.begin(), all_functions.end(), fname);
  if (it != all_functions.end()) { all_functions.erase(it); }

}

void Callgraph::add_to_follow_list(Module &M, std::string fname) {

  Function *F = M.getFunction(fname);

  std::vector<std::string>::iterator it =
      std::find(all_functions.begin(), all_functions.end(), fname);
  if (it != all_functions.end()) {

    all_functions.erase(it);
    if (!F || !F->size()) return;
    follow.push_back(fname);

  }

}

bool Callgraph::hookInstrs(Module &M) {

  std::vector<Instruction *> ins;
  // LLVMContext &              C = M.getContext();

  /*
    Type *       VoidTy = Type::getVoidTy(C);
    IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
    IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
  */

  /* Grab all functions */
  for (auto &F : M)
    if (F.size() && !isIgnoreFunction(&F))
      all_functions.push_back(F.getName().str());

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
    // if (!isInInstrumentList(&F)) continue;

    fprintf(stderr, "Following: %s\n", F->getName().str().c_str());

    for (auto &BB : *F) {

      for (auto &IN : BB) {

        auto SI = dyn_cast<StoreInst>(&IN);
        if (SI) {

          auto V = SI->getValueOperand();
          auto VV = V->stripPointerCastsAndAliases();
          if (VV) {

            auto T = VV->getType();
            if (T && T->isPointerTy()) {

              if (isa<FunctionType>(T->getPointerElementType())) {

                fprintf(stderr, "F:%s Store isFunction",
                        F->getName().str().c_str());
                Function *f = dyn_cast<Function>(VV);
                if (f) {

                  fprintf(stderr, " \"%s\"\n", f->getName().str().c_str());
                  // this is wrong here, needs static analysis
                  add_to_follow_list(M, f->getName().str());

                } else {

                  fprintf(stderr, " <unknown>\n");

                }

              }

            }

          }

        }

        auto CI = dyn_cast<CallInst>(&IN);
        if (CI) {

          Function *Callee = CI->getCalledFunction();
          add_to_follow_list(M, Callee->getName().str());

          for (int i = 0; i < CI->getNumArgOperands(); i++) {

            auto O = CI->getArgOperand(i);
            auto T = O->getType();
            if (T && T->isPointerTy()) {

              if (isa<FunctionType>(T->getPointerElementType())) {

                fprintf(stderr, "F:%s call %s ", F->getName().str().c_str(),
                        Callee->getName().str().c_str());
                fprintf(stderr, "isFunctionPtr[%d]", i);
                Function *f =
                    dyn_cast<Function>(O->stripPointerCastsAndAliases());
                if (f) {

                  fprintf(stderr, " \"%s\"\n", f->getName().str().c_str());
                  add_to_follow_list(M, f->getName().str());

                } else {

                  fprintf(stderr, " <unknown>\n");

                }

              }

            }

          }

        }

      }

    }

  }

  for (auto func : all_functions)
    fprintf(stderr, "UNREACHABLE FUNCTION: %s\n", func.c_str());

  return true;

}

bool Callgraph::runOnModule(Module &M) {

  if (getenv("AFL_QUIET") == NULL)
    printf("Running afl-llvm-callgraph by mh@mh-sec.de\n");
  else
    be_quiet = 1;

  hookInstrs(M);
  verifyModule(M);

  return true;

}

static void registerCallgraphPass(const PassManagerBuilder &,
                                  legacy::PassManagerBase &PM) {

  auto p = new Callgraph();
  PM.add(p);

}

static RegisterStandardPasses RegisterCallgraphPass(
    PassManagerBuilder::EP_OptimizerLast, registerCallgraphPass);

static RegisterStandardPasses RegisterCallgraphPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerCallgraphPass);

#if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterCallgraphPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast, registerCallgraphPass);
#endif

