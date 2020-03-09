/*
   american fuzzy lop++ - LLVM CmpLog instrumentation
   --------------------------------------------------

   Written by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016 Google Inc. All rights reserved.
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

using namespace llvm;

namespace {

class CmpLogInstructions : public ModulePass {

 public:
  static char ID;
  CmpLogInstructions() : ModulePass(ID) {

    char *instWhiteListFilename = getenv("AFL_LLVM_WHITELIST");
    if (instWhiteListFilename) {

      std::string   line;
      std::ifstream fileStream;
      fileStream.open(instWhiteListFilename);
      if (!fileStream) report_fatal_error("Unable to open AFL_LLVM_WHITELIST");
      getline(fileStream, line);
      while (fileStream) {

        myWhitelist.push_back(line);
        getline(fileStream, line);

      }

    }

  }

  bool runOnModule(Module &M) override;

#if LLVM_VERSION_MAJOR < 4
  const char *getPassName() const override {

#else
  StringRef getPassName() const override {

#endif
    return "cmplog instructions";

  }

 protected:
  std::list<std::string> myWhitelist;
  int                    be_quiet = 0;

 private:
  bool hookInstrs(Module &M);

};

}  // namespace

char CmpLogInstructions::ID = 0;

bool CmpLogInstructions::hookInstrs(Module &M) {

  std::vector<Instruction *> icomps;
  LLVMContext &              C = M.getContext();

  Type *       VoidTy = Type::getVoidTy(C);
  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c1 = M.getOrInsertFunction("__cmplog_ins_hook1", VoidTy, Int8Ty, Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogHookIns1 = cast<Function>(c1);
#else
  FunctionCallee cmplogHookIns1 = c1;
#endif

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c2 = M.getOrInsertFunction("__cmplog_ins_hook2", VoidTy, Int16Ty, Int16Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogHookIns2 = cast<Function>(c2);
#else
  FunctionCallee cmplogHookIns2 = c2;
#endif

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c4 = M.getOrInsertFunction("__cmplog_ins_hook4", VoidTy, Int32Ty, Int32Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogHookIns4 = cast<Function>(c4);
#else
  FunctionCallee cmplogHookIns4 = c4;
#endif

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c8 = M.getOrInsertFunction("__cmplog_ins_hook8", VoidTy, Int64Ty, Int64Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogHookIns8 = cast<Function>(c8);
#else
  FunctionCallee cmplogHookIns8 = c8;
#endif

  /* iterate over all functions, bbs and instruction and add suitable calls */
  for (auto &F : M) {

    for (auto &BB : F) {

      if (!myWhitelist.empty()) {

        BasicBlock::iterator IP = BB.getFirstInsertionPt();

        bool instrumentBlock = false;

        /* Get the current location using debug information.
         * For now, just instrument the block if we are not able
         * to determine our location. */
        DebugLoc Loc = IP->getDebugLoc();
#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR >= 7)
        if (Loc) {

          DILocation *cDILoc = dyn_cast<DILocation>(Loc.getAsMDNode());

          unsigned int instLine = cDILoc->getLine();
          StringRef    instFilename = cDILoc->getFilename();

          if (instFilename.str().empty()) {

            /* If the original location is empty, try using the inlined location
             */
            DILocation *oDILoc = cDILoc->getInlinedAt();
            if (oDILoc) {

              instFilename = oDILoc->getFilename();
              instLine = oDILoc->getLine();

            }

          }

          (void)instLine;

          /* Continue only if we know where we actually are */
          if (!instFilename.str().empty()) {

            for (std::list<std::string>::iterator it = myWhitelist.begin();
                 it != myWhitelist.end(); ++it) {

              /* We don't check for filename equality here because
               * filenames might actually be full paths. Instead we
               * check that the actual filename ends in the filename
               * specified in the list. */
              if (instFilename.str().length() >= it->length()) {

                if (instFilename.str().compare(
                        instFilename.str().length() - it->length(),
                        it->length(), *it) == 0) {

                  instrumentBlock = true;
                  break;

                }

              }

            }

          }

        }

#else
        if (!Loc.isUnknown()) {

          DILocation cDILoc(Loc.getAsMDNode(C));

          unsigned int instLine = cDILoc.getLineNumber();
          StringRef    instFilename = cDILoc.getFilename();

          (void)instLine;

          /* Continue only if we know where we actually are */
          if (!instFilename.str().empty()) {

            for (std::list<std::string>::iterator it = myWhitelist.begin();
                 it != myWhitelist.end(); ++it) {

              /* We don't check for filename equality here because
               * filenames might actually be full paths. Instead we
               * check that the actual filename ends in the filename
               * specified in the list. */
              if (instFilename.str().length() >= it->length()) {

                if (instFilename.str().compare(
                        instFilename.str().length() - it->length(),
                        it->length(), *it) == 0) {

                  instrumentBlock = true;
                  break;

                }

              }

            }

          }

        }

#endif

        /* Either we couldn't figure out our location or the location is
         * not whitelisted, so we skip instrumentation. */
        if (!instrumentBlock) continue;

      }

      for (auto &IN : BB) {

        CmpInst *selectcmpInst = nullptr;

        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {

          if (selectcmpInst->getPredicate() == CmpInst::ICMP_EQ ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_NE ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_UGT ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_SGT ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_ULT ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_SLT ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_UGE ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_SGE ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_ULE ||
              selectcmpInst->getPredicate() == CmpInst::ICMP_SLE) {

            auto op0 = selectcmpInst->getOperand(0);
            auto op1 = selectcmpInst->getOperand(1);

            IntegerType *intTyOp0 = dyn_cast<IntegerType>(op0->getType());
            IntegerType *intTyOp1 = dyn_cast<IntegerType>(op1->getType());

            /* this is probably not needed but we do it anyway */
            if (!intTyOp0 || !intTyOp1) { continue; }

            icomps.push_back(selectcmpInst);

          }

        }

      }

    }

  }

  if (!icomps.size()) return false;
  if (!be_quiet) errs() << "Hooking " << icomps.size() << " cmp instructions\n";

  for (auto &selectcmpInst : icomps) {

    IRBuilder<> IRB(selectcmpInst->getParent());
    IRB.SetInsertPoint(selectcmpInst);

    auto op0 = selectcmpInst->getOperand(0);
    auto op1 = selectcmpInst->getOperand(1);

    IntegerType *intTyOp0 = dyn_cast<IntegerType>(op0->getType());
    IntegerType *intTyOp1 = dyn_cast<IntegerType>(op1->getType());

    unsigned max_size = intTyOp0->getBitWidth() > intTyOp1->getBitWidth()
                            ? intTyOp0->getBitWidth()
                            : intTyOp1->getBitWidth();

    std::vector<Value *> args;
    args.push_back(op0);
    args.push_back(op1);

    switch (max_size) {

      case 8: IRB.CreateCall(cmplogHookIns1, args, "tmp"); break;
      case 16: IRB.CreateCall(cmplogHookIns2, args, "tmp"); break;
      case 32: IRB.CreateCall(cmplogHookIns4, args, "tmp"); break;
      case 64: IRB.CreateCall(cmplogHookIns8, args, "tmp"); break;
      default: break;

    }

  }

  return true;

}

bool CmpLogInstructions::runOnModule(Module &M) {

  if (getenv("AFL_QUIET") == NULL)
    llvm::errs()
        << "Running cmplog-instructions-pass by andreafioraldi@gmail.com\n";
  else
    be_quiet = 1;
  hookInstrs(M);
  verifyModule(M);

  return true;

}

static void registerCmpLogInstructionsPass(const PassManagerBuilder &,
                                           legacy::PassManagerBase &PM) {

  auto p = new CmpLogInstructions();
  PM.add(p);

}

static RegisterStandardPasses RegisterCmpLogInstructionsPass(
    PassManagerBuilder::EP_OptimizerLast, registerCmpLogInstructionsPass);

static RegisterStandardPasses RegisterCmpLogInstructionsPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerCmpLogInstructionsPass);

