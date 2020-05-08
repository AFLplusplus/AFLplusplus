/*
 * Copyright 2016 laf-intel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
#include "llvm/IR/DebugInfo.h"
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

class CompareTransform : public ModulePass {

 public:
  static char ID;
  CompareTransform() : ModulePass(ID) {

    initWhitelist();

  }

  bool runOnModule(Module &M) override;

#if LLVM_VERSION_MAJOR < 4
  const char *getPassName() const override {

#else
  StringRef getPassName() const override {

#endif
    return "transforms compare functions";

  }

 protected:
  int be_quiet = 0;

 private:
  bool transformCmps(Module &M, const bool processStrcmp,
                     const bool processMemcmp, const bool processStrncmp,
                     const bool processStrcasecmp,
                     const bool processStrncasecmp);

};

}  // namespace

char CompareTransform::ID = 0;

bool CompareTransform::transformCmps(Module &M, const bool processStrcmp,
                                     const bool processMemcmp,
                                     const bool processStrncmp,
                                     const bool processStrcasecmp,
                                     const bool processStrncasecmp) {

  DenseMap<Value *, std::string *> valueMap;
  std::vector<CallInst *>          calls;
  LLVMContext &                    C = M.getContext();
  IntegerType *                    Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *                    Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *                    Int64Ty = IntegerType::getInt64Ty(C);

#if LLVM_VERSION_MAJOR < 9
  Constant *
#else
  FunctionCallee
#endif
      c = M.getOrInsertFunction("tolower", Int32Ty, Int32Ty
#if LLVM_VERSION_MAJOR < 5
                                ,
                                NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *tolowerFn = cast<Function>(c);
#else
  FunctionCallee tolowerFn = c;
#endif

  /* iterate over all functions, bbs and instruction and add suitable calls to
   * strcmp/memcmp/strncmp/strcasecmp/strncasecmp */
  for (auto &F : M) {

    if (!isInWhitelist(&F)) continue;

    for (auto &BB : F) {

      for (auto &IN : BB) {

        CallInst *callInst = nullptr;

        if ((callInst = dyn_cast<CallInst>(&IN))) {

          bool isStrcmp = processStrcmp;
          bool isMemcmp = processMemcmp;
          bool isStrncmp = processStrncmp;
          bool isStrcasecmp = processStrcasecmp;
          bool isStrncasecmp = processStrncasecmp;
          bool isIntMemcpy = true;
          bool indirect = false;

          Function *Callee = callInst->getCalledFunction();
          if (!Callee) continue;
          if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
          StringRef FuncName = Callee->getName();
          isStrcmp &= !FuncName.compare(StringRef("strcmp"));
          isMemcmp &= !FuncName.compare(StringRef("memcmp"));
          isStrncmp &= !FuncName.compare(StringRef("strncmp"));
          isStrcasecmp &= !FuncName.compare(StringRef("strcasecmp"));
          isStrncasecmp &= !FuncName.compare(StringRef("strncasecmp"));
          isIntMemcpy &= !FuncName.compare("llvm.memcpy.p0i8.p0i8.i64");

          if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
              !isStrncasecmp && !isIntMemcpy)
            continue;

          /* Verify the strcmp/memcmp/strncmp/strcasecmp/strncasecmp function
           * prototype */
          FunctionType *FT = Callee->getFunctionType();

          isStrcmp &=
              FT->getNumParams() == 2 && FT->getReturnType()->isIntegerTy(32) &&
              FT->getParamType(0) == FT->getParamType(1) &&
              FT->getParamType(0) == IntegerType::getInt8PtrTy(M.getContext());
          isStrcasecmp &=
              FT->getNumParams() == 2 && FT->getReturnType()->isIntegerTy(32) &&
              FT->getParamType(0) == FT->getParamType(1) &&
              FT->getParamType(0) == IntegerType::getInt8PtrTy(M.getContext());
          isMemcmp &= FT->getNumParams() == 3 &&
                      FT->getReturnType()->isIntegerTy(32) &&
                      FT->getParamType(0)->isPointerTy() &&
                      FT->getParamType(1)->isPointerTy() &&
                      FT->getParamType(2)->isIntegerTy();
          isStrncmp &= FT->getNumParams() == 3 &&
                       FT->getReturnType()->isIntegerTy(32) &&
                       FT->getParamType(0) == FT->getParamType(1) &&
                       FT->getParamType(0) ==
                           IntegerType::getInt8PtrTy(M.getContext()) &&
                       FT->getParamType(2)->isIntegerTy();
          isStrncasecmp &= FT->getNumParams() == 3 &&
                           FT->getReturnType()->isIntegerTy(32) &&
                           FT->getParamType(0) == FT->getParamType(1) &&
                           FT->getParamType(0) ==
                               IntegerType::getInt8PtrTy(M.getContext()) &&
                           FT->getParamType(2)->isIntegerTy();

          if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
              !isStrncasecmp && !isIntMemcpy)
            continue;

          /* is a str{n,}{case,}cmp/memcmp, check if we have
           * str{case,}cmp(x, "const") or str{case,}cmp("const", x)
           * strn{case,}cmp(x, "const", ..) or strn{case,}cmp("const", x, ..)
           * memcmp(x, "const", ..) or memcmp("const", x, ..) */
          Value *Str1P = callInst->getArgOperand(0),
                *Str2P = callInst->getArgOperand(1);
          StringRef Str1, Str2;
          bool      HasStr1 = getConstantStringInfo(Str1P, Str1);
          bool      HasStr2 = getConstantStringInfo(Str2P, Str2);

          if (isIntMemcpy && HasStr2) {

            valueMap[Str1P] = new std::string(Str2.str());
            // fprintf(stderr, "saved %s for %p\n", Str2.str().c_str(), Str1P);
            continue;

          }

          // not literal? maybe global or local variable
          if (!(HasStr1 || HasStr2)) {

            auto *Ptr = dyn_cast<ConstantExpr>(Str2P);
            if (Ptr && Ptr->isGEPWithNoNotionalOverIndexing()) {

              if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {

                if (Var->hasInitializer()) {

                  if (auto *Array =
                          dyn_cast<ConstantDataArray>(Var->getInitializer())) {

                    HasStr2 = true;
                    Str2 = Array->getAsString();
                    valueMap[Str2P] = new std::string(Str2.str());
                    fprintf(stderr, "glo2 %s\n", Str2.str().c_str());

                  }

                }

              }

            }

            if (!HasStr2) {

              auto *Ptr = dyn_cast<ConstantExpr>(Str1P);
              if (Ptr && Ptr->isGEPWithNoNotionalOverIndexing()) {

                if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {

                  if (Var->hasInitializer()) {

                    if (auto *Array = dyn_cast<ConstantDataArray>(
                            Var->getInitializer())) {

                      HasStr1 = true;
                      Str1 = Array->getAsString();
                      valueMap[Str1P] = new std::string(Str1.str());
                      // fprintf(stderr, "glo1 %s\n", Str1.str().c_str());

                    }

                  }

                }

              }

            } else if (isIntMemcpy) {

              valueMap[Str1P] = new std::string(Str2.str());
              // fprintf(stderr, "saved\n");

            }

            if ((HasStr1 || HasStr2)) indirect = true;

          }

          if (isIntMemcpy) continue;

          if (!(HasStr1 || HasStr2)) {

            // do we have a saved local variable initialization?
            std::string *val = valueMap[Str1P];
            if (val && !val->empty()) {

              Str1 = StringRef(*val);
              HasStr1 = true;
              indirect = true;
              // fprintf(stderr, "loaded1 %s\n", Str1.str().c_str());

            } else {

              val = valueMap[Str2P];
              if (val && !val->empty()) {

                Str2 = StringRef(*val);
                HasStr2 = true;
                indirect = true;
                // fprintf(stderr, "loaded2 %s\n", Str2.str().c_str());

              }

            }

          }

          /* handle cases of one string is const, one string is variable */
          if (!(HasStr1 || HasStr2)) continue;

          if (isMemcmp || isStrncmp || isStrncasecmp) {

            /* check if third operand is a constant integer
             * strlen("constStr") and sizeof() are treated as constant */
            Value *      op2 = callInst->getArgOperand(2);
            ConstantInt *ilen = dyn_cast<ConstantInt>(op2);
            if (!ilen) continue;
            /* final precaution: if size of compare is larger than constant
             * string skip it*/
            uint64_t literalLength = HasStr1 ? Str1.size() : Str2.size();
            if (literalLength + 1 < ilen->getZExtValue()) continue;

          }

          calls.push_back(callInst);

        }

      }

    }

  }

  if (!calls.size()) return false;
  if (!be_quiet)
    errs() << "Replacing " << calls.size()
           << " calls to strcmp/memcmp/strncmp/strcasecmp/strncasecmp\n";

  for (auto &callInst : calls) {

    Value *Str1P = callInst->getArgOperand(0),
          *Str2P = callInst->getArgOperand(1);
    StringRef   Str1, Str2, ConstStr;
    std::string TmpConstStr;
    Value *     VarStr;
    bool        HasStr1 = getConstantStringInfo(Str1P, Str1);
    bool        HasStr2 = getConstantStringInfo(Str2P, Str2);
    uint64_t    constLen, sizedLen;
    bool        isMemcmp =
        !callInst->getCalledFunction()->getName().compare(StringRef("memcmp"));
    bool isSizedcmp = isMemcmp ||
                      !callInst->getCalledFunction()->getName().compare(
                          StringRef("strncmp")) ||
                      !callInst->getCalledFunction()->getName().compare(
                          StringRef("strncasecmp"));
    bool isCaseInsensitive = !callInst->getCalledFunction()->getName().compare(
                                 StringRef("strcasecmp")) ||
                             !callInst->getCalledFunction()->getName().compare(
                                 StringRef("strncasecmp"));

    if (isSizedcmp) {

      Value *      op2 = callInst->getArgOperand(2);
      ConstantInt *ilen = dyn_cast<ConstantInt>(op2);
      sizedLen = ilen->getZExtValue();

    } else {

      sizedLen = 0;

    }

    if (!(HasStr1 || HasStr2)) {

      // do we have a saved local or global variable initialization?
      std::string *val = valueMap[Str1P];
      if (val && !val->empty()) {

        Str1 = StringRef(*val);
        HasStr1 = true;

      } else {

        val = valueMap[Str2P];
        if (val && !val->empty()) {

          Str2 = StringRef(*val);
          HasStr2 = true;

        }

      }

    }

    if (HasStr1) {

      TmpConstStr = Str1.str();
      VarStr = Str2P;
      constLen = isMemcmp ? sizedLen : TmpConstStr.length();

    } else {

      TmpConstStr = Str2.str();
      VarStr = Str1P;
      constLen = isMemcmp ? sizedLen : TmpConstStr.length();

    }

    /* properly handle zero terminated C strings by adding the terminating 0 to
     * the StringRef (in comparison to std::string a StringRef has built-in
     * runtime bounds checking, which makes debugging easier) */
    TmpConstStr.append("\0", 1);
    if (!sizedLen) constLen++;
    ConstStr = StringRef(TmpConstStr);
    // fprintf(stderr, "issized: %d, const > sized ? %u > %u\n", isSizedcmp,
    // constLen, sizedLen);
    if (isSizedcmp && constLen > sizedLen && sizedLen) constLen = sizedLen;
    if (constLen > TmpConstStr.length()) constLen = TmpConstStr.length();
    if (!constLen) constLen = TmpConstStr.length();
    if (!constLen) continue;

    if (!be_quiet)
      errs() << callInst->getCalledFunction()->getName() << ": len " << constLen
             << ": " << ConstStr << "\n";

    /* split before the call instruction */
    BasicBlock *bb = callInst->getParent();
    BasicBlock *end_bb = bb->splitBasicBlock(BasicBlock::iterator(callInst));
    BasicBlock *next_bb =
        BasicBlock::Create(C, "cmp_added", end_bb->getParent(), end_bb);
    BranchInst::Create(end_bb, next_bb);
    PHINode *PN = PHINode::Create(Int32Ty, constLen + 1, "cmp_phi");

#if LLVM_VERSION_MAJOR < 8
    TerminatorInst *term = bb->getTerminator();
#else
    Instruction *term = bb->getTerminator();
#endif
    BranchInst::Create(next_bb, bb);
    term->eraseFromParent();

    for (uint64_t i = 0; i < constLen; i++) {

      BasicBlock *cur_bb = next_bb;

      char c = isCaseInsensitive ? tolower(ConstStr[i]) : ConstStr[i];

      BasicBlock::iterator IP = next_bb->getFirstInsertionPt();
      IRBuilder<>          IRB(&*IP);

      Value *v = ConstantInt::get(Int64Ty, i);
      Value *ele = IRB.CreateInBoundsGEP(VarStr, v, "empty");
      Value *load = IRB.CreateLoad(ele);
      if (isCaseInsensitive) {

        // load >= 'A' && load <= 'Z' ? load | 0x020 : load
        std::vector<Value *> args;
        args.push_back(load);
        load = IRB.CreateCall(tolowerFn, args, "tmp");
        load = IRB.CreateTrunc(load, Int8Ty);

      }

      Value *isub;
      if (HasStr1)
        isub = IRB.CreateSub(ConstantInt::get(Int8Ty, c), load);
      else
        isub = IRB.CreateSub(load, ConstantInt::get(Int8Ty, c));

      Value *sext = IRB.CreateSExt(isub, Int32Ty);
      PN->addIncoming(sext, cur_bb);

      if (i < constLen - 1) {

        next_bb =
            BasicBlock::Create(C, "cmp_added", end_bb->getParent(), end_bb);
        BranchInst::Create(end_bb, next_bb);

        Value *icmp = IRB.CreateICmpEQ(isub, ConstantInt::get(Int8Ty, 0));
        IRB.CreateCondBr(icmp, next_bb, end_bb);
        cur_bb->getTerminator()->eraseFromParent();

      } else {

        // IRB.CreateBr(end_bb);

      }

      // add offset to varstr
      // create load
      // create signed isub
      // create icmp
      // create jcc
      // create next_bb

    }

    /* since the call is the first instruction of the bb it is safe to
     * replace it with a phi instruction */
    BasicBlock::iterator ii(callInst);
    ReplaceInstWithInst(callInst->getParent()->getInstList(), ii, PN);

  }

  return true;

}

bool CompareTransform::runOnModule(Module &M) {

  if (isatty(2) && getenv("AFL_QUIET") == NULL)
    llvm::errs() << "Running compare-transform-pass by laf.intel@gmail.com, "
                    "extended by heiko@hexco.de\n";
  else
    be_quiet = 1;
  transformCmps(M, true, true, true, true, true);
  verifyModule(M);

  return true;

}

static void registerCompTransPass(const PassManagerBuilder &,
                                  legacy::PassManagerBase &PM) {

  auto p = new CompareTransform();
  PM.add(p);

}

static RegisterStandardPasses RegisterCompTransPass(
    PassManagerBuilder::EP_OptimizerLast, registerCompTransPass);

static RegisterStandardPasses RegisterCompTransPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerCompTransPass);

