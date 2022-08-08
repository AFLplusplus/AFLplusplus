/*
 * Copyright 2016 laf-intel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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
#include "llvm/IR/IRBuilder.h"
#if LLVM_MAJOR >= 11                                /* use new pass manager */
  #include "llvm/Passes/PassPlugin.h"
  #include "llvm/Passes/PassBuilder.h"
  #include "llvm/IR/PassManager.h"
#else
  #include "llvm/IR/LegacyPassManager.h"
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/ValueTracking.h"
#if LLVM_VERSION_MAJOR >= 14                /* how about stable interfaces? */
  #include "llvm/Passes/OptimizationLevel.h"
#endif

#if LLVM_VERSION_MAJOR >= 4 || \
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

#if LLVM_MAJOR >= 11                                /* use new pass manager */
class CompareTransform : public PassInfoMixin<CompareTransform> {

 public:
  CompareTransform() {

#else
class CompareTransform : public ModulePass {

 public:
  static char ID;
  CompareTransform() : ModulePass(ID) {

#endif

    initInstrumentList();

  }

#if LLVM_MAJOR < 11
  #if LLVM_VERSION_MAJOR >= 4
  StringRef getPassName() const override {

  #else
  const char *getPassName() const override {

  #endif

    return "cmplog transform";

  }

#endif

#if LLVM_MAJOR >= 11                                /* use new pass manager */
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif

 private:
  bool transformCmps(Module &M, const bool processStrcmp,
                     const bool processMemcmp, const bool processStrncmp,
                     const bool processStrcasecmp,
                     const bool processStrncasecmp);

};

}  // namespace

#if LLVM_MAJOR >= 11                                /* use new pass manager */
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "comparetransform", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

  #if 1
    #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
    #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(CompareTransform());

                });

  /* TODO LTO registration */
  #else
            using PipelineElement = typename PassBuilder::PipelineElement;
            PB.registerPipelineParsingCallback([](StringRef          Name,
                                                  ModulePassManager &MPM,
                                                  ArrayRef<PipelineElement>) {

              if (Name == "comparetransform") {

                MPM.addPass(CompareTransform());
                return true;

              } else {

                return false;

              }

            });

  #endif

          }};

}

#else
char CompareTransform::ID = 0;
#endif

bool CompareTransform::transformCmps(Module &M, const bool processStrcmp,
                                     const bool processMemcmp,
                                     const bool processStrncmp,
                                     const bool processStrcasecmp,
                                     const bool processStrncasecmp) {

  DenseMap<Value *, std::string *> valueMap;
  std::vector<CallInst *>          calls;
  LLVMContext                     &C = M.getContext();
  IntegerType                     *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType                     *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType                     *Int64Ty = IntegerType::getInt64Ty(C);

#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee tolowerFn;
#else
  Function *tolowerFn;
#endif
  {

#if LLVM_VERSION_MAJOR >= 9
    FunctionCallee
#else
    Constant *
#endif
        c = M.getOrInsertFunction("tolower", Int32Ty, Int32Ty
#if LLVM_VERSION_MAJOR < 5
                                  ,
                                  NULL
#endif
        );
#if LLVM_VERSION_MAJOR >= 9
    tolowerFn = c;
#else
    tolowerFn = cast<Function>(c);
#endif

  }

  /* iterate over all functions, bbs and instruction and add suitable calls to
   * strcmp/memcmp/strncmp/strcasecmp/strncasecmp */
  for (auto &F : M) {

    if (!isInInstrumentList(&F, MNAME)) continue;

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

          Function *Callee = callInst->getCalledFunction();
          if (!Callee) continue;
          if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
          StringRef FuncName = Callee->getName();
          isStrcmp &=
              (!FuncName.compare("strcmp") || !FuncName.compare("xmlStrcmp") ||
               !FuncName.compare("xmlStrEqual") ||
               !FuncName.compare("g_strcmp0") ||
               !FuncName.compare("curl_strequal") ||
               !FuncName.compare("strcsequal"));
          isMemcmp &=
              (!FuncName.compare("memcmp") || !FuncName.compare("bcmp") ||
               !FuncName.compare("CRYPTO_memcmp") ||
               !FuncName.compare("OPENSSL_memcmp") ||
               !FuncName.compare("memcmp_const_time") ||
               !FuncName.compare("memcmpct"));
          isStrncmp &= (!FuncName.compare("strncmp") ||
                        !FuncName.compare("xmlStrncmp") ||
                        !FuncName.compare("curl_strnequal"));
          isStrcasecmp &= (!FuncName.compare("strcasecmp") ||
                           !FuncName.compare("stricmp") ||
                           !FuncName.compare("ap_cstr_casecmp") ||
                           !FuncName.compare("OPENSSL_strcasecmp") ||
                           !FuncName.compare("xmlStrcasecmp") ||
                           !FuncName.compare("g_strcasecmp") ||
                           !FuncName.compare("g_ascii_strcasecmp") ||
                           !FuncName.compare("Curl_strcasecompare") ||
                           !FuncName.compare("Curl_safe_strcasecompare") ||
                           !FuncName.compare("cmsstrcasecmp"));
          isStrncasecmp &= (!FuncName.compare("strncasecmp") ||
                            !FuncName.compare("strnicmp") ||
                            !FuncName.compare("ap_cstr_casecmpn") ||
                            !FuncName.compare("OPENSSL_strncasecmp") ||
                            !FuncName.compare("xmlStrncasecmp") ||
                            !FuncName.compare("g_ascii_strncasecmp") ||
                            !FuncName.compare("Curl_strncasecompare") ||
                            !FuncName.compare("g_strncasecmp"));
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
            if (Ptr && Ptr->getOpcode() == Instruction::GetElementPtr) {

              if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {

                if (Var->hasInitializer()) {

                  if (auto *Array =
                          dyn_cast<ConstantDataArray>(Var->getInitializer())) {

                    HasStr2 = true;
                    Str2 = Array->getRawDataValues();
                    valueMap[Str2P] = new std::string(Str2.str());
                    // fprintf(stderr, "glo2 %s\n", Str2.str().c_str());

                  }

                }

              }

            }

            if (!HasStr2) {

              Ptr = dyn_cast<ConstantExpr>(Str1P);
              if (Ptr && Ptr->getOpcode() == Instruction::GetElementPtr) {

                if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {

                  if (Var->hasInitializer()) {

                    if (auto *Array = dyn_cast<ConstantDataArray>(
                            Var->getInitializer())) {

                      HasStr1 = true;
                      Str1 = Array->getRawDataValues();
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

          }

          if (isIntMemcpy) continue;

          if (!(HasStr1 || HasStr2)) {

            // do we have a saved local variable initialization?
            std::string *val = valueMap[Str1P];
            if (val && !val->empty()) {

              Str1 = StringRef(*val);
              HasStr1 = true;
              // fprintf(stderr, "loaded1 %s\n", Str1.str().c_str());

            } else {

              val = valueMap[Str2P];
              if (val && !val->empty()) {

                Str2 = StringRef(*val);
                HasStr2 = true;
                // fprintf(stderr, "loaded2 %s\n", Str2.str().c_str());

              }

            }

          }

          /* handle cases of one string is const, one string is variable */
          if (!(HasStr1 || HasStr2)) continue;

          if (isMemcmp || isStrncmp || isStrncasecmp) {

            /* check if third operand is a constant integer
             * strlen("constStr") and sizeof() are treated as constant */
            Value       *op2 = callInst->getArgOperand(2);
            ConstantInt *ilen = dyn_cast<ConstantInt>(op2);
            if (ilen) {

              // if len is zero this is a pointless call but allow real
              // implementation to worry about that
              if (ilen->getZExtValue() < 2) { continue; }

            } else if (isMemcmp) {

              // this *may* supply a len greater than the constant string at
              // runtime so similarly we don't want to have to handle that
              continue;

            }

          }

          calls.push_back(callInst);

        }

      }

    }

  }

  if (!calls.size()) return false;
  if (!be_quiet)
    printf(
        "Replacing %zu calls to strcmp/memcmp/strncmp/strcasecmp/strncasecmp\n",
        calls.size());

  for (auto &callInst : calls) {

    Value *Str1P = callInst->getArgOperand(0),
          *Str2P = callInst->getArgOperand(1);
    StringRef   Str1, Str2, ConstStr;
    std::string TmpConstStr;
    Value      *VarStr;
    bool        HasStr1 = getConstantStringInfo(Str1P, Str1);
    bool        HasStr2 = getConstantStringInfo(Str2P, Str2);
    uint64_t    constStrLen, unrollLen, constSizedLen = 0;
    bool        isMemcmp = false;
    bool        isSizedcmp = false;
    bool        isCaseInsensitive = false;
    bool        needs_null = false;
    Function   *Callee = callInst->getCalledFunction();

    if (Callee) {

      if (!Callee->getName().compare("memcmp") ||
          !Callee->getName().compare("bcmp") ||
          !Callee->getName().compare("CRYPTO_memcmp") ||
          !Callee->getName().compare("OPENSSL_memcmp") ||
          !Callee->getName().compare("memcmp_const_time") ||
          !Callee->getName().compare("memcmpct") ||
          !Callee->getName().compare("llvm.memcpy.p0i8.p0i8.i64"))
        isMemcmp = true;

      if (isMemcmp || !Callee->getName().compare("strncmp") ||
          !Callee->getName().compare("xmlStrncmp") ||
          !Callee->getName().compare("curl_strnequal") ||
          !Callee->getName().compare("strncasecmp") ||
          !Callee->getName().compare("strnicmp") ||
          !Callee->getName().compare("ap_cstr_casecmpn") ||
          !Callee->getName().compare("OPENSSL_strncasecmp") ||
          !Callee->getName().compare("xmlStrncasecmp") ||
          !Callee->getName().compare("g_ascii_strncasecmp") ||
          !Callee->getName().compare("Curl_strncasecompare") ||
          !Callee->getName().compare("g_strncasecmp"))
        isSizedcmp = true;

      if (!Callee->getName().compare("strcasecmp") ||
          !Callee->getName().compare("stricmp") ||
          !Callee->getName().compare("ap_cstr_casecmp") ||
          !Callee->getName().compare("OPENSSL_strcasecmp") ||
          !Callee->getName().compare("xmlStrcasecmp") ||
          !Callee->getName().compare("g_strcasecmp") ||
          !Callee->getName().compare("g_ascii_strcasecmp") ||
          !Callee->getName().compare("Curl_strcasecompare") ||
          !Callee->getName().compare("Curl_safe_strcasecompare") ||
          !Callee->getName().compare("cmsstrcasecmp") ||
          !Callee->getName().compare("strncasecmp") ||
          !Callee->getName().compare("strnicmp") ||
          !Callee->getName().compare("ap_cstr_casecmpn") ||
          !Callee->getName().compare("OPENSSL_strncasecmp") ||
          !Callee->getName().compare("xmlStrncasecmp") ||
          !Callee->getName().compare("g_ascii_strncasecmp") ||
          !Callee->getName().compare("Curl_strncasecompare") ||
          !Callee->getName().compare("g_strncasecmp"))
        isCaseInsensitive = true;

    }

    if (!isSizedcmp) needs_null = true;

    Value *sizedValue = isSizedcmp ? callInst->getArgOperand(2) : NULL;
    bool   isConstSized = sizedValue && isa<ConstantInt>(sizedValue);

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
          // HasStr2 = true;

        }

      }

    }

    if (isConstSized) {

      constSizedLen = dyn_cast<ConstantInt>(sizedValue)->getZExtValue();

    }

    if (HasStr1) {

      TmpConstStr = Str1.str();
      VarStr = Str2P;

    } else {

      TmpConstStr = Str2.str();
      VarStr = Str1P;

    }

    if (TmpConstStr.length() < 2 ||
        (TmpConstStr.length() == 2 && TmpConstStr[1] == 0)) {

      continue;

    }

    // the following is in general OK, but strncmp is sometimes used in binary
    // data structures and this can result in crashes :( so it is commented out

    // add null termination character implicit in c strings
    if (needs_null && TmpConstStr[TmpConstStr.length() - 1] != 0) {

      TmpConstStr.append("\0", 1);

    }

    // in the unusual case the const str has embedded null
    // characters, the string comparison functions should terminate
    // at the first null
    if (!isMemcmp && TmpConstStr.find('\0') != std::string::npos) {

      TmpConstStr.assign(TmpConstStr, 0, TmpConstStr.find('\0') + 1);

    }

    constStrLen = TmpConstStr.length();
    // prefer use of StringRef (in comparison to std::string a StringRef has
    // built-in runtime bounds checking, which makes debugging easier)
    ConstStr = StringRef(TmpConstStr);

    if (isConstSized)
      unrollLen = constSizedLen < constStrLen ? constSizedLen : constStrLen;
    else
      unrollLen = constStrLen;

    /* split before the call instruction */
    BasicBlock *bb = callInst->getParent();
    BasicBlock *end_bb = bb->splitBasicBlock(BasicBlock::iterator(callInst));

    BasicBlock *next_lenchk_bb = NULL;
    if (isSizedcmp && !isConstSized) {

      next_lenchk_bb =
          BasicBlock::Create(C, "len_check", end_bb->getParent(), end_bb);
      BranchInst::Create(end_bb, next_lenchk_bb);

    }

    BasicBlock *next_cmp_bb =
        BasicBlock::Create(C, "cmp_added", end_bb->getParent(), end_bb);
    BranchInst::Create(end_bb, next_cmp_bb);
    PHINode *PN = PHINode::Create(
        Int32Ty, (next_lenchk_bb ? 2 : 1) * unrollLen + 1, "cmp_phi");

#if LLVM_VERSION_MAJOR >= 8
    Instruction *term = bb->getTerminator();
#else
    TerminatorInst *term = bb->getTerminator();
#endif
    BranchInst::Create(next_lenchk_bb ? next_lenchk_bb : next_cmp_bb, bb);
    term->eraseFromParent();

    for (uint64_t i = 0; i < unrollLen; i++) {

      BasicBlock   *cur_cmp_bb = next_cmp_bb, *cur_lenchk_bb = next_lenchk_bb;
      unsigned char c;

      if (cur_lenchk_bb) {

        IRBuilder<> cur_lenchk_IRB(&*(cur_lenchk_bb->getFirstInsertionPt()));
        Value      *icmp = cur_lenchk_IRB.CreateICmpEQ(
                 sizedValue, ConstantInt::get(sizedValue->getType(), i));
        cur_lenchk_IRB.CreateCondBr(icmp, end_bb, cur_cmp_bb);
        cur_lenchk_bb->getTerminator()->eraseFromParent();

        PN->addIncoming(ConstantInt::get(Int32Ty, 0), cur_lenchk_bb);

      }

      if (isCaseInsensitive)
        c = (unsigned char)(tolower((int)ConstStr[i]) & 0xff);
      else
        c = (unsigned char)ConstStr[i];

      IRBuilder<> cur_cmp_IRB(&*(cur_cmp_bb->getFirstInsertionPt()));

      Value *v = ConstantInt::get(Int64Ty, i);
      Value *ele = cur_cmp_IRB.CreateInBoundsGEP(
#if LLVM_VERSION_MAJOR >= 14
          Int8Ty,
#endif
          VarStr, v, "empty");
      Value *load = cur_cmp_IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
          Int8Ty,
#endif
          ele);

      if (isCaseInsensitive) {

        // load >= 'A' && load <= 'Z' ? load | 0x020 : load
        load = cur_cmp_IRB.CreateZExt(load, Int32Ty);
        std::vector<Value *> args;
        args.push_back(load);
        load = cur_cmp_IRB.CreateCall(tolowerFn, args);
        load = cur_cmp_IRB.CreateTrunc(load, Int8Ty);

      }

      Value *isub;
      if (HasStr1)
        isub = cur_cmp_IRB.CreateSub(ConstantInt::get(Int8Ty, c), load);
      else
        isub = cur_cmp_IRB.CreateSub(load, ConstantInt::get(Int8Ty, c));

      Value *sext = cur_cmp_IRB.CreateSExt(isub, Int32Ty);
      PN->addIncoming(sext, cur_cmp_bb);

      if (i < unrollLen - 1) {

        if (cur_lenchk_bb) {

          next_lenchk_bb =
              BasicBlock::Create(C, "len_check", end_bb->getParent(), end_bb);
          BranchInst::Create(end_bb, next_lenchk_bb);

        }

        next_cmp_bb =
            BasicBlock::Create(C, "cmp_added", end_bb->getParent(), end_bb);
        BranchInst::Create(end_bb, next_cmp_bb);

        Value *icmp =
            cur_cmp_IRB.CreateICmpEQ(isub, ConstantInt::get(Int8Ty, 0));
        cur_cmp_IRB.CreateCondBr(
            icmp, next_lenchk_bb ? next_lenchk_bb : next_cmp_bb, end_bb);
        cur_cmp_bb->getTerminator()->eraseFromParent();

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

#if LLVM_MAJOR >= 11                                /* use new pass manager */
PreservedAnalyses CompareTransform::run(Module &M, ModuleAnalysisManager &MAM) {

#else
bool CompareTransform::runOnModule(Module &M) {

#endif

  if ((isatty(2) && getenv("AFL_QUIET") == NULL) || getenv("AFL_DEBUG") != NULL)
    printf(
        "Running compare-transform-pass by laf.intel@gmail.com, extended by "
        "heiko@hexco.de\n");
  else
    be_quiet = 1;

#if LLVM_MAJOR >= 11                                /* use new pass manager */
  auto PA = PreservedAnalyses::all();
#endif

  transformCmps(M, true, true, true, true, true);
  verifyModule(M);

#if LLVM_MAJOR >= 11                                /* use new pass manager */
                     /*  if (modified) {
                   
                         PA.abandon<XX_Manager>();
                   
                       }*/

  return PA;
#else
  return true;
#endif

}

#if LLVM_MAJOR < 11                                 /* use old pass manager */
static void registerCompTransPass(const PassManagerBuilder &,
                                  legacy::PassManagerBase &PM) {

  auto p = new CompareTransform();
  PM.add(p);

}

static RegisterStandardPasses RegisterCompTransPass(
    PassManagerBuilder::EP_OptimizerLast, registerCompTransPass);

static RegisterStandardPasses RegisterCompTransPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerCompTransPass);

  #if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterCompTransPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast, registerCompTransPass);
  #endif
#endif

