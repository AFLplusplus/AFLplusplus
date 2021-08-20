/*
   american fuzzy lop++ - LLVM LTO instrumentation pass
   ----------------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-lto.

 */

#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include <list>
#include <string>
#include <fstream>
#include <set>

#include "llvm/Config/llvm-config.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Pass.h"
#include "llvm/IR/Constants.h"

#include "afl-llvm-common.h"

#ifndef O_DSYNC
  #define O_DSYNC O_SYNC
#endif

using namespace llvm;

namespace {

class AFLdict2filePass : public ModulePass {

 public:
  static char ID;

  AFLdict2filePass() : ModulePass(ID) {

    if (getenv("AFL_DEBUG")) debug = 1;

  }

  bool runOnModule(Module &M) override;

};

}  // namespace

void dict2file(int fd, u8 *mem, u32 len) {

  u32  i, j, binary = 0;
  char line[MAX_AUTO_EXTRA * 8], tmp[8];

  strcpy(line, "\"");
  j = 1;
  for (i = 0; i < len; i++) {

    if (isprint(mem[i]) && mem[i] != '\\' && mem[i] != '"') {

      line[j++] = mem[i];

    } else {

      if (i + 1 != len || mem[i] != 0 || binary || len == 4 || len == 8) {

        line[j] = 0;
        sprintf(tmp, "\\x%02x", (u8)mem[i]);
        strcat(line, tmp);
        j = strlen(line);

      }

      binary = 1;

    }

  }

  line[j] = 0;
  strcat(line, "\"\n");
  if (write(fd, line, strlen(line)) <= 0)
    PFATAL("Could not write to dictionary file");
  fsync(fd);

  if (!be_quiet) fprintf(stderr, "Found dictionary token: %s", line);

}

bool AFLdict2filePass::runOnModule(Module &M) {

  DenseMap<Value *, std::string *> valueMap;
  char *                           ptr;
  int                              fd, found = 0;

  /* Show a banner */
  setvbuf(stdout, NULL, _IONBF, 0);

  if ((isatty(2) && !getenv("AFL_QUIET")) || debug) {

    SAYF(cCYA "afl-llvm-dict2file" VERSION cRST
              " by Marc \"vanHauser\" Heuse <mh@mh-sec.de>\n");

  } else

    be_quiet = 1;

  scanForDangerousFunctions(&M);

  ptr = getenv("AFL_LLVM_DICT2FILE");

  if (!ptr || *ptr != '/')
    FATAL("AFL_LLVM_DICT2FILE is not set to an absolute path: %s", ptr);

  if ((fd = open(ptr, O_WRONLY | O_APPEND | O_CREAT | O_DSYNC, 0644)) < 0)
    PFATAL("Could not open/create %s.", ptr);

  /* Instrument all the things! */

  for (auto &F : M) {

    if (isIgnoreFunction(&F)) continue;
    if (!isInInstrumentList(&F) || !F.size()) { continue; }

    /*  Some implementation notes.
     *
     *  We try to handle 3 cases:
     *  - memcmp("foo", arg, 3) <- literal string
     *  - static char globalvar[] = "foo";
     *    memcmp(globalvar, arg, 3) <- global variable
     *  - char localvar[] = "foo";
     *    memcmp(locallvar, arg, 3) <- local variable
     *
     *  The local variable case is the hardest. We can only detect that
     *  case if there is no reassignment or change in the variable.
     *  And it might not work across llvm version.
     *  What we do is hooking the initializer function for local variables
     *  (llvm.memcpy.p0i8.p0i8.i64) and note the string and the assigned
     *  variable. And if that variable is then used in a compare function
     *  we use that noted string.
     *  This seems not to work for tokens that have a size <= 4 :-(
     *
     *  - if the compared length is smaller than the string length we
     *    save the full string. This is likely better for fuzzing but
     *    might be wrong in a few cases depending on optimizers
     *
     *  - not using StringRef because there is a bug in the llvm 11
     *    checkout I am using which sometimes points to wrong strings
     *
     *  Over and out. Took me a full day. damn. mh/vh
     */

    for (auto &BB : F) {

      for (auto &IN : BB) {

        CallInst *callInst = nullptr;
        CmpInst * cmpInst = nullptr;

        if ((cmpInst = dyn_cast<CmpInst>(&IN))) {

          Value *      op = cmpInst->getOperand(1);
          ConstantInt *ilen = dyn_cast<ConstantInt>(op);

          /* We skip > 64 bit integers. why? first because their value is
             difficult to obtain, and second because clang does not support
             literals > 64 bit (as of llvm 12) */

          if (ilen && ilen->uge(0xffffffffffffffff) == false) {

            u64 val2 = 0, val = ilen->getZExtValue();
            u32 len = 0;
            if (val > 0x10000 && val < 0xffffffff) len = 4;
            if (val > 0x100000001 && val < 0xffffffffffffffff) len = 8;

            if (len) {

              auto c = cmpInst->getPredicate();

              switch (c) {

                case CmpInst::FCMP_OGT:  // fall through
                case CmpInst::FCMP_OLE:  // fall through
                case CmpInst::ICMP_SLE:  // fall through
                case CmpInst::ICMP_SGT:

                  // signed comparison and it is a negative constant
                  if ((len == 4 && (val & 80000000)) ||
                      (len == 8 && (val & 8000000000000000))) {

                    if ((val & 0xffff) != 1) val2 = val - 1;
                    break;

                  }

                  // fall through

                case CmpInst::FCMP_UGT:  // fall through
                case CmpInst::FCMP_ULE:  // fall through
                case CmpInst::ICMP_UGT:  // fall through
                case CmpInst::ICMP_ULE:
                  if ((val & 0xffff) != 0xfffe) val2 = val + 1;
                  break;

                case CmpInst::FCMP_OLT:  // fall through
                case CmpInst::FCMP_OGE:  // fall through
                case CmpInst::ICMP_SLT:  // fall through
                case CmpInst::ICMP_SGE:

                  // signed comparison and it is a negative constant
                  if ((len == 4 && (val & 80000000)) ||
                      (len == 8 && (val & 8000000000000000))) {

                    if ((val & 0xffff) != 1) val2 = val - 1;
                    break;

                  }

                  // fall through

                case CmpInst::FCMP_ULT:  // fall through
                case CmpInst::FCMP_UGE:  // fall through
                case CmpInst::ICMP_ULT:  // fall through
                case CmpInst::ICMP_UGE:
                  if ((val & 0xffff) != 1) val2 = val - 1;
                  break;

                default:
                  val2 = 0;

              }

              dict2file(fd, (u8 *)&val, len);
              found++;
              if (val2) {

                dict2file(fd, (u8 *)&val2, len);
                found++;

              }

            }

          }

        }

        if ((callInst = dyn_cast<CallInst>(&IN))) {

          bool   isStrcmp = true;
          bool   isMemcmp = true;
          bool   isStrncmp = true;
          bool   isStrcasecmp = true;
          bool   isStrncasecmp = true;
          bool   isIntMemcpy = true;
          bool   isStdString = true;
          bool   isStrstr = true;
          bool   addedNull = false;
          size_t optLen = 0;

          Function *Callee = callInst->getCalledFunction();
          if (!Callee) continue;
          if (callInst->getCallingConv() != llvm::CallingConv::C) continue;
          std::string FuncName = Callee->getName().str();
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
          isStrstr &= (!FuncName.compare("strstr") ||
                       !FuncName.compare("g_strstr_len") ||
                       !FuncName.compare("ap_strcasestr") ||
                       !FuncName.compare("xmlStrstr") ||
                       !FuncName.compare("xmlStrcasestr") ||
                       !FuncName.compare("g_str_has_prefix") ||
                       !FuncName.compare("g_str_has_suffix"));
          isIntMemcpy &= !FuncName.compare("llvm.memcpy.p0i8.p0i8.i64");
          isStdString &= ((FuncName.find("basic_string") != std::string::npos &&
                           FuncName.find("compare") != std::string::npos) ||
                          (FuncName.find("basic_string") != std::string::npos &&
                           FuncName.find("find") != std::string::npos));

          if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
              !isStrncasecmp && !isIntMemcpy && !isStdString && !isStrstr)
            continue;

          /* Verify the strcmp/memcmp/strncmp/strcasecmp/strncasecmp function
           * prototype */
          FunctionType *FT = Callee->getFunctionType();

          isStrstr &=
              FT->getNumParams() == 2 &&
              FT->getParamType(0) == FT->getParamType(1) &&
              FT->getParamType(0) == IntegerType::getInt8PtrTy(M.getContext());
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
          isStdString &= FT->getNumParams() >= 2 &&
                         FT->getParamType(0)->isPointerTy() &&
                         FT->getParamType(1)->isPointerTy();

          if (!isStrcmp && !isMemcmp && !isStrncmp && !isStrcasecmp &&
              !isStrncasecmp && !isIntMemcpy && !isStdString && !isStrstr)
            continue;

          /* is a str{n,}{case,}cmp/memcmp, check if we have
           * str{case,}cmp(x, "const") or str{case,}cmp("const", x)
           * strn{case,}cmp(x, "const", ..) or strn{case,}cmp("const", x, ..)
           * memcmp(x, "const", ..) or memcmp("const", x, ..) */
          Value *Str1P = callInst->getArgOperand(0),
                *Str2P = callInst->getArgOperand(1);
          std::string Str1, Str2;
          StringRef   TmpStr;
          bool        HasStr1;
          getConstantStringInfo(Str1P, TmpStr);

          if (isStrstr || TmpStr.empty()) {

            HasStr1 = false;

          } else {

            HasStr1 = true;
            Str1 = TmpStr.str();

          }

          bool HasStr2;
          getConstantStringInfo(Str2P, TmpStr);
          if (TmpStr.empty()) {

            HasStr2 = false;

          } else {

            HasStr2 = true;
            Str2 = TmpStr.str();

          }

          if (debug)
            fprintf(stderr, "F:%s %p(%s)->\"%s\"(%s) %p(%s)->\"%s\"(%s)\n",
                    FuncName.c_str(), (void *)Str1P,
                    Str1P->getName().str().c_str(), Str1.c_str(),
                    HasStr1 == true ? "true" : "false", (void *)Str2P,
                    Str2P->getName().str().c_str(), Str2.c_str(),
                    HasStr2 == true ? "true" : "false");

          // we handle the 2nd parameter first because of llvm memcpy
          if (!HasStr2) {

            auto *Ptr = dyn_cast<ConstantExpr>(Str2P);
            if (Ptr && Ptr->isGEPWithNoNotionalOverIndexing()) {

              if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {

                if (Var->hasInitializer()) {

                  if (auto *Array =
                          dyn_cast<ConstantDataArray>(Var->getInitializer())) {

                    HasStr2 = true;
                    Str2 = Array->getRawDataValues().str();

                  }

                }

              }

            }

          }

          // for the internal memcpy routine we only care for the second
          // parameter and are not reporting anything.
          if (isIntMemcpy == true) {

            if (HasStr2 == true) {

              Value *      op2 = callInst->getArgOperand(2);
              ConstantInt *ilen = dyn_cast<ConstantInt>(op2);
              if (ilen) {

                uint64_t literalLength = Str2.length();
                uint64_t optLength = ilen->getZExtValue();
                if (optLength > literalLength + 1) {

                  optLength = Str2.length() + 1;

                }

                if (literalLength + 1 == optLength) {

                  Str2.append("\0", 1);  // add null byte

                }

                if (optLength > Str2.length()) { optLength = Str2.length(); }

              }

              valueMap[Str1P] = new std::string(Str2);

              if (debug)
                fprintf(stderr, "Saved: %s for %p\n", Str2.c_str(),
                        (void *)Str1P);
              continue;

            }

            continue;

          }

          // Neither a literal nor a global variable?
          // maybe it is a local variable that we saved
          if (!HasStr2) {

            std::string *strng = valueMap[Str2P];
            if (strng && !strng->empty()) {

              Str2 = *strng;
              HasStr2 = true;
              if (debug)
                fprintf(stderr, "Filled2: %s for %p\n", strng->c_str(),
                        (void *)Str2P);

            }

          }

          if (!HasStr1) {

            auto Ptr = dyn_cast<ConstantExpr>(Str1P);

            if (Ptr && Ptr->isGEPWithNoNotionalOverIndexing()) {

              if (auto *Var = dyn_cast<GlobalVariable>(Ptr->getOperand(0))) {

                if (Var->hasInitializer()) {

                  if (auto *Array =
                          dyn_cast<ConstantDataArray>(Var->getInitializer())) {

                    HasStr1 = true;
                    Str1 = Array->getRawDataValues().str();

                  }

                }

              }

            }

          }

          // Neither a literal nor a global variable?
          // maybe it is a local variable that we saved
          if (!HasStr1) {

            std::string *strng = valueMap[Str1P];
            if (strng && !strng->empty()) {

              Str1 = *strng;
              HasStr1 = true;
              if (debug)
                fprintf(stderr, "Filled1: %s for %p\n", strng->c_str(),
                        (void *)Str1P);

            }

          }

          /* handle cases of one string is const, one string is variable */
          if (!(HasStr1 ^ HasStr2)) continue;

          std::string thestring;

          if (HasStr1)
            thestring = Str1;
          else
            thestring = Str2;

          optLen = thestring.length();

          if (optLen < 2 || (optLen == 2 && !thestring[1])) { continue; }

          if (isMemcmp || isStrncmp || isStrncasecmp) {

            Value *      op2 = callInst->getArgOperand(2);
            ConstantInt *ilen = dyn_cast<ConstantInt>(op2);

            if (ilen) {

              uint64_t literalLength = optLen;
              optLen = ilen->getZExtValue();
              if (optLen > thestring.length() + 1) {

                optLen = thestring.length() + 1;

              }

              if (optLen < 2) { continue; }
              if (literalLength + 1 == optLen) {  // add null byte
                thestring.append("\0", 1);
                addedNull = true;

              }

            }

          }

          // add null byte if this is a string compare function and a null
          // was not already added
          if (!isMemcmp) {

            if (addedNull == false && thestring[optLen - 1] != '\0') {

              thestring.append("\0", 1);  // add null byte
              optLen++;

            }

            if (!isStdString) {

              // ensure we do not have garbage
              size_t offset = thestring.find('\0', 0);
              if (offset + 1 < optLen) optLen = offset + 1;
              thestring = thestring.substr(0, optLen);

            }

          }

          // we take the longer string, even if the compare was to a
          // shorter part. Note that depending on the optimizer of the
          // compiler this can be wrong, but it is more likely that this
          // is helping the fuzzer
          if (optLen != thestring.length()) optLen = thestring.length();
          if (optLen > MAX_AUTO_EXTRA) optLen = MAX_AUTO_EXTRA;
          if (optLen < 3)  // too short? skip
            continue;

          ptr = (char *)thestring.c_str();

          dict2file(fd, (u8 *)ptr, optLen);
          found++;

        }

      }

    }

  }

  close(fd);

  /* Say something nice. */

  if (!be_quiet) {

    if (!found)
      OKF("No entries for a dictionary found.");
    else
      OKF("Wrote %d entries to the dictionary file.\n", found);

  }

  return true;

}

char AFLdict2filePass::ID = 0;

static void registerAFLdict2filePass(const PassManagerBuilder &,
                                     legacy::PassManagerBase &PM) {

  PM.add(new AFLdict2filePass());

}

static RegisterPass<AFLdict2filePass> X("afl-dict2file",
                                        "afl++ dict2file instrumentation pass",
                                        false, false);

static RegisterStandardPasses RegisterAFLdict2filePass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLdict2filePass);

static RegisterStandardPasses RegisterAFLdict2filePass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLdict2filePass);

