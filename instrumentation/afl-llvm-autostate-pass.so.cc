/*
   american fuzzy lop++ - part of the AFL++ project
   ------------------------------------------------

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

/*
   Automatic state context, AFL_LLVM_AUTOSTATE
   -------------------------------------------

   Finds the variables a program uses as a state machine and reports their
   values to the runtime, so the situation the target is in perturbs the edge
   hash without anybody annotating the source.

   A variable qualifies when the value loaded out of it is compared against at
   least AFL_AUTOSTATE_MIN_CONSTS distinct integer constants, counting switch
   cases, and it is narrow enough to be an enum rather than a payload. Slots are
   addressed by a hash of the variable's name, or of the struct type name plus
   the field index, so the same field gets the same slot in every translation
   unit.

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <map>
#include <set>
#include <string>

#include "llvm/Passes/PassBuilder.h"
#if defined(__has_include) && __has_include("llvm/Plugins/PassPlugin.h")
  #include "llvm/Plugins/PassPlugin.h"
#else
  #include "llvm/Passes/PassPlugin.h"
#endif
#include "llvm/IR/PassManager.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Support/raw_ostream.h"

#include "afl-llvm-common.h"

using namespace llvm;

#define AUTOSTATE_SLOTS 256U

namespace {

class AFLAutoState : public PassInfoMixin<AFLAutoState> {

 public:
  AFLAutoState() {

    initInstrumentList();

  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

 private:
  bool keyOf(Value *ptr, Type *accessTy, std::string &key, unsigned &width);
  void collect(Function &F);
  static uint32_t slotOf(const std::string &key);

  std::map<std::string, std::set<uint64_t>> consts;
  std::map<std::string, std::set<uint64_t>> stored;
  std::map<std::string, uint64_t>           masks;
  std::map<std::string, std::string>        bases;
  std::map<std::string, unsigned>           widths;
  const DataLayout                         *dl = nullptr;
  unsigned                                  min_consts = 3;
  unsigned                                  min_stores = 0;
  unsigned                                  max_width = 32;

};

}  // namespace

/* A stable name for the storage a pointer refers to: a global by its own name,
   a struct field by its type name and index. Anything else is skipped, because
   an alloca or a bare pointer cannot be matched up across translation units. */

bool AFLAutoState::keyOf(Value *ptr, Type *accessTy, std::string &key,
                         unsigned &width) {

  if (!accessTy || !accessTy->isIntegerTy()) { return false; }
  width = accessTy->getIntegerBitWidth();

  Value *raw = ptr->stripPointerCasts();

  /* A struct field reached through a GEP is named by its type and index, which
     is the same in every translation unit that includes the header. */

  if (auto *GEP = dyn_cast<GetElementPtrInst>(raw)) {

    Type *ST = GEP->getSourceElementType();

    if (ST->isStructTy() && cast<StructType>(ST)->hasName() &&
        GEP->getNumIndices() >= 2) {

      if (auto *last = dyn_cast<ConstantInt>(
              GEP->getOperand(GEP->getNumOperands() - 1))) {

        key = "f:" + cast<StructType>(ST)->getName().str() + ":" +
              std::to_string(last->getZExtValue());
        return true;

      }

    }

  }

  /* Otherwise fall back to the underlying object plus a byte offset, which is
     what a bitfield at the base of a global struct looks like once clang has
     dropped the zero-index GEP. */

  APInt  off(dl->getIndexTypeSizeInBits(raw->getType()), 0);
  Value *base = raw->stripAndAccumulateConstantOffsets(*dl, off, true);

  if (auto *GV = dyn_cast<GlobalVariable>(base)) {

    if (GV->isConstant()) { return false; }
    if (GV->getName().starts_with("__afl") ||
        GV->getName().starts_with("llvm.")) {

      return false;

    }

    key = "g:" + GV->getName().str() + "+" + std::to_string(off.getZExtValue());
    return true;

  }

  return false;

}

uint32_t AFLAutoState::slotOf(const std::string &key) {

  uint32_t h = 0x811c9dc5U;

  for (char c : key) {

    h ^= (uint8_t)c;
    h *= 0x01000193U;

  }

  return h % AUTOSTATE_SLOTS;

}

/* Evidence gathering: which constants does the value loaded out of a candidate
   get compared against. One level of trunc/and/lshr is followed, because a
   bitfield is loaded wide and then masked. */

static void walkConsts(Value *root, std::set<uint64_t> &out) {

  std::set<Value *>    seen;
  std::vector<Value *> work;

  seen.insert(root);
  work.push_back(root);

  while (!work.empty()) {

    Value *cur = work.back();
    work.pop_back();
    if (seen.size() > 64) { break; }

    for (auto *U : cur->users()) {

      if (auto *IC = dyn_cast<ICmpInst>(U)) {

        for (unsigned o = 0; o < 2; ++o) {

          if (auto *CI = dyn_cast<ConstantInt>(IC->getOperand(o))) {

            out.insert(CI->getZExtValue());

          }

        }

        continue;

      }

      if (auto *SW = dyn_cast<SwitchInst>(U)) {

        for (auto Case : SW->cases()) {

          out.insert(Case.getCaseValue()->getZExtValue());

        }

        continue;

      }

      bool pass_through = isa<TruncInst>(U) || isa<ZExtInst>(U) ||
                          isa<SExtInst>(U) || isa<PHINode>(U);

      if (auto *BO = dyn_cast<BinaryOperator>(U)) {

        switch (BO->getOpcode()) {

          case Instruction::LShr:
          case Instruction::AShr:
          case Instruction::Shl:
          case Instruction::Or:
            pass_through = true;
            break;
          default:
            break;

        }

      }

      if (pass_through && !seen.count(U)) {

        seen.insert(U);
        work.push_back(U);

      }

    }

  }

}

/* One storage unit can hold several bitfields, and a load of it feeds a
   separate `and` for each. Keying by (struct, field) alone therefore merges
   them, and the narrowest mask in the chain is not necessarily this field's -
   picking it collapsed OpenSSL's 3-bit channel state onto one bit. So a state
   variable is (struct, field, mask), and each mask is tracked separately. */

void AFLAutoState::collect(Function &F) {

  for (auto &BB : F) {

    for (auto &I : BB) {

      if (auto *SI = dyn_cast<StoreInst>(&I)) {

        std::string skey;
        unsigned    swidth = 0;

        if (keyOf(SI->getPointerOperand(), SI->getValueOperand()->getType(),
                  skey, swidth)) {

          if (auto *CI = dyn_cast<ConstantInt>(SI->getValueOperand())) {

            stored[skey].insert(CI->getZExtValue());

          }

        }

        continue;

      }

      auto *LD = dyn_cast<LoadInst>(&I);
      if (!LD) { continue; }

      std::string base;
      unsigned    width = 0;
      if (!keyOf(LD->getPointerOperand(), LD->getType(), base, width)) {

        continue;

      }

      /* Collect the field extractors: every `and` with a constant mask
         reachable from this load through width and shift operations. */

      std::set<Value *>                         seen;
      std::vector<Value *>                      work;
      std::vector<std::pair<Value *, uint64_t>> fields;

      seen.insert(LD);
      work.push_back(LD);

      while (!work.empty()) {

        Value *cur = work.back();
        work.pop_back();
        if (seen.size() > 64) { break; }

        for (auto *U : cur->users()) {

          auto *BO = dyn_cast<BinaryOperator>(U);

          if (BO && BO->getOpcode() == Instruction::And) {

            for (unsigned o = 0; o < 2; ++o) {

              if (auto *CI = dyn_cast<ConstantInt>(BO->getOperand(o))) {

                fields.push_back({BO, CI->getZExtValue()});

              }

            }

            continue;

          }

          bool pass_through = isa<TruncInst>(U) || isa<ZExtInst>(U) ||
                              isa<SExtInst>(U) || isa<PHINode>(U);

          if (BO && (BO->getOpcode() == Instruction::LShr ||
                     BO->getOpcode() == Instruction::AShr ||
                     BO->getOpcode() == Instruction::Shl)) {

            pass_through = true;

          }

          if (pass_through && !seen.count(U)) {

            seen.insert(U);
            work.push_back(U);

          }

        }

      }

      if (fields.empty()) {

        /* Not a bitfield: the whole unit is the value. */
        if (width > max_width) { continue; }
        std::string key = base + ":m0";
        widths[key] = width;
        bases[key] = base;
        masks[key] = 0;
        walkConsts(LD, consts[key]);
        continue;

      }

      for (auto &f : fields) {

        unsigned bits = __builtin_popcountll(f.second);
        if (!bits || bits > max_width) { continue; }

        char buf[32];
        snprintf(buf, sizeof(buf), ":m%llx", (unsigned long long)f.second);
        std::string key = base + buf;

        widths[key] = bits;
        bases[key] = base;
        masks[key] = f.second;
        walkConsts(f.first, consts[key]);

      }

    }

  }

}

PreservedAnalyses AFLAutoState::run(Module &M, ModuleAnalysisManager &MAM) {

  (void)MAM;
  setvbuf(stdout, NULL, _IONBF, 0);

  if (getenv("AFL_QUIET")) { be_quiet = 1; }

  if (char *e = getenv("AFL_AUTOSTATE_MIN_CONSTS")) {

    int v = atoi(e);
    if (v >= 2) { min_consts = (unsigned)v; }

  }

  if (char *e = getenv("AFL_AUTOSTATE_MIN_STORES")) {

    int v = atoi(e);
    if (v >= 0) { min_stores = (unsigned)v; }

  }

  if (char *e = getenv("AFL_AUTOSTATE_MAX_WIDTH")) {

    int v = atoi(e);
    if (v >= 1) { max_width = (unsigned)v; }

  }

  /* Scope that applies to state detection only, independent of
     AFL_LLVM_ALLOWLIST, which also scopes coverage. A comma-separated list of
     substrings matched against the module's source path. Needed because
     "compared against three constants" is not specific enough in a crypto
     library: unscoped, hash and bignum contexts were picked up and stability
     fell to 29.97% against 99.81%. */

  if (char *scope = getenv("AFL_AUTOSTATE_SCOPE")) {

    std::string src = M.getSourceFileName();
    std::string want(scope);
    bool        hit = false;
    size_t      pos = 0;

    while (pos <= want.size()) {

      size_t      next = want.find(',', pos);
      std::string one = want.substr(
          pos, next == std::string::npos ? std::string::npos : next - pos);

      if (!one.empty() && src.find(one) != std::string::npos) {

        hit = true;
        break;

      }

      if (next == std::string::npos) { break; }
      pos = next + 1;

    }

    if (!hit) { return PreservedAnalyses::all(); }

  }

  dl = &M.getDataLayout();

  LLVMContext   &C = M.getContext();
  Type          *VoidTy = Type::getVoidTy(C);
  IntegerType   *Int32Ty = IntegerType::getInt32Ty(C);
  FunctionType  *FT = FunctionType::get(VoidTy, {Int32Ty, Int32Ty}, false);
  FunctionCallee Set = M.getOrInsertFunction("afl_autostate_set", FT);

  for (auto &F : M) {

    if (F.isDeclaration() || !isInInstrumentList(&F, MNAME)) { continue; }
    collect(F);

  }

  std::set<std::string> chosen;

  /* Compared against constants is not enough on its own: a hash context field
     is compared against constants too, and it is written on every update with a
     computed value. A state machine assigns named constants, so require that
     the stores are constant as well. Without this the situation changes
     mid-execution in ways that do not reproduce - measured at 29.97% stability
     against 99.81% on the same target. */

  for (auto &kv : consts) {

    if (kv.second.size() < min_consts) { continue; }
    if (min_stores && stored[bases[kv.first]].size() < min_stores) { continue; }
    chosen.insert(kv.first);

  }

  std::map<std::string, std::vector<std::string>> by_base;

  for (auto &k : chosen) {

    by_base[bases[k]].push_back(k);

  }

  if (chosen.empty()) {

    if (!be_quiet && getenv("AFL_DEBUG")) {

      printf("autostate: no state variables found in this module\n");

    }

    return PreservedAnalyses::all();

  }

  unsigned stores = 0;

  for (auto &F : M) {

    if (F.isDeclaration() || !isInInstrumentList(&F, MNAME)) { continue; }

    std::vector<StoreInst *> todo;

    for (auto &BB : F) {

      for (auto &I : BB) {

        auto *SI = dyn_cast<StoreInst>(&I);
        if (!SI) { continue; }
        std::string base;
        unsigned    width = 0;
        if (!keyOf(SI->getPointerOperand(), SI->getValueOperand()->getType(),
                   base, width)) {

          continue;

        }

        if (!SI->getValueOperand()->getType()->isIntegerTy()) { continue; }
        if (!by_base.count(base)) { continue; }
        todo.push_back(SI);

      }

    }

    for (auto *SI : todo) {

      std::string base;
      unsigned    width = 0;
      keyOf(SI->getPointerOperand(), SI->getValueOperand()->getType(), base,
            width);

      IRBuilder<> IRB(SI->getNextNode());

      /* One call per field held in this storage unit. A bitfield store writes
         the whole unit, so the field has to be masked back out or the reported
         situation carries every other bit packed beside it - unmasked,
         OpenSSL's 3-bit channel state arrived as a 64-bit word and stability
         fell to 1.39%. */

      for (auto &key : by_base[base]) {

        Value *V = SI->getValueOperand();
        Type  *VT = V->getType();

        if (masks[key]) {

          V = IRB.CreateAnd(V, ConstantInt::get(VT, masks[key]));

        }

        if (V->getType() != Int32Ty) { V = IRB.CreateZExtOrTrunc(V, Int32Ty); }

        IRB.CreateCall(Set, {ConstantInt::get(Int32Ty, slotOf(key)), V});
        ++stores;

      }

    }

  }

  if (!be_quiet || getenv("AFL_AUTOSTATE_VERBOSE")) {

    printf("autostate: %u state variables, %u stores instrumented\n",
           (unsigned)chosen.size(), stores);

    if (getenv("AFL_DEBUG") || getenv("AFL_AUTOSTATE_VERBOSE")) {

      for (auto &k : chosen) {

        printf("    %-52s %u consts, %u stored, mask %#llx, slot %u\n",
               k.c_str(), (unsigned)consts[k].size(),
               (unsigned)stored[k].size(),
               (unsigned long long)(masks.count(k) ? masks[k] : 0), slotOf(k));

      }

    }

  }

  return PreservedAnalyses::none();

}

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "AFLAutoState", "v0.1", [](PassBuilder &PB) {

            /* Pipeline start, not optimizer last: clang canonicalises struct
               field accesses into byte offsets on i8 early in the optimiser,
               which erases the type a stable slot name needs. */

            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(AFLAutoState());

                });

          }};

}

