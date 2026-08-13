/*
   american fuzzy lop++ - part of the AFL++ project
   ------------------------------------------------

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#ifndef __AFLLLVMCOMMON_H
#define __AFLLLVMCOMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <list>
#include <string>
#include <fstream>

#ifdef __has_include
  #if __has_include(<optional>)
    #include <optional>
  #endif
#endif

#include <sys/time.h>

#include "llvm/Config/llvm-config.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Value.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"
#if LLVM_VERSION_MAJOR < 17
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif

#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/CFG.h"

#define MNAME M.getSourceFileName()
#define FMNAME F.getParent()->getSourceFileName()
#if LLVM_VERSION_MAJOR >= 16
// None becomes deprecated
// the standard std::nullopt_t is recommended instead
// from C++17 and onwards.
constexpr std::nullopt_t None = std::nullopt;
#endif

enum class CompareObserverMode {

  CmpLog,
  ValueProfile,

};

CompareObserverMode getCompareObserverModeFromEnv();
inline bool         isValueProfileMode(CompareObserverMode mode) {

  return mode == CompareObserverMode::ValueProfile;

}

inline bool isMemcmpRoutineName(llvm::StringRef Name) {

  return Name == "memcmp" || Name == "bcmp" || Name == "CRYPTO_memcmp" ||
         Name == "OPENSSL_memcmp" || Name == "memcmp_const_time" ||
         Name == "memcmpct";

}

inline bool isStrcmpRoutineName(llvm::StringRef Name) {

  return Name == "strcmp" || Name == "xmlStrcmp" || Name == "xmlStrEqual" ||
         Name == "g_strcmp0" || Name == "curl_strequal" ||
         Name == "strcsequal" || Name == "g_str_has_prefix" ||
         Name == "g_str_has_suffix";

}

inline bool isStrcasecmpRoutineName(llvm::StringRef Name) {

  return Name == "strcasecmp" || Name == "stricmp" ||
         Name == "ap_cstr_casecmp" || Name == "apr_cstr_casecmp" ||
         Name == "OPENSSL_strcasecmp" || Name == "xmlStrcasecmp" ||
         Name == "g_strcasecmp" || Name == "g_ascii_strcasecmp" ||
         Name == "Curl_strcasecompare" || Name == "Curl_safe_strcasecompare" ||
         Name == "cmsstrcasecmp" || Name == "sqlite3_stricmp" ||
         Name == "sqlite3StrICmp";

}

inline bool isStrncmpRoutineName(llvm::StringRef Name) {

  return Name == "strncmp" || Name == "xmlStrncmp" || Name == "curl_strnequal";

}

inline bool isStrncasecmpRoutineName(llvm::StringRef Name) {

  return Name == "strncasecmp" || Name == "strnicmp" ||
         Name == "ap_cstr_casecmpn" || Name == "apr_cstr_casecmpn" ||
         Name == "OPENSSL_strncasecmp" || Name == "xmlStrncasecmp" ||
         Name == "g_ascii_strncasecmp" || Name == "Curl_strncasecompare" ||
         Name == "g_strncasecmp" || Name == "sqlite3_strnicmp";

}

inline bool isCompareResultRoutineName(llvm::StringRef Name) {

  return isMemcmpRoutineName(Name) || isStrcmpRoutineName(Name) ||
         isStrcasecmpRoutineName(Name) || isStrncmpRoutineName(Name) ||
         isStrncasecmpRoutineName(Name);

}

inline uint64_t mixValueProfileSiteToken(uint64_t value) {

  value ^= value >> 30;
  value *= 0xbf58476d1ce4e5b9ULL;
  value ^= value >> 27;
  value *= 0x94d049bb133111ebULL;
  return value ^ (value >> 31);

}

inline uint64_t updateValueProfileSiteHash(uint64_t hash, uint64_t value) {

  for (unsigned i = 0; i < 8; ++i) {

    hash ^= (uint8_t)value;
    hash *= 0x100000001b3ULL;
    value >>= 8;

  }

  return hash;

}

inline uint64_t updateValueProfileSiteHash(uint64_t        hash,
                                           llvm::StringRef value) {

  hash = updateValueProfileSiteHash(hash, (uint64_t)value.size());
  for (char byte : value) {

    hash ^= (uint8_t)byte;
    hash *= 0x100000001b3ULL;

  }

  return hash;

}

inline uint64_t hashValueProfileDebugLocation(const llvm::DILocation *Loc) {

  if (!Loc) { return 0; }

  uint64_t hash = 0xcbf29ce484222325ULL;
  for (const llvm::DILocation *At = Loc; At; At = At->getInlinedAt()) {

    hash = updateValueProfileSiteHash(hash, At->getDirectory());
    hash = updateValueProfileSiteHash(hash, At->getFilename());
    hash = updateValueProfileSiteHash(hash, At->getLine());
    hash = updateValueProfileSiteHash(hash, At->getColumn());
    hash = updateValueProfileSiteHash(hash, At->getDiscriminator());

  }

  return mixValueProfileSiteToken(hash);

}

inline uint64_t getValueProfileDebugSiteKey(const llvm::Instruction &I) {

  if (const llvm::DILocation *Loc = I.getDebugLoc()) {

    return hashValueProfileDebugLocation(Loc);

  }

  return 0ULL;

}

inline void getValueProfileCompileUnitIdentity(const llvm::Instruction &I,
                                               llvm::StringRef         &Dir,
                                               llvm::StringRef         &File) {

  if (const llvm::DISubprogram *SP = I.getFunction()->getSubprogram()) {

    if (const llvm::DICompileUnit *CU = SP->getUnit()) {

      if (const llvm::DIFile *CUFile = CU->getFile()) {

        Dir = CUFile->getDirectory();
        File = CUFile->getFilename();

      }

    }

    if (Dir.empty() && File.empty()) {

      if (const llvm::DIFile *SPFile = SP->getFile()) {

        Dir = SPFile->getDirectory();
        File = SPFile->getFilename();

      } else {

        Dir = SP->getDirectory();
        File = SP->getFilename();

      }

    }

  }

  if ((Dir.empty() && File.empty())) {

    const llvm::Module &M = *I.getModule();
    File = M.getSourceFileName();
    if (File.empty()) { File = M.getModuleIdentifier(); }

  }

}

inline uint64_t computeValueProfileSiteToken(const llvm::Instruction &I,
                                             uint64_t                 salt,
                                             uint64_t disambiguator,
                                             uint64_t subsite_index) {

  llvm::StringRef Dir;
  llvm::StringRef File;
  getValueProfileCompileUnitIdentity(I, Dir, File);

  const llvm::Module &M = *I.getModule();

  uint64_t hash = 0xcbf29ce484222325ULL;
  hash = updateValueProfileSiteHash(hash, salt);
  hash = updateValueProfileSiteHash(hash, Dir);
  hash = updateValueProfileSiteHash(hash, File);
  hash = updateValueProfileSiteHash(hash, M.getSourceFileName());
  hash = updateValueProfileSiteHash(hash, M.getModuleIdentifier());
  hash = updateValueProfileSiteHash(hash, I.getFunction()->getName());
  hash = updateValueProfileSiteHash(
      hash, hashValueProfileDebugLocation(I.getDebugLoc()));
  hash = updateValueProfileSiteHash(hash, disambiguator);
  hash = updateValueProfileSiteHash(hash, subsite_index);
  return mixValueProfileSiteToken(hash);

}

char *getBBName(const llvm::BasicBlock *BB);
bool  isIgnoreFunction(const llvm::Function *F);
void  initInstrumentList();
bool  isInInstrumentList(llvm::Function *F, std::string Filename);
bool  isInstrumentListActive(void);
unsigned long long int calculateCollisions(uint32_t edges);
void                   scanForDangerousFunctions(llvm::Module *M);
unsigned int           calcCyclomaticComplexity(llvm::Function *F);
bool                   isAflCovInterestingInstruction(llvm::Instruction &I);
bool                   isAflCovMinMaxIntrinsic(llvm::Instruction &I);
bool                   isAflCovMinMaxEnabled(void);
bool                   isAflCovVectorEnabled(void);
bool                   isAflCovFusedEnabled(void);
bool                   isDecisionUse(const llvm::Value *Cond);
bool                   isExecCall(llvm::Instruction *IN);
std::pair<bool, bool>  detectIJONUsage(llvm::Module &M);
void createIJONEnabledGlobal(llvm::Module &M, llvm::Type *Int32Ty);
void createC11EnabledGlobal(llvm::Module &M, llvm::Type *Int32Ty);
bool setupReachability(llvm::StringMap<uint32_t> &values, const char *passName);
uint32_t getReachabilityValue(const llvm::StringMap<uint32_t> &values,
                              const llvm::Function            &F);
void     instrumentReachability(llvm::Function &F, uint32_t value);
void     markInstrumentedMarker(llvm::Module &M, const char *marker_name);
llvm::GlobalVariable *getOrCreateExternalWeakPtrGlobal(llvm::Module &M,
                                                       llvm::Type   *ptr_ty,
                                                       const char   *name);
llvm::GlobalVariable *getOrCreateExternalPtrGlobal(llvm::Module &M,
                                                   llvm::Type   *ptr_ty,
                                                   const char   *name);
llvm::Value *createMapPtrNotNullGuard(llvm::IRBuilder<> &IRB, llvm::Module &M,
                                      llvm::GlobalVariable *map_ptr,
                                      llvm::Type           *ptr_ty);
llvm::GlobalVariable *createIJONStateGlobal(llvm::Module &M,
                                            llvm::Type   *Int32Ty,
                                            bool          uses_ijon_state);

#ifndef IS_EXTERN
  #define IS_EXTERN
#endif

IS_EXTERN int debug;
IS_EXTERN int be_quiet;

#undef IS_EXTERN

[[noreturn]] inline void release_assert_fail(const char *msg) {

  llvm::errs() << "AFL++ ERROR: " << msg << "\n";
  abort();

}

#define release_assert(cond, msg)              \
  do {                                         \
                                               \
    if (!(cond)) { release_assert_fail(msg); } \
                                               \
  } while (0)

/* LLVM 23 made BasicBlock::getTerminator() assert on non-well-formed
   blocks; getTerminatorOrNull() restores the prior nullable behavior. */
inline llvm::Instruction *aflTerminatorOrNull(llvm::BasicBlock *BB) {

#if LLVM_VERSION_MAJOR >= 23
  return BB->getTerminatorOrNull();
#else
  return BB->getTerminator();
#endif

}

/* Mark an instruction so sanitizer passes ignore it. */
inline void setNoSanitizeMetadata(llvm::Instruction *I) {

#if LLVM_VERSION_MAJOR >= 19
  I->setNoSanitizeMetadata();
#elif LLVM_VERSION_MAJOR >= 16
  I->setMetadata(llvm::LLVMContext::MD_nosanitize,
                 llvm::MDNode::get(I->getContext(), std::nullopt));
#else
  I->setMetadata(I->getModule()->getMDKindID("nosanitize"),
                 llvm::MDNode::get(I->getContext(), llvm::None));
#endif

}

/* Mark an instruction as synthetic AFL IR so later AFL coverage passes skip it
   when needed. */
inline void setAflSkipMetadata(llvm::Instruction *I) {

  I->setMetadata("afl.skip", llvm::MDNode::get(I->getContext(), {}));

}

/* Mark a synthetic basic block so AFL coverage passes can ignore it during
   block coverage injection. */
inline void markAflSyntheticBlock(llvm::BasicBlock *BB) {

  if (!BB) return;
  if (auto *TI = BB->getTerminator()) {

    setAflSkipMetadata(TI);
    setNoSanitizeMetadata(TI);

  }

}

/* Detect synthetic AFL basic blocks that should not get edge coverage. */
inline bool isAflSyntheticBlock(const llvm::BasicBlock *BB) {

  if (!BB) return false;
  if (const auto *TI = BB->getTerminator()) {

    return TI->getMetadata("afl.skip") != nullptr;

  }

  return false;

}

/* True when BB has at least one non-terminator instruction and every
   non-terminator, non-debug instruction carries afl.skip, i.e. the block holds
   only synthetic AFL code. The ">=1 instruction" guard keeps branch-only blocks
   instrumented. */
inline bool isFullyArtificialBlock(const llvm::BasicBlock *BB) {

  bool seen = false;
  for (const llvm::Instruction &I : *BB) {

    if (I.isTerminator() || I.isDebugOrPseudoInst()) continue;
    if (!I.getMetadata("afl.skip")) return false;
    seen = true;

  }

  return seen;

}

/* Load __afl_area_ptr once at function entry and return the loaded value.
   Creates a preamble basic block so later per-block instrumentation never
   sees or displaces this load.  The load is marked invariant because
   __afl_area_ptr is set once at process start and never changes.

   The preamble is marked synthetic so shouldInstrumentBlock() skips it even
   when block pruning is off - instrumenting it would insert a map access
   ahead of the load it depends on. */
inline llvm::Value *hoistMapPointerLoad(llvm::Function       &F,
                                        llvm::GlobalVariable *AFLMapPtr,
                                        llvm::Type           *PtrTy) {

  using namespace llvm;
  LLVMContext &Ctx = F.getContext();
  BasicBlock  *OldEntry = &F.getEntryBlock();

  /* Collect static allocas before the preamble demotes them (#2722). */
  SmallVector<AllocaInst *, 16> StaticAllocas;
  for (auto &I : *OldEntry) {

    if (auto *AI = dyn_cast<AllocaInst>(&I))
      if (AI->isStaticAlloca()) StaticAllocas.push_back(AI);

  }

  BasicBlock *Preamble = BasicBlock::Create(Ctx, "afl.entry", &F, OldEntry);

  IRBuilder<> IRB(Preamble);
  auto       *Load = IRB.CreateLoad(PtrTy, AFLMapPtr);
  setNoSanitizeMetadata(Load);
  Load->setMetadata(LLVMContext::MD_invariant_load, MDNode::get(Ctx, {}));
  IRB.CreateBr(OldEntry);
  markAflSyntheticBlock(Preamble);

  /* Move static allocas into the preamble so ASan keeps them function-wide. */
  for (auto *AI : StaticAllocas) {

#if LLVM_VERSION_MAJOR >= 20
    AI->moveBefore(Load->getIterator());
#else
    AI->moveBefore(Load);
#endif

  }

  return Load;

}

/* Load the per-exec VP enabled byte from a runtime-exported pointer and return
   `enabled != 0`. The byte load stays volatile because the fuzzer updates
   this shared-memory control byte between target executions and a
   persistent-mode child must observe it. The pointer load does not: it is
   only ever reassigned from inside the AFL runtime itself (shared-memory
   attach/detach, selective-coverage toggles), always through opaque
   external calls that already force a reload, so a plain load here is both
   correct and CSE-able (and for that same reason !invariant.load must not
   be added). */
inline llvm::Value *createValueProfileEnabledGuard(
    llvm::IRBuilder<> &IRB, llvm::GlobalVariable *vp_enabled_ptr,
    llvm::Type *PtrTy, llvm::Type *Int8Ty) {

  auto *EnabledBytePtr = IRB.CreateLoad(PtrTy, vp_enabled_ptr);
  setNoSanitizeMetadata(EnabledBytePtr);

  auto *EnabledValue = IRB.CreateLoad(Int8Ty, EnabledBytePtr);
  EnabledValue->setVolatile(true);
  setNoSanitizeMetadata(EnabledValue);

  auto *IsEnabled = llvm::cast<llvm::Instruction>(IRB.CreateICmpNE(
      EnabledValue,
      llvm::ConstantInt::get(llvm::cast<llvm::IntegerType>(Int8Ty), 0)));
  setNoSanitizeMetadata(IsEnabled);
  /* afl.skip keeps a later compare-observer pass from value-profiling this
     guard itself. The switch pass runs first, so without it every guarded
     switch site also emits a bogus 8-bit compare hook on the enabled byte. */
  setAflSkipMetadata(IsEnabled);
  return IsEnabled;

}

/* Value profiling is off unless the fuzzer switches it on, so the guarded hook
   block is cold: weight it so the enabled test falls through on the hot path
   and the call is laid out away from it. */
inline llvm::MDNode *createValueProfileGuardWeights(llvm::LLVMContext &Ctx) {

  return llvm::MDBuilder(Ctx).createBranchWeights(1, 1u << 20);

}

#endif

