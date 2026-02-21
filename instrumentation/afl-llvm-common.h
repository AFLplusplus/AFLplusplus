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

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"
#if LLVM_VERSION_MAJOR < 17
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif

#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/CFG.h"

#define MNAME M.getSourceFileName()
#define FMNAME F.getParent()->getSourceFileName()
#if LLVM_VERSION_MAJOR >= 16
// None becomes deprecated
// the standard std::nullopt_t is recommended instead
// from C++17 and onwards.
constexpr std::nullopt_t None = std::nullopt;
#endif

char *getBBName(const llvm::BasicBlock *BB);
bool  isIgnoreFunction(const llvm::Function *F);
void  initInstrumentList();
bool  isInInstrumentList(llvm::Function *F, std::string Filename);
unsigned long long int calculateCollisions(uint32_t edges);
void                   scanForDangerousFunctions(llvm::Module *M);
unsigned int           calcCyclomaticComplexity(llvm::Function *F);
bool                   isAflCovInterestingInstruction(llvm::Instruction &I);
bool                   isDecisionUse(const llvm::Value *Cond);
bool                   isExecCall(llvm::Instruction *IN);
std::pair<bool, bool>  detectIJONUsage(llvm::Module &M);
void createIJONEnabledGlobal(llvm::Module &M, llvm::Type *Int32Ty);
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

/* Load __afl_area_ptr once at function entry and return the loaded value.
   Creates a preamble basic block so later per-block instrumentation never
   sees or displaces this load.  The load is marked invariant because
   __afl_area_ptr is set once at process start and never changes.

   Callers should collect BlocksToInstrument before calling this so the
   preamble is excluded from instrumentation. */
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

  /* Move static allocas into the preamble so ASan keeps them function-wide. */
  for (auto *AI : StaticAllocas)
    AI->moveBefore(Load);

  return Load;

}

#endif

