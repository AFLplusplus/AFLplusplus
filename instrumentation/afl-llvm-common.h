#ifndef __AFLLLVMCOMMON_H
#define __AFLLLVMCOMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>

#include "llvm/Config/llvm-config.h"
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 5
typedef long double max_align_t;
#endif

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/DebugInfo.h"
  #include "llvm/IR/CFG.h"
#else
  #include "llvm/DebugInfo.h"
  #include "llvm/Support/CFG.h"
#endif

char *                 getBBName(const llvm::BasicBlock *BB);
bool                   isIgnoreFunction(const llvm::Function *F);
void                   initInstrumentList();
bool                   isInInstrumentList(llvm::Function *F);
unsigned long long int calculateCollisions(uint32_t edges);
void                   scanForDangerousFunctions(llvm::Module *M);

#ifndef IS_EXTERN
  #define IS_EXTERN
#endif

IS_EXTERN int debug;
IS_EXTERN int be_quiet;

#undef IS_EXTERN

#endif

