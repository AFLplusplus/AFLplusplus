#ifndef LIBAFL_COMMON_LLVM_H
#define LIBAFL_COMMON_LLVM_H

#include <stdio.h>
#include <stdlib.h>

#include "llvm/Config/llvm-config.h"
#if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 5
typedef long double max_align_t;
#endif

#if LLVM_VERSION_MAJOR >= 7                         /* use new pass manager */
// #define USE_NEW_PM 1
#endif

/* #if LLVM_VERSION_STRING >= "4.0.1" */
#if LLVM_VERSION_MAJOR > 4 || \
    (LLVM_VERSION_MAJOR == 4 && LLVM_VERSION_PATCH >= 1)
  #define HAVE_VECTOR_INTRINSICS 1
#endif

#if LLVM_VERSION_MAJOR >= 16
  #include <optional>
constexpr std::nullopt_t None = std::nullopt;
#endif

#ifdef USE_NEW_PM
  #include "llvm/Passes/PassPlugin.h"
  #include "llvm/Passes/PassBuilder.h"
  #include "llvm/IR/PassManager.h"
#else
  #include "llvm/IR/LegacyPassManager.h"
  #include "llvm/Transforms/IPO/PassManagerBuilder.h"
#endif

#include "llvm/IR/Function.h"

#define FATAL(...)                          \
  do {                                      \
                                            \
    fprintf(stderr, "FATAL: " __VA_ARGS__); \
    exit(1);                                \
                                            \
  } while (0)

static uint32_t RandBelow(uint32_t max) {

  return (uint32_t)rand() % (max);

}

/* needed up to 3.9.0 */
#if LLVM_VERSION_MAJOR == 3 && \
    (LLVM_VERSION_MINOR < 9 || \
     (LLVM_VERSION_MINOR == 9 && LLVM_VERSION_PATCH < 1))
static uint64_t PowerOf2Ceil(unsigned in) {

  uint64_t in64 = in - 1;
  in64 |= (in64 >> 1);
  in64 |= (in64 >> 2);
  in64 |= (in64 >> 4);
  in64 |= (in64 >> 8);
  in64 |= (in64 >> 16);
  in64 |= (in64 >> 32);
  return in64 + 1;

}

#endif

/* Function that we never instrument or analyze */
/* Note: this ignore check is also called in isInInstrumentList() */
static inline bool isIgnoreFunction(const llvm::Function *F) {

  // Starting from "LLVMFuzzer" these are functions used in libfuzzer based
  // fuzzing campaign installations, e.g. oss-fuzz

  static constexpr const char *ignoreList[] = {

      "asan.",
      "llvm.",
      "sancov.",
      "__ubsan",
      "ign.",
      "__afl",
      "_fini",
      "__libc_",
      "__asan",
      "__msan",
      "__cmplog",
      "__sancov",
      "__san",
      "__cxx_",
      "__decide_deferred",
      "_GLOBAL",
      "_ZZN6__asan",
      "_ZZN6__lsan",
      "msan.",
      "LLVMFuzzerM",
      "LLVMFuzzerC",
      "LLVMFuzzerI",
      "maybe_duplicate_stderr",
      "discard_output",
      "close_stdout",
      "dup_and_close_stderr",
      "maybe_close_fd_mask",
      "ExecuteFilesOnyByOne"

  };

  for (auto const &ignoreListFunc : ignoreList) {

#if LLVM_VERSION_MAJOR >= 18
    if (F->getName().starts_with(ignoreListFunc)) { return true; }
#else
    if (F->getName().startswith(ignoreListFunc)) { return true; }
#endif

  }

  static constexpr const char *ignoreSubstringList[] = {

      "__asan",     "__msan",     "__ubsan",   "__lsan",
      "__san",      "__sanitize", "_GLOBAL__", "DebugCounter",
      "DwarfDebug", "DebugLoc"

  };

  for (auto const &ignoreListFunc : ignoreSubstringList) {

    // hexcoder: F->getName().contains() not avaiilable in llvm 3.8.0
    if (llvm::StringRef::npos != F->getName().find(ignoreListFunc)) {

      return true;

    }

  }

  return false;

}

#endif  // LIBAFL_COMMON_LLVM_H

