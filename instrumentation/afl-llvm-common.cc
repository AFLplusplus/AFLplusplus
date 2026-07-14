/*
   american fuzzy lop++ - part of the AFL++ project
   ------------------------------------------------

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <fnmatch.h>

#include <list>
#include <set>
#include <string>
#include <fstream>
#include <cmath>

#include <llvm/Support/raw_ostream.h>
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Instructions.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Demangle/Demangle.h"

#define IS_EXTERN extern
#include "afl-llvm-common.h"

using namespace llvm;

static std::list<std::string> allowListFiles;
static std::list<std::string> allowListFunctions;
static std::list<std::string> denyListFiles;
static std::list<std::string> denyListFunctions;
static std::set<std::string>  allowListFunctionsNoHash;
static std::set<std::string>  denyListFunctionsNoHash;

static std::string stripRustHash(const std::string &name) {

  const size_t tail = 20;
  if (name.size() > tail && name.back() == 'E' &&
      name.compare(name.size() - tail, 3, "17h") == 0) {

    bool hex = true;
    for (size_t i = name.size() - 17; i + 1 < name.size(); ++i) {

      char ch = name[i];
      if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) {

        hex = false;
        break;

      }

    }

    if (hex) return name.substr(0, name.size() - tail);

  }

  return name;

}

unsigned int calcCyclomaticComplexity(llvm::Function *F) {

  unsigned int numBlocks = 0;
  unsigned int numEdges = 0;
  unsigned int numCalls = 0;

  // Iterate through each basic block in the function
  for (BasicBlock &BB : *F) {

    // count all nodes == basic blocks
    numBlocks++;
    // Count the number of successors (outgoing edges)
    for (BasicBlock *Succ : successors(&BB)) {

      // count edges for CC
      numEdges++;
      (void)(Succ);

    }

    for (Instruction &I : BB) {

      // every call is also an edge, so we need to count the calls too
      if (isa<CallInst>(&I) || isa<InvokeInst>(&I)) {

        // Do not count llvm.* intrinsics (dbg, lifetime, etc.) as edges —
        // they are not real control-flow transfers.
        if (auto *CB = dyn_cast<CallBase>(&I)) {

          if (Function *Callee = CB->getCalledFunction()) {

            if (Callee->isIntrinsic()) continue;

          }

        }

        numCalls++;

      }

    }

  }

  // Cyclomatic Complexity V(G) = E - N + 2P
  // For a single function, P (number of connected components) is 1
  // Calls are considered to be an edge
  unsigned int CC = 2 + numCalls + numEdges - numBlocks;

  fprintf(stderr, "CyclomaticComplexity for %s: %u\n",
          F->getName().str().c_str(), CC);

  return CC;

}

/* Note that the caller needs to free returned value! Currently unused. */

char *getBBName(const llvm::BasicBlock *BB) {

  static char *name;

  if (!BB->getName().empty()) {

    name = strdup(BB->getName().str().c_str());
    return name;

  }

  std::string        Str;
  raw_string_ostream OS(Str);

  BB->printAsOperand(OS, false);
  name = strdup(OS.str().c_str());
  return name;

}

/* Function that we never instrument or analyze */
/* Note: this ignore check is also called in isInInstrumentList() */
bool isIgnoreFunction(const llvm::Function *F) {

  // Starting from "LLVMFuzzer" these are functions used in libfuzzer based
  // fuzzing campaign installations, e.g. oss-fuzz

  static constexpr const char *ignoreList[] = {

      "asan.", "llvm.", "sancov.", "__ubsan", "ign.", "__afl", "_fini",
      "__libc_", "__asan", "__msan", "__cmplog", "__sancov", "__san", "__lsan",
      "__cxx_", "__decide_deferred", "_GLOBAL", "_ZZN6__asan", "_ZZN6__lsan",
      "msan.", "LLVMFuzzerM", "LLVMFuzzerC", "LLVMFuzzerI",
      // LLVMFuzzerT(estOneInput is not in this list on purpose!
      "maybe_duplicate_stderr", "discard_output", "close_stdout",
      "dup_and_close_stderr", "maybe_close_fd_mask", "ExecuteFilesOnyByOne"

  };

  for (auto const &ignoreListFunc : ignoreList) {

#if LLVM_VERSION_MAJOR >= 19
    if (F->getName().starts_with(ignoreListFunc)) { return true; }
#else
    if (F->getName().startswith(ignoreListFunc)) { return true; }
#endif

  }

  static constexpr const char *ignoreSubstringList[] = {

      "__asan",     "__msan",       "__ubsan",    "__lsan",  "__san",
      "__sanitize", "DebugCounter", "DwarfDebug", "DebugLoc"

  };

  // This check is very sensitive, we must be sure to not include patterns
  // that are part of user-written C++ functions like the ones including
  // std::string as parameter (see #1927) as the mangled type is inserted in the
  // mangled name of the user-written function
  for (auto const &ignoreListFunc : ignoreSubstringList) {

    // hexcoder: F->getName().contains() not available in llvm 3.8.0
    if (StringRef::npos != F->getName().find(ignoreListFunc)) { return true; }

  }

  return false;

}

void initInstrumentList() {

  static int init = 0;
  if (init) return;
  init = 1;

  char *allowlist = getenv("AFL_LLVM_ALLOWLIST");
  if (!allowlist) allowlist = getenv("AFL_LLVM_INSTRUMENT_FILE");
  if (!allowlist) allowlist = getenv("AFL_LLVM_WHITELIST");
  char *denylist = getenv("AFL_LLVM_DENYLIST");
  if (!denylist) denylist = getenv("AFL_LLVM_BLOCKLIST");

  if (allowlist && denylist)
    FATAL(
        "You can only specify either AFL_LLVM_ALLOWLIST or AFL_LLVM_DENYLIST "
        "but not both!");

  if (allowlist) {

    std::string   line;
    std::ifstream fileStream;
    fileStream.open(allowlist);
    if (!fileStream) report_fatal_error("Unable to open AFL_LLVM_ALLOWLIST");
    getline(fileStream, line);
    bool first_entry = true;

    while (fileStream) {

      int         is_file = -1;
      std::size_t npos;
      std::string original_line = line;

      line.erase(std::remove_if(line.begin(), line.end(), ::isspace),
                 line.end());

      // remove # and following
      if ((npos = line.find("#")) != std::string::npos)
        line = line.substr(0, npos);

      if (first_entry && line.length() > 0) {

        first_entry = false;
        if (line == "src:*" || line == "source:*") {

          getline(fileStream, line);
          continue;

        }

      }

      if (line.compare(0, 4, "fun:") == 0) {

        is_file = 0;
        line = line.substr(4);

      } else if (line.compare(0, 9, "function:") == 0) {

        is_file = 0;
        line = line.substr(9);

      } else if (line.compare(0, 4, "src:") == 0) {

        is_file = 1;
        line = line.substr(4);

      } else if (line.compare(0, 7, "source:") == 0) {

        is_file = 1;
        line = line.substr(7);

      }

      if (is_file != 0 && line.find(":") != std::string::npos) {

        FATAL("invalid line in AFL_LLVM_ALLOWLIST: %s", original_line.c_str());

      }

      if (line.length() > 0) {

        // if the entry contains / or . it must be a file
        if (is_file == -1)
          if (line.find("/") != std::string::npos ||
              line.find(".") != std::string::npos)
            is_file = 1;
        // otherwise it is a function

        if (is_file == 1)
          allowListFiles.push_back(line);
        else {

          allowListFunctions.push_back(line);
          std::string nh = stripRustHash(line);
          if (nh != line) allowListFunctionsNoHash.insert(nh);

        }

      }

      getline(fileStream, line);

    }

    if (debug)
      DEBUGF("loaded allowlist with %zu file and %zu function entries\n",
             allowListFiles.size(), allowListFunctions.size());

  }

  if (denylist) {

    std::string   line;
    std::ifstream fileStream;
    fileStream.open(denylist);
    if (!fileStream) report_fatal_error("Unable to open AFL_LLVM_DENYLIST");
    getline(fileStream, line);

    while (fileStream) {

      int         is_file = -1;
      std::size_t npos;
      std::string original_line = line;

      line.erase(std::remove_if(line.begin(), line.end(), ::isspace),
                 line.end());

      // remove # and following
      if ((npos = line.find("#")) != std::string::npos)
        line = line.substr(0, npos);

      if (line.compare(0, 4, "fun:") == 0) {

        is_file = 0;
        line = line.substr(4);

      } else if (line.compare(0, 9, "function:") == 0) {

        is_file = 0;
        line = line.substr(9);

      } else if (line.compare(0, 4, "src:") == 0) {

        is_file = 1;
        line = line.substr(4);

      } else if (line.compare(0, 7, "source:") == 0) {

        is_file = 1;
        line = line.substr(7);

      }

      if (is_file != 0 && line.find(":") != std::string::npos) {

        FATAL("invalid line in AFL_LLVM_DENYLIST: %s", original_line.c_str());

      }

      if (line.length() > 0) {

        // if the entry contains / or . it must be a file
        if (is_file == -1)
          if (line.find("/") != std::string::npos ||
              line.find(".") != std::string::npos)
            is_file = 1;
        // otherwise it is a function

        if (is_file == 1)
          denyListFiles.push_back(line);
        else {

          denyListFunctions.push_back(line);
          std::string nh = stripRustHash(line);
          if (nh != line) denyListFunctionsNoHash.insert(nh);

        }

      }

      getline(fileStream, line);

    }

    if (debug)
      DEBUGF("loaded denylist with %zu file and %zu function entries\n",
             denyListFiles.size(), denyListFunctions.size());

  }

}

void scanForDangerousFunctions(llvm::Module *M) {

  if (!M) return;

  for (GlobalIFunc &IF : M->ifuncs()) {

    StringRef ifunc_name = IF.getName();
    Constant *r = IF.getResolver();
    if (r->getNumOperands() == 0) { continue; }
    StringRef r_name = cast<Function>(r->getOperand(0))->getName();
    if (!be_quiet)
      fprintf(stderr,
              "Note: Found an ifunc with name %s that points to resolver "
              "function %s, we will not instrument this, putting it into the "
              "block list.\n",
              ifunc_name.str().c_str(), r_name.str().c_str());
    denyListFunctions.push_back(r_name.str());

  }

  GlobalVariable *GV = M->getNamedGlobal("llvm.global_ctors");
  if (GV && !GV->isDeclaration() && !GV->hasLocalLinkage()) {

    ConstantArray *InitList = dyn_cast<ConstantArray>(GV->getInitializer());

    if (InitList) {

      for (unsigned i = 0, e = InitList->getNumOperands(); i != e; ++i) {

        if (ConstantStruct *CS =
                dyn_cast<ConstantStruct>(InitList->getOperand(i))) {

          if (CS->getNumOperands() >= 2) {

            // Skip null entries - these can appear when constructor functions
            // are removed by optimization passes (e.g., GlobalDCE) or during
            // LTO linking without the array being compacted.
            // See LLVM's CtorUtils.cpp which also uses continue for null
            // entries.
            if (CS->getOperand(1)->isNullValue()) continue;

            ConstantInt *CI = dyn_cast<ConstantInt>(CS->getOperand(0));
            int          Priority = CI ? CI->getSExtValue() : 0;

            Constant *FP = CS->getOperand(1);
            if (ConstantExpr *CE = dyn_cast<ConstantExpr>(FP))
              if (CE->isCast()) FP = CE->getOperand(0);
            if (Function *F = dyn_cast<Function>(FP)) {

              if (!F->isDeclaration() &&
                  strncmp(F->getName().str().c_str(), "__afl", 5) != 0) {

                if (!be_quiet)
                  fprintf(stderr,
                          "Note: Found constructor function %s with prio "
                          "%u, we will not instrument this, putting it into a "
                          "block list.\n",
                          F->getName().str().c_str(), Priority);
                denyListFunctions.push_back(F->getName().str());

              }

            }

          }

        }

      }

    }

  }

}

static std::string getSourceName(llvm::Function *F) {

  // let's try to get the filename for the function
  auto                 bb = &F->getEntryBlock();
  BasicBlock::iterator IP = bb->getFirstInsertionPt();
  IRBuilder<>          IRB(&(*IP));
  DebugLoc             Loc = IP->getDebugLoc();

  if (Loc) {

    StringRef   instFilename;
    DILocation *cDILoc = dyn_cast<DILocation>(Loc.getAsMDNode());

    if (cDILoc) { instFilename = cDILoc->getFilename(); }

    if (instFilename.str().empty() && cDILoc) {

      /* If the original location is empty, try using the inlined location
       */
      DILocation *oDILoc = cDILoc->getInlinedAt();
      if (oDILoc) { instFilename = oDILoc->getFilename(); }

    }

    return instFilename.str();

  }

  return std::string("");

}

/* Returns true if an AFL_LLVM_ALLOWLIST or AFL_LLVM_DENYLIST is in effect,
   i.e. at least one allow/deny file or function entry was loaded. */
bool isInstrumentListActive(void) {

  return !allowListFiles.empty() || !allowListFunctions.empty() ||
         !denyListFiles.empty() || !denyListFunctions.empty();

}

bool isInInstrumentList(llvm::Function *F, std::string Filename) {

  bool return_default = true;

  // is this a function with code? If it is external we don't instrument it
  // anyway and it can't be in the instrument file list. Or if it is it is
  // ignored.
  if (!F->size() || isIgnoreFunction(F)) return false;

  if (!denyListFiles.empty() || !denyListFunctions.empty()) {

    if (!denyListFunctions.empty()) {

      std::string instFunction = F->getName().str();
      std::string demangledFunction = llvm::demangle(instFunction);
      std::string noHashFunction = stripRustHash(instFunction);

      if (noHashFunction != instFunction &&
          denyListFunctionsNoHash.count(noHashFunction)) {

        if (debug)
          DEBUGF(
              "Function %s is in the deny function list, not instrumenting "
              "... \n",
              instFunction.c_str());
        return false;

      }

      for (std::list<std::string>::iterator it = denyListFunctions.begin();
           it != denyListFunctions.end(); ++it) {

        /* The entry is used directly as an fnmatch() pattern, no wildcard is
         * added automatically. Prefix the entry with '*' to match a suffix.
         * Both the mangled and the demangled function name are matched. */

        if (fnmatch(it->c_str(), instFunction.c_str(), 0) == 0 ||
            fnmatch(it->c_str(), demangledFunction.c_str(), 0) == 0) {

          if (debug)
            DEBUGF(
                "Function %s is in the deny function list, not instrumenting "
                "... \n",
                instFunction.c_str());
          return false;

        }

      }

    }

    if (!denyListFiles.empty()) {

      std::string source_file = getSourceName(F);

      if (source_file.empty()) { source_file = Filename; }

      if (!source_file.empty()) {

        for (std::list<std::string>::iterator it = denyListFiles.begin();
             it != denyListFiles.end(); ++it) {

          /* We don't check for filename equality here because
           * filenames might actually be full paths. Instead we
           * check that the actual filename ends in the filename
           * specified in the list. We also allow UNIX-style pattern
           * matching */

          if (source_file.length() >= it->length()) {

            if (fnmatch(("*" + *it).c_str(), source_file.c_str(), 0) == 0) {

              return false;

            }

          }

        }

      } else {

        // we could not find out the location. in this case we say it is not
        // in the instrument file list
        if (!be_quiet)
          WARNF(
              "No debug information found for function %s, will be "
              "instrumented (recompile with -g -O[1-3] and use a modern llvm).",
              F->getName().str().c_str());

      }

    }

  }

  // if we do not have a instrument file list return true
  if (!allowListFiles.empty() || !allowListFunctions.empty()) {

    return_default = false;

    if (!allowListFunctions.empty()) {

      std::string instFunction = F->getName().str();
      std::string demangledFunction = llvm::demangle(instFunction);
      std::string noHashFunction = stripRustHash(instFunction);

      if (noHashFunction != instFunction &&
          allowListFunctionsNoHash.count(noHashFunction)) {

        if (debug)
          DEBUGF(
              "Function %s is in the allow function list, instrumenting "
              "... \n",
              instFunction.c_str());
        return true;

      }

      for (std::list<std::string>::iterator it = allowListFunctions.begin();
           it != allowListFunctions.end(); ++it) {

        /* The entry is used directly as an fnmatch() pattern, no wildcard is
         * added automatically. Prefix the entry with '*' to match a suffix.
         * Both the mangled and the demangled function name are matched. */

        if (fnmatch(it->c_str(), instFunction.c_str(), 0) == 0 ||
            fnmatch(it->c_str(), demangledFunction.c_str(), 0) == 0) {

          if (debug)
            DEBUGF(
                "Function %s is in the allow function list, instrumenting "
                "... \n",
                instFunction.c_str());
          return true;

        }

      }

    }

    if (!allowListFiles.empty()) {

      std::string source_file = getSourceName(F);

      if (source_file.empty()) { source_file = Filename; }

      if (!source_file.empty()) {

        for (std::list<std::string>::iterator it = allowListFiles.begin();
             it != allowListFiles.end(); ++it) {

          /* We don't check for filename equality here because
           * filenames might actually be full paths. Instead we
           * check that the actual filename ends in the filename
           * specified in the list. We also allow UNIX-style pattern
           * matching */

          if (source_file.length() >= it->length()) {

            if (fnmatch(("*" + *it).c_str(), source_file.c_str(), 0) == 0) {

              if (debug)
                DEBUGF(
                    "Function %s is in the allowlist (%s), instrumenting ... "
                    "\n",
                    F->getName().str().c_str(), source_file.c_str());
              return true;

            }

          }

        }

      } else {

        // we could not find out the location. In this case we say it is not
        // in the instrument file list
        if (!be_quiet)
          WARNF(
              "No debug information found for function %s, will not be "
              "instrumented (recompile with -g -O[1-3] and use a modern llvm).",
              F->getName().str().c_str());
        return false;

      }

    }

  }

  return return_default;

}

// Calculate the number of average collisions that would occur if all
// location IDs would be assigned randomly (like normal afl/AFL++).
// This uses the "balls in bins" algorithm.
unsigned long long int calculateCollisions(uint32_t edges) {

  double                 bins = MAP_SIZE;
  double                 balls = edges;
  double                 step1 = 1 - (1 / bins);
  double                 step2 = pow(step1, balls);
  double                 step3 = bins * step2;
  double                 step4 = round(step3);
  unsigned long long int empty = step4;
  unsigned long long int collisions = edges - (MAP_SIZE - empty);
  return collisions;

}

bool isDecisionUse(const Value *Cond) {

  SmallVector<const Value *, 8> Worklist;
  SmallPtrSet<const Value *, 8> Visited;

  Worklist.push_back(Cond);

  while (!Worklist.empty()) {

    const Value *V = Worklist.pop_back_val();
    if (!Visited.insert(V).second) continue;

    for (const User *U : V->users()) {

      if (const auto *BI = dyn_cast<BranchInst>(U)) {

        if (BI->isConditional() && BI->getCondition() == V) return true;

      } else if (const auto *SI = dyn_cast<SelectInst>(U)) {

        if (SI->getCondition() == V) return true;

      } else if (const auto *SW = dyn_cast<SwitchInst>(U)) {

        if (SW->getCondition() == V) return true;

        /*

              } else if (const auto *CB = dyn_cast<CallBase>(U)) {

                const Function *F = CB->getCalledFunction();
                if (!F)
                  continue;
                Intrinsic::ID IID = F->getIntrinsicID();
                if (IID == Intrinsic::assume ||
                    IID == Intrinsic::experimental_guard ||
                    IID == Intrinsic::expect)
                  return true;
        */

      } else if (const auto *BO = dyn_cast<BinaryOperator>(U)) {

        if (BO->getType()->isIntegerTy(1)) Worklist.push_back(BO);

      } else if (const auto *PN = dyn_cast<PHINode>(U)) {

        if (PN->getType()->isIntegerTy(1)) return true;

      } else if (const auto *Cast = dyn_cast<CastInst>(U)) {

        if (Cast->getDestTy()->isIntegerTy(1) ||
            Cast->getSrcTy()->isIntegerTy(1))
          Worklist.push_back(Cast);

      } else if (const auto *FI = dyn_cast<FreezeInst>(U)) {

        if (FI->getType()->isIntegerTy(1)) Worklist.push_back(FI);

      }

    }

  }

  return false;

}

bool isAflCovInterestingInstruction(Instruction &I) {

  switch (I.getOpcode()) {

    case Instruction::ICmp:
    case Instruction::FCmp: {

      const Value *Cond = &I;
      Type        *Ty = Cond->getType();
      if (Ty->isIntegerTy(1) ||
          (Ty->isVectorTy() && Ty->getScalarType()->isIntegerTy(1))) {

        if (isDecisionUse(Cond)) return false;

      }

      return true;

    }

    case Instruction::Select: {

      auto   selectInst = dyn_cast<SelectInst>(&I);
      Value *condition = selectInst->getCondition();
      auto   t = condition->getType();

      if (t->getTypeID() == llvm::Type::IntegerTyID) return true;

      return false;

    }

    case Instruction::AtomicCmpXchg:
      return true;

    case Instruction::AtomicRMW: {

      auto *RMW = dyn_cast<AtomicRMWInst>(&I);
      if (!RMW) return false;

      AtomicRMWInst::BinOp Op = RMW->getOperation();

      return Op == AtomicRMWInst::Min || Op == AtomicRMWInst::Max ||
             Op == AtomicRMWInst::UMin || Op == AtomicRMWInst::UMax;

    }

    default:
      return false;

  }

}

bool isExecCall(llvm::Instruction *IN) {

  llvm::CallInst *callInst = llvm::dyn_cast<llvm::CallInst>(IN);
  if (!callInst) return false;

  llvm::Function *Callee = callInst->getCalledFunction();
  if (!Callee || !Callee->hasName() || Callee->isIntrinsic()) return false;

  return llvm::StringSwitch<bool>(Callee->getName())
#if LLVM_VERSION_MAJOR >= 22
      .Cases({"execve", "execl", "execlp", "execle"}, true)
      .Cases({"execv", "execvp", "execvP", "execvpe"}, true)
      .Cases({"fexecve", "execveat"}, true)
      .Cases({"posix_spawn", "posix_spawnp"}, true)
      .Cases({"system", "popen"}, true)
#else
      .Cases("execve", "execl", "execlp", "execle", true)
      .Cases("execv", "execvp", "execvP", "execvpe", true)
      .Cases("fexecve", "execveat", true)
      .Cases("posix_spawn", "posix_spawnp", true)
      .Cases("system", "popen", true)
#endif
      .Default(false);

}

std::pair<bool, bool> detectIJONUsage(Module &M) {

  bool uses_ijon_functions = false;
  bool uses_ijon_state = false;

  // Scan for IJON function calls to determine if we need IJON symbols
  for (auto &F : M) {

    for (auto &BB : F) {

      for (auto &I : BB) {

        Function *calledFunc = nullptr;

        // Check both CallInst and InvokeInst
        if (auto *call = dyn_cast<CallInst>(&I)) {

          calledFunc = dyn_cast<Function>(call->getCalledOperand());

        } else if (auto *invoke = dyn_cast<InvokeInst>(&I)) {

          calledFunc = dyn_cast<Function>(invoke->getCalledOperand());

        }

        if (!calledFunc) continue;

        StringRef funcName = calledFunc->getName();
#if LLVM_VERSION_MAJOR >= 18
        if (!funcName.starts_with("ijon_")) continue;
#else
        if (!funcName.startswith("ijon_")) continue;
#endif

        // Check for state-aware functions (only ijon_xor_state)
        if (funcName == "ijon_xor_state") {

          uses_ijon_functions = true;
          uses_ijon_state = true;
          break;

        }

        // Check for other IJON functions (max/min/set/inc)
        if (funcName == "ijon_max" || funcName == "ijon_min" ||
            funcName == "ijon_max_until" || funcName == "ijon_set" ||
            funcName == "ijon_inc" || funcName == "ijon_max_variadic" ||
            funcName == "ijon_min_variadic") {

          uses_ijon_functions = true;
          // Don't break - keep looking for ijon_xor_state
          continue;

        }

        // Ignore helper functions (ijon_hash*, ijon_strdist, etc.)
#if LLVM_VERSION_MAJOR >= 18
        if (funcName.starts_with("ijon_hash") || funcName == "ijon_strdist") {

#else
        if (funcName.startswith("ijon_hash") || funcName == "ijon_strdist") {

#endif
          continue;

        }

      }

      if (uses_ijon_state) break;

    }

    if (uses_ijon_state) break;

  }

  return {uses_ijon_functions, uses_ijon_state};

}

void createIJONEnabledGlobal(Module &M, Type *Int32Ty) {

  if (M.getNamedGlobal("__afl_ijon_enabled")) return;
  Constant *One32 = ConstantInt::get(Int32Ty, 1);
  // comdat so multiple instrumented TUs each defining it merge to one strong
  // definition instead of a multiple-definition link error, while still
  // overriding the runtime's weak __afl_ijon_enabled = 0 default
  auto *GV = new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage,
                                One32, "__afl_ijon_enabled");
  GV->setComdat(M.getOrInsertComdat("__afl_ijon_enabled"));

}

void createC11EnabledGlobal(Module &M, Type *Int32Ty) {

  if (M.getNamedGlobal("__afl_c11_enabled")) return;
  Constant *One32 = ConstantInt::get(Int32Ty, 1);
  // comdat so multiple instrumented TUs each defining it merge to one strong
  // definition instead of a multiple-definition link error, while still
  // overriding the runtime's weak __afl_c11_enabled = 0 default
  auto *GV = new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage,
                                One32, "__afl_c11_enabled");
  GV->setComdat(M.getOrInsertComdat("__afl_c11_enabled"));

}

GlobalVariable *createIJONStateGlobal(Module &M, Type *Int32Ty,
                                      bool uses_ijon_state) {

  if (!uses_ijon_state) return nullptr;

  if (auto *Existing = M.getNamedGlobal("__afl_ijon_state")) return Existing;

#if defined(__ANDROID__) || defined(__HAIKU__) || defined(NO_TLS)
  return new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage, 0,
                            "__afl_ijon_state");
#else
  return new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage, 0,
                            "__afl_ijon_state", 0,
                            GlobalVariable::GeneralDynamicTLSModel, 0, false);
#endif

}

