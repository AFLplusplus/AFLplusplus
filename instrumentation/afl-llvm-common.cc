#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <fnmatch.h>

#include <list>
#include <string>
#include <fstream>

#include <llvm/Support/raw_ostream.h>

#define IS_EXTERN extern
#include "afl-llvm-common.h"

using namespace llvm;

static std::list<std::string> allowListFiles;
static std::list<std::string> allowListFunctions;
static std::list<std::string> denyListFiles;
static std::list<std::string> denyListFunctions;

char *getBBName(const llvm::BasicBlock *BB) {

  static char *name;

  if (!BB->getName().empty()) {

    name = strdup(BB->getName().str().c_str());
    return name;

  }

  std::string        Str;
  raw_string_ostream OS(Str);

#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR >= 7)
  BB->printAsOperand(OS, false);
#endif
  name = strdup(OS.str().c_str());
  return name;

}

/* Function that we never instrument or analyze */
/* Note: this ignore check is also called in isInInstrumentList() */
bool isIgnoreFunction(const llvm::Function *F) {

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

    if (F->getName().startswith(ignoreListFunc)) { return true; }

  }

  static constexpr const char *ignoreSubstringList[] = {

      "__asan", "__msan",       "__ubsan",    "__lsan",  "__san", "__sanitize",
      "__cxx",  "DebugCounter", "DwarfDebug", "DebugLoc"

  };

  for (auto const &ignoreListFunc : ignoreSubstringList) {

    // hexcoder: F->getName().contains() not avaiilable in llvm 3.8.0
    if (StringRef::npos != F->getName().find(ignoreListFunc)) { return true; }

  }

  return false;

}

void initInstrumentList() {

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

      if (line.find(":") != std::string::npos) {

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
        else
          allowListFunctions.push_back(line);

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

      if (line.find(":") != std::string::npos) {

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
        else
          denyListFunctions.push_back(line);

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

#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR >= 9)

  for (GlobalIFunc &IF : M->ifuncs()) {

    StringRef ifunc_name = IF.getName();
    Constant *r = IF.getResolver();
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

            if (CS->getOperand(1)->isNullValue())
              break;  // Found a null terminator, stop here.

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

#endif

}

static std::string getSourceName(llvm::Function *F) {

  // let's try to get the filename for the function
  auto                 bb = &F->getEntryBlock();
  BasicBlock::iterator IP = bb->getFirstInsertionPt();
  IRBuilder<>          IRB(&(*IP));
  DebugLoc             Loc = IP->getDebugLoc();

#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR >= 7)
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

#else
  if (!Loc.isUnknown()) {

    DILocation cDILoc(Loc.getAsMDNode(F->getContext()));

    StringRef instFilename = cDILoc.getFilename();

    /* Continue only if we know where we actually are */
    return instFilename.str();

  }

#endif

  return std::string("");

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

      for (std::list<std::string>::iterator it = denyListFunctions.begin();
           it != denyListFunctions.end(); ++it) {

        /* We don't check for filename equality here because
         * filenames might actually be full paths. Instead we
         * check that the actual filename ends in the filename
         * specified in the list. We also allow UNIX-style pattern
         * matching */

        if (instFunction.length() >= it->length()) {

          if (fnmatch(("*" + *it).c_str(), instFunction.c_str(), 0) == 0) {

            if (debug)
              DEBUGF(
                  "Function %s is in the deny function list, not instrumenting "
                  "... \n",
                  instFunction.c_str());
            return false;

          }

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

      for (std::list<std::string>::iterator it = allowListFunctions.begin();
           it != allowListFunctions.end(); ++it) {

        /* We don't check for filename equality here because
         * filenames might actually be full paths. Instead we
         * check that the actual filename ends in the filename
         * specified in the list. We also allow UNIX-style pattern
         * matching */

        if (instFunction.length() >= it->length()) {

          if (fnmatch(("*" + *it).c_str(), instFunction.c_str(), 0) == 0) {

            if (debug)
              DEBUGF(
                  "Function %s is in the allow function list, instrumenting "
                  "... \n",
                  instFunction.c_str());
            return true;

          }

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
// location IDs would be assigned randomly (like normal afl/afl++).
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

