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
#include "afl-llvm-common.h"

using namespace llvm;

static std::list<std::string> myInstrumentList;

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

  static const char *ignoreList[] = {

      "asan.",
      "llvm.",
      "sancov.",
      "__ubsan_handle_",
      "ign.",
      "__afl_",
      "_fini",
      "__libc_csu",
      "__asan",
      "__msan",
      "msan.",
      "LLVMFuzzer",
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

  return false;

}

void initInstrumentList() {

  char *instrumentListFilename = getenv("AFL_LLVM_INSTRUMENT_FILE");
  if (!instrumentListFilename)
    instrumentListFilename = getenv("AFL_LLVM_WHITELIST");
  if (instrumentListFilename) {

    std::string   line;
    std::ifstream fileStream;
    fileStream.open(instrumentListFilename);
    if (!fileStream)
      report_fatal_error("Unable to open AFL_LLVM_INSTRUMENT_FILE");
    getline(fileStream, line);
    while (fileStream) {

      myInstrumentList.push_back(line);
      getline(fileStream, line);

    }

  }

}

bool isInInstrumentList(llvm::Function *F) {

  // is this a function with code? If it is external we dont instrument it
  // anyway and cant be in the the instrument file list. Or if it is ignored.
  if (!F->size() || isIgnoreFunction(F)) return false;

  // if we do not have a the instrument file list return true
  if (myInstrumentList.empty()) return true;

  // let's try to get the filename for the function
  auto                 bb = &F->getEntryBlock();
  BasicBlock::iterator IP = bb->getFirstInsertionPt();
  IRBuilder<>          IRB(&(*IP));
  DebugLoc             Loc = IP->getDebugLoc();

#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR >= 7)
  if (Loc) {

    DILocation *cDILoc = dyn_cast<DILocation>(Loc.getAsMDNode());

    unsigned int instLine = cDILoc->getLine();
    StringRef    instFilename = cDILoc->getFilename();

    if (instFilename.str().empty()) {

      /* If the original location is empty, try using the inlined location
       */
      DILocation *oDILoc = cDILoc->getInlinedAt();
      if (oDILoc) {

        instFilename = oDILoc->getFilename();
        instLine = oDILoc->getLine();

      }

    }

    (void)instLine;

    /* Continue only if we know where we actually are */
    if (!instFilename.str().empty()) {

      for (std::list<std::string>::iterator it = myInstrumentList.begin();
           it != myInstrumentList.end(); ++it) {

        /* We don't check for filename equality here because
         * filenames might actually be full paths. Instead we
         * check that the actual filename ends in the filename
         * specified in the list. We also allow UNIX-style pattern
         * matching */

        if (instFilename.str().length() >= it->length()) {

          if (fnmatch(("*" + *it).c_str(), instFilename.str().c_str(), 0) ==
              0) {

            return true;

          }

        }

      }

    }

  }

#else
  if (!Loc.isUnknown()) {

    DILocation cDILoc(Loc.getAsMDNode(F->getContext()));

    unsigned int instLine = cDILoc.getLineNumber();
    StringRef    instFilename = cDILoc.getFilename();

    (void)instLine;
    /* Continue only if we know where we actually are */
    if (!instFilename.str().empty()) {

      for (std::list<std::string>::iterator it = myInstrumentList.begin();
           it != myInstrumentList.end(); ++it) {

        /* We don't check for filename equality here because
         * filenames might actually be full paths. Instead we
         * check that the actual filename ends in the filename
         * specified in the list. We also allow UNIX-style pattern
         * matching */

        if (instFilename.str().length() >= it->length()) {

          if (fnmatch(("*" + *it).c_str(), instFilename.str().c_str(), 0) ==
              0) {

            return true;

          }

        }

      }

    }

  }

#endif
  else {

    // we could not find out the location. in this case we say it is not
    // in the the instrument file list

    return false;

  }

  //
  return false;

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

