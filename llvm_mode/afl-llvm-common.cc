#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include <list>
#include <string>
#include <fstream>

#include <llvm/Support/raw_ostream.h>
#include "afl-llvm-common.h"

using namespace llvm;

static std::list<std::string> myWhitelist;

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
/* Note: this blacklist check is also called in isInWhitelist() */
bool isBlacklisted(const llvm::Function *F) {

  static const char *Blacklist[] = {

      "asan.", "llvm.",      "sancov.", "__ubsan_handle_", "ign.", "__afl_",
      "_fini", "__libc_csu", "__asan",  "__msan",          "msan."

  };

  for (auto const &BlacklistFunc : Blacklist) {

    if (F->getName().startswith(BlacklistFunc)) { return true; }

  }

  return false;

}

void initWhitelist() {

  char *instWhiteListFilename = getenv("AFL_LLVM_WHITELIST");
  if (instWhiteListFilename) {

    std::string   line;
    std::ifstream fileStream;
    fileStream.open(instWhiteListFilename);
    if (!fileStream) report_fatal_error("Unable to open AFL_LLVM_WHITELIST");
    getline(fileStream, line);
    while (fileStream) {

      myWhitelist.push_back(line);
      getline(fileStream, line);

    }

  }

}

bool isInWhitelist(llvm::Function *F) {

  // is this a function with code? If it is external we dont instrument it
  // anyway and cant be in the whitelist. Or if it is blacklisted.
  if (!F->size() || isBlacklisted(F)) return false;

  // if we do not have a whitelist return true
  if (myWhitelist.empty()) return true;

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

      for (std::list<std::string>::iterator it = myWhitelist.begin();
           it != myWhitelist.end(); ++it) {

        /* We don't check for filename equality here because
         * filenames might actually be full paths. Instead we
         * check that the actual filename ends in the filename
         * specified in the list. */
        if (instFilename.str().length() >= it->length()) {

          if (instFilename.str().compare(
                  instFilename.str().length() - it->length(), it->length(),
                  *it) == 0) {

            return true;

          }

        }

      }

    }

  }

#else
  if (!Loc.isUnknown()) {

    DILocation cDILoc(Loc.getAsMDNode(C));

    unsigned int instLine = cDILoc.getLineNumber();
    StringRef    instFilename = cDILoc.getFilename();

    (void)instLine;
    /* Continue only if we know where we actually are */
    if (!instFilename.str().empty()) {

      for (std::list<std::string>::iterator it = myWhitelist.begin();
           it != myWhitelist.end(); ++it) {

        /* We don't check for filename equality here because
         * filenames might actually be full paths. Instead we
         * check that the actual filename ends in the filename
         * specified in the list. */
        if (instFilename.str().length() >= it->length()) {

          if (instFilename.str().compare(
                  instFilename.str().length() - it->length(), it->length(),
                  *it) == 0) {

            return true;

          }

        }

      }

    }

  }

#endif
  else {

    // we could not find out the location. in this case we say it is not
    // in the whitelist

    return false;

  }

  //
  return false;

}

