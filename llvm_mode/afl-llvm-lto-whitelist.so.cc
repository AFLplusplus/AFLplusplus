/*
   american fuzzy lop++ - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "config.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>
#include <fnmatch.h>

#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/CFG.h"

#include "afl-llvm-common.h"

using namespace llvm;

namespace {

class AFLwhitelist : public ModulePass {

 public:
  static char ID;
  AFLwhitelist() : ModulePass(ID) {

    int entries = 0;

    if (getenv("AFL_DEBUG")) debug = 1;

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
        entries++;

      }

    } else

      PFATAL("afl-llvm-lto-whitelist.so loaded without AFL_LLVM_WHITELIST?!");

    if (debug)
      SAYF(cMGN "[D] " cRST "loaded whitelist %s with %d entries\n",
           instWhiteListFilename, entries);

  }

  bool runOnModule(Module &M) override;

  // StringRef getPassName() const override {

  //  return "American Fuzzy Lop Instrumentation";
  // }

 protected:
  std::list<std::string> myWhitelist;
  int                    debug = 0;

};

}  // namespace

char AFLwhitelist::ID = 0;

bool AFLwhitelist::runOnModule(Module &M) {

  /* Show a banner */

  char be_quiet = 0;
  setvbuf(stdout, NULL, _IONBF, 0);

  if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {

    SAYF(cCYA "afl-llvm-lto-whitelist" VERSION cRST
              " by Marc \"vanHauser\" Heuse <mh@mh-sec.de>\n");

  } else if (getenv("AFL_QUIET"))

    be_quiet = 1;

  for (auto &F : M) {

    if (F.size() < 1) continue;
    // fprintf(stderr, "F:%s\n", F.getName().str().c_str());
    if (isBlacklisted(&F)) continue;

    BasicBlock::iterator IP = F.getEntryBlock().getFirstInsertionPt();
    IRBuilder<>          IRB(&(*IP));

    if (!myWhitelist.empty()) {

      bool instrumentFunction = false;

      /* Get the current location using debug information.
       * For now, just instrument the block if we are not able
       * to determine our location. */
      DebugLoc Loc = IP->getDebugLoc();
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

        if (debug)
          SAYF(cMGN "[D] " cRST "function %s is in file %s\n",
               F.getName().str().c_str(), instFilename.str().c_str());
        /* Continue only if we know where we actually are */
        if (!instFilename.str().empty()) {

          for (std::list<std::string>::iterator it = myWhitelist.begin();
               it != myWhitelist.end(); ++it) {

            /* We don't check for filename equality here because
             * filenames might actually be full paths. Instead we
             * check that the actual filename ends in the filename
             * specified in the list. */
            if (instFilename.str().length() >= it->length()) {

              if (fnmatch(("*" + *it).c_str(), instFilename.str().c_str(), 0) ==
                  0) {

                instrumentFunction = true;
                break;

              }

            }

          }

        }

      }

      /* Either we couldn't figure out our location or the location is
       * not whitelisted, so we skip instrumentation.
       * We do this by renaming the function. */
      if (instrumentFunction == true) {

        if (debug)
          SAYF(cMGN "[D] " cRST "function %s is in whitelist\n",
               F.getName().str().c_str());

      } else {

        if (debug)
          SAYF(cMGN "[D] " cRST "function %s is NOT in whitelist\n",
               F.getName().str().c_str());

        auto &        Ctx = F.getContext();
        AttributeList Attrs = F.getAttributes();
        AttrBuilder   NewAttrs;
        NewAttrs.addAttribute("skipinstrument");
        F.setAttributes(
            Attrs.addAttributes(Ctx, AttributeList::FunctionIndex, NewAttrs));

      }

    } else {

      PFATAL("Whitelist is empty");

    }

  }

  return true;

}

static void registerAFLwhitelistpass(const PassManagerBuilder &,
                                     legacy::PassManagerBase &PM) {

  PM.add(new AFLwhitelist());

}

static RegisterStandardPasses RegisterAFLwhitelistpass(
    PassManagerBuilder::EP_ModuleOptimizerEarly, registerAFLwhitelistpass);

static RegisterStandardPasses RegisterAFLwhitelistpass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLwhitelistpass);

