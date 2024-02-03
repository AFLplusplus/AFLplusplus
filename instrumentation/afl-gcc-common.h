/* GCC plugin common infrastructure for AFL++ instrumentation passes.

   Copyright 2014-2019 Free Software Foundation, Inc
   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2024 AdaCore

   Written by Alexandre Oliva <oliva@adacore.com>, based on the AFL++
   GCC plugin.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

 */

#include "../include/config.h"
#include "../include/debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef likely
  #undef likely
#endif
#ifdef unlikely
  #undef unlikely
#endif

#include <list>
#include <string>
#include <fstream>

#include <algorithm>
#include <fnmatch.h>

#include <gcc-plugin.h>
#include <plugin-version.h>
#include <toplev.h>
#include <tree-pass.h>
#include <context.h>
#include <tree.h>
#include <gimplify.h>
#include <basic-block.h>
#include <tree-ssa-alias.h>
#include <gimple-expr.h>
#include <gimple.h>
#include <gimple-iterator.h>
#include <stringpool.h>
#include <gimple-ssa.h>
#if (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__) >= \
    60200                                               /* >= version 6.2.0 */
  #include <tree-vrp.h>
#endif
#include <tree-ssanames.h>
#include <tree-phinodes.h>
#include <ssa-iterators.h>

#include <intl.h>

namespace {

struct afl_base_pass : gimple_opt_pass {

  afl_base_pass(bool quiet, bool debug, struct pass_data const &pd)
      : gimple_opt_pass(pd, g), be_quiet(quiet), debug(debug) {

    initInstrumentList();

  }

  /* Are we outputting to a non-terminal, or running with AFL_QUIET
     set?  */
  const bool be_quiet;

  /* Are we running with AFL_DEBUG set?  */
  const bool debug;

#define report_fatal_error(msg) BADF(msg)

  std::list<std::string> allowListFiles;
  std::list<std::string> allowListFunctions;
  std::list<std::string> denyListFiles;
  std::list<std::string> denyListFunctions;

  /* Note: this ignore check is also called in isInInstrumentList() */
  bool isIgnoreFunction(function *F) {

    // Starting from "LLVMFuzzer" these are functions used in libfuzzer based
    // fuzzing campaign installations, e.g. oss-fuzz

    static constexpr const char *ignoreList[] = {

        "asan.",
        "llvm.",
        "sancov.",
        "__ubsan_",
        "ign.",
        "__afl_",
        "_fini",
        "__libc_csu",
        "__asan",
        "__msan",
        "__cmplog",
        "__sancov",
        "msan.",
        "LLVMFuzzerM",
        "LLVMFuzzerC",
        "LLVMFuzzerI",
        "__decide_deferred",
        "maybe_duplicate_stderr",
        "discard_output",
        "close_stdout",
        "dup_and_close_stderr",
        "maybe_close_fd_mask",
        "ExecuteFilesOnyByOne"

    };

    const char *name = IDENTIFIER_POINTER(DECL_NAME(F->decl));
    int         len = IDENTIFIER_LENGTH(DECL_NAME(F->decl));

    for (auto const &ignoreListFunc : ignoreList) {

      if (strncmp(name, ignoreListFunc, len) == 0) { return true; }

    }

    return false;

  }

  void initInstrumentList() {

    char *allowlist = getenv("AFL_GCC_ALLOWLIST");
    if (!allowlist) allowlist = getenv("AFL_GCC_INSTRUMENT_FILE");
    if (!allowlist) allowlist = getenv("AFL_GCC_WHITELIST");
    if (!allowlist) allowlist = getenv("AFL_LLVM_ALLOWLIST");
    if (!allowlist) allowlist = getenv("AFL_LLVM_INSTRUMENT_FILE");
    if (!allowlist) allowlist = getenv("AFL_LLVM_WHITELIST");
    char *denylist = getenv("AFL_GCC_DENYLIST");
    if (!denylist) denylist = getenv("AFL_GCC_BLOCKLIST");
    if (!denylist) denylist = getenv("AFL_LLVM_DENYLIST");
    if (!denylist) denylist = getenv("AFL_LLVM_BLOCKLIST");

    if (allowlist && denylist)
      FATAL(
          "You can only specify either AFL_GCC_ALLOWLIST or AFL_GCC_DENYLIST "
          "but not both!");

    if (allowlist) {

      std::string   line;
      std::ifstream fileStream;
      fileStream.open(allowlist);
      if (!fileStream) report_fatal_error("Unable to open AFL_GCC_ALLOWLIST");
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

          FATAL("invalid line in AFL_GCC_ALLOWLIST: %s", original_line.c_str());

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
      if (!fileStream) report_fatal_error("Unable to open AFL_GCC_DENYLIST");
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

          FATAL("invalid line in AFL_GCC_DENYLIST: %s", original_line.c_str());

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

  /* Returns the source file name attached to the function declaration F. If
     there is no source location information, returns an empty string.  */
  std::string getSourceName(function *F) {

    return DECL_SOURCE_FILE(F->decl) ? DECL_SOURCE_FILE(F->decl) : "";

  }

  bool isInInstrumentList(function *F) {

    bool return_default = true;

    // is this a function with code? If it is external we don't instrument it
    // anyway and it can't be in the instrument file list. Or if it is it is
    // ignored.
    if (isIgnoreFunction(F)) return false;

    if (!denyListFiles.empty() || !denyListFunctions.empty()) {

      if (!denyListFunctions.empty()) {

        std::string instFunction = IDENTIFIER_POINTER(DECL_NAME(F->decl));

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
                    "Function %s is in the deny function list, not "
                    "instrumenting ... \n",
                    instFunction.c_str());
              return false;

            }

          }

        }

      }

      if (!denyListFiles.empty()) {

        std::string source_file = getSourceName(F);

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
                "instrumented (recompile with -g -O[1-3]).",
                IDENTIFIER_POINTER(DECL_NAME(F->decl)));

        }

      }

    }

    // if we do not have a instrument file list return true
    if (!allowListFiles.empty() || !allowListFunctions.empty()) {

      return_default = false;

      if (!allowListFunctions.empty()) {

        std::string instFunction = IDENTIFIER_POINTER(DECL_NAME(F->decl));

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
                      IDENTIFIER_POINTER(DECL_NAME(F->decl)),
                      source_file.c_str());
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
                "instrumented (recompile with -g -O[1-3]).",
                IDENTIFIER_POINTER(DECL_NAME(F->decl)));
          return false;

        }

      }

    }

    return return_default;

  }

};

}  // namespace

// compatibility for older gcc versions
#if (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__) >= \
    60200                                               /* >= version 6.2.0 */
  #define gimple gimple *
#else
  #define gimple gimple
#endif

