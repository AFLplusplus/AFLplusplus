/*
 * OptiMin, an optimal fuzzing corpus minimizer.
 *
 * Author: Adrian Herrera
 */

#include <cstdint>
#include <cstdlib>
#include <vector>

#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/Support/Chrono.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/Program.h>
#include <llvm/Support/WithColor.h>

#include "EvalMaxSAT.h"

using namespace llvm;

namespace {

// -------------------------------------------------------------------------- //
// Classes
// -------------------------------------------------------------------------- //

/// Ensure seed weights default to 1
class Weight {

 public:
  Weight() : Weight(1){};
  Weight(uint32_t V) : Value(V){};

  operator unsigned() const {

    return Value;

  }

 private:
  const unsigned Value;

};

// -------------------------------------------------------------------------- //
// Typedefs
// -------------------------------------------------------------------------- //

/// AFL tuple (edge) ID
using AFLTupleID = uint32_t;

/// Pair of tuple ID and hit count
using AFLTuple = std::pair<AFLTupleID, /* Frequency */ unsigned>;

/// Coverage for a given seed file
using AFLCoverageVector = std::vector<AFLTuple>;

/// Map seed file paths to its coverage vector
using AFLCoverageMap = StringMap<AFLCoverageVector>;

/// Map seed file paths to a weight
using WeightsMap = StringMap<Weight>;

/// A seed identifier in the MaxSAT solver
using SeedID = int;

/// Associates seed identifiers to seed files
using MaxSATSeeds =
    SmallVector<std::pair<SeedID, /* Seed file */ std::string>, 0>;

/// Set of literal identifiers
using MaxSATSeedSet = DenseSet<SeedID>;

/// Maps tuple IDs to the literal identifiers that "cover" that tuple
using MaxSATCoverageMap = DenseMap<AFLTupleID, MaxSATSeedSet>;

// -------------------------------------------------------------------------- //
// Global variables
// -------------------------------------------------------------------------- //

// This is based on the human class count in `count_class_human[256]` in
// `afl-showmap.c`
static constexpr uint32_t MAX_EDGE_FREQ = 8;

// The maximum number of failures allowed when parsing a weights file
static constexpr unsigned MAX_WEIGHT_FAILURES = 5;

static sys::TimePoint<>     StartTime, EndTime;
static std::chrono::seconds Duration;

static std::string ShowmapPath;
static bool        TargetArgsHasAtAt = false;
static bool        KeepTraces = false;
static bool        SkipBinCheck = false;

static const auto ErrMsg = [] {

  return WithColor(errs(), raw_ostream::RED, /*Bold=*/true) << "[-] ";

};

static const auto WarnMsg = [] {

  return WithColor(errs(), raw_ostream::MAGENTA, /*Bold=*/true) << "[-] ";

};

static const auto SuccMsg = [] {

  return WithColor(outs(), raw_ostream::GREEN, /*Bold=*/true) << "[+] ";

};

static const auto StatMsg = [] {

  return WithColor(outs(), raw_ostream::BLUE, /*Bold=*/true) << "[*] ";

};

static cl::opt<std::string> InputDir("i", cl::desc("Input directory"),
                                     cl::value_desc("dir"), cl::Required);
static cl::opt<std::string> OutputDir("o", cl::desc("Output directory"),
                                      cl::value_desc("dir"), cl::Required);

static cl::opt<bool>        EdgesOnly("f", cl::desc("Include edge hit counts"),
                               cl::init(true));
static cl::opt<std::string> WeightsFile("w", cl::desc("Weights file"),
                                        cl::value_desc("csv"));

static cl::opt<std::string>  TargetProg(cl::Positional,
                                       cl::desc("<target program>"),
                                       cl::Required);
static cl::list<std::string> TargetArgs(cl::ConsumeAfter,
                                        cl::desc("[target args...]"));

static cl::opt<std::string> MemLimit(
    "m", cl::desc("Memory limit for child process (default=none)"),
    cl::value_desc("megs"), cl::init("none"));
static cl::opt<std::string> Timeout(
    "t", cl::desc("Run time limit for child process (default=5000)"),
    cl::value_desc("msec"), cl::init("5000"));

static cl::opt<bool> CrashMode(
    "C", cl::desc("Keep crashing inputs, reject everything else"));
static cl::opt<bool> FridaMode(
    "O", cl::desc("Use binary-only instrumentation (FRIDA mode)"));
static cl::opt<bool> QemuMode(
    "Q", cl::desc("Use binary-only instrumentation (QEMU mode)"));
static cl::opt<bool> UnicornMode(
    "U", cl::desc("Use unicorn-based instrumentation (unicorn mode)"));

}  // anonymous namespace

// -------------------------------------------------------------------------- //
// Helper functions
// -------------------------------------------------------------------------- //

static void GetWeights(const MemoryBuffer &MB, WeightsMap &Weights) {

  SmallVector<StringRef, 0> Lines;
  MB.getBuffer().trim().split(Lines, '\n');

  unsigned FailureCount = 0;
  unsigned Weight = 0;

  for (const auto &Line : Lines) {

    const auto &[Seed, WeightStr] = Line.split(',');

    if (to_integer(WeightStr, Weight, 10)) {

      Weights.try_emplace(Seed, Weight);

    } else {

      if (FailureCount >= MAX_WEIGHT_FAILURES) {
        ErrMsg() << "Too many failures. Aborting\n";
        std::exit(1);
      }

      WarnMsg() << "Failed to read weight for '" << Seed << "'. Skipping...\n";
      FailureCount++;

    }

  }

}

static std::error_code readCov(const StringRef Trace, AFLCoverageVector &Cov) {

  const auto CovOrErr = MemoryBuffer::getFile(Trace);
  if (const auto EC = CovOrErr.getError()) return EC;

  SmallVector<StringRef, 0> Lines;
  CovOrErr.get()->getBuffer().trim().split(Lines, '\n');

  AFLTupleID Edge = 0;
  unsigned   Freq = 0;

  for (const auto &Line : Lines) {

    const auto &[EdgeStr, FreqStr] = Line.split(':');

    to_integer(EdgeStr, Edge, 10);
    to_integer(FreqStr, Freq, 10);
    Cov.push_back({Edge, Freq});

  }

  return std::error_code();

}

static Error runShowmap(AFLCoverageMap &CovMap, const StringRef Input,
                        bool BinCheck = false) {

  const bool          InputIsFile = !sys::fs::is_directory(Input);
  Optional<StringRef> Redirects[] = {None, None, None};

  SmallString<32> TraceDir{OutputDir};
  sys::path::append(TraceDir, ".traces");

  SmallString<32> Output{TraceDir};
  SmallString<32> StdinFile{TraceDir};

  // ------------------------------------------------------------------------ //
  // Prepare afl-showmap arguments
  //
  // If the given input is a file, then feed this directly into stdin.
  // Otherwise, if it is a directory, specify this on the afl-showmap command
  // line.
  // ------------------------------------------------------------------------ //

  SmallVector<StringRef, 12> ShowmapArgs{ShowmapPath, "-q",
                                         "-m",        MemLimit,
                                         "-t",        Timeout};

  if (InputIsFile) {

    StdinFile = Input;
    sys::path::append(Output,
                      BinCheck ? ".run_test" : sys::path::filename(Input));

  } else {

    sys::path::append(StdinFile, ".cur_input");
    ShowmapArgs.append({"-i", Input});

  }


  if (TargetArgsHasAtAt) {

    ShowmapArgs.append({"-A", StdinFile});
    Redirects[/* stdin */ 0] = "/dev/null";

  } else if (InputIsFile) {

    Redirects[/* stdin */ 0] = Input;

  }

  if (FridaMode) ShowmapArgs.push_back("-O");
  if (QemuMode) ShowmapArgs.push_back("-Q");
  if (UnicornMode) ShowmapArgs.push_back("-U");

  ShowmapArgs.append({"-o", Output, "--", TargetProg});
  ShowmapArgs.append(TargetArgs.begin(), TargetArgs.end());

  // ------------------------------------------------------------------------ //
  // Run afl-showmap
  // ------------------------------------------------------------------------ //

  const int RC = sys::ExecuteAndWait(ShowmapPath, ShowmapArgs,
                                     /*env=*/None, Redirects);
  if (RC && !CrashMode) {

    ErrMsg() << "Exit code " << RC << " != 0 received from afl-showmap\n";
    return createStringError(inconvertibleErrorCode(), "afl-showmap failed");

  }

  // ------------------------------------------------------------------------ //
  // Parse afl-showmap output
  // ------------------------------------------------------------------------ //

  AFLCoverageVector    Cov;
  std::error_code      EC;
  sys::fs::file_status Status;

  if (InputIsFile) {

    // Read a single output coverage file
    if ((EC = readCov(Output, Cov))) {

      sys::fs::remove(Output);
      return errorCodeToError(EC);

    }

    CovMap.try_emplace(sys::path::filename(Input), Cov);
    if (!KeepTraces) sys::fs::remove(Output);

  } else {

    // Read a directory of output coverage files
    for (sys::fs::recursive_directory_iterator Dir(TraceDir, EC), DirEnd;
         Dir != DirEnd && !EC; Dir.increment(EC)) {

      if (EC) return errorCodeToError(EC);

      const auto &Path = Dir->path();
      if ((EC = sys::fs::status(Path, Status))) return errorCodeToError(EC);

      switch (Status.type()) {

        case sys::fs::file_type::regular_file:
        case sys::fs::file_type::symlink_file:
        case sys::fs::file_type::type_unknown:
          Cov.clear();
          if ((EC = readCov(Path, Cov))) {

            sys::fs::remove(Path);
            return errorCodeToError(EC);

          }

          CovMap.try_emplace(sys::path::filename(Path), Cov);
        default:
          // Ignore
          break;

      }

    }

    if (!KeepTraces) sys::fs::remove_directories(TraceDir);

  }

  return Error::success();

}

static inline void StartTimer() {

  StartTime = std::chrono::system_clock::now();

}

static inline void EndTimer() {

  EndTime = std::chrono::system_clock::now();
  Duration =
      std::chrono::duration_cast<std::chrono::seconds>(EndTime - StartTime);

  SuccMsg() << "  Completed in " << Duration.count() << " s\n";

}

// -------------------------------------------------------------------------- //
// Main function
// -------------------------------------------------------------------------- //

int main(int argc, char *argv[]) {

  WeightsMap      Weights;
  std::error_code EC;

  // ------------------------------------------------------------------------ //
  // Parse command-line options and environment variables
  //
  // Also check the target arguments, as this determines how we run afl-showmap.
  // ------------------------------------------------------------------------ //

  cl::ParseCommandLineOptions(argc, argv, "Optimal corpus minimizer");

  KeepTraces = !!std::getenv("AFL_KEEP_TRACES");
  SkipBinCheck = !!std::getenv("AFL_SKIP_BIN_CHECK");
  const auto AFLPath = std::getenv("AFL_PATH");

  if (CrashMode) ::setenv("AFL_CMIN_CRASHES_ONLY", "1", /*overwrite=*/true);

  for (const auto &Arg : TargetArgs)
    if (Arg == "@@") TargetArgsHasAtAt = true;

  // ------------------------------------------------------------------------ //
  // Find afl-showmap
  // ------------------------------------------------------------------------ //

  SmallVector<StringRef, 16> EnvPaths;

  if (const char *PathEnv = std::getenv("PATH"))
    SplitString(PathEnv, EnvPaths, ":");
  if (AFLPath) EnvPaths.push_back(AFLPath);

  const auto ShowmapOrErr = sys::findProgramByName("afl-showmap", EnvPaths);
  if (ShowmapOrErr.getError()) {

    ErrMsg() << "Failed to find afl-showmap. Check your PATH\n";
    return 1;

  }

  ShowmapPath = *ShowmapOrErr;

  // ------------------------------------------------------------------------ //
  // Parse weights
  //
  // Weights are stored in CSV file mapping a seed file name to an integer
  // greater than zero.
  // ------------------------------------------------------------------------ //

  if (WeightsFile != "") {

    StatMsg() << "Reading weights from '" << WeightsFile << "'...\n";
    StartTimer();

    const auto WeightsOrErr = MemoryBuffer::getFile(WeightsFile);
    if ((EC = WeightsOrErr.getError())) {

      ErrMsg() << "Failed to read weights from '" << WeightsFile
               << "': " << EC.message() << '\n';
      return 1;

    }

    GetWeights(*WeightsOrErr.get(), Weights);

    EndTimer();

  }

  // ------------------------------------------------------------------------ //
  // Traverse input directory
  //
  // Find the seed files inside this directory (and subdirectories).
  // ------------------------------------------------------------------------ //

  StatMsg() << "Locating seeds in '" << InputDir << "'...\n";
  StartTimer();

  bool IsDirResult;
  if ((EC = sys::fs::is_directory(InputDir, IsDirResult))) {

    ErrMsg() << "Invalid input directory '" << InputDir << "': " << EC.message()
             << '\n';
    return 1;

  }

  sys::fs::file_status   Status;
  StringMap<std::string> SeedFiles;

  for (sys::fs::recursive_directory_iterator Dir(InputDir, EC), DirEnd;
       Dir != DirEnd && !EC; Dir.increment(EC)) {

    if (EC) {

      ErrMsg() << "Failed to traverse input directory '" << InputDir
               << "': " << EC.message() << '\n';
      return 1;

    }

    const auto &Path = Dir->path();
    if ((EC = sys::fs::status(Path, Status))) {

      ErrMsg() << "Failed to access '" << Path << "': " << EC.message() << '\n';
      return 1;

    }

    switch (Status.type()) {

      case sys::fs::file_type::regular_file:
      case sys::fs::file_type::symlink_file:
      case sys::fs::file_type::type_unknown:
        SeedFiles.try_emplace(sys::path::filename(Path),
                              sys::path::parent_path(Path));
      default:
        /* Ignore */
        break;

    }

  }

  EndTimer();

  if (SeedFiles.empty()) {

    ErrMsg() << "Failed to find any seed files in '" << InputDir << "'\n";
    return 1;

  }

  // ------------------------------------------------------------------------ //
  // Setup output directory
  // ------------------------------------------------------------------------ //

  SmallString<32> TraceDir{OutputDir};
  sys::path::append(TraceDir, ".traces");

  if ((EC = sys::fs::remove_directories(TraceDir))) {

    ErrMsg() << "Failed to remove existing trace directory in '" << OutputDir
             << "': " << EC.message() << '\n';
    return 1;

  }

  if ((EC = sys::fs::create_directories(TraceDir))) {

    ErrMsg() << "Failed to create output directory '" << OutputDir
             << "': " << EC.message() << '\n';
    return 1;

  }

  // ------------------------------------------------------------------------ //
  // Test the target binary
  // ------------------------------------------------------------------------ //

  AFLCoverageMap CovMap;

  if (!SkipBinCheck) {

    const auto      It = SeedFiles.begin();
    SmallString<32> TestSeed{It->second};
    sys::path::append(TestSeed, It->first());

    StatMsg() << "Testing the target binary with '" << TestSeed << "`...\n";
    StartTimer();

    if (auto Err = runShowmap(CovMap, TestSeed, /*BinCheck=*/true)) {

      ErrMsg() << "No instrumentation output detected \n";
      return 1;

    }

    EndTimer();
    SuccMsg() << "OK, " << CovMap.begin()->second.size()
              << " tuples recorded\n";

  }

  // ------------------------------------------------------------------------ //
  // Generate seed coverage
  //
  // Iterate over the corpus directory, which should contain seed files. Execute
  // these seeds in the target program to generate coverage information, and
  // then store this coverage information in the appropriate data structures.
  // ------------------------------------------------------------------------ //

  StatMsg() << "Running afl-showmap on " << SeedFiles.size() << " seeds...\n";
  StartTimer();

  MaxSATSeeds       SeedVars;
  MaxSATCoverageMap SeedCoverage;
  EvalMaxSAT        Solver(/*nbMinimizeThread=*/0);

  CovMap.clear();
  if (auto Err = runShowmap(CovMap, InputDir)) {

    ErrMsg() << "Failed to generate coverage: " << Err << '\n';
    return 1;

  }

  for (const auto &SeedCov : CovMap) {

    // Create a variable to represent the seed
    const SeedID Var = Solver.newVar();
    SeedVars.emplace_back(Var, SeedCov.first());

    // Record the set of seeds that cover a particular edge
    for (auto &[Edge, Freq] : SeedCov.second) {

      if (EdgesOnly) {

        // Ignore edge frequency
        SeedCoverage[Edge].insert(Var);

      } else {

        // Executing edge `E` `N` times means that it was executed `N - 1` times
        for (unsigned I = 0; I < Freq; ++I)
          SeedCoverage[MAX_EDGE_FREQ * Edge + I].insert(Var);

      }

    }

  }

  EndTimer();

  // ------------------------------------------------------------------------ //
  // Set the hard and soft constraints in the solver
  // ------------------------------------------------------------------------ //

  StatMsg() << "Generating constraints...\n";
  StartTimer();

  size_t SeedCount = 0;

  // Ensure that at least one seed is selected that covers a particular edge
  // (hard constraint)
  std::vector<SeedID> Clauses;
  for (const auto &[_, Seeds] : SeedCoverage) {

    if (Seeds.empty()) continue;

    Clauses.clear();
    for (const auto &Seed : Seeds)
      Clauses.push_back(Seed);

    Solver.addClause(Clauses);

  }

  // Select the minimum number of seeds that cover a particular set of edges
  // (soft constraint)
  for (const auto &[Var, Seed] : SeedVars)
    Solver.addWeightedClause({-Var}, Weights[sys::path::filename(Seed)]);

  EndTimer();

  // ------------------------------------------------------------------------ //
  // Generate a solution
  // ------------------------------------------------------------------------ //

  StatMsg() << "Solving...\n";
  StartTimer();

  const bool Solved = Solver.solve();

  EndTimer();

  // ------------------------------------------------------------------------ //
  // Save the solution
  //
  // This will copy the selected seeds to the given output directory.
  // ------------------------------------------------------------------------ //

  SmallVector<StringRef, 64> Solution;
  SmallString<32>            InputSeed, OutputSeed;

  if (Solved) {

    for (const auto &[Var, Seed] : SeedVars)
      if (Solver.getValue(Var) > 0) Solution.push_back(Seed);

  } else {

    ErrMsg() << "Failed to find an optimal solution for '" << InputDir << "'\n";
    return 1;

  }

  StatMsg() << "Copying " << Solution.size() << " seeds to '" << OutputDir
            << "'...\n";
  StartTimer();

  SeedCount = 0;

  for (const auto &Seed : Solution) {

    InputSeed = SeedFiles[Seed];
    sys::path::append(InputSeed, Seed);

    OutputSeed = OutputDir;
    sys::path::append(OutputSeed, Seed);

    if ((EC = sys::fs::copy_file(InputSeed, OutputSeed))) {

      ErrMsg() << "Failed to copy '" << Seed << "' to '" << OutputDir
               << "': " << EC.message() << '\n';
      return 1;

    }

  }

  EndTimer();
  SuccMsg() << "Done!\n";

  return 0;

}

