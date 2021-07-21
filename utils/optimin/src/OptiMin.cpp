/*
 * OptiMin, an optimal fuzzing corpus minimizer.
 *
 * Author: Adrian Herrera
 */

#include <cstdint>
#include <vector>

#include <llvm/ADT/DenseSet.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/Support/Chrono.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/Program.h>
#include <llvm/Support/WithColor.h>

#include "EvalMaxSAT.h"
#include "ProgressBar.h"

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

/// Maps seed file paths to a weight
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

static sys::TimePoint<>     StartTime, EndTime;
static std::chrono::seconds Duration;

static std::string AFLShowmapPath;
static bool        TargetArgsHasAtAt = false;

static const auto ErrMsg = [] {
  return WithColor(errs(), HighlightColor::Error) << "[-] ";
};
static const auto WarnMsg = [] {
  return WithColor(errs(), HighlightColor::Warning) << "[-] ";
};
static const auto SuccMsg = [] {
  return WithColor(outs(), HighlightColor::String) << "[+] ";
};
static const auto StatMsg = [] {
  return WithColor(outs(), HighlightColor::Remark) << "[*] ";
};

static cl::opt<std::string>  CorpusDir("i", cl::desc("Input directory"),
                                      cl::value_desc("dir"), cl::Required);
static cl::opt<std::string>  OutputDir("o", cl::desc("Output directory"),
                                      cl::value_desc("dir"), cl::Required);
static cl::opt<bool>         EdgesOnly("f", cl::desc("Include edge hit counts"),
                               cl::init(true));
static cl::opt<bool>         ShowProgBar("p", cl::desc("Display progress bar"));
static cl::opt<std::string>  WeightsFile("w", cl::desc("Weights file"),
                                        cl::value_desc("csv"));
static cl::opt<std::string>  TargetProg(cl::Positional,
                                       cl::desc("<target program>"),
                                       cl::Required);
static cl::list<std::string> TargetArgs(cl::ConsumeAfter,
                                        cl::desc("[target args...]"));
static cl::opt<std::string>  MemLimit(
    "m", cl::desc("Memory limit for child process (default=none)"),
    cl::value_desc("megs"), cl::init("none"));
static cl::opt<std::string> Timeout(
    "t", cl::desc("Run time limit for child process (default=none)"),
    cl::value_desc("msec"), cl::init("none"));
static cl::opt<bool> CrashMode(
    "C", cl::desc("Keep crashing inputs, reject everything else"));
static cl::opt<bool> QemuMode("Q", cl::desc("Use binary-only instrumentation"));
}  // anonymous namespace

// -------------------------------------------------------------------------- //
// Helper functions
// -------------------------------------------------------------------------- //

static void GetWeights(const MemoryBuffer &MB, WeightsMap &Weights) {
  SmallVector<StringRef, 0> Lines;
  MB.getBuffer().trim().split(Lines, '\n');

  unsigned Weight = 0;

  for (const auto &Line : Lines) {
    const auto &[Seed, WeightStr] = Line.split(',');

    if (to_integer(WeightStr, Weight, 10)) {
      Weights.try_emplace(Seed, Weight);
    } else {
      WarnMsg() << "Failed to read weight for `" << Seed << "`. Skipping...\n";
    }
  }
}

[[nodiscard]] static std::error_code getAFLCoverage(const StringRef    Seed,
                                                    AFLCoverageVector &Cov) {
  Optional<StringRef> Redirects[] = {None, None, None};
  std::error_code     EC;

  // Create temporary output file
  SmallString<64> OutputPath;
  if (EC = sys::fs::createTemporaryFile("showmap", "txt", OutputPath))
    return EC;

  // Prepare afl-showmap arguments
  SmallVector<StringRef, 12> AFLShowmapArgs{
      AFLShowmapPath, "-m", MemLimit, "-t", Timeout, "-q", "-o", OutputPath};

  if (TargetArgsHasAtAt)
    AFLShowmapArgs.append({"-A", Seed});
  else
    Redirects[/* stdin */ 0] = Seed;

  if (QemuMode) AFLShowmapArgs.push_back("-Q");
  if (CrashMode) AFLShowmapArgs.push_back("-C");

  AFLShowmapArgs.append({"--", TargetProg});
  AFLShowmapArgs.append(TargetArgs.begin(), TargetArgs.end());

  // Run afl-showmap
  const int RC = sys::ExecuteAndWait(AFLShowmapPath, AFLShowmapArgs,
                                     /*env=*/None, Redirects);
  if (RC) return std::make_error_code(std::errc::executable_format_error);

  // Parse afl-showmap output
  const auto CovOrErr = MemoryBuffer::getFile(OutputPath);
  if (EC = CovOrErr.getError()) {
    sys::fs::remove(OutputPath);
    return EC;
  }

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

  return sys::fs::remove(OutputPath);
}

static inline void StartTimer(bool ShowProgBar) {
  StartTime = std::chrono::system_clock::now();
}

static inline void EndTimer(bool ShowProgBar) {
  EndTime = std::chrono::system_clock::now();
  Duration =
      std::chrono::duration_cast<std::chrono::seconds>(EndTime - StartTime);

  if (ShowProgBar)
    outs() << '\n';
  else
    outs() << Duration.count() << "s\n";
}

// -------------------------------------------------------------------------- //
// Main function
// -------------------------------------------------------------------------- //

int main(int argc, char *argv[]) {
  WeightsMap      Weights;
  ProgressBar     ProgBar;
  std::error_code EC;

  // ------------------------------------------------------------------------ //
  // Parse command-line options
  //
  // Also check the target arguments, as this determines how we run afl-showmap.
  // ------------------------------------------------------------------------ //

  cl::ParseCommandLineOptions(argc, argv, "Optimal corpus minimizer");

  if (!sys::fs::is_directory(OutputDir)) {
    ErrMsg() << "Invalid output directory `" << OutputDir << "`\n";
    return 1;
  }

  for (const auto &Arg : TargetArgs)
    if (Arg == "@@") TargetArgsHasAtAt = true;

  // ------------------------------------------------------------------------ //
  // Find afl-showmap
  // ------------------------------------------------------------------------ //

  const auto AFLShowmapOrErr = sys::findProgramByName("afl-showmap");
  if (AFLShowmapOrErr.getError()) {
    ErrMsg() << "Failed to find afl-showmap. Check your PATH\n";
    return 1;
  }
  AFLShowmapPath = *AFLShowmapOrErr;

  // ------------------------------------------------------------------------ //
  // Parse weights
  //
  // Weights are stored in CSV file mapping a seed file name to an integer
  // greater than zero.
  // ------------------------------------------------------------------------ //

  if (WeightsFile != "") {
    StatMsg() << "Reading weights from `" << WeightsFile << "`... ";
    StartTimer(/*ShowProgBar=*/false);

    const auto WeightsOrErr = MemoryBuffer::getFile(WeightsFile);
    if (EC = WeightsOrErr.getError()) {
      ErrMsg() << "Failed to read weights from `" << WeightsFile
               << "`: " << EC.message() << '\n';
      return 1;
    }

    GetWeights(*WeightsOrErr.get(), Weights);

    EndTimer(/*ShowProgBar=*/false);
  }

  // ------------------------------------------------------------------------ //
  // Traverse corpus directory
  //
  // Find the seed files inside this directory.
  // ------------------------------------------------------------------------ //

  StatMsg() << "Locating seeds in `" << CorpusDir << "`... ";
  StartTimer(/*ShowProgBar=*/false);

  std::vector<std::string> SeedFiles;
  sys::fs::file_status     Status;

  for (sys::fs::directory_iterator Dir(CorpusDir, EC), DirEnd;
       Dir != DirEnd && !EC; Dir.increment(EC)) {
    if (EC) {
      ErrMsg() << "Failed to traverse corpus directory `" << CorpusDir
               << "`: " << EC.message() << '\n';
      return 1;
    }

    const auto &Path = Dir->path();
    if (EC = sys::fs::status(Path, Status)) {
      WarnMsg() << "Failed to access seed file `" << Path
                << "`: " << EC.message() << ". Skipping...\n";
      continue;
    }

    switch (Status.type()) {
      case sys::fs::file_type::regular_file:
      case sys::fs::file_type::symlink_file:
      case sys::fs::file_type::type_unknown:
        SeedFiles.push_back(Path);
      default:
        /* Ignore */
        break;
    }
  }

  EndTimer(/*ShowProgBar=*/false);

  // ------------------------------------------------------------------------ //
  // Generate seed coverage
  //
  // Iterate over the corpus directory, which should contain seed files. Execute
  // these seeds in the target program to generate coverage information, and
  // then store this coverage information in the appropriate data structures.
  // ------------------------------------------------------------------------ //

  size_t       SeedCount = 0;
  const size_t NumSeeds = SeedFiles.size();

  if (!ShowProgBar)
    StatMsg() << "Generating coverage for " << NumSeeds << " seeds... ";
  StartTimer(ShowProgBar);

  EvalMaxSAT        Solver(/*nbMinimizeThread=*/0);
  MaxSATSeeds       SeedVars;
  MaxSATCoverageMap SeedCoverage;
  AFLCoverageVector Cov;

  for (const auto &SeedFile : SeedFiles) {
    // Execute seed
    Cov.clear();
    if (EC = getAFLCoverage(SeedFile, Cov)) {
      ErrMsg() << "Failed to get coverage for seed " << SeedFile << ": "
               << EC.message() << '\n';
      return 1;
    }

    // Create a variable to represent the seed
    const SeedID Var = Solver.newVar();
    SeedVars.push_back({Var, SeedFile});

    // Record the set of seeds that cover a particular edge
    for (const auto &[Edge, Freq] : Cov) {
      if (EdgesOnly) {
        // Ignore edge frequency
        SeedCoverage[Edge].insert(Var);
      } else {
        // Executing edge `E` `N` times means that it was executed `N - 1` times
        for (unsigned I = 0; I < Freq; ++I)
          SeedCoverage[MAX_EDGE_FREQ * Edge + I].insert(Var);
      }
    }

    if ((++SeedCount % 10 == 0) && ShowProgBar)
      ProgBar.update(SeedCount * 100 / NumSeeds, "Generating seed coverage");
  }

  EndTimer(ShowProgBar);

  // ------------------------------------------------------------------------ //
  // Set the hard and soft constraints in the solver
  // ------------------------------------------------------------------------ //

  if (!ShowProgBar) StatMsg() << "Generating constraints... ";
  StartTimer(ShowProgBar);

  SeedCount = 0;

  // Ensure that at least one seed is selected that covers a particular edge
  // (hard constraint)
  std::vector<SeedID> Clauses;
  for (const auto &[_, Seeds] : SeedCoverage) {
    if (Seeds.empty()) continue;

    Clauses.clear();
    for (const auto &Seed : Seeds)
      Clauses.push_back(Seed);

    Solver.addClause(Clauses);

    if ((++SeedCount % 10 == 0) && ShowProgBar)
      ProgBar.update(SeedCount * 100 / SeedCoverage.size(),
                     "Generating clauses");
  }

  // Select the minimum number of seeds that cover a particular set of edges
  // (soft constraint)
  for (const auto &[Var, Seed] : SeedVars)
    Solver.addWeightedClause({-Var}, Weights[sys::path::filename(Seed)]);

  EndTimer(ShowProgBar);

  // ------------------------------------------------------------------------ //
  // Generate a solution
  // ------------------------------------------------------------------------ //

  StatMsg() << "Solving... ";
  StartTimer(/*ShowProgBar=*/false);

  const bool Solved = Solver.solve();

  EndTimer(/*ShowProgBar=*/false);

  // ------------------------------------------------------------------------ //
  // Save the solution
  //
  // This will copy the selected seeds to the given output directory.
  // ------------------------------------------------------------------------ //

  SmallVector<StringRef, 64> Solution;
  SmallString<32>            OutputSeed;

  if (Solved) {
    for (const auto &[Var, Seed] : SeedVars)
      if (Solver.getValue(Var) > 0) Solution.push_back(Seed);
  } else {
    ErrMsg() << "Failed to find an optimal solution for `" << CorpusDir
             << "`\n";
    return 1;
  }

  SuccMsg() << "Minimized corpus size: " << Solution.size() << " seeds\n";

  if (!ShowProgBar) StatMsg() << "Copying to `" << OutputDir << "`... ";
  StartTimer(ShowProgBar);

  SeedCount = 0;

  for (const auto &Seed : Solution) {
    OutputSeed = OutputDir;
    sys::path::append(OutputSeed, sys::path::filename(Seed));

    if (EC = sys::fs::copy_file(Seed, OutputSeed)) {
      WarnMsg() << "Failed to copy `" << Seed << "` to `" << OutputDir
                << "`: " << EC.message() << '\n';
    }

    if ((++SeedCount % 10 == 0) && ShowProgBar)
      ProgBar.update(SeedCount * 100 / Solution.size(), "Copying seeds");
  }

  EndTimer(ShowProgBar);
  SuccMsg() << "Done!\n";

  return 0;
}
