// Adapted from afl-coverage-pass.cc

#include "common-llvm.h"

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
  #include <unistd.h>
  #include <sys/time.h>
#else
  #include <io.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include <list>
#include <string>
#include <fstream>

#include "llvm/Support/CommandLine.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/PseudoProbe.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/ConstantRange.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Support/FormatVariadic.h"

// Without this, Can't build with llvm-14 & old PM
#if LLVM_VERSION_MAJOR >= 14 && !defined(USE_NEW_PM)
  #include "llvm/Pass.h"
#endif

#if LLVM_VERSION_MAJOR > 3 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/DebugInfo.h"
  #include "llvm/IR/CFG.h"
#else
  #include "llvm/DebugInfo.h"
  #include "llvm/Support/CFG.h"
#endif

#ifndef STORFUZZ_MAP_SIZE
  #define STORFUZZ_MAP_SIZE 65536
#endif

#define DATA_MAP_SIZE STORFUZZ_MAP_SIZE

using namespace llvm;

// To enable: Add `-mllvm --debug_storfuzz_coverage` to cmd-line
static cl::opt<bool> Debug("debug_storfuzz_coverage", cl::desc("Debug prints"),
                           cl::init(false), cl::NotHidden);

namespace {

#ifdef USE_NEW_PM
class StorFuzzCoverage : public PassInfoMixin<StorFuzzCoverage> {

 public:
  StorFuzzCoverage() {

#else
class StorFuzzCoverage : public ModulePass {

 public:
  static char            ID;
  static llvm::StringRef name() {

    return "StorFuzzCoverage";

  }

  StorFuzzCoverage() : ModulePass(ID) {

#endif

  }

#ifdef USE_NEW_PM
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif

 protected:
  uint32_t map_size = DATA_MAP_SIZE;
  uint32_t function_minimum_size = 1;

  bool getInsertionPointInSameBB(Instruction          *start,
                                 BasicBlock::iterator &insertionPoint) {

    BasicBlock *insertionBB = start->getParent();
    insertionPoint = start->getIterator();
    BasicBlock::const_iterator End = insertionBB->end();
    // Safeguard against infinite loops due to logic errors on my side
    int i = 0;

    // Ensure that we are not already at the end of the BB
    if (insertionPoint == End) { return false; }
    ++insertionPoint;
    while (insertionPoint != End && i < insertionBB->size()) {

      if (!isa<PHINode>(*insertionPoint) && !insertionPoint->isEHPad()) {

        return true;

      } else if (insertionBB->isEntryBlock()) {

        while (insertionPoint != End && i < insertionBB->size() &&
               (isa<AllocaInst>(*insertionPoint) ||
                isa<DbgInfoIntrinsic>(*insertionPoint) ||
                isa<PseudoProbeInst>(*insertionPoint))) {

          if (const AllocaInst *AI = dyn_cast<AllocaInst>(&*insertionPoint)) {

            if (!AI->isStaticAlloca()) break;

          }

          i++;

        }

        return true;

      }

      insertionPoint++;
      i++;

    }

    if (i >= insertionBB->size()) {

      errs() << "ERROR: We have exceeded the size of the BB. The question is "
                "why?\n";
      errs() << "Start instr: " << start;
      errs() << "Insertion BB: " << insertionBB;
      return false;

    }

    return insertionPoint != End;

  }

  /* Function that we never instrument or analyze */
  /* Copied from cmplog pass */
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
        "ExecuteFilesOnyByOne",

    };

    for (auto const &ignoreListFunc : ignoreList) {

      if (F->getName().startswith(ignoreListFunc)) { return true; }

    }

    static constexpr const char *ignoreSubstringList[] = {

        "__asan",       "__msan",     "__ubsan", "__lsan",
        "__san",        "__sanitize", "__cxx",   "_GLOBAL__",
        "DebugCounter", "DwarfDebug", "DebugLoc"

    };

    for (auto const &ignoreListFunc : ignoreSubstringList) {

      // hexcoder: F->getName().contains() not avaiilable in llvm 3.8.0
      if (StringRef::npos != F->getName().find(ignoreListFunc)) { return true; }

    }

    return false;

  }

  static bool isSmallConstantAdditionOrSubtraction(Instruction *instr,
                                                   uint64_t smallConstant = 2) {

    if (instr->getOpcode() == Instruction::Add) {

      for (auto op : instr->operand_values()) {

        if (isa<ConstantInt>(op) &&
            (cast<ConstantInt>(op)->getValue().abs().ule(smallConstant))) {

          return true;

        }

      }

    } else if (instr->getOpcode() == Instruction::Sub) {

      // Only find those that subtract a small constant rather than those
      // that subtract FROM a small constant
      if (isa<ConstantInt>(instr->getOperand(1)) &&
          (cast<ConstantInt>(instr->getOperand(1))
               ->getValue()
               .abs()
               .ule(smallConstant)))
        return true;

    }

    return false;

  }

  // Weaken functions if requested (code by tholl)
  void maybeWeakenFunction(Module &M, Function &F) {

    StringSet WeakenFunctions;
    WeakenFunctions.insert("main");

    if (WeakenFunctions.contains(F.getName())) {

      auto        PreviousLinkage = F.getLinkage();
      std::string PreviousLinkageDescription = "";
      switch (PreviousLinkage) {

        // Appending linkage cannot be merged
        case GlobalValue::LinkageTypes::AppendingLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName()
                 << ", symbol has appending linkage\n";
          break;
          // These are weaker or equivalent to WeakAnyLinkage
        case GlobalValue::LinkageTypes::InternalLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName()
                 << ", symbol already has internal linkage\n";
          break;
        case GlobalValue::LinkageTypes::PrivateLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName()
                 << ", symbol already has private linkage\n";
          break;
        case GlobalValue::LinkageTypes::AvailableExternallyLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName()
                 << ", symbol is already marked as 'available externally'\n";
          break;
        case GlobalValue::LinkageTypes::WeakAnyLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName()
                 << ", symbol is already marked as weak\n";
          break;
        case GlobalValue::LinkageTypes::LinkOnceAnyLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName()
                 << ", symbol is already marked as link-once\n";
          break;
        case GlobalValue::LinkageTypes::ExternalWeakLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName()
                 << ", symbol is already marked as weak and extern\n";
          break;
        case GlobalValue::LinkageTypes::CommonLinkage:
          errs() << "Cannot weaken " << F.getName() << " in " << M.getName()
                 << ", function is marked as common (this should not be "
                    "possible!)\n";
          break;
          // These must be weakened.
        case GlobalValue::LinkageTypes::ExternalLinkage:
          PreviousLinkageDescription = "external";
          break;
        case GlobalValue::LinkageTypes::LinkOnceODRLinkage:
          PreviousLinkageDescription = "link-once (ODR)";
          break;
        case GlobalValue::LinkageTypes::WeakODRLinkage:
          PreviousLinkageDescription = "weak (ODR)";
          break;

      }

      if (!PreviousLinkageDescription.empty()) {

        errs() << "Dropping linkage of " << F.getName() << " in " << M.getName()
               << " from " << PreviousLinkageDescription
               << " to weak linkage\n";
        F.setLinkage(GlobalValue::LinkageTypes::WeakAnyLinkage);
        GlobalAlias::create(F.getType(), /* AddrSpace = */ 0, PreviousLinkage,
                            "__storfuzz_original_" + F.getName(), &F, &M);

      }

    }

  }

  // Value.printNameOrAsOperand is only available in debug builds
  std::string printNameOrAsOperandInRelease(Value *value, Module *M = nullptr,
                                            bool printType = true) {

    assert(value != nullptr);
    if (!value->getName().empty()) return std::string(value->getName());

    std::string        BBName;
    raw_string_ostream OS(BBName);
    value->printAsOperand(OS, printType, M);
    return OS.str();

  }

  // Returns the given value, if it does not have to be uncasted
  Value *uncast(Value *value, bool emit_log = false) {

    assert(value != nullptr);
    CastInst *castInstruction = nullptr;
    Value    *uncastedValue = value;

    // As long as the uncasted value is a CastInst, we can uncast it
    while ((castInstruction = dyn_cast<CastInst>(uncastedValue))) {

      // Get the value before the cast
      uncastedValue = castInstruction->getOperand(0);

    }

    return uncastedValue;

  }

  bool isLoopCtr(LoopInfo *loopInfo, Value *potentialLoopCtr,
                 Value *potentialLoopCtrLocation) {

    // This detection is not complete, it may miss loop counters.
    if (loopInfo == nullptr) {

      errs() << "WARNING: This analysis requires the result of LoopAnalysis\n";
      return false;

    }

    Value       *actualDef = uncast(potentialLoopCtr);
    Instruction *actualDefInst = dyn_cast<Instruction>(actualDef);

    bool is_loop_ctr = false;
    if (actualDefInst &&
        isSmallConstantAdditionOrSubtraction(actualDefInst, 8)) {

      // Skip loop_ctrs
      // If the potentialLoopCtr, its uncasted value or the store location of
      // the potentialLoopCtr are part of a latch cmp instruction in any loop
      // containing the respective basic block, we have discovered a loop
      // counter
      auto loop = loopInfo->getLoopFor(actualDefInst->getParent());

      while (loop && !is_loop_ctr) {

        auto cmp_instr = loop->getLatchCmpInst();
        if (cmp_instr) {

          for (auto val : cmp_instr->operand_values()) {

            // Easy case
            if (val == actualDef || val == potentialLoopCtr ||
                val == potentialLoopCtrLocation) {

              is_loop_ctr = true;

            }

            // Allow for one level of indirection
            if (isa<Instruction>(val)) {

              // We can cast directly due to the check above
              for (auto indirect_val :
                   cast<Instruction>(val)->operand_values()) {

                if (indirect_val == actualDef ||
                    indirect_val == potentialLoopCtr ||
                    indirect_val == potentialLoopCtrLocation) {

                  is_loop_ctr = true;
                  break;

                }

              }

            }

          }

        }

        loop = loop->getParentLoop();

      }

    }

    return is_loop_ctr;

  }

};

}  // namespace

#ifdef USE_NEW_PM
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "StorFuzzCoverage", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

  #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
  #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {

                  MPM.addPass(StorFuzzCoverage());

                });

            // Allow for testing with opt
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {

                  if (Name == "StorFuzzCoverage") {

                    MPM.addPass(StorFuzzCoverage());
                    return true;

                  }

                  return false;

                });

          }};

}

#else

char StorFuzzCoverage::ID = 1;
#endif

#ifdef USE_NEW_PM
PreservedAnalyses StorFuzzCoverage::run(Module &M, ModuleAnalysisManager &MAM) {

#else
bool StorFuzzCoverage::runOnModule(Module &M) {

#endif
  // Magic needed to get some pre-build checks to pass
  if (getenv("CONFIGURE_MODE")) {

    errs() << "WARNING: CONFIGURE_MODE, not doing anything\n";
#ifdef USE_NEW_PM
    return PreservedAnalyses::all();
#else
    return true;
#endif

  }

  // DO SETUP
  LLVMContext &C = M.getContext();

  Type *VoidTy = Type::getVoidTy(C);

  IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  IntegerType *Int64Ty = IntegerType::getInt64Ty(C);
  Type        *Int8PtrTy = PointerType::getUnqual(IntegerType::getInt8Ty(C));
  Type        *Int16PtrTy = PointerType::getUnqual(IntegerType::getInt16Ty(C));
  Type        *Int32PtrTy = PointerType::getUnqual(IntegerType::getInt32Ty(C));
  Type        *Int64PtrTy = PointerType::getUnqual(IntegerType::getInt64Ty(C));
  Type *Int128PtrTy = PointerType::getUnqual(IntegerType::getInt128Ty(C));

  uint32_t     rand_seed;
  unsigned int cur_loc = 0;

#ifdef USE_NEW_PM
  auto PA = PreservedAnalyses::none();
  // See here:
  // https://github.com/AFLplusplus/AFLplusplus/blob/358cd1b062e58ce1d5c8efeef4789a5aca7ac5a9/instrumentation/SanitizerCoveragePCGUARD.so.cc#L236

  auto &FAM = MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
#else
  errs() << "WARNING: without new pass manager, we do not support certain "
            "analyses!\n";
#endif

  /* Setup random() so we get Actually Random(TM) */
  rand_seed = time(NULL);
  srand(rand_seed);

  GlobalVariable *StorFuzzMapPtr = new GlobalVariable(
      M, PointerType::getUnqual(Int8Ty), false,
      GlobalValue::ExternalWeakLinkage, nullptr, "__storfuzz_area_ptr");

  // other constants we need
  ConstantInt *Mask[8] = {

      ConstantInt::get(Int8Ty, 1 << 0), ConstantInt::get(Int8Ty, 1 << 1),
      ConstantInt::get(Int8Ty, 1 << 2), ConstantInt::get(Int8Ty, 1 << 3),
      ConstantInt::get(Int8Ty, 1 << 4), ConstantInt::get(Int8Ty, 1 << 5),
      ConstantInt::get(Int8Ty, 1 << 6), ConstantInt::get(Int8Ty, 1 << 7)};

  // Threshold used to determine whether a bb should be instrumented
  auto THRESHOLD = 0;
  if (auto env_str = getenv("MAX_STORES_PER_BB")) { THRESHOLD = atoi(env_str); }
  if (THRESHOLD <= 0) {

    THRESHOLD = 9;  // Default to 9

  }

  assert(isPowerOf2_32(map_size));

  auto REDUCTION_WIDTH = 0;
  if (auto env_str = getenv("VALUE_REDUCTION_WIDTH")) {

    REDUCTION_WIDTH = atoi(env_str);

  }

  if (REDUCTION_WIDTH <= 0) {

    REDUCTION_WIDTH = 8;  // StorFuzz default is 8

  }

  assert(map_size * 8 >= (1 << REDUCTION_WIDTH) * 4096);
  // SETUP DONE

  /* Instrument all the things! */

  int inst_stores = 0;

  for (auto &F : M) {

    maybeWeakenFunction(M, F);
    if (Debug)
      errs() << "FUNCTION: " << F.getName() << " size=" << F.size() << "\n";
    if (isIgnoreFunction(&F)) {

      if (Debug) errs() << "Ignoring function " << F.getName() << "\n";
      continue;

    }

    // Bail out quickly
    if (F.onlyReadsMemory()) {

      errs() << "FUNCTION: " << F.getName() << " does not write to memory\n";
      continue;

    }

    if (F.size() < function_minimum_size) { continue; }
    LoopInfo *loopInfo = nullptr;
#ifdef USE_NEW_PM
    auto *LVI = &FAM.getResult<LazyValueAnalysis>(F);
    (void)LVI;
    loopInfo = &FAM.getResult<LoopAnalysis>(F);
#endif
    // The number of potentially interesting stores in a function may be
    // different from the number of instrumented stores due to the
    // MAX_STORES_PER_BB threshold
    auto potentially_interesting_stores_in_func = 0;
    auto instrumented_stores_in_func = 0;

    SmallDenseMap<BasicBlock *, uint16_t> stores_per_bb(8);

    // Pass over each block twice and only instrument it when it has fewer than
    // <THRESHOLD> stores
    for (int pass = 0; pass < 2; pass++) {

      bool instrument_this_time = (pass == 1);

      if (instrument_this_time) {

        if (stores_per_bb.empty()) {

          errs() << "ERROR: Could not find info on any BB in '" << M.getName()
                 << ": " << F.getName() << "\n";
          break;

        }

        for (auto &pair : stores_per_bb) {

          potentially_interesting_stores_in_func += pair.getSecond();
          if (pair.getSecond() <= THRESHOLD)
            instrumented_stores_in_func += pair.getSecond();

        }

      }

      for (auto &BB : F) {

        BasicBlock::iterator insertionPoint = BB.getFirstInsertionPt();
        IRBuilder<>          IRB(&(*insertionPoint));

        uint16_t BB_store_count = 0;

        if (instrument_this_time) {

          auto stores_in_this_bb = 0;
          if (stores_per_bb.count(&BB) != 0) {

            stores_in_this_bb = stores_per_bb.find(&BB)->getSecond();

          } else {

            errs() << "ERROR: Could not find info on '" << M.getName() << ": "
                   << F.getName() << ": " << BB.getName() << "\n";

          }

          // Bail out if there are no stores to instrument in the current basic
          // block
          if (stores_in_this_bb == 0) { continue; }
          // Bail out if there are too many stores in this BB
          if (stores_in_this_bb > THRESHOLD) {

            dbgs() << "DEBUG: Not instrumenting '" << M.getName() << ": "
                   << F.getName() << ": " << BB.getName()
                   << "' because it has more than " << THRESHOLD << " stores\n";
            continue;

          }

        }

        for (auto &instr : BB) {

          StoreInst *storeInst;
          if ((storeInst = dyn_cast<StoreInst>(&instr))) {

            // Check that this instruction is not already part of AFL
            // instrumentation
            if (storeInst->getMetadata("nosanitize") != nullptr) continue;

            // Don't instrument stores to alloca'd locations
            Value *storeLocation = storeInst->getPointerOperand();
            if (!(dyn_cast<AllocaInst>(storeLocation))) {

              Value *storedValue;
              storedValue = storeInst->getValueOperand();

              Instruction *valueDefInstruction;
              // If the stored value does not stem from an instruction it is not
              // interesting
              if (!(valueDefInstruction = dyn_cast<Instruction>(storedValue)))
                continue;

              // We are only interested in stores of integer typed values
              IntegerType *storedType;
              if ((storedType =
                       dyn_cast<IntegerType>(storedValue->getType()))) {

                // Try to get the value before the cast, if the stored value
                // does not stem from an instruction it is not interesting
                Instruction *actual_valueDefInstruction;
                Value       *actual_storedValue =
                    uncast(storedValue, !instrument_this_time);
                if (!(actual_valueDefInstruction =
                          dyn_cast<Instruction>(actual_storedValue)))
                  continue;

                // Skip direct copies (modulo truncation/extension)
                if (isa<LoadInst, VAArgInst>(actual_valueDefInstruction) &&
                    !getenv("STORFUZZ_INSTRUMENT_MEM2MEM_COPY")) {

                  continue;

                } else if (isLoopCtr(loopInfo, storedValue, storeLocation)) {

                  continue;

                }

                // If the type we started casting from, was not an integer, we
                // don't want it
                IntegerType *actual_storedType;
                if (!(actual_storedType = dyn_cast<IntegerType>(
                          actual_storedValue->getType()))) {

                  continue;

                }

                Value   *CurLoc;
                uint32_t bitmask_selector;

                // Handle phi node as store_location (stores to different
                // locations are considered seperately)
                auto storeLocationToID = DenseMap<Value *, ConstantInt *>(4);

                // We only ever change anything in the second pass
                if (!instrument_this_time) {

                  if ((isa<PHINode>(storeLocation))) {

                    PHINode *storeLocationPhi =
                        dyn_cast<PHINode>(storeLocation);
                    for (uint32_t i = 0;
                         i < storeLocationPhi->getNumIncomingValues(); i++) {

                      // Use as a simple set, we only care about the number of
                      // different store locations
                      auto curLocIDIter = storeLocationToID.find(
                          storeLocationPhi->getIncomingValue(i));
                      if (curLocIDIter == storeLocationToID.end()) {

                        storeLocationToID.insert(
                            std::pair<Value *, ConstantInt *>(
                                storeLocationPhi->getIncomingValue(i),
                                nullptr));
                        BB_store_count++;

                      }  // If we did not record the store location yet

                    }  // For incoming value in store location phi node

                  }  // ! instrument_this_time && is_phi_node

                  else {  // ! instrument_this_tume && ! is_phi_node
                    BB_store_count++;

                  }

                } else {  // If instrument_this_time

                  if ((isa<PHINode>(storeLocation))) {

                    PHINode *storeLocationPhi =
                        dyn_cast<PHINode>(storeLocation);
                    insertionPoint = storeLocationPhi->getIterator();
                    while (insertionPoint !=
                               storeLocationPhi->getParent()->end() &&
                           isa<PHINode>(*insertionPoint)) {

                      insertionPoint++;

                    }

                    assert(insertionPoint !=
                           storeLocationPhi->getParent()->end());
                    IRB.SetInsertPoint(storeLocationPhi->getParent(),
                                       insertionPoint);

                    PHINode *CurLocPhi = IRB.CreatePHI(
                        Int32Ty, storeLocationPhi->getNumIncomingValues());
                    for (uint32_t i = 0;
                         i < storeLocationPhi->getNumIncomingValues(); i++) {

                      // E.g.:
                      // %x.sink30 = phi ptr [ @x, %sw.bb9 ], [ @x, %sw.bb7 ], [
                      // @y, %sw.bb6 ], [ @y, %while.body ] %74 = phi i32 [
                      // 12312, %sw.bb9 ], [ 12312, %sw.bb7 ], [ 45645, %sw.bb6
                      // ], [ 45645, %while.body ]
                      ConstantInt *curLocID;
                      auto         curLocIDIter = storeLocationToID.find(
                          storeLocationPhi->getIncomingValue(i));
                      if (curLocIDIter == storeLocationToID.end()) {

                        // Use globally unique identifiers
                        curLocID =
                            ConstantInt::get(Int32Ty, RandBelow(map_size));

                        BB_store_count++;

                        storeLocationToID.insert(
                            std::pair<Value *, ConstantInt *>(
                                storeLocationPhi->getIncomingValue(i),
                                curLocID));

                      } else {

                        curLocID = curLocIDIter->getSecond();

                      }

                      CurLocPhi->addIncoming(
                          curLocID, storeLocationPhi->getIncomingBlock(i));

                    }

                    CurLoc = CurLocPhi;

                  } else {  // if store location is not a PHI

                    /* Make up globally unique location_id */
                    cur_loc = RandBelow(map_size);
                    CurLoc = ConstantInt::get(Int32Ty, cur_loc);
                    BB_store_count++;

                  }  // if store location is not a PHI

                  bitmask_selector = RandBelow(8);

                  // Get a valid insert point (ideally directly after the value
                  // definition)
                  if ((isa<PHINode>(storeLocation)) ||
                      !getInsertionPointInSameBB(valueDefInstruction,
                                                 insertionPoint)) {

                    if (!(isa<PHINode>(storeLocation))) {

                      errs()
                          << "WARNING: Could not find insertion point in BB of "
                             "value definition function '"
                          << F.getName() << "'val: " << storedValue << "\n";

                    }

                    if (!getInsertionPointInSameBB(storeInst, insertionPoint)) {

                      // We failed to find an insertion point both close to
                      // definition and store, what now???
                      errs() << "ERROR: Could not find insertion point in "
                                "function '"
                             << F.getName() << "' val: " << storedValue << "\n";
                      assert(0);

                    }

                  }

                  BasicBlock *insertionBB = (*insertionPoint).getParent();
                  IRB.SetInsertPoint(insertionBB, insertionPoint);

                  Value *mask = Mask[bitmask_selector];

                  Value *ReducedValue;
                  Value *Lower16Bit =
                      IRB.CreateZExtOrTrunc(storedValue, IRB.getInt16Ty());

                  if (REDUCTION_WIDTH == 8) {

                    Value *Upper8Bit = IRB.CreateZExtOrTrunc(
                        IRB.CreateLShr(Lower16Bit, 8), IRB.getInt8Ty());
                    Value *Lower8Bit =
                        IRB.CreateZExtOrTrunc(Lower16Bit, IRB.getInt8Ty());

                    ReducedValue = IRB.CreateXor(Upper8Bit, Lower8Bit);

                  } else if (REDUCTION_WIDTH == 4) {

                    Value *Upper8Bit = IRB.CreateZExtOrTrunc(
                        IRB.CreateLShr(Lower16Bit, 8), IRB.getInt8Ty());
                    Value *Lower8Bit =
                        IRB.CreateZExtOrTrunc(Lower16Bit, IRB.getInt8Ty());

                    Value *halfReduction = IRB.CreateXor(Upper8Bit, Lower8Bit);
                    ReducedValue =
                        IRB.CreateXor(IRB.CreateAnd(halfReduction, 0xF),
                                      IRB.CreateLShr(halfReduction, 4));

                  } else if (REDUCTION_WIDTH == 12) {

                    // 12 bit (leaving lower and upper 4 bit unchanged):
                    // reduced = (((val & 0xFF00) >> 4) ^ (val & 0xFF)) & 0xFFF

                    auto temp =
                        IRB.CreateLShr(IRB.CreateAnd(Lower16Bit, 0xFF00), 4);
                    auto temp2 = IRB.CreateAnd(Lower16Bit, 0xFF);

                    ReducedValue =
                        IRB.CreateAnd(IRB.CreateXor(temp, temp2), 0xFFF);

                  } else if (REDUCTION_WIDTH == 16) {

                    ReducedValue = Lower16Bit;

                  } else {

                    assert(false && "This is an unsupported REDUCTION_WIDTH\n");

                  }

                  // Get Map location
                  LoadInst *MapPtrLoad = IRB.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
                      PointerType::get(Int8Ty, 0),
#endif
                      StorFuzzMapPtr);
                  MapPtrLoad->setMetadata(M.getMDKindID("nosanitize"),
                                          MDNode::get(C, None));

                  // Calculate Index in map
                  Value *MapPtrIdx;
                  MapPtrIdx = IRB.CreateGEP(
#if LLVM_VERSION_MAJOR >= 14
                      Int8Ty,
#endif
                      MapPtrLoad,
                      IRB.CreateXor(CurLoc,
                                    IRB.CreateZExtOrTrunc(ReducedValue,
                                                          IRB.getInt32Ty())));
                  dyn_cast<Instruction>(MapPtrIdx)->setMetadata(
                      M.getMDKindID("storfuzz_calc_index"),
                      MDNode::get(C, None));
                  if (getenv("STORFUZZ_VERBOSE")) {

                    errs() << "MapPtrIdx: " << MapPtrIdx
                           << "\ninsertion BB: " << insertionBB << "\n";

                  }

                  // Write to map
                  IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Or, MapPtrIdx,
                                      mask,
#if LLVM_VERSION_MAJOR >= 13
                                      llvm::MaybeAlign(1),
#endif
                                      llvm::AtomicOrdering::Monotonic);

                }  // If instrument_this_time

              }  // If stored value is an integer

            }  // If storeLocation is no alloc

          }  // if instr is store

        }  // Iter instructions in BB

        // Don't skew statistics if we didn't instrument anything
        if (!instrument_this_time) {

          if (stores_per_bb.count(&BB) != 0) {

            errs() << "ERROR: BB already in stores_per_bb map " << M.getName()
                   << ": " << F.getName() << ": " << BB.getName() << "\n";

          }

          stores_per_bb.insert(std::pair(&BB, BB_store_count));

          BB_store_count = 0;

        } else {

          inst_stores += BB_store_count;

        }

      }  // Iter BBs in Func

    }  // Pass over each block twice

  }  // Iter Funcs in Module

  outs() << "StorFuzz on '" << M.getName() << "': Instrumented " << inst_stores
         << " targets\n";
#ifdef USE_NEW_PM
  return PA;
#else
  return true;
#endif

}

#ifndef USE_NEW_PM
static void registerStorFuzzPass(const PassManagerBuilder &,
                                 legacy::PassManagerBase &PM) {

  PM.add(new StorFuzzCoverage());

}

static RegisterStandardPasses RegisterStorFuzzPass(
    PassManagerBuilder::EP_OptimizerLast, registerStorFuzzPass);

static RegisterStandardPasses RegisterStorFuzzPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerStorFuzzPass);
#endif

