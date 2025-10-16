/*
   american fuzzy lop++ - LLVM IJON instrumentation pass
   -----------------------------------------------------

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <list>
#include <string>
#include <fstream>
#include <set>

// Include LLVM headers first to avoid macro conflicts
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/OptimizationLevel.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Intrinsics.h"
#if LLVM_MAJOR >= 16
  #include "llvm/TargetParser/Triple.h"
#else
  #include "llvm/ADT/Triple.h"
#endif
#include "llvm/Transforms/Utils/ModuleUtils.h"

// Now include AFL++ headers
#include "afl-llvm-common.h"
#include "llvm-alternative-coverage.h"

using namespace llvm;

namespace {

class IJONInstrumentation : public PassInfoMixin<IJONInstrumentation> {

 public:
  IJONInstrumentation() {

    initInstrumentList();

  }

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);

 private:
  int      instrumentFunction(Function &F);
  uint32_t generateLocationHash(CallInst *call, uint32_t call_index);
  void     transformIJONMaxCall(CallInst *call, uint32_t call_index);
  void     transformIJONSetCall(CallInst *call, uint32_t call_index);
  void     transformIJONIncCall(CallInst *call, uint32_t call_index);

  void   createIJONMaxVariadicFunction(Module &M);
  Value *castToInt64(Value *V, IRBuilder<> &IRB);

  // Counters for different IJON call types
  int ijon_max_calls = 0;
  int ijon_set_calls = 0;
  int ijon_inc_calls = 0;
  int ijon_state_calls = 0;

};

}  // namespace

PreservedAnalyses IJONInstrumentation::run(Module                &M,
                                           ModuleAnalysisManager &MAM) {

  /* Show a banner */

  setvbuf(stdout, NULL, _IONBF, 0);

  if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {

    printf("afl-llvm-ijon-pass" VERSION "\n");

  } else if (getenv("AFL_QUIET"))

    be_quiet = 1;

  /* Create the ijon_max_variadic and ijon_set functions if they don't exist */
  createIJONMaxVariadicFunction(M);

  // Create the ijon_set function: void ijon_set(uint32_t addr, uint32_t val)
  LLVMContext &Context = M.getContext();

  FunctionType *ijonSetFT = FunctionType::get(
      Type::getVoidTy(Context),
      {Type::getInt32Ty(Context), Type::getInt32Ty(Context)},  // addr, val
      false                                                    // not variadic
  );
  (void)Function::Create(ijonSetFT, Function::ExternalLinkage, "ijon_set", &M);

  // Create runtime utility functions that IJON macros depend on
  // ijon_strdist function: uint32_t ijon_strdist(char* a, char* b)

#if LLVM_MAJOR >= 20
  Type *PtrTy = PointerType::getUnqual(Context);
#else
  Type *Int8Ty = Type::getInt8Ty(Context);
  Type *PtrTy = PointerType::get(Int8Ty, 0);
#endif

  FunctionType *strdistFT = FunctionType::get(Type::getInt32Ty(Context),
                                              {PtrTy, PtrTy},  // char*, char*
                                              false            // not variadic
  );
  (void)Function::Create(strdistFT, Function::ExternalLinkage, "ijon_strdist",
                         &M);

  // ijon_hashstack function: uint32_t ijon_hashstack(void)
  FunctionType *hashstackFT =
      FunctionType::get(Type::getInt32Ty(Context), {},  // no arguments
                        false                           // not variadic
      );
  (void)Function::Create(hashstackFT, Function::ExternalLinkage,
                         "ijon_hashstack", &M);

  // ijon_hashint function: uint32_t ijon_hashint(uint32_t old, uint32_t val)
  FunctionType *hashintFT =
      FunctionType::get(Type::getInt32Ty(Context),
                        {Type::getInt32Ty(Context),
                         Type::getInt32Ty(Context)},  // uint32_t, uint32_t
                        false                         // not variadic
      );
  (void)Function::Create(hashintFT, Function::ExternalLinkage, "ijon_hashint",
                         &M);

  // Create the ijon_inc function: void ijon_inc(uint32_t addr, uint32_t val)
  FunctionType *ijonIncFT = FunctionType::get(
      Type::getVoidTy(Context),
      {Type::getInt32Ty(Context), Type::getInt32Ty(Context)},  // addr, val
      false                                                    // not variadic
  );
  (void)Function::Create(ijonIncFT, Function::ExternalLinkage, "ijon_inc", &M);

  // Create the ijon_xor_state function: void ijon_xor_state(uint32_t val)
  FunctionType *ijonXorStateFT = FunctionType::get(
      Type::getVoidTy(Context), {Type::getInt32Ty(Context)},  // val
      false                                                   // not variadic
  );
  (void)Function::Create(ijonXorStateFT, Function::ExternalLinkage,
                         "ijon_xor_state", &M);

  /* Instrument all the things! */

  int inst_blocks = 0;

  for (auto &F : M) {

    int calls_in_function = instrumentFunction(F);
    if (calls_in_function > 0) { inst_blocks++; }

  }

  if (!inst_blocks) {

    // This is normal during linking phase
    if (getenv("AFL_IJON_VERBOSE")) {

      printf("IJON pass: No functions to process (normal during linking)\n");

    }

  } else {

    printf("IJON pass: Found %d functions to process\n", inst_blocks);

    int total_calls =
        ijon_max_calls + ijon_set_calls + ijon_inc_calls + ijon_state_calls;

    if (total_calls > 0) {

      printf("Instrumented %d IJON calls for tracking", total_calls);
      if (ijon_max_calls > 0) printf(" (IJON_MAX: %d)", ijon_max_calls);
      if (ijon_set_calls > 0) printf(" (IJON_SET: %d)", ijon_set_calls);
      if (ijon_inc_calls > 0) printf(" (IJON_INC: %d)", ijon_inc_calls);
      if (ijon_state_calls > 0) printf(" (IJON_STATE: %d)", ijon_state_calls);
      printf(".\n");

      if (M.getGlobalVariable("__afl_ijon_enabled", true) == nullptr) {

        // Always create __afl_ijon_enabled for IJON memory allocation
        IRBuilder<> IRB(M.getContext());
        Constant   *One32 = ConstantInt::get(IRB.getInt32Ty(), 1);
        new GlobalVariable(M, IRB.getInt32Ty(), false,
                           GlobalValue::ExternalLinkage, One32,
                           "__afl_ijon_enabled");

      }

    } else {

      printf("No IJON calls found to instrument.\n");

    }

  }

  return PreservedAnalyses::none();

}

void IJONInstrumentation::createIJONMaxVariadicFunction(Module &M) {

  LLVMContext &Context = M.getContext();

  // Create the ijon_max_variadic function: void ijon_max_variadic(uint32_t
  // addr, ...)
  FunctionType *ijonMaxVariadicFT = FunctionType::get(
      Type::getVoidTy(Context),
      {Type::getInt32Ty(Context)},  // First parameter: address/location hash
      true                          // Variadic function
  );
  (void)Function::Create(ijonMaxVariadicFT, Function::ExternalLinkage,
                         "ijon_max_variadic", &M);

}

int IJONInstrumentation::instrumentFunction(Function &F) {

  if (!isInInstrumentList(&F, FMNAME)) return 0;
  if (F.size() < 1) return 0;

  int calls_processed = 0;
  (void)F.getContext();  // Suppress unused variable warning

  // Get the ijon_max_variadic function
  Function *ijonMaxVariadicFunc =
      F.getParent()->getFunction("ijon_max_variadic");

  if (!ijonMaxVariadicFunc) {

    printf("ERROR: ijon_max_variadic function not found!\n");
    return 0;

  }

  // Collect calls to transform first, then transform them
  std::vector<CallInst *> callsToTransform;

  // Iterate through all instructions in the function
  for (auto &BB : F) {

    for (auto &I : BB) {

      // Look for CallInst that might be ijon_max calls
      if (CallInst *call = dyn_cast<CallInst>(&I)) {

        // Check if this is a call to a function named "ijon_max"
        Value *calledValue = call->getCalledOperand();
        if (Function *calledFunc = dyn_cast<Function>(calledValue)) {

          if (calledFunc->getName() == "ijon_max" ||
              calledFunc->getName() == "ijon_max_variadic" ||
              calledFunc->getName() == "ijon_set" ||
              calledFunc->getName() == "ijon_inc" ||
              calledFunc->getName() == "ijon_xor_state") {

            // Check argument count
            unsigned argCount = call->arg_size();

            // Skip if already transformed (has location hash as first argument)
            bool alreadyTransformed = false;
            if (calledFunc->getName() == "ijon_max_variadic" && argCount >= 2) {

              // Check if the first argument is a constant (location hash)
              if (isa<ConstantInt>(call->getArgOperand(0))) {

                alreadyTransformed = true;

              }

            }

            if (!alreadyTransformed && argCount >= 1) {

              callsToTransform.push_back(call);

            } else if (alreadyTransformed) {

            }

          }

        } else {

          // Check if it's an indirect call that might be to ijon_max
          std::string        callStr;
          raw_string_ostream rso(callStr);
          call->print(rso);
          if (callStr.find("ijon_max") != std::string::npos ||
              callStr.find("ijon_set") != std::string::npos ||
              callStr.find("ijon_inc") != std::string::npos ||
              callStr.find("ijon_xor_state") != std::string::npos) {

            unsigned argCount = call->arg_size();
            if (argCount >= 1) { callsToTransform.push_back(call); }

          }

        }

      }

    }

  }

  // Now transform all the collected calls
  for (uint32_t i = 0; i < callsToTransform.size(); i++) {

    // Check if this is an ijon_set call or ijon_max call
    CallInst *call = callsToTransform[i];
    Value    *calledValue = call->getCalledOperand();
    if (Function *calledFunc = dyn_cast<Function>(calledValue)) {

      if (calledFunc->getName() == "ijon_set") {

        transformIJONSetCall(call, i);
        ijon_set_calls++;

      } else if (calledFunc->getName() == "ijon_inc") {

        transformIJONIncCall(call, i);
        ijon_inc_calls++;

      } else if (calledFunc->getName() == "ijon_xor_state") {

        // For ijon_xor_state, we don't transform - just count and pass through
        ijon_state_calls++;

      } else {

        transformIJONMaxCall(call, i);
        ijon_max_calls++;

      }

    } else {

      transformIJONMaxCall(call, i);  // Default to max transformation
      ijon_max_calls++;

    }

    calls_processed++;

  }

  return calls_processed;

}

uint32_t IJONInstrumentation::generateLocationHash(CallInst *call,
                                                   uint32_t  call_index) {

  // Use a deterministic hash based on source file path, line number, column,
  // and call index
  uint32_t hash = 0xdeadbeef;  // Default hash

  DebugLoc DL = call->getDebugLoc();
  if (DL) {

    // Use line number as primary component
    uint32_t line = DL.getLine() ? DL.getLine() : 0;
    uint32_t column = DL.getCol() ? DL.getCol() : 0;
    hash = line * 0x9e3779b1 + column;

    // Add source file path for better uniqueness
    if (DL.getScope()) {

      if (MDNode *scopeNode = DL.getScope()) {

        if (DIScope *scope = dyn_cast<DIScope>(scopeNode)) {

          // Get the file path
          if (DIFile *file = scope->getFile()) {

            std::string file_path = file->getFilename().str();
            for (char c : file_path) {

              hash = hash * 0x9e3779b1 + (uint32_t)c;

            }

          }

        }

      }

    }

  } else {

    // Fallback to call index if no debug info
    hash = (call_index + 0x12345678) * 0x9e3779b1;

  }

  // ALWAYS incorporate call_index to ensure each call site is unique
  hash = hash * 0x9e3779b1 + call_index;

  return hash;

}

void IJONInstrumentation::transformIJONMaxCall(CallInst *call,
                                               uint32_t  call_index) {

  IRBuilder<> IRB(call);

  // Get the number of arguments
  unsigned argCount = call->arg_size();

  // Get the ijon_max_variadic function
  Function *ijonMaxVariadicFunc =
      call->getParent()->getParent()->getParent()->getFunction(
          "ijon_max_variadic");

  if (!ijonMaxVariadicFunc) {

    printf("ERROR: ijon_max_variadic function not found!\n");
    return;

  }

  // Build arguments for ijon_max_variadic preserving the macro's location hash
  std::vector<Value *> args;

  // First argument: preserve the original location hash from the macro (if
  // available) For IJON_MAX macro calls, the first argument should be the
  // macro's location hash
  if (argCount > 0) {

    Value *firstArg = call->getArgOperand(0);
    if (firstArg->getType()->isIntegerTy()) {

      // This looks like it came from IJON_MAX macro - preserve the location
      // hash
      args.push_back(IRB.CreateIntCast(
          firstArg, Type::getInt32Ty(call->getContext()), false));

      // Add the remaining arguments (skip the first one as it's the location
      // hash)
      for (unsigned i = 1; i < argCount; i++) {

        Value *arg = castToInt64(call->getArgOperand(i), IRB);
        args.push_back(arg);

      }

    } else {

      // Direct call or non-integer first arg - generate location hash and
      // include all args
      uint32_t locationHash = generateLocationHash(call, call_index);
      args.push_back(
          ConstantInt::get(Type::getInt32Ty(call->getContext()), locationHash));

      // Add all original arguments
      for (unsigned i = 0; i < argCount; i++) {

        Value *arg = castToInt64(call->getArgOperand(i), IRB);
        args.push_back(arg);

      }

    }

  } else {

    // No arguments - generate location hash
    uint32_t locationHash = generateLocationHash(call, call_index);
    args.push_back(
        ConstantInt::get(Type::getInt32Ty(call->getContext()), locationHash));

  }

  // Add sentinel (0ULL) to mark end of arguments
  args.push_back(ConstantInt::get(Type::getInt64Ty(call->getContext()), 0));

  // Create the call to ijon_max_variadic
  IRB.CreateCall(ijonMaxVariadicFunc, args);

  // Remove the old call
  call->eraseFromParent();

}

void IJONInstrumentation::transformIJONSetCall(CallInst *call,
                                               uint32_t  call_index) {

  IRBuilder<> IRB(call);

  // Get the ijon_set function
  Function *ijonSetFunc =
      call->getParent()->getParent()->getParent()->getFunction("ijon_set");

  if (!ijonSetFunc) {

    printf("ERROR: ijon_set function not found!\n");
    return;

  }

  // Check arguments - ijon_set should have exactly 2 arguments
  if (call->arg_size() != 2) {

    printf("ERROR: ijon_set should have exactly 2 arguments!\n");
    return;

  }

  // Build arguments for ijon_set preserving the macro's location hash
  std::vector<Value *> args;

  // First argument: preserve the original location hash from the macro
  Value *originalLocationHash =
      call->getArgOperand(0);  // First argument (macro's hash)
  if (originalLocationHash->getType()->isIntegerTy()) {

    args.push_back(IRB.CreateIntCast(
        originalLocationHash, Type::getInt32Ty(call->getContext()), false));

  } else {

    // Fallback: use generated hash if original is not an integer
    uint32_t locationHash = generateLocationHash(call, call_index);
    args.push_back(
        ConstantInt::get(Type::getInt32Ty(call->getContext()), locationHash));

  }

  // Second argument: original value (cast to uint32_t)
  Value *originalArg = call->getArgOperand(1);  // Second argument (the value)
  Value *castArg;
  if (originalArg->getType()->isIntegerTy()) {

    castArg = IRB.CreateIntCast(originalArg,
                                Type::getInt32Ty(call->getContext()), false);

  } else if (originalArg->getType()->isPointerTy()) {

    castArg =
        IRB.CreatePtrToInt(originalArg, Type::getInt32Ty(call->getContext()));

  } else {

    // For other types, cast to int32
    castArg = ConstantInt::get(Type::getInt32Ty(call->getContext()), 1);

  }

  args.push_back(castArg);

  // Create the call to ijon_set with preserved location hash
  IRB.CreateCall(ijonSetFunc, args);

  // Remove the old call
  call->eraseFromParent();

}

void IJONInstrumentation::transformIJONIncCall(CallInst *call,
                                               uint32_t  call_index) {

  IRBuilder<> IRB(call);

  // Get the ijon_inc function
  Function *ijonIncFunc =
      call->getParent()->getParent()->getParent()->getFunction("ijon_inc");

  if (!ijonIncFunc) {

    printf("ERROR: ijon_inc function not found!\n");
    return;

  }

  // Check arguments - ijon_inc should have exactly 2 arguments
  if (call->arg_size() != 2) {

    printf("ERROR: ijon_inc should have exactly 2 arguments!\n");
    return;

  }

  // Build arguments for ijon_inc preserving the macro's location hash
  std::vector<Value *> args;

  // First argument: preserve the original location hash from the macro
  Value *originalLocationHash =
      call->getArgOperand(0);  // First argument (macro's hash)
  if (originalLocationHash->getType()->isIntegerTy()) {

    args.push_back(IRB.CreateIntCast(
        originalLocationHash, Type::getInt32Ty(call->getContext()), false));

  } else {

    // Fallback: use generated hash if original is not an integer
    uint32_t locationHash = generateLocationHash(call, call_index);
    args.push_back(
        ConstantInt::get(Type::getInt32Ty(call->getContext()), locationHash));

  }

  // Second argument: original value (cast to uint32_t)
  Value *originalArg = call->getArgOperand(1);  // Second argument (the value)
  Value *castArg;
  if (originalArg->getType()->isIntegerTy()) {

    castArg = IRB.CreateIntCast(originalArg,
                                Type::getInt32Ty(call->getContext()), false);

  } else if (originalArg->getType()->isPointerTy()) {

    castArg =
        IRB.CreatePtrToInt(originalArg, Type::getInt32Ty(call->getContext()));

  } else {

    // For other types, cast to int32
    castArg = ConstantInt::get(Type::getInt32Ty(call->getContext()), 1);

  }

  args.push_back(castArg);

  // Create the call to ijon_inc with preserved location hash
  IRB.CreateCall(ijonIncFunc, args);

  // Remove the old call
  call->eraseFromParent();

}

Value *IJONInstrumentation::castToInt64(Value *V, IRBuilder<> &IRB) {

  Type *targetType = Type::getInt64Ty(V->getContext());

  if (V->getType() == targetType) {

    return V;

  } else if (V->getType()->isIntegerTy()) {

    return IRB.CreateIntCast(V, targetType, false);

  } else if (V->getType()->isPointerTy()) {

    return IRB.CreatePtrToInt(V, targetType);

  } else if (V->getType()->isFloatingPointTy()) {

    return IRB.CreateFPToUI(V, targetType);

  } else {

    // Fallback: bitcast to int of same size, then extend/trunc to int64
    unsigned bitWidth = V->getType()->getPrimitiveSizeInBits();
    if (bitWidth > 0) {

      Type  *intType = Type::getIntNTy(V->getContext(), bitWidth);
      Value *asInt = IRB.CreateBitCast(V, intType);
      return IRB.CreateIntCast(asInt, targetType, false);

    } else {

      // Last resort: cast to zero
      return ConstantInt::get(targetType, 0);

    }

  }

}

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {

  return {LLVM_PLUGIN_API_VERSION, "IJONInstrumentation", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

#if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
            // Register only once to avoid duplicate processing
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL
#if LLVM_VERSION_MAJOR >= 20
                   ,
                   ThinOrFullLTOPhase Phase
#endif
                ) { MPM.addPass(IJONInstrumentation()); });

          }};

}

