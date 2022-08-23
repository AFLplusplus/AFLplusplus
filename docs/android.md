# Source code fuzzing on Android

_note: Currently there are many features such a CMPLOG missing from Android souce code fuzzing._  

Follow these steps to build an AFL++ fuzzer for fuzzing Android source code. 
Write you fuzzer using the LLVMFuzzerTestOneInput function as the entry point into your code.

**fuzz.cpp**
```
#include <stddef.h>
#include <stdint.h>
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Optionally use FuzzedDataProvider
    FuzzedDataProvider fdp(data,size);
    bool some_bool = fdp.ConsumeBool();
    
    // More code here
    return 0;
}
```

Then create a build target in your Android.bp file

**Android.bp**
```
cc_fuzz {
    name: "afl_fuzz_target",
    srcs: [
        "fuzz.cpp",
    ],
    static_libs: [
        "some_static_lib",
    ],
    
    host_supported: true, //optionally set host_supported
}
```

Then build your fuzzer
```
$ product=PRODUCT (ex redfin, coral, flame etc.)
$ source build/envsetup.sh
$ lunch aosp_$product-userdebug
$ FUZZ_FRAMEWORK=AFL mma afl_fuzz_target -j8
$ FUZZ_FRAMEWORK=AFL mma afl-fuzz -j8
```

_note: if "FUZZ\_FRAMEWORK is not set the default will be a libfuzzer build  

___
### Fuzzing on host (if host_supported=true in Android.bp build target)

```
$ cd $ANDROID_HOST_OUT
$ mkdir in out
$ echo "hello" > in/t
$ bin/afl-fuzz -i in -o out fuzz/$(get_build_var HOST_ARCH)/afl_fuzz_target/afl_fuzz_target
```
___
### Fuzzing on device

```
$ cd $ANDROID_PRODUCT_OUT
$ adb root
$ adb sync data
$ adb push system/bin/afl-fuzz /data/fuzz/afl-fuzz
$ adb push system/lib64 /data/fuzz
$ adb shell
# cd /data/fuzz
# mkdir in out
# echo "hey" > in/t
# ./afl-fuzz -i in -o out arm64/afl_fuzz_target/afl_fuzz_target
```

# To Get Coverage
Build your fuzz target with CLANG_COVERAGE=true
```
$ FUZZ_FRAMEWORK=AFL CLANG_COVERAGE=true NATIVE_COVERAGE_PATHS='*' make afl_fuzz_target -j8
```

You will only be able to generate coverage reports for on device fuzzing, not on host.
To do so, you will need to 
- Push afl-fuzz and afl_fuzz_target to your device
- set LLVM_PROFILE_FILE  
```export LLVM_PROFILE_FILE=cov/%m_%p.profraw```
- Run your fuzzer
- Pull cov/ from your device
- Make sure your LLVM tools version match the version that was used to build the fuzz target  
```export PATH=$ANDROID_BUILD_TOP/prebuilts/clang/host/linux-x86/llvm-binutils-stable:$PATH```
- Run these commands to generate the report:

```
$ llvm-profdata merge --sparse cov/*.profraw -output data.profdata
$ llvm-cov show --format=html --instr-profile=data.profdata \
${ANDROID_PRODUCT_OUT}/symbols/data/fuzz/$(get_build_var TARGET_ARCH/afl_fuzz_target/afl_fuzz_target \
--output-dir=coverage-html --path-equivalence=/proc/self/cwd,$ANDROID_BUILD_TOP
```

The above will generate coverage for your binary and statically linked librarys.
To include shared libraries you will need to append the paths to those shared libraries in your
```llvm-cov``` command. These libraries are at $ANDROID_PRODUCT_OUT/symbols/data/fuzz/$(get_build_var TARGET_ARCH)/lib/\<library_to_include\>.so

```
$ llvm-cov show --format=html --instr-profile=data.profdata \
${ANDROID_PRODUCT_OUT}/symbols/data/fuzz/$(get_build_var TARGET_ARCH/afl_fuzz_target/afl_fuzz_target \
--output-dir=coverage-html --path-equivalence=/proc/self/cwd,$ANDROID_BUILD_TOP \
-object $ANDROID_PRODUCT_OUT/symbols/data/fuzz/$(get_build_var TARGET_ARCH)/lib/<library_to_include>.so
```
