"use strict";
class Afl {
    /**
     * This is equivalent to setting a value in `AFL_FRIDA_EXCLUDE_RANGES`,
     * it takes as arguments a `NativePointer` and a `number`. It can be
     * called multiple times to exclude several ranges.
     */
    static addExcludedRange(addressess, size) {
        Afl.jsApiAddExcludeRange(addressess, size);
    }
    /**
     * This is equivalent to setting a value in `AFL_FRIDA_INST_RANGES`,
     * it takes as arguments a `NativePointer` and a `number`. It can be
     * called multiple times to include several ranges.
     */
    static addIncludedRange(addressess, size) {
        Afl.jsApiAddIncludeRange(addressess, size);
    }
    /**
     * This must always be called at the end of your script. This lets
     * FRIDA mode know that your configuration is finished and that
     * execution has reached the end of your script. Failure to call
     * this will result in a fatal error.
     */
    static done() {
        Afl.jsApiDone();
    }
    /**
     * This function can be called within your script to cause FRIDA
     * mode to trigger a fatal error. This is useful if for example you
     * discover a problem you weren't expecting and want everything to
     * stop. The user will need to enable `AFL_DEBUG_CHILD=1` to view
     * this error message.
     */
    static error(msg) {
        const buf = Memory.allocUtf8String(msg);
        Afl.jsApiError(buf);
    }
    /**
     * Function used to provide access to `__afl_fuzz_ptr`, which contains the length of
     * fuzzing data when using in-memory test case fuzzing.
     */
    static getAflFuzzLen() {
        return Afl.jsApiGetSymbol("__afl_fuzz_len");
    }
    /**
     * Function used to provide access to `__afl_fuzz_ptr`, which contains the fuzzing
     * data when using in-memory test case fuzzing.
     */
    static getAflFuzzPtr() {
        return Afl.jsApiGetSymbol("__afl_fuzz_ptr");
    }
    /**
     * Print a message to the STDOUT. This should be preferred to
     * FRIDA's `console.log` since FRIDA will queue it's log messages.
     * If `console.log` is used in a callback in particular, then there
     * may no longer be a thread running to service this queue.
     */
    static print(msg) {
        const STDOUT_FILENO = 2;
        const log = `${msg}\n`;
        const buf = Memory.allocUtf8String(log);
        Afl.jsApiWrite(STDOUT_FILENO, buf, log.length);
    }
    /**
     * See `AFL_FRIDA_STALKER_NO_BACKPATCH`.
     */
    static setBackpatchDisable() {
        Afl.jsApiSetBackpatchDisable();
    }
    /**
     * See `AFL_FRIDA_INST_NO_CACHE`.
     */
    static setCacheDisable() {
        Afl.jsApiSetCacheDisable();
    }
    /**
     * See `AFL_FRIDA_DEBUG_MAPS`.
     */
    static setDebugMaps() {
        Afl.jsApiSetDebugMaps();
    }
    /**
     * This has the same effect as setting `AFL_ENTRYPOINT`, but has the
     * convenience of allowing you to use FRIDAs APIs to determine the
     * address you would like to configure, rather than having to grep
     * the output of `readelf` or something similarly ugly. This
     * function should be called with a `NativePointer` as its
     * argument.
     */
    static setEntryPoint(address) {
        Afl.jsApiSetEntryPoint(address);
    }
    /**
     * Function used to enable in-memory test cases for fuzzing.
     */
    static setInMemoryFuzzing() {
        Afl.jsApiAflSharedMemFuzzing.writeInt(1);
    }
    /**
     * See `AFL_FRIDA_INST_CACHE_SIZE`. This function takes a single `number`
     * as an argument.
     */
    static setInstrumentCacheSize(size) {
        Afl.jsApiSetInstrumentCacheSize(size);
    }
    /**
     * See `AFL_FRIDA_INST_COVERAGE_FILE`. This function takes a single `string`
     * as an argument.
     */
    static setInstrumentCoverageFile(file) {
        const buf = Memory.allocUtf8String(file);
        Afl.jsApiSetInstrumentCoverageFile(buf);
    }
    /**
     * See `AFL_FRIDA_INST_DEBUG_FILE`. This function takes a single `string` as
     * an argument.
     */
    static setInstrumentDebugFile(file) {
        const buf = Memory.allocUtf8String(file);
        Afl.jsApiSetInstrumentDebugFile(buf);
    }
    /**
     * See `AFL_FRIDA_INST_TRACE`.
     */
    static setInstrumentEnableTracing() {
        Afl.jsApiSetInstrumentTrace();
    }
    /**
     * See `AFL_FRIDA_INST_INSN`
     */
    static setInstrumentInstructions() {
        Afl.jsApiSetInstrumentInstructions();
    }
    /**
     * See `AFL_FRIDA_INST_JIT`.
     */
    static setInstrumentJit() {
        Afl.jsApiSetInstrumentJit();
    }
    /**
     * See `AFL_INST_LIBS`.
     */
    static setInstrumentLibraries() {
        Afl.jsApiSetInstrumentLibraries();
    }
    /**
     * See `AFL_FRIDA_INST_NO_OPTIMIZE`
     */
    static setInstrumentNoOptimize() {
        Afl.jsApiSetInstrumentNoOptimize();
    }
    /*
     * See `AFL_FRIDA_INST_SEED`
     */
    static setInstrumentSeed(seed) {
        Afl.jsApiSetInstrumentSeed(seed);
    }
    /**
     * See `AFL_FRIDA_INST_TRACE_UNIQUE`.
     */
    static setInstrumentTracingUnique() {
        Afl.jsApiSetInstrumentTraceUnique();
    }
    /**
     * See `AFL_FRIDA_INST_UNSTABLE_COVERAGE_FILE`. This function takes a single
     * `string` as an argument.
     */
    static setInstrumentUnstableCoverageFile(file) {
        const buf = Memory.allocUtf8String(file);
        Afl.jsApiSetInstrumentUnstableCoverageFile(buf);
    }
    /*
     * Set a callback to be called in place of the usual `main` function. This see
     * `Scripting.md` for details.
     */
    static setJsMainHook(address) {
        Afl.jsApiSetJsMainHook(address);
    }
    /**
     * This is equivalent to setting `AFL_FRIDA_PERSISTENT_ADDR`, again a
     * `NativePointer` should be provided as it's argument.
     */
    static setPersistentAddress(address) {
        Afl.jsApiSetPersistentAddress(address);
    }
    /**
     * This is equivalent to setting `AFL_FRIDA_PERSISTENT_CNT`, a
     * `number` should be provided as it's argument.
     */
    static setPersistentCount(count) {
        Afl.jsApiSetPersistentCount(count);
    }
    /**
     * See `AFL_FRIDA_PERSISTENT_DEBUG`.
     */
    static setPersistentDebug() {
        Afl.jsApiSetPersistentDebug();
    }
    /**
     * See `AFL_FRIDA_PERSISTENT_ADDR`. This function takes a NativePointer as an
     * argument. See above for examples of use.
     */
    static setPersistentHook(address) {
        Afl.jsApiSetPersistentHook(address);
    }
    /**
     * This is equivalent to setting `AFL_FRIDA_PERSISTENT_RET`, again a
     * `NativePointer` should be provided as it's argument.
     */
    static setPersistentReturn(address) {
        Afl.jsApiSetPersistentReturn(address);
    }
    /**
     * See `AFL_FRIDA_INST_NO_PREFETCH_BACKPATCH`.
     */
    static setPrefetchBackpatchDisable() {
        Afl.jsApiSetPrefetchBackpatchDisable();
    }
    /**
     * See `AFL_FRIDA_INST_NO_PREFETCH`.
     */
    static setPrefetchDisable() {
        Afl.jsApiSetPrefetchDisable();
    }
    /**
     * See `AFL_FRIDA_SECCOMP_FILE`. This function takes a single `string` as
     * an argument.
     */
    static setSeccompFile(file) {
        const buf = Memory.allocUtf8String(file);
        Afl.jsApiSetSeccompFile(buf);
    }
    /**
     * See `AFL_FRIDA_STALKER_ADJACENT_BLOCKS`.
     */
    static setStalkerAdjacentBlocks(val) {
        Afl.jsApiSetStalkerAdjacentBlocks(val);
    }
    /*
     * Set a function to be called for each instruction which is instrumented
     * by AFL FRIDA mode.
     */
    static setStalkerCallback(callback) {
        Afl.jsApiSetStalkerCallback(callback);
    }
    /**
     * See `AFL_FRIDA_STALKER_IC_ENTRIES`.
     */
    static setStalkerIcEntries(val) {
        Afl.jsApiSetStalkerIcEntries(val);
    }
    /**
     * See `AFL_FRIDA_STATS_FILE`. This function takes a single `string` as
     * an argument.
     */
    static setStatsFile(file) {
        const buf = Memory.allocUtf8String(file);
        Afl.jsApiSetStatsFile(buf);
    }
    /**
     * See `AFL_FRIDA_STATS_INTERVAL`. This function takes a `number` as an
     * argument
     */
    static setStatsInterval(interval) {
        Afl.jsApiSetStatsInterval(interval);
    }
    /**
     * See `AFL_FRIDA_OUTPUT_STDERR`. This function takes a single `string` as
     * an argument.
     */
    static setStdErr(file) {
        const buf = Memory.allocUtf8String(file);
        Afl.jsApiSetStdErr(buf);
    }
    /**
     * See `AFL_FRIDA_OUTPUT_STDOUT`. This function takes a single `string` as
     * an argument.
     */
    static setStdOut(file) {
        const buf = Memory.allocUtf8String(file);
        Afl.jsApiSetStdOut(buf);
    }
    /**
     * See `AFL_FRIDA_TRACEABLE`.
     */
    static setTraceable() {
        Afl.jsApiSetTraceable();
    }
    /**
     * See `AFL_FRIDA_VERBOSE`
     */
    static setVerbose() {
        Afl.jsApiSetVerbose();
    }
    static jsApiGetFunction(name, retType, argTypes) {
        const addr = Afl.module.getExportByName(name);
        return new NativeFunction(addr, retType, argTypes);
    }
    static jsApiGetSymbol(name) {
        return Afl.module.getExportByName(name);
    }
}
/**
 * Field containing the `Module` object for `afl-frida-trace.so` (the FRIDA mode
 * implementation).
 */
Afl.module = Process.getModuleByName("afl-frida-trace.so");
Afl.jsApiAddExcludeRange = Afl.jsApiGetFunction("js_api_add_exclude_range", "void", ["pointer", "size_t"]);
Afl.jsApiAddIncludeRange = Afl.jsApiGetFunction("js_api_add_include_range", "void", ["pointer", "size_t"]);
Afl.jsApiAflSharedMemFuzzing = Afl.jsApiGetSymbol("__afl_sharedmem_fuzzing");
Afl.jsApiDone = Afl.jsApiGetFunction("js_api_done", "void", []);
Afl.jsApiError = Afl.jsApiGetFunction("js_api_error", "void", ["pointer"]);
Afl.jsApiSetBackpatchDisable = Afl.jsApiGetFunction("js_api_set_backpatch_disable", "void", []);
Afl.jsApiSetCacheDisable = Afl.jsApiGetFunction("js_api_set_cache_disable", "void", []);
Afl.jsApiSetDebugMaps = Afl.jsApiGetFunction("js_api_set_debug_maps", "void", []);
Afl.jsApiSetEntryPoint = Afl.jsApiGetFunction("js_api_set_entrypoint", "void", ["pointer"]);
Afl.jsApiSetInstrumentCacheSize = Afl.jsApiGetFunction("js_api_set_instrument_cache_size", "void", ["size_t"]);
Afl.jsApiSetInstrumentCoverageFile = Afl.jsApiGetFunction("js_api_set_instrument_coverage_file", "void", ["pointer"]);
Afl.jsApiSetInstrumentDebugFile = Afl.jsApiGetFunction("js_api_set_instrument_debug_file", "void", ["pointer"]);
Afl.jsApiSetInstrumentInstructions = Afl.jsApiGetFunction("js_api_set_instrument_instructions", "void", []);
Afl.jsApiSetInstrumentJit = Afl.jsApiGetFunction("js_api_set_instrument_jit", "void", []);
Afl.jsApiSetInstrumentLibraries = Afl.jsApiGetFunction("js_api_set_instrument_libraries", "void", []);
Afl.jsApiSetInstrumentNoOptimize = Afl.jsApiGetFunction("js_api_set_instrument_no_optimize", "void", []);
Afl.jsApiSetInstrumentSeed = Afl.jsApiGetFunction("js_api_set_instrument_seed", "void", ["uint64"]);
Afl.jsApiSetInstrumentTrace = Afl.jsApiGetFunction("js_api_set_instrument_trace", "void", []);
Afl.jsApiSetInstrumentTraceUnique = Afl.jsApiGetFunction("js_api_set_instrument_trace_unique", "void", []);
Afl.jsApiSetInstrumentUnstableCoverageFile = Afl.jsApiGetFunction("js_api_set_instrument_unstable_coverage_file", "void", ["pointer"]);
Afl.jsApiSetJsMainHook = Afl.jsApiGetFunction("js_api_set_js_main_hook", "void", ["pointer"]);
Afl.jsApiSetPersistentAddress = Afl.jsApiGetFunction("js_api_set_persistent_address", "void", ["pointer"]);
Afl.jsApiSetPersistentCount = Afl.jsApiGetFunction("js_api_set_persistent_count", "void", ["uint64"]);
Afl.jsApiSetPersistentDebug = Afl.jsApiGetFunction("js_api_set_persistent_debug", "void", []);
Afl.jsApiSetPersistentHook = Afl.jsApiGetFunction("js_api_set_persistent_hook", "void", ["pointer"]);
Afl.jsApiSetPersistentReturn = Afl.jsApiGetFunction("js_api_set_persistent_return", "void", ["pointer"]);
Afl.jsApiSetPrefetchBackpatchDisable = Afl.jsApiGetFunction("js_api_set_prefetch_backpatch_disable", "void", []);
Afl.jsApiSetPrefetchDisable = Afl.jsApiGetFunction("js_api_set_prefetch_disable", "void", []);
Afl.jsApiSetSeccompFile = Afl.jsApiGetFunction("js_api_set_seccomp_file", "void", ["pointer"]);
Afl.jsApiSetStalkerAdjacentBlocks = Afl.jsApiGetFunction("js_api_set_stalker_adjacent_blocks", "void", ["uint32"]);
Afl.jsApiSetStalkerCallback = Afl.jsApiGetFunction("js_api_set_stalker_callback", "void", ["pointer"]);
Afl.jsApiSetStalkerIcEntries = Afl.jsApiGetFunction("js_api_set_stalker_ic_entries", "void", ["uint32"]);
Afl.jsApiSetStatsFile = Afl.jsApiGetFunction("js_api_set_stats_file", "void", ["pointer"]);
Afl.jsApiSetStatsInterval = Afl.jsApiGetFunction("js_api_set_stats_interval", "void", ["uint64"]);
Afl.jsApiSetStdErr = Afl.jsApiGetFunction("js_api_set_stderr", "void", ["pointer"]);
Afl.jsApiSetStdOut = Afl.jsApiGetFunction("js_api_set_stdout", "void", ["pointer"]);
Afl.jsApiSetTraceable = Afl.jsApiGetFunction("js_api_set_traceable", "void", []);
Afl.jsApiSetVerbose = Afl.jsApiGetFunction("js_api_set_verbose", "void", []);
Afl.jsApiWrite = new NativeFunction(
/* tslint:disable-next-line:no-null-keyword */
Module.getExportByName(null, "write"), "int", ["int", "pointer", "int"]);
