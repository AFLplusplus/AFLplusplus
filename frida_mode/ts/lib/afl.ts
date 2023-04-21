class Afl {

  /**
   * Field containing the `Module` object for `afl-frida-trace.so` (the FRIDA mode
   * implementation).
   */
  public static module: Module = Process.getModuleByName("afl-frida-trace.so");

  /**
   * This is equivalent to setting a value in `AFL_FRIDA_EXCLUDE_RANGES`,
   * it takes as arguments a `NativePointer` and a `number`. It can be
   * called multiple times to exclude several ranges.
   */
  public static addExcludedRange(addressess: NativePointer, size: number): void {
    Afl.jsApiAddExcludeRange(addressess, size);
  }

  /**
   * This is equivalent to setting a value in `AFL_FRIDA_INST_RANGES`,
   * it takes as arguments a `NativePointer` and a `number`. It can be
   * called multiple times to include several ranges.
   */
  public static addIncludedRange(addressess: NativePointer, size: number): void {
    Afl.jsApiAddIncludeRange(addressess, size);
  }

  /**
   * This must always be called at the end of your script. This lets
   * FRIDA mode know that your configuration is finished and that
   * execution has reached the end of your script. Failure to call
   * this will result in a fatal error.
   */
  public static done(): void {
    Afl.jsApiDone();
  }

  /**
   * This function can be called within your script to cause FRIDA
   * mode to trigger a fatal error. This is useful if for example you
   * discover a problem you weren't expecting and want everything to
   * stop. The user will need to enable `AFL_DEBUG_CHILD=1` to view
   * this error message.
   */
  public static error(msg: string): void {
    const buf = Memory.allocUtf8String(msg);
    Afl.jsApiError(buf);
  }

  /**
   * Function used to provide access to `__afl_fuzz_ptr`, which contains the length of
   * fuzzing data when using in-memory test case fuzzing.
   */
  public static getAflFuzzLen(): NativePointer {

    return Afl.jsApiGetSymbol("__afl_fuzz_len");
  }

  /**
   * Function used to provide access to `__afl_fuzz_ptr`, which contains the fuzzing
   * data when using in-memory test case fuzzing.
   */
  public static getAflFuzzPtr(): NativePointer {

    return Afl.jsApiGetSymbol("__afl_fuzz_ptr");
  }

  /**
   * Print a message to the STDOUT. This should be preferred to
   * FRIDA's `console.log` since FRIDA will queue it's log messages.
   * If `console.log` is used in a callback in particular, then there
   * may no longer be a thread running to service this queue.
   */
  public static print(msg: string): void {
    const STDOUT_FILENO = 2;
    const log = `${msg}\n`;
    const buf = Memory.allocUtf8String(log);
    Afl.jsApiWrite(STDOUT_FILENO, buf, log.length);
  }

  /**
   * See `AFL_FRIDA_STALKER_NO_BACKPATCH`.
   */
  public static setBackpatchDisable(): void {
    Afl.jsApiSetBackpatchDisable();
  }

  /**
   * See `AFL_FRIDA_INST_NO_CACHE`.
   */
  public static setCacheDisable(): void {
    Afl.jsApiSetCacheDisable();
  }

  /**
   * See `AFL_FRIDA_DEBUG_MAPS`.
   */
  public static setDebugMaps(): void {
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
  public static setEntryPoint(address: NativePointer): void {
    Afl.jsApiSetEntryPoint(address);
  }

  /**
   * Function used to enable in-memory test cases for fuzzing.
   */
  public static setInMemoryFuzzing(): void {
    Afl.jsApiAflSharedMemFuzzing.writeInt(1);
  }

  /**
   * See `AFL_FRIDA_INST_CACHE_SIZE`. This function takes a single `number`
   * as an argument.
   */
  public static setInstrumentCacheSize(size: number): void {
    Afl.jsApiSetInstrumentCacheSize(size);
  }

  /**
   * See `AFL_FRIDA_INST_COVERAGE_ABSOLUTE`.
   */
  public static setInstrumentCoverageAbsolute(): void {
    Afl.jsApiSetInstrumentCoverageAbsolute();
  }

  /**
   * See `AFL_FRIDA_INST_COVERAGE_FILE`. This function takes a single `string`
   * as an argument.
   */
  public static setInstrumentCoverageFile(file: string): void {
    const buf = Memory.allocUtf8String(file);
    Afl.jsApiSetInstrumentCoverageFile(buf);
  }

  /**
   * See `AFL_FRIDA_INST_DEBUG_FILE`. This function takes a single `string` as
   * an argument.
   */
  public static setInstrumentDebugFile(file: string): void {
    const buf = Memory.allocUtf8String(file);
    Afl.jsApiSetInstrumentDebugFile(buf);
  }

  /**
   * See `AFL_FRIDA_INST_TRACE`.
   */
  public static setInstrumentEnableTracing(): void {
    Afl.jsApiSetInstrumentTrace();
  }

  /**
   * See `AFL_FRIDA_INST_INSN`
   */
  public static setInstrumentInstructions(): void {
    Afl.jsApiSetInstrumentInstructions();
  }

  /**
   * See `AFL_FRIDA_INST_JIT`.
   */
  public static setInstrumentJit(): void {
    Afl.jsApiSetInstrumentJit();
  }

  /**
   * See `AFL_INST_LIBS`.
   */
  public static setInstrumentLibraries(): void {
    Afl.jsApiSetInstrumentLibraries();
  }

  /**
   * See `AFL_FRIDA_INST_NO_DYNAMIC_LOAD`
   */
  public static setInstrumentNoDynamicLoad(): void {
    Afl.jsApiSetInstrumentNoDynamicLoad();
  }

  /**
   * See `AFL_FRIDA_INST_NO_OPTIMIZE`
   */
  public static setInstrumentNoOptimize(): void {
    Afl.jsApiSetInstrumentNoOptimize();
  }

  /**
   * See `AFL_FRIDA_INST_REGS_FILE`. This function takes a single `string` as
   * an argument.
   */
  public static setInstrumentRegsFile(file: string): void {
    const buf = Memory.allocUtf8String(file);
    Afl.jsApiSetInstrumentRegsFile(buf);
  }

  /*
   * See `AFL_FRIDA_INST_SEED`
   */
  public static setInstrumentSeed(seed: NativePointer): void {
    Afl.jsApiSetInstrumentSeed(seed);
  }

  /*
   * See `AFL_FRIDA_INST_NO_SUPPRESS`
   */
  public static setInstrumentSuppressDisable(): void{
    Afl.jsApiSetInstrumentSuppressDisable();
  }

  /**
   * See `AFL_FRIDA_INST_TRACE_UNIQUE`.
   */
  public static setInstrumentTracingUnique(): void {
    Afl.jsApiSetInstrumentTraceUnique();
  }

  /**
   * See `AFL_FRIDA_INST_UNSTABLE_COVERAGE_FILE`. This function takes a single
   * `string` as an argument.
   */
  public static setInstrumentUnstableCoverageFile(file: string): void {
    const buf = Memory.allocUtf8String(file);
    Afl.jsApiSetInstrumentUnstableCoverageFile(buf);
  }

  /*
   * Set a callback to be called in place of the usual `main` function. This see
   * `Scripting.md` for details.
   */
  public static setJsMainHook(address: NativePointer): void {
    Afl.jsApiSetJsMainHook(address);
  }

  /**
   * This is equivalent to setting `AFL_FRIDA_PERSISTENT_ADDR`, again a
   * `NativePointer` should be provided as it's argument.
   */
  public static setPersistentAddress(address: NativePointer): void {
    Afl.jsApiSetPersistentAddress(address);
  }

  /**
   * This is equivalent to setting `AFL_FRIDA_PERSISTENT_CNT`, a
   * `number` should be provided as it's argument.
   */
  public static setPersistentCount(count: number): void {
    Afl.jsApiSetPersistentCount(count);
  }

  /**
   * See `AFL_FRIDA_PERSISTENT_DEBUG`.
   */
  public static setPersistentDebug(): void {
    Afl.jsApiSetPersistentDebug();
  }

  /**
   * See `AFL_FRIDA_PERSISTENT_ADDR`. This function takes a NativePointer as an
   * argument. See above for examples of use.
   */
  public static setPersistentHook(address: NativePointer): void {
    Afl.jsApiSetPersistentHook(address);
  }

  /**
   * This is equivalent to setting `AFL_FRIDA_PERSISTENT_RET`, again a
   * `NativePointer` should be provided as it's argument.
   */
  public static setPersistentReturn(address: NativePointer): void {
    Afl.jsApiSetPersistentReturn(address);
  }

  /**
   * See `AFL_FRIDA_INST_NO_PREFETCH_BACKPATCH`.
   */
  public static setPrefetchBackpatchDisable(): void {
    Afl.jsApiSetPrefetchBackpatchDisable();
  }

  /**
   * See `AFL_FRIDA_INST_NO_PREFETCH`.
   */
  public static setPrefetchDisable(): void {
    Afl.jsApiSetPrefetchDisable();
  }

  /**
   * See `AFL_FRIDA_SECCOMP_FILE`. This function takes a single `string` as
   * an argument.
   */
  public static setSeccompFile(file: string): void {
    const buf = Memory.allocUtf8String(file);
    Afl.jsApiSetSeccompFile(buf);
  }

  /**
   * See `AFL_FRIDA_STALKER_ADJACENT_BLOCKS`.
   */
  public static setStalkerAdjacentBlocks(val: number): void {
    Afl.jsApiSetStalkerAdjacentBlocks(val);
  }

  /*
   * Set a function to be called for each instruction which is instrumented
   * by AFL FRIDA mode.
   */
  public static setStalkerCallback(callback: NativePointer): void {
    Afl.jsApiSetStalkerCallback(callback);
  }

  /**
   * See `AFL_FRIDA_STALKER_IC_ENTRIES`.
   */
  public static setStalkerIcEntries(val: number): void {
    Afl.jsApiSetStalkerIcEntries(val);
  }

  /**
   * See `AFL_FRIDA_STATS_FILE`. This function takes a single `string` as
   * an argument.
   */
  public static setStatsFile(file: string): void {
    const buf = Memory.allocUtf8String(file);
    Afl.jsApiSetStatsFile(buf);
  }

  /**
   * See `AFL_FRIDA_STATS_INTERVAL`. This function takes a `number` as an
   * argument
   */
  public static setStatsInterval(interval: number): void {
    Afl.jsApiSetStatsInterval(interval);
  }

  /**
   * See `AFL_FRIDA_OUTPUT_STDERR`. This function takes a single `string` as
   * an argument.
   */
  public static setStdErr(file: string): void {
    const buf = Memory.allocUtf8String(file);
    Afl.jsApiSetStdErr(buf);
  }

  /**
   * See `AFL_FRIDA_OUTPUT_STDOUT`. This function takes a single `string` as
   * an argument.
   */
  public static setStdOut(file: string): void {
    const buf = Memory.allocUtf8String(file);
    Afl.jsApiSetStdOut(buf);
  }

  /**
   * See `AFL_FRIDA_TRACEABLE`.
   */
  public static setTraceable(): void {
    Afl.jsApiSetTraceable();
  }

  /**
   * See `AFL_FRIDA_VERBOSE`
   */
  public static setVerbose(): void {
    Afl.jsApiSetVerbose();
  }

  private static readonly jsApiAddExcludeRange = Afl.jsApiGetFunction(
    "js_api_add_exclude_range",
    "void",
    ["pointer", "size_t"]);

  private static readonly jsApiAddIncludeRange = Afl.jsApiGetFunction(
    "js_api_add_include_range",
    "void",
    ["pointer", "size_t"]);

  private static readonly jsApiAflSharedMemFuzzing = Afl.jsApiGetSymbol("__afl_sharedmem_fuzzing");

  private static readonly jsApiDone = Afl.jsApiGetFunction(
    "js_api_done",
    "void",
    []);

  private static readonly jsApiError = Afl.jsApiGetFunction(
    "js_api_error",
    "void",
    ["pointer"]);

  private static readonly jsApiSetBackpatchDisable = Afl.jsApiGetFunction(
    "js_api_set_backpatch_disable",
    "void",
    []);

  private static readonly jsApiSetCacheDisable = Afl.jsApiGetFunction(
    "js_api_set_cache_disable",
    "void",
    []);

  private static readonly jsApiSetDebugMaps = Afl.jsApiGetFunction(
    "js_api_set_debug_maps",
    "void",
    []);

  private static readonly jsApiSetEntryPoint = Afl.jsApiGetFunction(
    "js_api_set_entrypoint",
    "void",
    ["pointer"]);

  private static readonly jsApiSetInstrumentCacheSize = Afl.jsApiGetFunction(
    "js_api_set_instrument_cache_size",
    "void",
    ["size_t"]);

  private static readonly jsApiSetInstrumentCoverageAbsolute = Afl.jsApiGetFunction(
    "js_api_set_instrument_coverage_absolute",
    "void",
    []
  );

  private static readonly jsApiSetInstrumentCoverageFile = Afl.jsApiGetFunction(
    "js_api_set_instrument_coverage_file",
    "void",
    ["pointer"]);

  private static readonly jsApiSetInstrumentDebugFile = Afl.jsApiGetFunction(
    "js_api_set_instrument_debug_file",
    "void",
    ["pointer"]);

  private static readonly jsApiSetInstrumentInstructions = Afl.jsApiGetFunction(
    "js_api_set_instrument_instructions",
    "void",
    []);

  private static readonly jsApiSetInstrumentJit = Afl.jsApiGetFunction(
    "js_api_set_instrument_jit",
    "void",
    []);

  private static readonly jsApiSetInstrumentLibraries = Afl.jsApiGetFunction(
    "js_api_set_instrument_libraries",
    "void",
    []);

  private static readonly jsApiSetInstrumentNoDynamicLoad = Afl.jsApiGetFunction(
    "js_api_set_instrument_no_dynamic_load",
    "void",
    []);

  private static readonly jsApiSetInstrumentNoOptimize = Afl.jsApiGetFunction(
    "js_api_set_instrument_no_optimize",
    "void",
    []);

  private static readonly jsApiSetInstrumentRegsFile = Afl.jsApiGetFunction(
    "js_api_set_instrument_regs_file",
    "void",
    ["pointer"]);

  private static readonly jsApiSetInstrumentSeed = Afl.jsApiGetFunction(
    "js_api_set_instrument_seed",
    "void",
    ["uint64"]);

  private static readonly jsApiSetInstrumentSuppressDisable = Afl.jsApiGetFunction(
    "js_api_set_instrument_suppress_disable",
    "void",
    []);

  private static readonly jsApiSetInstrumentTrace = Afl.jsApiGetFunction(
    "js_api_set_instrument_trace",
    "void",
    []);

  private static readonly jsApiSetInstrumentTraceUnique = Afl.jsApiGetFunction(
    "js_api_set_instrument_trace_unique",
    "void",
    []);

  private static readonly jsApiSetInstrumentUnstableCoverageFile = Afl.jsApiGetFunction(
    "js_api_set_instrument_unstable_coverage_file",
    "void",
    ["pointer"]);

  private static readonly jsApiSetJsMainHook = Afl.jsApiGetFunction(
    "js_api_set_js_main_hook",
    "void",
    ["pointer"]);

  private static readonly jsApiSetPersistentAddress = Afl.jsApiGetFunction(
    "js_api_set_persistent_address",
    "void",
    ["pointer"]);

  private static readonly jsApiSetPersistentCount = Afl.jsApiGetFunction(
    "js_api_set_persistent_count",
    "void",
    ["uint64"]);

  private static readonly jsApiSetPersistentDebug = Afl.jsApiGetFunction(
    "js_api_set_persistent_debug",
    "void",
    []);

  private static readonly jsApiSetPersistentHook = Afl.jsApiGetFunction(
    "js_api_set_persistent_hook",
    "void",
    ["pointer"]);

  private static readonly jsApiSetPersistentReturn = Afl.jsApiGetFunction(
    "js_api_set_persistent_return",
    "void",
    ["pointer"]);

  private static readonly jsApiSetPrefetchBackpatchDisable = Afl.jsApiGetFunction(
    "js_api_set_prefetch_backpatch_disable",
    "void",
    []);

  private static readonly jsApiSetPrefetchDisable = Afl.jsApiGetFunction(
    "js_api_set_prefetch_disable",
    "void",
    []);

  private static readonly jsApiSetSeccompFile = Afl.jsApiGetFunction(
    "js_api_set_seccomp_file",
    "void",
    ["pointer"]);

  private static readonly jsApiSetStalkerAdjacentBlocks = Afl.jsApiGetFunction(
    "js_api_set_stalker_adjacent_blocks",
    "void",
    ["uint32"]);

  private static readonly jsApiSetStalkerCallback = Afl.jsApiGetFunction(
    "js_api_set_stalker_callback",
    "void",
    ["pointer"]);

  private static readonly jsApiSetStalkerIcEntries = Afl.jsApiGetFunction(
    "js_api_set_stalker_ic_entries",
    "void",
    ["uint32"]);

  private static readonly jsApiSetStatsFile = Afl.jsApiGetFunction(
    "js_api_set_stats_file",
    "void",
    ["pointer"]);

  private static readonly jsApiSetStatsInterval = Afl.jsApiGetFunction(
    "js_api_set_stats_interval",
    "void",
    ["uint64"]);

  private static readonly jsApiSetStdErr = Afl.jsApiGetFunction(
    "js_api_set_stderr",
    "void",
    ["pointer"]);

  private static readonly jsApiSetStdOut = Afl.jsApiGetFunction(
    "js_api_set_stdout",
    "void",
    ["pointer"]);

  private static readonly jsApiSetTraceable = Afl.jsApiGetFunction(
    "js_api_set_traceable",
    "void",
    []);

  private static readonly jsApiSetVerbose = Afl.jsApiGetFunction(
    "js_api_set_verbose",
    "void",
    []);

  private static readonly jsApiWrite = new NativeFunction(
    /* tslint:disable-next-line:no-null-keyword */
    Module.getExportByName(null, "write"),
    "int",
    ["int", "pointer", "int"]);

  private static jsApiGetFunction(name: string, retType: NativeType, argTypes: NativeType[]): NativeFunction {
    const addr: NativePointer = Afl.module.getExportByName(name);

    return new NativeFunction(addr, retType, argTypes);
  }

  private static jsApiGetSymbol(name: string): NativePointer {

    return Afl.module.getExportByName(name);
  }

}

export { Afl };
