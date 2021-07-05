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
   * See `AFL_FRIDA_INST_NO_OPTIMIZE`
   */
  public static setInstrumentNoOptimize(): void {
    Afl.jsApiSetInstrumentNoOptimize();
  }

  /**
   * See `AFL_FRIDA_INST_TRACE_UNIQUE`.
   */
  public static setInstrumentTracingUnique(): void {
    Afl.jsApiSetInstrumentTraceUnique();
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
   * See `AFL_FRIDA_INST_NO_PREFETCH`.
   */
  public static setPrefetchDisable(): void {
    Afl.jsApiSetPrefetchDisable();
  }

  /*
   * Set a function to be called for each instruction which is instrumented
   * by AFL FRIDA mode.
   */
  public static setStalkerCallback(callback: NativePointer): void {
    Afl.jsApiSetStalkerCallback(callback);
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
   * See `AFL_FRIDA_STATS_TRANSITIONS`
   */
  public static setStatsTransitions(): void {
    Afl.jsApiSetStatsTransitions();
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

  private static readonly jsApiSetDebugMaps = Afl.jsApiGetFunction(
    "js_api_set_debug_maps",
    "void",
    []);

  private static readonly jsApiSetEntryPoint = Afl.jsApiGetFunction(
    "js_api_set_entrypoint",
    "void",
    ["pointer"]);

  private static readonly jsApiSetInstrumentDebugFile = Afl.jsApiGetFunction(
    "js_api_set_instrument_debug_file",
    "void",
    ["pointer"]);

  private static readonly jsApiSetInstrumentJit = Afl.jsApiGetFunction(
    "js_api_set_instrument_jit",
    "void",
    []);

  private static readonly jsApiSetInstrumentLibraries = Afl.jsApiGetFunction(
    "js_api_set_instrument_libraries",
    "void",
    []);

  private static readonly jsApiSetInstrumentNoOptimize = Afl.jsApiGetFunction(
    "js_api_set_instrument_no_optimize",
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

  private static readonly jsApiSetPrefetchDisable = Afl.jsApiGetFunction(
    "js_api_set_prefetch_disable",
    "void",
    []);

  private static readonly jsApiSetStalkerCallback = Afl.jsApiGetFunction(
    "js_api_set_stalker_callback",
    "void",
    ["pointer"]);

  private static readonly jsApiSetStatsFile = Afl.jsApiGetFunction(
    "js_api_set_stats_file",
    "void",
    ["pointer"]);

  private static readonly jsApiSetStatsInterval = Afl.jsApiGetFunction(
    "js_api_set_stats_interval",
    "void",
    ["uint64"]);

  private static readonly jsApiSetStatsTransitions = Afl.jsApiGetFunction(
    "js_api_set_stats_transitions",
    "void",
    []);

  private static readonly jsApiSetStdErr = Afl.jsApiGetFunction(
    "js_api_set_stderr",
    "void",
    ["pointer"]);

  private static readonly jsApiSetStdOut = Afl.jsApiGetFunction(
    "js_api_set_stdout",
    "void",
    ["pointer"]);

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
