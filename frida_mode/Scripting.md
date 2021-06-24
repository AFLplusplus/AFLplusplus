# Scripting
FRIDA now supports the ability to configure itself using JavaScript. This allows
the user to make use of the convenience of FRIDA's scripting engine (along with
it's support for debug symbols and exports) to configure all of the things which
were traditionally configured using environment variables.

By default FRIDA mode will look for the file `afl.js` in the current working
directory of the target. Alternatively, a script file can be configured using
the environment variable `AFL_FRIDA_JS_SCRIPT`.

This script can make use of all of the standard [frida api functions](https://frida.re/docs/javascript-api/), but FRIDA mode adds some additional functions to allow
you to interact with FRIDA mode itself. These can all be accessed via the global
`Afl` parameter. e.g. `Afl.print("HELLO WORLD");`,

If you encounter a problem with your script, then you should set the environment
variable `AFL_DEBUG_CHILD=1` to view any diagnostic information.


# Example
Most of the time, users will likely be wanting to call the functions which configure an address (e.g. for the entry point, or the persistent address).

The example below uses the API [`DebugSymbol.fromName()`](https://frida.re/docs/javascript-api/#debugsymbol). Another use API is [`Module.getExportByName()`](https://frida.re/docs/javascript-api/#module).

```js
/* Use Afl.print instead of console.log */
Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

/* Print some useful diagnostics stuff */
Afl.print(`PID: ${Process.id}`);

new ModuleMap().values().forEach(m => {
    Afl.print(`${m.base}-${m.base.add(m.size)} ${m.name}`);
});

/*
 * Configure entry-point, persistence etc. This will be what most
 * people want to do.
 */
const persistent_addr = DebugSymbol.fromName('main');
Afl.print(`persistent_addr: ${persistent_addr.address}`);

if (persistent_addr.address.equals(ptr(0))) {
    Afl.error('Cannot find symbol main');
}

const persistent_ret = DebugSymbol.fromName('slow');
Afl.print(`persistent_ret: ${persistent_ret.address}`);

if (persistent_ret.address.equals(ptr(0))) {
    Afl.error('Cannot find symbol slow');
}

Afl.setPersistentAddress(persistent_addr.address);
Afl.setPersistentReturn(persistent_ret.address);
Afl.setPersistentCount(1000000);

/* Control instrumentation, you may want to do this too */
Afl.setInstrumentLibraries();
const mod = Process.findModuleByName("libc-2.31.so")
Afl.addExcludedRange(mod.base, mod.size);

/* Some useful options to configure logging */
Afl.setStdOut("/tmp/stdout.txt");
Afl.setStdErr("/tmp/stderr.txt");

/* Show the address layout. Sometimes helpful */
Afl.setDebugMaps();

/*
 * If you are using these options, then things aren't going
 * very well for you.
 */
Afl.setInstrumentDebugFile("/tmp/instr.log");
Afl.setPrefetchDisable();
Afl.setInstrumentNoOptimize();
Afl.setInstrumentEnableTracing();
Afl.setInstrumentTracingUnique();
Afl.setStatsFile("/tmp/stats.txt");
Afl.setStatsInterval(1);
Afl.setStatsTransitions();

/* *ALWAYS* call this when you have finished all your configuration */
Afl.done();
Afl.print("done");
```

# Stripped Binaries

Lastly, if the binary you attempting to fuzz has no symbol information, and no
exports, then the following approach can be used.

```js
const module = Process.getModuleByName('target.exe');
/* Hardcoded offset within the target image */
const address = module.base.add(0xdeadface);
Afl.setPersistentAddress(address);
```

# API
```js
/*
 * Print a message to the STDOUT. This should be preferred to
 * FRIDA's `console.log` since FRIDA will queue it's log messages.
 * If `console.log` is used in a callback in particular, then there
 * may no longer be a thread running to service this queue.
 */
Afl.print(msg);

/*
 * This must always be called at the end of your script. This lets
 * FRIDA mode know that your configuration is finished and that
 * execution has reached the end of your script. Failure to call
 * this will result in a fatal error.
 */
Afl.done();

/*
 * This function can be called within your script to cause FRIDA
 * mode to trigger a fatal error. This is useful if for example you
 * discover a problem you weren't expecting and want everything to
 * stop. The user will need to enable `AFL_DEBUG_CHILD=1` to view
 * this error message.
 */
Afl.error();

/*
 * This has the same effect as setting `AFL_ENTRYPOINT`, but has the
 * convenience of allowing you to use FRIDAs APIs to determine the
 * address you would like to configure, rather than having to grep
 * the output of `readelf` or something similarly ugly. This
 * function should be called with a `NativePointer` as its
 * argument.
 */
Afl.setEntryPoint(address);

/*
 * This is equivalent to setting `AFL_FRIDA_PERSISTENT_ADDR`, again a
 * `NativePointer` should be provided as it's argument.
 */
Afl.setPersistentAddress(address);

/*
 * This is equivalent to setting `AFL_FRIDA_PERSISTENT_RET`, again a
 * `NativePointer` should be provided as it's argument.
 */
Afl.setPersistentReturn(address);

/*
 * This is equivalent to setting `AFL_FRIDA_PERSISTENT_CNT`, a
 * `number` should be provided as it's argument.
 */
Afl.setPersistentCount(count);

/*
 * See `AFL_FRIDA_PERSISTENT_DEBUG`.
 */
Afl.setPersistentDebug();

/*
 * See `AFL_FRIDA_DEBUG_MAPS`.
 */
Afl.setDebugMaps();

/*
 * This is equivalent to setting a value in `AFL_FRIDA_INST_RANGES`,
 * it takes as arguments a `NativePointer` and a `number`. It can be
 * called multiple times to include several ranges.
 */
Afl.addIncludedRange(address, size);

/*
 * This is equivalent to setting a value in `AFL_FRIDA_EXCLUDE_RANGES`,
 * it takes as arguments a `NativePointer` and a `number`. It can be
 * called multiple times to exclude several ranges.
 */
Afl.addExcludedRange(address, size);

/*
 * See `AFL_INST_LIBS`.
 */
Afl.setInstrumentLibraries();

/*
 * See `AFL_FRIDA_INST_DEBUG_FILE`. This function takes a single `string` as
 * an argument.
 */
Afl.setInstrumentDebugFile(file);

/*
 * See `AFL_FRIDA_INST_NO_PREFETCH`.
 */
Afl.setPrefetchDisable();

/*
 * See `AFL_FRIDA_INST_NO_OPTIMIZE`
 */
Afl.setInstrumentNoOptimize();

/*
 * See `AFL_FRIDA_INST_TRACE`.
 */
Afl.setInstrumentEnableTracing();

/*
 * See `AFL_FRIDA_INST_TRACE_UNIQUE`.
 */
Afl.setInstrumentTracingUnique()

/*
 * See `AFL_FRIDA_OUTPUT_STDOUT`. This function takes a single `string` as
 * an argument.
 */
Afl.setStdOut(file);

/*
 * See `AFL_FRIDA_OUTPUT_STDERR`. This function takes a single `string` as
 * an argument.
 */
Afl.setStdErr(file);

/*
 * See `AFL_FRIDA_STATS_FILE`. This function takes a single `string` as
 * an argument.
 */
Afl.setStatsFile(file);

/*
 * See `AFL_FRIDA_STATS_INTERVAL`. This function takes a `number` as an
 * argument
 */
Afl.setStatsInterval(interval);

/*
 * See `AFL_FRIDA_STATS_TRANSITIONS`
 */
Afl.setStatsTransitions()
```
