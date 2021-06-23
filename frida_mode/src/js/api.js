const write = new NativeFunction(
    Module.getExportByName(null, 'write'),
    'int',
    ['int', 'pointer', 'int']
);

const afl_frida_trace = Process.findModuleByName('afl-frida-trace.so');

function get_api(name, ret, args) {
    const addr = afl_frida_trace.findExportByName(name);
    return new NativeFunction(addr, ret, args);
}

const js_api_done = get_api(
    'js_api_done',
    'void',
    []);

const js_api_error = get_api(
    'js_api_error',
    'void',
    ['pointer']);

const js_api_set_entrypoint = get_api(
    'js_api_set_entrypoint',
    'void',
    ['pointer']);

const js_api_set_persistent_address = get_api(
    'js_api_set_persistent_address',
    'void',
    ['pointer']);

const js_api_set_persistent_return = get_api(
    'js_api_set_persistent_return',
    'void',
    ['pointer']);

const js_api_set_persistent_count = get_api(
    'js_api_set_persistent_count',
    'void',
    ['uint64']);

const js_api_set_persistent_debug = get_api(
    'js_api_set_persistent_debug',
    'void',
    []);

const js_api_set_debug_maps = get_api(
    'js_api_set_debug_maps',
    'void',
    []);

const js_api_add_include_range = get_api(
    'js_api_add_include_range',
    'void',
    ['pointer', 'size_t']);

const js_api_add_exclude_range = get_api(
    'js_api_add_exclude_range',
    'void',
    ['pointer', 'size_t']);

const js_api_set_instrument_libraries = get_api(
    'js_api_set_instrument_libraries',
    'void',
    []);

const js_api_set_instrument_debug_file = get_api(
    'js_api_set_instrument_debug_file',
    'void',
    ['pointer']);

const js_api_set_prefetch_disable = get_api(
    'js_api_set_prefetch_disable',
    'void',
    []);

const js_api_set_instrument_no_optimize = get_api(
    'js_api_set_instrument_no_optimize',
    'void',
    []);

const js_api_set_instrument_trace = get_api(
    'js_api_set_instrument_trace',
    'void',
    []);

const js_api_set_instrument_trace_unique = get_api(
    'js_api_set_instrument_trace_unique',
    'void',
    []);

const js_api_set_stdout = get_api(
    'js_api_set_stdout',
    'void',
    ['pointer']);

const js_api_set_stderr = get_api(
    'js_api_set_stderr',
    'void',
    ['pointer']);

const js_api_set_stats_file = get_api(
    'js_api_set_stats_file',
    'void',
    ['pointer']);

const js_api_set_stats_interval = get_api(
    'js_api_set_stats_interval',
    'void',
    ['uint64']);

const js_api_set_stats_transitions = get_api(
    'js_api_set_stats_transitions',
    'void',
    []);

const afl = {
    print: function (msg) {
        const STDOUT_FILENO = 2;
        const log = `${msg}\n`;
        const buf = Memory.allocUtf8String(log);
        write(STDOUT_FILENO, buf, log.length);
    },
    done: function() {
        js_api_done();
    },
    error: function(msg) {
        const buf = Memory.allocUtf8String(msg);
        js_api_error(buf);
    },
    setEntryPoint: function(addr) {
        js_api_set_entrypoint(addr);
    },
    setPersistentAddress: function(addr) {
        js_api_set_persistent_address(addr);
    },
    setPersistentReturn: function(addr) {
        js_api_set_persistent_return(addr);
    },
    setPersistentCount: function(addr) {
        js_api_set_persistent_count(addr);
    },
    setPersistentDebug: function() {
        js_api_set_persistent_debug();
    },
    setDebugMaps: function() {
        js_api_set_debug_maps();
    },
    addIncludedRange: function(address, size) {
        js_api_add_include_range(address, size);
    },
    addExcludedRange: function(address, size) {
        js_api_add_exclude_range(address, size);
    },
    setInstrumentLibraries: function() {
        js_api_set_instrument_libraries();
    },
    setInstrumentDebugFile: function(file) {
        const buf = Memory.allocUtf8String(file);
        js_api_set_instrument_debug_file(buf)
    },
    setPrefetchDisable: function() {
        js_api_set_prefetch_disable();
    },
    setInstrumentNoOptimize: function() {
        js_api_set_instrument_no_optimize();
    },
    setInstrumentEnableTracing: function() {
        js_api_set_instrument_trace();
    },
    setInstrumentTracingUnique: function() {
        js_api_set_instrument_trace_unique();
    },
    setStdOut: function(file) {
        const buf = Memory.allocUtf8String(file);
        js_api_set_stdout(buf)
    },
    setStdErr: function(file) {
        const buf = Memory.allocUtf8String(file);
        js_api_set_stderr(buf)
    },
    setStatsFile: function(file) {
        const buf = Memory.allocUtf8String(file);
        js_api_set_stats_file(buf)
    },
    setStatsInterval: function(interval) {
        js_api_set_stats_interval(interval);
    },
    setStatsTransitions: function() {
        js_api_set_stats_transitions();
    }

};

Object.defineProperty(global, 'Afl', {value: afl, writeable: false});

////////////////////////////////////////////////////////////////////////////////
//                          END OF API                                        //
////////////////////////////////////////////////////////////////////////////////
