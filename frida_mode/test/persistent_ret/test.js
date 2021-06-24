Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

Afl.print(`PID: ${Process.id}`);

new ModuleMap().values().forEach(m => {
    Afl.print(`${m.base}-${m.base.add(m.size)} ${m.name}`);
});

const persistent_addr = DebugSymbol.fromName('main');
Afl.print(`persistent_addr: ${persistent_addr.address}`);

const persistent_ret = DebugSymbol.fromName('slow');
Afl.print(`persistent_ret: ${persistent_ret.address}`);

Afl.setPersistentAddress(persistent_addr.address);
Afl.setPersistentReturn(persistent_ret.address);
Afl.setPersistentCount(1000000);

Afl.setDebugMaps();

const mod = Process.findModuleByName("libc-2.31.so")
Afl.addExcludedRange(mod.base, mod.size);
Afl.setInstrumentLibraries();
Afl.setInstrumentDebugFile("/tmp/instr.log");
Afl.setPrefetchDisable();
Afl.setInstrumentNoOptimize();
Afl.setInstrumentEnableTracing();
Afl.setInstrumentTracingUnique();
Afl.setStdOut("/tmp/stdout.txt");
Afl.setStdErr("/tmp/stderr.txt");
Afl.setStatsFile("/tmp/stats.txt");
Afl.setStatsInterval(1);
Afl.setStatsTransitions();
Afl.done();
Afl.print("done");
