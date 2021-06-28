Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

Afl.print(`PID: ${Process.id}`);

const name = Process.enumerateModules()[0].name;
Afl.print(`Name: ${name}`);

new ModuleMap().values().forEach(m => {
    Afl.print(`${m.base}-${m.base.add(m.size)} ${m.name}`);
});

if (name === 'testinstr') {
    const persistent_addr = DebugSymbol.fromName('LLVMFuzzerTestOneInput').address;
    Afl.print(`persistent_addr: ${persistent_addr}`);
    Afl.setEntryPoint(persistent_addr);
    Afl.setPersistentAddress(persistent_addr);
    Afl.setInstrumentDebugFile("/dev/stdout");
    Afl.setPersistentDebug();
    Afl.setInstrumentNoOptimize();
    Afl.setInstrumentEnableTracing();

    const LLVMFuzzerTestOneInput = new NativeFunction(
        persistent_addr,
        'void',
        ['pointer', 'uint64'],
        {traps: "all"});

    const persistentHook = new NativeCallback(
        (data, size) => {
            const input = Afl.aflFuzzPtr.readPointer();
            const len = Afl.aflFuzzLen.readPointer().readU32();
            const hd = hexdump(input, {length: len, header: false, ansi: true});
            Afl.print(`input: ${hd}`);
            LLVMFuzzerTestOneInput(input, len);
        },
        'void',
        ['pointer', 'uint64']);

    Afl.aflSharedMemFuzzing.writeInt(1);
    Interceptor.replace(persistent_addr, persistentHook);
    Interceptor.flush();
}

Afl.print("done");
Afl.done();
