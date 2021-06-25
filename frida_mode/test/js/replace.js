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

const slow = DebugSymbol.fromName('slow').address;
Afl.print(`slow: ${slow}`);

const LLVMFuzzerTestOneInput = DebugSymbol.fromName('LLVMFuzzerTestOneInput').address;
Afl.print(`LLVMFuzzerTestOneInput: ${LLVMFuzzerTestOneInput}`);

const cm = new CModule(`

    extern unsigned char * __afl_fuzz_ptr;
    extern unsigned int * __afl_fuzz_len;
    extern void LLVMFuzzerTestOneInput(char *buf, int len);

    void slow(void) {

      LLVMFuzzerTestOneInput(__afl_fuzz_ptr, *__afl_fuzz_len);
    }
    `,
    {
        LLVMFuzzerTestOneInput: LLVMFuzzerTestOneInput,
        __afl_fuzz_ptr: Afl.getAflFuzzPtr(),
        __afl_fuzz_len: Afl.getAflFuzzLen()
    });

Afl.setEntryPoint(cm.slow);
Afl.setPersistentAddress(cm.slow);
Afl.setInMemoryFuzzing();
Interceptor.replace(slow, cm.slow);
Afl.print("done");
Afl.done();
