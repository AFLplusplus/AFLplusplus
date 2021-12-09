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

const LLVMFuzzerTestOneInput = DebugSymbol.fromName('LLVMFuzzerTestOneInput').address;
Afl.print(`LLVMFuzzerTestOneInput: ${LLVMFuzzerTestOneInput}`);

const cm = new CModule(`

    extern unsigned char * __afl_fuzz_ptr;
    extern unsigned int * __afl_fuzz_len;
    extern void LLVMFuzzerTestOneInput(char *buf, int len);

    void My_LLVMFuzzerTestOneInput(char *buf, int len) {

      LLVMFuzzerTestOneInput(__afl_fuzz_ptr, *__afl_fuzz_len);

    }
    `,
    {
        LLVMFuzzerTestOneInput: LLVMFuzzerTestOneInput,
        __afl_fuzz_ptr: Afl.getAflFuzzPtr(),
        __afl_fuzz_len: Afl.getAflFuzzLen()
    });

Afl.setEntryPoint(cm.My_LLVMFuzzerTestOneInput);
Afl.setPersistentAddress(cm.My_LLVMFuzzerTestOneInput);
Afl.setInMemoryFuzzing();
Interceptor.replace(LLVMFuzzerTestOneInput, cm.My_LLVMFuzzerTestOneInput);
Afl.print("done");
Afl.done();
