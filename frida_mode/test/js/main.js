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

const main = DebugSymbol.fromName('main').address;
Afl.print(`main: ${main}`);

const LLVMFuzzerTestOneInput = DebugSymbol.fromName('LLVMFuzzerTestOneInput').address;
Afl.print(`LLVMFuzzerTestOneInput: ${LLVMFuzzerTestOneInput}`);

const cm = new CModule(`

    extern unsigned char * __afl_fuzz_ptr;
    extern unsigned int * __afl_fuzz_len;
    extern void LLVMFuzzerTestOneInput(char *buf, int len);

    int main(int argc, char **argv)  {

      LLVMFuzzerTestOneInput(__afl_fuzz_ptr, *__afl_fuzz_len);

    }
    `,
    {
        LLVMFuzzerTestOneInput: LLVMFuzzerTestOneInput,
        __afl_fuzz_ptr: Afl.getAflFuzzPtr(),
        __afl_fuzz_len: Afl.getAflFuzzLen()
    });

Afl.setEntryPoint(cm.main);
Afl.setPersistentAddress(cm.main);
Afl.setInMemoryFuzzing();
Afl.setJsMainHook(cm.main);
Afl.print("done");
Afl.done();
