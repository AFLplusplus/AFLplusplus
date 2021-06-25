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

const persistent_addr = DebugSymbol.fromName('LLVMFuzzerTestOneInput').address;
Afl.print(`persistent_addr: ${persistent_addr}`);
Afl.setEntryPoint(persistent_addr);
Afl.setPersistentAddress(persistent_addr);

const cm = new CModule(`

    #include <string.h>
    #include <gum/gumdefs.h>

    void afl_persistent_hook(GumCpuContext *regs, uint8_t *input_buf,
      uint32_t input_buf_len) {

      memcpy((void *)regs->rdi, input_buf, input_buf_len);
      regs->rsi = input_buf_len;

    }
    `,
    {
        memcpy: Module.getExportByName(null, 'memcpy')
    });
Afl.setPersistentHook(cm.afl_persistent_hook);

Afl.print("done");
Afl.done();
