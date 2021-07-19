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

const path = Afl.module.path;
const dir = path.substring(0, path.lastIndexOf("/"));
const mod = Module.load(`${dir}/frida_mode/build/frida_hook.so`);
const hook = mod.getExportByName('afl_persistent_hook');
Afl.setPersistentHook(hook);

Afl.print("done");
Afl.done();
