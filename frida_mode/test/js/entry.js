Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

Afl.print(`PID: ${Process.id}`);

new ModuleMap().values().forEach(m => {
    Afl.print(`${m.base}-${m.base.add(m.size)} ${m.name}`);
});

const entry_point = DebugSymbol.fromName('run');
Afl.print(`entry_point: ${entry_point.address}`);

Afl.setEntryPoint(entry_point.address);

// Afl.error('HARD NOPE');

Afl.done();
Afl.print("done");
