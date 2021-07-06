Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

Afl.print(`PID: ${Process.id}`);

new ModuleMap().values().forEach(m => {
    Afl.print(`${m.base}-${m.base.add(m.size)} ${m.name}`);
});

Afl.print('Searching...\n');
const entry_point = DebugSymbol.fromName('run');
Afl.print(`entry_point: ${entry_point}`);

Afl.setEntryPoint(entry_point.address);

// Afl.error('HARD NOPE');

Afl.done();
Afl.print("done");
