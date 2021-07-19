Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

Afl.print(`PID: ${Process.id}`);

new ModuleMap().values().forEach(m => {
    Afl.print(`${m.base}-${m.base.add(m.size)} ${m.name}`);
});

const name = Process.enumerateModules()[0].name;
Afl.print(`Name: ${name}`);

if (name === 'test') {

    Afl.print('Searching...\n');
    const entry_point = DebugSymbol.fromName('run');
    Afl.print(`entry_point: ${entry_point}`);

    Afl.setEntryPoint(entry_point.address);

}

Afl.done();
Afl.print("done");
