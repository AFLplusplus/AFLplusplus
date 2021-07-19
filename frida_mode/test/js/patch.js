Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

const main = DebugSymbol.fromName('main').address;
Afl.print(`main: ${main}`);
Afl.setEntryPoint(main);
Afl.setPersistentAddress(main);
Afl.setPersistentCount(10000000);

const crc32_check = DebugSymbol.fromName('crc32_check').address;
const crc32_replacement = new NativeCallback(
    (buf, len) => {
        Afl.print(`len: ${len}`);
        if (len < 4) {
            return 0;
        }

        return 1;
    },
    'int',
    ['pointer', 'int']);
Interceptor.replace(crc32_check, crc32_replacement);

const some_boring_bug = DebugSymbol.fromName('some_boring_bug').address
const boring_replacement = new NativeCallback(
    (c) => { },
    'void',
    ['char']);
Interceptor.replace(some_boring_bug, boring_replacement);

Afl.done();
Afl.print("done");
