Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

const main = DebugSymbol.fromName('main').address;
Afl.print(`main: ${main}`);
Afl.setEntryPoint(main);
Afl.setPersistentAddress(main);
Afl.setPersistentCount(10000000);

/* Replace CRC-32 check */
const crc32_check = DebugSymbol.fromName('crc32_check').address;
const crc32_replacement = new NativeCallback(
    (buf, len) => {
        if (len < 4) {
            return 0;
        }

        return 1;
    },
    'int',
    ['pointer', 'int']);
Interceptor.replace(crc32_check, crc32_replacement);

/* Patch out the first boring bug */
const some_boring_bug = DebugSymbol.fromName('some_boring_bug').address
const boring_replacement = new NativeCallback(
    (c) => { },
    'void',
    ['char']);
Interceptor.replace(some_boring_bug, boring_replacement);

/* Modify the instructions */
const some_boring_bug2 = DebugSymbol.fromName('some_boring_bug2').address
const pid = Memory.alloc(4);
pid.writeInt(Process.id);

const cm = new CModule(`
    #include <stdio.h>
    #include <gum/gumstalker.h>

    typedef int pid_t;

    #define STDERR_FILENO 2
    #define BORING2_LEN 10

    extern int dprintf(int fd, const char *format, ...);
    extern void some_boring_bug2(char c);
    extern pid_t getpid(void);
    extern pid_t pid;

    gboolean js_stalker_callback(const cs_insn *insn, gboolean begin,
        gboolean excluded, GumStalkerOutput *output)
    {
        pid_t my_pid = getpid();
        GumX86Writer *cw = output->writer.x86;

        if (GUM_ADDRESS(insn->address) < GUM_ADDRESS(some_boring_bug2)) {

            return TRUE;

        }

        if (GUM_ADDRESS(insn->address) >=
            GUM_ADDRESS(some_boring_bug2) + BORING2_LEN) {

            return TRUE;

        }

        if (my_pid == pid) {

            if (begin) {

                dprintf(STDERR_FILENO, "\n> 0x%016lX: %s %s\n", insn->address,
                        insn->mnemonic, insn->op_str);

            } else {

                dprintf(STDERR_FILENO, "  0x%016lX: %s %s\n", insn->address,
                        insn->mnemonic, insn->op_str);

            }

        }

        if (insn->id == X86_INS_UD2) {

            gum_x86_writer_put_nop(cw);
            return FALSE;

        } else {

            return TRUE;

        }
    }
    `,
    {
        dprintf: Module.getExportByName(null, 'dprintf'),
        getpid: Module.getExportByName(null, 'getpid'),
        some_boring_bug2: some_boring_bug2,
        pid: pid
    });
Afl.setStalkerCallback(cm.js_stalker_callback)
Afl.setStdErr("/tmp/stderr.txt");
Afl.done();
Afl.print("done");
