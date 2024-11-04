# Short talk
[Open Source Security Foundation'24]( https://www.youtube.com/watch?v=qx1PCjQ1bCA&t=307s )

# Native hooking support into QEMUAFL
* The essential idea is to have inbuilt hooking support into QEMU, instead of relying on the more expensive options UNICORN and its children.
* This solution comprises a bridge (QEMU plugin) that connects your hooks (in a shared library (.so)) with the QEMU usermode ecosystem.
* Currently, LINUX only

## Bridge compilation
Run build_qemu_support.sh as you do to compile qemuafl, additionally with three args namely:
* `ENABLE_HOOKING=1` to compile the bridge
* `GLIB_H` and `GLIB_CONFIG_H` point to headers `glib.h` and `glibconfig.h` to wherever they are installed on your system

## Writting hooks
1. Create one or more hooking functions in a shared library, say `hook.so`.
2. Include `exports.h` in your hook build. You can find this header at `<your AFL++ path>/qemu_mode/hooking_bridge/inc`.
3. Shown below is an example which will use to walkthrough hook creation
    ```C
    struct ret* hook_000000400deadc08(){ 
        memset (buf, 0, 8);
        scanf("%s",buf);
        r_reg(RSI,(void *)&h_addr);
        w_mem(h_addr,8, buf);
        to_ret = (struct ret){0x400deadcab, 0};
        return &to_ret;
    }
    ```
    i. Hook functions must be named as `hook_<left padded hook location>`. Here, `<left padded hook location>` means `<hook location>` left padded with 0's to until 16 hex characters. The unpaded part of `<hook location>` is the absolute address where you want to place the hook. It is basically the file base address (which does not change in QEMU as of now) plus the instruction offset where the hooks is to be placed. The hook function must return a `struct ret *`, which is touched upon later.

    ii. Most likely you will need to access memory or registers in the hook. So we provide four functions
    ```C
        // Read memory (from address, num. bytes, destination buffer) -> returns 0 on success
        int r_mem(unsigned long long addr, unsigned long long len, void *dest);
        // Write memory (to address, num. bytes, source buffer) -> returns 0 on success
        int w_mem(unsigned long long addr, unsigned long long len, void *src);
        // Read register (identifier, destination buffer) -> returns number of bytes read
        int r_reg(unsigned char reg, void *dest);
        // Read register (identifier, source buffer) -> returns number of bytes written
        int w_reg(unsigned char reg, char *src);
    ```
    When operating on registers, the functions require a `reg` identifier. This is basically a number gdb uses to lookup a register and can be found under `<qemu(afl) path>/gdb-xml` in the architecture specific xml files. For the example case from above, `RSI` is 4 as obtained from `i386-64bit.xml`.

    iii. Once done with the processing, the hooks needs to return a `struct ret` type pointer, the struct format being
    ```C
    struct ret{
        unsigned long long addr;
        char remove_bp;
    };
    ```
    As we can see, there are two fields: first that indicates the address to return to and second that indicates whether the installed hook should be removed after the return. The second field becomes critical if the hook is within an ongoing loop and should be kept intact for future references.

    iv. Finally, mention the list of hooks in a `configure` function that we can call and install your hooks
    ```C
    struct conf config;
    struct conf* configure(){
        config.IP_reg_num = 16;
        config.entry_addr = 0x4000001000;
        config.num_hooks = NUMHOOKS; //1,2,3...
        hooks[0] = 0x400deadc08;
        // hooks[1] = 0xcafecace
        // ....
        config.hooks = hooks;

        //Any other processing stuff you need done before fuzztime

        return &config;
    }
    ``` 
    The `configure` function must have the signature `struct conf* configure()` i.e. it must return a pointer to the `config` object. The format of the `config` object is
    ```C
    struct conf{
        unsigned char IP_reg_num; //found in <qemudir>/gdb-xml
        unsigned long long entry_addr; //Main, init, or any entry point that is executed by QEMU prior to hooking targets
        unsigned long long* hooks; //list of hooked addresses
        unsigned long long num_hooks; // Number of hooks
    };
    ```
    `IP_reg_num` here is the register number assigned under the architecture specific xml file under `<qemu(afl) path>/gdb-xml` to the instruction pointer.

## Running with hooks
Set `QEMU_PLUGIN="file=<AFL download path>qemu_mode/hooking_bridge/build/plugin.so,arg=<your hook .so>"` before running AFL++ in QEMU mode. Note `<your hook .so>` is the absolute path to your hooks library. 

## Current limitations
1. Cannot be used to debug (-g option) when using the bridge as it uses the gdbstub internally. This is not a problem if used with AFL++, so not such a big issue.
2. Cannot put a hook on the first block after `<entry point>`. Not typically a hookable location.
3. The current implementation can only function on Linux. We have tested on the following configuration
    ```Bash
    lsb_release -a
    ---------------
    Distributor ID: Ubuntu
    Description:    Ubuntu 22.04.3 LTS
    Release:        22.04
    Codename:       jammy
    ```
    ```Bash
    uname -a
    ----------
    Linux someone 6.5.0-28-generic #29~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Apr  4 14:39:20 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
    ```
