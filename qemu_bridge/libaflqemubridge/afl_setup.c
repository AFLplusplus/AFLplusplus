#include "qemu/osdep.h"
#include "qemu.h"
#include "libafl/user.h"
#include "libafl/hooks/tcg/instruction.h"
#include "libaflqemubridge/afl.h"
#include "libaflqemubridge/imported/config.h"
#include "libaflqemubridge/imported/types.h"

#ifdef CONFIG_AFL

#include <sys/shm.h>

static uint32_t afl_resolve_map_size(void)
{
    char *e = getenv("AFL_QEMU_MAP_SIZE");
    if (e) {
        uint32_t v = (uint32_t)strtoul(e, NULL, 10);
        if (v >= 8 && v < (1U << 29)) {
            return v;
        }
    }
    return MAP_SIZE;
}

static void afl_entrypoint_hook(uint64_t data, vaddr pc)
{
    (void)data;
    libafl_qemu_remove_instruction_hooks_at(pc, 1);
    afl_forkserver_start();
}

static void afl_exitpoint_hook(uint64_t data, vaddr pc)
{
    (void)data;
    (void)pc;
    _exit(0);
}

void afl_initialize(int argc, char **argv, char **envp)
{
    (void)argc;
    (void)argv;
    (void)envp;
    afl_map_size = afl_resolve_map_size();
    char *id_str = getenv(SHM_ENV_VAR);
    if (id_str) {
        int shm_id = atoi(id_str);
        afl_area_ptr = shmat(shm_id, NULL, 0);
        if (afl_area_ptr == (void *)-1) {
            perror("shmat __AFL_SHM_ID");
            _exit(1);
        }
    } else {
        static uint8_t dummy[MAP_SIZE + MAP_SIZE_IJON_MAP + MAP_SIZE_IJON_BYTES];
        afl_area_ptr = dummy;
        if (afl_map_size > MAP_SIZE) {
            afl_map_size = MAP_SIZE;
        }
    }
    afl_idtable_init(afl_map_size);
    afl_ranges_init();
    afl_coverage_register();
    afl_cmplog_init();
    if (!afl_cmplog_is_active()) {
        afl_compcov_init();
    }
    afl_qasan_init();
    afl_ijon_init(afl_map_size);
    afl_persistent_init();

    uint64_t entry = afl_entry_point();
    uint64_t exit_pt = afl_exit_point();

    if (exit_pt) {
        libafl_qemu_add_instruction_hooks(exit_pt, afl_exitpoint_hook, 0, 1);
    }

    libafl_qemu_add_instruction_hooks(entry, afl_entrypoint_hook, 0, 1);
}

#endif
