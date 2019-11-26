#if defined(UNICORN_AFL)

#if defined(UNICORN_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#endif

#include <string.h>

#include "uc_priv.h"

#include <sys/mman.h> 
#include <sys/stat.h>

UNICORN_EXPORT
uc_afl_ret uc_afl_forkserver_start(uc_engine *uc, uint64_t *exits, size_t exit_count)
{
    /*
    Why we need exits as parameter to forkserver:
    In the original unicorn-afl, Unicorn needed to flush the tb cache for every iteration.
    This is super slow.
    Problem was, that the otiginal forked server doesn't know about possible future exits.
    The cached blocks, in the next child, therefore whould have no exit set and run forever.
    Also it's nice to have multiple exits, so let's just do it right.
    */

    if (!uc) {
        fprintf(stderr, "[!] Unicorn Engine passed to uc_afl_fuzz is NULL!\n");
        return UC_AFL_RET_ERROR;
    }
    if (!exit_count) {
        fprintf(stderr, "[!] Nullptr provided for exits.\n");
        return UC_AFL_RET_ERROR;
    }
    if (unlikely(uc->afl_area_ptr)) {
        fprintf(stderr, "[!] forkserver_start(...) called twice. Already fuzzing!\n");
        return UC_AFL_RET_ERROR;
    }

    /* Copy exits to unicorn env buffer */
    uc->exits = g_realloc(uc->exits, exit_count * sizeof(exits[0]));
    if (uc->exits == NULL) {
        perror("[!] malloc failed when starting forkserver.");
        return UC_AFL_RET_ERROR;
    }
    memcpy(uc->exits, exits, sizeof(uint64_t) * exit_count);
    uc->exit_count = exit_count;

    /* Fork() :) */
    return uc->afl_forkserver_start(uc);

}

/* returns the filesize in bytes, -1 or error. */
static size_t uc_afl_mmap_file(char *filename, char **buf_ptr) {

    int ret = -1;

    int fd = open(filename, O_RDONLY);

    struct stat st = {0};
    if (fstat(fd, &st)) goto exit;

    off_t in_len = st.st_size;

    *buf_ptr = mmap(0, in_len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (*buf_ptr != MAP_FAILED) ret = in_len;

exit:
    close(fd);
    return ret;

}

/* A start with "less features" for our afl use-case */
/* this is largely copied from uc_emu_start, just without setting the entry point, counter and timeout. */
UNICORN_EXPORT
int uc_afl_emu_start(uc_engine *uc) {

    uc->emu_counter = 0;
    uc->invalid_error = UC_ERR_OK;
    uc->block_full = false;
    uc->emulation_done = false;
    uc->stop_request = false;

    // remove count hook if counting isn't necessary
    if (uc->count_hook != 0) {
        uc_hook_del(uc, uc->count_hook);
        uc->count_hook = 0;
    }

    if (uc->vm_start(uc)) {
        return UC_ERR_RESOURCE;
    }

    // emulation is done
    uc->emulation_done = true;

    return uc->invalid_error;

}

/* similar to __afl_persistent loop */
UNICORN_EXPORT
uc_afl_ret uc_afl_next(uc_engine *uc)
{

    if (unlikely(!uc->afl_area_ptr)) {
        fprintf(stderr, "[!] uc_afl_next(...) called before forkserver_start(...).");
        return UC_AFL_RET_ERROR;
    }

    // Tell the parent we need a new testcase, then stop until testcase is available.
    if (uc->afl_child_request_next) {

        if (uc->afl_child_request_next() == UC_AFL_RET_ERROR) return UC_AFL_RET_ERROR;
        raise(SIGSTOP);

        return UC_AFL_RET_CHILD;

    }     

    return UC_AFL_RET_NO_AFL;

}

UNICORN_EXPORT
uc_afl_ret uc_afl_fuzz(
        uc_engine *uc, 
        char* input_file, 
        uc_afl_cb_place_input_t place_input_callback, 
        uint64_t *exits, 
        size_t exit_count, 
        uc_afl_cb_validate_crash_t validate_crash_callback, 
        bool always_validate,
        uint32_t persistent_iters,
        void *data
){

    if (!uc) {
        fprintf(stderr, "[!] Unicorn Engine passed to uc_afl_fuzz is NULL!\n");
        return UC_AFL_RET_ERROR;
    }
    if (!input_file || input_file[0] == 0) {
        fprintf(stderr, "[!] No input file provided to uc_afl_fuzz.\n");
        return UC_AFL_RET_ERROR;
    }
    if (!place_input_callback) {
        fprintf(stderr, "[!] no place_input_callback set.\n");
        return UC_AFL_RET_ERROR;
    }
    if (always_validate && !validate_crash_callback) {
        fprintf(stderr, "[!] always_validate set but validate_crash_callback is missing.\n");
        return UC_AFL_RET_ERROR;
    }
    if (!exit_count) {
        fprintf(stderr, "[!] Nullptr provided for exits.\n");
        return UC_AFL_RET_ERROR;
    }

    char *in_buf = NULL;

    uc_afl_ret afl_ret = uc_afl_forkserver_start(uc, exits, exit_count);
    switch(afl_ret) {
        case UC_AFL_RET_CHILD:
            break;
        case UC_AFL_RET_NO_AFL:
            // Not running in AFL.
            persistent_iters = 1;
            break;
        case UC_AFL_RET_FINISHED:
            // Nothing more to do
            return afl_ret;
        case UC_AFL_RET_ERROR:
            // Nothing more we can do
            return afl_ret;
        default:
            // What have we done
            fprintf(stderr, "[!] Unexpected forkserver return: %d", afl_ret);
            return UC_AFL_RET_ERROR;
    }

    bool first_round = true;

    // 0 means never stop child in persistence mode.
    for (uint32_t i = 0; persistent_iters == 0 || i < persistent_iters; i++) {

        // The main fuzz loop starts here :)
        if (first_round) {
            first_round = false;
        } else {
            uc_afl_next(uc);
        }

        size_t in_len = uc_afl_mmap_file(input_file, &in_buf);
        if (unlikely(place_input_callback(uc, in_buf, in_len, i, data) == false)) {
            // Apparently, we're supposed to quit.
            break;
        }
        uc_err uc_emu_ret = uc_afl_emu_start(uc);

        if (unlikely((uc_emu_ret != UC_ERR_OK) || (always_validate && validate_crash_callback))) {
            
            if (validate_crash_callback != NULL && validate_crash_callback(
                    uc, uc_emu_ret, in_buf, in_len, i, data) != true) {
                // The callback thinks this is not a valid crash. Ignore.
                continue;
            }

            fprintf(stderr, "[!] UC returned Error: '%s' - let's abort().\n", uc_strerror(uc_emu_ret));
            fflush(stderr);
            abort();

        }
    }
    // UC_AFL_RET_CHILD -> We looped through all iters. 
    // We are still in the child, nothing good will come after this.
    // Exit and let the next generation run.
    if (likely(afl_ret == UC_AFL_RET_CHILD)) {
        exit(0);
    }

    if (uc->afl_area_ptr) {
        // Nothing should ever come after this but clean it up still.
        // shmdt(uc->afl_area_ptr);
        uc->afl_area_ptr = NULL;
    }

    // UC_AFL_RET_NO_AFL -> Not fuzzing. We ran once.
    return UC_AFL_RET_NO_AFL;
}

#endif /* UNICORN_AFL */