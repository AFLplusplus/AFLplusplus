#ifndef LIBAFL_AFL_H
#define LIBAFL_AFL_H

#ifdef CONFIG_AFL

#include <stdint.h>

void afl_initialize(int argc, char **argv, char **envp);

void afl_idtable_init(uint32_t map_size);
uint64_t afl_idtable_lookup(uint64_t src, uint64_t dst);
uint32_t afl_idtable_count(void);

extern uint8_t *afl_area_ptr;
extern uint32_t afl_map_size;
extern uint32_t afl_inst_ratio;
void afl_coverage_register(void);

void afl_ranges_init(void);
bool afl_range_is_instrumented(uint64_t pc);
bool afl_inst_ratio_keep(uint64_t pc);
uint64_t afl_entry_point(void);
uint64_t afl_exit_point(void);
uint64_t afl_get_exec_entry(void);

void afl_forkserver_start(void);

#define AFL_TSL_FD 197
extern int afl_fork_child;
void afl_wait_tsl(int fd);

void afl_persistent_init(void);
bool afl_is_persistent(void);

extern int afl_compcov_level;
void afl_compcov_init(void);

int afl_cmplog_is_active(void);
void afl_cmplog_init(void);

void afl_qasan_init(void);

void afl_ijon_init(uint32_t cov_map_size);
uint32_t afl_ijon_extra_size(void);
extern int afl_ijon_enabled;

extern uint32_t *afl_child_sync;
extern int afl_persistent_use_futex;

#endif
#endif
