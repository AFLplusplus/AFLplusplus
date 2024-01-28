#include <cstdio>
#include <fstream>

extern "C" {

#include "afl-fuzz.h"

}

FILE *profile_fd;

void plot_profile_data(afl_state_t *afl, struct queue_entry *q) {

  if (!profile_fd) {

    std::string out_dir = (const char *)afl->out_dir;
    profile_fd = fopen((out_dir + "/plot_stage_data").c_str(), "w");

  }

  u64 current_ms = get_cur_time() - afl->start_time;

  u32    current_edges = count_non_255_bytes(afl, afl->virgin_bits);
  double det_finding_rate = (double)afl->havoc_prof->total_det_edge * 100.0 /
                            (double)current_edges,
         det_time_rate = (double)afl->havoc_prof->total_det_time * 100.0 /
                         (double)current_ms;

  u32 ndet_bits = 0;
  for (u32 i = 0; i < afl->fsrv.map_size; i++) {

    if (afl->skipdet_g->virgin_det_bits[i]) ndet_bits += 1;

  }

  double det_fuzzed_rate = (double)ndet_bits * 100.0 / (double)current_edges;

  fprintf(profile_fd,
          "[%02lld:%02lld:%02lld] fuzz %d (%d), find %d/%d among %d(%02.2f) "
          "and spend %lld/%lld(%02.2f), cover %02.2f yet, %d/%d undet bits, "
          "continue %d.\n",
          current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60,
          (current_ms / 1000) % 60, afl->current_entry, q->fuzz_level,
          afl->havoc_prof->edge_det_stage, afl->havoc_prof->edge_havoc_stage,
          current_edges, det_finding_rate,
          afl->havoc_prof->det_stage_time / 1000,
          afl->havoc_prof->havoc_stage_time / 1000, det_time_rate,
          det_fuzzed_rate, q->skipdet_e->undet_bits,
          afl->skipdet_g->undet_bits_threshold, q->skipdet_e->continue_inf);

  fflush(profile_fd);

}

