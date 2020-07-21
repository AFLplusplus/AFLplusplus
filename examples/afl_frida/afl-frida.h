extern int is_persistent;

G_BEGIN_DECLS

#define GUM_TYPE_FAKE_EVENT_SINK (gum_fake_event_sink_get_type())

G_DECLARE_FINAL_TYPE(GumFakeEventSink, gum_fake_event_sink, GUM,
                     FAKE_EVENT_SINK, GObject)

struct _GumFakeEventSink {

  GObject      parent;
  GumEventType mask;

};

GumEventSink *gum_fake_event_sink_new(void);
void          gum_fake_event_sink_reset(GumFakeEventSink *self);

G_END_DECLS

typedef struct {

  GumAddress base_address;
  guint64    code_start, code_end;

} range_t;

void instr_basic_block(GumStalkerIterator *iterator, GumStalkerOutput *output,
                       gpointer user_data);
#pragma once

void afl_setup(void);
void afl_start_forkserver(void);
int  __afl_persistent_loop(unsigned int max_cnt);

inline static inline void afl_maybe_log(guint64 current_pc) {

  extern unsigned int afl_instr_rms;
  extern uint8_t *    afl_area_ptr;

  static __thread guint64 previous_pc;

  current_pc = (current_pc >> 4) ^ (current_pc << 8);
  current_pc &= MAP_SIZE - 1;

  if (current_pc >= afl_instr_rms) return;

  afl_area_ptr[current_pc ^ previous_pc]++;
  previous_pc = current_pc >> 1;

}

