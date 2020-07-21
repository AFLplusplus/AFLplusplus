/*
   american fuzzy lop++ - afl-frida skeleton example
   -------------------------------------------------

   Copyright 2020 AFLplusplus Project. All rights reserved.

   Written mostly by meme -> https://github.com/meme/hotwax

   Modificationy by Marc Heuse <mh@mh-sec.de>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

   http://www.apache.org/licenses/LICENSE-2.0

   HOW-TO
   ======

   You only need to change the following:

   1. set the defines and function call parameters.
   2. dl load the library you want to fuzz, lookup the functions you need
      and setup the calls to these.
   3. in the while loop you call the functions in the necessary order -
      incl the cleanup. the cleanup is important!

   Just look these steps up in the code, look for "// STEP x:"

*/

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/shm.h>
#include <dlfcn.h>

#ifndef __APPLE__
  #include <sys/wait.h>
  #include <sys/personality.h>
#endif

int debug = 0;

// STEP 1:

// The presets are for the example libtestinstr.so:

/* What is the name of the library to fuzz */
#define TARGET_LIBRARY "libtestinstr.so"

/* What is the name of the function to fuzz */
#define TARGET_FUNCTION "testinstr"

/* here you need to specify the parameter for the target function */
static void *(*o_function)(uint8_t *, int);

// END STEP 1

#include "frida-gum.h"

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

static void         gum_fake_event_sink_iface_init(gpointer g_iface,
                                                   gpointer iface_data);
static void         gum_fake_event_sink_finalize(GObject *obj);
static GumEventType gum_fake_event_sink_query_mask(GumEventSink *sink);
static void gum_fake_event_sink_process(GumEventSink *sink, const GumEvent *ev);
void instr_basic_block(GumStalkerIterator *iterator, GumStalkerOutput *output,
                       gpointer user_data);
void afl_setup(void);
void afl_start_forkserver(void);
int  __afl_persistent_loop(unsigned int max_cnt);

static void gum_fake_event_sink_class_init(GumFakeEventSinkClass *klass) {

  GObjectClass *object_class = G_OBJECT_CLASS(klass);
  object_class->finalize = gum_fake_event_sink_finalize;

}

static void gum_fake_event_sink_iface_init(gpointer g_iface,
                                           gpointer iface_data) {

  GumEventSinkInterface *iface = (GumEventSinkInterface *)g_iface;
  iface->query_mask = gum_fake_event_sink_query_mask;
  iface->process = gum_fake_event_sink_process;

}

G_DEFINE_TYPE_EXTENDED(GumFakeEventSink, gum_fake_event_sink, G_TYPE_OBJECT, 0,
                       G_IMPLEMENT_INTERFACE(GUM_TYPE_EVENT_SINK,
                                             gum_fake_event_sink_iface_init))

#include "../../config.h"

// Shared memory fuzzing.
int                   __afl_sharedmem_fuzzing = 1;
extern unsigned int * __afl_fuzz_len;
extern unsigned char *__afl_fuzz_ptr;

// Notify AFL about persistent mode.
static volatile char AFL_PERSISTENT[] = "##SIG_AFL_PERSISTENT##";
int                  __afl_persistent_loop(unsigned int);

// Notify AFL about deferred forkserver.
static volatile char AFL_DEFER_FORKSVR[] = "##SIG_AFL_DEFER_FORKSRV##";
void                 __afl_manual_init();

// Because we do our own logging.
extern uint8_t *        __afl_area_ptr;
static __thread guint64 previous_pc;

// Frida stuff below.
typedef struct {

  GumAddress base_address;
  guint64    code_start, code_end;

} range_t;

inline static void afl_maybe_log(guint64 current_pc) {

  // fprintf(stderr, "PC: %p ^ %p\n", current_pc, previous_pc);

  current_pc = (current_pc >> 4) ^ (current_pc << 8);
  current_pc &= MAP_SIZE - 1;

  __afl_area_ptr[current_pc ^ previous_pc]++;
  previous_pc = current_pc >> 1;

}

static void on_basic_block(GumCpuContext *context, gpointer user_data) {

  afl_maybe_log((guint64)user_data);

}

void instr_basic_block(GumStalkerIterator *iterator, GumStalkerOutput *output,
                       gpointer user_data) {

  range_t *range = (range_t *)user_data;

  const cs_insn *instr;
  gboolean       begin = TRUE;
  while (gum_stalker_iterator_next(iterator, &instr)) {

    if (begin) {

      if (instr->address >= range->code_start &&
          instr->address <= range->code_end) {

        gum_stalker_iterator_put_callout(iterator, on_basic_block,
                                         (gpointer)instr->address, NULL);
        begin = FALSE;

      }

    }

    gum_stalker_iterator_keep(iterator);

  }

}

static void gum_fake_event_sink_init(GumFakeEventSink *self) {

}

static void gum_fake_event_sink_finalize(GObject *obj) {

  G_OBJECT_CLASS(gum_fake_event_sink_parent_class)->finalize(obj);

}

GumEventSink *gum_fake_event_sink_new(void) {

  GumFakeEventSink *sink;
  sink = (GumFakeEventSink *)g_object_new(GUM_TYPE_FAKE_EVENT_SINK, NULL);
  return GUM_EVENT_SINK(sink);

}

void gum_fake_event_sink_reset(GumFakeEventSink *self) {

}

static GumEventType gum_fake_event_sink_query_mask(GumEventSink *sink) {

  return 0;

}

typedef struct library_list {

  uint8_t *name;
  uint64_t addr_start, addr_end;

} library_list_t;

#define MAX_LIB_COUNT 256
static library_list_t liblist[MAX_LIB_COUNT];
static u32            liblist_cnt;

void read_library_information() {

#if defined(__linux__)
  FILE *f;
  u8    buf[1024], *b, *m, *e, *n;

  if ((f = fopen("/proc/self/maps", "r")) == NULL) {

    fprintf(stderr, "Error: cannot open /proc/self/maps\n");
    exit(-1);

  }

  if (debug) fprintf(stderr, "Library list:\n");
  while (fgets(buf, sizeof(buf), f)) {

    if (strstr(buf, " r-x")) {

      if (liblist_cnt >= MAX_LIB_COUNT) {

        fprintf(
            stderr,
            "Warning: too many libraries to old, maximum count of %d reached\n",
            liblist_cnt);
        return;

      }

      b = buf;
      m = index(buf, '-');
      e = index(buf, ' ');
      if ((n = rindex(buf, '/')) == NULL) n = rindex(buf, ' ');
      if (n &&
          ((*n >= '0' && *n <= '9') || *n == '[' || *n == '{' || *n == '('))
        n = NULL;
      else
        n++;
      if (b && m && e && n && *n) {

        *m++ = 0;
        *e = 0;
        if (n[strlen(n) - 1] == '\n') n[strlen(n) - 1] = 0;

        if (rindex(n, '/') != NULL) {

          n = rindex(n, '/');
          n++;

        }

        liblist[liblist_cnt].name = strdup(n);
        liblist[liblist_cnt].addr_start = strtoull(b, NULL, 16);
        liblist[liblist_cnt].addr_end = strtoull(m, NULL, 16);
        if (debug)
          fprintf(
              stderr, "%s:%llx (%llx-%llx)\n", liblist[liblist_cnt].name,
              liblist[liblist_cnt].addr_end - liblist[liblist_cnt].addr_start,
              liblist[liblist_cnt].addr_start,
              liblist[liblist_cnt].addr_end - 1);
        liblist_cnt++;

      }

    }

  }

  if (debug) fprintf(stderr, "\n");

#elif defined(__FreeBSD__)
  int    mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, getpid()};
  char * buf, *start, *end;
  size_t miblen = sizeof(mib) / sizeof(mib[0]);
  size_t len;

  if (debug) fprintf(stderr, "Library list:\n");
  if (sysctl(mib, miblen, NULL, &len, NULL, 0) == -1) { return; }

  len = len * 4 / 3;

  buf = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
  if (buf == MAP_FAILED) { return; }
  if (sysctl(mib, miblen, buf, &len, NULL, 0) == -1) {

    munmap(buf, len);
    return;

  }

  start = buf;
  end = buf + len;

  while (start < end) {

    struct kinfo_vmentry *region = (struct kinfo_vmentry *)start;
    size_t                size = region->kve_structsize;

    if (size == 0) { break; }

    if ((region->kve_protection & KVME_PROT_READ) &&
        !(region->kve_protection & KVME_PROT_EXEC)) {

      liblist[liblist_cnt].name =
          region->kve_path[0] != '\0' ? strdup(region->kve_path) : 0;
      liblist[liblist_cnt].addr_start = region->kve_start;
      liblist[liblist_cnt].addr_end = region->kve_end;

      if (debug) {

        fprintf(stderr, "%s:%x (%lx-%lx)\n", liblist[liblist_cnt].name,
                liblist[liblist_cnt].addr_end - liblist[liblist_cnt].addr_start,
                liblist[liblist_cnt].addr_start,
                liblist[liblist_cnt].addr_end - 1);

      }

      liblist_cnt++;

    }

    start += size;

  }

#endif

}

library_list_t *find_library(char *name) {

  char *filename = rindex(name, '/');

  if (filename)
    filename++;
  else
    filename = name;

#if defined(__linux__)
  u32 i;
  for (i = 0; i < liblist_cnt; i++)
    if (strcmp(liblist[i].name, filename) == 0) return &liblist[i];
#elif defined(__APPLE__) && defined(__LP64__)
  kern_return_t         err;
  static library_list_t lib;

  // get the list of all loaded modules from dyld
  // the task_info mach API will get the address of the dyld all_image_info
  // struct for the given task from which we can get the names and load
  // addresses of all modules
  task_dyld_info_data_t  task_dyld_info;
  mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
  err = task_info(mach_task_self(), TASK_DYLD_INFO,
                  (task_info_t)&task_dyld_info, &count);

  const struct dyld_all_image_infos *all_image_infos =
      (const struct dyld_all_image_infos *)task_dyld_info.all_image_info_addr;
  const struct dyld_image_info *image_infos = all_image_infos->infoArray;

  for (size_t i = 0; i < all_image_infos->infoArrayCount; i++) {

    const char *      image_name = image_infos[i].imageFilePath;
    mach_vm_address_t image_load_address =
        (mach_vm_address_t)image_infos[i].imageLoadAddress;
    if (strstr(image_name, name)) {

      lib.name = name;
      lib.addr_start = (u64)image_load_address;
      lib.addr_end = 0;
      return &lib;

    }

  }

#endif

  return NULL;

}

static void gum_fake_event_sink_process(GumEventSink *  sink,
                                        const GumEvent *ev) {

}

/* Because this CAN be called more than once, it will return the LAST range */
static int enumerate_ranges(const GumRangeDetails *details,
                            gpointer               user_data) {

  GumMemoryRange *code_range = (GumMemoryRange *)user_data;
  memcpy(code_range, details->range, sizeof(*code_range));
  return 0;

}

int main() {

#ifndef __APPLE__
  (void)personality(ADDR_NO_RANDOMIZE);  // disable ASLR
#endif

  // STEP 2: load the library you want to fuzz and lookup the functions,
  //         inclusive of the cleanup functions.
  //         If there is just one function, then there is nothing to change
  //         or add here.

  void *dl = dlopen(TARGET_LIBRARY, RTLD_LAZY);
  if (!dl) {

    fprintf(stderr, "Could not load %s\n", TARGET_LIBRARY);
    exit(-1);

  }

  if (!(o_function = dlsym(dl, TARGET_FUNCTION))) {

    fprintf(stderr, "Could not find function %s\n", TARGET_FUNCTION);
    exit(-1);

  }

  // END STEP 2

  read_library_information();
  library_list_t *lib = find_library(TARGET_LIBRARY);

  if (lib == NULL) {

    fprintf(stderr, "Could not find target library\n");
    exit(-1);

  }

  gum_init_embedded();
  if (!gum_stalker_is_supported()) {

    gum_deinit_embedded();
    return 1;

  }

  GumStalker *stalker = gum_stalker_new();

  /*
  This does not work here as we load a shared library. pretty sure this
  would also be easily solvable with frida gum, but I already have all the
  code I need from afl-untracer

  GumAddress base_address = gum_module_find_base_address(TARGET_LIBRARY);
  GumMemoryRange code_range;
  gum_module_enumerate_ranges(TARGET_LIBRARY, GUM_PAGE_RX, enumerate_ranges,
                              &code_range);
  guint64 code_start = code_range.base_address - base_address;
  guint64 code_end = (code_range.base_address + code_range.size) - base_address;
  range_t instr_range = {base_address, code_start, code_end};
  */
  range_t instr_range = {0, lib->addr_start, lib->addr_end};

  GumStalkerTransformer *transformer =
      gum_stalker_transformer_make_from_callback(instr_basic_block,
                                                 &instr_range, NULL);

  GumEventSink *event_sink = gum_fake_event_sink_new();

  // to ensure that the signatures are not optimized out
  memcpy(__afl_area_ptr, (void *)AFL_PERSISTENT, sizeof(AFL_PERSISTENT) + 1);
  memcpy(__afl_area_ptr + 32, (void *)AFL_DEFER_FORKSVR,
         sizeof(AFL_DEFER_FORKSVR) + 1);
  __afl_manual_init();

  //
  // any expensive target library initialization that has to be done just once
  // - put that here
  //

  gum_stalker_follow_me(stalker, transformer, event_sink);

  while (__afl_persistent_loop(UINT32_MAX) != 0) {

    previous_pc = 0;  // Required!

#ifdef _DEBUG
    fprintf(stderr, "CLIENT crc: %016llx len: %u\n", hash64(__afl_fuzz_ptr, *__a
    fprintf(stderr, "RECV:");
    for (int i = 0; i < *__afl_fuzz_len; i++)
      fprintf(stderr, "%02x", __afl_fuzz_ptr[i]);
    fprintf(stderr,"\n");
#endif

    // STEP 3: ensure the minimum length is present and setup the target
    //         function to fuzz.

    if (*__afl_fuzz_len > 0) {

      __afl_fuzz_ptr[*__afl_fuzz_len] = 0;  // if you need to null terminate
      (*o_function)(__afl_fuzz_ptr, *__afl_fuzz_len);

    }

    // END STEP 3

  }

  gum_stalker_unfollow_me(stalker);

  while (gum_stalker_garbage_collect(stalker))
    g_usleep(10000);

  g_object_unref(stalker);
  g_object_unref(transformer);
  g_object_unref(event_sink);
  gum_deinit_embedded();

  return 0;

}

