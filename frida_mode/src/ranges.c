#include "frida-gumjs.h"

#include "debug.h"

#include "lib.h"
#include "ranges.h"
#include "stalker.h"
#include "util.h"

#define MAX_RANGES 20

typedef struct {

  gchar *         suffix;
  GumMemoryRange *range;
  gboolean        done;

} convert_name_ctx_t;

gboolean ranges_debug_maps = FALSE;
gboolean ranges_inst_libs = FALSE;
gboolean ranges_inst_jit = FALSE;

static GArray *module_ranges = NULL;
static GArray *libs_ranges = NULL;
static GArray *jit_ranges = NULL;
static GArray *include_ranges = NULL;
static GArray *exclude_ranges = NULL;
static GArray *ranges = NULL;

static void convert_address_token(gchar *token, GumMemoryRange *range) {

  gchar **tokens;
  int     token_count;
  tokens = g_strsplit(token, "-", 2);
  for (token_count = 0; tokens[token_count] != NULL; token_count++) {}

  if (token_count != 2) {

    FATAL("Invalid range (should have two addresses seperated by a '-'): %s\n",
          token);

  }

  gchar *from_str = tokens[0];
  gchar *to_str = tokens[1];

  if (!g_str_has_prefix(from_str, "0x")) {

    FATAL("Invalid range: %s - Start address should have 0x prefix: %s\n",
          token, from_str);

  }

  if (!g_str_has_prefix(to_str, "0x")) {

    FATAL("Invalid range: %s - End address should have 0x prefix: %s\n", token,
          to_str);

  }

  from_str = &from_str[2];
  to_str = &to_str[2];

  for (char *c = from_str; *c != '\0'; c++) {

    if (!g_ascii_isxdigit(*c)) {

      FATAL("Invalid range: %s - Start address not formed of hex digits: %s\n",
            token, from_str);

    }

  }

  for (char *c = to_str; *c != '\0'; c++) {

    if (!g_ascii_isxdigit(*c)) {

      FATAL("Invalid range: %s - End address not formed of hex digits: %s\n",
            token, to_str);

    }

  }

  guint64 from = g_ascii_strtoull(from_str, NULL, 16);
  if (from == 0) {

    FATAL("Invalid range: %s - Start failed hex conversion: %s\n", token,
          from_str);

  }

  guint64 to = g_ascii_strtoull(to_str, NULL, 16);
  if (to == 0) {

    FATAL("Invalid range: %s - End failed hex conversion: %s\n", token, to_str);

  }

  if (from >= to) {

    FATAL("Invalid range: %s - Start (0x%016" G_GINT64_MODIFIER
          "x) must be less than end "
          "(0x%016" G_GINT64_MODIFIER "x)\n",
          token, from, to);

  }

  range->base_address = from;
  range->size = to - from;

  g_strfreev(tokens);

}

static gboolean convert_name_token_for_module(const GumModuleDetails *details,
                                              gpointer user_data) {

  convert_name_ctx_t *ctx = (convert_name_ctx_t *)user_data;
  if (details->path == NULL) { return true; };

  if (!g_str_has_suffix(details->path, ctx->suffix)) { return true; };

  OKF("Found module - prefix: %s, 0x%016" G_GINT64_MODIFIER
      "x-0x%016" G_GINT64_MODIFIER "x %s",
      ctx->suffix, details->range->base_address,
      details->range->base_address + details->range->size, details->path);

  *ctx->range = *details->range;
  ctx->done = true;
  return false;

}

static void convert_name_token(gchar *token, GumMemoryRange *range) {

  gchar *            suffix = g_strconcat("/", token, NULL);
  convert_name_ctx_t ctx = {.suffix = suffix, .range = range, .done = false};

  gum_process_enumerate_modules(convert_name_token_for_module, &ctx);
  if (!ctx.done) { FATAL("Failed to resolve module: %s\n", token); }
  g_free(suffix);

}

static void convert_token(gchar *token, GumMemoryRange *range) {

  if (g_str_has_prefix(token, "0x")) {

    convert_address_token(token, range);

  }

  else {

    convert_name_token(token, range);

  }

  OKF("Converted token: %s -> 0x%016" G_GINT64_MODIFIER
      "x-0x%016" G_GINT64_MODIFIER "x\n",
      token, range->base_address, range->base_address + range->size);

}

gint range_sort(gconstpointer a, gconstpointer b) {

  return ((GumMemoryRange *)a)->base_address -
         ((GumMemoryRange *)b)->base_address;

}

static gboolean print_ranges_callback(const GumRangeDetails *details,
                                      gpointer               user_data) {

  UNUSED_PARAMETER(user_data);

  if (details->file == NULL) {

    OKF("MAP - 0x%016" G_GINT64_MODIFIER "x - 0x%016" G_GINT64_MODIFIER
        "X %c%c%c",
        details->range->base_address,
        details->range->base_address + details->range->size,
        details->protection & GUM_PAGE_READ ? 'R' : '-',
        details->protection & GUM_PAGE_WRITE ? 'W' : '-',
        details->protection & GUM_PAGE_EXECUTE ? 'X' : '-');

  } else {

    OKF("MAP - 0x%016" G_GINT64_MODIFIER "x - 0x%016" G_GINT64_MODIFIER
        "X %c%c%c %s(0x%016" G_GINT64_MODIFIER "x)",
        details->range->base_address,
        details->range->base_address + details->range->size,
        details->protection & GUM_PAGE_READ ? 'R' : '-',
        details->protection & GUM_PAGE_WRITE ? 'W' : '-',
        details->protection & GUM_PAGE_EXECUTE ? 'X' : '-', details->file->path,
        details->file->offset);

  }

  return true;

}

static void print_ranges(char *key, GArray *ranges) {

  OKF("Range: %s Length: %d", key, ranges->len);
  for (guint i = 0; i < ranges->len; i++) {

    GumMemoryRange *curr = &g_array_index(ranges, GumMemoryRange, i);
    GumAddress      curr_limit = curr->base_address + curr->size;
    OKF("Range: %s Idx: %3d - 0x%016" G_GINT64_MODIFIER
        "x-0x%016" G_GINT64_MODIFIER "x",
        key, i, curr->base_address, curr_limit);

  }

}

static gboolean collect_module_ranges_callback(const GumRangeDetails *details,
                                               gpointer user_data) {

  GArray *       ranges = (GArray *)user_data;
  GumMemoryRange range = *details->range;
  g_array_append_val(ranges, range);
  return TRUE;

}

static GArray *collect_module_ranges(void) {

  GArray *result;
  result = g_array_new(false, false, sizeof(GumMemoryRange));
  gum_process_enumerate_ranges(GUM_PAGE_NO_ACCESS,
                               collect_module_ranges_callback, result);
  print_ranges("Modules", result);
  return result;

}

static void check_for_overlaps(GArray *array) {

  for (guint i = 1; i < array->len; i++) {

    GumMemoryRange *prev = &g_array_index(array, GumMemoryRange, i - 1);
    GumMemoryRange *curr = &g_array_index(array, GumMemoryRange, i);
    GumAddress      prev_limit = prev->base_address + prev->size;
    GumAddress      curr_limit = curr->base_address + curr->size;
    if (prev_limit > curr->base_address) {

      FATAL("OVerlapping ranges 0x%016" G_GINT64_MODIFIER
            "x-0x%016" G_GINT64_MODIFIER "x 0x%016" G_GINT64_MODIFIER
            "x-0x%016" G_GINT64_MODIFIER "x",
            prev->base_address, prev_limit, curr->base_address, curr_limit);

    }

  }

}

void ranges_add_include(GumMemoryRange *range) {

  g_array_append_val(include_ranges, *range);
  g_array_sort(include_ranges, range_sort);
  check_for_overlaps(include_ranges);

}

void ranges_add_exclude(GumMemoryRange *range) {

  g_array_append_val(exclude_ranges, *range);
  g_array_sort(exclude_ranges, range_sort);
  check_for_overlaps(exclude_ranges);

}

static GArray *collect_ranges(char *env_key) {

  char *         env_val;
  gchar **       tokens;
  int            token_count;
  GumMemoryRange range;
  int            i;
  GArray *       result;

  result = g_array_new(false, false, sizeof(GumMemoryRange));

  env_val = getenv(env_key);
  if (env_val == NULL) return result;

  tokens = g_strsplit(env_val, ",", MAX_RANGES);

  for (token_count = 0; tokens[token_count] != NULL; token_count++)
    ;

  for (i = 0; i < token_count; i++) {

    convert_token(tokens[i], &range);
    g_array_append_val(result, range);

  }

  g_array_sort(result, range_sort);

  check_for_overlaps(result);

  print_ranges(env_key, result);

  g_strfreev(tokens);

  return result;

}

static GArray *collect_libs_ranges(void) {

  GArray *       result;
  GumMemoryRange range;
  result = g_array_new(false, false, sizeof(GumMemoryRange));

  if (ranges_inst_libs) {

    range.base_address = 0;
    range.size = G_MAXULONG;

  } else {

    range.base_address = lib_get_text_base();
    range.size = lib_get_text_limit() - lib_get_text_base();

  }

  g_array_append_val(result, range);

  print_ranges("AFL_INST_LIBS", result);

  return result;

}

static gboolean collect_jit_ranges_callback(const GumRangeDetails *details,
                                            gpointer               user_data) {

  GArray *ranges = (GArray *)user_data;

  /* If the executable code isn't backed by a file, it's probably JIT */
  if (details->file == NULL) {

    GumMemoryRange range = *details->range;
    g_array_append_val(ranges, range);

  }

  return TRUE;

}

static GArray *collect_jit_ranges(void) {

  GArray *result;
  result = g_array_new(false, false, sizeof(GumMemoryRange));
  if (!ranges_inst_jit) {

    gum_process_enumerate_ranges(GUM_PAGE_EXECUTE, collect_jit_ranges_callback,
                                 result);

  }

  print_ranges("JIT", result);
  return result;

}

static gboolean intersect_range(GumMemoryRange *rr, GumMemoryRange *ra,
                                GumMemoryRange *rb) {

  GumAddress rab = ra->base_address;
  GumAddress ral = rab + ra->size;

  GumAddress rbb = rb->base_address;
  GumAddress rbl = rbb + rb->size;

  GumAddress rrb = 0;
  GumAddress rrl = 0;

  rr->base_address = 0;
  rr->size = 0;

  /* ra is before rb */
  if (ral < rbb) { return false; }

  /* ra is after rb */
  if (rab > rbl) { return true; }

  /* The largest of the two base addresses */
  rrb = rab > rbb ? rab : rbb;

  /* The smallest of the two limits */
  rrl = ral < rbl ? ral : rbl;

  rr->base_address = rrb;
  rr->size = rrl - rrb;
  return true;

}

static GArray *intersect_ranges(GArray *a, GArray *b) {

  GArray *        result;
  GumMemoryRange *ra;
  GumMemoryRange *rb;
  GumMemoryRange  ri;

  result = g_array_new(false, false, sizeof(GumMemoryRange));

  for (guint i = 0; i < a->len; i++) {

    ra = &g_array_index(a, GumMemoryRange, i);
    for (guint j = 0; j < b->len; j++) {

      rb = &g_array_index(b, GumMemoryRange, j);

      if (!intersect_range(&ri, ra, rb)) { break; }

      if (ri.size == 0) { continue; }

      g_array_append_val(result, ri);

    }

  }

  return result;

}

static GArray *subtract_ranges(GArray *a, GArray *b) {

  GArray *        result;
  GumMemoryRange *ra;
  GumAddress      ral;
  GumMemoryRange *rb;
  GumMemoryRange  ri;
  GumMemoryRange  rs;

  result = g_array_new(false, false, sizeof(GumMemoryRange));

  for (guint i = 0; i < a->len; i++) {

    ra = &g_array_index(a, GumMemoryRange, i);
    ral = ra->base_address + ra->size;
    for (guint j = 0; j < b->len; j++) {

      rb = &g_array_index(b, GumMemoryRange, j);

      /*
       * If rb is after ra, we have no more possible intersections and we can
       * simply keep the remaining range
       */
      if (!intersect_range(&ri, ra, rb)) { break; }

      /*
       * If there is no intersection, then rb must be before ra, so we must
       * continue
       */
      if (ri.size == 0) { continue; }

      /*
       * If the intersection is part way through the range, then we keep the
       * start of the range
       */
      if (ra->base_address < ri.base_address) {

        rs.base_address = ra->base_address;
        rs.size = ri.base_address - ra->base_address;
        g_array_append_val(result, rs);

      }

      /*
       * If the intersection extends past the limit of the range, then we should
       * continue with the next range
       */
      if ((ri.base_address + ri.size) > ral) {

        ra->base_address = ral;
        ra->size = 0;
        break;

      }

      /*
       * Otherwise we advance the base of the range to the end of the
       * intersection and continue with the remainder of the range
       */
      ra->base_address = ri.base_address + ri.size;
      ra->size = ral - ra->base_address;

    }

    /*
     * When we have processed all the possible intersections, we add what is
     * left
     */
    if (ra->size != 0) g_array_append_val(result, *ra);

  }

  return result;

}

static GArray *merge_ranges(GArray *a) {

  GArray *        result;
  GumMemoryRange  rp;
  GumMemoryRange *r;

  result = g_array_new(false, false, sizeof(GumMemoryRange));
  if (a->len == 0) return result;

  rp = g_array_index(a, GumMemoryRange, 0);

  for (guint i = 1; i < a->len; i++) {

    r = &g_array_index(a, GumMemoryRange, i);

    if (rp.base_address + rp.size == r->base_address) {

      rp.size += r->size;

    } else {

      g_array_append_val(result, rp);
      rp.base_address = r->base_address;
      rp.size = r->size;
      continue;

    }

  }

  g_array_append_val(result, rp);

  return result;

}

void ranges_config(void) {

  if (getenv("AFL_FRIDA_DEBUG_MAPS") != NULL) { ranges_debug_maps = TRUE; }
  if (getenv("AFL_INST_LIBS") != NULL) { ranges_inst_libs = TRUE; }
  if (getenv("AFL_FRIDA_INST_JIT") != NULL) { ranges_inst_jit = TRUE; }

  if (ranges_debug_maps) {

    gum_process_enumerate_ranges(GUM_PAGE_NO_ACCESS, print_ranges_callback,
                                 NULL);

  }

  include_ranges = collect_ranges("AFL_FRIDA_INST_RANGES");
  exclude_ranges = collect_ranges("AFL_FRIDA_EXCLUDE_RANGES");

}

void ranges_init(void) {

  GumMemoryRange ri;
  GArray *       step1;
  GArray *       step2;
  GArray *       step3;
  GArray *       step4;
  GArray *       step5;

  OKF("Ranges - Instrument jit [%c]", ranges_inst_jit ? 'X' : ' ');
  OKF("Ranges - Instrument libraries [%c]", ranges_inst_libs ? 'X' : ' ');

  print_ranges("AFL_FRIDA_INST_RANGES", include_ranges);
  print_ranges("AFL_FRIDA_EXCLUDE_RANGES", exclude_ranges);

  OKF("Ranges - Instrument libraries [%c]", ranges_inst_libs ? 'X' : ' ');

  print_ranges("AFL_FRIDA_INST_RANGES", include_ranges);
  print_ranges("AFL_FRIDA_EXCLUDE_RANGES", exclude_ranges);

  module_ranges = collect_module_ranges();
  libs_ranges = collect_libs_ranges();
  jit_ranges = collect_jit_ranges();

  /* If include ranges is empty, then assume everything is included */
  if (include_ranges->len == 0) {

    ri.base_address = 0;
    ri.size = G_MAXULONG;
    g_array_append_val(include_ranges, ri);

  }

  /* Intersect with .text section of main executable unless AFL_INST_LIBS */
  step1 = intersect_ranges(module_ranges, libs_ranges);
  print_ranges("step1", step1);

  /* Intersect with AFL_FRIDA_INST_RANGES */
  step2 = intersect_ranges(step1, include_ranges);
  print_ranges("step2", step2);

  /* Subtract AFL_FRIDA_EXCLUDE_RANGES */
  step3 = subtract_ranges(step2, exclude_ranges);
  print_ranges("step3", step3);

  step4 = subtract_ranges(step3, jit_ranges);
  print_ranges("step4", step4);

  /*
   * After step4, we have the total ranges to be instrumented, we now subtract
   * that from the original ranges of the modules to configure stalker.
   */
  step5 = subtract_ranges(module_ranges, step4);
  print_ranges("step5", step5);

  ranges = merge_ranges(step5);
  print_ranges("final", ranges);

  g_array_free(step5, TRUE);
  g_array_free(step4, TRUE);
  g_array_free(step3, TRUE);
  g_array_free(step2, TRUE);
  g_array_free(step1, TRUE);

  ranges_exclude();

}

gboolean range_is_excluded(GumAddress address) {

  if (ranges == NULL) { return false; }

  for (guint i = 0; i < ranges->len; i++) {

    GumMemoryRange *curr = &g_array_index(ranges, GumMemoryRange, i);
    GumAddress      curr_limit = curr->base_address + curr->size;

    if (address < curr->base_address) { return false; }

    if (address < curr_limit) { return true; }

  }

  return false;

}

void ranges_exclude() {

  GumMemoryRange *r;
  GumStalker *    stalker = stalker_get();

  OKF("Excluding ranges");

  for (guint i = 0; i < ranges->len; i++) {

    r = &g_array_index(ranges, GumMemoryRange, i);
    gum_stalker_exclude(stalker, r);

  }

}

