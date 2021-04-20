// 0x123-0x321
// module.so

#include "ranges.h"
#include "debug.h"

#define MAX_RANGES 20

typedef struct {

  gchar *         suffix;
  GumMemoryRange *range;
  gboolean        done;

} convert_name_ctx_t;

typedef struct {

  GumStalker *stalker;
  GArray *    array;

} include_range_ctx_t;

GArray * ranges = NULL;
gboolean exclude_ranges = false;

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

  if (g_strrstr(token, "-")) {

    convert_address_token(token, range);

  } else {

    convert_name_token(token, range);

  }

  OKF("Converted token: %s -> 0x%016" G_GINT64_MODIFIER
      "x-0x%016" G_GINT64_MODIFIER "x\n",
      token, range->base_address, range->base_address + range->size);

}

static gboolean include_ranges(const GumRangeDetails *details,
                               gpointer               user_data) {

  include_range_ctx_t *ctx = (include_range_ctx_t *)user_data;
  GArray *             array = (GArray *)ctx->array;
  GumAddress           base = details->range->base_address;
  GumAddress limit = details->range->base_address + details->range->size;

  OKF("Range for inclusion 0x%016" G_GINT64_MODIFIER
      "x-0x%016" G_GINT64_MODIFIER "x",
      base, limit);

  for (int i = 0; i < array->len; i++) {

    GumMemoryRange *range = &g_array_index(array, GumMemoryRange, i);
    GumAddress      range_base = range->base_address;
    GumAddress      range_limit = range->base_address + range->size;

    /* Before the region */
    if (range_limit < base) { continue; }

    /* After the region */
    if (range_base > limit) {

      GumMemoryRange exclude = {.base_address = base, .size = limit - base};
      OKF("\t Excluding 0x%016" G_GINT64_MODIFIER "x-0x%016" G_GINT64_MODIFIER
          "x",
          base, limit);
      gum_stalker_exclude(ctx->stalker, &exclude);
      return true;

    }

    /* Overlap the start of the region */
    if (range_base < base) {

      /* Range contains the region */
      if (range_limit > limit) {

        return true;

      } else {

        base = range_limit;
        continue;

      }

      /* Overlap the end of the region */

    } else {

      GumMemoryRange exclude = {.base_address = base,
                                .size = range_base - base};
      OKF("\t Excluding 0x%016" G_GINT64_MODIFIER "x-0x%016" G_GINT64_MODIFIER
          "x",
          base, range_base);
      gum_stalker_exclude(ctx->stalker, &exclude);
      /* Extend past the end of the region */
      if (range_limit >= limit) {

        return true;

        /* Contained within the region */

      } else {

        base = range_limit;
        continue;

      }

    }

  }

  GumMemoryRange exclude = {.base_address = base, .size = limit - base};
  OKF("\t Excluding 0x%016" G_GINT64_MODIFIER "x-0x%016" G_GINT64_MODIFIER "x",
      base, limit);
  gum_stalker_exclude(ctx->stalker, &exclude);
  return true;

}

gint range_sort(gconstpointer a, gconstpointer b) {

  return ((GumMemoryRange *)a)->base_address -
         ((GumMemoryRange *)b)->base_address;

}

static gboolean print_ranges(const GumRangeDetails *details,
                             gpointer               user_data) {

  if (details->file == NULL) {

    OKF("MAP - 0x%016" G_GINT64_MODIFIER "x - 0x%016" G_GINT64_MODIFIER "X",
        details->range->base_address,
        details->range->base_address + details->range->size);

  } else {

    OKF("MAP - 0x%016" G_GINT64_MODIFIER "x - 0x%016" G_GINT64_MODIFIER
        "X %s(0x%016" G_GINT64_MODIFIER "x)",
        details->range->base_address,
        details->range->base_address + details->range->size,
        details->file->path, details->file->offset);

  }

  return true;

}

void ranges_init(GumStalker *stalker) {

  char *         showmaps;
  char *         include;
  char *         exclude;
  char *         list;
  gchar **       tokens;
  int            token_count;
  GumMemoryRange range;

  int i;

  showmaps = getenv("AFL_FRIDA_DEBUG_MAPS");
  include = getenv("AFL_FRIDA_INST_RANGES");
  exclude = getenv("AFL_FRIDA_EXCLUDE_RANGES");

  if (showmaps) {

    gum_process_enumerate_ranges(GUM_PAGE_NO_ACCESS, print_ranges, NULL);

  }

  if (include != NULL && exclude != NULL) {

    FATAL(
        "Cannot specifify both AFL_FRIDA_INST_RANGES and "
        "AFL_FRIDA_EXCLUDE_RANGES");

  }

  if (include == NULL && exclude == NULL) { return; }

  list = include == NULL ? exclude : include;
  exclude_ranges = include == NULL ? true : false;

  tokens = g_strsplit(list, ",", MAX_RANGES);

  for (token_count = 0; tokens[token_count] != NULL; token_count++)
    ;

  ranges = g_array_sized_new(false, false, sizeof(GumMemoryRange), token_count);

  for (i = 0; i < token_count; i++) {

    convert_token(tokens[i], &range);
    g_array_append_val(ranges, range);

  }

  g_array_sort(ranges, range_sort);

  /* Check for overlaps */
  for (i = 1; i < token_count; i++) {

    GumMemoryRange *prev = &g_array_index(ranges, GumMemoryRange, i - 1);
    GumMemoryRange *curr = &g_array_index(ranges, GumMemoryRange, i);
    GumAddress      prev_limit = prev->base_address + prev->size;
    GumAddress      curr_limit = curr->base_address + curr->size;
    if (prev_limit > curr->base_address) {

      FATAL("OVerlapping ranges 0x%016" G_GINT64_MODIFIER
            "x-0x%016" G_GINT64_MODIFIER "x 0x%016" G_GINT64_MODIFIER
            "x-0x%016" G_GINT64_MODIFIER "x",
            prev->base_address, prev_limit, curr->base_address, curr_limit);

    }

  }

  for (i = 0; i < token_count; i++) {

    GumMemoryRange *curr = &g_array_index(ranges, GumMemoryRange, i);
    GumAddress      curr_limit = curr->base_address + curr->size;
    OKF("Range %3d - 0x%016" G_GINT64_MODIFIER "x-0x%016" G_GINT64_MODIFIER "x",
        i, curr->base_address, curr_limit);

  }

  if (include == NULL) {

    for (i = 0; i < token_count; i++) {

      gum_stalker_exclude(stalker, &g_array_index(ranges, GumMemoryRange, i));

    }

  } else {

    include_range_ctx_t ctx = {.stalker = stalker, .array = ranges};
    gum_process_enumerate_ranges(GUM_PAGE_NO_ACCESS, include_ranges, &ctx);

  }

  g_strfreev(tokens);

}

gboolean range_is_excluded(gpointer address) {

  int        i;
  GumAddress test = GUM_ADDRESS(address);

  if (ranges == NULL) { return false; }

  for (i = 0; i < ranges->len; i++) {

    GumMemoryRange *curr = &g_array_index(ranges, GumMemoryRange, i);
    GumAddress      curr_limit = curr->base_address + curr->size;

    if (test < curr->base_address) { return !exclude_ranges; }

    if (test < curr_limit) { return exclude_ranges; }

  }

  return !exclude_ranges;

}

