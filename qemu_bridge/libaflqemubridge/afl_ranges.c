#include "qemu/osdep.h"
#include "qemu/selfmap.h"
#include "qemu/interval-tree.h"
#include "user/page-protection.h"
#include "qemu.h"
#include "loader.h"

#include "libafl/user.h"
#include "libaflqemubridge/afl.h"
#include "libaflqemubridge/imported/config.h"

#ifdef CONFIG_AFL

#include <string.h>

struct vmrange {
    uint64_t start;
    uint64_t end;
    char *name;
    bool exclude;
    struct vmrange *next;
};

static struct vmrange *afl_instr_code;
static uint64_t afl_start_code;
static uint64_t afl_end_code;
static uint64_t afl_entry_point_val;
static uint64_t afl_exit_point_val;

uint32_t afl_inst_ratio = 100;

static uint64_t afl_ranges_hash(uint64_t v)
{
    v ^= ((v << 49) | (v >> 15)) ^ ((v << 24) | (v >> 40));
    v *= 0x9FB21C651E98DF25ULL;
    v ^= (v >> 35) + 8;
    v *= 0x9FB21C651E98DF25ULL;
    return v ^ (v >> 28);
}

static void afl_ranges_add(const char *str, bool exclude)
{
    char *dup = strdup(str);
    char *saveptr1 = NULL;
    char *tok = strtok_r(dup, ",", &saveptr1);
    while (tok) {
        char *entry = strdup(tok);
        char *saveptr2 = NULL;
        char *pt2 = strtok_r(entry, "-", &saveptr2);
        char *pt3 = strtok_r(NULL, "-", &saveptr2);

        struct vmrange *n = calloc(1, sizeof(struct vmrange));
        n->exclude = exclude;
        n->next = afl_instr_code;

        if (pt3 == NULL) {
            n->start = (uint64_t)-1;
            n->end = 0;
            n->name = strdup(tok);
        } else {
            n->start = strtoull(pt2, NULL, 16);
            n->end = strtoull(pt3, NULL, 16);
            if (n->start && n->end) {
                n->name = NULL;
            } else {
                n->start = (uint64_t)-1;
                n->end = 0;
                n->name = strdup(tok);
            }
        }

        afl_instr_code = n;
        free(entry);
        tok = strtok_r(NULL, ",", &saveptr1);
    }
    free(dup);
}

static int afl_ranges_have_names(void)
{
    for (struct vmrange *n = afl_instr_code; n; n = n->next) {
        if (n->name) {
            return 1;
        }
    }
    return 0;
}

static void afl_ranges_resolve_names(void)
{
    IntervalTreeRoot *proc_maps = read_self_maps();
    IntervalTreeRoot *pageflags = pageflags_get_root();

    IntervalTreeNode *node = libafl_maps_first(pageflags);
    while (node) {
        struct libafl_mapinfo info;
        node = libafl_maps_next(node, proc_maps, &info);
        if (!info.is_valid || !info.path) {
            continue;
        }
        for (struct vmrange *n = afl_instr_code; n; n = n->next) {
            if (n->name && strstr(info.path, n->name)) {
                if (info.start < n->start) {
                    n->start = info.start;
                }
                if (info.end > n->end) {
                    n->end = info.end;
                }
                break;
            }
        }
    }

    free_self_maps(proc_maps);
}

void afl_ranges_init(void)
{
    struct image_info *image = libafl_get_image_info();

    afl_start_code = image->start_code;
    afl_end_code = image->end_code;

    char *inst_r = getenv("AFL_INST_RATIO");
    if (inst_r) {
        unsigned int r = (unsigned int)atoi(inst_r);
        if (r > 100) {
            r = 100;
        }
        if (r == 0) {
            r = 1;
        }
        afl_inst_ratio = r;
    }

    if (getenv("AFL_INST_LIBS")) {
        afl_start_code = 0;
        afl_end_code = (uint64_t)-1;
    }

    if (getenv("AFL_CODE_START")) {
        afl_start_code = strtoull(getenv("AFL_CODE_START"), NULL, 16);
    }
    if (getenv("AFL_CODE_END")) {
        afl_end_code = strtoull(getenv("AFL_CODE_END"), NULL, 16);
    }

    if (getenv("AFL_QEMU_INST_RANGES")) {
        afl_ranges_add(getenv("AFL_QEMU_INST_RANGES"), false);
    }
    if (getenv("AFL_QEMU_EXCLUDE_RANGES")) {
        afl_ranges_add(getenv("AFL_QEMU_EXCLUDE_RANGES"), true);
    }

    if (afl_ranges_have_names()) {
        afl_ranges_resolve_names();
    }

    afl_entry_point_val = afl_get_exec_entry();
    if (getenv("AFL_ENTRYPOINT")) {
        afl_entry_point_val = strtoull(getenv("AFL_ENTRYPOINT"), NULL, 16);
    }

    afl_exit_point_val = 0;
    if (getenv("AFL_EXITPOINT")) {
        afl_exit_point_val = strtoull(getenv("AFL_EXITPOINT"), NULL, 16);
    }

    if (getenv("AFL_DEBUG")) {
        fprintf(stderr, "[AFL] instrument range: 0x%lx-0x%lx\n",
                (unsigned long)afl_start_code, (unsigned long)afl_end_code);
        for (struct vmrange *n = afl_instr_code; n; n = n->next) {
            fprintf(stderr, "[AFL] %s range: 0x%lx-0x%lx (%s)\n",
                    n->exclude ? "exclude" : "instrument",
                    (unsigned long)n->start, (unsigned long)n->end,
                    n->name ? n->name : "<noname>");
        }
        fprintf(stderr, "[AFL] entrypoint: 0x%lx exitpoint: 0x%lx ratio: %u\n",
                (unsigned long)afl_entry_point_val,
                (unsigned long)afl_exit_point_val, afl_inst_ratio);
    }
}

bool afl_range_is_instrumented(uint64_t pc)
{
    for (struct vmrange *n = afl_instr_code; n; n = n->next) {
        if (n->exclude && pc < n->end && pc >= n->start) {
            return false;
        }
    }

    if (pc < afl_end_code && pc >= afl_start_code) {
        return true;
    }

    for (struct vmrange *n = afl_instr_code; n; n = n->next) {
        if (!n->exclude && pc < n->end && pc >= n->start) {
            return true;
        }
    }

    return false;
}

bool afl_inst_ratio_keep(uint64_t pc)
{
    if (afl_inst_ratio >= 100) {
        return true;
    }
    uint32_t h = (uint32_t)afl_ranges_hash(pc) & (MAP_SIZE - 1);
    return h < (MAP_SIZE * afl_inst_ratio / 100);
}

uint64_t afl_entry_point(void)
{
    return afl_entry_point_val;
}

uint64_t afl_exit_point(void)
{
    return afl_exit_point_val;
}

#endif
