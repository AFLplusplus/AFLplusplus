#include "qemu/osdep.h"
#include "libaflqemubridge/afl.h"

#ifdef CONFIG_AFL

#include <sys/mman.h>

struct afl_id_slot {
    uint64_t src;
    uint64_t dst;
    uint32_t id;
    uint32_t used;
};

struct afl_id_hdr {
    uint32_t next_id;
    uint32_t capacity;
    uint32_t map_size;
};

static struct afl_id_hdr  *afl_id_hdr;
static struct afl_id_slot *afl_id_slots;

void afl_idtable_init(uint32_t map_size)
{
    size_t capacity = 1;
    while (capacity < (size_t)map_size * 2) {
        capacity <<= 1;
    }
    size_t bytes = sizeof(struct afl_id_hdr) +
                   capacity * sizeof(struct afl_id_slot);
    void *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        perror("afl_idtable mmap");
        _exit(1);
    }
    afl_id_hdr = (struct afl_id_hdr *)p;
    afl_id_slots = (struct afl_id_slot *)(afl_id_hdr + 1);
    afl_id_hdr->next_id = 0;
    afl_id_hdr->capacity = (uint32_t)capacity;
    afl_id_hdr->map_size = map_size;
}

static inline uint64_t afl_id_hash(uint64_t src, uint64_t dst)
{
    uint64_t h = src * 0x9E3779B97F4A7C15ULL;
    h ^= dst + 0x9E3779B97F4A7C15ULL + (h << 6) + (h >> 2);
    return h;
}

uint64_t afl_idtable_lookup(uint64_t src, uint64_t dst)
{
    uint32_t cap = afl_id_hdr->capacity;
    uint32_t mask = cap - 1;
    uint32_t pos = (uint32_t)afl_id_hash(src, dst) & mask;
    for (uint32_t probe = 0; probe < cap; probe++) {
        struct afl_id_slot *s = &afl_id_slots[pos];
        uint32_t u = __atomic_load_n(&s->used, __ATOMIC_ACQUIRE);
        if (u == 0) {
            uint32_t expected = 0;
            if (__atomic_compare_exchange_n(&s->used, &expected, 1, 0,
                                            __ATOMIC_ACQ_REL,
                                            __ATOMIC_ACQUIRE)) {
                s->src = src;
                s->dst = dst;
                uint32_t raw = __atomic_fetch_add(&afl_id_hdr->next_id, 1,
                                                  __ATOMIC_ACQ_REL);
                uint32_t slot = raw % (afl_id_hdr->map_size - 5);
                if (slot == 0 && raw != 0) {
                    fprintf(stderr,
                            "[AFL] WARNING: QEMU edge id table wrapped after "
                            "%u edges (map_size %u), edge IDs now colliding\n",
                            raw, afl_id_hdr->map_size);
                }
                uint32_t id = slot + 5;
                s->id = id;
                __atomic_store_n(&s->used, 2, __ATOMIC_RELEASE);
                return id;
            }
            u = expected;
        }
        while (u == 1) {
            u = __atomic_load_n(&s->used, __ATOMIC_ACQUIRE);
        }
        if (s->src == src && s->dst == dst) {
            return s->id;
        }
        pos = (pos + 1) & mask;
    }
    return 5 + afl_id_hash(src, dst) % (afl_id_hdr->map_size - 5);
}

uint32_t afl_idtable_count(void)
{
    uint32_t n = __atomic_load_n(&afl_id_hdr->next_id, __ATOMIC_ACQUIRE);
    return n < afl_id_hdr->map_size ? n : afl_id_hdr->map_size;
}

#endif
