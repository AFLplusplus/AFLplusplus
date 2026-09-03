# describe_state template

A starting point for telling `afl-fuzz` **how much work an input performs**.

Fill in one function and every queue entry gains an operation count.

## Why

AFL++ judges an input by how large and how slow it is. For a target that
replays a program of protocol operations that is the wrong axis: an input that
performs 200 operations and one that performs 3 are told apart only by byte
count, and `update_bitmap_score()` actively prefers the *smaller and faster* of
two inputs covering the same edge.

`afl_custom_describe_state` supplies the missing quantity. AFL++ then uses it
wherever it would otherwise use mutation depth — which counts generations from
a seed, not work done:

| consumer | what the count changes |
|---|---|
| `-Jd` deep-input shelf | inputs compete in buckets by operations performed, not by length |
| `fuzzer_stats` | `plugin_described`, `plugin_ops_avg`, `plugin_ops_max` |

Without it, `state_shelf_cell()` silently falls back to `q->len`, and the
shelf's whole achievement axis becomes a proxy for file size.

## Quick start

```sh
make
AFL_CUSTOM_MUTATOR_LIBRARY=$PWD/describe_state_template.so \
  afl-fuzz -Jdm -i in -o out -- ./target
```

Then confirm `fuzzer_stats` has grown `plugin_ops_avg` and `plugin_ops_max`. If
those lines are absent, the callback returned 0 for every input and nothing
downstream changed.

The default parser understands the common framing — a two-byte record marker, a
fixed header, and a little-endian 16-bit length in the header, with the length
accepted only when it lands on the next marker or the end of the buffer. That is
enough for several real harnesses with no code change at all: it reproduces
libssh's `ssh_loopback_fuzzer` operation counts exactly, on 120 of 120 queue
entries, with none of the variables below set.

| variable | default | meaning |
|---|---|---|
| `DESCRIBE_MARKER` | `5aa5` | record marker, two hex bytes; `none` to disable the scan |
| `DESCRIBE_HDR` | `8` | header length in bytes |
| `DESCRIBE_LENOFF` | `6` | offset of the 16-bit LE length within the header; `-1` for none |
| `DESCRIBE_MAXOPS` | `4096` | cap on operations counted per input |

## Adapting it

Replace `next_record()`. It takes a cursor and the end of the buffer and returns
the first byte after the operation starting there, or `NULL` when no further
operation starts. It must advance by at least one byte per call. Everything
else in the file is boilerplate.

If your harness already has a decoder, calling it is better than reimplementing
it — link the decoder in and have `next_record()` walk its output.

## Validate it before you trust it

**A record parser that disagrees with the harness is worse than no parser**,
because every scheduling decision downstream then rests on a number nobody
checked. The check is cheap:

1. Give the harness an environment variable that makes it print one line per
   retired operation.
2. Replay ~100 queue entries through the harness and count those lines.
   Subtract any fixed warm-up prefix; measure that constant on an empty input
   rather than assuming it.
3. Call `afl_custom_describe_state` on the same files and require **exact**
   agreement.

Disagreement usually means the harness stops early — an operation cap, a dead
session, a decode failure — where the parser keeps counting. Count what the
harness *retires*, not what the bytes *encode*.

## Two deliberate design choices

**No `afl_custom_fuzz`.** afl-fuzz warns about the missing symbol and keeps its
own mutations, so adding this to a campaign changes what afl-fuzz *knows*
without changing what it *does*. That makes it safe to drop into a running
configuration, and it makes "with" and "without" a clean A/B arm rather than a
comparison against a whole new mutator.

**`state_id` is left at 0.** afl-fuzz ignores it — the channels that consumed a
state id were measured to cost without paying and were removed — and the
parameter survives only so that mutators built against the older API still
link. The operation count is the whole point of this template. See
[docs/custom_mutators.md](../../docs/custom_mutators.md).

## Building

`SO_CC`, not `CC`. afl-fuzz `dlopen`s mutators with `RTLD_NOW`, and an
instrumented `.so` needs `__afl_area_ptr` from the target, so building this with
`afl-clang-fast` aborts every instance at startup.

## See also

- [docs/custom_mutators.md](../../docs/custom_mutators.md) — the full API,
  including `describe_state_ops`
- [`../state_records/`](../state_records) — a complete mutator implementing all
  of it over one concrete record format
