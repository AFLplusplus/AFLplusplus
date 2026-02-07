# FrameShift – Automatic Size/Offset Field Tracking for AFL++

FrameShift is a **runtime analysis stage** in AFL++ that automatically discovers
size and offset fields in structured binary inputs and keeps them consistent as
havoc mutations insert or delete bytes.

Many binary formats (ELF, PNG, PDF, protocol buffers, TLV encodings, ...) embed
length or offset fields that describe the layout of the data that follows. When
a fuzzer blindly inserts or removes bytes, these fields become stale and the
target's parser rejects the input long before it reaches deeper code. FrameShift
solves this by:

1. **Discovering** which bytes in an input act as size/offset fields.
2. **Tracking** how havoc-stage mutations (insertions and deletions) affect
   those fields.
3. **Sanitizing** the mutated buffer so every tracked field is updated to
   reflect the new layout before the test case is executed.

This is fully automatic -- no format specification, grammar, or custom mutator
is required.

* More extensive details and evaluations in our research paper: [FrameShift: Learning to Resize Fuzzer Inputs Without Breaking Them](https://arxiv.org/abs/2507.05421v1)

## How it works

### Discovery (the frameshift stage)

When afl-fuzz first picks a queue entry that has not been analyzed yet, it runs
the **frameshift stage** before the havoc loop. The stage works as follows:

1. **Baseline coverage** -- Execute the original input and record which coverage
   map indices are hit. Subtract the indices that are also hit by a trivially
   invalid input (a single byte `"a"`) to isolate coverage unique to the current
   test case.

2. **Candidate scan** -- For every byte offset in the input, try interpreting
   the bytes at that position as a u8, u16, u32, or u64 value in both little-
   and big-endian order (largest first). If the decoded value is non-zero and
   does not exceed the input length, it is a plausible size/offset field.

3. **Loss test** -- Corrupt the candidate field (add a shift amount to its
   value) and re-execute the input. If more than 5% of the baseline coverage
   indices are lost, the field may be structural.

4. **Anchor search** -- To determine *where* bytes should be counted from, the
   stage tries several anchor points. For each candidate anchor, it constructs a
   test case with the field value updated and padding bytes inserted at the
   corresponding insertion point. If the insertion **recovers** more than 20% of
   the lost coverage, the (field, anchor, insertion point) triple is recorded as
   a **relation**.

5. **Iteration** -- The search repeats (up to 10 iterations) because discovering
   one relation can unblock positions that were previously inside a tracked
   field.

Each analyzed input receives a per-queue `fs_meta_t` that stores all discovered
relations. Already-analyzed fields are marked in a blocked-points bitmap so they
are not re-tested.

### Tracking (during havoc)

During the havoc and splice stages, every insertion and deletion mutation is
reported to the relation tracker:

- **Insertions** adjust `pos`, `anchor`, `insert`, and `val` of each relation
  that spans the affected region.
- **Deletions** do the same in reverse, shrinking the relevant intervals.

If a mutation would break a relation (e.g., inserting inside a tracked field),
that relation is disabled for the remainder of the current havoc round.

### Sanitization (before execution)

After all mutations in a single havoc iteration are applied, `fs_sanitize()`
writes the updated field values back into the buffer. This means the target sees
an input whose size/offset fields are consistent with the actual byte layout,
dramatically increasing the chance of reaching deep parsing code.

At the start of each new havoc iteration the relation metadata is restored to
its original state, so relations are never permanently lost.

## Relation model

A relation field is described by four dynamic values:

| Field    | Meaning |
|----------|---------|
| `pos`    | Byte offset of the size/offset field in the input. |
| `val`    | Current numeric value of the field. |
| `anchor` | The reference point from which the distance is measured. |
| `insert` | The point at which inserted bytes are counted toward the field value. |

Together with fixed attributes:

| Field  | Meaning |
|--------|---------|
| `size` | Width of the field in bytes (1, 2, 4, or 8). |
| `le`   | Whether the field is little-endian (`1`) or big-endian (`0`). |

When bytes are inserted between `anchor` and `insert`, the field value is
incremented by the insertion size. When bytes are removed from that region, the
field value is decremented.

## Environment variables

- **`AFL_FRAMESHIFT_DISABLE`** -- Set to `1` to disable the frameshift stage and
  all relation tracking entirely. Useful for targets that do not consume
  structured binary formats, or when you want to eliminate the analysis overhead.

- **`AFL_FRAMESHIFT_MAX_OVERHEAD`** -- A float between `0.0` and `1.0` (default
  `0.10`, i.e. 10%) that caps the fraction of total fuzzing time the frameshift
  analysis is allowed to consume. Once the cumulative analysis time exceeds this
  fraction of the overall run time, new analyses are skipped until the ratio
  drops back under the limit. Set to `0.0` to effectively disable analysis after
  startup, or increase toward `1.0` for thorough analysis at the cost of fewer
  havoc executions.

## Compile-time constants

The following constants are defined in `src/afl-fuzz-frameshift.c` and can be
adjusted by editing the source:

| Constant | Default | Meaning |
|----------|---------|---------|
| `FRAMESHIFT_MAX_ITERS` | 10 | Maximum discovery iterations per input. |
| `FRAMESHIFT_LOSS_PCT` | 5 | Minimum coverage loss (%) to consider a field structural. |
| `FRAMESHIFT_RECOVER_PCT` | 20 | Minimum coverage recovery (%) to accept an anchor. |
| `FRAMESHIFT_TIME_BUDGET_MS` | 2000 | Hard per-input time budget for the analysis stage (ms). |

## When to use FrameShift

FrameShift is **enabled by default** and is most effective for:

- Binary formats with embedded lengths (TLV, chunked encodings, container
  formats).
- Network protocols with length-prefixed messages.
- Any target where inserting or deleting bytes causes the parser to bail out
  early because a size or offset field no longer matches.

Overhead on non-structured targets is minimal in practice, but can be avoided entirely by setting `AFL_FRAMESHIFT_DISABLE=1`.

## Source files

| File | Contents |
|------|----------|
| `src/afl-fuzz-frameshift.c` | Discovery stage, relation tracking, sanitization. |
| `include/afl-fuzz.h` | `fs_relation_t`, `fs_meta_t`, `frameshift_stats` definitions. |
| `src/afl-fuzz-one.c` | Integration with the havoc/splice loop. |
