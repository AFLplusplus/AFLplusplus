# state_records

A record format for targets that are state machines, plus the AFL++ custom
mutator that fuzzes it.

An input is a *program*: a list of operations that reach each other through a
small store of slots. `OPEN` puts something in a slot, `WRITE` copies from one
slot into another, `DUP` clones one, `CLOSE` releases one, `COMMIT` does
something that depends on what is currently open. That is the shape of most
interesting bugs in stateful code — the bug is in the *sequence*, not in any
one operation.

The point of this directory is the wire format. A mutator that shuffles
operations is easy; a format that survives being shuffled is not, and the two
rules below are the whole reason this format looks the way it does.

**Adopting that wire format is a precondition for everything here**, including
`afl_custom_describe_state`. Every function is hard-wired to the `5a a5`
marker, the 8-byte header and the `STATE_OP_*` opcode semantics below — it is
not a generic record mutator with a pluggable format. Pointed at a harness with
its own encoding it does not fail loudly: `afl_custom_describe_state` finds no
records and reports `ops=0, state_id=0` for every entry, and `afl_custom_fuzz`
emits *this* format, which that harness's parser reads as one opaque blob. If
your target already has a record format, copy this mutator and change the
codec in `state_records.h`, or make the harness read this format; do not expect
the state hook to work across formats.

## Files

| File | Contents |
|---|---|
| `state_records.h` | format, encoder, decoder. Header only, needs `stdint.h`, `stddef.h` and `string.h` and nothing else, so a target can use it standalone |
| `state_records.c` | the custom mutator |
| `example_harness.c` | a slot machine target with two deliberate bugs |
| `Makefile` | builds both |

Tests live in `../../test/unittests/unit_state_records.c` (`make
unit_state_records`) and `../../test/test-state-records.sh`.

## The format

One record:

```
offset 0   0x5a          sync marker byte 0
offset 1   0xa5          sync marker byte 1
offset 2   opcode   u8
offset 3   dst slot u8
offset 4   src slot u8
offset 5   flags    u8
offset 6   len      u16 little endian    -- a hint, never the only separator
offset 8   payload[len]
```

An input is a bare concatenation of records. `dst` and `src` are taken modulo
the slot count (8), so every byte names a live slot and no record is ever
rejected for naming one that does not exist. Opcodes the target does not know
are ignored rather than fatal.

### Rule 1: there is no header

No magic, no version, no total length, no item count. Nothing at the front of
the input that the rest of the input depends on.

This is not tidiness. If a format starts with a length or a count, then every
mutation that changes the size of the body has to be matched by a mutation of
that field, and byte mutators do not do matched pairs. Measured on this kind
of input, a leading length field leaves **1.2%** of inputs intact after a
single inserted byte; the other 98.8% are rejected by the parser before
reaching any target logic. With no header, a byte glued to the front of the
input shifts every record by one and damages none of them — the decoder skips
forward to the first `5a a5` and carries on. `unit_state_records.c` asserts
exactly that.

### Rule 2: the length is never the only separator

The decoder reads `len`, and then *checks* it: the two bytes at `payload +
len` must be the next sync marker, or exactly the end of the buffer. If that
check fails, the decoder throws `len` away, rescans forward from `payload` for
the next `5a a5`, and treats everything up to it as the payload.

So the length is a fast path, and the marker is the truth. A format that
trusts a bare length field recovers from an inserted or deleted byte **4.8%**
of the time, and **59%** of havoc rounds insert or delete something — the
arithmetic says such a format spends most of its budget producing inputs the
parser drops on the floor. With validation and rescan, a byte inserted in the
middle of a program damages the record it landed in and leaves every later
record byte-for-byte intact.

Two consequences worth stating plainly:

* A payload may contain `5a a5`. On the happy path the validated length hint
  carries the decoder straight past it. On the damaged path the record is
  truncated at the embedded marker — still a legal record, just a shorter
  one.
* Every byte string decodes to *some* record list. There is no such thing as
  a parse error here, which is what makes the format worth mutating.

## The mutator

`afl_custom_fuzz` decodes the input into records, stacks one to eight record
level operators on it, and encodes the result. It never edits the encoded
bytes.

| Operator | Effect |
|---|---|
| `insert` | insert a newly generated record |
| `delete` | remove a record |
| `duplicate` | copy a record in place |
| `swap` | exchange two records |
| `move` | move a record earlier or later |
| `opcode` | change a record's opcode |
| `flags` | change a record's flag byte |
| `rewire` | repoint `src` or `dst` at another slot |
| `payload` | flip, replace, add to or subtract from payload bytes |
| `grow` | extend a payload |
| `shrink` | cut a payload short |
| `generate` | build a program from scratch when the input holds no records |
| `splice` | see below |

`rewire` and record generation prefer a slot that an *earlier* record actually
writes, so most generated programs have a data flow that reaches the target's
deeper paths — without ever requiring it, since malformed programs are exactly
what finds the error handling.

**Splicing at record boundaries.** When AFL++ hands over a splice partner in
`add_buf`, with probability 1/2 the mutator decodes both inputs and joins a
prefix of one to a suffix of the other, cutting only between records. It
prefers a cut where the record before it and the record after it touch the
same slot, so the spliced program still means something.

**Trimming whole operations.** `afl_custom_init_trim` reports the record
count, each `afl_custom_trim` step emits the program with one record removed,
and `afl_custom_post_trim` keeps the shorter program when the behaviour
survived. Byte level trimming inside a record only corrupts that record, so
the custom trim path replaces it for this format.

**Describing.** `afl_custom_describe` names the operator that ran, so a queue
entry is called `...,rec_splice` or `...,rec_rewire` and it is visible which
operator is earning its keep.

## Running it

The top level `make` builds `state_records.so`, and rebuilds it whenever
`state_records.c` changes. To build it alone:

```sh
make -C custom_mutators/state_records

AFL_CUSTOM_MUTATOR_LIBRARY=custom_mutators/state_records/state_records.so \
  afl-fuzz -i in -o out -- ./your_target @@
```

A stale `.so` is easy to mistake for a format problem: `afl-fuzz` says which
optional hooks it did not find.

To run it against the example target:

```sh
cd custom_mutators/state_records
make CC=../../afl-clang-fast example_harness
AFL_CUSTOM_MUTATOR_LIBRARY=$PWD/state_records.so \
  ../../afl-fuzz -i seeds -o out -- ./example_harness @@
```

`example_harness.c` has two deliberate bugs, both memory errors, so build it
with `AFL_USE_ASAN=1` to see them:

* `DUP` checks that the source slot still holds a pointer instead of checking
  that it is open, so the sequence `OPEN s`, `CLOSE s`, `DUP d,s` reads freed
  memory.
* `COMMIT` writes its terminator one byte past the end of its buffer when the
  open slots hold exactly 64 bytes together.

Neither is reachable by a single operation, which is the point.

## Reporting state: `afl_custom_describe_state`

The mutator also answers the question AFL++ cannot answer for itself: what does
this input *do*? It walks the program the way the harness does and reports the
number of operations per queue entry.

That count is what `-Jd`'s achievement bucket always wanted; without it the
shelf falls back to the input length, which makes its depth axis a proxy for
file size. Supplying it was measured **not** to change depth on its own, so it
is worth reporting because the number is then right, not because it buys depth.

The state id the hook also takes is left over from a removed feature: nothing in
`afl-fuzz` consumes one any more, and `STATE_RECORDS_DIGEST` therefore only
affects what this mutator computes for itself. Level 3 remains a demonstration
of the failure mode a state digest has — it names a *path*, not a state, so
almost every input looks like a new state.

## Do not set `AFL_CUSTOM_MUTATOR_ONLY`

Deliberately not recommended, and the recommendation is not a hedge.

This mutator only ever emits well-formed records. That is useful — it is how
the deep sequences get built — but a target that parses records also has a
parser, and parsers are where the memory bugs are. Plain byte mutation
produces truncated records, absurd length hints, payloads that end mid-marker
and opcodes nobody wrote a case for, and those find the bugs this mutator
structurally cannot generate. The format was designed to survive byte
mutation precisely so that both can run on the same corpus at the same time.

Run the custom mutator alongside havoc, which is what AFL++ does by default.
