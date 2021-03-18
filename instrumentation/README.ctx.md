# AFL Context Sensitive Branch Coverage

## What is this?

This is an LLVM-based implementation of the context sensitive branch coverage.

Basically every function gets its own ID and, every time when an edge is logged,
all the IDs in the callstack are hashed and combined with the edge transition
hash to augment the classic edge coverage with the information about the
calling context.

So if both function A and function B call a function C, the coverage
collected in C will be different.

In math the coverage is collected as follows:
`map[current_location_ID ^ previous_location_ID >> 1 ^ hash_callstack_IDs] += 1`

The callstack hash is produced XOR-ing the function IDs to avoid explosion with
recursive functions.

## Usage

Set the `AFL_LLVM_INSTRUMENT=CTX` or `AFL_LLVM_CTX=1` environment variable.

It is highly recommended to increase the MAP_SIZE_POW2 definition in
config.h to at least 18 and maybe up to 20 for this as otherwise too
many map collisions occur.

## Caller Branch Coverage

If the context sensitive coverage introduces too may collisions and becoming
detrimental, the user can choose to augment edge coverage with just the
called function ID, instead of the entire callstack hash.

In math the coverage is collected as follows:
`map[current_location_ID ^ previous_location_ID >> 1 ^ previous_callee_ID] += 1`

Set the `AFL_LLVM_INSTRUMENT=CALLER` or `AFL_LLVM_CALLER=1` environment variable.
