# qemu_taint

First level taint implementation with qemu for linux user mode

**THIS IS NOT WORKING YET** **WIP**

## What is this for

On new queue entries (newly discovered paths into the target) this tainter
is run with the new input and the data gathered which bytes in the input
file are actually touched.

Only touched bytes are then fuzzed by afl-fuzz

## How to build

./build_qemu_taint.sh

## How to use

Add the -A flag to afl-fuzz

## Caveats

For some targets this is amazing and improves fuzzing a lot, but if a target
copies all input bytes first (e.g. for creating a crc checksum or just to
safely work with the data), then this is not helping at all.

## Future

Two fuzz modes for a queue entry which will be switched back and forth:

  1. fuzz all touched bytes
  2. fuzz only bytes that are newly touched (compared to the one this queue
     entry is based on)

## TODO

  * Direct trim: trim to highest touched byte, that is all we need to do
  * add 5-25% dummy bytes to the queue entries? (maybe create a 2nd one?)
  * Disable trim?

