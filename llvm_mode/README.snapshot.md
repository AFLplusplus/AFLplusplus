# AFL++ snapshot feature

Snapshotting is a feature that makes a snapshot from a process and then
restores it's state, which is faster then forking it again.

All targets compiled with llvm_mode are automatically enabled for the
snapshot feature.

To use the snapshot feature for fuzzing compile and load this kernel
module: [https://github.com/AFLplusplus/AFL-Snapshot-LKM](https://github.com/AFLplusplus/AFL-Snapshot-LKM)

Note that is has little value for persistent (__AFL_LOOP) fuzzing.

## Notes

Snapshot does not work with multithreaded targets yet. Still in WIP, it is now usable only for single threaded applications.
