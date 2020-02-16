# TODO list for AFL++

## Roadmap 2.61

Makefile:
 - -march=native -Ofast -flto=full (especially for afl-fuzz)

llvm_mode:
 - using lto + opt to instrument at link time, and using a sat solver to
   select basic block IDs that do not result in collisions
   (Solution for "The far away future", see bottom of file)

qemu_mode:
 - ensure redqueen implementation works fine
 - ensure no issues in persistent mode


## Further down the road

afl-fuzz:
 - sync_fuzzers(): only masters sync from all, slaves only sync from master
   (@andrea: be careful, often people run all slaves)
 - ascii_only mode

gcc_plugin:
 - laf-intel
 - better instrumentation

qemu_mode:
 - update to 4.x (probably this will be skipped :( )
 - instrim for QEMU mode via static analysis (with r2pipe? or angr?)
   Idea: The static analyzer outputs a map in which each edge that must be
   skipped is marked with 1. QEMU loads it at startup in the parent process.
 - rename qemu specific envs to AFL_QEMU (AFL_ENTRYPOINT, AFL_CODE_START/END, AFL_COMPCOV_LEVEL?)
 - add AFL_QEMU_EXITPOINT (maybe multiple?)
 - add/implement AFL_QEMU_INST_LIBLIST and AFL_QEMU_NOINST_PROGRAM
 - add/implement AFL_QEMU_INST_REGIONS as a list of _START/_END addresses

custom_mutators:
 - rip what Superion is doing into custom mutators for js, php, etc.
 - uniform python and custom mutators API


## The far away future:

Problem: Average targets (tiff, jpeg, unrar) go through 1500 edges.
         At afl's default map that means ~16 collisions and ~3 wrappings.

 - Solution #1: increase map size.

    => speed loss is bad. last resort solution

    every +1 decreases fuzzing speed by ~10% and halfs the collisions
    birthday paradox predicts collisions at this # of edges:
    
    | mapsize | collisions |
    | :-----: | :--------: |
    | 2^16    | 302        |
    | 2^17    | 427        |
    | 2^18    | 603        |
    | 2^19    | 853        |
    | 2^20    | 1207       |
    | 2^21    | 1706       |
    | 2^22    | 2412       |
    | 2^23    | 3411       |
    | 2^24    | 4823       |

    Increasing the map is an easy solution but also not a good one.

 - Solution #2: use dynamic map size and collision free basic block IDs

    => This works and is the selected solution

    This only works in llvm_mode and llvm >= 9 though
    A potential good future solution. Heiko/hexcoder follows this up

 - Solution #3: write instruction pointers to a big shared map

    => Tested and it is a dead end

    512kb/1MB shared map and the instrumented code writes the instruction
    pointer into the map. Map must be big enough but could be command line
    controlled.
    
    Good: complete coverage information, nothing is lost. choice of analysis
          impacts speed, but this can be decided by user options
    
    Neutral: a little bit slower but no loss of coverage
    
    Bad: completely changes how afl uses the map and the scheduling.
    Overall another very good solution, Marc Heuse/vanHauser follows this up
    
