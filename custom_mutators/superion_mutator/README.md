# custum mutator: Superion


Implementation details.

The AFLplusplus API the has been implemented in js_parser/TreeMutation.cpp.  This can be used to fuzz various languages such as javascript/php/jerryscript etc. See the Superion for more details, https://github.com/zhunki/Superion/ .




Building

In order to build, execute the build.sh script inside the superion_mutator folder.




Running 

When you want to fuzz simply set the following env_variables prior to running AFLplusplus as usual:

export AFL_CUSTOM_MUTATOR_ONLY=1
export AFL_CUSTOM_MUTATOR_LIBRARY=~/Downloads/afl++/tree_mutation/js_parser/libTreeMutation.so



