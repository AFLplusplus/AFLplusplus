# GramaTron

Gramatron is a coverage-guided fuzzer that uses grammar automatons to perform
grammar-aware fuzzing.  Technical details about our framework are available in our
[ISSTA'21 paper](https://nebelwelt.net/files/21ISSTA.pdf). The artifact to reproduce the
experiments presented in our paper are present in `artifact/`. Instructions to run
a sample campaign and incorporate new grammars is presented below: 

# Compiling

- Install `json-c` 
```
git clone https://github.com/json-c/json-c.git
cd json-c && git reset --hard af8dd4a307e7b837f9fa2959549548ace4afe08b && sh autogen.sh && ./configure && make && make install 
```

afterwards you can just `make` GrammaTron

# Running

You have to set the grammar file to use with `GRAMMATRON_AUTOMATION`:

```
export AFL_DISABLE_TRIM=1
export AFL_CUSTOM_MUTATOR_ONLY=1
export AFL_CUSTOM_MUTATOR_LIBRARY=./gramatron.so
export GRAMATRON_AUTOMATION=grammars/ruby/source_automata.json
afl-fuzz -i in -o out -- ./target
```

# Adding and testing a new grammar

- Specify in a JSON format for CFG. Examples are correspond `source.json` files 
- Run the automaton generation script (in `src/gramfuzz-mutator/preprocess`)
  which will place the generated automaton in the same folder.
```
./preprocess/prep_automaton.sh <grammar_file> <start_symbol> [stack_limit]

Eg. ./preprocess/prep_automaton.sh ~/grammars/ruby/source.json PROGRAM
```
- If the grammar has no self-embedding rules then you do not need to pass the
  stack limit parameter. However, if it does have self-embedding rules then you
  need to pass the stack limit parameter. We recommend starting with `5` and
  then increasing it if you need more complexity
- To sanity-check that the automaton is generating inputs as expected you can use the `test` binary housed in `src/gramfuzz-mutator`
```
./test SanityCheck <automaton_file>

Eg. ./test SanityCheck ~/grammars/ruby/source_automata.json
```

