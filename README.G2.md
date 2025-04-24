# Description
Modern software often accepts inputs with highly complex grammars. To conduct greybox fuzzing and uncover security bugs in such software, it is essential to generate inputs that conform to the software input grammar. However, this is a well-known challenging task because it requires a deep understanding of the grammar, which is often not available and hard to infer. Recent advances in large language models (LLMs) have shown that they can be used to synthesize high-quality natural language text and code that conforms to the grammar of a given input format. Nevertheless, LLMs are often incapable or too costly to generate non-textual outputs, such as images, videos, and PDF files. This limitation hinders the application of LLMs in grammar-aware fuzzing.

This paper presents a novel approach to enabling grammar-aware fuzzing over non-textual inputs. We employ LLMs (e.g., GPT-3.5) to synthesize and further mutate input generators, often in the format of Python scripts, that generate data that conform to the grammar of a given input format. Then, non-textual data yielded by the input generators are further mutated by traditional fuzzers (e.g., AFL++) to explore the software input space more effectively. Holistically, our approach, namely G2FUZZ, features a hybrid strategy that combines a “holistic search” driven by LLMs and a “local search” driven by industrial quality fuzzers. Two key advantages of G2FUZZ are: (1) LLMs are good at synthesizing and mutating input generators and enabling jumping out of local optima, thus achieving a synergistic effect when combined with mutation-based fuzzers; (2) LLMs are less frequently invoked unless really needed, thus significantly reducing the cost of LLM usage. 



# How to use it
## The setting of LLM
In default, we use the GPT-3.5 to get the generator. To use it, you’ll need to define your OpenAI API key in both `program_gen.py` and `generator_mutation_gpt_3_5.py`. If you wish to use other large language models (LLMs), you can modify the code in these two files accordingly.

To run the fuzzer, use the following command:
```
    ./afl-fuzz -i input -o output -c PROGRAM_CMP -m 1024 -J PROGRAM_NAME -k G2FUZZ_LOC -- PROGRAM_AFL @@
```
`-J`: Specifies the target program name.
`-k`: Specifies the path to G2FUZZ.

G2FUZZ will generate diverse input structures. These inputs help the fuzzer explore untested code regions more effectively.
