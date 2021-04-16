# Autodict-QL - Optimal Token Generation for Fuzzing

## What is this?

`Autodict-QL` is a plugin system that enables fast generation of Tokens/Dictionaries in a handy way that can be manipulated by the user (unlike The LLVM Passes that are hard to modify). This means that autodict-ql is a scriptable feature which basically uses CodeQL (a powerful semantic code analysis engine) to fetch information from a code base.

Tokens are useful when you perform fuzzing on different parsers. The AFL++ `-x` switch enables the usage of dictionaries through your fuzzing campaign. If you are not familiar with Dictionaries in fuzzing, take a look [here](https://github.com/AFLplusplus/AFLplusplus/tree/stable/dictionaries) .


## Why CodeQL ?
We basically developed this plugin on top of the CodeQL engine because it gives the user scripting features, it's easier and it's independent of the LLVM system. This means that a user can write his CodeQL scripts or modify the current scripts to improve or change the token generation algorithms based on different program analysis concepts.


## CodeQL scripts
Currently, we pushed some scripts as defaults for Token generation. In addition, we provide every CodeQL script as an standalone script because it's easier to modify or test.

Currently we provided the following CodeQL scripts :

`strcmp-str.ql` is used to extract strings that are related to the `strcmp` function.

`strncmp-str.ql` is used to extract the strings from the `strncmp` function.

`memcmp-str.ql` is used to extract the strings from the `memcmp` function.

`litool.ql` extracts Magic numbers as Hexadecimal format.

`strtool.ql` extracts strings with uses of a regex and dataflow concept to capture the string comparison functions. If `strcmp` is rewritten in a project as Mystrcmp or something like strmycmp, then this script can catch the arguments and these are valuable tokens.

You can write other CodeQL scripts to extract possible effective tokens if you think they can be useful.


## Usage

Before you proceed to installation make sure that you have the following packages by installing them :
```shell
sudo apt install build-essential libtool-bin python3-dev python3 automake git vim wget -y
```
The usage of Autodict-QL is pretty easy. But let's describe it as:

1. First of all, you need to have CodeQL installed on the system. we make this possible with `build-codeql.sh` bash script. This script will install CodeQL completety and will set the required environment variables for your system.
Do the following :
```shell
# chmod +x codeql-build.sh
# ./codeql-build.sh
# source ~/.bashrc
# codeql 
```
Then you should get:

```shell
Usage: codeql <command> <argument>...
Create and query CodeQL databases, or work with the QL language.

GitHub makes this program freely available for the analysis of open-source software and certain other uses, but it is
not itself free software. Type codeql --license to see the license terms.

      --license              Show the license terms for the CodeQL toolchain.
Common options:
  -h, --help                 Show this help text.
  -v, --verbose              Incrementally increase the number of progress messages printed.
  -q, --quiet                Incrementally decrease the number of progress messages printed.
Some advanced options have been hidden; try --help -v for a fuller view.
Commands:
  query     Compile and execute QL code.
  bqrs      Get information from .bqrs files.
  database  Create, analyze and process CodeQL databases.
  dataset   [Plumbing] Work with raw QL datasets.
  test      Execute QL unit tests.
  resolve   [Deep plumbing] Helper commands to resolve disk locations etc.
  execute   [Deep plumbing] Low-level commands that need special JVM options.
  version   Show the version of the CodeQL toolchain.
  generate  Generate formatted QL documentation.
  github    Commands useful for interacting with the GitHub API through CodeQL.
```

2. Compile your project with CodeQL: For using the Autodict-QL plugin, you need to compile the source of the target you want to fuzz with CodeQL. This is not something hard.
	- First you need to create a CodeQL database of the project codebase, suppose we want to compile `libxml` with codeql. Go to libxml and issue the following commands:
		- `./configure --disable-shared`
		- `codeql create database libxml-db --language=cpp --command=make`
			- Now you have the CodeQL database of the project :-)
3. The final step is to update the CodeQL database you created in step 2 (Suppose we are in `aflplusplus/utils/autodict_ql/` directory):
	- `codeql database upgrade /home/user/libxml/libxml-db`
4. Everything is set! Now you should issue the following to get the tokens:
	- `python3 autodict-ql.py [CURRECT_DIR] [CODEQL_DATABASE_PATH] [TOKEN_PATH]`
		- example : `python3 /home/user/AFLplusplus/utils/autodict_ql/autodict-ql.py $PWD /home/user/libxml/libxml-db tokens`
			- This will create the final `tokens` dir for you and you are done, then pass the tokens path to AFL++'s `-x` flag.
5. Done! 


## More on dictionaries and tokens
Core developer of the AFL++ project Marc Heuse also developed a similar tool named `dict2file` which is a LLVM pass which can automatically extract useful tokens, in addition with LTO instrumentation mode, this dict2file is automatically generates token extraction. `Autodict-QL` plugin gives you scripting capability and you can do whatever you want to extract from the Codebase and it's up to you. In addition it's independent from LLVM system.
On the other hand, you can also use Google dictionaries which have been made public in May 2020, but the problem of using Google dictionaries is that they are limited to specific file formats and specifications. For example, for testing binutils and ELF file format or AVI in FFMPEG, there are no prebuilt dictionaries, so it is highly recommended to use `Autodict-QL` or `Dict2File` features to automatically generate dictionaries based on the target.

I've personally prefered to use `Autodict-QL` or `dict2file` rather than Google dictionaries or any other manually generated dictionaries as `Autodict-QL` and `dict2file` are working based on the target.
In overall, fuzzing with dictionaries and well-generated tokens will give better results.

There are 2 important points to remember :

- If you combine `Autodict-QL` with AFL++ cmplog, you will get much better code coverage and hence better chances to discover new bugs.
- Do not forget to set `AFL_MAX_DET_EXTRAS` at least to the number of generated dictionaries. If you forget to set this environment variable, then AFL++ uses just 200 tokens and use the rest of them only probabilistically. So this will guarantee that your tokens will be used by AFL++.
