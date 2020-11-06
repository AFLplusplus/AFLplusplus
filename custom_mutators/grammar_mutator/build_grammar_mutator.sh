#!/bin/sh

test -d Grammar-Mutator || git clone --depth=1 https://github.com/AFLplusplus/Grammar-Mutator

cd Grammar-Mutator || exit 1
git stash ; git pull

wget -c https://www.antlr.org/download/antlr-4.8-complete.jar

echo
echo
echo "All successfully prepared!"
echo "To build for your grammar just do:"
echo "  cd Grammar_Mutator"
echo "  make GRAMMAR_FILE=/path/to/your/grammar"
echo "You will find a JSON and RUBY grammar in Grammar_Mutator/grammars to play with."
echo
