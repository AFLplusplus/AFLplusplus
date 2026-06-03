#!/bin/bash
# This scipt creates a FSA describing the input grammar *.g4
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$#" -ne 2 ] && [ "$#" -ne 3 ]; then
  echo "Usage: $0 <grammar_file> <start> [stack_limit]"
  exit 1
fi

GRAMMAR_FILE=$1
GRAMMAR_DIR="$(dirname $GRAMMAR_FILE)"
START="$2"
STACK_LIMIT="$3"

# Get filename
FILE=$(basename -- "$GRAMMAR_FILE")
echo "File:$FILE"
FILENAME="${FILE%.*}"
echo "Name:$FILENAME"


# Create the GNF form of the grammar
CMD="python ${DIR}/gnf_converter.py --gf $GRAMMAR_FILE --out ${FILENAME}.json --start $START"
$CMD

# Generate grammar automaton
# Check if user provided a stack limit
if [ -z "${STACK_LIMIT}" ]; then
CMD="python3 ${DIR}/construct_automata.py --gf ${FILENAME}.json"
else
CMD="python ${DIR}/construct_automata.py --gf ${FILENAME}.json --limit ${STACK_LIMIT}"
fi
echo $CMD
$CMD

# Move PDA to the source dir of the grammar
echo "Copying ${FILENAME}_automata.json to $GRAMMAR_DIR"
mv "${FILENAME}_automata.json" $GRAMMAR_DIR/
