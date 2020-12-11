#!/bin/sh

##################################################
# AFL++ tool to update a git ref.
# Usage: ./<script>.sh <new commit hash>
# If no commit hash was provided, it'll take HEAD.
##################################################

TOOL="grammar mutator"
VERSION_FILE='./GRAMMAR_VERSION'
REPO_FOLDER='./grammar_mutator'
THIS_SCRIPT=`basename $0`
BRANCH="stable"

NEW_VERSION="$1"

if [ "$NEW_VERSION" = "-h" ]; then
  echo "Internal script to update bound $TOOL version."
  echo
  echo "Usage: $THIS_SCRIPT <new commit hash>"
  echo "If no commit hash is provided, will use HEAD."
  echo "-h to show this help screen."
  exit 1
fi

git submodule init && git submodule update ./grammar_mutator || exit 1
cd "$REPO_FOLDER" || exit 1
git fetch origin $BRANCH 1>/dev/null || exit 1
git stash 1>/dev/null 2>/dev/null
git stash drop 1>/dev/null 2>/dev/null
git checkout $BRANCH

if [ -z "$NEW_VERSION" ]; then
  # No version provided, take HEAD.
  NEW_VERSION=$(git rev-parse --short HEAD)
fi

if [ -z "$NEW_VERSION" ]; then
  echo "Error getting version."
  exit 1
fi

git checkout "$NEW_VERSION" || exit 1

cd ..

rm "$VERSION_FILE"
echo "$NEW_VERSION" > "$VERSION_FILE"

echo "Done. New $TOOL version is $NEW_VERSION."
