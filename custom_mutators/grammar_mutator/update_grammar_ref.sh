#!/bin/sh

##################################################
# AFL++ tool to update a git ref.
# Usage: ./<script>.sh <new commit hash> <branch>
# If no commit hash was provided, it'll take HEAD.
# If no branch was provided, it'll take stable branch.
##################################################

TOOL="grammar mutator"
VERSION_FILE='./GRAMMAR_VERSION'
REPO_FOLDER='./grammar_mutator'
THIS_SCRIPT=`basename $0`

NEW_VERSION="$1"
BRANCH="$2"

if [ "$NEW_VERSION" = "-h" ]; then
  echo "Internal script to update bound $TOOL version."
  echo
  echo "Usage: $THIS_SCRIPT <new commit hash> <branch>"
  echo "If no commit hash is provided, will use HEAD."
  echo "If no branch was provided, it'll take stable branch."
  echo "-h to show this help screen."
  exit 1
fi

if [ "$BRANCH" = "dev" ]; then
  BRANCH="dev"
elif [ -z "$BRANCH" ]; then
  BRANCH="stable"
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

rm "$
"
echo "$NEW_VERSION" > "$VERSION_FILE"

echo "Done. New $TOOL version is $NEW_VERSION."
