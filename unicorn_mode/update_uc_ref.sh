#/bin/sh

##################################################
# AFL++ internal tool to update unicornafl ref.
# Usage: ./update_uc_ref.sh <new commit hash>
# If no commit hash was provided, it'll take HEAD.
##################################################

UC_VERSION_FILE='./UNICORNAFL_VERSION'

NEW_VERSION="$1"

if [ "$NEW_VERSION" = "-h" ]; then
  echo "Internal script to update bound unicornafl version."
  echo
  echo "Usage: ./update_uc_ref.sh <new commit hash>"
  echo "If no commit hash is provided, will use HEAD."
  echo "-h to show this help screen."
  exit 1
fi

git submodule init && git submodule update unicornafl || exit 1
cd ./unicornafl || exit 1
git fetch origin uc1 1>/dev/null || exit 1
git stash 1>/dev/null 2>/dev/null
git stash drop 1>/dev/null 2>/dev/null
git checkout main

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

rm "$UC_VERSION_FILE"
echo "$NEW_VERSION" > "$UC_VERSION_FILE"

echo "Done. New unicornafl version is $NEW_VERSION."
