#/bin/sh

UC_VERSION_FILE='./UNICORNAFL_VERSION'

NEW_VERSION="$1"
if [ -z "$NEW_VERSION" ]; then
  echo "Internal script to update bound unicornafl version."
  echo
  echo "Usage: ./update_uc_ref.sh <new commit hash>"
  exit 1
fi

git submodule init && git submodule update || exit 1
cd ./unicornafl
git fetch origin master 1>/dev/null || exit 1
git stash 1>/dev/null 2>/dev/null
git stash drop 1>/dev/null 2>/dev/null
git checkout "$NEW_VERSION" || exit 1

cd ..

rm "$UC_VERSION_FILE"
echo "$NEW_VERSION" > "$UC_VERSION_FILE"

echo "Done. New unicornafl version is $NEW_VERSION."
