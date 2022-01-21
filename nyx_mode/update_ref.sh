#/bin/sh

##################################################
# AFL++ internal tool to update nyx references.
# Usage: ./update_ref.sh
# It will take HEAD of all the repos!
##################################################

if [ "$NEW_VERSION" = "-h" ]; then
  echo "Internal script to update bound qemuafl version."
  echo
  echo "Usage: ./update_ref.sh"
  echo "t will take HEAD of all the repos!"
  echo "-h to show this help screen."
  exit 1
fi

git submodule init && git submodule update || exit 1

UC_VERSION_FILE='./LIBNYX_VERSION'
NEW_VERSION=""

cd ./libnyx || exit 1
git fetch origin main 1>/dev/null || exit 1
git stash 1>/dev/null 2>/dev/null
git stash drop 1>/dev/null 2>/dev/null
git checkout main
git pull origin main 1>/dev/null || exit 1

NEW_VERSION=$(git rev-parse --short HEAD)

if [ -z "$NEW_VERSION" ]; then
  echo "Error getting version."
  exit 1
fi

git checkout "$NEW_VERSION" || exit 1

cd ..

rm "$UC_VERSION_FILE"
echo "$NEW_VERSION" > "$UC_VERSION_FILE"

echo "Done. New XXX version is $NEW_VERSION."


UC_VERSION_FILE='./PACKER_VERSION'
NEW_VERSION=""

cd ./packer || exit 1
git fetch origin main 1>/dev/null || exit 1
git stash 1>/dev/null 2>/dev/null
git stash drop 1>/dev/null 2>/dev/null
git checkout main
git pull origin main 1>/dev/null || exit 1

NEW_VERSION=$(git rev-parse --short HEAD)

if [ -z "$NEW_VERSION" ]; then
  echo "Error getting version."
  exit 1
fi

git checkout "$NEW_VERSION" || exit 1

cd ..

rm "$UC_VERSION_FILE"
echo "$NEW_VERSION" > "$UC_VERSION_FILE"

echo "Done. New XXX version is $NEW_VERSION."


UC_VERSION_FILE='./QEMU_NYX_VERSION'
NEW_VERSION=""

cd ./QEMU-Nyx || exit 1
git fetch origin qemu-nyx-4.2.0 1>/dev/null || exit 1
git stash 1>/dev/null 2>/dev/null
git stash drop 1>/dev/null 2>/dev/null
git checkout qemu-nyx-4.2.0
git pull origin qemu-nyx-4.2.0 1>/dev/null || exit 1

NEW_VERSION=$(git rev-parse --short HEAD)

if [ -z "$NEW_VERSION" ]; then
  echo "Error getting version."
  exit 1
fi

git checkout "$NEW_VERSION" || exit 1

cd ..

rm "$UC_VERSION_FILE"
echo "$NEW_VERSION" > "$UC_VERSION_FILE"

echo "Done. New XXX version is $NEW_VERSION."

