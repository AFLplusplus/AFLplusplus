#!/bin/sh

# cd to the directory of the script to ensure paths are correct
cd "$(dirname "$0")"

. ./test-pre.sh

# Dynamically run all test scripts matching test-*.sh
for script in test-*.sh; do
  # Skip exclusions
  if [ "$script" = "test-pre.sh" ] || \
     [ "$script" = "test-post.sh" ] || \
     [ "$script" = "test-all.sh" ]; then
    continue
  fi

  if [ -r "$script" ]; then
    . "./$script"
  fi
done

. ./test-post.sh
