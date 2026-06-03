#!/bin/sh

# cd to the directory of the script to ensure paths are correct
cd "$(dirname "$0")"

. ./test-pre.sh
TEST_DIR=$(pwd)


ALL_CODE=0

# Dynamically run all test scripts matching test-*.sh
for script in test-*.sh; do
  CODE=0
  # Skip exclusions
  if [ "$script" = "test-pre.sh" ] || \
     [ "$script" = "test-post.sh" ] || \
     [ "$script" = "test-all.sh" ]; then
    continue
  fi

# Check if script is meant to be sourced (sources test-pre.sh)
  if grep -q "test-pre.sh" "$script"; then
    if [ -r "$script" ]; then
      . "./$script"
    fi
    # Restore directory in case the sourced script changed it
    cd "$TEST_DIR"
  else
    echo "$GREY[*] Running $script independently..."
    . ./test-pre.sh
    if [ -x "./$script" ]; then
      "./$script"
    else
      sh "./$script"
    fi
    if [ $? -ne 0 ]; then
      CODE=1
    fi
    . ./test-post.sh
  fi

  if [ "$CODE" = "1" ]; then
    echo "$RED[!] Test script $script failed!$RESET"
    ALL_CODE=1
  fi
done

CODE=$ALL_CODE

. ./test-post.sh
echo done
