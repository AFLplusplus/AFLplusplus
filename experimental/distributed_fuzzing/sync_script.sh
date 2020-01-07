#!/bin/sh
#
# american fuzzy lop++ - fuzzer synchronization tool
# --------------------------------------------------
#
# Originally written by Michal Zalewski
#
# Copyright 2014 Google Inc. All rights reserved.
# Copyright 2019-2020 AFLplusplus Project. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# To make this script work:
#
# - Edit FUZZ_HOSTS, FUZZ_DOMAIN, FUZZ_USER, and SYNC_DIR to reflect your
#   environment.
#
# - Make sure that the system you are running this on can log into FUZZ_HOSTS
#   without a password (authorized_keys or otherwise).
#
# - Make sure that every fuzzer is running with -o pointing to SYNC_DIR and -S
#   that consists of its local host name, followed by an underscore, and then
#   by some host-local fuzzer ID.
#

# Hosts to synchronize the data across.
FUZZ_HOSTS='host1 host2 host3 host4'

# Domain for all hosts
FUZZ_DOMAIN='example.com'

# Remote user for SSH
FUZZ_USER=bob

# Directory to synchronize
SYNC_DIR='/home/bob/sync_dir'

# Interval (seconds) between sync attempts
SYNC_INTERVAL=$((30 * 60))

if [ "$AFL_ALLOW_TMP" = "" ]; then

  if [ "$PWD" = "/tmp" -o "$PWD" = "/var/tmp" ]; then
    echo "[-] Error: do not use shared /tmp or /var/tmp directories with this script." 1>&2
    exit 1
  fi

fi

rm -rf .sync_tmp 2>/dev/null
mkdir .sync_tmp || exit 1

while :; do

  # Pull data in...

  for host in $FUZZ_HOSTS; do

    echo "[*] Retrieving data from ${host}.${FUZZ_DOMAIN}..."

    ssh -o 'passwordauthentication no' ${FUZZ_USER}@${host}.$FUZZ_DOMAIN \
      "cd '$SYNC_DIR' && tar -czf - ${host}_*/[qf]*" >".sync_tmp/${host}.tgz"

  done

  # Distribute data. For large fleets, see tips in the docs/ directory.

  for dst_host in $FUZZ_HOSTS; do

    echo "[*] Distributing data to ${dst_host}.${FUZZ_DOMAIN}..."

    for src_host in $FUZZ_HOSTS; do

      test "$src_host" = "$dst_host" && continue

      echo "    Sending fuzzer data from ${src_host}.${FUZZ_DOMAIN}..."

      ssh -o 'passwordauthentication no' ${FUZZ_USER}@$dst_host \
        "cd '$SYNC_DIR' && tar -xkzf -" <".sync_tmp/${src_host}.tgz"

    done

  done

  echo "[+] Done. Sleeping for $SYNC_INTERVAL seconds (Ctrl-C to quit)."

  sleep $SYNC_INTERVAL

done

