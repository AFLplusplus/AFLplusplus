#!/bin/bash
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# set -x
target="$1"
symbol="$2"
base="$3"

test -z "$target" -o -z "$symbol" -o '!' -e "$target" && exit 0

test $(uname -s) = "Darwin" && symbol=_"$symbol"

file "$target" | grep -q executable && {
  nm "$target" | grep -i "T $symbol" | awk '{print"0x"$1}'
  exit 0
}

hex_base=$(echo "$3" | awk '{sub("^0x","");print $0}' | tr a-f A-F )
nm "$target" | grep -i "T $symbol" | awk '{print$1}' | tr a-f A-F | \
  xargs echo "ibase=16;obase=10;$hex_base + " | bc | tr A-F a-f | awk '{print "0x"$0}'
exit 0
