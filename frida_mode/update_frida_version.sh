#!/bin/sh
test -n "$1" && { echo This script has no options. It updates the referenced Frida version in GNUmakefile to the most current one. ; exit 1 ; }

OLD=$(egrep '^GUM_DEVKIT_VERSION=' GNUmakefile 2>/dev/null|awk -F= '{print$2}')
NEW=$(curl https://github.com/frida/frida/releases/ 2>/dev/null|egrep 'frida-gum-devkit-[0-9.]*-linux-x86_64'|head -n 1|sed 's/.*frida-gum-devkit-//'|sed 's/-linux.*//')

echo Current set version: $OLD
echo Newest available version: $NEW

test -z "$OLD" -o -z "$NEW" -o "$OLD" = "$NEW" && { echo Nothing to be done. ; exit 0 ; }

sed -i "s/=$OLD/=$NEW/" GNUmakefile || exit 1
echo Successfully updated GNUmakefile
