#!/bin/bash
export PWD=$(pwd)
export PARENT=$(realpath $PWD/..)
export QEMU_OUT=$PWD/qemu_out
export FRIDA_OUT=$PWD/frida_out

QEMU_EXECS=$(grep execs_done $QEMU_OUT -h -r --include fuzzer_stats | cut -d ":" -f 2 | paste -sd+ - | bc)
FRIDA_EXECS=$(grep execs_done $FRIDA_OUT -h -r --include fuzzer_stats | cut -d ":" -f 2 | paste -sd+ - | bc)

echo QEMU_EXECS $QEMU_EXECS
echo FRIDA_EXECS $FRIDA_EXECS

if [ "$FRIDA_EXECS" -gt "$QEMU_EXECS" ];
then
    DELTA=$(echo "$FRIDA_EXECS - $QEMU_EXECS" | bc)
    CALC=$(echo "scale=2;$DELTA * 100" / $QEMU_EXECS| bc)
    echo FRIDA is $CALC % faster
else
    DELTA=$(echo "$QEMU_EXECS - $FRIDA_EXECS" | bc)
    CALC=$(echo "scale=2;$DELTA * 100" / $FRIDA_EXECS| bc)
    echo QEMU is $CALC % faster
fi;

QEMU_STABILITY=$(grep stability $QEMU_OUT -h -r --include fuzzer_stats | cut -d ":" -f 2)
echo QEMU_STABILITY $QEMU_STABILITY

FRIDA_STABILITY=$(grep stability $FRIDA_OUT -h -r --include fuzzer_stats | cut -d ":" -f 2)
echo FRIDA_STABILITY $FRIDA_STABILITY

echo "QEMU RESULTS"
$PARENT/afl-whatsup -s -d $QEMU_OUT

echo "FRIDA RESULTS"
$PARENT/afl-whatsup -s -d $FRIDA_OUT