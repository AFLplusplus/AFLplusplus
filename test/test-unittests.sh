#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Execution cmocka Unit-Tests $GREY"
unset AFL_CC
make -C .. unit || CODE=1 INCOMPLETE=1 :

. ./test-post.sh
