#!/bin/sh
AFL_TEST_DEPTH=$((AFL_TEST_DEPTH-1))

if [ $AFL_TEST_DEPTH = 0 ]; then
# All runs done :)

$ECHO "$GREY[*] $AFL_TEST_COUNT test cases completed.$RESET"
test "$INCOMPLETE" = "0" && $ECHO "$GREEN[+] all test cases executed"
test "$INCOMPLETE" = "1" && $ECHO "$YELLOW[-] not all test cases were executed"
test "$CODE" = "0" && $ECHO "$GREEN[+] all tests were successful :-)$RESET"
test "$CODE" = "0" || $ECHO "$RED[!] failure in tests :-($RESET"
exit $CODE

fi
