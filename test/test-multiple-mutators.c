/**
 * Test-Case for multiple custom mutators in C
 * Reference:
 * https://github.com/bruce30262/libprotobuf-mutator_fuzzing_learning/blob/master/4_libprotobuf_aflpp_custom_mutator/vuln.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char ** argv)
{
    int a=0;
    char s[16];
    memset(s, 0, 16);
    read(0, s, 0xa0);

    if ( s[17] != '\x00') {
        abort();
    }

    return 0;
}
