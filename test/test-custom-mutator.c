/**
 * Reference: https://github.com/bruce30262/libprotobuf-mutator_fuzzing_learning/blob/master/4_libprotobuf_aflpp_custom_mutator/vuln.c
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    char str[100]={ };
    read(0, str, 100);
    int *ptr = NULL;
    if( str[0] == 'P') {
        *ptr = 123;
    }
    return 0;
}
