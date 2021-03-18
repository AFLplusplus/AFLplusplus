#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    char str[100]={};
    read(0, str, 100);
    int *ptr = NULL;
    if( str[0] == '\x02' || str[0] == '\xe8') {
        *ptr = 123; 
    }
    return 0;
}

