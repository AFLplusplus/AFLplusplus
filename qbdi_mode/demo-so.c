#include <stdio.h>



// gcc -shared -o libdemo.so demo-so.c -w


int target_func(char* buf, int size){
    
    printf("buffer:%p, size:%p\n", buf, size);

    switch (buf[0])
    {
    case 1:
        puts("222");
        if(buf[1]=='\x44'){
            puts("xxxiiii");
        }
        break;
    case '\xfe':
        // assert(0);
        if(buf[4]=='\xf0'){
            puts("xxxiiii");
        }
        break;
    case 0xff:
        if(buf[2]=='\xff'){
            if(buf[1]=='\x44'){
                puts("xxxiiii");
                assert(0);
            }else{
                puts("xxxiiii");
            }
        }
        puts("xxxx");
        break;
    default:
        puts("xxxxxxx");
        break;
    }

    return 1;
}



