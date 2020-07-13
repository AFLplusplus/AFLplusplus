#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    long double magic;

    ssize_t bytes_read = read(STDIN_FILENO, &magic, sizeof(magic));
    if (bytes_read < (ssize_t)sizeof(magic)) {
        return 1;
    }

    if( (-magic == 15.0 + 0.5 + 0.125 + 0.03125 + 0.0078125) ){ /* 15 + 1/2 + 1/8 + 1/32 + 1/128 */
        abort();
    }

    return 0;
}
