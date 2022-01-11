#include <errno.h>
#include <link.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/personality.h>

#define UNUSED_PARAMETER(x) (void)(x)

int phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    UNUSED_PARAMETER (size);

    ElfW(Addr) * base = data;

    if (info->dlpi_name[0] == 0) { *base = info->dlpi_addr; }
    return 0;
}

int main (int argc, char** argv, char** envp) {
    UNUSED_PARAMETER (argc);

    ElfW(Addr) base = 0;

    int persona = personality(ADDR_NO_RANDOMIZE);
    if (persona == -1) {

        printf("Failed to set ADDR_NO_RANDOMIZE: %d", errno);
        return 1;
    }

    if ((persona & ADDR_NO_RANDOMIZE) == 0) { execvpe(argv[0], argv, envp); }

    dl_iterate_phdr(phdr_callback, &base);

    printf("%p\n", (void *)base);
    if (base == 0) { return 1; }

    return 0;
}
