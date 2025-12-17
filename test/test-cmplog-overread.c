// Test: cmplog buffer over-read bug
// __cmplog_rtn_hook_* functions copy 32 bytes regardless of string length
// Compile: AFL_LLVM_CMPLOG=1 ./afl-clang-fast -o test-cmplog-overread test/test-cmplog-overread.c
// Run: AFL_CMPLOG_DEBUG=1 ./test-cmplog-overread

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    long ps = sysconf(_SC_PAGESIZE);
    void *p = mmap(NULL, ps * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap((char*)p + ps, ps);  // unmap second page

    char *s = (char*)p + ps - 4;  // 4 bytes before page boundary
    strcpy(s, "abc");

    // Bug: strcmp triggers __cmplog_rtn_hook_str which copies 32 bytes
    // from 's', reading 28 bytes past the page boundary -> SIGSEGV
    if (strcmp(s, "xyz") == 0) return 1;

    printf("No crash - cmplog may be disabled\n");
    return 0;
}
