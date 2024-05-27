#ifndef API_H
#define API_H

//# EXPORTS
// Returns 0 on success, -1 on error
int r_mem(unsigned long long addr, unsigned long long len, void *dest);
// // Returns 0 on success, -1 on error
int w_mem(unsigned long long addr, unsigned long long len, void *src);
// //NOTE Lookup arch.h for architecture and corresponding register names 
// Returns num of bytes read; 
int r_reg(unsigned char reg, void *dest);
// // Returns num of bytes written
int w_reg(unsigned char reg, char *src);
// //A newline must be put at the end of the last line tp be printed -- better for each line
void q_log(char *buf);


//NOTE Lookup arch.h for architecture and corresponding register names 
//NOTE hook function must be named hook_<16 hex character at_addr>
//NOTE must define function `struct conf* configure()`
//TODO Unfortunately we cannot break on the first block after main at this time. I suspect this is trivial. Will look into it later. 
struct conf{
    unsigned char arch;
    unsigned long long main_addr;
    unsigned long long* hooks;
    unsigned long long num_hooks;
};

struct ret{
    unsigned long long addr;
    char remove_bp;
};

#endif