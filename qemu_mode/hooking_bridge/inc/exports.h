#ifndef API_H
#define API_H

//# EXPORTS
// Returns 0 on success
int r_mem(unsigned long long addr, unsigned long long len, void *dest);
// // Returns 0 on success
int w_mem(unsigned long long addr, unsigned long long len, void *src);
// Returns num of bytes read; 
int r_reg(unsigned char reg, void *dest);
// // Returns num of bytes written
int w_reg(unsigned char reg, char *src);


//NOTE hook function must be named hook_<16 hex character at_addr>
//NOTE must define function `struct conf* configure()`
struct conf{
    unsigned char IP_reg_num;
    unsigned long long entry_addr;
    unsigned long long* hooks;
    unsigned long long num_hooks;
}conf;

struct ret{
    unsigned long long addr;
    char remove_bp;
};

#endif