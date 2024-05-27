#ifndef ARCH_H
#define ARCH_H

//NOTE Update register enums here

//# ARCHS
enum ARCH{
    X86_64, X86, ARM, ARM64
};

//# REGS
enum x86_64_REG{
    RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8, R9, R10, R11, R12, R13, R14, R15, RIP
};

#endif