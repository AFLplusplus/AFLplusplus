/*
   Simple test harness for AFL++'s unicornafl c mode.

   This loads the simple_target_x86_64 binary into
   Unicorn's memory map for emulation, places the specified input into
   argv[1], sets up argv, and argc and executes 'main()'.
   If run inside AFL, afl_fuzz automatically does the "right thing"

   Run under AFL as follows:

   $ cd <afl_path>/unicorn_mode/samples/simple/
   $ make
   $ ../../../afl-fuzz -m none -i sample_inputs -o out -- ./harness @@
*/

// This is not your everyday Unicorn.
#define UNICORN_AFL

#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <unicorn/unicorn.h>

// Path to the file containing the binary to emulate
#define BINARY_FILE ("../target")

// Memory map for the code to be tested
// Arbitrary address where code to test will be loaded
static const int64_t BASE_ADDRESS = 0x0;
// Max size for the code (64kb)
static const int64_t CODE_SIZE_MAX = 0x00010000;
// Location where the input will be placed (make sure the emulated program knows this somehow, too ;) )
static const int64_t INPUT_ADDRESS = 0x00100000;
// Maximum size for our input
static const int64_t INPUT_MAX = 0x00100000;
// Where our pseudo-heap is at
static const int64_t HEAP_ADDRESS = 0x00200000;
// Maximum allowable size for the heap
static const int64_t HEAP_SIZE_MAX = 0x000F0000;
// Address of the stack (Some random address again)
static const int64_t STACK_ADDRESS = 0x00400000;
// Size of the stack (arbitrarily chosen, just make it big enough)
static const int64_t STACK_SIZE = 0x000F0000;

// Alignment for unicorn mappings (seems to be needed)
static const int64_t ALIGNMENT = 0x1000;

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
}

/* Unicorn page needs to be 0x1000 aligned, apparently */
static uint64_t pad(uint64_t size) {
    if (size % ALIGNMENT == 0) { return size; }
    return ((size / ALIGNMENT) + 1) * ALIGNMENT;
} 

/* returns the filesize in bytes, -1 or error. */
static off_t afl_mmap_file(char *filename, char **buf_ptr) {

    off_t ret = -1;

    int fd = open(filename, O_RDONLY);

    struct stat st = {0};
    if (fstat(fd, &st)) goto exit;

    off_t in_len = st.st_size;
    if (in_len == -1) {
        /* This can only ever happen on 32 bit if the file is exactly 4gb. */
        fprintf(stderr, "Filesize of %s too large\n", filename);
        goto exit;
    }

    *buf_ptr = mmap(0, in_len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (*buf_ptr != MAP_FAILED) ret = in_len;

exit:
    close(fd);
    return ret;

}

/* Place the input at the right spot inside unicorn.
   This code path is *HOT*, do as little work as possible! */
static bool place_input_callback(
    uc_engine *uc, 
    char *input, 
    size_t input_len, 
    uint32_t persistent_round, 
    void *data
){
    // printf("Placing input with len %ld to %x\n", input_len, DATA_ADDRESS);
    if (input_len >= INPUT_MAX) {
        // Test input too short or too long, ignore this testcase
        return false;
    }

    // We need a valid c string, make sure it never goes out of bounds.
    input[input_len-1] = '\0';

    // Write the testcase to unicorn.
    uc_mem_write(uc, INPUT_ADDRESS, input, input_len);

    return true;
}

// exit in case the unicorn-internal mmap fails.
static void mem_map_checked(uc_engine *uc, uint64_t addr, size_t size, uint32_t mode) {
    size = pad(size);
    //printf("SIZE %llx, align: %llx\n", size, ALIGNMENT);
    uc_err err = uc_mem_map(uc, addr, size, mode);
    if (err != UC_ERR_OK) {
        printf("Error mapping %ld bytes at 0x%lx: %s (mode: %d)\n", size, addr, uc_strerror(err), mode);
        exit(1);
    }
}

// allocates an array, reads all addrs to the given array ptr, returns a size
ssize_t read_all_addrs(char *path, uint64_t *addrs, size_t max_count) {

    FILE *f = fopen(path, "r"); 
    if (!f) {
        perror("fopen");
        fprintf(stderr, "Could not read %s, make sure you ran ./get_offsets.py\n", path);
        exit(-1);
    }
    for (size_t i = 0; i < max_count; i++) {
        bool end = false;
        if(fscanf(f, "%lx", &addrs[i]) == EOF) {
            end = true;
            i--;
        } else if (fgetc(f) == EOF) {
            end = true;
        }
        if (end) {
            printf("Set %ld addrs for %s\n", i + 1, path);
            fclose(f);
            return i + 1;
        }
    }
    return max_count;
}

// Read all addresses from the given file, and set a hook for them.
void set_all_hooks(uc_engine *uc, char *hook_file, void *hook_fn) {

    FILE *f = fopen(hook_file, "r");
    if (!f) {
        fprintf(stderr, "Could not read %s, make sure you ran ./get_offsets.py\n", hook_file);
        exit(-1);
    }
    uint64_t hook_addr;
    for (int hook_count = 0; 1; hook_count++) {
        if(fscanf(f, "%lx", &hook_addr) == EOF) {
            printf("Set %d hooks for %s\n", hook_count, hook_file);
            fclose(f);
            return;
        }
        printf("got new hook addr %lx (count: %d) ohbytw: sizeof %lx\n", hook_addr, hook_count, sizeof(uc_hook));
        hook_addr += BASE_ADDRESS;
        // We'll leek these hooks like a good citizen.
        uc_hook *hook = calloc(1, sizeof(uc_hook));
        if (!hook) {
            perror("calloc");
            exit(-1);
        }
        uc_hook_add(uc, hook, UC_HOOK_CODE, hook_fn, NULL, hook_addr, hook_addr);
        // guzzle up newline
        if (fgetc(f) == EOF) {
            printf("Set %d hooks for %s\n", hook_count, hook_file);
            fclose(f);
            return;
        }
    }

}

// This is a fancy print function that we're just going to skip for fuzzing.
static void hook_magicfn(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    address += size;
    uc_reg_write(uc, UC_X86_REG_RIP, &address);
} 

static bool already_allocated = false;

// We use a very simple malloc/free stub here, that only works for exactly one allocation at a time.
static void hook_malloc(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    if (already_allocated) {
        printf("Double malloc, not supported right now!\n");
        abort();
    }
    // read the first param.
    uint64_t malloc_size;
    uc_reg_read(uc, UC_X86_REG_RDI, &malloc_size);
    if (malloc_size > HEAP_SIZE_MAX) {
        printf("Tried to allocated %ld bytes, but we only support up to %ld\n", malloc_size, HEAP_SIZE_MAX);
        abort();
    }
    uc_reg_write(uc, UC_X86_REG_RAX, &HEAP_ADDRESS);
    address += size;
    uc_reg_write(uc, UC_X86_REG_RIP, &address);
    already_allocated = true;
}

// No real free, just set the "used"-flag to false.
static void hook_free(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    if (!already_allocated) {
        printf("Double free detected. Real bug?\n");
        abort();
    }
    // read the first param.
    uint64_t free_ptr;
    uc_reg_read(uc, UC_X86_REG_RDI, &free_ptr);
    if (free_ptr != HEAP_ADDRESS) {
        printf("Tried to free wrong mem region: 0x%lx at code loc 0x%lx\n", free_ptr, address);
        abort();
    }
    address +=  size;
    uc_reg_write(uc, UC_X86_REG_RIP, &address);
    already_allocated = false;
}

int main(int argc, char **argv, char **envp) {
    if (argc == 1) {
        printf("Test harness to measure speed against Rust and python. Usage: harness [-t] <inputfile>\n");
        exit(1);
    }
    bool tracing = false;
    char *filename = argv[1];
    if (argc > 2 && !strcmp(argv[1], "-t")) {
        tracing = true;
        filename = argv[2];
    }

    uc_engine *uc;
    uc_err err;
    uc_hook hooks[2];
    char *file_contents;

    // Initialize emulator in X86_64 mode
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return -1;
    }

    // If we want tracing output, set the callbacks here
    if (tracing) {
        // tracing all basic blocks with customized callback
        uc_hook_add(uc, &hooks[0], UC_HOOK_BLOCK, hook_block, NULL, 1, 0);
        uc_hook_add(uc, &hooks[1], UC_HOOK_CODE, hook_code, NULL, 1, 0);
    }

    printf("The input testcase is set to %s\n", filename);


    printf("Loading target from %s\n", BINARY_FILE);
    off_t len = afl_mmap_file(BINARY_FILE, &file_contents);
    printf("Binary file size: %lx\n", len);
    if (len < 0) {
        perror("Could not read binary to emulate");
        return -2;
    }
    if (len == 0) {
        fprintf(stderr, "File at '%s' is empty\n", BINARY_FILE);
        return -3;
    }
    if (len > CODE_SIZE_MAX) {
        fprintf(stderr, "Binary too large, increase CODE_SIZE_MAX\n");
        return -4;
    }

    // Map memory.
    mem_map_checked(uc, BASE_ADDRESS, len, UC_PROT_ALL);
    fflush(stdout);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, BASE_ADDRESS, file_contents, len) != UC_ERR_OK) {
        puts("Error writing to CODE");
        exit(-1);
    }

    // Release copied contents
    munmap(file_contents, len);

    // Set the program counter to the start of the code
    FILE *f = fopen("../target.offsets.main", "r");
    if (!f) {
        perror("fopen");
        puts("Could not read offset to main function, make sure you ran ./get_offsets.py");
        exit(-1);
    }
    uint64_t start_address;
    if(fscanf(f, "%lx", &start_address) == EOF) {
        puts("Start address not found in target.offests.main");
        exit(-1);
    }
    fclose(f);
    start_address += BASE_ADDRESS;
    printf("Execution will start at 0x%lx", start_address);
    // Set the program counter to the start of the code
    uc_reg_write(uc, UC_X86_REG_RIP, &start_address); // address of entry point of main()

    // Setup the Stack
    mem_map_checked(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE);
    // Setup the stack pointer, but allocate two pointers for the pointers to input
    uint64_t val = STACK_ADDRESS + STACK_SIZE - 16;
    //printf("Stack at %lu\n", stack_val);
    uc_reg_write(uc, UC_X86_REG_RSP, &val);

    // reserve some space for our input data
    mem_map_checked(uc, INPUT_ADDRESS, INPUT_MAX, UC_PROT_READ);

    // argc = 2
    val = 2;
    uc_reg_write(uc, UC_X86_REG_RDI, &val);
    //RSI points to our little 2 QWORD space at the beginning of the stack...
    val = STACK_ADDRESS + STACK_SIZE - 16;
    uc_reg_write(uc, UC_X86_REG_RSI, &val);

    //... which points to the Input. Write the ptr to mem in little endian.
    uint32_t addr_little = STACK_ADDRESS;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    // The chances you are on a big_endian system aren't too high, but still...
    __builtin_bswap32(addr_little);
#endif

    uc_mem_write(uc, STACK_ADDRESS + STACK_SIZE - 16, (char *)&addr_little, 4);

    set_all_hooks(uc, "../target.offsets.malloc", hook_malloc);
    set_all_hooks(uc, "../target.offsets.magicfn", hook_magicfn);
    set_all_hooks(uc, "../target.offsets.free", hook_free);

    int exit_count_max = 100;
    // we don't need more exits for now.
    uint64_t exits[exit_count_max];

    ssize_t exit_count = read_all_addrs("../target.offsets.main_ends", exits, exit_count_max);
    if (exit_count < 1) {
        printf("Could not find exits! aborting.\n");
        abort();
    }

    printf("Starting to fuzz. Running from addr %ld to one of these %ld exits:\n", start_address, exit_count);
    for (ssize_t i = 0; i < exit_count; i++) {
        printf("    exit %ld: %ld\n", i, exits[i]);
    }

    fflush(stdout);

    // let's gooo
    uc_afl_ret afl_ret = uc_afl_fuzz(
        uc, // The unicorn instance we prepared
        filename, // Filename of the input to process. In AFL this is usually the '@@' placeholder, outside it's any input file.
        place_input_callback, // Callback that places the input (automatically loaded from the file at filename) in the unicorninstance
        exits, // Where to exit (this is an array)
        exit_count,  // Count of end addresses
        NULL, // Optional calback to run after each exec
        false, // true, if the optional callback should be run also for non-crashes
        1000, // For persistent mode: How many rounds to run
        NULL // additional data pointer
    );
    switch(afl_ret) {
        case UC_AFL_RET_ERROR:
            printf("Error starting to fuzz");
            return -3;
            break;
        case UC_AFL_RET_NO_AFL:
            printf("No AFL attached - We are done with a single run.");
            break;
        default:
            break;
    } 
    return 0;
}
