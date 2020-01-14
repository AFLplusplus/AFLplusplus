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
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <unicorn/unicorn.h>

// Path to the file containing the binary to emulate
#define BINARY_FILE ("simple_target_x86_64")

// Memory map for the code to be tested
// Arbitrary address where code to test will be loaded
#define BASE_ADDRESS (0x100000)
#define CODE_ADDRESS (0x101119)
#define END_ADDRESS  (0x1011d7)
// Address of the stack (Some random address again)
#define STACK_ADDRESS (((int64_t) 0x01) << 58)
// Size of the stack (arbitrarily chosen, just make it big enough)
#define STACK_SIZE (0x10000)  
// Location where the input will be placed (make sure the emulated program knows this somehow, too ;) )
#define INPUT_LOCATION (0x10000)
// Inside the location, we have an ofset in our special case
#define INPUT_OFFSET (0x16) 
// Maximum allowable size of mutated data from AFL
#define INPUT_SIZE_MAX (0x10000)  
// Alignment for unicorn mappings (seems to be needed)
#define ALIGNMENT ((uint64_t) 0x1000)

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
}

/* Unicorn page needs to be 0x1000 aligned, apparently */
static uint64_t pad(uint64_t size) {
    if (size % ALIGNMENT == 0) return size;
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
	fprintf(stderr, "Filesize of %s too large", filename);
	goto exit;
    }

    *buf_ptr = mmap(0, in_len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (*buf_ptr != MAP_FAILED) ret = in_len;

exit:
    close(fd);
    return ret;

}

/* Place the input at the right spot inside unicorn */
static bool place_input_callback(
    uc_engine *uc, 
    char *input, 
    size_t input_len, 
    uint32_t persistent_round, 
    void *data
){
    // printf("Placing input with len %ld to %x\n", input_len, DATA_ADDRESS);
    if (input_len >= INPUT_SIZE_MAX - INPUT_OFFSET) {
        // Test input too long, ignore this testcase
        return false;
    }
    uc_mem_write(uc, INPUT_LOCATION + INPUT_OFFSET, input, input_len);
    return true;
}

static void mem_map_checked(uc_engine *uc, uint64_t addr, size_t size, uint32_t mode) {
    size = pad(size);
    //printf("SIZE %lx, align: %lx\n", size, ALIGNMENT);
    uc_err err = uc_mem_map(uc, addr, size, mode);
    if (err != UC_ERR_OK) {
        printf("Error mapping %ld bytes at 0x%lx: %s (mode: %d)\n", size, addr, uc_strerror(err), mode);
        exit(1);
    }
}

int main(int argc, char **argv, char **envp) {
    if (argc == 1) {
        printf("Test harness for simple_target.bin. Usage: harness [-t] <inputfile>\n");
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

    printf("Loading data input from %s\n", BINARY_FILE);
    off_t len = afl_mmap_file(BINARY_FILE, &file_contents);
    if (len < 0) {
        perror("Could not read binary to emulate");
        return -2;
    }
    if (len == 0) {
	fprintf(stderr, "File at '%s' is empty\n", BINARY_FILE);
	return -3;
    }

    // Map memory.
    mem_map_checked(uc, BASE_ADDRESS, len, UC_PROT_ALL);
    printf("Len: %lx", len);
    fflush(stdout);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, BASE_ADDRESS, file_contents, len) != UC_ERR_OK) {
        printf("Error writing to CODE");
    }

    // Release copied contents
    munmap(file_contents, len);

    // Set the program counter to the start of the code
    uint64_t start_address = CODE_ADDRESS;      // address of entry point of main()
    uint64_t end_address = END_ADDRESS; // Address of last instruction in main()
    uc_reg_write(uc, UC_X86_REG_RIP, &start_address); // address of entry point of main()
    
    // Setup the Stack
    mem_map_checked(uc, STACK_ADDRESS - STACK_SIZE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE);
    uint64_t stack_val = STACK_ADDRESS;
    printf("%ld", stack_val);
    uc_reg_write(uc, UC_X86_REG_RSP, &stack_val);

    // reserve some space for our input data
    mem_map_checked(uc, INPUT_LOCATION, INPUT_SIZE_MAX, UC_PROT_READ);

    // build a "dummy" argv with lenth 2 at 0x10000: 
    // 0x10000 argv[0]  NULL
    // 0x10008 argv[1]  (char *)0x10016 --. points to the next offset.
    // 0x10016 argv[1][0], ...          <-^ contains the acutal input data. (INPUT_LOCATION + INPUT_OFFSET)

    uc_mem_write(uc, 0x10008, "\x16\x00\x01", 3); // little endian of 0x10016, see above

    // Set up the function parameters accordingly RSI, RDI (see calling convention/disassembly)
    uint64_t input_location = INPUT_LOCATION;
    uc_reg_write(uc, UC_X86_REG_RSI, &input_location); // argv
    uint64_t emulated_argc = 2;
    uc_reg_write(uc, UC_X86_REG_RDI, &emulated_argc);  // argc == 2
   
    // If we want tracing output, set the callbacks here
    if (tracing) {
        // tracing all basic blocks with customized callback
        uc_hook_add(uc, &hooks[0], UC_HOOK_BLOCK, hook_block, NULL, 1, 0);
        uc_hook_add(uc, &hooks[1], UC_HOOK_CODE, hook_code, NULL, BASE_ADDRESS, BASE_ADDRESS + len - 1);
    }

    printf("Starting to fuzz :)\n");
    fflush(stdout);

    // let's gooo
    uc_afl_ret afl_ret = uc_afl_fuzz(
        uc, // The unicorn instance we prepared
        filename, // Filename of the input to process. In AFL this is usually the '@@' placeholder, outside it's any input file.
        place_input_callback, // Callback that places the input (automatically loaded from the file at filename) in the unicorninstance
        &end_address, // Where to exit (this is an array)
        1,  // Count of end addresses
        NULL, // Optional calback to run after each exec
        false,
        1, // For persistent mode: How many rounds to run
        NULL
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
