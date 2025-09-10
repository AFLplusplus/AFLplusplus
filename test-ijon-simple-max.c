#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

int main(int argc, char *argv[]) {
    __AFL_INIT();  // Initialize AFL++ forkserver

    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    // AFL++ forkserver handshake compatibility: don't exit if file doesn't exist yet
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        // During AFL++ handshake, the input file might not exist yet
        // Just return success to complete the handshake
        return 0;
    }

    // Read input
    unsigned char buf[1024];
    size_t len = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    if (len < 8) {
        printf("Need at least 8 bytes of input\n");
        return 1;
    }

    // Use first 4 bytes as first value
    uint32_t value1 = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];

    // Use next 4 bytes as second value
    uint32_t value2 = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];

    // Test single argument tracking
    printf("About to call IJON_MAX(value1) on line %d\n", __LINE__ + 1);
    IJON_MAX(value1);

    // Test two argument tracking
    printf("About to call IJON_MAX(value1, value2) on line %d\n", __LINE__ + 1);
    IJON_MAX(value1, value2);

    // Test with some derived values
    uint32_t sum = value1 + value2;
    uint32_t product = value1 * value2;
    printf("About to call IJON_MAX(sum, product, value1, value2) on line %d\n", __LINE__ + 1);
    IJON_MAX(sum, product, value1, value2);

    // Test IJON_INC calls - these should increment coverage counters
    printf("About to call IJON_INC(value1) on line %d\n", __LINE__ + 1);
    IJON_INC(value1);

    printf("About to call IJON_INC(value2) on line %d\n", __LINE__ + 1);
    IJON_INC(value2);

    // Test multiple increments of same value (should accumulate)
    printf("About to call IJON_INC(sum) on line %d\n", __LINE__ + 1);
    IJON_INC(sum);
    printf("About to call IJON_INC(sum) again on line %d\n", __LINE__ + 1);
    IJON_INC(sum);

    printf("All IJON_MAX and IJON_INC calls completed\n");
    return 0;
}