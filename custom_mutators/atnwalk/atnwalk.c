#include "../../include/afl-fuzz.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>


#define INIT_BUF_SIZE 4096
#define SOCKET_NAME "/tmp/atnwalk.socket"

// handshake constants
const uint8_t SERVER_ARE_YOU_ALIVE = 42;
const uint8_t SERVER_YES_I_AM_ALIVE = 213;

// control bits
const uint8_t SERVER_CROSSOVER_BIT = 0b00000001;
const uint8_t SERVER_MUTATE_BIT = 0b00000010;
const uint8_t SERVER_DECODE_BIT = 0b00000100;
const uint8_t SERVER_ENCODE_BIT = 0b00001000;


typedef struct atnwalk_mutator {
    uint8_t *decoded_buf;
    size_t decoded_size;
} atnwalk_mutator_t;


int read_all(int fd, uint8_t *buf, size_t buf_size) {
    int n;
    size_t offset = 0;
    while (offset < buf_size) {
        n = read(fd, buf + offset, buf_size - offset);
        if (n == -1) {
            return 0;
        }
        offset += n;
    }
    return 1;
}


int write_all(int fd, uint8_t *buf, size_t buf_size) {
    int n;
    size_t offset = 0;
    while (offset < buf_size) {
        n = write(fd, buf + offset, buf_size - offset);
        if (n == -1) {
            return 0;
        }
        offset += n;
    }
    return 1;
}


/**
 * Initialize this custom mutator
 *
 * @param[in] afl a pointer to the internal state object. Can be ignored for
 * now.
 * @param[in] seed A seed for this mutator - the same seed should always mutate
 * in the same way.
 * @return Pointer to the data object this custom mutator instance should use.
 *         There may be multiple instances of this mutator in one afl-fuzz run!
 *         Return NULL on error.
 */
atnwalk_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
    srand(seed);
    atnwalk_mutator_t *data = (atnwalk_mutator_t *) malloc(sizeof(atnwalk_mutator_t));
    if (!data) {
        perror("afl_custom_init alloc");
        return NULL;
    }
    data->decoded_buf = (uint8_t *) malloc(INIT_BUF_SIZE);
    data->decoded_size = INIT_BUF_SIZE;
    return data;
}

// TODO: implement
/**
 * Perform custom mutations on a given input
 *
 * (Optional for now. Required in the future)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[in] buf Pointer to input data to be mutated
 * @param[in] buf_size Size of input data
 * @param[out] out_buf the buffer we will work on. we can reuse *buf. NULL on
 * error.
 * @param[in] add_buf Buffer containing the additional test case
 * @param[in] add_buf_size Size of the additional test case
 * @param[in] max_size Maximum size of the mutated output. The mutation must not
 *     produce data larger than max_size.
 * @return Size of the mutated output.
 */
size_t afl_custom_fuzz(atnwalk_mutator_t *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf,
                       uint8_t *add_buf, size_t add_buf_size, size_t max_size) {
    struct sockaddr_un addr;
    int fd_socket;
    ssize_t n;
    uint8_t buffer[5];

    // initialize the socket
    fd_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd_socket == -1) {
        perror("socket");
        *out_buf = NULL;
        return 0;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);
    if (connect(fd_socket, (const struct sockaddr *) &addr, sizeof(addr)) == -1) {
        perror("atnwalk server is down");
        *out_buf = NULL;
        return 0;
    }

    if (!write_all(fd_socket, buffer, 5)) {
        perror("write to atnwalk server failed");
        *out_buf = NULL;
        return 0;
    }

    if (read_all(fd_socket, buffer, 5)) {
        perror("read to atnwalk server failed");
        exit(EXIT_FAILURE);
    }

    close(fd_socket);
}

// TODO: implement
/**
 * A post-processing function to use right before AFL writes the test case to
 * disk in order to execute the target.
 *
 * (Optional) If this functionality is not needed, simply don't define this
 * function.
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[in] buf Buffer containing the test case to be executed
 * @param[in] buf_size Size of the test case
 * @param[out] out_buf Pointer to the buffer containing the test case after
 *     processing. External library should allocate memory for out_buf.
 *     The buf pointer may be reused (up to the given buf_size);
 * @return Size of the output buffer after processing or the needed amount.
 *     A return of 0 indicates an error.
 */
size_t afl_custom_post_process(atnwalk_mutator_t *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf) {
    data->decoded_buf[0] = 'p';
    data->decoded_buf[1] = 'u';
    data->decoded_buf[2] = 't';
    data->decoded_buf[3] = 's';
    data->decoded_buf[4] = ' ';
    data->decoded_buf[5] = ';';
    data->decoded_buf[6] = '\n';
    return 7;
}

// TODO: implement
/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(atnwalk_mutator_t *data) {
    free(data->decoded_buf);
    free(data);
}
