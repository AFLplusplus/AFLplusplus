#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include "afl-fuzz.h"

static int my_debug = 0;
static int my_read = 0;

#define DEBUG(...) if (my_debug) printf(__VA_ARGS__)

typedef struct tcp_send_mutator {
    afl_state_t* afl;
    struct sockaddr_in server_addr;
} tcp_send_mutator_t;

void *afl_custom_init(afl_state_t* afl, uint32_t seed) {
    const char* ip = getenv("CUSTOM_SEND_IP");
    const char* port = getenv("CUSTOM_SEND_PORT");

    if (getenv("AFL_DEBUG")) my_debug = 1;
    if (getenv("CUSTOM_SEND_READ")) my_read = 1;

    if (!ip || !port) {
       fprintf(stderr, "You forgot to set CUSTOM_SEND_IP and/or CUSTOM_SEND_PORT\n");
       exit(1); 
    }

    tcp_send_mutator_t* mutator = calloc(1, sizeof(tcp_send_mutator_t));
    if (!mutator) {
       fprintf(stderr, "Failed to allocate mutator struct\n");
       exit(1); 
    }

    mutator->afl = afl;

    bzero(&mutator->server_addr, sizeof(mutator->server_addr));
    mutator->server_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &mutator->server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Could not convert target ip address!\n");
        exit(1);
    }
    mutator->server_addr.sin_port = htons(atoi(port));
    
    printf("[+] Custom tcp send mutator setup ready to go!\n");

    return mutator;
}

int try_connect(tcp_send_mutator_t *mutator, int sock, int max_attempts) {
    while (max_attempts > 0) {
        if (connect(sock, (struct sockaddr*)&mutator->server_addr, sizeof(mutator->server_addr)) == 0) {
            return 0;
        }

        // Even with AFL_CUSTOM_LATE_SEND=1, there is a race between the
        // application under test having started to listen for connections and
        // afl_custom_fuzz_send being called. To address this race, we attempt
        // to connect N times and sleep a short period of time in between
        // connection attempts.
        struct timespec t;
        t.tv_sec = 0;
        t.tv_nsec = 100;
        nanosleep(&t, NULL);
        --max_attempts;
    }
    return 1;
}

void afl_custom_fuzz_send(tcp_send_mutator_t *mutator, uint8_t *buf, size_t buf_size) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    int written = 0;
    if (sock >= 0 && try_connect(mutator, sock, 10000) == 0) {
        DEBUG("connected, write()\n");
        written = write(sock, buf, buf_size); 
    } else {
        DEBUG("socket() or connect() error: %d\n", errno);
    }

    if (written < 0) {
        DEBUG("write() error: %d\n", errno);
    } else if (my_read) {
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        fd_set set;
        FD_ZERO(&set);
        FD_SET(sock, &set);

        int select_res = select(sock + 1, &set, NULL, NULL, &timeout);
        if (select_res == -1) {
            DEBUG("select() error: %d\n", errno);
        } else if (select_res == 0) {
            DEBUG("read() timeout!\n");
        } else {
            uint8_t buf[64];
            (void)read(sock, buf, sizeof(buf));
        }
    }

    close(sock);
}

void afl_custom_deinit(tcp_send_mutator_t* mutator) {
    free(mutator);
}
