#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include "afl-fuzz.h"


int sock = 0;
struct sockaddr_in server;
int error = 0;

int statsd_init(char *host, int port){
    if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
        perror("socket");
        exit(1);
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    
    struct addrinfo *result;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if ( (error = getaddrinfo(host, NULL, &hints, &result)) ) {
        perror("getaddrinfo");
        exit(1);
    }

    memcpy(&(server.sin_addr), &((struct sockaddr_in*)result->ai_addr)->sin_addr, sizeof(struct in_addr));
    freeaddrinfo(result);

    return 0;
}

int send_statsd_metric(afl_state_t *afl){
    u64 cur_ms = get_cur_time();
    if (cur_ms - afl->stats_last_plot_ms < 1000) {
        return 0;
    }

    error = statsd_init("127.0.0.1", 12345);
    if (error){
        perror("Failed to init statsd client. Aborting");
        return -1;
    }
    
    if(!sock){
        perror("sock");
        return -1;
    }
    char buff[512];
    statsd_format_metric(afl, buff, 512);

    if (sendto(sock, buff, strlen(buff), 0, (struct sockaddr *) &server, sizeof(server)) == -1) {
        perror("sendto");
        return -1;
    }
    close(sock);
    sock=0;

    return 0;
}


void statsd_format_metric(afl_state_t *afl, char *buff, int bufflen){
    char *format = "fuzzing.afl.cycle_done:%llu|c\n"
    "fuzzing.afl.total_path:%lu|c\n"
    "fuzzing.afl.unique_crashes:%llu|c\n"
    "fuzzing.afl.total_crashes:%llu|c\n"
    "fuzzing.afl.unique_hangs:%llu|c\n";
    snprintf(buff, bufflen, format,
        afl->queue_cycle,
        afl->queued_paths,
        afl->unique_crashes,
        afl->total_crashes,
        afl->unique_hangs
    );
}