#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include "afl-fuzz.h"


#define MAX_STATSD_PACKET_SIZE 1400
#define MAX_TAG_LEN 200

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
    
    u16 port = 8125;
    char* host = "127.0.0.1";

    char* port_env;
    char* host_env;
    if ((port_env = getenv("AFL_STATSD_PORT")) != NULL) {
        // sanitization check ?
        port = atoi(port_env);
    }
    if ((host_env = getenv("AFL_STATSD_HOST")) != NULL) {
        // sanitization check ?
        host = host_env;
    }
    
    error = statsd_init(host, port);
    if (error){
        perror("Failed to init statsd client. Aborting");
        return -1;
    }
    
    if(!sock){
        perror("sock");
        return -1;
    }

    char buff[MAX_STATSD_PACKET_SIZE] = {0};

    statsd_format_metric(afl, buff, MAX_STATSD_PACKET_SIZE);
    if (sendto(sock, buff, MAX_STATSD_PACKET_SIZE, 0,
               (struct sockaddr *)&server, sizeof(server)) == -1) {
      perror("sendto");
      return -1;
    }

    close(sock);
    sock=0;

    return 0;
}

int statsd_format_metric(afl_state_t *afl, char *buff, size_t bufflen){
    /*
    metric format:
    <some.namespaced.name>:<value>|<type>|<tags>
    tags format:
    #key:value,key:value,key
    */
    char tags[MAX_TAG_LEN * 2] = {0};
    snprintf(tags, MAX_TAG_LEN * 2,
        "banner:%s,afl_version:%s",
        afl->use_banner,
        VERSION);
    // Sends multiple metrics with one UDP Packet.
    // bufflen will limit to the max safe size.
    snprintf(buff, bufflen,
        "fuzzing.afl.cycle_done:%llu|g|#%s\n"
        "fuzzing.afl.total_path:%u|g|#%s\n"
        "fuzzing.afl.unique_crashes:%llu|g|#%s\n"
        "fuzzing.afl.total_crashes:%llu|g|#%s\n"
        "fuzzing.afl.unique_hangs:%llu|g|#%s\n",
        afl->queue_cycle, tags, afl->queued_paths, tags, afl->unique_crashes,
        tags, afl->total_crashes, tags, afl->unique_hangs, tags);

    return 0;
}