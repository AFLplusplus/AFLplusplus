#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>
#include "afl-fuzz.h"


#define MAX_STATSD_PACKET_SIZE 4096
#define MAX_TAG_LEN 200
#define METRIC_PREFIX "fuzzing"

struct sockaddr_in server;
int error = 0;
int statds_sock = 0;

int statsd_socket_init(char *host, int port){
    int sock;
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

    return sock;
}

int statsd_send_metric(afl_state_t *afl){
    
    char buff[MAX_STATSD_PACKET_SIZE] = {0};
    /* Default port and host.
    Will be overwritten by AFL_STATSD_PORT and AFL_STATSD_HOST environment variable, if they exists.
    */
    u16 port = STATSD_DEFAULT_PORT;
    char* host = STATSD_DEFAULT_HOST;

    char* port_env;
    char* host_env;
    if ((port_env = getenv("AFL_STATSD_PORT")) != NULL) {
        port = atoi(port_env);
    }
    if ((host_env = getenv("AFL_STATSD_HOST")) != NULL) {
        host = host_env;
    }

    /* statds_sock is a global variable. We set it once in the beginning and reuse the socket.
    If the sendto later fail, we reset it to 0 to be able to recreate it.
    */
    if(!statds_sock){
        statds_sock = statsd_socket_init(host, port);
        if(!statds_sock){
            perror("Cannot create socket");
            return -1;
        }
    }

    statsd_format_metric(afl, buff, MAX_STATSD_PACKET_SIZE);
    if (sendto(statds_sock, buff, strlen(buff), 0, (struct sockaddr *)&server, sizeof(server)) == -1) {
        if(!close(statds_sock)){
            perror("Cannot close socket");
        }
        statds_sock = 0;
        perror("Cannot sendto");
        return -1;
    }

    return 0;
}

int statsd_format_metric(afl_state_t *afl, char *buff, size_t bufflen){
    /* Metric format:
    <some.namespaced.name>:<value>|<type>
    */
    #ifdef USE_STATSD_TAGS
    /* Tags format: DogStatsD
    <some.namespaced.name>:<value>|<type>|#key:value,key:value,key
    */
    char tags[MAX_TAG_LEN * 2] = {0};
    snprintf(tags, MAX_TAG_LEN * 2,
        "|#banner:%s,afl_version:%s",
        afl->use_banner,
        VERSION);
    #else
    /* No tags.
    */
    char *tags = "";
    #endif
    /* Sends multiple metrics with one UDP Packet.
    bufflen will limit to the max safe size.
    */
    snprintf(buff, bufflen,
        METRIC_PREFIX".cycle_done:%llu|g%s\n"
        METRIC_PREFIX".cycles_wo_finds:%llu|g%s\n"
        METRIC_PREFIX".execs_done:%llu|g%s\n"
        METRIC_PREFIX".execs_per_sec:%0.02f|g%s\n"
        METRIC_PREFIX".paths_total:%u|g%s\n"
        METRIC_PREFIX".paths_favored:%u|g%s\n"
        METRIC_PREFIX".paths_found:%u|g%s\n"
        METRIC_PREFIX".paths_imported:%u|g%s\n"
        METRIC_PREFIX".max_depth:%u|g%s\n"
        METRIC_PREFIX".cur_path:%u|g%s\n"
        METRIC_PREFIX".pending_favs:%u|g%s\n"
        METRIC_PREFIX".pending_total:%u|g%s\n"
        METRIC_PREFIX".variable_paths:%u|g%s\n"
        METRIC_PREFIX".unique_crashes:%llu|g%s\n"
        METRIC_PREFIX".unique_hangs:%llu|g%s\n"
        METRIC_PREFIX".total_crashes:%llu|g%s\n"
        METRIC_PREFIX".slowest_exec_ms:%u|g%s\n"
        METRIC_PREFIX".edges_found:%u|g%s\n"
        METRIC_PREFIX".var_byte_count:%u|g%s\n"
        METRIC_PREFIX".havoc_expansion:%u|g%s\n",
        afl->queue_cycle ? (afl->queue_cycle - 1) : 0, tags,
        afl->cycles_wo_finds, tags,
        afl->fsrv.total_execs, tags,
        afl->fsrv.total_execs / ((double)(get_cur_time() - afl->start_time) / 1000), tags,
        afl->queued_paths, tags,
        afl->queued_favored, tags,
        afl->queued_discovered, tags,
        afl->queued_imported, tags,
        afl->max_depth, tags,
        afl->current_entry, tags,
        afl->pending_favored, tags,
        afl->pending_not_fuzzed, tags,
        afl->queued_variable, tags,
        afl->unique_crashes, tags,
        afl->unique_hangs, tags,
        afl->total_crashes, tags,
        afl->slowest_exec_ms, tags,
        count_non_255_bytes(afl, afl->virgin_bits), tags,
        afl->var_byte_count, tags,
        afl->expand_havoc, tags
        );

    return 0;
}