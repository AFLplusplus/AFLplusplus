/*
 * This implements rpc.statsd support, see docs/rpc_statsd.md
 *
 */

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

/* Tags format for metrics
  DogStatsD:
  metric.name:<value>|<type>|#key:value,key2:value2

  InfluxDB
  metric.name,key=value,key2=value2:<value>|<type>

  Librato
  metric.name#key=value,key2=value2:<value>|<type>

  SignalFX
  metric.name[key=value,key2=value2]:<value>|<type>

*/

// after the whole metric.
#define DOGSTATSD_TAGS_FORMAT "|#banner:%s,afl_version:%s"

// just after the metric name.
#define LIBRATO_TAGS_FORMAT "#banner=%s,afl_version=%s"
#define INFLUXDB_TAGS_FORMAT ",banner=%s,afl_version=%s"
#define SIGNALFX_TAGS_FORMAT "[banner=%s,afl_version=%s]"

// For DogstatsD
#define STATSD_TAGS_TYPE_SUFFIX 1
#define STATSD_TAGS_SUFFIX_METRICS                                       \
  METRIC_PREFIX                                                          \
  ".cycle_done:%llu|g%s\n" METRIC_PREFIX                                 \
  ".cycles_wo_finds:%llu|g%s\n" METRIC_PREFIX                            \
  ".execs_done:%llu|g%s\n" METRIC_PREFIX                                 \
  ".execs_per_sec:%0.02f|g%s\n" METRIC_PREFIX                            \
  ".corpus_count:%u|g%s\n" METRIC_PREFIX                                 \
  ".corpus_favored:%u|g%s\n" METRIC_PREFIX                               \
  ".corpus_found:%u|g%s\n" METRIC_PREFIX                                 \
  ".corpus_imported:%u|g%s\n" METRIC_PREFIX                              \
  ".max_depth:%u|g%s\n" METRIC_PREFIX ".cur_item:%u|g%s\n" METRIC_PREFIX \
  ".pending_favs:%u|g%s\n" METRIC_PREFIX                                 \
  ".pending_total:%u|g%s\n" METRIC_PREFIX                                \
  ".corpus_variable:%u|g%s\n" METRIC_PREFIX                              \
  ".saved_crashes:%llu|g%s\n" METRIC_PREFIX                              \
  ".saved_hangs:%llu|g%s\n" METRIC_PREFIX                                \
  ".total_crashes:%llu|g%s\n" METRIC_PREFIX                              \
  ".slowest_exec_ms:%u|g%s\n" METRIC_PREFIX                              \
  ".edges_found:%u|g%s\n" METRIC_PREFIX                                  \
  ".var_byte_count:%u|g%s\n" METRIC_PREFIX ".havoc_expansion:%u|g%s\n"

// For Librato, InfluxDB, SignalFX
#define STATSD_TAGS_TYPE_MID 2
#define STATSD_TAGS_MID_METRICS                                          \
  METRIC_PREFIX                                                          \
  ".cycle_done%s:%llu|g\n" METRIC_PREFIX                                 \
  ".cycles_wo_finds%s:%llu|g\n" METRIC_PREFIX                            \
  ".execs_done%s:%llu|g\n" METRIC_PREFIX                                 \
  ".execs_per_sec%s:%0.02f|g\n" METRIC_PREFIX                            \
  ".corpus_count%s:%u|g\n" METRIC_PREFIX                                 \
  ".corpus_favored%s:%u|g\n" METRIC_PREFIX                               \
  ".corpus_found%s:%u|g\n" METRIC_PREFIX                                 \
  ".corpus_imported%s:%u|g\n" METRIC_PREFIX                              \
  ".max_depth%s:%u|g\n" METRIC_PREFIX ".cur_item%s:%u|g\n" METRIC_PREFIX \
  ".pending_favs%s:%u|g\n" METRIC_PREFIX                                 \
  ".pending_total%s:%u|g\n" METRIC_PREFIX                                \
  ".corpus_variable%s:%u|g\n" METRIC_PREFIX                              \
  ".saved_crashes%s:%llu|g\n" METRIC_PREFIX                              \
  ".saved_hangs%s:%llu|g\n" METRIC_PREFIX                                \
  ".total_crashes%s:%llu|g\n" METRIC_PREFIX                              \
  ".slowest_exec_ms%s:%u|g\n" METRIC_PREFIX                              \
  ".edges_found%s:%u|g\n" METRIC_PREFIX                                  \
  ".var_byte_count%s:%u|g\n" METRIC_PREFIX ".havoc_expansion%s:%u|g\n"

void statsd_setup_format(afl_state_t *afl) {

  if (afl->afl_env.afl_statsd_tags_flavor &&
      strcmp(afl->afl_env.afl_statsd_tags_flavor, "dogstatsd") == 0) {

    afl->statsd_tags_format = DOGSTATSD_TAGS_FORMAT;
    afl->statsd_metric_format = STATSD_TAGS_SUFFIX_METRICS;
    afl->statsd_metric_format_type = STATSD_TAGS_TYPE_SUFFIX;

  } else if (afl->afl_env.afl_statsd_tags_flavor &&

             strcmp(afl->afl_env.afl_statsd_tags_flavor, "librato") == 0) {

    afl->statsd_tags_format = LIBRATO_TAGS_FORMAT;
    afl->statsd_metric_format = STATSD_TAGS_MID_METRICS;
    afl->statsd_metric_format_type = STATSD_TAGS_TYPE_MID;

  } else if (afl->afl_env.afl_statsd_tags_flavor &&

             strcmp(afl->afl_env.afl_statsd_tags_flavor, "influxdb") == 0) {

    afl->statsd_tags_format = INFLUXDB_TAGS_FORMAT;
    afl->statsd_metric_format = STATSD_TAGS_MID_METRICS;
    afl->statsd_metric_format_type = STATSD_TAGS_TYPE_MID;

  } else if (afl->afl_env.afl_statsd_tags_flavor &&

             strcmp(afl->afl_env.afl_statsd_tags_flavor, "signalfx") == 0) {

    afl->statsd_tags_format = SIGNALFX_TAGS_FORMAT;
    afl->statsd_metric_format = STATSD_TAGS_MID_METRICS;
    afl->statsd_metric_format_type = STATSD_TAGS_TYPE_MID;

  } else {

    // No tags at all.
    afl->statsd_tags_format = "";
    // Still need to pick a format. Doesn't change anything since if will be
    // replaced by the empty string anyway.
    afl->statsd_metric_format = STATSD_TAGS_MID_METRICS;
    afl->statsd_metric_format_type = STATSD_TAGS_TYPE_MID;

  }

}

int statsd_socket_init(afl_state_t *afl) {

  /* Default port and host.
  Will be overwritten by AFL_STATSD_PORT and AFL_STATSD_HOST environment
  variable, if they exists.
  */
  u16   port = STATSD_DEFAULT_PORT;
  char *host = STATSD_DEFAULT_HOST;

  if (afl->afl_env.afl_statsd_port) {

    port = atoi(afl->afl_env.afl_statsd_port);

  }

  if (afl->afl_env.afl_statsd_host) { host = afl->afl_env.afl_statsd_host; }

  int sock;
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {

    FATAL("Failed to create socket");

  }

  memset(&afl->statsd_server, 0, sizeof(afl->statsd_server));
  afl->statsd_server.sin_family = AF_INET;
  afl->statsd_server.sin_port = htons(port);

  struct addrinfo *result;
  struct addrinfo  hints;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;

  if ((getaddrinfo(host, NULL, &hints, &result))) {

    FATAL("Fail to getaddrinfo");

  }

  memcpy(&(afl->statsd_server.sin_addr),
         &((struct sockaddr_in *)result->ai_addr)->sin_addr,
         sizeof(struct in_addr));
  freeaddrinfo(result);

  return sock;

}

int statsd_send_metric(afl_state_t *afl) {

  char buff[MAX_STATSD_PACKET_SIZE] = {0};

  /* afl->statsd_sock is set once in the initialisation of afl-fuzz and reused
  each time If the sendto later fail, we reset it to 0 to be able to recreates
  it.
  */
  if (!afl->statsd_sock) {

    afl->statsd_sock = statsd_socket_init(afl);
    if (!afl->statsd_sock) {

      WARNF("Cannot create socket");
      return -1;

    }

  }

  statsd_format_metric(afl, buff, MAX_STATSD_PACKET_SIZE);
  if (sendto(afl->statsd_sock, buff, strlen(buff), 0,
             (struct sockaddr *)&afl->statsd_server,
             sizeof(afl->statsd_server)) == -1) {

    if (!close(afl->statsd_sock)) { PFATAL("Cannot close socket"); }
    afl->statsd_sock = 0;
    WARNF("Cannot sendto");
    return -1;

  }

  return 0;

}

int statsd_format_metric(afl_state_t *afl, char *buff, size_t bufflen) {

  char tags[MAX_TAG_LEN * 2] = {0};
  if (afl->statsd_tags_format) {

    snprintf(tags, MAX_TAG_LEN * 2, afl->statsd_tags_format, afl->use_banner,
             VERSION);

  }

  /* Sends multiple metrics with one UDP Packet.
  bufflen will limit to the max safe size.
  */
  if (afl->statsd_metric_format_type == STATSD_TAGS_TYPE_SUFFIX) {

    snprintf(
        buff, bufflen, afl->statsd_metric_format,
        afl->queue_cycle ? (afl->queue_cycle - 1) : 0, tags,
        afl->cycles_wo_finds, tags, afl->fsrv.total_execs, tags,
        afl->fsrv.total_execs /
            ((double)(get_cur_time() + afl->prev_run_time - afl->start_time) /
             1000),
        tags, afl->queued_items, tags, afl->queued_favored, tags,
        afl->queued_discovered, tags, afl->queued_imported, tags,
        afl->max_depth, tags, afl->current_entry, tags, afl->pending_favored,
        tags, afl->pending_not_fuzzed, tags, afl->queued_variable, tags,
        afl->saved_crashes, tags, afl->saved_hangs, tags, afl->total_crashes,
        tags, afl->slowest_exec_ms, tags,
        count_non_255_bytes(afl, afl->virgin_bits), tags, afl->var_byte_count,
        tags, afl->expand_havoc, tags);

  } else if (afl->statsd_metric_format_type == STATSD_TAGS_TYPE_MID) {

    snprintf(
        buff, bufflen, afl->statsd_metric_format, tags,
        afl->queue_cycle ? (afl->queue_cycle - 1) : 0, tags,
        afl->cycles_wo_finds, tags, afl->fsrv.total_execs, tags,
        afl->fsrv.total_execs /
            ((double)(get_cur_time() + afl->prev_run_time - afl->start_time) /
             1000),
        tags, afl->queued_items, tags, afl->queued_favored, tags,
        afl->queued_discovered, tags, afl->queued_imported, tags,
        afl->max_depth, tags, afl->current_entry, tags, afl->pending_favored,
        tags, afl->pending_not_fuzzed, tags, afl->queued_variable, tags,
        afl->saved_crashes, tags, afl->saved_hangs, tags, afl->total_crashes,
        tags, afl->slowest_exec_ms, tags,
        count_non_255_bytes(afl, afl->virgin_bits), tags, afl->var_byte_count,
        tags, afl->expand_havoc);

  }

  return 0;

}

