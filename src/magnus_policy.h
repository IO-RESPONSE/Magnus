#ifndef MAGNUS_POLICY_H
#define MAGNUS_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAGNUS_MAX_UPSTREAMS 16

typedef struct {
    char address[64];
    unsigned port;
    unsigned weight;
    int current_weight;
    unsigned failures;
    uint64_t retry_after_ms;
    bool healthy;
} magnus_endpoint_t;

typedef struct {
    magnus_endpoint_t endpoints[MAGNUS_MAX_UPSTREAMS];
    size_t count;
    unsigned failure_threshold;
    uint64_t cooldown_ms;
} magnus_cluster_t;

typedef struct {
    double tokens;
    double rate;
    double burst;
    uint64_t updated_ms;
} magnus_rate_limit_t;

void magnus_cluster_init(magnus_cluster_t *cluster, unsigned failure_threshold,
                         uint64_t cooldown_ms);
int magnus_cluster_add(magnus_cluster_t *cluster, const char *address,
                       unsigned port, unsigned weight);
int magnus_cluster_select(magnus_cluster_t *cluster, uint64_t now_ms,
                          const char *affinity_key);
void magnus_cluster_result(magnus_cluster_t *cluster, size_t endpoint,
                           bool success, uint64_t now_ms);
void magnus_rate_init(magnus_rate_limit_t *limit, double rate, double burst,
                      uint64_t now_ms);
bool magnus_rate_allow(magnus_rate_limit_t *limit, uint64_t now_ms);

#endif
