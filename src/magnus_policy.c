#include "magnus_policy.h"

#include <string.h>

static uint64_t
magnus_hash(const char *text)
{
    uint64_t value = UINT64_C(1469598103934665603);
    while (*text != '\0') {
        value ^= (unsigned char) *text++;
        value *= UINT64_C(1099511628211);
    }
    return value;
}

void
magnus_cluster_init(magnus_cluster_t *cluster, unsigned failure_threshold,
                    uint64_t cooldown_ms)
{
    memset(cluster, 0, sizeof(*cluster));
    cluster->failure_threshold = failure_threshold == 0 ? 3 : failure_threshold;
    cluster->cooldown_ms = cooldown_ms == 0 ? 5000 : cooldown_ms;
}

int
magnus_cluster_add(magnus_cluster_t *cluster, const char *address,
                   unsigned port, unsigned weight)
{
    magnus_endpoint_t *endpoint;
    if (cluster->count == MAGNUS_MAX_UPSTREAMS || address == NULL
        || strlen(address) >= sizeof(cluster->endpoints[0].address)
        || port == 0 || port > 65535) return -1;
    endpoint = &cluster->endpoints[cluster->count++];
    strcpy(endpoint->address, address);
    endpoint->port = port;
    endpoint->weight = weight == 0 ? 1 : weight;
    endpoint->healthy = true;
    return 0;
}

static int
magnus_cluster_select_round_robin(magnus_cluster_t *cluster, uint64_t now_ms)
{
    unsigned total = 0;
    int selected = -1;
    for (size_t index = 0; index < cluster->count; index++) {
        magnus_endpoint_t *endpoint = &cluster->endpoints[index];
        if (!endpoint->healthy && now_ms < endpoint->retry_after_ms) continue;
        endpoint->current_weight += (int) endpoint->weight;
        total += endpoint->weight;
        if (selected < 0 || endpoint->current_weight
            > cluster->endpoints[selected].current_weight) selected = (int) index;
    }
    if (selected >= 0) cluster->endpoints[selected].current_weight -= (int) total;
    return selected;
}

int
magnus_cluster_select(magnus_cluster_t *cluster, uint64_t now_ms,
                      const char *affinity_key)
{
    if (cluster->count == 0) return -1;
    if (affinity_key != NULL && *affinity_key != '\0') {
        uint64_t start = magnus_hash(affinity_key) % cluster->count;
        for (size_t offset = 0; offset < cluster->count; offset++) {
            size_t index = (size_t) ((start + offset) % cluster->count);
            magnus_endpoint_t *endpoint = &cluster->endpoints[index];
            if (endpoint->healthy || now_ms >= endpoint->retry_after_ms)
                return (int) index;
        }
        return -1;
    }
    return magnus_cluster_select_round_robin(cluster, now_ms);
}

int
magnus_cluster_select_sticky(magnus_cluster_t *cluster, uint64_t now_ms,
                             size_t preferred_index)
{
    if (cluster->count == 0) return -1;
    if (preferred_index < cluster->count) {
        magnus_endpoint_t *endpoint = &cluster->endpoints[preferred_index];
        if (endpoint->healthy || now_ms >= endpoint->retry_after_ms)
            return (int) preferred_index;
    }
    return magnus_cluster_select_round_robin(cluster, now_ms);
}

void
magnus_cluster_result(magnus_cluster_t *cluster, size_t endpoint_index,
                      bool success, uint64_t now_ms)
{
    magnus_endpoint_t *endpoint;
    if (endpoint_index >= cluster->count) return;
    endpoint = &cluster->endpoints[endpoint_index];
    if (success) {
        endpoint->failures = 0;
        endpoint->healthy = true;
        endpoint->retry_after_ms = 0;
    } else if (++endpoint->failures >= cluster->failure_threshold) {
        endpoint->healthy = false;
        endpoint->retry_after_ms = now_ms + cluster->cooldown_ms;
    }
}

void
magnus_rate_init(magnus_rate_limit_t *limit, double rate, double burst,
                 uint64_t now_ms)
{
    limit->rate = rate;
    limit->burst = burst;
    limit->tokens = burst;
    limit->updated_ms = now_ms;
}

bool
magnus_rate_allow(magnus_rate_limit_t *limit, uint64_t now_ms)
{
    double elapsed = (double) (now_ms - limit->updated_ms) / 1000.0;
    limit->tokens += elapsed * limit->rate;
    if (limit->tokens > limit->burst) limit->tokens = limit->burst;
    limit->updated_ms = now_ms;
    if (limit->tokens < 1.0) return false;
    limit->tokens -= 1.0;
    return true;
}
