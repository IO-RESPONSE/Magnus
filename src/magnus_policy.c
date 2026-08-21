#include "magnus_policy.h"

#include <stdio.h>
#include <string.h>

/* FNV-1a, 64-bit -- a running hash so it can be fed a key and then an
 * endpoint's own identity in sequence (magnus_cluster_select_rendezvous()'s
 * own use) without ever concatenating them into one buffer first. */
static uint64_t
magnus_hash_init(void)
{
    return UINT64_C(1469598103934665603);
}

static uint64_t
magnus_hash_update(uint64_t hash, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    for (size_t index = 0; index < length; index++) {
        hash ^= bytes[index];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

void
magnus_cluster_init(magnus_cluster_t *cluster, unsigned failure_threshold,
                    uint64_t cooldown_ms, magnus_lb_policy_t policy)
{
    memset(cluster, 0, sizeof(*cluster));
    cluster->failure_threshold = failure_threshold == 0 ? 3 : failure_threshold;
    cluster->cooldown_ms = cooldown_ms == 0 ? 5000 : cooldown_ms;
    cluster->policy = policy;
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

static bool
magnus_cluster_endpoint_available(const magnus_endpoint_t *endpoint,
                                  uint64_t now_ms)
{
    return endpoint->healthy || now_ms >= endpoint->retry_after_ms;
}

static int
magnus_cluster_select_round_robin(magnus_cluster_t *cluster, uint64_t now_ms)
{
    unsigned total = 0;
    int selected = -1;
    for (size_t index = 0; index < cluster->count; index++) {
        magnus_endpoint_t *endpoint = &cluster->endpoints[index];
        if (!magnus_cluster_endpoint_available(endpoint, now_ms)) continue;
        endpoint->current_weight += (int) endpoint->weight;
        total += endpoint->weight;
        if (selected < 0 || endpoint->current_weight
            > cluster->endpoints[selected].current_weight) selected = (int) index;
    }
    if (selected >= 0) cluster->endpoints[selected].current_weight -= (int) total;
    return selected;
}

/* Picks the available endpoint with the fewest requests currently in
 * flight against it (magnus_endpoint_t's own `active_requests`), ties
 * broken by lowest index -- see that field's own comment on which
 * callers actually maintain it. */
static int
magnus_cluster_select_least_conn(magnus_cluster_t *cluster, uint64_t now_ms)
{
    int selected = -1;
    for (size_t index = 0; index < cluster->count; index++) {
        magnus_endpoint_t *endpoint = &cluster->endpoints[index];
        if (!magnus_cluster_endpoint_available(endpoint, now_ms)) continue;
        if (selected < 0
            || endpoint->active_requests
                   < cluster->endpoints[selected].active_requests)
            selected = (int) index;
    }
    return selected;
}

/* Rendezvous (highest-random-weight) hashing: every available endpoint is
 * scored by hashing `key` followed by that endpoint's own address:port
 * identity, and the endpoint with the highest score wins. Deterministic
 * for a fixed (key, endpoint set) pair, and -- the entire point of
 * choosing this over a plain `hash(key) % count` -- minimally disruptive
 * when the endpoint set changes: removing or adding one endpoint only
 * ever changes the outcome for keys whose *highest* score belonged to
 * that one endpoint, never reshuffles anyone else's own winner. Used both
 * for this codebase's own MAGNUS_AFFINITY cookie-based stickiness
 * (`key`/`key_length` is the cookie's own token) and for
 * MAGNUS_LB_IP_HASH (`key`/`key_length` is the client's raw address
 * bytes) -- the same primitive, just a different key, since both are
 * really the same problem ("consistently map an opaque key onto one
 * endpoint"). */
static int
magnus_cluster_select_rendezvous(magnus_cluster_t *cluster, uint64_t now_ms,
                                 const void *key, size_t key_length)
{
    int selected = -1;
    uint64_t best_score = 0;
    for (size_t index = 0; index < cluster->count; index++) {
        magnus_endpoint_t *endpoint = &cluster->endpoints[index];
        char identity[80];
        int identity_length;
        uint64_t score;
        if (!magnus_cluster_endpoint_available(endpoint, now_ms)) continue;
        identity_length = snprintf(identity, sizeof(identity), "%s:%u",
                                   endpoint->address, endpoint->port);
        if (identity_length < 0) continue;
        if ((size_t) identity_length >= sizeof(identity))
            identity_length = (int) sizeof(identity) - 1;
        score = magnus_hash_update(magnus_hash_init(), key, key_length);
        score = magnus_hash_update(score, identity, (size_t) identity_length);
        if (selected < 0 || score > best_score) {
            selected = (int) index;
            best_score = score;
        }
    }
    return selected;
}

int
magnus_cluster_select(magnus_cluster_t *cluster, uint64_t now_ms,
                      const char *affinity_key, struct in_addr client_ip)
{
    if (cluster->count == 0) return -1;
    if (affinity_key != NULL && *affinity_key != '\0') {
        return magnus_cluster_select_rendezvous(cluster, now_ms, affinity_key,
                                                strlen(affinity_key));
    }
    switch (cluster->policy) {
    case MAGNUS_LB_IP_HASH:
        return magnus_cluster_select_rendezvous(cluster, now_ms, &client_ip,
                                                sizeof(client_ip));
    case MAGNUS_LB_LEAST_CONN:
        return magnus_cluster_select_least_conn(cluster, now_ms);
    case MAGNUS_LB_ROUND_ROBIN:
    default:
        return magnus_cluster_select_round_robin(cluster, now_ms);
    }
}

int
magnus_cluster_select_sticky(magnus_cluster_t *cluster, uint64_t now_ms,
                             size_t preferred_index, struct in_addr client_ip)
{
    if (cluster->count == 0) return -1;
    if (preferred_index < cluster->count) {
        magnus_endpoint_t *endpoint = &cluster->endpoints[preferred_index];
        if (magnus_cluster_endpoint_available(endpoint, now_ms))
            return (int) preferred_index;
    }
    /* Falls back to whichever policy this cluster is configured for --
     * not hardcoded round-robin -- since the preferred endpoint being
     * unavailable is exactly the situation MAGNUS_LB_LEAST_CONN/IP_HASH
     * exist to handle as gracefully as plain round-robin already did. */
    return magnus_cluster_select(cluster, now_ms, NULL, client_ip);
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
magnus_cluster_endpoint_begin(magnus_cluster_t *cluster, size_t endpoint_index)
{
    if (endpoint_index >= cluster->count) return;
    cluster->endpoints[endpoint_index].active_requests++;
}

void
magnus_cluster_endpoint_end(magnus_cluster_t *cluster, size_t endpoint_index)
{
    if (endpoint_index >= cluster->count) return;
    if (cluster->endpoints[endpoint_index].active_requests > 0)
        cluster->endpoints[endpoint_index].active_requests--;
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
