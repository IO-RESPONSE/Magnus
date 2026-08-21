#ifndef MAGNUS_POLICY_H
#define MAGNUS_POLICY_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAGNUS_MAX_UPSTREAMS 16

/* Advanced load balancing (roadmap 2e-1). Chosen per magnus_cluster_t
 * (magnus_cluster_init()'s own `policy` argument), never per request --
 * every fresh (non-sticky-cookie) selection against one cluster uses
 * exactly one of these. A client's own MAGNUS_AFFINITY cookie, when
 * present, always takes priority over whichever policy is configured
 * (see magnus_cluster_select()'s own comment) -- the policy only decides
 * what a *fresh* selection does. */
typedef enum {
    /* Smooth weighted round-robin -- the long-standing default,
     * unchanged since before this enum existed. */
    MAGNUS_LB_ROUND_ROBIN = 0,
    /* Picks the healthy endpoint with the fewest requests currently in
     * flight against it (magnus_cluster_endpoint_begin()/_end()'s own
     * live count) -- ties broken by lowest index, deterministically.
     * Well suited to a backend fleet whose per-request cost varies
     * enough that "equal share of requests" (round-robin) does not mean
     * "equal share of load." */
    MAGNUS_LB_LEAST_CONN,
    /* Rendezvous (highest-random-weight) hashing on the client's own
     * source IP address -- the same client always lands on the same
     * healthy endpoint, deterministically, with no cookie/Set-Cookie
     * round trip needed at all (unlike this codebase's own
     * MAGNUS_AFFINITY cookie mechanism, which most non-browser clients,
     * including every real gRPC client, simply never persist). Minimal
     * remapping on membership change: adding or removing one endpoint
     * only ever moves the traffic that specific endpoint's own scores
     * affected, not a wholesale reshuffle the way a plain `hash % count`
     * would cause. */
    MAGNUS_LB_IP_HASH
} magnus_lb_policy_t;

typedef struct {
    char address[64];
    unsigned port;
    unsigned weight;
    int current_weight;
    unsigned failures;
    uint64_t retry_after_ms;
    bool healthy;
    /* Requests currently in flight against this endpoint -- maintained
     * only by callers that opt in via magnus_cluster_endpoint_begin()/
     * _end() (the HTTP/1.1 and HTTP/2 proxy dispatch paths, both sharing
     * one magnus_cluster_t; the separate gRPC cluster does not
     * participate in this increment -- see magnus_cluster_endpoint_begin()'s
     * own comment). Read by MAGNUS_LB_LEAST_CONN; otherwise unused, and
     * harmless to leave untouched -- it is also exposed on its own via
     * `magnus_upstream_active_requests` in /metrics regardless of which
     * policy is configured. */
    unsigned active_requests;
} magnus_endpoint_t;

typedef struct {
    magnus_endpoint_t endpoints[MAGNUS_MAX_UPSTREAMS];
    size_t count;
    unsigned failure_threshold;
    uint64_t cooldown_ms;
    magnus_lb_policy_t policy;
} magnus_cluster_t;

typedef struct {
    double tokens;
    double rate;
    double burst;
    uint64_t updated_ms;
} magnus_rate_limit_t;

/* `policy` governs every *fresh* selection this cluster ever makes (see
 * magnus_lb_policy_t's own comment) -- MAGNUS_LB_ROUND_ROBIN if this is
 * never explicitly set to anything else, preserving this function's own
 * pre-2e-1 behavior exactly. */
void magnus_cluster_init(magnus_cluster_t *cluster, unsigned failure_threshold,
                         uint64_t cooldown_ms, magnus_lb_policy_t policy);
int magnus_cluster_add(magnus_cluster_t *cluster, const char *address,
                       unsigned port, unsigned weight);
/* Picks a healthy (or past-cooldown) endpoint. `affinity_key`, when
 * non-empty, always wins regardless of `cluster->policy` -- rendezvous-
 * hashed against every available endpoint (roadmap 2e-1: replaces the
 * previous `hash(key) % count` plus linear probe, which reshuffled most
 * existing key->endpoint assignments on any membership change; rendezvous
 * hashing only ever remaps the traffic whichever endpoint actually
 * changed was itself responsible for). This is this codebase's own
 * MAGNUS_AFFINITY cookie mechanism's selection primitive, unchanged in
 * priority or contract by this increment -- only its algorithm improved.
 * `client_ip` is used only when `affinity_key` is empty *and*
 * `cluster->policy == MAGNUS_LB_IP_HASH` (rendezvous-hashed the same way,
 * on the raw address bytes); ignored by every other policy, but still
 * required as a parameter (rather than optional) so a caller can never
 * silently forget to pass it and only notice once ip_hash is configured
 * in production. */
int magnus_cluster_select(magnus_cluster_t *cluster, uint64_t now_ms,
                          const char *affinity_key, struct in_addr client_ip);
/* Like magnus_cluster_select(), but keys directly off a known endpoint
 * index (e.g. one decoded from a sticky-session cookie) instead of hashing
 * a string. Returns `preferred_index` directly when it is in range and
 * available (healthy, or past its cooldown); otherwise falls back to
 * `cluster->policy` exactly like magnus_cluster_select()'s own
 * no-affinity-key path (with the same `client_ip` used for
 * MAGNUS_LB_IP_HASH). */
int magnus_cluster_select_sticky(magnus_cluster_t *cluster, uint64_t now_ms,
                                 size_t preferred_index,
                                 struct in_addr client_ip);
void magnus_cluster_result(magnus_cluster_t *cluster, size_t endpoint,
                           bool success, uint64_t now_ms);
/* Bumps/drops `endpoint`'s own live active_requests count -- see that
 * field's own comment on which callers are expected to use these
 * (paired, exactly once each per request actually dispatched to this
 * endpoint) and which are not. magnus_cluster_endpoint_end() is safe to
 * call on an index whose count is already 0 (a defensive floor, never
 * underflows) so a caller does not need to track on its own whether a
 * given attempt's own begin() ever actually ran. */
void magnus_cluster_endpoint_begin(magnus_cluster_t *cluster, size_t endpoint);
void magnus_cluster_endpoint_end(magnus_cluster_t *cluster, size_t endpoint);
void magnus_rate_init(magnus_rate_limit_t *limit, double rate, double burst,
                      uint64_t now_ms);
bool magnus_rate_allow(magnus_rate_limit_t *limit, uint64_t now_ms);

#endif
