#ifndef MAGNUS_CONFIG_H
#define MAGNUS_CONFIG_H

#include "magnus_policy.h"
#include "magnus_route.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAGNUS_CONFIG_MAX_UPSTREAMS 16
#define MAGNUS_CONFIG_PATH_MAX 256
#define MAGNUS_CONFIG_MAX_ROUTES 32
#define MAGNUS_CONFIG_MAX_TRUSTED_PROXIES 16
/* Separate, smaller cap from MAGNUS_CONFIG_MAX_UPSTREAMS: a gRPC upstream
 * cluster (roadmap 2c-1) is its own pool, not a shared namespace with the
 * ordinary HTTP/1.x `upstream` cluster -- a real gRPC deployment typically
 * has far fewer distinct backend clusters than a general reverse-proxy
 * fleet might, so 8 is generous without copying the 16 bound blindly. */
#define MAGNUS_CONFIG_MAX_GRPC_UPSTREAMS 8

typedef struct {
    struct in_addr network;
    unsigned prefix_length;
} magnus_cidr_t;

typedef struct {
    /* Either a literal IPv4 address, or (is_hostname true) a hostname to
     * be resolved asynchronously at runtime -- see magnus_dns.h. Either
     * way this is the value as written in the config; a hostname entry's
     * *current* resolved address lives on the runtime cluster endpoint
     * (magnus_policy.h), not here. */
    char address[64];
    bool is_hostname;
    unsigned port;
    unsigned weight;
} magnus_config_upstream_t;

/* The full, validated shape of a magnus data-plane config file. Every
 * field here has already passed magnus_config_load()'s schema check --
 * callers never need to re-validate ranges or cross-field constraints
 * (e.g. tls_cert/tls_key both-or-neither) themselves. */
typedef struct {
    unsigned port;
    bool has_root;
    char root[MAGNUS_CONFIG_PATH_MAX];
    bool has_tls;
    char tls_cert[MAGNUS_CONFIG_PATH_MAX];
    char tls_key[MAGNUS_CONFIG_PATH_MAX];
    size_t upstream_count;
    magnus_config_upstream_t upstreams[MAGNUS_CONFIG_MAX_UPSTREAMS];
    /* Advanced load balancing (roadmap 2e-1) for the `upstream` cluster
     * above only -- the separate `grpc_upstream` cluster keeps its own
     * pre-existing weighted round-robin unconditionally (see
     * magnus_apply_config()'s own comment on why). Defaults to
     * MAGNUS_LB_ROUND_ROBIN (value 0) via magnus_config_load()'s own
     * memset(), so a config that never mentions `lb_policy` at all keeps
     * this codebase's original behavior unchanged. */
    magnus_lb_policy_t lb_policy;
    /* gRPC upstream cluster (roadmap 2c-1): same ipv4:port[:weight] shape
     * and validation as `upstreams` above (magnus_config_parse_upstream()
     * is reused as-is), but a hostname entry is rejected here -- DNS
     * resolution (1c) is not wired up for this cluster yet, unlike the
     * ordinary one. Targeted only by a route with action=grpc. */
    size_t grpc_upstream_count;
    magnus_config_upstream_t grpc_upstreams[MAGNUS_CONFIG_MAX_GRPC_UPSTREAMS];
    bool has_rate_limit;
    double rate_limit_rps;
    double rate_limit_burst;
    bool access_log_enabled;
    unsigned access_log_sample;
    bool has_admin_socket;
    char admin_socket[MAGNUS_CONFIG_PATH_MAX];
    /* Parsed eagerly here (not left as raw strings) so a malformed route
     * is caught by config validation itself, same as every other field --
     * see magnus_route_parse(). Evaluated in file order; the first
     * matching route wins. Optional: a config with none behaves exactly
     * as it did before routes existed. */
    size_t route_count;
    magnus_route_t routes[MAGNUS_CONFIG_MAX_ROUTES];
    size_t trusted_proxy_count;
    magnus_cidr_t trusted_proxies[MAGNUS_CONFIG_MAX_TRUSTED_PROXIES];
} magnus_config_t;

typedef enum {
    MAGNUS_CONFIG_OK = 0,
    MAGNUS_CONFIG_ERROR
} magnus_config_result_t;

/* Parses and strictly validates the config file at `path`:
 *   - unknown keys are rejected (no silently-ignored typos)
 *   - every value is range/format checked (port, ipv4:port[:weight],
 *     file existence for root/tls_cert/tls_key, tls_cert and tls_key must
 *     be given together, rate_limit_burst requires rate_limit_rps,
 *     access_log is 'on'/'off', access_log_sample is a positive integer,
 *     route is a valid magnus_route_parse() spec -- see magnus_route.h,
 *     lb_policy is 'round_robin'/'least_conn'/'ip_hash' -- see
 *     magnus_policy.h's own magnus_lb_policy_t)
 *   - `port` is required; access_log defaults to "on" and
 *     access_log_sample defaults to 1 (log every request) when omitted;
 *     lb_policy defaults to "round_robin" when omitted
 *
 * On success returns MAGNUS_CONFIG_OK with `config` fully populated. On
 * failure returns MAGNUS_CONFIG_ERROR and writes a human-readable reason
 * (including the offending line number where applicable) into `error`;
 * `config`'s contents are unspecified in this case and must not be used. */
magnus_config_result_t magnus_config_load(const char *path,
                                          magnus_config_t *config,
                                          char *error, size_t error_capacity);

/* A stable (not cryptographic) content fingerprint of a validated config,
 * used for audit trail and generation tracking. Two configs that parse to
 * the same field values hash the same regardless of comment/whitespace
 * differences in the source file. */
uint64_t magnus_config_hash(const magnus_config_t *config);

/* True if `text` is at least hostname-*shaped* (labels of alphanumeric/
 * hyphen, dot-separated, no leading/trailing hyphen or dot, length
 * bounds) -- not a claim that it resolves, which can only be checked
 * asynchronously at runtime (see magnus_dns.h). Exposed so magnus.c's
 * plain --upstream CLI flag can apply the identical check
 * magnus_config_load()'s `upstream` key does, rather than duplicating or
 * drifting from it. */
bool magnus_config_looks_like_hostname(const char *text);

#endif
