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
/* TLS passthrough / SNI routing (roadmap 3b): a modest cap on the number
 * of *distinct patterns*, matching MAGNUS_CONFIG_MAX_GRPC_UPSTREAMS's own
 * "a real deployment has far fewer of these than the main upstream list"
 * reasoning -- each pattern still gets up to MAGNUS_CONFIG_MAX_UPSTREAMS
 * endpoints of its own. */
#define MAGNUS_CONFIG_MAX_SNI_ROUTES 8
#define MAGNUS_CONFIG_SNI_PATTERN_MAX 128

/* PROXY protocol emission (the "PROXY protocol" line item from Phase 3's
 * own roadmap headline, not covered by TCP passthrough (3a), TLS
 * passthrough (3b), or UDP passthrough (3d)): the reverse direction from
 * magnus_realip.h's own magnus_proxy_proto_parse() -- magnus is here the
 * *emitter*, not the receiver, telling the L4 stream cluster's own
 * backend the real client (source IP, source port) it would otherwise
 * never see (every connection looks like it originates from magnus's
 * own address). Defined here (not magnus_realip.h, which already
 * depends on this header for magnus_cidr_t and cannot be depended on in
 * the other direction) so both this config schema and
 * magnus_realip.h's own build-side declarations can share one enum. */
typedef enum {
    MAGNUS_PROXY_PROTOCOL_OFF = 0,
    MAGNUS_PROXY_PROTOCOL_V1,
    MAGNUS_PROXY_PROTOCOL_V2
} magnus_proxy_protocol_mode_t;

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

typedef struct {
    /* An exact hostname, or a `*.` prefix followed by one -- see
     * magnus_sni_pattern_matches() (magnus_sni.h) for the exact matching
     * rule this drives at runtime. */
    char pattern[MAGNUS_CONFIG_SNI_PATTERN_MAX];
    size_t upstream_count;
    magnus_config_upstream_t upstreams[MAGNUS_CONFIG_MAX_UPSTREAMS];
} magnus_config_sni_route_t;

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
    /* L4 TCP passthrough (roadmap 3a): a second, independent listener that
     * never goes through magnus_http_parse() at all -- raw bytes relayed
     * bidirectionally to whichever endpoint stream_lb_policy picks, with
     * no protocol awareness of what is actually flowing over it. Optional
     * (has_stream_listen false when the config never mentions
     * `stream_listen` at all, the same shape as has_admin_socket); a
     * hostname stream_upstream is rejected, same restriction as
     * grpc_upstream and for the same reason (DNS resolution is not wired
     * up for this cluster). Changing stream_listen itself requires a
     * restart, exactly like `port`/`admin_socket` -- only stream_upstream/
     * stream_lb_policy are hot-reloadable. */
    bool has_stream_listen;
    unsigned stream_listen_port;
    size_t stream_upstream_count;
    magnus_config_upstream_t stream_upstreams[MAGNUS_CONFIG_MAX_UPSTREAMS];
    magnus_lb_policy_t stream_lb_policy;
    /* PROXY protocol emission -- see magnus_proxy_protocol_mode_t's own
     * comment. Applies uniformly to every stream connection regardless
     * of which cluster it ends up at (the plain stream_upstream cluster,
     * or a matched stream_sni_route one) -- a deliberate first-increment
     * simplification assuming homogeneous backend expectations across
     * the whole stream_listen surface; per-pattern override is a
     * distinct possible future increment, not silently half-done. Off
     * by default -- unconditionally on would break any existing
     * deployment whose backend does not already expect this preamble as
     * its first bytes. Hot-reloadable, like stream_lb_policy above. */
    magnus_proxy_protocol_mode_t stream_proxy_protocol;
    /* TLS passthrough / SNI routing (roadmap 3b): layered on top of the
     * stream cluster above, never a replacement for it -- a connection
     * whose peeked ClientHello either does not parse, carries no SNI, or
     * matches none of these patterns falls back to the plain
     * stream_upstream cluster (which stream_listen already requires be
     * present). Each `stream_sni_route` line names one pattern plus one
     * endpoint; multiple lines sharing the same pattern accumulate into
     * that pattern's own cluster, first-match-wins in file order, the
     * same evaluation order `route` already uses. Every matched
     * cluster gets its own passive (connect-result) health tracking,
     * same circuit-breaker mechanics as every other cluster in this
     * codebase, but deliberately no active probe of its own in this
     * increment (round_robin only, no configurable policy) -- a
     * dynamic, unbounded-in-principle set of small clusters is a
     * distinct future increment away from the "one active-probe-array
     * per cluster" shape every other cluster here already uses. */
    size_t sni_route_count;
    magnus_config_sni_route_t sni_routes[MAGNUS_CONFIG_MAX_SNI_ROUTES];
    /* UDP passthrough (roadmap 3d): a fourth, independent listener --
     * SOCK_DGRAM, no `accept()`/handshake of any kind, one NAT-style
     * session per distinct (source IP, source port) tuple the listener
     * ever sees. udp_listen may equal `port` or `stream_listen` without
     * conflict (UDP and TCP occupy independent port namespaces at the OS
     * level -- unlike stream_listen vs `port`, which really would
     * collide since both are TCP), so there is deliberately no
     * "must differ" check for it, unlike stream_listen's own. Reuses the
     * same magnus_lb_policy_t selection magnus_cluster_t already
     * provides (round_robin/least_conn/ip_hash), but -- see
     * magnus_udp_session_t's own comment -- no health tracking of any
     * kind: a connect()ed UDP socket's own connect() call almost always
     * "succeeds" locally regardless of whether anything is actually
     * listening at the other end, so it carries none of the passive
     * signal a TCP connect() attempt does, and a real UDP-level health
     * probe is a distinct, not-yet-built future increment. */
    bool has_udp_listen;
    unsigned udp_listen_port;
    size_t udp_upstream_count;
    magnus_config_upstream_t udp_upstreams[MAGNUS_CONFIG_MAX_UPSTREAMS];
    magnus_lb_policy_t udp_lb_policy;
    unsigned udp_session_idle_seconds;
    unsigned udp_max_sessions;
    bool has_rate_limit;
    double rate_limit_rps;
    double rate_limit_burst;
    bool access_log_enabled;
    unsigned access_log_sample;
    bool has_admin_socket;
    char admin_socket[MAGNUS_CONFIG_PATH_MAX];
    /* Active health checking (roadmap 2f): applies uniformly to both the
     * `upstream` cluster's HTTP-level probe (GET health_check_path,
     * success iff the response status equals health_check_expected_status)
     * and the `grpc_upstream` cluster's plain TCP-connect probe (path/
     * expected_status are meaningless there -- see magnus_apply_config()'s
     * own comment on why an HTTP/1.1 GET is not sent to a gRPC-only
     * upstream). failure_threshold/cooldown_seconds feed
     * magnus_cluster_init() for both clusters, the same trip/recovery
     * state active probes already shared with live-traffic passive health
     * before this increment. Defaults (path "/", expected_status 200,
     * interval 5s, timeout 2s, failure_threshold 3, cooldown 5s) exactly
     * reproduce this codebase's pre-2f hardcoded behavior when a config
     * never mentions any of these keys. */
    char health_check_path[MAGNUS_CONFIG_PATH_MAX];
    unsigned health_check_expected_status;
    unsigned health_check_interval_seconds;
    unsigned health_check_timeout_seconds;
    unsigned health_check_failure_threshold;
    unsigned health_check_cooldown_seconds;
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
 *     magnus_policy.h's own magnus_lb_policy_t, health_check_path starts
 *     with '/' and carries no whitespace, health_check_expected_status is
 *     100-599, health_check_interval_seconds/_timeout_seconds/
 *     _failure_threshold/_cooldown_seconds are all positive integers,
 *     stream_upstream must be a literal IPv4 address (not a hostname),
 *     stream_lb_policy is the same enum as lb_policy, stream_listen
 *     requires at least one stream_upstream and vice versa,
 *     stream_proxy_protocol is 'off'/'v1'/'v2',
 *     stream_sni_route is "<pattern> <ipv4:port[:weight]>" -- pattern is
 *     an exact hostname or a `*.`-prefixed one, endpoint is a literal
 *     IPv4 address same as stream_upstream, and stream_sni_route
 *     requires stream_listen; udp_upstream must be a literal IPv4
 *     address, udp_lb_policy is the same enum as lb_policy,
 *     udp_session_idle_seconds is 1-3600, udp_max_sessions is
 *     1-MAGNUS_UDP_MAX_SESSIONS_CEILING (magnus.c), udp_listen requires
 *     at least one udp_upstream and vice versa)
 *   - `port` is required; access_log defaults to "on" and
 *     access_log_sample defaults to 1 (log every request) when omitted;
 *     lb_policy defaults to "round_robin" when omitted; health_check_path
 *     defaults to "/", health_check_expected_status to 200,
 *     health_check_interval_seconds to 5, health_check_timeout_seconds to
 *     2, health_check_failure_threshold to 3, health_check_cooldown_seconds
 *     to 5; stream_listen is optional (the L4 passthrough listener does
 *     not exist at all when omitted); stream_lb_policy defaults to
 *     "round_robin" when omitted; stream_proxy_protocol defaults to "off"
 *     (unconditionally on would break any backend not already expecting
 *     the preamble); stream_sni_route defaults to none (every
 *     stream connection uses the plain stream_upstream cluster); udp_listen
 *     is optional (the UDP listener does not exist at all when omitted);
 *     udp_lb_policy defaults to "round_robin"; udp_session_idle_seconds
 *     defaults to 30; udp_max_sessions defaults to 1024
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
