#include "magnus_phase.h"
#include "magnus_base64.h"
#include "magnus_config.h"
#include "magnus_http.h"
#include "magnus_policy.h"
#include "magnus_dns.h"
#include "magnus_h2.h"
#include "magnus_proxy.h"
#include "magnus_route.h"
#include "magnus_ws.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <nghttp2/nghttp2.h>

#define MAGNUS_VERSION "1.10.0"
#define MAGNUS_MAX_EVENTS 1024
#define MAGNUS_MAX_FDS 65536
#define MAGNUS_INPUT_LIMIT 8192
#define MAGNUS_MAX_BODY (1 * 1024 * 1024)
#define MAGNUS_OUTPUT_LIMIT 2048
/* Sized to stay well clear of MAGNUS_OUTPUT_LIMIT once wrapped in
 * response headers; magnus_build_metrics()'s per-endpoint/per-bucket
 * loops stop appending once they run out of room rather than risk
 * overflowing the response envelope, so the fixed aggregate lines are
 * always present even when there is not room for full detail. */
#define MAGNUS_METRICS_BUFFER 1536
#define MAGNUS_IDLE_SECONDS 30
#define MAGNUS_HEADER_TIMEOUT_SECONDS 10
#define MAGNUS_PROXY_BUFFER 16384
#define MAGNUS_INITIAL_INPUT 2048
#define MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS 5
#define MAGNUS_PROXY_READ_TIMEOUT_SECONDS 10
#define MAGNUS_PROXY_HEADER_LIMIT MAGNUS_PROXY_BUFFER
#define MAGNUS_PROXY_SANITIZED_LIMIT 4096
#define MAGNUS_PROXY_MAX_ATTEMPTS 2
#define MAGNUS_HEALTH_CHECK_INTERVAL_SECONDS 5
#define MAGNUS_HEALTH_PROBE_TIMEOUT_SECONDS 2
#define MAGNUS_CLUSTER_FAILURE_THRESHOLD 3
#define MAGNUS_CLUSTER_COOLDOWN_MS 5000
#define MAGNUS_RATE_TABLE_SIZE 512
#define MAGNUS_POOL_MAX_IDLE_PER_ENDPOINT 8
#define MAGNUS_POOL_IDLE_TIMEOUT_SECONDS 60
#define MAGNUS_POOL_MAX_REQUESTS_PER_CONNECTION 100
/* How often a hostname upstream is re-resolved. Fixed, not the record's
 * actual TTL -- see magnus_dns.h's design note on why this module cannot
 * see a real TTL at all without hand-rolling DNS wire-format parsing. */
#define MAGNUS_DNS_REFRESH_SECONDS 30
/* Cap on concurrent streams per HTTP/2 connection (roadmap 1e-1): plenty
 * for a browser's fan-out of a single page's static assets, small enough
 * that a hostile client opening streams as fast as possible cannot grow
 * this connection's own bookkeeping (the h2_streams list) without bound
 * -- nghttp2 itself enforces the limit once advertised via SETTINGS. */
#define MAGNUS_H2_MAX_CONCURRENT_STREAMS 128
/* Rapid-Reset-class abuse hardening (roadmap 1e-3, CVE-2023-44487's
 * attack shape: open a stream, immediately RST_STREAM it, repeat as
 * fast as possible -- cheap for the attacker, expensive for the server
 * if each open triggers real dispatch work). Both caps are per
 * connection, per second: generous enough that no legitimate client
 * (even a browser's full-page fan-out, or a legitimate client cancelling
 * a handful of in-flight requests, e.g. a fast page navigation away)
 * ever comes close, tight enough that an attacker cycling through
 * MAGNUS_H2_MAX_CONCURRENT_STREAMS-many streams far faster than any real
 * response could ever be produced gets cut off almost immediately
 * rather than after doing meaningful damage. */
#define MAGNUS_H2_MAX_NEW_STREAMS_PER_SECOND 100
#define MAGNUS_H2_MAX_RESETS_PER_SECOND 50

/* h2c (roadmap 1e-5): cleartext HTTP/2, plain (non-TLS) listener only --
 * the existing TLS+ALPN h2 path (1e-1) is completely separate and
 * unaffected. Two entry points, both defined by RFC 9113 3.2/3.4:
 *   - "prior knowledge": the client just sends the connection preface as
 *     the very first bytes on a plain connection, with no HTTP/1.1
 *     exchange at all. MAGNUS_H2C_PREFACE is exactly what
 *     nghttp2_session_server_new() already expects and validates as the
 *     first bytes of any h2 session (the same 24 bytes a TLS+ALPN
 *     connection's first mem_recv2() call implicitly checks) -- prior
 *     knowledge only needs magnus to *notice* early enough not to hand
 *     these bytes to the HTTP/1.1 parser first, not to hand-parse the
 *     preface itself.
 *   - "Upgrade: h2c": an ordinary HTTP/1.1 request carries
 *     `Connection: Upgrade, HTTP2-Settings`, `Upgrade: h2c`, and an
 *     `HTTP2-Settings: <base64url>` header; if magnus accepts, it answers
 *     `101 Switching Protocols` and the *same* request is then treated
 *     as h2 stream 1 (nghttp2_session_upgrade2() exists specifically for
 *     this). Scoped to a request with no body for this increment -- see
 *     magnus_h2c_upgrade_eligible()'s own comment for why. */
#define MAGNUS_H2C_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define MAGNUS_H2C_PREFACE_LEN 24
/* Generous for any realistic HTTP2-Settings value (each SETTINGS
 * parameter is 6 bytes; this fits 32 of them) while bounding the
 * base64url decode below to a small, fixed-size stack buffer regardless
 * of how long a hostile client's header value actually is. */
#define MAGNUS_H2C_SETTINGS_MAX 192

/* Forward-declared so magnus_connection_t can hold a pointer to it;
 * fully defined alongside the rest of the HTTP/2 (1e-1) implementation,
 * near magnus_h2_session_create() below. */
struct magnus_h2_stream;

typedef struct {
    int fd;
    char *input;
    size_t input_capacity;
    size_t input_length;
    char output[MAGNUS_OUTPUT_LIMIT];
    size_t output_length;
    size_t output_sent;
    bool close_after_write;
    int file_fd;
    off_t file_offset;
    off_t file_length;
    SSL *tls;
    bool tls_ready;
    char *file_buffer;
    size_t file_buffer_length;
    size_t file_buffer_sent;
    int upstream_fd;
    bool proxy_active;
    bool proxy_connected;
    bool proxy_headers_sent;
    bool proxy_eof;
    /* Sized for the worst case a WebSocket handshake relay can produce
     * (forward_path up to 255 bytes, Sec-WebSocket-Protocol/-Extensions
     * up to 191 bytes each per magnus_http_header_t's own field size,
     * plus fixed overhead) -- 512 was enough for the plain-request format
     * alone but is not always enough once those headers are forwarded
     * verbatim. */
    char proxy_request[1280];
    size_t proxy_request_length;
    size_t proxy_request_sent;
    /* How much of `body` has been relayed to the upstream so far, once
     * the proxy request's headers have gone out. */
    size_t proxy_body_sent;
    /* Whether the *client's* original request wanted the connection kept
     * alive, captured before dispatch starts (close_after_write gets
     * overwritten the moment a proxy attempt begins, since the real
     * decision -- whether the upstream response is even unambiguously
     * framed -- isn't known until magnus_proxy_receive_headers() parses
     * it). */
    bool proxy_client_wants_close;
    /* Response-body framing/pool-eligibility, filled in by
     * magnus_proxy_receive_headers() from magnus_proxy_response_info_t.
     * has_response_length false means "relay until the upstream closes,
     * exactly like before this connection pool existed" -- the safe
     * fallback for any response this pool cannot reason precisely about
     * (no Content-Length, or Transfer-Encoding present). */
    bool proxy_upstream_poolable;
    bool proxy_has_response_length;
    unsigned long proxy_response_length;
    unsigned long proxy_response_received;
    /* Carried over from a pooled connection at checkout (0 for a freshly
     * connected one) so magnus_proxy_flush() can decide, once this
     * response completes, whether the connection has already done its
     * MAGNUS_POOL_MAX_REQUESTS_PER_CONNECTION share and should be closed
     * rather than pooled again. */
    unsigned proxy_upstream_requests_served;
    /* WebSocket (1d): proxy_ws_requested is set as soon as the client's
     * request is recognized as an upgrade attempt, before the upstream
     * has answered -- magnus_proxy_receive_headers() only actually
     * engages relay mode (proxy_ws_active) if the upstream comes back
     * with 101; any other status is just a normal (if unusual) proxied
     * response, handled exactly like one. Once proxy_ws_active, this
     * connection pair is a raw bidirectional byte pipe: ws_buffer carries
     * client->upstream bytes (mirroring proxy_buffer's existing
     * upstream->client role) -- see magnus_ws_pump_direction(). */
    bool proxy_ws_requested;
    bool proxy_ws_active;
    char *ws_buffer;
    size_t ws_buffer_length;
    size_t ws_buffer_sent;
    /* HTTP/2 (1e-1): set once ALPN negotiates "h2" in
     * magnus_tls_handshake(), right alongside tls_ready. From that point
     * this connection is driven exclusively by magnus_h2_service() (see
     * the main dispatch loop's early branch, mirroring proxy_ws_active's
     * own early branch for an upgraded WebSocket connection) -- static
     * file serving is the only thing 1e-1 dispatches to; a later
     * sub-phase adds proxy/route dispatch over h2. h2_streams is the
     * head of a small intrusive linked list of every stream still open
     * on this connection, kept only so magnus_close_connection() can
     * walk and free them: nghttp2_session_del() does not itself invoke
     * the stream-close callback for streams still open when the session
     * is torn down, and each stream may be holding an open static-file
     * fd. h2_output/_length/_sent hold whatever serialized bytes
     * nghttp2_session_mem_send2() has already produced but a partial,
     * would-block socket write could not get rid of yet -- unlike
     * proxy_buffer/ws_buffer's own relay buffers, nghttp2 only
     * guarantees a mem_send2() chunk's pointer stays valid until the
     * *next* mem_send2/mem_recv2 call, so any unsent remainder has to be
     * copied out here before this connection is allowed to ask nghttp2
     * for anything else. */
    bool h2_active;
    nghttp2_session *h2_session;
    struct magnus_h2_stream *h2_streams;
    char *h2_output;
    size_t h2_output_length;
    size_t h2_output_sent;
    /* Rapid-Reset-class abuse hardening (roadmap 1e-3): a lazily-reset
     * one-second sliding window (refreshed the moment either counter is
     * next touched, not swept separately) counting how many new request
     * streams this connection has opened, and how many RST_STREAM
     * frames the *client* has sent on it, within the current second.
     * Either exceeding its cap (magnus_h2_on_begin_headers()/
     * magnus_h2_on_frame_recv() -- see MAGNUS_H2_MAX_NEW_STREAMS_PER_SECOND/
     * MAGNUS_H2_MAX_RESETS_PER_SECOND) terminates the connection
     * immediately by returning NGHTTP2_ERR_CALLBACK_FAILURE from the
     * offending callback, exactly the mechanism nghttp2 itself already
     * uses internally for its own PING/SETTINGS-ack-flood and
     * CONTINUATION-flood protections (NGHTTP2_ERR_FLOODED /
     * NGHTTP2_ERR_TOO_MANY_CONTINUATIONS, both already fatal via the
     * existing `consumed < 0` check in magnus_h2_service() -- this is
     * the same treatment extended to a class of abuse nghttp2 has no
     * built-in cap for, since a rate genuinely legitimate for it is
     * application-specific.) */
    time_t h2_abuse_window_start;
    unsigned h2_streams_opened_this_second;
    unsigned h2_resets_received_this_second;
    /* h2c (1e-5): true the moment this plain (non-TLS) connection's
     * first bytes have been checked against MAGNUS_H2C_PREFACE (whether
     * that confirmed prior-knowledge h2c, ruled it out, or the check
     * failed outright) -- set exactly once per connection, at most, so
     * every read after the very first never re-runs it. Meaningless (and
     * never checked) for a TLS or admin-socket connection, both of which
     * skip the check entirely. */
    bool checked_h2c_preface;
    /* True once an Upgrade: h2c request's 101 response has been queued
     * into connection->output but not yet fully flushed -- consumed by
     * magnus_handle_write() the moment output finishes draining, which
     * is where this connection actually switches into h2 mode (see
     * magnus_h2c_activate()). Between magnus_h2c_begin_upgrade() setting
     * this and magnus_h2c_activate() clearing it, connection->pending_parsed
     * and h2c_settings/_length hold the state that transition needs --
     * reusing pending_parsed's existing field rather than a third
     * full-size magnus_http_request_t, safe because a connection is
     * never simultaneously reading_body (the other pending_parsed use)
     * and h2c_pending: an Upgrade: h2c request carrying a body is simply
     * not accepted for upgrade at all (see
     * magnus_h2c_upgrade_eligible()'s own comment on that scope
     * boundary). */
    bool h2c_pending;
    unsigned char h2c_settings[MAGNUS_H2C_SETTINGS_MAX];
    size_t h2c_settings_length;
    char *proxy_buffer;
    size_t proxy_buffer_length;
    size_t proxy_buffer_sent;
    bool proxy_headers_received;
    size_t proxy_header_accum;
    char *proxy_header_out;
    size_t proxy_header_out_length;
    size_t proxy_header_out_sent;
    bool proxy_response_started;
    char proxy_request_id[33];
    time_t proxy_connect_started;
    time_t proxy_last_activity;
    size_t proxy_endpoint_index;
    unsigned proxy_attempt;
    char proxy_affinity_key[64];
    bool proxy_issue_affinity_cookie;
    /* client-side method/target of the request currently being proxied,
     * captured at proxy start so the completion access-log line (written
     * later, asynchronously, once the upstream response arrives) can
     * still report what the client actually asked for. */
    char proxy_log_method[8];
    char proxy_log_target[256];
    struct in_addr client_address;
    /* set when this connection was accepted on the admin-only Unix
     * socket listener (see magnus_admin_listener): restricted to
     * /healthz and /metrics, and exempt from rate limiting since access
     * is already gated by that socket's filesystem permissions. */
    bool admin_only;
    uint64_t request_started_ms;
    /* Absolute deadline (from accept time) for finishing the *first*
     * request's headers, checked in magnus_expire_idle() independently of
     * MAGNUS_IDLE_SECONDS: the idle timer resets on every byte received,
     * so a slowloris-style client trickling one byte every few seconds
     * would never trip it and could hold a connection (and its input
     * buffer and fd) open indefinitely. No longer enforced once
     * request_started_ms shows a request has actually completed --
     * legitimate keep-alive idling between requests is fine and is what
     * MAGNUS_IDLE_SECONDS is for. */
    time_t header_deadline;
    time_t last_active;
    /* Request body (Content-Length only -- chunked is rejected by the
     * parser). NULL/0 whenever the request in flight has none, which is
     * also this struct's zero-initialized state from calloc() at accept
     * time, so nothing here needs an explicit reset on plain connect. Owned
     * by whichever of magnus_dispatch_request()'s callers still holds it:
     * freed right after a non-proxy dispatch, or once fully relayed to (or
     * abandoned by) the upstream -- see magnus_free_body_if_unowned(). */
    char *body;
    size_t body_capacity;
    size_t body_length;
    size_t body_needed;
    bool reading_body;
    /* The already-parsed request a body-bearing connection is waiting on
     * more bytes for; only meaningful while reading_body is true. */
    magnus_http_request_t pending_parsed;
} magnus_connection_t;

static volatile sig_atomic_t magnus_running = 1;
static magnus_phase_engine_t magnus_phases;
static magnus_connection_t *magnus_connections[MAGNUS_MAX_FDS];
static int magnus_root_fd = -1;
static SSL_CTX *magnus_tls_context;
static magnus_cluster_t magnus_cluster;
static bool magnus_upstream_enabled;
/* Evaluated in order, first match wins, ahead of the built-in
 * healthz/metrics/proxy-prefix/static dispatch -- see
 * magnus_dispatch_request(). Empty (route_count == 0, the default) means
 * every request falls straight through to that built-in dispatch exactly
 * as it did before routes existed. */
static magnus_route_t magnus_routes[MAGNUS_CONFIG_MAX_ROUTES];
static size_t magnus_route_count;
static magnus_connection_t *magnus_upstream_owner[MAGNUS_MAX_FDS];
/* Parallel to magnus_upstream_owner[] above, for an upstream fd opened on
 * behalf of one HTTP/2 stream's proxy dispatch (1e-2) rather than a whole
 * client connection: unlike HTTP/1.1, one h2 connection can have many
 * streams each proxying to a (possibly different) upstream concurrently,
 * so ownership cannot be keyed by connection alone. An fd is owned by at
 * most one of these two tables, never both. */
static struct magnus_h2_stream *magnus_h2_upstream_owner[MAGNUS_MAX_FDS];
/* Set once, right after epoll_create1() succeeds in main() -- this
 * process ever has exactly one epoll instance for its whole lifetime.
 * Read-only convenience for the handful of nghttp2 callback contexts
 * (invoked deep inside nghttp2_session_mem_recv2()/_mem_send2(), not by
 * magnus.c's own dispatch loop) that need to epoll_ctl a stream's
 * upstream fd but have no epoll_fd parameter of their own to work with --
 * every other function in this file still takes epoll_fd as a normal
 * parameter and should keep doing so. */
static int magnus_global_epoll_fd = -1;

/* Idle upstream connections kept open for reuse, per cluster endpoint.
 * Deliberately *not* registered with epoll while idle -- simpler and
 * safer than adding a whole second "this fd's event belongs to a pooled,
 * currently-unowned connection" branch to the main dispatch loop for a
 * case (the backend closing or sending unexpected bytes to an idle
 * connection) that is both rare and, worst case, just means a checkout
 * finds a dead connection a little later than it otherwise could have.
 * Liveness is instead checked cheaply (MSG_PEEK, non-blocking) at
 * checkout time, and MAGNUS_POOL_IDLE_TIMEOUT_SECONDS bounds how long a
 * connection nothing ever checks out again sits here regardless. */
typedef struct {
    int fd;
    time_t idle_since;
    unsigned requests_served;
} magnus_pool_slot_t;

typedef struct {
    magnus_pool_slot_t slots[MAGNUS_POOL_MAX_IDLE_PER_ENDPOINT];
    size_t count;
} magnus_pool_t;

static magnus_pool_t magnus_upstream_pool[MAGNUS_MAX_UPSTREAMS];

/* Returns a still-live, reusable fd for `endpoint_index` if the pool has
 * one, discarding any dead (peer-closed) or exhausted
 * (MAGNUS_POOL_MAX_REQUESTS_PER_CONNECTION already reached) connections it
 * finds along the way rather than handing them out. Checks the
 * most-recently-idled slot first (LIFO -- the warmest connection, most
 * likely to still be alive on a backend with its own idle timeout).
 * Returns -1 if none is available; the caller falls back to opening a
 * fresh connection exactly as it did before pooling existed. */
static int
magnus_pool_checkout(size_t endpoint_index, unsigned *out_requests_served)
{
    magnus_pool_t *pool;
    if (endpoint_index >= MAGNUS_MAX_UPSTREAMS) return -1;
    pool = &magnus_upstream_pool[endpoint_index];
    while (pool->count > 0) {
        magnus_pool_slot_t slot = pool->slots[pool->count - 1];
        char probe;
        ssize_t peeked;
        pool->count--;
        if (slot.requests_served >= MAGNUS_POOL_MAX_REQUESTS_PER_CONNECTION) {
            close(slot.fd);
            continue;
        }
        peeked = recv(slot.fd, &probe, 1, MSG_PEEK | MSG_DONTWAIT);
        if (peeked == 0
            || (peeked < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
            /* peer closed it, or it is otherwise unusable */
            close(slot.fd);
            continue;
        }
        if (peeked > 0) {
            /* Backend sent bytes with no request pending -- not something
             * a well-behaved HTTP/1.1 server does while idle. Whatever it
             * is, this connection's framing can no longer be trusted. */
            close(slot.fd);
            continue;
        }
        *out_requests_served = slot.requests_served;
        return slot.fd;
    }
    return -1;
}

/* Returns fd to the idle pool for `endpoint_index` if there is room and it
 * has not yet hit its request budget; otherwise just closes it. Ownership
 * of fd (its magnus_upstream_owner[] entry, its epoll registration -- none
 * held while idle, per the type comment above) is entirely the caller's
 * responsibility to have already cleared before calling this. */
static void
magnus_pool_checkin(size_t endpoint_index, int fd, unsigned requests_served)
{
    magnus_pool_t *pool;
    if (endpoint_index >= MAGNUS_MAX_UPSTREAMS) {
        close(fd);
        return;
    }
    pool = &magnus_upstream_pool[endpoint_index];
    if (pool->count == MAGNUS_POOL_MAX_IDLE_PER_ENDPOINT
        || requests_served >= MAGNUS_POOL_MAX_REQUESTS_PER_CONNECTION) {
        close(fd);
        return;
    }
    pool->slots[pool->count] = (magnus_pool_slot_t) {
        .fd = fd, .idle_since = time(NULL), .requests_served = requests_served
    };
    pool->count++;
}

/* Closes any pooled connection that has sat idle past
 * MAGNUS_POOL_IDLE_TIMEOUT_SECONDS. Called once per second from the same
 * sweep as magnus_expire_idle()/magnus_expire_proxies(). */
static void
magnus_pool_expire_idle(time_t now)
{
    for (size_t endpoint = 0; endpoint < MAGNUS_MAX_UPSTREAMS; endpoint++) {
        magnus_pool_t *pool = &magnus_upstream_pool[endpoint];
        size_t write_index = 0;
        for (size_t read_index = 0; read_index < pool->count; read_index++) {
            magnus_pool_slot_t slot = pool->slots[read_index];
            if (now - slot.idle_since > MAGNUS_POOL_IDLE_TIMEOUT_SECONDS) {
                close(slot.fd);
                continue;
            }
            pool->slots[write_index++] = slot;
        }
        pool->count = write_index;
    }
}

/* Closes every pooled idle connection on every endpoint. Called once at
 * shutdown -- these fds are not attached to any magnus_connection_t, so
 * nothing else closes them. */
static void
magnus_pool_close_all(void)
{
    for (size_t endpoint = 0; endpoint < MAGNUS_MAX_UPSTREAMS; endpoint++) {
        magnus_pool_t *pool = &magnus_upstream_pool[endpoint];
        for (size_t index = 0; index < pool->count; index++)
            close(pool->slots[index].fd);
        pool->count = 0;
    }
}

/* Hostname-upstream tracking (1c). Parallel to magnus_cluster.endpoints[]
 * by index -- magnus_dns_apply_result() overwrites an endpoint's address
 * in place on a successful resolution, so magnus_endpoint_sockaddr() and
 * everything downstream of it (connect, health checks, the connection
 * pool) needs no DNS-awareness of its own at all. The eventfd
 * magnus_dns_start() returns is registered with epoll once, at startup;
 * the worker thread itself is started once and outlives any number of
 * config reloads (only what it's asked to resolve changes). */
static int magnus_dns_eventfd = -1;
static bool magnus_dns_hostname_endpoint[MAGNUS_MAX_UPSTREAMS];
static char magnus_dns_endpoint_hostname[MAGNUS_MAX_UPSTREAMS][64];
static time_t magnus_dns_next_resolution[MAGNUS_MAX_UPSTREAMS];
static bool magnus_dns_resolution_pending[MAGNUS_MAX_UPSTREAMS];

/* Registers endpoint `index` as needing async resolution of `hostname`
 * and kicks off an immediate first attempt (if the resolver started
 * successfully -- if not, the endpoint's address stays whatever the
 * config/CLI flag literally said, which is not a valid IP for a hostname
 * entry, so it simply fails connect attempts cleanly via the existing
 * magnus_endpoint_sockaddr() -> inet_pton() failure path, same as any
 * other bad address would). */
static void
magnus_dns_track(size_t index, const char *hostname)
{
    if (index >= MAGNUS_MAX_UPSTREAMS
        || strlen(hostname) >= sizeof(magnus_dns_endpoint_hostname[0]))
        return;
    magnus_dns_hostname_endpoint[index] = true;
    strcpy(magnus_dns_endpoint_hostname[index], hostname);
    magnus_dns_next_resolution[index] = time(NULL) + MAGNUS_DNS_REFRESH_SECONDS;
    if (magnus_dns_eventfd < 0) return;
    magnus_dns_resolution_pending[index] = true;
    magnus_dns_resolve(hostname, index);
}

/* Rebuilds hostname tracking from scratch for a freshly applied config
 * (initial load or reload): every previous index's tracking is cleared
 * first since after a reload, position N in the new cluster is not
 * necessarily the same upstream it was before (same reasoning as the
 * connection pool's reload flush in magnus_apply_config()). */
static void
magnus_dns_apply_upstreams(const magnus_config_upstream_t *upstreams, size_t count)
{
    for (size_t i = 0; i < MAGNUS_MAX_UPSTREAMS; i++) {
        magnus_dns_hostname_endpoint[i] = false;
        magnus_dns_resolution_pending[i] = false;
    }
    for (size_t i = 0; i < count && i < MAGNUS_MAX_UPSTREAMS; i++) {
        if (upstreams[i].is_hostname) magnus_dns_track(i, upstreams[i].address);
    }
}

/* Called once per second from the main sweep: kicks off re-resolution for
 * any hostname endpoint whose refresh interval has elapsed and that does
 * not already have a resolution in flight. A resolution failure does not
 * touch next_resolution or the endpoint's current address here -- see
 * magnus_dns_apply_result() -- so a transient DNS hiccup just means this
 * retries again next interval, exactly as if nothing had gone wrong. */
static void
magnus_dns_tick(time_t now)
{
    for (size_t i = 0; i < MAGNUS_MAX_UPSTREAMS; i++) {
        if (!magnus_dns_hostname_endpoint[i] || magnus_dns_resolution_pending[i]
            || now < magnus_dns_next_resolution[i])
            continue;
        magnus_dns_resolution_pending[i] = true;
        magnus_dns_next_resolution[i] = now + MAGNUS_DNS_REFRESH_SECONDS;
        magnus_dns_resolve(magnus_dns_endpoint_hostname[i], i);
    }
}

/* magnus_dns_drain_results() callback: applies a completed resolution to
 * the live cluster. A stale result for an index the cluster has since
 * shrunk past (a reload removed upstream entries) or that is no longer
 * tracked as a hostname at all (an in-flight resolution from before a
 * reload, completing after magnus_dns_apply_upstreams() already reset
 * tracking for the new config) is simply ignored -- the token space is
 * only ever endpoint indices, so there is nothing else it could mean.
 *
 * On failure, the endpoint's current address is left exactly as it was:
 * a still-good address from a previous successful resolution should not
 * be thrown away over one failed refresh (this is the "keep last-known-
 * good" policy noted as a design decision in docs/development-roadmap.md's
 * 1c entry), and a first-ever resolution that fails simply leaves the
 * address as whatever it started as (the hostname itself, not a valid IP
 * literal -- see magnus_dns_track()'s comment), which already fails
 * connect attempts cleanly rather than needing special-case handling
 * here. */
static void
magnus_dns_apply_result(const magnus_dns_result_t *result, void *data)
{
    size_t index = result->token;
    (void) data;
    if (index >= MAGNUS_MAX_UPSTREAMS || index >= magnus_cluster.count
        || !magnus_dns_hostname_endpoint[index])
        return;
    magnus_dns_resolution_pending[index] = false;
    if (!result->ok) {
        fprintf(stderr, "magnus: dns: '%s' did not resolve, keeping last "
                        "known address\n", magnus_dns_endpoint_hostname[index]);
        return;
    }
    strcpy(magnus_cluster.endpoints[index].address, result->address);
}

/* Health-probe fds share the same epoll_fd as client/upstream connections.
 * Index i+1 (0 means "not a probe fd") names the cluster endpoint a given
 * fd is probing, so the main dispatch loop can route its events here
 * instead of treating it as client or proxied-upstream traffic. */
static int magnus_health_probe_owner[MAGNUS_MAX_FDS];
static int magnus_health_probe_fd[MAGNUS_MAX_UPSTREAMS];
static time_t magnus_health_probe_started[MAGNUS_MAX_UPSTREAMS];
static time_t magnus_health_last_probe[MAGNUS_MAX_UPSTREAMS];
static uint64_t magnus_connections_total;
static uint64_t magnus_connections_active;
static uint64_t magnus_requests_total;
static uint64_t magnus_responses_4xx;
static uint64_t magnus_responses_5xx;
static uint64_t magnus_bytes_sent;
static uint64_t magnus_rate_limited_total;

/* Access log: off/on, and 1-in-N sampling, both configurable (magnus_config
 * access_log / access_log_sample) so a busy deployment can turn the log
 * down instead of paying a syscall per request. Buffered in memory and
 * flushed with a single write() -- on the once-a-second sweep, when the
 * buffer is nearly full, and at shutdown -- rather than one fprintf() per
 * request; a full buffer at flush time is handled by flushing first and
 * retrying rather than silently growing without bound. */
#define MAGNUS_ACCESS_LOG_BUFFER 8192
static bool magnus_access_log_enabled = true;
static unsigned magnus_access_log_sample = 1;
static uint64_t magnus_access_log_seen;
static char magnus_access_log_buffer[MAGNUS_ACCESS_LOG_BUFFER];
static size_t magnus_access_log_length;

/* Request latency histogram (milliseconds, from "headers fully parsed" to
 * "response prepared" -- for a proxied request that means through to the
 * upstream's response headers arriving, not just the connect). Bucket
 * boundaries are intentionally coarse and few: this is a lightweight
 * gateway's own view of its tail, not a general-purpose metrics library. */
static const double magnus_latency_bucket_bounds_ms[] =
    { 1, 5, 10, 50, 100, 500, 1000, 5000 };
#define MAGNUS_LATENCY_BUCKETS \
    (sizeof(magnus_latency_bucket_bounds_ms) \
     / sizeof(magnus_latency_bucket_bounds_ms[0]))
static uint64_t magnus_latency_bucket_counts[MAGNUS_LATENCY_BUCKETS];
static uint64_t magnus_latency_count;
static double magnus_latency_sum_ms;

/* Admin-only Unix domain socket listener (magnus_config admin_socket /
 * --admin-socket): serves only /healthz and /metrics, exempt from rate
 * limiting, access controlled by the socket file's own permissions rather
 * than an in-process RBAC layer. When enabled, /metrics is withdrawn from
 * the regular (TCP) listener entirely -- /healthz stays there too, since
 * that is what a load balancer on the public port needs to reach. */
static int magnus_admin_listener = -1;
static bool magnus_admin_enabled;
static char magnus_admin_socket_path[MAGNUS_CONFIG_PATH_MAX];

/* Per-client-IP ingress rate limiting. Disabled unless --rate-limit is
 * given. A bounded linear-scan table keeps memory flat regardless of how
 * many distinct clients are ever seen; once full, the least-recently-seen
 * entry is evicted to make room for a new client -- acceptable for a
 * lightweight gateway's admission control, not a precise per-IP ledger. */
typedef struct {
    struct in_addr address;
    bool in_use;
    time_t last_seen;
    magnus_rate_limit_t limiter;
} magnus_rate_entry_t;

static bool magnus_rate_limit_enabled;
static double magnus_rate_limit_rps;
static double magnus_rate_limit_burst;
static magnus_rate_entry_t magnus_rate_table[MAGNUS_RATE_TABLE_SIZE];

/* --config <path> mode: magnus_config_path holds the file SIGHUP reload
 * re-reads. Without it (plain --port/--root/... flags), SIGHUP has
 * nothing to reload against and is a documented no-op. */
static bool magnus_config_mode;
static char magnus_config_path[MAGNUS_CONFIG_PATH_MAX];
static unsigned magnus_listen_port;
static volatile sig_atomic_t magnus_reload_requested;

static int magnus_update_interest(int epoll_fd,
                                  magnus_connection_t *connection,
                                  uint32_t events);
static ssize_t magnus_socket_write(magnus_connection_t *connection,
                                   const void *buffer, size_t length);
static ssize_t magnus_socket_read(magnus_connection_t *connection,
                                  void *buffer, size_t length);
static void magnus_prepare_response(magnus_connection_t *connection,
                                    unsigned status, const char *reason,
                                    const char *content_type, const char *body,
                                    bool head_only, bool close_connection,
                                    magnus_request_t *request);
static char *magnus_find_header_end(char *buffer, size_t length);
static int magnus_process_input(int epoll_fd, magnus_connection_t *connection);
static int magnus_ws_update_interest(int epoll_fd, magnus_connection_t *connection);
static int magnus_ws_service(int epoll_fd, magnus_connection_t *connection);
static int magnus_h2_session_create(magnus_connection_t *connection);
static int magnus_h2_service(int epoll_fd, magnus_connection_t *connection);
static void magnus_h2_close(magnus_connection_t *connection);
static void magnus_h2_proxy_start(magnus_connection_t *connection,
                                  struct magnus_h2_stream *stream,
                                  const char *forward_path);
static int magnus_h2_handle_upstream(struct magnus_h2_stream *stream,
                                     uint32_t flags);
static void magnus_h2_submit_text(magnus_connection_t *connection,
                                  struct magnus_h2_stream *stream,
                                  const char *status, const char *content_type,
                                  const char *body, bool head_only);
static void magnus_build_metrics(char *out, size_t out_capacity);
static uint64_t magnus_now_ms(void);
static int magnus_proxy_pick_and_start(int epoll_fd,
                                       magnus_connection_t *connection,
                                       const magnus_request_t *request,
                                       const magnus_http_request_t *parsed,
                                       const char *forward_path,
                                       const char *client_affinity_key,
                                       bool client_wants_close);

static void
magnus_signal_handler(int signal_number)
{
    (void) signal_number;
    magnus_running = 0;
}

static void
magnus_reload_signal_handler(int signal_number)
{
    (void) signal_number;
    magnus_reload_requested = 1;
}

/* Fills `out[32]` (plus a NUL terminator, so `out` must be at least 33
 * bytes) with a random 128-bit value hex-encoded. Used both for the
 * per-request trace id and for freshly minted cluster affinity tokens. */
static void
magnus_generate_token(char *out)
{
    unsigned char random_bytes[16];
    static const char hex[] = "0123456789abcdef";
    static uint64_t fallback_counter;
    size_t index;

    if (getrandom(random_bytes, sizeof(random_bytes), GRND_NONBLOCK)
        != (ssize_t) sizeof(random_bytes)) {
        struct timespec now;
        uint64_t seed;
        clock_gettime(CLOCK_MONOTONIC, &now);
        seed = (uint64_t) now.tv_nsec ^ (uint64_t) now.tv_sec
               ^ (uint64_t) getpid() ^ ++fallback_counter;
        for (index = 0; index < sizeof(random_bytes); index++) {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            random_bytes[index] = (unsigned char) seed;
        }
    }
    for (index = 0; index < sizeof(random_bytes); index++) {
        out[index * 2] = hex[random_bytes[index] >> 4];
        out[index * 2 + 1] = hex[random_bytes[index] & 0x0f];
    }
    out[32] = '\0';
}

static int
magnus_trace_handler(magnus_request_t *request, void *data)
{
    (void) data;
    magnus_generate_token(request->request_id);
    return 0;
}

static void
magnus_close_connection(int epoll_fd, magnus_connection_t *connection)
{
    int fd = connection->fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    close(fd);
    if (connection->file_fd >= 0) close(connection->file_fd);
    if (connection->tls != NULL) SSL_free(connection->tls);
    free(connection->input);
    free(connection->file_buffer);
    free(connection->proxy_buffer);
    free(connection->proxy_header_out);
    free(connection->ws_buffer);
    magnus_h2_close(connection);
    /* Safety net: normally already freed by magnus_free_body_if_unowned()
     * or once fully relayed in magnus_handle_upstream(), but a connection
     * can close mid-body (client abort, retry budget exhausted before any
     * send) with it still attached. */
    free(connection->body);
    if (magnus_connections_active > 0) magnus_connections_active--;
    if (connection->upstream_fd >= 0) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, connection->upstream_fd, NULL);
        magnus_upstream_owner[connection->upstream_fd] = NULL;
        close(connection->upstream_fd);
    }
    magnus_connections[fd] = NULL;
    free(connection);
}

static uint64_t
magnus_now_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t) now.tv_sec * 1000 + (uint64_t) now.tv_nsec / 1000000;
}

static void
magnus_access_log_flush(void)
{
    if (magnus_access_log_length == 0) return;
    /* Best-effort: a partial or failed write() here would otherwise mean
     * looping or blocking in the middle of the event loop over a log
     * sink under pressure, which the event loop must never do. Dropping
     * log bytes beats stalling every connection to protect them. */
    ssize_t ignored = write(STDERR_FILENO, magnus_access_log_buffer,
                            magnus_access_log_length);
    (void) ignored;
    magnus_access_log_length = 0;
}

static void
magnus_access_log(const char *request_id, const char *method,
                  const char *target, unsigned status, double latency_ms)
{
    int written;
    if (!magnus_access_log_enabled) return;
    magnus_access_log_seen++;
    if (magnus_access_log_sample > 1
        && (magnus_access_log_seen % magnus_access_log_sample) != 0) return;
    written = snprintf(magnus_access_log_buffer + magnus_access_log_length,
        sizeof(magnus_access_log_buffer) - magnus_access_log_length,
        "access request_id=%s method=%s target=%s status=%u "
        "latency_ms=%.2f\n", request_id, method, target, status, latency_ms);
    if (written < 0) return;
    if ((size_t) written >= sizeof(magnus_access_log_buffer)
                            - magnus_access_log_length) {
        magnus_access_log_flush();
        written = snprintf(magnus_access_log_buffer,
            sizeof(magnus_access_log_buffer),
            "access request_id=%s method=%s target=%s status=%u "
            "latency_ms=%.2f\n", request_id, method, target, status,
            latency_ms);
        if (written > 0 && (size_t) written < sizeof(magnus_access_log_buffer))
            magnus_access_log_length = (size_t) written;
        return;
    }
    magnus_access_log_length += (size_t) written;
}

static void
magnus_record_latency(double latency_ms)
{
    size_t index;
    magnus_latency_count++;
    magnus_latency_sum_ms += latency_ms;
    for (index = 0; index < MAGNUS_LATENCY_BUCKETS; index++) {
        if (latency_ms <= magnus_latency_bucket_bounds_ms[index])
            magnus_latency_bucket_counts[index]++;
    }
}

/* Admits or rejects one request from `address` against the shared
 * per-client-IP token bucket table. Always returns true when rate
 * limiting is disabled. Finds (or creates, evicting the oldest entry if
 * the bounded table is full) that client's bucket and consumes a token. */
static bool
magnus_rate_check(struct in_addr address, time_t now)
{
    uint64_t now_ms = (uint64_t) now * 1000;
    size_t free_slot = MAGNUS_RATE_TABLE_SIZE;
    size_t oldest_slot = 0;
    time_t oldest_seen = 0;
    size_t index;

    if (!magnus_rate_limit_enabled) return true;

    for (index = 0; index < MAGNUS_RATE_TABLE_SIZE; index++) {
        magnus_rate_entry_t *entry = &magnus_rate_table[index];
        if (entry->in_use && entry->address.s_addr == address.s_addr) {
            entry->last_seen = now;
            return magnus_rate_allow(&entry->limiter, now_ms);
        }
        if (!entry->in_use && free_slot == MAGNUS_RATE_TABLE_SIZE) {
            free_slot = index;
        }
        if (index == 0 || entry->last_seen < oldest_seen) {
            oldest_seen = entry->last_seen;
            oldest_slot = index;
        }
    }

    index = free_slot != MAGNUS_RATE_TABLE_SIZE ? free_slot : oldest_slot;
    magnus_rate_table[index].address = address;
    magnus_rate_table[index].in_use = true;
    magnus_rate_table[index].last_seen = now;
    magnus_rate_init(&magnus_rate_table[index].limiter, magnus_rate_limit_rps,
                     magnus_rate_limit_burst, now_ms);
    return magnus_rate_allow(&magnus_rate_table[index].limiter, now_ms);
}

static bool
magnus_endpoint_sockaddr(size_t index, struct sockaddr_in *out)
{
    if (index >= magnus_cluster.count) return false;
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t) magnus_cluster.endpoints[index].port);
    return inet_pton(AF_INET, magnus_cluster.endpoints[index].address,
                     &out->sin_addr) == 1;
}

/* Opens a non-blocking connect() to cluster endpoint `endpoint_index`,
 * reusing connection->proxy_request (already built by the caller) and
 * (re)allocating connection->proxy_buffer if needed, and registers the
 * socket with epoll. Resets every per-attempt proxy_* field, so this is
 * safe to call again for a retry once the previous attempt's upstream has
 * been torn down via magnus_proxy_teardown_upstream(). Returns 0 once the
 * attempt is in flight, -1 on immediate failure (the caller records the
 * failure and decides whether to retry or give up). */
/* Common state setup once a socket (freshly connected or handed out of
 * magnus_upstream_pool) is ready to be this connection's active upstream:
 * resets every per-attempt proxy_* field and registers it with epoll.
 * `connected` is true immediately for a pooled fd (already established by
 * definition) or for a fresh connect() that happened to complete
 * synchronously; otherwise EPOLLOUT will report completion later.
 * Returns 0 once the attempt is in flight, -1 on immediate failure (fd is
 * already closed by the time this returns -1). */
static int
magnus_proxy_attach_upstream(int epoll_fd, magnus_connection_t *connection,
                             size_t endpoint_index, int fd, bool connected,
                             unsigned requests_served)
{
    struct epoll_event event;

    if (connection->proxy_buffer == NULL) {
        connection->proxy_buffer = malloc(MAGNUS_PROXY_BUFFER);
        if (connection->proxy_buffer == NULL) {
            close(fd);
            return -1;
        }
    }
    connection->upstream_fd = fd;
    connection->proxy_active = true;
    connection->proxy_connected = connected;
    connection->proxy_request_sent = 0;
    connection->proxy_body_sent = 0;
    connection->proxy_headers_sent = false;
    connection->proxy_headers_received = false;
    connection->proxy_header_accum = 0;
    connection->proxy_eof = false;
    connection->proxy_response_started = false;
    connection->proxy_upstream_poolable = false;
    connection->proxy_has_response_length = false;
    connection->proxy_response_length = 0;
    connection->proxy_response_received = 0;
    connection->proxy_ws_active = false;
    connection->proxy_upstream_requests_served = requests_served;
    connection->proxy_endpoint_index = endpoint_index;
    connection->proxy_connect_started = time(NULL);
    connection->proxy_last_activity = connection->proxy_connect_started;
    /* Provisional; magnus_proxy_receive_headers() corrects this once the
     * response's actual framing (and the client's own original
     * preference, in proxy_client_wants_close) is known. */
    connection->close_after_write = true;
    magnus_upstream_owner[fd] = connection;
    event = (struct epoll_event) { .events = EPOLLOUT | EPOLLRDHUP,
                                   .data.fd = fd };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        magnus_upstream_owner[fd] = NULL;
        close(fd);
        connection->upstream_fd = -1;
        connection->proxy_active = false;
        return -1;
    }
    return 0;
}

/* A pooled idle connection for this endpoint is tried first -- skipping
 * the TCP handshake (and, for a TLS upstream in a future phase, its
 * handshake too) entirely -- before falling back to opening a fresh one,
 * exactly as before this pool existed. Every caller of this function
 * (including retries against a different endpoint after a connect
 * failure) benefits automatically; none of them needed to change. */
static int
magnus_proxy_connect_endpoint(int epoll_fd, magnus_connection_t *connection,
                              size_t endpoint_index)
{
    struct sockaddr_in address;
    int result;
    int fd;
    unsigned pooled_requests_served;
    int pooled_fd = magnus_pool_checkout(endpoint_index, &pooled_requests_served);

    if (pooled_fd >= 0) {
        if (magnus_proxy_attach_upstream(epoll_fd, connection, endpoint_index,
                                         pooled_fd, true,
                                         pooled_requests_served) == 0)
            return 0;
        /* attach itself failed (buffer allocation, or epoll_ctl) -- the fd
         * is already closed; fall through to a fresh connection rather
         * than giving up the whole attempt over what the pool offered. */
    }

    if (!magnus_endpoint_sockaddr(endpoint_index, &address)) return -1;
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0 || fd >= MAGNUS_MAX_FDS) {
        if (fd >= 0) close(fd);
        return -1;
    }
    result = connect(fd, (struct sockaddr *) &address, sizeof(address));
    if (result < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return magnus_proxy_attach_upstream(epoll_fd, connection, endpoint_index,
                                        fd, result == 0, 0);
}

/* The MAGNUS_AFFINITY cookie value this gateway issues encodes the target
 * cluster endpoint directly as a 2-hex-digit prefix (e.g. "05-<random>"),
 * so a returning client's sticky endpoint can be recovered by a plain
 * integer parse instead of re-deriving it by hashing -- precise, and
 * independent of magnus_cluster_select()'s unrelated hash-based affinity
 * mode (kept for other potential callers). Returns false if `cookie` is
 * NULL/empty or not in this format. */
static bool
magnus_decode_affinity_cookie(const char *cookie, size_t *out_index)
{
    char *end;
    unsigned long value;
    if (cookie == NULL || cookie[0] == '\0') return false;
    errno = 0;
    value = strtoul(cookie, &end, 16);
    if (errno != 0 || end == cookie || *end != '-') return false;
    *out_index = (size_t) value;
    return true;
}

static void
magnus_encode_affinity_cookie(char *out, size_t out_capacity,
                              size_t endpoint_index)
{
    char token[33];
    magnus_generate_token(token);
    snprintf(out, out_capacity, "%02zx-%s", endpoint_index, token);
}

/* Builds the outbound proxy request once, then selects a healthy cluster
 * endpoint and connects to it, retrying against a different endpoint -- up
 * to MAGNUS_PROXY_MAX_ATTEMPTS total attempts -- if the connect itself
 * fails immediately. Returns 0 if an attempt is now in flight (client
 * interest already updated to watch for abort), -1 if no healthy endpoint
 * was available or the retry budget was exhausted.
 *
 * `forward_path` is what actually goes out on the wire as the upstream
 * request's target: request->path with the literal "/proxy" prefix
 * stripped for a request that reached here via that hardcoded prefix, or
 * request->path unchanged for one that reached here via a matched
 * action=proxy route instead (see magnus_dispatch_request()) -- a route
 * is not anchored to any particular prefix, so there is nothing route
 * matching implies should be stripped before relaying.
 *
 * Selection uses session affinity: if the client's request carried a valid
 * MAGNUS_AFFINITY cookie, its encoded endpoint is preferred for this first
 * attempt only (magnus_cluster_select_sticky() itself already falls back
 * to round-robin if that endpoint is unavailable); a client with no cookie
 * gets a plain round-robin pick, exactly as if affinity did not exist.
 * Either way, any retry after a failed attempt always falls back to plain
 * round-robin rather than insisting on the same (just-failed) endpoint
 * again -- a single connect failure does not yet flip passive health
 * unhealthy, so re-trying "sticky" here would silently double the wait
 * instead of actually finding a working endpoint. A fresh cookie is minted
 * (for magnus_proxy_receive_headers() to issue via Set-Cookie once headers
 * arrive) whenever the client did not already carry a usable one. */
static int
magnus_proxy_pick_and_start(int epoll_fd, magnus_connection_t *connection,
                            const magnus_request_t *request,
                            const magnus_http_request_t *parsed,
                            const char *forward_path,
                            const char *client_affinity_cookie,
                            bool client_wants_close)
{
    int written;
    size_t preferred_index;
    bool sticky;
    bool is_websocket;

    /* RFC 6455 6.1: a client upgrade request needs all of Upgrade:
     * websocket, a Connection token containing "upgrade" (a
     * comma-separated list, not necessarily exactly that value -- e.g.
     * "keep-alive, Upgrade" is common), and a non-empty Sec-WebSocket-Key.
     * GET is not re-checked here since is_proxy_route's caller
     * (magnus_dispatch_request()) already only reaches this function for
     * GET/HEAD or an is_proxy_route request, and a WebSocket handshake is
     * always a GET in practice; nothing downstream depends on rejecting a
     * technically-off-spec non-GET upgrade attempt more strictly than
     * that. */
    {
        const char *upgrade = magnus_http_header_find(parsed, "upgrade");
        const char *conn = magnus_http_header_find(parsed, "connection");
        const char *key = magnus_http_header_find(parsed, "sec-websocket-key");
        is_websocket = upgrade != NULL && strcasecmp(upgrade, "websocket") == 0
            && conn != NULL && strcasestr(conn, "upgrade") != NULL
            && key != NULL && key[0] != '\0';
    }
    connection->proxy_ws_requested = is_websocket;

    if (is_websocket) {
        const char *version = magnus_http_header_find(parsed, "sec-websocket-version");
        const char *protocol = magnus_http_header_find(parsed, "sec-websocket-protocol");
        const char *extensions = magnus_http_header_find(parsed, "sec-websocket-extensions");
        const char *key = magnus_http_header_find(parsed, "sec-websocket-key");
        char protocol_line[256] = "";
        char extensions_line[256] = "";
        /* Forwarded transparently, not interpreted: this proxy relays the
         * upgraded connection as a raw byte pipe (see
         * magnus_ws_pump_direction()), so it has no need to understand
         * -- or role in negotiating -- a subprotocol or an extension like
         * permessage-deflate. Whatever the client offered, the upstream
         * decides. */
        if (protocol != NULL)
            snprintf(protocol_line, sizeof(protocol_line),
                    "Sec-WebSocket-Protocol: %s\r\n", protocol);
        if (extensions != NULL)
            snprintf(extensions_line, sizeof(extensions_line),
                    "Sec-WebSocket-Extensions: %s\r\n", extensions);
        written = snprintf(connection->proxy_request,
                           sizeof(connection->proxy_request),
                           "%s %s HTTP/1.1\r\nHost: magnus-upstream\r\n"
                           "Connection: Upgrade\r\nUpgrade: websocket\r\n"
                           "Sec-WebSocket-Key: %s\r\n"
                           "Sec-WebSocket-Version: %s\r\n"
                           "%s%sX-Magnus-Request-Id: %s\r\n\r\n",
                           request->method, forward_path, key,
                           version != NULL ? version : "13",
                           protocol_line, extensions_line,
                           request->request_id);
        if (written < 0 || (size_t) written >= sizeof(connection->proxy_request))
            return -1;
        connection->proxy_request_length = (size_t) written;
        connection->proxy_client_wants_close = false; /* N/A once upgraded */
        memcpy(connection->proxy_request_id, request->request_id,
              sizeof(connection->proxy_request_id));
        connection->proxy_attempt = 0;
        connection->proxy_issue_affinity_cookie = false;
        for (;;) {
            int endpoint = magnus_cluster_select(&magnus_cluster, magnus_now_ms(),
                                                 NULL);
            if (endpoint < 0) return -1;
            connection->proxy_attempt++;
            if (magnus_proxy_connect_endpoint(epoll_fd, connection,
                                              (size_t) endpoint) == 0)
                return magnus_update_interest(epoll_fd, connection, EPOLLRDHUP);
            magnus_cluster_result(&magnus_cluster, (size_t) endpoint, false,
                                  magnus_now_ms());
            if (connection->proxy_attempt >= MAGNUS_PROXY_MAX_ATTEMPTS) return -1;
        }
    }

    /* connection->body/body_length carry whatever request body was
     * buffered before dispatch reached here (empty for GET/HEAD and any
     * other request that had none). Relaying it is magnus_handle_upstream's
     * job, once these headers have gone out.
     *
     * Always *offers* the upstream keep-alive (regardless of what the
     * client itself wanted) -- whether the connection actually gets
     * reused afterward depends on whether the response turns out to have
     * an unambiguous length (see magnus_proxy_receive_headers()), not on
     * this request. Worst case the upstream ignores it and closes anyway,
     * exactly like before this pool existed: MAGNUS_PROXY_READ_TIMEOUT_SECONDS
     * still bounds how long a response with neither Content-Length nor a
     * closed connection can stay unresolved. */
    written = connection->body_length > 0
        ? snprintf(connection->proxy_request, sizeof(connection->proxy_request),
                   "%s %s HTTP/1.0\r\nHost: magnus-upstream\r\n"
                   "Connection: keep-alive\r\nContent-Length: %zu\r\n"
                   "X-Magnus-Request-Id: %s\r\n\r\n",
                   request->method, forward_path,
                   connection->body_length, request->request_id)
        : snprintf(connection->proxy_request, sizeof(connection->proxy_request),
                   "%s %s HTTP/1.0\r\nHost: magnus-upstream\r\n"
                   "Connection: keep-alive\r\nX-Magnus-Request-Id: %s\r\n\r\n",
                   request->method, forward_path, request->request_id);
    if (written < 0 || (size_t) written >= sizeof(connection->proxy_request))
        return -1;
    connection->proxy_request_length = (size_t) written;
    connection->proxy_client_wants_close = client_wants_close;
    memcpy(connection->proxy_request_id, request->request_id,
          sizeof(connection->proxy_request_id));
    connection->proxy_attempt = 0;
    sticky = magnus_decode_affinity_cookie(client_affinity_cookie,
                                           &preferred_index);
    connection->proxy_issue_affinity_cookie = !sticky;

    for (;;) {
        int endpoint = sticky
            ? magnus_cluster_select_sticky(&magnus_cluster, magnus_now_ms(),
                                           preferred_index)
            : magnus_cluster_select(&magnus_cluster, magnus_now_ms(), NULL);
        if (endpoint < 0) return -1;
        if (sticky) {
            sticky = false;
        } else if (connection->proxy_attempt > 0) {
            /* deviating from the client's original sticky target (or from
             * plain round-robin) because a previous attempt failed: the
             * cookie must be refreshed to reflect the endpoint actually
             * used, not what a retried/failed attempt implied. */
            connection->proxy_issue_affinity_cookie = true;
        }
        connection->proxy_attempt++;
        if (magnus_proxy_connect_endpoint(epoll_fd, connection,
                                          (size_t) endpoint) == 0) {
            if (connection->proxy_issue_affinity_cookie) {
                magnus_encode_affinity_cookie(connection->proxy_affinity_key,
                                              sizeof(connection->proxy_affinity_key),
                                              (size_t) endpoint);
            }
            return magnus_update_interest(epoll_fd, connection, EPOLLRDHUP);
        }
        magnus_cluster_result(&magnus_cluster, (size_t) endpoint, false,
                              magnus_now_ms());
        if (connection->proxy_attempt >= MAGNUS_PROXY_MAX_ATTEMPTS) return -1;
    }
}

static void
magnus_proxy_teardown_upstream(int epoll_fd, magnus_connection_t *connection)
{
    if (connection->upstream_fd >= 0) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, connection->upstream_fd, NULL);
        magnus_upstream_owner[connection->upstream_fd] = NULL;
        close(connection->upstream_fd);
        connection->upstream_fd = -1;
    }
    connection->proxy_active = false;
    free(connection->proxy_buffer);
    connection->proxy_buffer = NULL;
    free(connection->proxy_header_out);
    connection->proxy_header_out = NULL;
}

/* Ends an in-flight proxy attempt before any response bytes have reached
 * the client: tears the upstream connection down and switches the client
 * connection to a synthesized error response. Must only be called while
 * connection->proxy_response_started is still false -- once the status
 * line has been forwarded downstream a clean status-coded error is no
 * longer possible and magnus_proxy_abort() must be used instead. */
static int
magnus_proxy_fail(int epoll_fd, magnus_connection_t *connection,
                  unsigned status, const char *reason)
{
    magnus_request_t request = {0};
    magnus_proxy_teardown_upstream(epoll_fd, connection);
    memcpy(request.request_id, connection->proxy_request_id,
          sizeof(request.request_id));
    magnus_prepare_response(connection, status, reason, "text/plain",
                            status == 504 ? "gateway timeout\n"
                                          : "bad gateway\n",
                            false, true, &request);
    {
        double latency_ms = (double) (magnus_now_ms()
                                      - connection->request_started_ms);
        magnus_record_latency(latency_ms);
        magnus_access_log(request.request_id, connection->proxy_log_method,
                          connection->proxy_log_target, status, latency_ms);
    }
    return magnus_update_interest(epoll_fd, connection, EPOLLOUT | EPOLLRDHUP);
}

/* Ends an in-flight proxy attempt after response bytes were already
 * forwarded to the client, so the connection can only be aborted (client
 * abort / truncated response), not answered with a fresh status code. */
static int
magnus_proxy_abort(int epoll_fd, magnus_connection_t *connection)
{
    magnus_proxy_teardown_upstream(epoll_fd, connection);
    return -1;
}

/* Records a connect-stage failure for the endpoint currently in flight and
 * either retries against a different healthy endpoint -- bounded by
 * MAGNUS_PROXY_MAX_ATTEMPTS total attempts -- or gives up with a clean
 * status-coded error. Must only be called while
 * connection->proxy_response_started is still false: a connect-stage
 * failure by definition means no response bytes have reached the client
 * yet, so retrying (or eventually failing cleanly) is always safe here. */
static int
magnus_proxy_connect_failed(int epoll_fd, magnus_connection_t *connection,
                            unsigned give_up_status,
                            const char *give_up_reason)
{
    magnus_cluster_result(&magnus_cluster, connection->proxy_endpoint_index,
                          false, magnus_now_ms());
    magnus_proxy_teardown_upstream(epoll_fd, connection);
    if (connection->proxy_attempt < MAGNUS_PROXY_MAX_ATTEMPTS) {
        /* never sticky here: this is already a retry after a failure, so
         * insisting on the original (just-failed) preferred endpoint again
         * would only waste the remaining attempt budget on it. */
        int endpoint = magnus_cluster_select(&magnus_cluster, magnus_now_ms(),
                                             NULL);
        if (endpoint >= 0) {
            connection->proxy_attempt++;
            if (magnus_proxy_connect_endpoint(epoll_fd, connection,
                                              (size_t) endpoint) == 0) {
                /* deviated from whatever selection strategy produced the
                 * failed attempt: refresh the cookie to match reality. */
                connection->proxy_issue_affinity_cookie = true;
                magnus_encode_affinity_cookie(connection->proxy_affinity_key,
                                              sizeof(connection->proxy_affinity_key),
                                              (size_t) endpoint);
                return magnus_update_interest(epoll_fd, connection,
                                              EPOLLRDHUP);
            }
            magnus_cluster_result(&magnus_cluster, (size_t) endpoint, false,
                                  magnus_now_ms());
        }
    }
    return magnus_proxy_fail(epoll_fd, connection, give_up_status,
                             give_up_reason);
}

static int
magnus_proxy_flush(int epoll_fd, magnus_connection_t *connection)
{
    while (connection->proxy_header_out != NULL
           && connection->proxy_header_out_sent
              < connection->proxy_header_out_length) {
        ssize_t sent = magnus_socket_write(connection,
            connection->proxy_header_out + connection->proxy_header_out_sent,
            connection->proxy_header_out_length
                - connection->proxy_header_out_sent);
        if (sent > 0) {
            connection->proxy_header_out_sent += (size_t) sent;
            connection->last_active = time(NULL);
            connection->proxy_last_activity = connection->last_active;
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return magnus_update_interest(epoll_fd, connection,
                                          EPOLLOUT | EPOLLRDHUP);
        return magnus_proxy_abort(epoll_fd, connection);
    }
    if (connection->proxy_header_out != NULL) {
        free(connection->proxy_header_out);
        connection->proxy_header_out = NULL;
        connection->proxy_response_started = true;
    }
    while (connection->proxy_buffer_sent < connection->proxy_buffer_length) {
        ssize_t sent = magnus_socket_write(connection,
            connection->proxy_buffer + connection->proxy_buffer_sent,
            connection->proxy_buffer_length - connection->proxy_buffer_sent);
        if (sent > 0) {
            connection->proxy_buffer_sent += (size_t) sent;
            connection->last_active = time(NULL);
            connection->proxy_last_activity = connection->last_active;
            connection->proxy_response_started = true;
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return magnus_update_interest(epoll_fd, connection,
                                          EPOLLOUT | EPOLLRDHUP);
        return magnus_proxy_abort(epoll_fd, connection);
    }
    connection->proxy_buffer_length = 0;
    connection->proxy_buffer_sent = 0;

    /* The 101 response (and any WebSocket frame bytes that arrived
     * attached to the same read as its headers) has now been fully
     * relayed to the client -- hand off to the raw bidirectional pump
     * instead of any of the ordinary "is this proxied response complete"
     * reasoning below, none of which applies once upgraded. Both
     * buffers are empty at this point (the drain loops above only ever
     * reach here once they have fully sent whatever they held), so
     * magnus_ws_update_interest() will correctly arm both fds for
     * reading. */
    if (connection->proxy_ws_active)
        return magnus_ws_update_interest(epoll_fd, connection);

    {
        bool complete_by_length = connection->proxy_has_response_length
            && connection->proxy_response_received
               >= connection->proxy_response_length;
        if (!connection->proxy_eof && !complete_by_length) {
            /* Still mid-body; keep watching the upstream for more. */
            if (connection->upstream_fd >= 0) {
                struct epoll_event event = { .events = EPOLLIN | EPOLLRDHUP,
                                             .data.fd = connection->upstream_fd };
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, connection->upstream_fd,
                         &event);
            }
            return magnus_update_interest(epoll_fd, connection, EPOLLRDHUP);
        }

        /* Response complete. The upstream leg either goes back into the
         * pool (cleanly length-framed, and not asked to close -- see
         * magnus_proxy_receive_headers()) or gets torn down exactly as
         * before this pool existed; independently, the client leg either
         * stays open for its next request or closes, per whatever
         * close_after_write was already set to there. */
        if (complete_by_length && connection->proxy_upstream_poolable
            && connection->upstream_fd >= 0) {
            int fd = connection->upstream_fd;
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
            magnus_upstream_owner[fd] = NULL;
            connection->upstream_fd = -1;
            magnus_pool_checkin(connection->proxy_endpoint_index, fd,
                connection->proxy_upstream_requests_served + 1);
        } else {
            magnus_proxy_teardown_upstream(epoll_fd, connection);
        }
        connection->proxy_active = false;

        if (connection->close_after_write) return -1;
        if (connection->input_length > 0
            && magnus_find_header_end(connection->input,
                                      connection->input_length) != NULL) {
            return magnus_process_input(epoll_fd, connection);
        }
        return magnus_update_interest(epoll_fd, connection,
                                      EPOLLIN | EPOLLRDHUP);
    }
}

/* Accumulates the upstream response's status line + header block (which
 * may arrive split across several recv() calls) into connection->proxy_buffer,
 * then rewrites it via magnus_proxy_sanitize_response_headers() once the
 * terminating blank line is found. Leftover bytes already read past the
 * header block are preserved as the first chunk of body. Returns 1 while
 * still waiting for more header bytes, 0 once handed off to
 * magnus_proxy_flush(), or a magnus_proxy_fail()/-1 result on error. */
static int
magnus_proxy_receive_headers(int epoll_fd, magnus_connection_t *connection)
{
    char *body_start;
    size_t header_length;
    size_t leftover;
    char header_copy[MAGNUS_PROXY_HEADER_LIMIT + 1];
    char sanitize_scratch[MAGNUS_PROXY_HEADER_LIMIT + 1];
    char sanitized[MAGNUS_PROXY_SANITIZED_LIMIT];
    magnus_proxy_response_info_t info;
    int sanitized_length;

    while (connection->proxy_header_accum < MAGNUS_PROXY_BUFFER) {
        ssize_t received = recv(connection->upstream_fd,
            connection->proxy_buffer + connection->proxy_header_accum,
            MAGNUS_PROXY_BUFFER - connection->proxy_header_accum, 0);
        if (received > 0) {
            connection->proxy_header_accum += (size_t) received;
            connection->last_active = time(NULL);
            connection->proxy_last_activity = connection->last_active;
            /* Stop as soon as the header block is complete instead of
             * greedily draining the socket: for a fast/bursty upstream
             * (the whole response already sitting in the kernel receive
             * buffer) that avoids reading all the way up to
             * MAGNUS_PROXY_BUFFER, which would otherwise make the next
             * recv() request zero bytes -- and recv() with length 0
             * legitimately returns 0, indistinguishable here from a real
             * peer close, which would misreport upstream EOF and truncate
             * the response. Any body bytes left unread simply stay in the
             * kernel buffer for the normal body-relay path to pick up. */
            if (magnus_find_header_end(connection->proxy_buffer,
                                       connection->proxy_header_accum) != NULL) {
                break;
            }
            continue;
        }
        if (received == 0) {
            connection->proxy_eof = true;
            break;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                           "Bad Gateway");
    }

    body_start = magnus_find_header_end(connection->proxy_buffer,
                                        connection->proxy_header_accum);
    if (body_start == NULL) {
        if (connection->proxy_eof)
            return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                           "Bad Gateway");
        if (connection->proxy_header_accum == MAGNUS_PROXY_BUFFER)
            return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                           "Bad Gateway");
        return 1;
    }

    header_length = (size_t) (body_start - connection->proxy_buffer);
    leftover = connection->proxy_header_accum - header_length;
    if (header_length > MAGNUS_PROXY_HEADER_LIMIT)
        return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                           "Bad Gateway");
    memcpy(header_copy, connection->proxy_buffer, header_length);
    header_copy[header_length] = '\0';
    /* magnus_proxy_sanitize_response_headers() tokenizes its `raw` buffer
     * in place (replacing the \r/\n delimiters it splits on with NUL as
     * part of strtok_r) -- it needs its own scratch copy so header_copy
     * itself stays byte-for-byte intact for the WebSocket 101 case below,
     * which relays it verbatim rather than using sanitize's output at
     * all. */
    memcpy(sanitize_scratch, header_copy, header_length + 1);
    sanitized_length = magnus_proxy_sanitize_response_headers(sanitize_scratch,
        header_length, sanitized, sizeof(sanitized),
        connection->proxy_issue_affinity_cookie
            ? connection->proxy_affinity_key : NULL,
        connection->proxy_client_wants_close, &info);
    if (sanitized_length < 0)
        return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                           "Bad Gateway");

    /* A WebSocket upgrade attempt that the upstream actually confirmed
     * (101): relay every header as-is, not the sanitized/hop-by-hop-
     * stripped block above -- Connection: Upgrade, Upgrade: websocket,
     * and Sec-WebSocket-Accept are exactly what the client needs to see
     * to know the upgrade succeeded, and normal hop-by-hop filtering
     * would strip the first two. header_copy is already a complete,
     * well-formed "status line + headers + blank line" block (that is
     * what header_length spans), so it can be relayed verbatim with no
     * further parsing. Any other status for a requested-but-not-granted
     * upgrade (a plain 200, a 404, whatever the upstream decided) falls
     * through to the normal sanitized path below exactly like any other
     * proxied response -- magnus_dispatch_request() never promised the
     * client an upgrade, only relayed the attempt. */
    if (connection->proxy_ws_requested && info.status == 101) {
        connection->proxy_header_out = malloc(header_length);
        if (connection->proxy_header_out == NULL)
            return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                               "Bad Gateway");
        memcpy(connection->proxy_header_out, header_copy, header_length);
        connection->proxy_header_out_length = header_length;
        connection->proxy_header_out_sent = 0;
        connection->proxy_buffer_length = leftover;
        connection->proxy_buffer_sent = 0;
        connection->proxy_headers_received = true;
        connection->close_after_write = false;
        connection->proxy_upstream_poolable = false;
        connection->proxy_has_response_length = false;
        connection->proxy_response_length = 0;
        connection->proxy_response_received = 0;
        connection->proxy_ws_active = true;
        magnus_cluster_result(&magnus_cluster, connection->proxy_endpoint_index,
                              true, magnus_now_ms());
        magnus_requests_total++;
        {
            double latency_ms = (double) (magnus_now_ms()
                                          - connection->request_started_ms);
            magnus_record_latency(latency_ms);
            magnus_access_log(connection->proxy_request_id,
                              connection->proxy_log_method,
                              connection->proxy_log_target, 101, latency_ms);
        }
        return magnus_proxy_flush(epoll_fd, connection);
    }

    connection->proxy_header_out = malloc((size_t) sanitized_length);
    if (connection->proxy_header_out == NULL)
        return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                           "Bad Gateway");
    memcpy(connection->proxy_header_out, sanitized, (size_t) sanitized_length);
    connection->proxy_header_out_length = (size_t) sanitized_length;
    connection->proxy_header_out_sent = 0;
    /* `leftover` is body bytes that arrived in the same recv() as the
     * headers -- already fully received from upstream even though
     * magnus_proxy_flush() hasn't written them to the client yet, so it
     * counts toward proxy_response_received now, not just once flushed:
     * what decides whether more needs to be read from *upstream* (and
     * therefore whether the upstream connection can be freed for reuse)
     * is what has been received, independent of client-write progress.
     * If a length was declared and the backend sent more than that in one
     * burst (a misbehaving backend, or a pipelined next response arriving
     * early on a connection this pool just started reusing), the excess
     * must not be forwarded as part of *this* response's body -- doing so
     * would desync the client's own parser -- so it is dropped, not
     * buffered, here. */
    if (info.has_content_length && leftover > info.content_length)
        leftover = info.content_length;
    memmove(connection->proxy_buffer, body_start, leftover);
    connection->proxy_buffer_length = leftover;
    connection->proxy_buffer_sent = 0;
    connection->proxy_headers_received = true;
    connection->close_after_write = !info.keep_client_alive;
    connection->proxy_upstream_poolable = info.upstream_poolable;
    connection->proxy_has_response_length = info.has_content_length;
    connection->proxy_response_length = info.content_length;
    connection->proxy_response_received = leftover;
    magnus_cluster_result(&magnus_cluster, connection->proxy_endpoint_index,
                          true, magnus_now_ms());
    magnus_requests_total++;
    if (info.status >= 500) magnus_responses_5xx++;
    else if (info.status >= 400) magnus_responses_4xx++;
    {
        double latency_ms = (double) (magnus_now_ms()
                                      - connection->request_started_ms);
        magnus_record_latency(latency_ms);
        magnus_access_log(connection->proxy_request_id,
                          connection->proxy_log_method,
                          connection->proxy_log_target, info.status,
                          latency_ms);
    }
    return magnus_proxy_flush(epoll_fd, connection);
}

/* Sets both fds' epoll interest from the current state of both relay
 * buffers -- the one function that actually decides what to watch for,
 * called after every attempt to move bytes in magnus_ws_service() below.
 * Each direction reads into whichever of the two buffers is "its own"
 * (ws_buffer for client->upstream, mirroring proxy_buffer's pre-existing
 * upstream->client role) and writes out of the other pump's buffer, so a
 * fd's interest is: EPOLLIN once its own outbound buffer is empty (ready
 * to accept more), EPOLLOUT whenever the *other* direction's buffer still
 * has unsent bytes destined for it. Always includes EPOLLRDHUP so a
 * clean shutdown from either peer is still noticed while only one of
 * EPOLLIN/EPOLLOUT (or neither) is otherwise being watched for. */
static int
magnus_ws_update_interest(int epoll_fd, magnus_connection_t *connection)
{
    uint32_t client_events = EPOLLRDHUP;
    uint32_t upstream_events = EPOLLRDHUP;
    struct epoll_event client_event, upstream_event;

    if (connection->ws_buffer_length == connection->ws_buffer_sent)
        client_events |= EPOLLIN;
    else
        upstream_events |= EPOLLOUT;
    if (connection->proxy_buffer_length == connection->proxy_buffer_sent)
        upstream_events |= EPOLLIN;
    else
        client_events |= EPOLLOUT;

    client_event = (struct epoll_event) { .events = client_events,
                                          .data.fd = connection->fd };
    upstream_event = (struct epoll_event) { .events = upstream_events,
                                            .data.fd = connection->upstream_fd };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, connection->fd, &client_event) < 0)
        return -1;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, connection->upstream_fd,
                 &upstream_event) < 0)
        return -1;
    return 0;
}

/* Moves bytes for one direction of the relay as far as they will go
 * without blocking: drains whatever is already buffered first (the
 * backpressure case -- the destination could not take it all last time),
 * then keeps alternating read/write while data keeps flowing. Mirrors the
 * read-then-write, EAGAIN/EINTR-handling shape already used for ordinary
 * proxied response bodies (see magnus_proxy_flush() and the body-read
 * loop in magnus_handle_upstream()) -- this is that same pattern applied
 * to a raw pipe with no HTTP framing on top of it, not a new one.
 * `from_client` selects the direction: true reads connection->fd and
 * writes connection->upstream_fd (through ws_buffer); false is the
 * reverse (through proxy_buffer, already allocated from the handshake).
 * Returns -1 if either peer closed or a hard I/O error occurred (the
 * whole relay pair is torn down on any such error, same as an ordinary
 * proxied connection breaking mid-response), 0 otherwise -- including
 * when it stopped only because it would have blocked, which is the
 * common case and not a problem the caller needs to react to beyond
 * calling magnus_ws_update_interest() once both directions have been
 * tried. */
static int
magnus_ws_pump_direction(magnus_connection_t *connection, bool from_client)
{
    char *buffer = from_client ? connection->ws_buffer : connection->proxy_buffer;
    size_t *length = from_client ? &connection->ws_buffer_length
                                  : &connection->proxy_buffer_length;
    size_t *sent = from_client ? &connection->ws_buffer_sent
                                : &connection->proxy_buffer_sent;

    for (;;) {
        while (*sent < *length) {
            ssize_t written = from_client
                ? send(connection->upstream_fd, buffer + *sent,
                      *length - *sent, MSG_NOSIGNAL)
                : magnus_socket_write(connection, buffer + *sent,
                                     *length - *sent);
            if (written > 0) {
                *sent += (size_t) written;
                connection->last_active = time(NULL);
                connection->proxy_last_activity = connection->last_active;
                continue;
            }
            if (written < 0 && errno == EINTR) continue;
            if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
            return -1;
        }
        *length = 0;
        *sent = 0;
        {
            ssize_t received = from_client
                ? magnus_socket_read(connection, buffer, MAGNUS_PROXY_BUFFER)
                : recv(connection->upstream_fd, buffer, MAGNUS_PROXY_BUFFER, 0);
            if (received > 0) {
                *length = (size_t) received;
                connection->last_active = time(NULL);
                connection->proxy_last_activity = connection->last_active;
                continue;
            }
            if (received == 0) return -1;
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
            return -1;
        }
    }
}

/* Entry point for any epoll event on either fd of a WebSocket-upgraded
 * connection pair once magnus_proxy_ws_active is set: always attempts
 * both directions regardless of which specific fd's event fired (a
 * would-block on the direction that was not actually ready simply
 * returns immediately), then recomputes both fds' interest once from
 * the result. Lazily allocates ws_buffer on first use -- proxy_buffer
 * already exists from the handshake, but nothing needed the
 * client->upstream direction's buffer before now. */
static int
magnus_ws_service(int epoll_fd, magnus_connection_t *connection)
{
    if (connection->ws_buffer == NULL) {
        connection->ws_buffer = malloc(MAGNUS_PROXY_BUFFER);
        if (connection->ws_buffer == NULL) return -1;
    }
    if (magnus_ws_pump_direction(connection, true) < 0) return -1;
    if (magnus_ws_pump_direction(connection, false) < 0) return -1;
    return magnus_ws_update_interest(epoll_fd, connection);
}

static int
magnus_handle_upstream(int epoll_fd, magnus_connection_t *connection,
                       uint32_t flags)
{
    if (connection->proxy_ws_active) {
        if ((flags & (EPOLLERR | EPOLLHUP)) != 0) return -1;
        return magnus_ws_service(epoll_fd, connection);
    }
    struct epoll_event event;
    if ((flags & (EPOLLERR | EPOLLHUP)) != 0) {
        if (connection->proxy_response_started)
            return magnus_proxy_abort(epoll_fd, connection);
        return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                           "Bad Gateway");
    }
    if (!connection->proxy_connected) {
        int error = 0;
        socklen_t length = sizeof(error);
        if (getsockopt(connection->upstream_fd, SOL_SOCKET, SO_ERROR,
                       &error, &length) < 0 || error != 0)
            return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                               "Bad Gateway");
        connection->proxy_connected = true;
        connection->proxy_last_activity = time(NULL);
    }
    while (!connection->proxy_headers_sent) {
        ssize_t sent = send(connection->upstream_fd,
            connection->proxy_request + connection->proxy_request_sent,
            connection->proxy_request_length - connection->proxy_request_sent,
            MSG_NOSIGNAL);
        if (sent > 0) {
            connection->proxy_request_sent += (size_t) sent;
            connection->proxy_last_activity = time(NULL);
        } else if (sent < 0 && errno == EINTR) {
            continue;
        } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        } else {
            return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                               "Bad Gateway");
        }
        if (connection->proxy_request_sent == connection->proxy_request_length)
            connection->proxy_headers_sent = true;
    }
    while (connection->proxy_body_sent < connection->body_length) {
        ssize_t sent = send(connection->upstream_fd,
            connection->body + connection->proxy_body_sent,
            connection->body_length - connection->proxy_body_sent,
            MSG_NOSIGNAL);
        if (sent > 0) {
            connection->proxy_body_sent += (size_t) sent;
            connection->proxy_last_activity = time(NULL);
        } else if (sent < 0 && errno == EINTR) {
            continue;
        } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        } else {
            return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                               "Bad Gateway");
        }
    }
    /* Fully relayed (or there never was one): this connection's copy is no
     * longer needed regardless of how the upstream response turns out. */
    free(connection->body);
    connection->body = NULL;
    connection->body_capacity = 0;
    connection->body_length = 0;
    connection->body_needed = 0;
    if (!connection->proxy_headers_received) {
        if ((flags & (EPOLLIN | EPOLLRDHUP)) != 0) {
            return magnus_proxy_receive_headers(epoll_fd, connection);
        }
        event = (struct epoll_event) { .events = EPOLLIN | EPOLLRDHUP,
                                       .data.fd = connection->upstream_fd };
        return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, connection->upstream_fd,
                         &event);
    }
    if (connection->proxy_buffer_length != 0) return 0;
    if ((flags & EPOLLIN) != 0 || (flags & EPOLLRDHUP) != 0) {
        /* Never read past a declared Content-Length: leftover bytes in the
         * kernel buffer past this response's end would otherwise belong to
         * whatever comes next on this connection (a pipelined response, if
         * this pool ever hands the connection to a concurrent user again --
         * it does not today, but the boundary must hold regardless) rather
         * than to this one. */
        size_t want = MAGNUS_PROXY_BUFFER;
        if (connection->proxy_has_response_length) {
            size_t remaining = connection->proxy_response_length
                - connection->proxy_response_received;
            if (remaining < want) want = remaining;
        }
        ssize_t received = want > 0
            ? recv(connection->upstream_fd, connection->proxy_buffer, want, 0)
            : 0;
        if (received > 0) {
            connection->proxy_buffer_length = (size_t) received;
            connection->proxy_response_received += (size_t) received;
            connection->last_active = time(NULL);
            connection->proxy_last_activity = connection->last_active;
        } else if (want == 0) {
            /* Already have every declared body byte -- nothing left to
             * read, and treating a want-0 recv()'s return as EOF would be
             * exactly the same misread magnus_proxy_receive_headers()
             * already avoids for the same reason. */
        } else if (received == 0) {
            connection->proxy_eof = true;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return magnus_proxy_abort(epoll_fd, connection);
        }
        if (connection->proxy_buffer_length != 0 || connection->proxy_eof
            || want == 0)
            return magnus_proxy_flush(epoll_fd, connection);
    }
    event = (struct epoll_event) { .events = EPOLLIN | EPOLLRDHUP,
                                   .data.fd = connection->upstream_fd };
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, connection->upstream_fd, &event);
}

static ssize_t
magnus_socket_read(magnus_connection_t *connection, void *buffer, size_t length)
{
    int result;
    int ssl_error;
    if (connection->tls == NULL)
        return recv(connection->fd, buffer, length, 0);
    result = SSL_read(connection->tls, buffer, (int) length);
    if (result > 0) return result;
    ssl_error = SSL_get_error(connection->tls, result);
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        errno = EAGAIN;
        return -1;
    }
    if (ssl_error == SSL_ERROR_ZERO_RETURN) return 0;
    errno = EIO;
    return -1;
}

static ssize_t
magnus_socket_write(magnus_connection_t *connection, const void *buffer,
                    size_t length)
{
    int result;
    int ssl_error;
    if (connection->tls == NULL)
        return send(connection->fd, buffer, length, MSG_NOSIGNAL);
    result = SSL_write(connection->tls, buffer, (int) length);
    if (result > 0) return result;
    ssl_error = SSL_get_error(connection->tls, result);
    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        errno = EAGAIN;
        return -1;
    }
    errno = EIO;
    return -1;
}

static int
magnus_tls_handshake(int epoll_fd, magnus_connection_t *connection)
{
    int result = SSL_accept(connection->tls);
    int ssl_error;
    if (result == 1) {
        const unsigned char *alpn = NULL;
        unsigned int alpn_length = 0;
        connection->tls_ready = true;
        SSL_get0_alpn_selected(connection->tls, &alpn, &alpn_length);
        if (alpn != NULL && alpn_length == 2 && alpn[0] == 'h' && alpn[1] == '2') {
            if (magnus_h2_session_create(connection) != 0) return -1;
            return magnus_h2_service(epoll_fd, connection);
        }
        return magnus_update_interest(epoll_fd, connection, EPOLLIN | EPOLLRDHUP);
    }
    ssl_error = SSL_get_error(connection->tls, result);
    if (ssl_error == SSL_ERROR_WANT_READ)
        return magnus_update_interest(epoll_fd, connection, EPOLLIN | EPOLLRDHUP);
    if (ssl_error == SSL_ERROR_WANT_WRITE)
        return magnus_update_interest(epoll_fd, connection, EPOLLOUT | EPOLLRDHUP);
    return -1;
}

static const char *
magnus_content_type(const char *path)
{
    const char *extension = strrchr(path, '.');
    if (extension == NULL) return "application/octet-stream";
    if (strcmp(extension, ".html") == 0) return "text/html; charset=utf-8";
    if (strcmp(extension, ".css") == 0) return "text/css; charset=utf-8";
    if (strcmp(extension, ".js") == 0) return "text/javascript; charset=utf-8";
    if (strcmp(extension, ".json") == 0) return "application/json";
    if (strcmp(extension, ".svg") == 0) return "image/svg+xml";
    if (strcmp(extension, ".png") == 0) return "image/png";
    if (strcmp(extension, ".jpg") == 0 || strcmp(extension, ".jpeg") == 0)
        return "image/jpeg";
    return "application/octet-stream";
}

static int
magnus_open_static(const char *target, struct stat *metadata)
{
    char path[256];
    char *part;
    char *next;
    char *state = NULL;
    size_t length = strcspn(target, "?");
    int directory;
    int fd = -1;
    if (magnus_root_fd < 0 || length < 2 || length >= sizeof(path)
        || memchr(target, '%', length) != NULL
        || strstr(target, "//") != NULL || strstr(target, "/../") != NULL
        || (length >= 3 && memcmp(target + length - 3, "/..", 3) == 0))
        return -1;
    memcpy(path, target + 1, length - 1);
    path[length - 1] = '\0';
    directory = dup(magnus_root_fd);
    if (directory < 0) return -1;
    part = strtok_r(path, "/", &state);
    while (part != NULL) {
        next = strtok_r(NULL, "/", &state);
        if (strcmp(part, ".") == 0 || strcmp(part, "..") == 0) {
            close(directory);
            return -1;
        }
        fd = openat(directory, part, O_RDONLY | O_CLOEXEC | O_NOFOLLOW
                    | (next != NULL ? O_DIRECTORY : 0));
        close(directory);
        if (fd < 0) return -1;
        if (next == NULL) break;
        directory = fd;
        fd = -1;
        part = next;
    }
    if (fd < 0 || fstat(fd, metadata) < 0 || !S_ISREG(metadata->st_mode)) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

static void
magnus_prepare_file_response(magnus_connection_t *connection, int file_fd,
                             const struct stat *metadata, bool head_only,
                             bool close_connection, magnus_request_t *request)
{
    int written;
    request->status = 200;
    magnus_requests_total++;
    (void) magnus_phase_run(&magnus_phases, MAGNUS_PHASE_RESPONSE, request);
    written = snprintf(connection->output, sizeof(connection->output),
        "HTTP/1.1 200 OK\r\nServer: Magnus/%s\r\nContent-Type: %s\r\n"
        "Content-Length: %lld\r\nConnection: %s\r\nAccept-Ranges: bytes\r\n"
        "X-Magnus-Engine: native-c17/0.1\r\nX-Magnus-Request-Id: %s\r\n\r\n",
        MAGNUS_VERSION, magnus_content_type(request->path),
        (long long) metadata->st_size, close_connection ? "close" : "keep-alive",
        request->request_id);
    if (written < 0 || (size_t) written >= sizeof(connection->output)) {
        close(file_fd);
        connection->output_length = 0;
        connection->close_after_write = true;
        return;
    }
    connection->output_length = (size_t) written;
    connection->output_sent = 0;
    connection->close_after_write = close_connection;
    connection->file_fd = head_only ? -1 : file_fd;
    connection->file_offset = 0;
    connection->file_length = head_only ? 0 : metadata->st_size;
    if (head_only) close(file_fd);
}

static int
magnus_update_interest(int epoll_fd, magnus_connection_t *connection,
                       uint32_t events)
{
    struct epoll_event event = { .events = events, .data.fd = connection->fd };
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, connection->fd, &event);
}

/* ---- HTTP/2 (roadmap Phase 1e-1): ALPN-negotiated "h2", nghttp2-driven
 * session, static-file responses only -- no proxy/route dispatch over h2
 * yet, and no h2c (cleartext upgrade). See magnus_h2.c/.h for the
 * standalone, independently-tested ALPN selection callback; everything
 * below is the actual session/stream wiring, which lives here because
 * nghttp2's callback model needs direct access to this file's
 * static-file-serving (magnus_open_static/magnus_content_type) and
 * socket-I/O (magnus_socket_read/write) internals. */

/* One nghttp2 stream's worth of request/response state. Deliberately
 * minimal -- 1e-1 only ever serves a static file per stream, so all a
 * stream needs to remember is which one and how far it has gotten. An
 * intrusive doubly-linked list (next/prev) threads every stream still
 * open on a connection onto that connection's h2_streams head, purely so
 * magnus_close_connection() can walk and free them; nghttp2_session_del()
 * does not itself invoke the stream-close callback for streams still
 * open when a session is torn down, and a stream may be holding an open
 * file_fd. */
struct magnus_h2_stream {
    struct magnus_h2_stream *next;
    struct magnus_h2_stream *prev;
    magnus_connection_t *connection;
    int32_t stream_id;
    /* Captured request, in the same magnus_http_request_t shape the
     * HTTP/1.1 wire parser (magnus_http_parse()) produces -- but filled
     * in directly from nghttp2-decoded pseudo-/regular headers instead of
     * parsing wire bytes, since h2 never has an HTTP/1.1-formatted
     * request to parse in the first place. This is what lets
     * magnus_route_matches() (host/path-prefix/method/header/cookie/
     * query/source-CIDR routing, written once for 1b and never touched
     * since) work unmodified for h2 traffic too -- the "common internal
     * request model" the master prompt's Section 3.1 asks for, in its
     * first, narrowest form (route matching only; proxy/static dispatch
     * below still branches by protocol). */
    magnus_http_request_t parsed;
    /* True if the client's :method, :path, or :authority pseudo-header
     * value would not fit the fixed buffer it is captured into -- rather
     * than truncating and silently resolving the wrong (shorter) target,
     * such a request is answered with 405/414 (method/path) or simply
     * routed as if it had no Host at all (authority -- a truncated host
     * cannot safely match a host-based route, so leaving it empty is the
     * only safe fallback, not picking some prefix of it). */
    bool method_overflow;
    bool path_overflow;
    bool head_only;
    /* Set the moment magnus_h2_dispatch() runs, so a second END_STREAM-
     * bearing frame on the same stream (defensively -- HTTP/2 framing
     * should never actually produce one) cannot dispatch it twice. */
    bool dispatched;

    /* -- static-file dispatch (1e-1) -- */
    int file_fd;
    off_t file_offset;
    off_t file_length;

    /* -- proxy dispatch (1e-2): client h2 stream -> upstream HTTP/1.x --
     * Each field below is this stream's own private copy of what an
     * ordinary HTTP/1.1 proxy attempt keeps on magnus_connection_t
     * itself (proxy_request/body/upstream_fd/proxy_buffer/etc.) --
     * necessarily duplicated rather than shared, since one h2 connection
     * can have many streams each proxying to a (possibly different)
     * upstream concurrently, where HTTP/1.1 only ever has one proxy
     * attempt in flight per client connection at a time. */
    bool is_proxy;
    int upstream_fd;
    bool upstream_connected;
    bool upstream_headers_sent;
    size_t endpoint_index;
    unsigned attempt;
    unsigned upstream_requests_served;
    time_t connect_started;
    time_t last_activity;
    uint64_t started_ms;
    char request_id[33];
    char log_method[8];
    char log_target[256];
    char affinity_key[64];
    bool issue_affinity_cookie;
    /* Built once at proxy start: "METHOD target HTTP/1.0\r\nHost: ...
     * \r\n...\r\n\r\n", sent to the upstream ahead of any request body. */
    char proxy_request[512];
    size_t proxy_request_length;
    size_t proxy_request_sent;
    /* Client's request body, accumulated from DATA frames (see
     * magnus_h2_on_data_chunk_recv()) up to MAGNUS_MAX_BODY, same cap
     * the HTTP/1.1 path enforces -- then relayed to the upstream once
     * proxy_request has gone out. body_overflow means the client sent
     * more than that; the stream is answered 413 once END_STREAM
     * arrives rather than mid-stream, matching how an oversized
     * Content-Length is rejected up front on the HTTP/1.1 side. */
    char *body;
    size_t body_capacity;
    size_t body_length;
    size_t body_sent;
    bool body_overflow;
    /* Upstream response: one shared buffer reused across two phases,
     * exactly like connection->proxy_buffer's own dual role for the
     * HTTP/1.1 path -- first accumulating the raw status-line+headers
     * block (header_accum counts bytes so far), then (after
     * magnus_find_header_end() locates the end of it) holding body
     * chunks for the nghttp2 data-provider read callback to pull from
     * (io_length/io_sent). Unlike connection->proxy_buffer, nothing here
     * is ever written straight to a client socket -- io_length/io_sent
     * are drained by magnus_h2_read_io_buffer() instead, pulled by
     * nghttp2 whenever it is ready to emit this stream's next DATA
     * frame. */
    char *io_buffer;
    size_t header_accum;
    size_t io_length;
    size_t io_sent;
    bool headers_received;
    bool response_headers_submitted;
    bool upstream_eof;
    /* Set once the response is known to be fully received from the
     * upstream (Content-Length reached, or the upstream closed) -- tells
     * magnus_h2_read_io_buffer() it is safe to report
     * NGHTTP2_DATA_FLAG_EOF once io_buffer is fully drained, rather than
     * DEFERRED (more is still expected). */
    bool response_complete;
    /* True if magnus_h2_read_io_buffer() last returned
     * NGHTTP2_ERR_DEFERRED because io_buffer was empty and
     * response_complete was not yet set -- nghttp2 will not call it
     * again for this stream on its own; whoever next adds bytes to
     * io_buffer must call nghttp2_session_resume_data() to make it
     * eligible again. */
    bool deferred;
    bool has_response_length;
    unsigned long response_length;
    unsigned long response_received;
    bool upstream_poolable;
};

static struct magnus_h2_stream *
magnus_h2_stream_new(magnus_connection_t *connection, int32_t stream_id)
{
    struct magnus_h2_stream *stream = calloc(1, sizeof(*stream));
    if (stream == NULL) return NULL;
    stream->connection = connection;
    stream->stream_id = stream_id;
    stream->file_fd = -1;
    stream->upstream_fd = -1;
    stream->started_ms = magnus_now_ms();
    stream->next = connection->h2_streams;
    stream->prev = NULL;
    if (connection->h2_streams != NULL) connection->h2_streams->prev = stream;
    connection->h2_streams = stream;
    return stream;
}

/* Tears down this stream's upstream connection, if it still has one, as
 * a plain close -- never a pool checkin. A clean, poolable completion
 * already checks its upstream fd into the pool (and sets upstream_fd
 * back to -1) the moment that is known, well before the stream itself
 * ever closes -- see magnus_h2_proxy_maybe_complete() -- so reaching
 * here with upstream_fd still >= 0 only ever means an abnormal teardown
 * (the client connection dying mid-flight, a stream reset, ...), for
 * which closing plainly is the only safe option. */
static void
magnus_h2_stream_teardown_upstream(struct magnus_h2_stream *stream)
{
    if (stream->upstream_fd < 0) return;
    if (magnus_global_epoll_fd >= 0)
        epoll_ctl(magnus_global_epoll_fd, EPOLL_CTL_DEL, stream->upstream_fd,
                 NULL);
    magnus_h2_upstream_owner[stream->upstream_fd] = NULL;
    close(stream->upstream_fd);
    stream->upstream_fd = -1;
}

static void
magnus_h2_stream_free(struct magnus_h2_stream *stream)
{
    magnus_connection_t *connection = stream->connection;
    if (stream->prev != NULL) stream->prev->next = stream->next;
    else connection->h2_streams = stream->next;
    if (stream->next != NULL) stream->next->prev = stream->prev;
    if (stream->file_fd >= 0) close(stream->file_fd);
    magnus_h2_stream_teardown_upstream(stream);
    free(stream->body);
    free(stream->io_buffer);
    free(stream);
}

static nghttp2_nv
magnus_h2_nv(const char *name, const char *value)
{
    /* nghttp2_nv's fields are non-const uint8_t* because the same struct
     * doubles as an "I'll hand you memory to keep, don't copy it" slot
     * (the NGHTTP2_NV_FLAG_NO_COPY_* flags, unused here) -- with those
     * flags absent (NGHTTP2_NV_FLAG_NONE below), nghttp2_submit_response2
     * copies both strings into its own storage before returning, so this
     * cast never lets nghttp2 hold on to memory it does not own. */
    return (nghttp2_nv) {
        .name = (uint8_t *) name, .value = (uint8_t *) value,
        .namelen = strlen(name), .valuelen = strlen(value),
        .flags = NGHTTP2_NV_FLAG_NONE,
    };
}

static void
magnus_h2_submit_status(nghttp2_session *session, int32_t stream_id,
                        const char *status)
{
    nghttp2_nv headers[2] = {
        magnus_h2_nv(":status", status),
        magnus_h2_nv("server", "Magnus/" MAGNUS_VERSION),
    };
    (void) nghttp2_submit_response2(session, stream_id, headers, 2, NULL);
}

static nghttp2_ssize
magnus_h2_read_file(nghttp2_session *session, int32_t stream_id, uint8_t *buf,
                    size_t length, uint32_t *data_flags,
                    nghttp2_data_source *source, void *user_data)
{
    struct magnus_h2_stream *stream = source->ptr;
    off_t remaining = stream->file_length - stream->file_offset;
    ssize_t got;
    (void) session;
    (void) stream_id;
    (void) user_data;
    if (remaining <= 0) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }
    if ((off_t) length > remaining) length = (size_t) remaining;
    got = pread(stream->file_fd, buf, length, stream->file_offset);
    if (got < 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
    stream->file_offset += got;
    if (got == 0 || stream->file_offset >= stream->file_length)
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return got;
}

/* Serves stream->parsed.target as a static file, exactly like the
 * HTTP/1.1 GET path (magnus_open_static() + magnus_content_type(), same
 * helpers) -- reused rather than reimplemented so both protocols agree
 * on path resolution/traversal safety by construction. Called from
 * magnus_h2_dispatch() below once routing has decided this request is
 * not a proxy match and its method is GET/HEAD. */
static void
magnus_h2_dispatch_static(magnus_connection_t *connection,
                          struct magnus_h2_stream *stream)
{
    nghttp2_session *session = connection->h2_session;
    struct stat metadata;
    int fd;
    char content_length[32];
    nghttp2_nv headers[4];

    fd = magnus_open_static(stream->parsed.target, &metadata);
    if (fd < 0) {
        magnus_h2_submit_status(session, stream->stream_id, "404");
        return;
    }
    stream->head_only = strcmp(stream->parsed.method, "HEAD") == 0;
    stream->file_offset = 0;
    stream->file_length = metadata.st_size;
    snprintf(content_length, sizeof(content_length), "%lld",
            (long long) metadata.st_size);
    headers[0] = magnus_h2_nv(":status", "200");
    headers[1] = magnus_h2_nv("server", "Magnus/" MAGNUS_VERSION);
    headers[2] = magnus_h2_nv("content-type",
                              magnus_content_type(stream->parsed.target));
    headers[3] = magnus_h2_nv("content-length", content_length);
    if (stream->head_only) {
        close(fd);
        (void) nghttp2_submit_response2(session, stream->stream_id, headers, 4,
                                        NULL);
        return;
    }
    stream->file_fd = fd;
    {
        nghttp2_data_provider2 data_provider = {
            .source = { .ptr = stream },
            .read_callback = magnus_h2_read_file,
        };
        (void) nghttp2_submit_response2(session, stream->stream_id, headers, 4,
                                        &data_provider);
    }
}

/* Routes, then branches to either a proxied upstream request (1e-2), a
 * built-in /healthz//metrics response (1e-4), or a static-file response
 * (1e-1) -- deliberately kept close in shape to
 * magnus_dispatch_request()'s own route-then-branch structure for
 * HTTP/1.1 (see that function for the fuller commentary, and note this
 * mirrors its exact branch *order* too, not just which branches exist:
 * rate-limit check first -- consuming a token even for a request that
 * turns out denied, matching HTTP/1.1's own quirk here exactly rather
 * than "fixing" it into a divergence -- then route_denied, then the
 * method check, then /healthz, then /metrics, then proxy, then static;
 * a literal "/healthz" or "/metrics" path wins over a route that
 * happened to match action=proxy for that same literal path, exactly
 * like HTTP/1.1's own if/else-if chain), reusing the exact same
 * magnus_route_matches() call against stream->parsed rather than a
 * second routing implementation: a literal "/proxy" path prefix is
 * equivalent to an unconditional action=proxy route, ahead of
 * everything configured; routes are evaluated in file order, first
 * match wins. connection->admin_only is never true for an h2 connection
 * (h2 requires TLS+ALPN; the admin channel is a plain, non-TLS Unix
 * socket), so the HTTP/1.1 path's various `admin_only ||`/`!admin_only
 * &&` conditions collapse to their non-admin case here without needing
 * to be repeated. Called once per stream, the moment its request headers
 * and any body (buffered into stream->body -- see
 * magnus_h2_on_data_chunk_recv()) are fully received. */
static void
magnus_h2_dispatch(magnus_connection_t *connection, struct magnus_h2_stream *stream)
{
    nghttp2_session *session = connection->h2_session;
    bool literal_proxy_prefix;
    bool is_proxy_route;
    bool route_denied = false;
    bool is_healthz_path;
    bool is_metrics_path;
    bool head_only;
    const char *forward_path;

    stream->dispatched = true;
    if (stream->method_overflow) {
        magnus_h2_submit_status(session, stream->stream_id, "405");
        return;
    }
    if (stream->path_overflow) {
        magnus_h2_submit_status(session, stream->stream_id, "414");
        return;
    }

    literal_proxy_prefix = magnus_upstream_enabled
        && strncmp(stream->parsed.target, "/proxy", 6) == 0
        && (stream->parsed.target[6] == '/' || stream->parsed.target[6] == '\0');
    is_proxy_route = literal_proxy_prefix;
    forward_path = literal_proxy_prefix ? stream->parsed.target + 6
                                        : stream->parsed.target;

    for (size_t r = 0; r < magnus_route_count; r++) {
        if (!magnus_route_matches(&magnus_routes[r], &stream->parsed,
                                  connection->client_address))
            continue;
        if (magnus_routes[r].action == MAGNUS_ROUTE_ACTION_PROXY) {
            is_proxy_route = true;
            forward_path = stream->parsed.target;
        } else if (magnus_routes[r].action == MAGNUS_ROUTE_ACTION_DENY) {
            route_denied = true;
        }
        break;
    }

    /* /healthz and /metrics stay exempt from rate limiting for the same
     * reason as HTTP/1.1: they are exactly what an operator or
     * monitoring system needs to reach to see *why* real traffic is
     * being throttled, so gating them behind the same limiter would be
     * self-defeating. */
    is_healthz_path = strcmp(stream->parsed.target, "/healthz") == 0;
    is_metrics_path = strcmp(stream->parsed.target, "/metrics") == 0;
    if (!is_healthz_path && !is_metrics_path
        && !magnus_rate_check(connection->client_address, time(NULL))) {
        magnus_rate_limited_total++;
        magnus_h2_submit_status(session, stream->stream_id, "429");
        return;
    }

    if (route_denied) {
        magnus_h2_submit_status(session, stream->stream_id, "403");
        return;
    }
    head_only = strcmp(stream->parsed.method, "HEAD") == 0;
    if (strcmp(stream->parsed.method, "GET") != 0 && !head_only
        && !is_proxy_route) {
        /* Static files, /healthz, and /metrics are inherently read-only;
         * the reverse proxy is the one route that has always been meant
         * to relay whatever method (and body) the client sent. */
        magnus_h2_submit_status(session, stream->stream_id, "405");
        return;
    }
    if (is_healthz_path) {
        magnus_h2_submit_text(connection, stream, "200", "text/plain",
                              "magnus: ok\n", head_only);
        return;
    }
    if (is_metrics_path && !magnus_admin_enabled) {
        char metrics[MAGNUS_METRICS_BUFFER];
        magnus_build_metrics(metrics, sizeof(metrics));
        magnus_h2_submit_text(connection, stream, "200",
                              "text/plain; version=0.0.4", metrics, head_only);
        return;
    }
    if (is_proxy_route) {
        if (stream->body_overflow) {
            magnus_h2_submit_status(session, stream->stream_id, "413");
            return;
        }
        magnus_h2_proxy_start(connection, stream, forward_path);
        return;
    }
    magnus_h2_dispatch_static(connection, stream);
}

/* Rolls `connection`'s Rapid-Reset-hardening window over to the current
 * second if it has changed since it was last touched -- called from
 * both magnus_h2_on_begin_headers() and magnus_h2_on_frame_recv()'s
 * RST_STREAM branch right before incrementing whichever counter applies,
 * so the two counters always share one window regardless of which kind
 * of event happens to advance it first. */
static void
magnus_h2_abuse_window_refresh(magnus_connection_t *connection, time_t now)
{
    if (now == connection->h2_abuse_window_start) return;
    connection->h2_abuse_window_start = now;
    connection->h2_streams_opened_this_second = 0;
    connection->h2_resets_received_this_second = 0;
}

static int
magnus_h2_on_begin_headers(nghttp2_session *session, const nghttp2_frame *frame,
                           void *user_data)
{
    magnus_connection_t *connection = user_data;
    struct magnus_h2_stream *stream;
    if (frame->hd.type != NGHTTP2_HEADERS
        || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    magnus_h2_abuse_window_refresh(connection, time(NULL));
    connection->h2_streams_opened_this_second++;
    if (connection->h2_streams_opened_this_second
        > MAGNUS_H2_MAX_NEW_STREAMS_PER_SECOND)
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    stream = magnus_h2_stream_new(connection, frame->hd.stream_id);
    if (stream == NULL) return NGHTTP2_ERR_CALLBACK_FAILURE;
    if (nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
                                             stream) != 0) {
        magnus_h2_stream_free(stream);
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

static int
magnus_h2_on_header(nghttp2_session *session, const nghttp2_frame *frame,
                    const uint8_t *name, size_t namelen, const uint8_t *value,
                    size_t valuelen, uint8_t flags, void *user_data)
{
    struct magnus_h2_stream *stream;
    (void) flags;
    (void) user_data;
    if (frame->hd.type != NGHTTP2_HEADERS
        || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    stream = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (stream == NULL) return 0;

    if (namelen == 7 && memcmp(name, ":method", 7) == 0) {
        if (valuelen >= sizeof(stream->parsed.method)) {
            stream->method_overflow = true;
            return 0;
        }
        memcpy(stream->parsed.method, value, valuelen);
        stream->parsed.method[valuelen] = '\0';
        return 0;
    }
    if (namelen == 5 && memcmp(name, ":path", 5) == 0) {
        if (valuelen >= sizeof(stream->parsed.target)) {
            stream->path_overflow = true;
            return 0;
        }
        memcpy(stream->parsed.target, value, valuelen);
        stream->parsed.target[valuelen] = '\0';
        return 0;
    }
    if (namelen == 10 && memcmp(name, ":authority", 10) == 0) {
        /* Left empty (never partially copied) on overflow, unlike a
         * fixed-size body-relay buffer being truncated would be merely
         * wasteful -- a truncated Host value could accidentally match a
         * host-based route condition it should not, so leaving it at
         * its zero-initialized "" is the only safe fallback. */
        if (valuelen < sizeof(stream->parsed.host)) {
            memcpy(stream->parsed.host, value, valuelen);
            stream->parsed.host[valuelen] = '\0';
        }
        return 0;
    }
    if (namelen > 0 && name[0] == ':') return 0; /* any other pseudo-header */

    /* An ordinary header field. HTTP/2 field names are already lowercase
     * by construction (RFC 9113 8.2.1 -- nghttp2 enforces this on
     * decode), so no case-folding is needed here the way the HTTP/1.1
     * wire parser has to. Truncated (not rejected) past its fixed-size
     * slot, and simply not retained past MAGNUS_HTTP_MAX_HEADERS -- both
     * exactly mirroring magnus_http_parse()'s own handling of an
     * oversized/over-count header, so route matching behaves
     * identically regardless of which protocol a request arrived
     * over. */
    if (stream->parsed.header_count < MAGNUS_HTTP_MAX_HEADERS) {
        magnus_http_header_t *stored
            = &stream->parsed.headers[stream->parsed.header_count];
        size_t stored_name_length = namelen < sizeof(stored->name) - 1
            ? namelen : sizeof(stored->name) - 1;
        size_t stored_value_length = valuelen < sizeof(stored->value) - 1
            ? valuelen : sizeof(stored->value) - 1;
        memcpy(stored->name, name, stored_name_length);
        stored->name[stored_name_length] = '\0';
        memcpy(stored->value, value, stored_value_length);
        stored->value[stored_value_length] = '\0';
        stream->parsed.header_count++;
    }
    return 0;
}

/* Accumulates a proxy-bound stream's request body from DATA frames, up
 * to MAGNUS_MAX_BODY -- the same cap (and the same "buffer whole before
 * dispatch" shape) the HTTP/1.1 path enforces via
 * magnus_begin_body()/magnus_continue_body(). A non-proxy stream (static
 * file, denied, or not yet routed) has no use for a body at all, so
 * bytes are simply not retained for it; magnus_h2_dispatch() only ever
 * looks at stream->body for an is_proxy_route match anyway. Once the cap
 * is hit, no further bytes are retained (body_overflow latches) --
 * magnus_h2_dispatch() answers 413 once END_STREAM arrives rather than
 * failing the stream mid-flight. */
static int
magnus_h2_on_data_chunk_recv(nghttp2_session *session, uint8_t flags,
                             int32_t stream_id, const uint8_t *data,
                             size_t len, void *user_data)
{
    struct magnus_h2_stream *stream
        = nghttp2_session_get_stream_user_data(session, stream_id);
    (void) session;
    (void) flags;
    (void) user_data;
    if (stream == NULL || stream->body_overflow || len == 0) return 0;
    if (stream->body_length + len > MAGNUS_MAX_BODY) {
        stream->body_overflow = true;
        return 0;
    }
    if (stream->body_length + len > stream->body_capacity) {
        size_t new_capacity = stream->body_capacity == 0
            ? MAGNUS_PROXY_BUFFER : stream->body_capacity * 2;
        char *grown;
        while (new_capacity < stream->body_length + len) new_capacity *= 2;
        grown = realloc(stream->body, new_capacity);
        if (grown == NULL) {
            /* Allocation failure this far under MAGNUS_MAX_BODY (1 MiB)
             * would mean genuine system-wide memory pressure -- folded
             * into the same body_overflow/413 path as an oversized body
             * rather than a distinct code path, since either way this
             * stream simply cannot be proxied with a body attached. */
            stream->body_overflow = true;
            return 0;
        }
        stream->body = grown;
        stream->body_capacity = new_capacity;
    }
    memcpy(stream->body + stream->body_length, data, len);
    stream->body_length += len;
    return 0;
}

/* Frame types other than HEADERS/DATA/RST_STREAM (GOAWAY, PING,
 * SETTINGS, WINDOW_UPDATE, PRIORITY, ...) all fall through this
 * function's checks and are simply ignored -- not overlooked, but
 * deliberately safe to ignore: nghttp2 already applies each one's
 * protocol-level consequences (adjusting flow-control windows, refusing
 * new streams past a received GOAWAY's declared last-stream-id, acking
 * PINGs, ...) before this callback ever runs, and none of them need any
 * further reaction from magnus itself at this stage of the roadmap. */
static int
magnus_h2_on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame,
                        void *user_data)
{
    magnus_connection_t *connection = user_data;
    struct magnus_h2_stream *stream;

    if (frame->hd.type == NGHTTP2_RST_STREAM) {
        /* The client resetting a stream it opened -- the Rapid Reset
         * (CVE-2023-44487) signature when it happens at volume. See
         * MAGNUS_H2_MAX_RESETS_PER_SECOND's own comment for why the cap
         * is enforced here rather than via any nghttp2-builtin
         * protection (nghttp2's own flood detection covers PING/SETTINGS
         * acks and CONTINUATION floods, not this). */
        magnus_h2_abuse_window_refresh(connection, time(NULL));
        connection->h2_resets_received_this_second++;
        if (connection->h2_resets_received_this_second
            > MAGNUS_H2_MAX_RESETS_PER_SECOND)
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        return 0;
    }

    if ((frame->hd.type != NGHTTP2_HEADERS && frame->hd.type != NGHTTP2_DATA)
        || (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) == 0)
        return 0;
    if (frame->hd.type == NGHTTP2_HEADERS
        && frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    stream = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (stream == NULL || stream->dispatched) return 0;
    magnus_h2_dispatch(connection, stream);
    return 0;
}

static int
magnus_h2_on_stream_close(nghttp2_session *session, int32_t stream_id,
                          uint32_t error_code, void *user_data)
{
    struct magnus_h2_stream *stream
        = nghttp2_session_get_stream_user_data(session, stream_id);
    (void) error_code;
    (void) user_data;
    if (stream != NULL) magnus_h2_stream_free(stream);
    return 0;
}

static int
magnus_h2_session_create(magnus_connection_t *connection)
{
    nghttp2_session_callbacks *callbacks;
    nghttp2_settings_entry settings[1] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
          MAGNUS_H2_MAX_CONCURRENT_STREAMS },
    };
    int result;

    if (nghttp2_session_callbacks_new(&callbacks) != 0) return -1;
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,
        magnus_h2_on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(callbacks,
        magnus_h2_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
        magnus_h2_on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
        magnus_h2_on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
        magnus_h2_on_stream_close);

    result = nghttp2_session_server_new(&connection->h2_session, callbacks,
                                        connection);
    nghttp2_session_callbacks_del(callbacks);
    if (result != 0) return -1;

    if (nghttp2_submit_settings(connection->h2_session, NGHTTP2_FLAG_NONE,
                                settings, 1) != 0) {
        nghttp2_session_del(connection->h2_session);
        connection->h2_session = NULL;
        return -1;
    }
    connection->h2_active = true;
    return 0;
}

/* Called from magnus_close_connection() unconditionally (a no-op if h2
 * was never negotiated on this connection, since every field it touches
 * is NULL in that case). */
static void
magnus_h2_close(magnus_connection_t *connection)
{
    while (connection->h2_streams != NULL)
        magnus_h2_stream_free(connection->h2_streams);
    if (connection->h2_session != NULL) {
        nghttp2_session_del(connection->h2_session);
        connection->h2_session = NULL;
    }
    free(connection->h2_output);
    connection->h2_output = NULL;
    connection->h2_output_length = 0;
    connection->h2_output_sent = 0;
}

/* Flushes whatever was left over from a previous magnus_h2_drain_send()
 * call that could not be written in one go. Never asks nghttp2 for more
 * (see magnus_h2_drain_send()'s own comment on why) -- just drains this
 * buffer as far as the socket allows. */
static int
magnus_h2_flush_output(magnus_connection_t *connection)
{
    while (connection->h2_output != NULL
           && connection->h2_output_sent < connection->h2_output_length) {
        ssize_t sent = magnus_socket_write(connection,
            connection->h2_output + connection->h2_output_sent,
            connection->h2_output_length - connection->h2_output_sent);
        if (sent > 0) {
            connection->h2_output_sent += (size_t) sent;
            connection->last_active = time(NULL);
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        return -1;
    }
    if (connection->h2_output != NULL) {
        free(connection->h2_output);
        connection->h2_output = NULL;
        connection->h2_output_length = 0;
        connection->h2_output_sent = 0;
    }
    return 0;
}

/* Pulls as much serialized output as nghttp2 currently has queued
 * (SETTINGS/HEADERS/DATA/etc. for anything submitted so far -- including
 * frames nghttp2 generates on its own, like automatic PING/WINDOW_UPDATE
 * acks) and writes it out. nghttp2_session_mem_send2() only guarantees
 * the pointer it returns stays valid until the *next* mem_send2 or
 * mem_recv2 call, so a partial (would-block) write's remainder is copied
 * into connection->h2_output here rather than retried against the same
 * pointer later -- once that happens this function must not be called
 * again until magnus_h2_flush_output() has fully drained it. */
static int
magnus_h2_drain_send(magnus_connection_t *connection)
{
    nghttp2_session *session = connection->h2_session;
    for (;;) {
        const uint8_t *data = NULL;
        nghttp2_ssize length = nghttp2_session_mem_send2(session, &data);
        ssize_t sent;
        if (length < 0) return -1;
        if (length == 0) return 0;
        sent = magnus_socket_write(connection, data, (size_t) length);
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) sent = 0;
        else if (sent < 0) return -1;
        if ((size_t) sent == (size_t) length) {
            connection->last_active = time(NULL);
            continue;
        }
        connection->h2_output = malloc((size_t) length - (size_t) sent);
        if (connection->h2_output == NULL) return -1;
        memcpy(connection->h2_output, data + sent,
              (size_t) length - (size_t) sent);
        connection->h2_output_length = (size_t) length - (size_t) sent;
        connection->h2_output_sent = 0;
        return 0;
    }
}

static int
magnus_h2_update_interest(int epoll_fd, magnus_connection_t *connection)
{
    uint32_t events = EPOLLRDHUP;
    int want_read = nghttp2_session_want_read(connection->h2_session);
    int want_write = nghttp2_session_want_write(connection->h2_session);
    if (!want_read && !want_write && connection->h2_output == NULL) return -1;
    if (want_read) events |= EPOLLIN;
    if (want_write || connection->h2_output != NULL) events |= EPOLLOUT;
    return magnus_update_interest(epoll_fd, connection, events);
}

/* Flushes leftover output, then (only if that fully drained) asks
 * nghttp2 for anything newly ready to send and writes that out too --
 * the "push whatever nghttp2 has queued onto the wire" sequence used
 * both at the top of every magnus_h2_service() call (below) and, for
 * proxy dispatch (1e-2), from magnus_h2_handle_upstream() whenever an
 * upstream event makes more of some *other* stream's response body
 * available: that push has to happen from there too, since nothing
 * guarantees the client fd itself has a pending epoll event at that
 * moment to otherwise trigger it. */
static int
magnus_h2_push(int epoll_fd, magnus_connection_t *connection)
{
    if (magnus_h2_flush_output(connection) < 0) return -1;
    if (connection->h2_output == NULL && magnus_h2_drain_send(connection) < 0)
        return -1;
    return magnus_h2_update_interest(epoll_fd, connection);
}

/* Entry point for any epoll event on an h2_active connection's fd, and
 * also called once, directly, right after magnus_h2_session_create()
 * succeeds -- that first call is what actually gets the server's initial
 * SETTINGS frame (queued by nghttp2_submit_settings() at session
 * creation) onto the wire, since nothing has been read from the client
 * yet at that point to otherwise trigger a send. */
static int
magnus_h2_service(int epoll_fd, magnus_connection_t *connection)
{
    unsigned char recv_buffer[MAGNUS_PROXY_BUFFER];

    if (magnus_h2_flush_output(connection) < 0) return -1;
    if (connection->h2_output == NULL && magnus_h2_drain_send(connection) < 0)
        return -1;
    if (connection->h2_output != NULL)
        return magnus_h2_update_interest(epoll_fd, connection);

    for (;;) {
        ssize_t received = magnus_socket_read(connection, recv_buffer,
                                              sizeof(recv_buffer));
        if (received > 0) {
            nghttp2_ssize consumed = nghttp2_session_mem_recv2(
                connection->h2_session, recv_buffer, (size_t) received);
            if (consumed < 0) return -1;
            connection->last_active = time(NULL);
            if (magnus_h2_drain_send(connection) < 0) return -1;
            if (connection->h2_output != NULL) break;
            continue;
        }
        if (received == 0) return -1;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        return -1;
    }
    return magnus_h2_update_interest(epoll_fd, connection);
}

/* ---- HTTP/2 proxy dispatch (roadmap Phase 1e-2): an h2 stream matched
 * to action=proxy (or the literal "/proxy" prefix) is relayed to an
 * ordinary HTTP/1.x upstream -- the same magnus_cluster/magnus_upstream_pool
 * every HTTP/1.1 proxy attempt already uses, and the same
 * magnus_proxy_sanitize_response_headers() hop-by-hop-stripping/framing
 * logic, translated into h2 response headers + DATA frames rather than
 * raw bytes written straight to a client socket. Deliberately its own
 * parallel set of functions rather than a reuse of
 * magnus_proxy_pick_and_start()/magnus_handle_upstream()/etc.: those are
 * built around exactly one proxy attempt in flight per client
 * *connection* at a time (magnus_connection_t's own proxy_* fields),
 * which an h2 connection's concurrent multiplexing genuinely breaks --
 * one connection can have many streams each proxying to a (possibly
 * different) upstream at once, so this proxy state lives on
 * struct magnus_h2_stream instead. WebSocket upgrades are not attempted
 * here: h2 has no Upgrade-style handshake at all (RFC 9113 8.5
 * repurposes :protocol/extended CONNECT for that, which this increment
 * does not implement -- see docs/development-roadmap.md's 1e entry). */

/* Ends a proxy-dispatched stream before any response headers have been
 * submitted to the client -- the h2 analogue of magnus_proxy_fail() for
 * HTTP/1.1. Unlike that function, no client-visible "connection" needs
 * closing over this: h2 multiplexes many streams over one connection
 * that stays open regardless of how any single stream's proxy attempt
 * turned out, so only this one stream ends, answered with a synthesized
 * status. Must only be called while
 * stream->response_headers_submitted is still false. */
static void
magnus_h2_proxy_fail(magnus_connection_t *connection,
                     struct magnus_h2_stream *stream, const char *status)
{
    unsigned status_code = (unsigned) strtoul(status, NULL, 10);
    double latency_ms = (double) (magnus_now_ms() - stream->started_ms);
    magnus_h2_stream_teardown_upstream(stream);
    magnus_h2_submit_status(connection->h2_session, stream->stream_id, status);
    magnus_requests_total++;
    if (status_code >= 500) magnus_responses_5xx++;
    else if (status_code >= 400) magnus_responses_4xx++;
    magnus_record_latency(latency_ms);
    magnus_access_log(stream->request_id, stream->log_method, stream->log_target,
                      status_code, latency_ms);
}

/* Ends a proxy-dispatched stream after response headers were already
 * submitted -- the h2 analogue of magnus_proxy_abort() for HTTP/1.1: a
 * fresh status code is no longer possible (h2 does not allow a second
 * HEADERS frame after the response has started any more than HTTP/1.1
 * allows a second status line), so the stream itself is reset instead.
 * The client sees this as an abruptly terminated response, same as an
 * HTTP/1.1 client would see a connection abort mid-body. */
static void
magnus_h2_proxy_abort(struct magnus_h2_stream *stream)
{
    magnus_h2_stream_teardown_upstream(stream);
    (void) nghttp2_submit_rst_stream(stream->connection->h2_session,
                                     NGHTTP2_FLAG_NONE, stream->stream_id,
                                     NGHTTP2_INTERNAL_ERROR);
}

/* The h2 analogue of magnus_proxy_attach_upstream(): common state setup
 * once a socket (freshly connected, or handed out of
 * magnus_upstream_pool) is ready to be this stream's upstream, on
 * magnus_h2_upstream_owner[] rather than magnus_upstream_owner[] since
 * ownership here is per-stream, not per-connection. Returns 0 once the
 * attempt is in flight, -1 on immediate failure (fd already closed). */
static int
magnus_h2_proxy_attach_upstream(magnus_connection_t *connection,
                                struct magnus_h2_stream *stream,
                                size_t endpoint_index, int fd, bool connected,
                                unsigned requests_served)
{
    struct epoll_event event;
    (void) connection;
    if (fd < 0 || fd >= MAGNUS_MAX_FDS) {
        if (fd >= 0) close(fd);
        return -1;
    }
    if (stream->io_buffer == NULL) {
        stream->io_buffer = malloc(MAGNUS_PROXY_BUFFER);
        if (stream->io_buffer == NULL) {
            close(fd);
            return -1;
        }
    }
    stream->upstream_fd = fd;
    stream->upstream_connected = connected;
    stream->upstream_requests_served = requests_served;
    stream->endpoint_index = endpoint_index;
    stream->connect_started = time(NULL);
    stream->last_activity = stream->connect_started;
    magnus_h2_upstream_owner[fd] = stream;
    event = (struct epoll_event) { .events = EPOLLOUT | EPOLLRDHUP,
                                   .data.fd = fd };
    if (epoll_ctl(magnus_global_epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        magnus_h2_upstream_owner[fd] = NULL;
        close(fd);
        stream->upstream_fd = -1;
        return -1;
    }
    return 0;
}

/* The h2 analogue of magnus_proxy_connect_endpoint(): a pooled idle
 * connection for this endpoint is tried first, exactly like the
 * HTTP/1.1 path -- this is the connection-pool reuse the master prompt
 * asked 1e-2 to keep, and it works unmodified here since
 * magnus_upstream_pool is keyed by cluster endpoint, not by which
 * client connection or protocol is asking. */
static int
magnus_h2_proxy_connect_endpoint(magnus_connection_t *connection,
                                 struct magnus_h2_stream *stream,
                                 size_t endpoint_index)
{
    struct sockaddr_in address;
    int result;
    int fd;
    unsigned pooled_requests_served;
    int pooled_fd = magnus_pool_checkout(endpoint_index, &pooled_requests_served);

    if (pooled_fd >= 0) {
        if (magnus_h2_proxy_attach_upstream(connection, stream, endpoint_index,
                                            pooled_fd, true,
                                            pooled_requests_served) == 0)
            return 0;
    }
    if (!magnus_endpoint_sockaddr(endpoint_index, &address)) return -1;
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0 || fd >= MAGNUS_MAX_FDS) {
        if (fd >= 0) close(fd);
        return -1;
    }
    result = connect(fd, (struct sockaddr *) &address, sizeof(address));
    if (result < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return magnus_h2_proxy_attach_upstream(connection, stream, endpoint_index,
                                           fd, result == 0, 0);
}

/* The h2 analogue of magnus_proxy_connect_failed(): records a
 * connect-stage failure for the endpoint currently in flight and either
 * retries against a different healthy endpoint -- bounded by
 * MAGNUS_PROXY_MAX_ATTEMPTS total attempts -- or gives up with a clean
 * status-coded error. Must only be called while
 * stream->response_headers_submitted is still false. */
static void
magnus_h2_proxy_connect_failed(magnus_connection_t *connection,
                               struct magnus_h2_stream *stream,
                               const char *give_up_status)
{
    magnus_cluster_result(&magnus_cluster, stream->endpoint_index, false,
                          magnus_now_ms());
    magnus_h2_stream_teardown_upstream(stream);
    if (stream->attempt < MAGNUS_PROXY_MAX_ATTEMPTS) {
        int endpoint = magnus_cluster_select(&magnus_cluster, magnus_now_ms(),
                                             NULL);
        if (endpoint >= 0) {
            stream->attempt++;
            if (magnus_h2_proxy_connect_endpoint(connection, stream,
                                                 (size_t) endpoint) == 0) {
                stream->issue_affinity_cookie = true;
                magnus_encode_affinity_cookie(stream->affinity_key,
                                              sizeof(stream->affinity_key),
                                              (size_t) endpoint);
                return;
            }
            magnus_cluster_result(&magnus_cluster, (size_t) endpoint, false,
                                  magnus_now_ms());
        }
    }
    magnus_h2_proxy_fail(connection, stream, give_up_status);
}

/* Entry point from magnus_h2_dispatch(): builds the outbound proxy
 * request (an h2 analogue of magnus_proxy_pick_and_start(), minus the
 * WebSocket branch -- see this block's own top-of-section comment for
 * why), then selects a healthy cluster endpoint and connects, retrying
 * once on an immediate connect failure exactly like the HTTP/1.1 path.
 * `forward_path` is what actually goes out on the wire as the upstream
 * request's target -- stream->parsed.target with the literal "/proxy"
 * prefix stripped for a request that reached here via that hardcoded
 * prefix, or unchanged for one that reached here via a matched
 * action=proxy route (see magnus_h2_dispatch()). Session affinity works
 * the same way as HTTP/1.1: a valid MAGNUS_AFFINITY cookie in the
 * request's "cookie" header is preferred for the first attempt only. */
static void
magnus_h2_proxy_start(magnus_connection_t *connection,
                      struct magnus_h2_stream *stream, const char *forward_path)
{
    const char *cookie_header = magnus_http_header_find(&stream->parsed, "cookie");
    char client_affinity[64] = "";
    bool sticky;
    size_t preferred_index;
    int written;

    magnus_generate_token(stream->request_id);
    strncpy(stream->log_method, stream->parsed.method,
           sizeof(stream->log_method) - 1);
    stream->log_method[sizeof(stream->log_method) - 1] = '\0';
    strncpy(stream->log_target, stream->parsed.target,
           sizeof(stream->log_target) - 1);
    stream->log_target[sizeof(stream->log_target) - 1] = '\0';

    written = stream->body_length > 0
        ? snprintf(stream->proxy_request, sizeof(stream->proxy_request),
                   "%s %s HTTP/1.0\r\nHost: magnus-upstream\r\n"
                   "Connection: keep-alive\r\nContent-Length: %zu\r\n"
                   "X-Magnus-Request-Id: %s\r\n\r\n",
                   stream->parsed.method, forward_path, stream->body_length,
                   stream->request_id)
        : snprintf(stream->proxy_request, sizeof(stream->proxy_request),
                   "%s %s HTTP/1.0\r\nHost: magnus-upstream\r\n"
                   "Connection: keep-alive\r\nX-Magnus-Request-Id: %s\r\n\r\n",
                   stream->parsed.method, forward_path, stream->request_id);
    if (written < 0 || (size_t) written >= sizeof(stream->proxy_request)) {
        magnus_h2_proxy_fail(connection, stream, "502");
        return;
    }
    stream->proxy_request_length = (size_t) written;
    stream->is_proxy = true;

    if (cookie_header != NULL)
        (void) magnus_http_extract_cookie(cookie_header, strlen(cookie_header),
                                          MAGNUS_AFFINITY_COOKIE_NAME,
                                          client_affinity,
                                          sizeof(client_affinity));
    sticky = magnus_decode_affinity_cookie(
        client_affinity[0] != '\0' ? client_affinity : NULL, &preferred_index);
    stream->issue_affinity_cookie = !sticky;
    stream->attempt = 0;

    for (;;) {
        int endpoint = sticky
            ? magnus_cluster_select_sticky(&magnus_cluster, magnus_now_ms(),
                                           preferred_index)
            : magnus_cluster_select(&magnus_cluster, magnus_now_ms(), NULL);
        if (endpoint < 0) {
            magnus_h2_proxy_fail(connection, stream, "502");
            return;
        }
        if (sticky) {
            sticky = false;
        } else if (stream->attempt > 0) {
            stream->issue_affinity_cookie = true;
        }
        stream->attempt++;
        if (magnus_h2_proxy_connect_endpoint(connection, stream,
                                             (size_t) endpoint) == 0) {
            if (stream->issue_affinity_cookie) {
                magnus_encode_affinity_cookie(stream->affinity_key,
                                              sizeof(stream->affinity_key),
                                              (size_t) endpoint);
            }
            return;
        }
        magnus_cluster_result(&magnus_cluster, (size_t) endpoint, false,
                              magnus_now_ms());
        if (stream->attempt >= MAGNUS_PROXY_MAX_ATTEMPTS) {
            magnus_h2_proxy_fail(connection, stream, "502");
            return;
        }
    }
}

/* nghttp2 data-provider read callback that pulls from
 * stream->io_buffer/io_length/io_sent, generic across every h2 response
 * that streams its body out of that one buffer: a proxy-dispatched
 * stream's upstream response (magnus_h2_proxy_stream_response() below
 * keeps it refilled from the upstream socket as more arrives, setting
 * response_complete only once the upstream is fully drained), and
 * /healthz//metrics (roadmap 1e-4, magnus_h2_submit_text() below), whose
 * entire body is already sitting in io_buffer with response_complete
 * set to true from the very start -- nothing ever needs to defer for
 * those. Reports NGHTTP2_ERR_DEFERRED (not EOF, not more bytes) whenever
 * the buffer is empty but response_complete is not yet set -- more is
 * still expected, it just is not available *right now*; whichever code
 * next adds bytes to io_buffer must call nghttp2_session_resume_data()
 * to make this stream eligible again (see stream->deferred's own
 * comment). */
static nghttp2_ssize
magnus_h2_read_io_buffer(nghttp2_session *session, int32_t stream_id,
                          uint8_t *buf, size_t length, uint32_t *data_flags,
                          nghttp2_data_source *source, void *user_data)
{
    struct magnus_h2_stream *stream = source->ptr;
    size_t available = stream->io_length - stream->io_sent;
    (void) session;
    (void) stream_id;
    (void) user_data;
    if (available == 0) {
        if (stream->response_complete) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }
        stream->deferred = true;
        return NGHTTP2_ERR_DEFERRED;
    }
    if (length > available) length = available;
    memcpy(buf, stream->io_buffer + stream->io_sent, length);
    stream->io_sent += length;
    if (stream->io_sent == stream->io_length) {
        stream->io_length = 0;
        stream->io_sent = 0;
        if (stream->response_complete) *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return (nghttp2_ssize) length;
}

/* Submits a complete, already-known, in-memory text response --
 * /healthz and /metrics (roadmap 1e-4) are the only callers -- using the
 * same stream->io_buffer/magnus_h2_read_io_buffer() plumbing the proxy
 * path streams an upstream response body through, just with the whole
 * body copied in and response_complete set to true from the very start:
 * nothing here ever needs to defer, since there is no upstream (or
 * anything else asynchronous) to wait on. */
static void
magnus_h2_submit_text(magnus_connection_t *connection,
                      struct magnus_h2_stream *stream, const char *status,
                      const char *content_type, const char *body,
                      bool head_only)
{
    nghttp2_session *session = connection->h2_session;
    size_t body_length = strlen(body);
    char content_length[32];
    nghttp2_nv headers[4];

    snprintf(content_length, sizeof(content_length), "%zu", body_length);
    headers[0] = magnus_h2_nv(":status", status);
    headers[1] = magnus_h2_nv("server", "Magnus/" MAGNUS_VERSION);
    headers[2] = magnus_h2_nv("content-type", content_type);
    headers[3] = magnus_h2_nv("content-length", content_length);

    if (head_only || body_length == 0) {
        (void) nghttp2_submit_response2(session, stream->stream_id, headers, 4,
                                        NULL);
        return;
    }
    stream->io_buffer = malloc(body_length);
    if (stream->io_buffer == NULL) {
        magnus_h2_submit_status(session, stream->stream_id, "500");
        return;
    }
    memcpy(stream->io_buffer, body, body_length);
    stream->io_length = body_length;
    stream->io_sent = 0;
    stream->response_complete = true;
    {
        nghttp2_data_provider2 data_provider = {
            .source = { .ptr = stream },
            .read_callback = magnus_h2_read_io_buffer,
        };
        (void) nghttp2_submit_response2(session, stream->stream_id, headers, 4,
                                        &data_provider);
    }
}

/* Converts a magnus_proxy_sanitize_response_headers() text block (status
 * line + hop-by-hop-stripped, framing-rewritten headers, already
 * NUL-terminated and mutated in place by that call) into h2 response
 * headers and submits them. The `Connection` header sanitize always
 * appends is dropped -- forbidden in HTTP/2 by RFC 9113 8.2.2, and
 * meaningless there regardless (an h2 stream's lifetime is governed by
 * END_STREAM/RST_STREAM/GOAWAY, not a client-facing keep-alive/close
 * choice per response) -- every other header (Content-Type,
 * Content-Length, an affinity Set-Cookie, X-Magnus-Via, ...) is
 * forwarded as-is, lowercased (h2 field names must be lowercase; an
 * HTTP/1.x upstream's are not guaranteed to be). */
static void
magnus_h2_proxy_submit_response(magnus_connection_t *connection,
                                struct magnus_h2_stream *stream,
                                unsigned status, char *sanitized)
{
    nghttp2_nv headers[24];
    char name_storage[24][64];
    size_t count = 0;
    char status_text[8];
    char *saveptr = NULL;
    char *line;

    snprintf(status_text, sizeof(status_text), "%u", status);
    headers[count] = magnus_h2_nv(":status", status_text);
    count++;

    strtok_r(sanitized, "\r\n", &saveptr); /* status line, already captured */
    for (line = strtok_r(NULL, "\r\n", &saveptr);
         line != NULL && count < sizeof(headers) / sizeof(headers[0]);
         line = strtok_r(NULL, "\r\n", &saveptr)) {
        char *colon = strchr(line, ':');
        char *value;
        size_t name_length;
        if (colon == NULL) continue;
        name_length = (size_t) (colon - line);
        if (name_length == 0 || name_length >= sizeof(name_storage[0]))
            continue;
        memcpy(name_storage[count], line, name_length);
        name_storage[count][name_length] = '\0';
        for (size_t i = 0; i < name_length; i++)
            name_storage[count][i]
                = (char) tolower((unsigned char) name_storage[count][i]);
        if (strcmp(name_storage[count], "connection") == 0) continue;
        value = colon + 1;
        while (*value == ' ' || *value == '\t') value++;
        headers[count] = magnus_h2_nv(name_storage[count], value);
        count++;
    }

    stream->response_headers_submitted = true;
    {
        nghttp2_data_provider2 data_provider = {
            .source = { .ptr = stream },
            .read_callback = magnus_h2_read_io_buffer,
        };
        (void) nghttp2_submit_response2(connection->h2_session,
                                        stream->stream_id, headers, count,
                                        &data_provider);
    }
}

/* Once the response is known to be fully received from the upstream
 * (Content-Length reached, or the upstream closed), decides -- exactly
 * like the tail of magnus_proxy_flush() for HTTP/1.1 -- whether the
 * upstream leg goes back into the pool or is torn down, and marks
 * response_complete so magnus_h2_read_io_buffer() knows it is safe to
 * report EOF once io_buffer finishes draining rather than DEFERRED. */
static void
magnus_h2_proxy_maybe_complete(struct magnus_h2_stream *stream)
{
    bool complete_by_length = stream->has_response_length
        && stream->response_received >= stream->response_length;
    if (!stream->upstream_eof && !complete_by_length) return;
    stream->response_complete = true;
    if (complete_by_length && stream->upstream_poolable
        && stream->upstream_fd >= 0) {
        int fd = stream->upstream_fd;
        epoll_ctl(magnus_global_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        magnus_h2_upstream_owner[fd] = NULL;
        stream->upstream_fd = -1;
        magnus_pool_checkin(stream->endpoint_index, fd,
                            stream->upstream_requests_served + 1);
    } else {
        magnus_h2_stream_teardown_upstream(stream);
    }
}

/* The h2 analogue of magnus_proxy_receive_headers(): accumulates the
 * upstream response's status line + header block (which may arrive
 * split across several recv() calls) into stream->io_buffer, then
 * rewrites it via magnus_proxy_sanitize_response_headers() -- the exact
 * same hop-by-hop-stripping/framing logic the HTTP/1.1 path uses --
 * once the terminating blank line is found, and submits it as this
 * stream's h2 response. Leftover bytes already read past the header
 * block become the first chunk of body. Returns true once headers were
 * fully received (whether the outcome was a clean submit or a failure
 * this stream is now done for), false while still waiting for more. */
static bool
magnus_h2_proxy_receive_headers(magnus_connection_t *connection,
                                struct magnus_h2_stream *stream)
{
    char *body_start;
    size_t header_length;
    size_t leftover;
    char header_copy[MAGNUS_PROXY_HEADER_LIMIT + 1];
    char sanitized[MAGNUS_PROXY_SANITIZED_LIMIT];
    magnus_proxy_response_info_t info;
    int sanitized_length;

    while (stream->header_accum < MAGNUS_PROXY_BUFFER) {
        ssize_t received = recv(stream->upstream_fd,
            stream->io_buffer + stream->header_accum,
            MAGNUS_PROXY_BUFFER - stream->header_accum, 0);
        if (received > 0) {
            stream->header_accum += (size_t) received;
            stream->last_activity = time(NULL);
            if (magnus_find_header_end(stream->io_buffer, stream->header_accum)
                != NULL)
                break;
            continue;
        }
        if (received == 0) {
            stream->upstream_eof = true;
            break;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return false;
        magnus_h2_proxy_connect_failed(connection, stream, "502");
        return true;
    }

    body_start = magnus_find_header_end(stream->io_buffer, stream->header_accum);
    if (body_start == NULL) {
        if (stream->upstream_eof
            || stream->header_accum == MAGNUS_PROXY_BUFFER) {
            magnus_h2_proxy_connect_failed(connection, stream, "502");
            return true;
        }
        return false;
    }

    header_length = (size_t) (body_start - stream->io_buffer);
    leftover = stream->header_accum - header_length;
    if (header_length > MAGNUS_PROXY_HEADER_LIMIT) {
        magnus_h2_proxy_connect_failed(connection, stream, "502");
        return true;
    }
    memcpy(header_copy, stream->io_buffer, header_length);
    header_copy[header_length] = '\0';
    sanitized_length = magnus_proxy_sanitize_response_headers(header_copy,
        header_length, sanitized, sizeof(sanitized),
        stream->issue_affinity_cookie ? stream->affinity_key : NULL,
        true /* client_wants_close: N/A for h2 -- see magnus_h2_proxy_submit_response()'s
              * own comment on why the Connection header this produces is
              * dropped rather than forwarded either way */, &info);
    if (sanitized_length < 0) {
        magnus_h2_proxy_connect_failed(connection, stream, "502");
        return true;
    }

    if (info.has_content_length && leftover > info.content_length)
        leftover = info.content_length;
    memmove(stream->io_buffer, body_start, leftover);
    stream->io_length = leftover;
    stream->io_sent = 0;
    stream->headers_received = true;
    stream->upstream_poolable = info.upstream_poolable;
    stream->has_response_length = info.has_content_length;
    stream->response_length = info.content_length;
    stream->response_received = leftover;

    magnus_cluster_result(&magnus_cluster, stream->endpoint_index, true,
                          magnus_now_ms());
    magnus_h2_proxy_submit_response(connection, stream, info.status, sanitized);
    magnus_requests_total++;
    if (info.status >= 500) magnus_responses_5xx++;
    else if (info.status >= 400) magnus_responses_4xx++;
    {
        double latency_ms = (double) (magnus_now_ms() - stream->started_ms);
        magnus_record_latency(latency_ms);
        magnus_access_log(stream->request_id, stream->log_method,
                          stream->log_target, info.status, latency_ms);
    }
    magnus_h2_proxy_maybe_complete(stream);
    return true;
}

/* Once headers are received (magnus_h2_proxy_receive_headers() already
 * ran and submitted the h2 response), keeps stream->io_buffer filled
 * from the upstream socket for magnus_h2_read_io_buffer() to pull
 * from, respecting backpressure (never reads more while the buffer
 * still holds bytes nghttp2 has not pulled out yet) and never reading
 * past a declared Content-Length -- exactly the same shape as the tail
 * of magnus_handle_upstream() for HTTP/1.1, adapted to refill a pull
 * buffer instead of writing straight to a client socket. */
static void
magnus_h2_proxy_stream_response(struct magnus_h2_stream *stream)
{
    size_t want;
    ssize_t received;

    if (stream->io_length > stream->io_sent) return; /* backpressure */
    want = MAGNUS_PROXY_BUFFER;
    if (stream->has_response_length) {
        size_t remaining = stream->response_length - stream->response_received;
        if (remaining < want) want = remaining;
    }
    if (want == 0) {
        magnus_h2_proxy_maybe_complete(stream);
        return;
    }
    received = recv(stream->upstream_fd, stream->io_buffer, want, 0);
    if (received > 0) {
        stream->io_length = (size_t) received;
        stream->io_sent = 0;
        stream->response_received += (size_t) received;
        stream->last_activity = time(NULL);
        magnus_h2_proxy_maybe_complete(stream);
        return;
    }
    if (received == 0) {
        stream->upstream_eof = true;
        magnus_h2_proxy_maybe_complete(stream);
        return;
    }
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return;
    magnus_h2_proxy_abort(stream);
}

/* Entry point for any epoll event on a proxy-dispatched stream's
 * upstream fd -- the h2 analogue of magnus_handle_upstream(). Unlike
 * that function, a failure here never means the *client* connection
 * must close: only this one stream is affected (see this block's
 * top-of-section comment), so this always returns 0 for a stream-local
 * outcome and -1 only if pushing the resulting h2 output onto the
 * client fd itself fails (a real client-connection-level problem,
 * exactly like any other h2_session-wide failure magnus_h2_service()
 * itself already treats as connection-fatal). */
static int
magnus_h2_handle_upstream(struct magnus_h2_stream *stream, uint32_t flags)
{
    magnus_connection_t *connection = stream->connection;
    int epoll_fd = magnus_global_epoll_fd;

    if ((flags & (EPOLLERR | EPOLLHUP)) != 0) {
        if (stream->response_headers_submitted) magnus_h2_proxy_abort(stream);
        else magnus_h2_proxy_connect_failed(connection, stream, "502");
        return magnus_h2_push(epoll_fd, connection);
    }
    if (!stream->upstream_connected) {
        int error = 0;
        socklen_t length = sizeof(error);
        if (getsockopt(stream->upstream_fd, SOL_SOCKET, SO_ERROR, &error,
                       &length) < 0 || error != 0) {
            magnus_h2_proxy_connect_failed(connection, stream, "502");
            return magnus_h2_push(epoll_fd, connection);
        }
        stream->upstream_connected = true;
        stream->last_activity = time(NULL);
    }
    while (!stream->upstream_headers_sent) {
        ssize_t sent = send(stream->upstream_fd,
            stream->proxy_request + stream->proxy_request_sent,
            stream->proxy_request_length - stream->proxy_request_sent,
            MSG_NOSIGNAL);
        if (sent > 0) {
            stream->proxy_request_sent += (size_t) sent;
            stream->last_activity = time(NULL);
        } else if (sent < 0 && errno == EINTR) {
            continue;
        } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        } else {
            magnus_h2_proxy_connect_failed(connection, stream, "502");
            return magnus_h2_push(epoll_fd, connection);
        }
        if (stream->proxy_request_sent == stream->proxy_request_length)
            stream->upstream_headers_sent = true;
    }
    while (stream->body_sent < stream->body_length) {
        ssize_t sent = send(stream->upstream_fd,
            stream->body + stream->body_sent,
            stream->body_length - stream->body_sent, MSG_NOSIGNAL);
        if (sent > 0) {
            stream->body_sent += (size_t) sent;
            stream->last_activity = time(NULL);
        } else if (sent < 0 && errno == EINTR) {
            continue;
        } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        } else {
            magnus_h2_proxy_connect_failed(connection, stream, "502");
            return magnus_h2_push(epoll_fd, connection);
        }
    }
    if (!stream->headers_received) {
        if ((flags & (EPOLLIN | EPOLLRDHUP)) != 0) {
            if (!magnus_h2_proxy_receive_headers(connection, stream)) {
                struct epoll_event event = { .events = EPOLLIN | EPOLLRDHUP,
                                             .data.fd = stream->upstream_fd };
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, stream->upstream_fd, &event);
                return 0;
            }
        } else {
            /* Just finished connecting and sending the request+body (this
             * call was driven by that EPOLLOUT event, not an EPOLLIN
             * one) -- the fd is still only armed for EPOLLOUT|EPOLLRDHUP
             * from magnus_h2_proxy_attach_upstream(), so it must be
             * switched to watch for the response now, exactly like
             * magnus_handle_upstream() does for HTTP/1.1. */
            struct epoll_event event = { .events = EPOLLIN | EPOLLRDHUP,
                                         .data.fd = stream->upstream_fd };
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, stream->upstream_fd, &event);
            return 0;
        }
    } else if ((flags & (EPOLLIN | EPOLLRDHUP)) != 0) {
        magnus_h2_proxy_stream_response(stream);
    }

    /* Whatever just happened above may have added bytes to io_buffer (or
     * torn the stream down entirely): wake nghttp2 up for this stream if
     * it had gone DEFERRED, then push anything now ready onto the client
     * fd -- nothing else will trigger that push, since this event fired
     * on the *upstream* fd, not the client's. */
    if (stream->deferred
        && (stream->io_length > stream->io_sent || stream->response_complete)) {
        stream->deferred = false;
        (void) nghttp2_session_resume_data(connection->h2_session,
                                           stream->stream_id);
    }
    return magnus_h2_push(epoll_fd, connection);
}

static char *
magnus_find_header_end(char *buffer, size_t length)
{
    size_t index;
    for (index = 3; index < length; index++) {
        if (buffer[index - 3] == '\r' && buffer[index - 2] == '\n'
            && buffer[index - 1] == '\r' && buffer[index] == '\n') {
            return &buffer[index + 1];
        }
    }
    return NULL;
}

static void
magnus_prepare_response(magnus_connection_t *connection, unsigned status,
                        const char *reason, const char *content_type,
                        const char *body, bool head_only, bool close_connection,
                        magnus_request_t *request)
{
    size_t body_length = strlen(body);
    int written;

    request->status = status;
    magnus_requests_total++;
    if (status >= 500) magnus_responses_5xx++;
    else if (status >= 400) magnus_responses_4xx++;
    (void) magnus_phase_run(&magnus_phases, MAGNUS_PHASE_RESPONSE, request);
    written = snprintf(connection->output, sizeof(connection->output),
        "HTTP/1.1 %u %s\r\n"
        "Server: Magnus/%s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "X-Magnus-Engine: native-c17/0.1\r\n"
        "X-Magnus-Request-Id: %s\r\n"
        "X-Magnus-Phases: ingress,route,response\r\n"
        "\r\n%s",
        status, reason, MAGNUS_VERSION, content_type, body_length,
        close_connection ? "close" : "keep-alive", request->request_id,
        head_only ? "" : body);
    if (written < 0 || (size_t) written >= sizeof(connection->output)) {
        connection->output_length = 0;
        connection->close_after_write = true;
        return;
    }
    connection->output_length = (size_t) written;
    connection->output_sent = 0;
    connection->close_after_write = close_connection;
}

/* Renders the Prometheus text-exposition-format /metrics body into
 * `out` (an at-least-MAGNUS_METRICS_BUFFER-byte buffer), NUL-terminated.
 * Shared by both the HTTP/1.1 dispatch path below and the HTTP/2 one
 * (magnus_h2_dispatch_metrics(), roadmap 1e-4) so the two protocols
 * cannot drift into reporting different numbers for the same process. */
static void
magnus_build_metrics(char *out, size_t out_capacity)
{
    size_t written;
    size_t healthy = 0;
    for (size_t index = 0; index < magnus_cluster.count; index++) {
        if (magnus_cluster.endpoints[index].healthy) healthy++;
    }
    written = (size_t) snprintf(out, out_capacity,
        "# TYPE magnus_connections_total counter\n"
        "magnus_connections_total %llu\n"
        "# TYPE magnus_connections_active gauge\n"
        "magnus_connections_active %llu\n"
        "# TYPE magnus_requests_total counter\n"
        "magnus_requests_total %llu\n"
        "magnus_responses_4xx_total %llu\n"
        "magnus_responses_5xx_total %llu\n"
        "magnus_bytes_sent_total %llu\n"
        "magnus_rate_limited_total %llu\n"
        "# TYPE magnus_upstream_endpoints gauge\n"
        "magnus_upstream_endpoints_total %zu\n"
        "magnus_upstream_endpoints_healthy %zu\n",
        (unsigned long long) magnus_connections_total,
        (unsigned long long) magnus_connections_active,
        (unsigned long long) magnus_requests_total,
        (unsigned long long) magnus_responses_4xx,
        (unsigned long long) magnus_responses_5xx,
        (unsigned long long) magnus_bytes_sent,
        (unsigned long long) magnus_rate_limited_total,
        magnus_cluster.count, healthy);
    for (size_t index = 0; index < magnus_cluster.count
         && written < out_capacity; index++) {
        int line = snprintf(out + written, out_capacity - written,
            "magnus_upstream_healthy{endpoint=\"%s:%u\"} %d\n",
            magnus_cluster.endpoints[index].address,
            magnus_cluster.endpoints[index].port,
            magnus_cluster.endpoints[index].healthy ? 1 : 0);
        if (line < 0 || (size_t) line >= out_capacity - written) return;
        written += (size_t) line;
    }
    if (written < out_capacity) {
        int line = snprintf(out + written, out_capacity - written,
            "# TYPE magnus_request_duration_milliseconds histogram\n");
        if (line > 0 && (size_t) line < out_capacity - written)
            written += (size_t) line;
    }
    for (size_t index = 0; index < MAGNUS_LATENCY_BUCKETS
         && written < out_capacity; index++) {
        int line = snprintf(out + written, out_capacity - written,
            "magnus_request_duration_milliseconds_bucket{le=\"%g\"} %llu\n",
            magnus_latency_bucket_bounds_ms[index],
            (unsigned long long) magnus_latency_bucket_counts[index]);
        if (line < 0 || (size_t) line >= out_capacity - written) return;
        written += (size_t) line;
    }
    if (written < out_capacity) {
        int line = snprintf(out + written, out_capacity - written,
            "magnus_request_duration_milliseconds_bucket{le=\"+Inf\"} %llu\n"
            "magnus_request_duration_milliseconds_sum %.2f\n"
            "magnus_request_duration_milliseconds_count %llu\n",
            (unsigned long long) magnus_latency_count,
            magnus_latency_sum_ms,
            (unsigned long long) magnus_latency_count);
        if (line > 0 && (size_t) line < out_capacity - written)
            written += (size_t) line;
    }
}

/* Runs the already-parsed request through ingress/route, rate limiting,
 * and the final route dispatch (static file, proxy, healthz/metrics,
 * admin). connection->body/body_length carry whatever request body was
 * buffered ahead of this call (empty for the overwhelmingly common
 * no-body case) -- see magnus_begin_body()/magnus_continue_body() and
 * magnus_process_request() below, which is what parses the request and
 * decides whether a body needs buffering before dispatch can even run.
 * Returns 1 if a reverse-proxy attempt is now in flight (body ownership,
 * if any, has moved to it -- see magnus_free_body_if_unowned()), 0
 * otherwise (fully handled synchronously, body if any no longer needed). */
static int
magnus_dispatch_request(int epoll_fd, magnus_connection_t *connection,
                        const magnus_http_request_t *parsed)
{
    magnus_request_t request = {0};
    bool close_connection = parsed->close_connection;
    bool head_only = parsed->head_only;
    bool is_proxy_route;
    bool literal_proxy_prefix;
    bool route_denied = false;
    const char *proxy_forward_path;

    memcpy(request.method, parsed->method, sizeof(request.method));
    memcpy(request.path, parsed->target, sizeof(request.path));

    literal_proxy_prefix = magnus_upstream_enabled && !connection->admin_only
        && strncmp(request.path, "/proxy", 6) == 0
        && (request.path[6] == '/' || request.path[6] == '\0');
    is_proxy_route = literal_proxy_prefix;
    proxy_forward_path = literal_proxy_prefix ? request.path + 6 : request.path;

    /* Routes (advanced host/path/method/header/cookie/query/source-IP
     * matching -- see magnus_route.h) are evaluated in file order, first
     * match wins, ahead of everything else below except the phase hooks.
     * The admin channel is exempt outright, same as it already is from
     * the literal "/proxy" prefix above -- its own routing is that
     * socket's filesystem permissions, not this. An action=static match
     * needs no special handling here: matching and being neither deny nor
     * proxy already falls through to the same static-file dispatch a
     * request with no matching route at all gets, which is the point --
     * it lets a route's *conditions* gate access to it. */
    if (!connection->admin_only) {
        for (size_t r = 0; r < magnus_route_count; r++) {
            if (!magnus_route_matches(&magnus_routes[r], parsed,
                                      connection->client_address))
                continue;
            if (magnus_routes[r].action == MAGNUS_ROUTE_ACTION_PROXY) {
                is_proxy_route = true;
                proxy_forward_path = request.path;
            } else if (magnus_routes[r].action == MAGNUS_ROUTE_ACTION_DENY) {
                route_denied = true;
            }
            break;
        }
    }

    if (magnus_phase_run(&magnus_phases, MAGNUS_PHASE_INGRESS, &request) != 0
        || magnus_phase_run(&magnus_phases, MAGNUS_PHASE_ROUTE, &request) != 0) {
        magnus_prepare_response(connection, 500, "Internal Server Error",
                                "text/plain", "phase error\n", head_only, true,
                                &request);
        return 0;
    }

    /* /healthz and /metrics stay exempt: they are exactly what an operator
     * or monitoring system needs to reach to see *why* real traffic is
     * being throttled, so gating them behind the same limiter would be
     * self-defeating. The admin channel is exempt outright -- access to
     * it is already gated by its socket's own file permissions. */
    if (!connection->admin_only
        && strcmp(request.path, "/healthz") != 0
        && strcmp(request.path, "/metrics") != 0
        && !magnus_rate_check(connection->client_address, time(NULL))) {
        magnus_rate_limited_total++;
        magnus_prepare_response(connection, 429, "Too Many Requests",
                                "text/plain", "rate limit exceeded\n", head_only,
                                true, &request);
        return 0;
    }

    if (route_denied) {
        magnus_prepare_response(connection, 403, "Forbidden", "text/plain",
                                "forbidden\n", head_only, close_connection,
                                &request);
    } else if (strcmp(request.method, "GET") != 0 && !head_only && !is_proxy_route) {
        /* Static files, /healthz, and /metrics are inherently read-only;
         * the reverse proxy is the one route that has always been meant
         * to relay whatever method (and body) the client sent -- see the
         * is_proxy_route branch below, which is why it is excluded here. */
        magnus_prepare_response(connection, 405, "Method Not Allowed",
                                "text/plain", "method not allowed\n", false,
                                close_connection, &request);
    } else if (strcmp(request.path, "/healthz") == 0) {
        magnus_prepare_response(connection, 200, "OK", "text/plain",
                                "magnus: ok\n", head_only, close_connection,
                                &request);
    } else if (strcmp(request.path, "/metrics") == 0
               && (connection->admin_only || !magnus_admin_enabled)) {
        char metrics[MAGNUS_METRICS_BUFFER];
        magnus_build_metrics(metrics, sizeof(metrics));
        magnus_prepare_response(connection, 200, "OK",
                                "text/plain; version=0.0.4", metrics,
                                head_only, close_connection, &request);
    } else if (connection->admin_only) {
        /* Everything else is off-limits on the admin channel. */
        magnus_prepare_response(connection, 404, "Not Found", "text/plain",
                                "not found\n", head_only, close_connection,
                                &request);
    } else if (is_proxy_route) {
        if (magnus_proxy_pick_and_start(epoll_fd, connection, &request, parsed,
                                        proxy_forward_path,
                                        parsed->affinity_key,
                                        close_connection) == 0) {
            /* No access-log line here: the request has not completed yet
             * (that happens later, asynchronously, once the upstream
             * responds -- see magnus_proxy_receive_headers/_fail). Just
             * remember what the client asked for so that completion line
             * can still report it. */
            strncpy(connection->proxy_log_method, request.method,
                   sizeof(connection->proxy_log_method) - 1);
            connection->proxy_log_method[
                sizeof(connection->proxy_log_method) - 1] = '\0';
            strncpy(connection->proxy_log_target, request.path,
                   sizeof(connection->proxy_log_target) - 1);
            connection->proxy_log_target[
                sizeof(connection->proxy_log_target) - 1] = '\0';
            return 1;
        }
        magnus_prepare_response(connection, 502, "Bad Gateway", "text/plain",
                                "bad gateway\n", head_only, true, &request);
    } else if (strcmp(request.path, "/") == 0) {
        magnus_prepare_response(connection, 200, "OK", "application/json",
                                "{\"name\":\"Magnus\",\"engine\":\"native-c17\",\"status\":\"ready\"}\n",
                                head_only, close_connection, &request);
    } else {
        struct stat metadata;
        int file_fd = magnus_open_static(request.path, &metadata);
        if (file_fd >= 0)
            magnus_prepare_file_response(connection, file_fd, &metadata,
                                         head_only, close_connection, &request);
        else
            magnus_prepare_response(connection, 404, "Not Found", "text/plain",
                                    "not found\n", head_only, close_connection,
                                    &request);
    }
    (void) magnus_phase_run(&magnus_phases, MAGNUS_PHASE_LOG, &request);
    {
        double latency_ms = (double) (magnus_now_ms()
                                      - connection->request_started_ms);
        magnus_record_latency(latency_ms);
        magnus_access_log(request.request_id, request.method, request.path,
                          request.status, latency_ms);
    }
    return 0;
}

/* ---- h2c (roadmap Phase 1e-5): cleartext HTTP/2, plain listener only.
 * See MAGNUS_H2C_PREFACE's own top-of-file comment for the two entry
 * points (prior knowledge, Upgrade: h2c) this section implements. */

/* True if `parsed` is a well-formed Upgrade: h2c request this connection
 * should actually accept -- decodes the HTTP2-Settings header into
 * `settings_out` (at least MAGNUS_H2C_SETTINGS_MAX bytes) as a side
 * effect of returning true, since the caller needs it immediately
 * afterward and re-finding/re-decoding the same header a second time
 * would be redundant. Deliberately declines (returns false, indistinguishable
 * from "not an upgrade request at all" -- the request is simply handled
 * as ordinary HTTP/1.1) whenever the request carries a body: RFC 9113
 * 3.2 permits an Upgrade: h2c request to have one (it becomes the first
 * DATA on stream 1), but that needs the body-buffering machinery
 * (magnus_begin_body()/magnus_continue_body()) to finish *before* the
 * upgrade can proceed, which this increment does not wire up -- the
 * overwhelmingly common real-world case (a GET priming a connection for
 * h2) has no body at all, so this is a narrow, explicit scope boundary,
 * not a silent gap. h2c is never offered on a TLS connection (it is
 * exclusively the plain-listener entry point; TLS already has ALPN,
 * 1e-1) or the admin channel (matching every other h2 code path's own
 * `admin_only` exclusion -- see magnus_h2_dispatch()'s comment on why). */
static bool
magnus_h2c_upgrade_eligible(magnus_connection_t *connection,
                            const magnus_http_request_t *parsed,
                            unsigned char *settings_out,
                            size_t *settings_length)
{
    const char *connection_header;
    const char *upgrade_header;
    const char *settings_header;
    int decoded;

    if (connection->tls != NULL || connection->admin_only) return false;
    if (parsed->has_content_length && parsed->content_length > 0) return false;

    upgrade_header = magnus_http_header_find(parsed, "upgrade");
    if (upgrade_header == NULL || strcasecmp(upgrade_header, "h2c") != 0)
        return false;
    connection_header = magnus_http_header_find(parsed, "connection");
    if (connection_header == NULL
        || strcasestr(connection_header, "upgrade") == NULL)
        return false;
    settings_header = magnus_http_header_find(parsed, "http2-settings");
    if (settings_header == NULL || settings_header[0] == '\0') return false;

    decoded = magnus_base64url_decode(settings_header, strlen(settings_header),
                                      settings_out, MAGNUS_H2C_SETTINGS_MAX);
    if (decoded < 0) return false;
    *settings_length = (size_t) decoded;
    return true;
}

/* Queues the `101 Switching Protocols` response and stashes everything
 * magnus_h2c_activate() will need once it has actually gone out --
 * queues, not sends: connection->output is drained the same way any
 * other synchronous response is, through the ordinary
 * magnus_handle_write() path, so the 101 status line is guaranteed to
 * reach the client before this connection ever starts emitting real h2
 * bytes after it, even if the write has to span more than one
 * non-blocking attempt. Infallible by construction (a fixed-size literal
 * response, no interpolated values, trivially within
 * MAGNUS_OUTPUT_LIMIT) -- unlike every other response builder in this
 * file, so it does not need magnus_process_request()'s caller chain to
 * plumb a fatal-error return value through the `1 = proxy in flight, 0 =
 * handled synchronously` contract those callers already share. */
static void
magnus_h2c_begin_upgrade(magnus_connection_t *connection,
                         const magnus_http_request_t *parsed,
                         const unsigned char *settings_payload,
                         size_t settings_length)
{
    static const char response[] =
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
        "Upgrade: h2c\r\n\r\n";
    memcpy(connection->output, response, sizeof(response) - 1);
    connection->output_length = sizeof(response) - 1;
    connection->output_sent = 0;
    connection->close_after_write = false;
    connection->pending_parsed = *parsed;
    memcpy(connection->h2c_settings, settings_payload, settings_length);
    connection->h2c_settings_length = settings_length;
    connection->h2c_pending = true;
}

/* Called from magnus_handle_write() the moment the 101 response has
 * fully flushed: creates the h2 session, hands nghttp2 the client's
 * already-decoded HTTP2-Settings via nghttp2_session_upgrade2() (which
 * treats it as if a SETTINGS frame had just been received, and opens
 * stream 1 in half-closed-remote state -- the client is not going to
 * send anything more on it, since everything it had to say already
 * arrived as the original HTTP/1.1 request), attaches a
 * magnus_h2_stream to that stream, copies the already-parsed original
 * request into it directly (both use the exact same
 * magnus_http_request_t shape -- no re-derivation needed), and
 * dispatches it immediately, exactly as if its END_STREAM had just been
 * observed (nothing will ever trigger that callback for a stream that
 * was never really delivered as HEADERS frames in the first place). Any
 * bytes already sitting in connection->input past the original request
 * are the client's own optimistic h2 frames -- RFC 9113 3.2 explicitly
 * allows sending them without waiting for the 101 -- fed in immediately
 * afterward. */
static int
magnus_h2c_activate(int epoll_fd, magnus_connection_t *connection)
{
    struct magnus_h2_stream *stream;
    bool head_request;

    connection->h2c_pending = false;
    if (magnus_h2_session_create(connection) != 0) return -1;
    head_request = strcmp(connection->pending_parsed.method, "HEAD") == 0;
    if (nghttp2_session_upgrade2(connection->h2_session, connection->h2c_settings,
                                 connection->h2c_settings_length,
                                 head_request ? 1 : 0, NULL) != 0)
        return -1;
    stream = magnus_h2_stream_new(connection, 1);
    if (stream == NULL) return -1;
    if (nghttp2_session_set_stream_user_data(connection->h2_session, 1,
                                             stream) != 0) {
        magnus_h2_stream_free(stream);
        return -1;
    }
    stream->parsed = connection->pending_parsed;
    magnus_h2_dispatch(connection, stream);

    if (connection->input_length > 0) {
        nghttp2_ssize consumed = nghttp2_session_mem_recv2(connection->h2_session,
            (const uint8_t *) connection->input, connection->input_length);
        if (consumed < 0) return -1;
        connection->input_length = 0;
    }
    return magnus_h2_push(epoll_fd, connection);
}

/* Called from magnus_handle_read() on a plain (non-TLS, non-admin)
 * connection's every read until it resolves one way or the other (see
 * checked_h2c_preface's own comment): compares whatever has accumulated
 * in connection->input so far against MAGNUS_H2C_PREFACE. Returns 0 if
 * it is still a matching prefix (more bytes needed before the decision
 * can be made -- do not attempt HTTP/1.1 parsing yet), 1 if it has
 * definitively diverged (this is an ordinary HTTP/1.1 connection;
 * checked_h2c_preface is now permanently true and the caller should
 * proceed exactly as if this check did not exist), 2 if it was a
 * confirmed full match and the connection is now h2_active with its
 * epoll interest already armed (via magnus_h2_push()) -- the caller has
 * nothing further to do for this read -- or -1 if any of that setup
 * failed (fatal; the caller must close the connection, same as every
 * other -1 in this file). */
static int
magnus_h2c_check_preface(int epoll_fd, magnus_connection_t *connection)
{
    size_t compare_length = connection->input_length < MAGNUS_H2C_PREFACE_LEN
        ? connection->input_length : MAGNUS_H2C_PREFACE_LEN;
    if (memcmp(connection->input, MAGNUS_H2C_PREFACE, compare_length) != 0) {
        connection->checked_h2c_preface = true;
        return 1;
    }
    if (connection->input_length < MAGNUS_H2C_PREFACE_LEN) return 0;
    connection->checked_h2c_preface = true;
    if (magnus_h2_session_create(connection) != 0) return -1;
    {
        nghttp2_ssize consumed = nghttp2_session_mem_recv2(connection->h2_session,
            (const uint8_t *) connection->input, connection->input_length);
        if (consumed < 0) return -1;
    }
    connection->input_length = 0;
    if (magnus_h2_push(epoll_fd, connection) < 0) return -1;
    return 2;
}

/* Parses the request line/headers already accumulated in connection->input
 * (exactly request_length bytes, no body) and dispatches it. Only ever
 * reached for a request that magnus_process_input() has already determined
 * has no body to buffer -- see magnus_begin_body() for the one that does. */
static int
magnus_process_request(int epoll_fd, magnus_connection_t *connection,
                       size_t request_length)
{
    magnus_http_request_t parsed;
    magnus_http_result_t parse_result;

    parse_result = magnus_http_parse(connection->input, request_length, &parsed);
    if (parse_result != MAGNUS_HTTP_OK) {
        magnus_request_t request = {0};
        unsigned status = parse_result == MAGNUS_HTTP_URI_TOO_LONG ? 414
            : parse_result == MAGNUS_HTTP_VERSION_UNSUPPORTED ? 505 : 400;
        const char *reason = status == 414 ? "URI Too Long"
            : status == 505 ? "HTTP Version Not Supported" : "Bad Request";
        magnus_trace_handler(&request, NULL);
        magnus_prepare_response(connection, status, reason, "text/plain",
                                "bad request\n", false, true, &request);
        return 0;
    }
    {
        unsigned char settings_payload[MAGNUS_H2C_SETTINGS_MAX];
        size_t settings_length;
        if (magnus_h2c_upgrade_eligible(connection, &parsed, settings_payload,
                                        &settings_length)) {
            magnus_h2c_begin_upgrade(connection, &parsed, settings_payload,
                                     settings_length);
            return 0;
        }
    }
    return magnus_dispatch_request(epoll_fd, connection, &parsed);
}

/* Frees connection->body unless magnus_dispatch_request() just handed it
 * off to an in-flight reverse-proxy attempt (dispatch_result == 1), in
 * which case magnus_handle_upstream() owns it from here -- either relaying
 * it and freeing it itself once fully sent, or leaving it for
 * magnus_close_connection()'s safety net if the connection closes first. */
static void
magnus_free_body_if_unowned(magnus_connection_t *connection, int dispatch_result)
{
    if (dispatch_result == 1) return;
    free(connection->body);
    connection->body = NULL;
    connection->body_capacity = 0;
    connection->body_length = 0;
    connection->body_needed = 0;
}

/* Called once magnus_process_input() has determined the just-parsed
 * request (parsed, covering exactly the first request_length bytes of
 * connection->input) carries a Content-Length body. Buffers whatever body
 * bytes already arrived in the same read as the headers, separates them
 * from any pipelined next request sitting after them, and either
 * dispatches immediately (the whole body was already in hand) or switches
 * the connection into body-accumulation mode for magnus_continue_body()
 * to finish across future reads. */
static int
magnus_begin_body(int epoll_fd, magnus_connection_t *connection,
                  size_t request_length, const magnus_http_request_t *parsed)
{
    size_t available_after_headers;
    size_t take;
    size_t consumed;

    if (parsed->content_length > MAGNUS_MAX_BODY) {
        magnus_request_t request = {0};
        magnus_trace_handler(&request, NULL);
        memcpy(request.method, parsed->method, sizeof(request.method));
        memcpy(request.path, parsed->target, sizeof(request.path));
        magnus_prepare_response(connection, 413, "Payload Too Large",
                                "text/plain", "payload too large\n", false,
                                true, &request);
        /* Closing the connection either way (close_connection forced true
         * above), so there is no next request to preserve framing for --
         * simplest and safest to just drop whatever is left unread. */
        connection->input_length = 0;
        return magnus_update_interest(epoll_fd, connection, EPOLLOUT);
    }

    connection->body = malloc(parsed->content_length > 0
                              ? parsed->content_length : 1);
    if (connection->body == NULL) return -1;
    connection->body_capacity = parsed->content_length;
    connection->body_needed = parsed->content_length;
    connection->pending_parsed = *parsed;

    available_after_headers = connection->input_length - request_length;
    take = available_after_headers < connection->body_needed
        ? available_after_headers : connection->body_needed;
    if (take > 0)
        memcpy(connection->body, connection->input + request_length, take);
    connection->body_length = take;

    /* Whatever is left after this request's headers *and* body is the
     * start of a pipelined next request -- keep only that in `input`. */
    consumed = request_length + take;
    memmove(connection->input, connection->input + consumed,
            connection->input_length - consumed);
    connection->input_length -= consumed;

    if (connection->body_length < connection->body_needed) {
        connection->reading_body = true;
        return 0;
    }

    {
        int process_result = magnus_dispatch_request(epoll_fd, connection,
                                                      &connection->pending_parsed);
        magnus_free_body_if_unowned(connection, process_result);
        if (process_result == 1) return 0;
        return magnus_update_interest(epoll_fd, connection, EPOLLOUT);
    }
}

/* Continues filling connection->body from the client socket across
 * however many more non-blocking reads it takes, then dispatches once it
 * is complete. Mirrors magnus_handle_read()'s header-accumulation loop,
 * just against connection->body instead of connection->input. */
static int
magnus_continue_body(int epoll_fd, magnus_connection_t *connection)
{
    ssize_t received;

    while (connection->body_length < connection->body_needed) {
        received = magnus_socket_read(connection,
                        connection->body + connection->body_length,
                        connection->body_needed - connection->body_length);
        if (received > 0) {
            connection->body_length += (size_t) received;
            connection->last_active = time(NULL);
            continue;
        }
        if (received == 0) return -1;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        if (errno == EINTR) continue;
        return -1;
    }

    connection->reading_body = false;
    {
        int process_result = magnus_dispatch_request(epoll_fd, connection,
                                                      &connection->pending_parsed);
        magnus_free_body_if_unowned(connection, process_result);
        if (process_result == 1) return 0;
        return magnus_update_interest(epoll_fd, connection, EPOLLOUT);
    }
}

static int
magnus_process_input(int epoll_fd, magnus_connection_t *connection)
{
    char *end = magnus_find_header_end(connection->input,
                                       connection->input_length);
    size_t request_length;

    if (end == NULL) {
        if (connection->input_length == MAGNUS_INPUT_LIMIT) {
            magnus_request_t request = {0};
            magnus_trace_handler(&request, NULL);
            magnus_prepare_response(connection, 431,
                                    "Request Header Fields Too Large",
                                    "text/plain", "headers too large\n", false,
                                    true, &request);
            return magnus_update_interest(epoll_fd, connection, EPOLLOUT);
        }
        return 0;
    }

    request_length = (size_t) (end - connection->input);
    connection->request_started_ms = magnus_now_ms();

    {
        /* A second parse of the same bytes magnus_process_request() (or
         * magnus_begin_body()) will parse again momentarily -- headers are
         * small and this runs once per request, so the duplicate work is
         * cheap next to what it buys: knowing whether a body needs
         * buffering *before* committing to either path, without threading
         * a pre-parsed request through both. */
        magnus_http_request_t peek;
        if (magnus_http_parse(connection->input, request_length, &peek)
                == MAGNUS_HTTP_OK
            && peek.has_content_length && peek.content_length > 0) {
            return magnus_begin_body(epoll_fd, connection, request_length,
                                     &peek);
        }
    }

    int process_result = magnus_process_request(epoll_fd, connection,
                                                request_length);
    memmove(connection->input, connection->input + request_length,
            connection->input_length - request_length);
    connection->input_length -= request_length;
    if (process_result == 1) return 0;
    return magnus_update_interest(epoll_fd, connection, EPOLLOUT);
}

static int
magnus_handle_read(int epoll_fd, magnus_connection_t *connection)
{
    ssize_t received;
    if (connection->reading_body) return magnus_continue_body(epoll_fd, connection);
    if (connection->input_length == connection->input_capacity
        && connection->input_capacity < MAGNUS_INPUT_LIMIT) {
        size_t capacity = connection->input_capacity * 2;
        char *grown;
        if (capacity > MAGNUS_INPUT_LIMIT) capacity = MAGNUS_INPUT_LIMIT;
        grown = realloc(connection->input, capacity);
        if (grown == NULL) return -1;
        connection->input = grown;
        connection->input_capacity = capacity;
    }
    while (connection->input_length < connection->input_capacity) {
        received = magnus_socket_read(connection,
                        connection->input + connection->input_length,
                        connection->input_capacity - connection->input_length);
        if (received > 0) {
            connection->input_length += (size_t) received;
            connection->last_active = time(NULL);
            /* h2c prior knowledge (1e-5): checked at most once per
             * connection, before ever attempting HTTP/1.1 parsing on it
             * -- see magnus_h2c_check_preface()'s own comment. Must run
             * before magnus_find_header_end() below: a partial preface
             * like "PRI * HTTP/2.0\r\n\r\n" (18 of its 24 bytes) would
             * otherwise look like a complete, if bizarre, HTTP/1.1
             * header block to that check. */
            if (connection->tls == NULL && !connection->admin_only
                && !connection->checked_h2c_preface) {
                int decision = magnus_h2c_check_preface(epoll_fd, connection);
                if (decision == 2) return 0;
                if (decision == -1) return -1;
                if (decision == 0) continue;
                /* decision == 1: definitively not h2c -- fall through to
                 * ordinary HTTP/1.1 processing of what has accumulated,
                 * exactly as if this check did not exist. */
            }
            if (magnus_find_header_end(connection->input,
                                       connection->input_length) != NULL) {
                return magnus_process_input(epoll_fd, connection);
            }
            continue;
        }
        if (received == 0) {
            return -1;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        return -1;
    }
    return magnus_process_input(epoll_fd, connection);
}

static int
magnus_handle_write(int epoll_fd, magnus_connection_t *connection)
{
    ssize_t sent;
    while (connection->output_sent < connection->output_length) {
        sent = magnus_socket_write(connection,
                    connection->output + connection->output_sent,
                    connection->output_length - connection->output_sent);
        if (sent > 0) {
            connection->output_sent += (size_t) sent;
            magnus_bytes_sent += (uint64_t) sent;
            connection->last_active = time(NULL);
            continue;
        }
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        }
        return -1;
    }
    while (connection->tls == NULL && connection->file_fd >= 0
           && connection->file_offset < connection->file_length) {
        sent = sendfile(connection->fd, connection->file_fd,
                        &connection->file_offset,
                        (size_t) (connection->file_length
                                  - connection->file_offset));
        if (sent > 0) {
            magnus_bytes_sent += (uint64_t) sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        return -1;
    }
    while (connection->tls != NULL && connection->file_fd >= 0
           && connection->file_offset < connection->file_length) {
        if (connection->file_buffer_sent == connection->file_buffer_length) {
            if (connection->file_buffer == NULL) {
                connection->file_buffer = malloc(4096);
                if (connection->file_buffer == NULL) return -1;
            }
            ssize_t loaded = pread(connection->file_fd, connection->file_buffer,
                                   4096,
                                   connection->file_offset);
            if (loaded <= 0) return -1;
            connection->file_buffer_length = (size_t) loaded;
            connection->file_buffer_sent = 0;
        }
        sent = magnus_socket_write(connection,
            connection->file_buffer + connection->file_buffer_sent,
            connection->file_buffer_length - connection->file_buffer_sent);
        if (sent > 0) {
            connection->file_buffer_sent += (size_t) sent;
            connection->file_offset += sent;
            magnus_bytes_sent += (uint64_t) sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        return -1;
    }
    if (connection->file_fd >= 0) {
        close(connection->file_fd);
        connection->file_fd = -1;
    }
    if (connection->close_after_write) {
        return -1;
    }
    connection->output_length = 0;
    connection->output_sent = 0;
    /* h2c (1e-5): the 101 Switching Protocols response
     * magnus_h2c_begin_upgrade() queued has now fully reached the
     * client -- switch this connection into h2 mode before falling
     * through to any of the ordinary HTTP/1.1 "what's next" logic below,
     * none of which applies to it anymore. */
    if (connection->h2c_pending) {
        return magnus_h2c_activate(epoll_fd, connection);
    }
    if (connection->input_length > 0
        && magnus_find_header_end(connection->input,
                                  connection->input_length) != NULL) {
        return magnus_process_input(epoll_fd, connection);
    }
    return magnus_update_interest(epoll_fd, connection, EPOLLIN | EPOLLRDHUP);
}

static int
magnus_accept_connections(int epoll_fd, int listener, bool admin)
{
    for (;;) {
        struct sockaddr_in peer_address = {0};
        socklen_t peer_length = sizeof(peer_address);
        /* The admin listener is a Unix domain socket: it has no IPv4 peer
         * address, and access to it is already controlled by the socket
         * file's own permissions, so we do not bother asking for one. */
        int client = admin
            ? accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)
            : accept4(listener, (struct sockaddr *) &peer_address,
                      &peer_length, SOCK_NONBLOCK | SOCK_CLOEXEC);
        magnus_connection_t *connection;
        struct epoll_event event;

        if (client < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (client >= MAGNUS_MAX_FDS) {
            close(client);
            continue;
        }
        if (!admin) {
            /* The admin listener is a Unix domain socket -- TCP_NODELAY
             * does not apply there. On the public listener, without this
             * a keep-alive connection's small response segments sit in
             * Nagle's algorithm waiting for the peer's ACK, which the
             * peer's own delayed-ACK timer can hold off for up to ~40ms;
             * the two stalls compound into a fixed ~40ms floor on every
             * request regardless of load. Connection: close traffic never
             * showed this (a single write immediately followed by close
             * has nothing left to wait for), which is what made it easy
             * to miss until a keep-alive benchmark surfaced it. */
            int one = 1;
            (void) setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one,
                              sizeof(one));
        }
        connection = calloc(1, sizeof(*connection));
        if (connection == NULL) {
            close(client);
            continue;
        }
        connection->input = malloc(MAGNUS_INITIAL_INPUT);
        if (connection->input == NULL) {
            close(client);
            free(connection);
            continue;
        }
        connection->input_capacity = MAGNUS_INITIAL_INPUT;
        connection->fd = client;
        connection->file_fd = -1;
        /* calloc() zero-initializes the rest of the struct, so without
         * this, upstream_fd defaults to 0 (not "no upstream") for every
         * connection that never proxies. magnus_close_connection()'s only
         * "no upstream" check is `>= 0`, so that 0 reads as a real fd to
         * tear down -- silently close()ing fd 0 on every ordinary
         * connection's cleanup. Harmless by pure accident as long as fd 0
         * was inherited stdin magnus never reads -- but the very next
         * unrelated open() elsewhere (SIGHUP reload re-opening the root
         * directory, in particular) then silently lands on fd 0 instead,
         * which is exactly what surfaced this: a reload's new root fd
         * ending up on 0, breaking static file lookups. */
        connection->upstream_fd = -1;
        connection->client_address = peer_address.sin_addr;
        connection->admin_only = admin;
        /* No TLS on the admin channel: it is a local Unix socket, already
         * confidential and access-controlled by filesystem permissions,
         * and keeping it TLS-free keeps the isolation story simple (one
         * fewer thing that could be misconfigured to leak metrics). */
        if (!admin && magnus_tls_context != NULL) {
            connection->tls = SSL_new(magnus_tls_context);
            if (connection->tls == NULL
                || SSL_set_fd(connection->tls, client) != 1) {
                if (connection->tls != NULL) SSL_free(connection->tls);
                close(client);
                free(connection->input);
                free(connection);
                continue;
            }
            SSL_set_accept_state(connection->tls);
        } else {
            connection->tls_ready = true;
        }
        connection->last_active = time(NULL);
        connection->header_deadline =
            connection->last_active + MAGNUS_HEADER_TIMEOUT_SECONDS;
        magnus_connections[client] = connection;
        event = (struct epoll_event) {
            .events = EPOLLIN | EPOLLRDHUP,
            .data.fd = client
        };
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client, &event) < 0) {
            magnus_connections[client] = NULL;
            close(client);
            if (connection->tls != NULL) SSL_free(connection->tls);
            free(connection->input);
            free(connection);
        } else {
            magnus_connections_total++;
            magnus_connections_active++;
        }
    }
}

static void
magnus_expire_idle(int epoll_fd, time_t now)
{
    int fd;
    for (fd = 0; fd < MAGNUS_MAX_FDS; fd++) {
        magnus_connection_t *connection = magnus_connections[fd];
        if (connection == NULL) continue;
        if (now - connection->last_active > MAGNUS_IDLE_SECONDS) {
            magnus_close_connection(epoll_fd, connection);
            continue;
        }
        /* Slowloris guard: a trickle of bytes keeps resetting last_active
         * above without ever finishing a request, so it alone cannot
         * catch this. Only applies before the first request on this
         * connection has ever completed (request_started_ms == 0) --
         * legitimate keep-alive idling between later requests is exactly
         * what MAGNUS_IDLE_SECONDS above is for. */
        if (connection->request_started_ms == 0
            && now > connection->header_deadline) {
            magnus_close_connection(epoll_fd, connection);
        }
    }
}

/* Bounds how long a proxied request may spend connecting to, or waiting on,
 * an upstream: a stalled connect() is reported as 504 after
 * MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS, and a connected-but-silent upstream
 * (or a stalled write to a slow client while relaying) is reported as 504
 * after MAGNUS_PROXY_READ_TIMEOUT_SECONDS of proxy inactivity. Once
 * response bytes have already reached the client a clean status can no
 * longer be sent, so the connection is aborted instead.
 *
 * Only the connect-stage timeout retries against a different endpoint: a
 * connect() that never completed is exactly the "try elsewhere" case a
 * retry budget exists for. A connected-but-silent upstream is deliberately
 * NOT retried here -- the endpoint already accepted the connection, so
 * retrying would only double the wait (another full read timeout) without
 * addressing a slow responder, which is precisely the retry-storm/tail-
 * latency amplification the retry budget must avoid. */
static void
magnus_expire_proxies(int epoll_fd, time_t now)
{
    int fd;
    for (fd = 0; fd < MAGNUS_MAX_FDS; fd++) {
        magnus_connection_t *connection = magnus_connections[fd];
        int result;
        if (connection == NULL || !connection->proxy_active) continue;
        if (!connection->proxy_connected) {
            if (now - connection->proxy_connect_started
                < MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS) continue;
            result = magnus_proxy_connect_failed(epoll_fd, connection, 504,
                                                 "Gateway Timeout");
        } else if (now - connection->proxy_last_activity
                   >= MAGNUS_PROXY_READ_TIMEOUT_SECONDS) {
            if (connection->proxy_response_started) {
                result = magnus_proxy_abort(epoll_fd, connection);
            } else {
                /* still counts as a passive-health failure even though we
                 * do not retry this request against another endpoint. */
                magnus_cluster_result(&magnus_cluster,
                                      connection->proxy_endpoint_index, false,
                                      magnus_now_ms());
                result = magnus_proxy_fail(epoll_fd, connection, 504,
                                           "Gateway Timeout");
            }
        } else {
            continue;
        }
        if (result < 0 && magnus_connections[connection->fd] != NULL) {
            magnus_close_connection(epoll_fd, connection);
        }
    }

    /* HTTP/2 proxy dispatch (1e-2): the same connect/read timeout budgets
     * as the HTTP/1.1 sweep above, but there is no equivalent of
     * magnus_connections[]'s single set of proxy_* fields to check here
     * -- one h2 connection can have many streams each proxying
     * concurrently, so every open stream on every h2-active connection
     * needs its own check. */
    for (fd = 0; fd < MAGNUS_MAX_FDS; fd++) {
        magnus_connection_t *connection = magnus_connections[fd];
        struct magnus_h2_stream *stream;
        bool push_needed = false;
        if (connection == NULL || !connection->h2_active) continue;
        for (stream = connection->h2_streams; stream != NULL;
             stream = stream->next) {
            if (!stream->is_proxy || stream->upstream_fd < 0) continue;
            if (!stream->upstream_connected) {
                if (now - stream->connect_started
                    < MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS) continue;
                magnus_h2_proxy_connect_failed(connection, stream, "504");
                push_needed = true;
            } else if (now - stream->last_activity
                       >= MAGNUS_PROXY_READ_TIMEOUT_SECONDS) {
                if (stream->response_headers_submitted) {
                    magnus_h2_proxy_abort(stream);
                } else {
                    magnus_cluster_result(&magnus_cluster,
                                          stream->endpoint_index, false,
                                          magnus_now_ms());
                    magnus_h2_proxy_fail(connection, stream, "504");
                }
                push_needed = true;
            }
        }
        if (push_needed && magnus_h2_push(epoll_fd, connection) < 0
            && magnus_connections[connection->fd] != NULL) {
            magnus_close_connection(epoll_fd, connection);
        }
    }
}

/* Active health checking: independent of live traffic, periodically opens
 * a bare non-blocking TCP connect() to each cluster endpoint and feeds the
 * outcome into the same magnus_cluster_result() passive-health state that
 * real proxy traffic feeds, so an endpoint can be found (and recover) even
 * while it is receiving no requests at all. */

static void
magnus_health_close_probe(int epoll_fd, size_t index)
{
    int fd = magnus_health_probe_fd[index];
    if (fd < 0) return;
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    magnus_health_probe_owner[fd] = 0;
    close(fd);
    magnus_health_probe_fd[index] = -1;
}

static void
magnus_health_start_probe(int epoll_fd, size_t index, time_t now)
{
    struct sockaddr_in address;
    struct epoll_event event;
    int fd;
    int result;

    if (!magnus_endpoint_sockaddr(index, &address)) return;
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0 || fd >= MAGNUS_MAX_FDS) {
        if (fd >= 0) close(fd);
        return;
    }
    result = connect(fd, (struct sockaddr *) &address, sizeof(address));
    if (result < 0 && errno != EINPROGRESS) {
        close(fd);
        magnus_cluster_result(&magnus_cluster, index, false, magnus_now_ms());
        return;
    }
    event = (struct epoll_event) { .events = EPOLLOUT | EPOLLRDHUP,
                                   .data.fd = fd };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        close(fd);
        return;
    }
    magnus_health_probe_fd[index] = fd;
    magnus_health_probe_owner[fd] = (int) (index + 1);
    magnus_health_probe_started[index] = now;
    if (result == 0) {
        /* connected synchronously (typical for loopback/LAN targets):
         * resolve immediately instead of waiting on an epoll event that a
         * level-triggered, already-satisfied condition may not re-deliver. */
        magnus_cluster_result(&magnus_cluster, index, true, magnus_now_ms());
        magnus_health_close_probe(epoll_fd, index);
    }
}

static void
magnus_health_handle_probe(int epoll_fd, size_t index, uint32_t flags)
{
    int fd = magnus_health_probe_fd[index];
    bool success = false;
    if (fd < 0) return;
    if ((flags & (EPOLLERR | EPOLLHUP)) == 0) {
        int error = 0;
        socklen_t length = sizeof(error);
        success = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0
                   && error == 0;
    }
    magnus_cluster_result(&magnus_cluster, index, success, magnus_now_ms());
    magnus_health_close_probe(epoll_fd, index);
}

static void
magnus_health_tick(int epoll_fd, time_t now)
{
    size_t index;
    for (index = 0; index < magnus_cluster.count; index++) {
        if (magnus_health_probe_fd[index] >= 0) {
            if (now - magnus_health_probe_started[index]
                >= MAGNUS_HEALTH_PROBE_TIMEOUT_SECONDS) {
                magnus_cluster_result(&magnus_cluster, index, false,
                                      magnus_now_ms());
                magnus_health_close_probe(epoll_fd, index);
            }
            continue;
        }
        if (now - magnus_health_last_probe[index]
            >= MAGNUS_HEALTH_CHECK_INTERVAL_SECONDS) {
            magnus_health_last_probe[index] = now;
            magnus_health_start_probe(epoll_fd, index, now);
        }
    }
}

static int
magnus_create_listener(unsigned port)
{
    int listener;
    int enabled = 1;
    struct sockaddr_in address = {0};

    listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener < 0) {
        return -1;
    }
    if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled,
                   sizeof(enabled)) < 0) {
        close(listener);
        return -1;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((uint16_t) port);
    if (bind(listener, (struct sockaddr *) &address, sizeof(address)) < 0
        || listen(listener, SOMAXCONN) < 0) {
        close(listener);
        return -1;
    }
    return listener;
}

/* Binds the admin-only Unix domain socket listener at `path`: mode 0700
 * (owner-only) is the access control for /healthz and /metrics on this
 * channel, in place of an in-process RBAC layer -- whoever can reach this
 * socket file can reach admin endpoints, same as any other Unix socket
 * service. A stale socket file from a previous run (e.g. an unclean
 * shutdown) is removed first so bind() does not fail with EADDRINUSE. */
static int
magnus_create_admin_listener(const char *path)
{
    int listener;
    struct sockaddr_un address = {0};

    if (strlen(path) >= sizeof(address.sun_path)) return -1;
    listener = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listener < 0) return -1;
    unlink(path);
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, path);
    if (bind(listener, (struct sockaddr *) &address, sizeof(address)) < 0
        || chmod(path, 0700) < 0 || listen(listener, SOMAXCONN) < 0) {
        close(listener);
        unlink(path);
        return -1;
    }
    return listener;
}

/* Builds new root-fd/TLS-context/cluster/rate-limit state from a validated
 * config and, only once every referenced resource actually opened
 * successfully, swaps it into the live globals in one shot. Since magnus
 * is single-threaded (epoll, no worker threads), this swap is atomic from
 * every other execution point's perspective -- there is no window in
 * which another code path could observe half-old/half-new state. It
 * intentionally never touches the listening port or in-flight
 * connections: existing proxy attempts already hold their own connected
 * upstream fd and never re-consult magnus_cluster, and already-open
 * static-file fds and already-established TLS sessions keep working via
 * OpenSSL's own SSL_CTX refcounting -- so in-flight requests "drain"
 * naturally against whatever generation they started under, while every
 * request that begins after this function returns sees the new one.
 * Returns 0 on success, -1 if a filesystem/TLS resource named in the
 * config could not actually be opened despite passing
 * magnus_config_load()'s validation (e.g. removed between check and
 * apply); nothing is changed in that case. */
static int
magnus_apply_config(const magnus_config_t *config)
{
    int new_root_fd = -1;
    SSL_CTX *new_tls_context = NULL;
    magnus_cluster_t new_cluster;
    size_t index;

    if (config->has_root) {
        new_root_fd = open(config->root, O_RDONLY | O_DIRECTORY | O_CLOEXEC
                           | O_NOFOLLOW);
        if (new_root_fd < 0) return -1;
    }
    if (config->has_tls) {
        new_tls_context = SSL_CTX_new(TLS_server_method());
        if (new_tls_context == NULL
            || SSL_CTX_set_min_proto_version(new_tls_context,
                                             TLS1_2_VERSION) != 1
            || SSL_CTX_use_certificate_chain_file(new_tls_context,
                                                  config->tls_cert) != 1
            || SSL_CTX_use_PrivateKey_file(new_tls_context, config->tls_key,
                                           SSL_FILETYPE_PEM) != 1
            || SSL_CTX_check_private_key(new_tls_context) != 1) {
            if (new_tls_context != NULL) SSL_CTX_free(new_tls_context);
            if (new_root_fd >= 0) close(new_root_fd);
            return -1;
        }
        SSL_CTX_set_options(new_tls_context, SSL_OP_NO_COMPRESSION);
        magnus_h2_configure_alpn(new_tls_context);
    }
    magnus_cluster_init(&new_cluster, MAGNUS_CLUSTER_FAILURE_THRESHOLD,
                        MAGNUS_CLUSTER_COOLDOWN_MS);
    for (index = 0; index < config->upstream_count; index++) {
        if (magnus_cluster_add(&new_cluster, config->upstreams[index].address,
                               config->upstreams[index].port,
                               config->upstreams[index].weight) != 0) {
            if (new_tls_context != NULL) SSL_CTX_free(new_tls_context);
            if (new_root_fd >= 0) close(new_root_fd);
            return -1;
        }
    }

    if (magnus_root_fd >= 0) close(magnus_root_fd);
    magnus_root_fd = new_root_fd;
    if (magnus_tls_context != NULL) SSL_CTX_free(magnus_tls_context);
    magnus_tls_context = new_tls_context;
    /* Pooled connections are indexed purely by endpoint *position*
     * (0..count-1), not by address -- after a reload, position N in the
     * new cluster is not necessarily the same backend it was in the old
     * one (an upstream line added, removed, or reordered shifts every
     * index after it). Handing one out under the new cluster without
     * this flush could send a request meant for the new endpoint N to
     * whatever pooled connection happened to be sitting at slot N from
     * before the reload. */
    magnus_pool_close_all();
    magnus_cluster = new_cluster;
    magnus_upstream_enabled = new_cluster.count > 0;
    magnus_dns_apply_upstreams(config->upstreams, config->upstream_count);
    memcpy(magnus_routes, config->routes, sizeof(magnus_routes));
    magnus_route_count = config->route_count;
    magnus_rate_limit_enabled = config->has_rate_limit;
    if (config->has_rate_limit) {
        magnus_rate_limit_rps = config->rate_limit_rps;
        magnus_rate_limit_burst = config->rate_limit_burst;
    }
    magnus_access_log_enabled = config->access_log_enabled;
    magnus_access_log_sample = config->access_log_sample;
    return 0;
}

static void
magnus_handle_reload(void)
{
    magnus_config_t config;
    char error[192];

    if (!magnus_config_mode) {
        fprintf(stderr, "magnus: reload ignored: not started with "
                        "--config, nothing to reload from\n");
        return;
    }
    if (magnus_config_load(magnus_config_path, &config, error, sizeof(error))
        != MAGNUS_CONFIG_OK) {
        fprintf(stderr, "magnus: reload rejected: %s\n", error);
        return;
    }
    if (config.port != magnus_listen_port) {
        fprintf(stderr, "magnus: reload rejected: changing the listening "
                        "port requires a restart (running on %u, config "
                        "has %u)\n", magnus_listen_port, config.port);
        return;
    }
    if (config.has_admin_socket != magnus_admin_enabled
        || (config.has_admin_socket
            && strcmp(config.admin_socket, magnus_admin_socket_path) != 0)) {
        fprintf(stderr, "magnus: reload rejected: changing admin_socket "
                        "requires a restart\n");
        return;
    }
    if (magnus_apply_config(&config) != 0) {
        fprintf(stderr, "magnus: reload rejected: a referenced root/tls "
                        "resource could not be opened\n");
        return;
    }
    fprintf(stderr, "magnus: reload applied generation=%016llx\n",
            (unsigned long long) magnus_config_hash(&config));
}

static unsigned
magnus_parse_options(int argc, char **argv)
{
    unsigned port = 0;
    int index;
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        printf("Magnus Web Engine %s (native C17/epoll)\n", MAGNUS_VERSION);
        exit(0);
    }
    if (argc == 3 && strcmp(argv[1], "--config") == 0) {
        /* Config-file mode replaces every other flag: port, root, TLS,
         * upstream cluster and rate limit all come from the file, and the
         * same path is remembered for SIGHUP to re-validate and apply
         * later (magnus_handle_reload). */
        magnus_config_t config;
        char error[192];
        if (magnus_config_load(argv[2], &config, error, sizeof(error))
            != MAGNUS_CONFIG_OK) {
            fprintf(stderr, "magnus: config: %s\n", error);
            exit(2);
        }
        if (strlen(argv[2]) >= sizeof(magnus_config_path)) {
            fprintf(stderr, "magnus: config: path too long\n");
            exit(2);
        }
        strcpy(magnus_config_path, argv[2]);
        magnus_config_mode = true;
        if (magnus_apply_config(&config) != 0) {
            fprintf(stderr, "magnus: config: a referenced root/tls "
                            "resource could not be opened\n");
            exit(2);
        }
        if (config.has_admin_socket) {
            strcpy(magnus_admin_socket_path, config.admin_socket);
            magnus_admin_enabled = true;
        }
        return config.port;
    }
    const char *certificate = NULL;
    const char *private_key = NULL;
    magnus_cluster_init(&magnus_cluster, MAGNUS_CLUSTER_FAILURE_THRESHOLD,
                        MAGNUS_CLUSTER_COOLDOWN_MS);
    for (index = 1; index < argc; index += 2) {
        if (index + 1 >= argc) break;
        if (strcmp(argv[index], "--port") == 0) {
            char *end;
            unsigned long value;
            errno = 0;
            value = strtoul(argv[index + 1], &end, 10);
            if (errno != 0 || *end != '\0' || value == 0 || value > 65535)
                break;
            port = (unsigned) value;
        } else if (strcmp(argv[index], "--root") == 0) {
            magnus_root_fd = open(argv[index + 1], O_RDONLY | O_DIRECTORY
                                  | O_CLOEXEC | O_NOFOLLOW);
            if (magnus_root_fd < 0) {
                perror("magnus: root");
                exit(2);
            }
        } else if (strcmp(argv[index], "--tls-cert") == 0) {
            certificate = argv[index + 1];
        } else if (strcmp(argv[index], "--tls-key") == 0) {
            private_key = argv[index + 1];
        } else if (strcmp(argv[index], "--upstream") == 0) {
            /* host:port or host:port:weight; repeatable to build a cluster. */
            char spec[80];
            char *saveptr = NULL;
            char *address;
            char *port_text;
            char *weight_text;
            char *end;
            unsigned long upstream_port;
            unsigned long weight = 1;
            struct in_addr probe;
            bool is_hostname;
            if (strlen(argv[index + 1]) >= sizeof(spec)) break;
            strcpy(spec, argv[index + 1]);
            address = strtok_r(spec, ":", &saveptr);
            port_text = strtok_r(NULL, ":", &saveptr);
            weight_text = strtok_r(NULL, ":", &saveptr);
            if (address == NULL || port_text == NULL) break;
            is_hostname = inet_pton(AF_INET, address, &probe) != 1;
            if (is_hostname && !magnus_config_looks_like_hostname(address))
                break;
            errno = 0;
            upstream_port = strtoul(port_text, &end, 10);
            if (errno != 0 || *end != '\0' || upstream_port == 0
                || upstream_port > 65535) break;
            if (weight_text != NULL) {
                errno = 0;
                weight = strtoul(weight_text, &end, 10);
                if (errno != 0 || *end != '\0' || weight == 0
                    || weight > 1000) break;
            }
            if (magnus_cluster_add(&magnus_cluster, address,
                                   (unsigned) upstream_port,
                                   (unsigned) weight) != 0) break;
            magnus_upstream_enabled = true;
            if (is_hostname)
                magnus_dns_track(magnus_cluster.count - 1, address);
        } else if (strcmp(argv[index], "--rate-limit") == 0) {
            /* requests-per-second, or requests-per-second:burst */
            char spec[32];
            char *saveptr = NULL;
            char *rps_text;
            char *burst_text;
            char *end;
            double rps;
            double burst;
            if (strlen(argv[index + 1]) >= sizeof(spec)) break;
            strcpy(spec, argv[index + 1]);
            rps_text = strtok_r(spec, ":", &saveptr);
            burst_text = strtok_r(NULL, ":", &saveptr);
            if (rps_text == NULL) break;
            errno = 0;
            rps = strtod(rps_text, &end);
            if (errno != 0 || *end != '\0' || !(rps > 0.0)) break;
            burst = rps;
            if (burst_text != NULL) {
                errno = 0;
                burst = strtod(burst_text, &end);
                if (errno != 0 || *end != '\0' || !(burst > 0.0)) break;
            }
            magnus_rate_limit_rps = rps;
            magnus_rate_limit_burst = burst;
            magnus_rate_limit_enabled = true;
        } else if (strcmp(argv[index], "--admin-socket") == 0) {
            if (strlen(argv[index + 1]) >= sizeof(magnus_admin_socket_path))
                break;
            strcpy(magnus_admin_socket_path, argv[index + 1]);
            magnus_admin_enabled = true;
        } else if (strcmp(argv[index], "--access-log") == 0) {
            if (strcmp(argv[index + 1], "on") == 0) {
                magnus_access_log_enabled = true;
            } else if (strcmp(argv[index + 1], "off") == 0) {
                magnus_access_log_enabled = false;
            } else {
                break;
            }
        } else if (strcmp(argv[index], "--access-log-sample") == 0) {
            char *end;
            unsigned long sample;
            errno = 0;
            sample = strtoul(argv[index + 1], &end, 10);
            if (errno != 0 || *end != '\0' || sample == 0
                || sample > 1000000) break;
            magnus_access_log_sample = (unsigned) sample;
        } else if (strcmp(argv[index], "--route") == 0) {
            char route_error[128];
            if (magnus_route_count == MAGNUS_CONFIG_MAX_ROUTES) break;
            if (!magnus_route_parse(argv[index + 1],
                                    &magnus_routes[magnus_route_count],
                                    route_error, sizeof(route_error))) {
                fprintf(stderr, "magnus: --route: %s\n", route_error);
                exit(2);
            }
            magnus_route_count++;
        } else {
            break;
        }
    }
    for (size_t r = 0; r < magnus_route_count; r++) {
        if (magnus_routes[r].action == MAGNUS_ROUTE_ACTION_PROXY
            && !magnus_upstream_enabled) {
            fprintf(stderr, "magnus: --route: a route with action=proxy "
                            "needs at least one --upstream\n");
            exit(2);
        }
    }
    if (index == argc && port != 0
        && ((certificate == NULL && private_key == NULL)
            || (certificate != NULL && private_key != NULL))) {
        if (certificate != NULL) {
            magnus_tls_context = SSL_CTX_new(TLS_server_method());
            if (magnus_tls_context == NULL
                || SSL_CTX_set_min_proto_version(magnus_tls_context,
                                                 TLS1_2_VERSION) != 1
                || SSL_CTX_use_certificate_chain_file(magnus_tls_context,
                                                      certificate) != 1
                || SSL_CTX_use_PrivateKey_file(magnus_tls_context, private_key,
                                               SSL_FILETYPE_PEM) != 1
                || SSL_CTX_check_private_key(magnus_tls_context) != 1) {
                ERR_print_errors_fp(stderr);
                exit(2);
            }
            SSL_CTX_set_options(magnus_tls_context, SSL_OP_NO_COMPRESSION);
            magnus_h2_configure_alpn(magnus_tls_context);
        }
        return port;
    }
    fprintf(stderr, "usage: %s --port <1-65535> [--root <directory>] "
                    "[--tls-cert <pem> --tls-key <pem>] "
                    "[--upstream <ipv4:port[:weight]> ...] "
                    "[--rate-limit <rps[:burst]>] "
                    "[--admin-socket <path>] "
                    "[--access-log on|off] [--access-log-sample <n>] "
                    "[--route <spec> ...] "
                    "| %s --config <path> | %s --version\n",
            argv[0], argv[0], argv[0]);
    exit(2);
}

/* Defense in depth alongside the upstream_fd fix above: magnus never
 * reads stdin, so fd 0 is unconditionally pinned to our own /dev/null
 * before anything else runs. A process spawned detached from a
 * controlling terminal (magnusd's fork()+exec() child, in particular) can
 * inherit fd 0 as something that looks valid at startup but turns out to
 * be fragile; owning it ourselves from the very first instruction removes
 * any dependency on what was inherited. stdout/stderr are left alone when
 * already valid (used for logging); only a genuine gap there is filled. */
static void
magnus_ensure_standard_fds(void)
{
    int placeholder = open("/dev/null", O_RDWR);
    if (placeholder < 0) return;
    if (placeholder != 0) {
        dup2(placeholder, 0);
        close(placeholder);
    }
    for (int fd = 1; fd <= 2; fd++) {
        if (fcntl(fd, F_GETFD) < 0 && errno == EBADF) {
            int opened = open("/dev/null", O_RDWR);
            if (opened >= 0 && opened != fd) close(opened);
        }
    }
}

int
main(int argc, char **argv)
{
    unsigned port;
    int listener;
    magnus_ensure_standard_fds();
    /* Started before option parsing: a --config or --upstream hostname
     * entry kicks off its first resolution as soon as it is parsed (see
     * magnus_dns_track()/magnus_dns_apply_upstreams()), which needs the
     * worker thread already running. A failure here is not fatal -- IP-
     * literal upstreams are entirely unaffected, and a hostname one just
     * never resolves (fails connect attempts cleanly, same as any other
     * bad address) until process restart. */
    magnus_dns_eventfd = magnus_dns_start();
    if (magnus_dns_eventfd < 0) {
        fprintf(stderr, "magnus: dns: resolver unavailable (%s); hostname "
                        "upstreams will not resolve\n", strerror(errno));
    }
    port = magnus_parse_options(argc, argv);
    magnus_listen_port = port;
    listener = magnus_create_listener(port);
    int epoll_fd;
    struct epoll_event listener_event;
    struct epoll_event events[MAGNUS_MAX_EVENTS];
    time_t last_sweep = time(NULL);

    if (listener < 0) {
        perror("magnus: listener");
        return 1;
    }
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        perror("magnus: epoll_create1");
        close(listener);
        return 1;
    }
    magnus_global_epoll_fd = epoll_fd;
    listener_event = (struct epoll_event) { .events = EPOLLIN,
                                             .data.fd = listener };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listener, &listener_event) < 0) {
        perror("magnus: epoll_ctl");
        close(epoll_fd);
        close(listener);
        return 1;
    }
    if (magnus_dns_eventfd >= 0) {
        struct epoll_event dns_event = { .events = EPOLLIN,
                                         .data.fd = magnus_dns_eventfd };
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, magnus_dns_eventfd,
                      &dns_event) < 0) {
            perror("magnus: dns: epoll_ctl");
            magnus_dns_stop();
            magnus_dns_eventfd = -1;
        }
    }
    if (magnus_admin_enabled) {
        struct epoll_event admin_event;
        magnus_admin_listener =
            magnus_create_admin_listener(magnus_admin_socket_path);
        if (magnus_admin_listener < 0) {
            perror("magnus: admin-socket");
            close(epoll_fd);
            close(listener);
            return 1;
        }
        admin_event = (struct epoll_event) { .events = EPOLLIN,
                                             .data.fd = magnus_admin_listener };
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, magnus_admin_listener,
                      &admin_event) < 0) {
            perror("magnus: admin-socket epoll_ctl");
            close(magnus_admin_listener);
            close(epoll_fd);
            close(listener);
            return 1;
        }
    }

    magnus_phase_init(&magnus_phases);
    if (magnus_phase_register(&magnus_phases, MAGNUS_PHASE_INGRESS, 100,
                              "request-trace", magnus_trace_handler, NULL) != 0) {
        fprintf(stderr, "magnus: phase registration failed\n");
        return 1;
    }
    signal(SIGINT, magnus_signal_handler);
    signal(SIGTERM, magnus_signal_handler);
    signal(SIGHUP, magnus_reload_signal_handler);
    signal(SIGPIPE, SIG_IGN);
    for (size_t index = 0; index < MAGNUS_MAX_UPSTREAMS; index++) {
        magnus_health_probe_fd[index] = -1;
    }
    fprintf(stderr, "magnus: native engine listening on 0.0.0.0:%u\n", port);

    while (magnus_running) {
        int ready;
        int index;
        time_t now;
        if (magnus_reload_requested) {
            magnus_reload_requested = 0;
            magnus_handle_reload();
        }
        ready = epoll_wait(epoll_fd, events, MAGNUS_MAX_EVENTS, 1000);
        now = time(NULL);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("magnus: epoll_wait");
            break;
        }
        for (index = 0; index < ready; index++) {
            int fd = events[index].data.fd;
            uint32_t flags = events[index].events;
            magnus_connection_t *connection;
            int result = 0;
            if (fd == listener) {
                (void) magnus_accept_connections(epoll_fd, listener, false);
                continue;
            }
            if (magnus_admin_enabled && fd == magnus_admin_listener) {
                (void) magnus_accept_connections(epoll_fd, magnus_admin_listener,
                                                 true);
                continue;
            }
            if (magnus_dns_eventfd >= 0 && fd == magnus_dns_eventfd) {
                magnus_dns_drain_results(magnus_dns_apply_result, NULL);
                continue;
            }
            if (fd >= 0 && fd < MAGNUS_MAX_FDS
                && magnus_upstream_owner[fd] != NULL) {
                connection = magnus_upstream_owner[fd];
                result = magnus_handle_upstream(epoll_fd, connection, flags);
                if (result < 0
                    && magnus_connections[connection->fd] != NULL)
                    magnus_close_connection(epoll_fd, connection);
                continue;
            }
            if (fd >= 0 && fd < MAGNUS_MAX_FDS
                && magnus_h2_upstream_owner[fd] != NULL) {
                /* Unlike the HTTP/1.1 branch above, a stream-local
                 * failure here (magnus_h2_handle_upstream() already
                 * handles those internally) never implies the whole h2
                 * client connection must close -- only a failure
                 * *pushing* the result onto the client fd does, which
                 * is exactly what a negative return here now means. */
                struct magnus_h2_stream *stream = magnus_h2_upstream_owner[fd];
                magnus_connection_t *owner = stream->connection;
                if (magnus_h2_handle_upstream(stream, flags) < 0
                    && magnus_connections[owner->fd] != NULL)
                    magnus_close_connection(epoll_fd, owner);
                continue;
            }
            if (fd >= 0 && fd < MAGNUS_MAX_FDS
                && magnus_health_probe_owner[fd] != 0) {
                magnus_health_handle_probe(epoll_fd,
                    (size_t) (magnus_health_probe_owner[fd] - 1), flags);
                continue;
            }
            if (fd < 0 || fd >= MAGNUS_MAX_FDS
                || (connection = magnus_connections[fd]) == NULL) {
                continue;
            }
            if (connection->proxy_ws_active) {
                result = (flags & (EPOLLERR | EPOLLHUP)) != 0
                    ? -1 : magnus_ws_service(epoll_fd, connection);
            } else if (connection->h2_active) {
                result = (flags & (EPOLLERR | EPOLLHUP)) != 0
                    ? -1 : magnus_h2_service(epoll_fd, connection);
            } else if ((flags & (EPOLLERR | EPOLLHUP)) != 0) {
                result = -1;
            } else if (!connection->tls_ready) {
                result = magnus_tls_handshake(epoll_fd, connection);
            } else if ((flags & EPOLLIN) != 0) {
                result = magnus_handle_read(epoll_fd, connection);
            } else if ((flags & EPOLLOUT) != 0 && connection->proxy_active) {
                result = magnus_proxy_flush(epoll_fd, connection);
            } else if ((flags & EPOLLOUT) != 0) {
                result = magnus_handle_write(epoll_fd, connection);
            } else if ((flags & EPOLLRDHUP) != 0 && connection->proxy_active) {
                /* client aborted while we were only watching for hangup
                 * (connecting to, or waiting on headers from, upstream) */
                result = -1;
            }
            if (result < 0 && magnus_connections[fd] != NULL) {
                magnus_close_connection(epoll_fd, connection);
            }
        }
        if (now != last_sweep) {
            magnus_expire_proxies(epoll_fd, now);
            magnus_expire_idle(epoll_fd, now);
            magnus_pool_expire_idle(now);
            magnus_dns_tick(now);
            magnus_health_tick(epoll_fd, now);
            magnus_access_log_flush();
            last_sweep = now;
        }
    }

    /* Graceful GOAWAY (roadmap 1e-3): every still-open h2 connection gets
     * one best-effort GOAWAY (NGHTTP2_NO_ERROR, this session's own
     * last-processed stream id) before the hard close loop below tears
     * everything down regardless -- a clean signal for a well-behaved
     * client, at essentially no cost, rather than the abrupt
     * RST/connection-drop it would otherwise see. Deliberately not the
     * full two-GOAWAY graceful-shutdown dance RFC 9113 6.8 describes for
     * avoiding a race with in-flight new streams: that dance is meant to
     * span a full RTT before the real shutdown, and magnus's own
     * shutdown proceeds immediately after this loop regardless, so
     * there is no window for it to matter in. magnus_h2_push() is
     * attempted once, best-effort -- if the client fd would block, the
     * GOAWAY simply does not make it out in time, exactly as if the
     * process had been killed a moment earlier; this is a courtesy, not
     * a guarantee. */
    for (int fd = 0; fd < MAGNUS_MAX_FDS; fd++) {
        magnus_connection_t *connection = magnus_connections[fd];
        if (connection == NULL || !connection->h2_active) continue;
        (void) nghttp2_submit_goaway(connection->h2_session, NGHTTP2_FLAG_NONE,
            nghttp2_session_get_last_proc_stream_id(connection->h2_session),
            NGHTTP2_NO_ERROR, NULL, 0);
        (void) magnus_h2_push(epoll_fd, connection);
    }

    for (int fd = 0; fd < MAGNUS_MAX_FDS; fd++) {
        if (magnus_connections[fd] != NULL) {
            magnus_close_connection(epoll_fd, magnus_connections[fd]);
        }
    }
    magnus_pool_close_all();
    magnus_dns_stop();
    close(epoll_fd);
    close(listener);
    if (magnus_admin_listener >= 0) {
        close(magnus_admin_listener);
        unlink(magnus_admin_socket_path);
    }
    if (magnus_root_fd >= 0) close(magnus_root_fd);
    if (magnus_tls_context != NULL) SSL_CTX_free(magnus_tls_context);
    magnus_access_log_flush();
    fprintf(stderr, "magnus: stopped\n");
    return 0;
}
