#include "magnus_phase.h"
#include "magnus_base64.h"
#include "magnus_cache.h"
#include "magnus_config.h"
#include "magnus_compression.h"
#include "magnus_http.h"
#include "magnus_policy.h"
#include "magnus_dns.h"
#include "magnus_h2.h"
#include "magnus_proxy.h"
#include "magnus_quic.h"
#include "magnus_realip.h"
#include "magnus_static.h"
#include "magnus_route.h"
#include "magnus_sni.h"
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

/* MAGNUS_VERSION itself now lives in magnus_quic.h (included below) --
 * see that header's own comment on why. */
#define MAGNUS_MAX_EVENTS 1024
#define MAGNUS_MAX_FDS 65536
#define MAGNUS_INPUT_LIMIT 8192
#define MAGNUS_MAX_BODY (1 * 1024 * 1024)
/* Bumped 2048 -> 9216 (roadmap 3a), then -> 17408 (roadmap 3b): with the
 * `upstream`, `grpc_upstream`, and `stream` clusters all at their own max
 * endpoint count plus every gRPC status code and every latency-histogram
 * bucket all actually present at once, /metrics' real worst-case body was
 * already close to 6.2KB at 3a -- comfortably past the *original*
 * 2048-byte ceiling, which silently emptied the *entire* response (not
 * just truncated the body) once the rendered body plus headers exceeded
 * it, a real bug found live rather than in code review (see
 * CHANGELOG.md 3a's own writeup). 3b's own stream_sni_route clusters add
 * a genuinely large *theoretical* worst case on top of that (up to
 * MAGNUS_CONFIG_MAX_SNI_ROUTES patterns, each up to
 * MAGNUS_CONFIG_MAX_UPSTREAMS endpoints, one gauge line apiece) --
 * comfortable headroom for any deployment actually likely to exist
 * (a handful of patterns, a handful of endpoints each) rather than the
 * full theoretical maximum, which would still gracefully truncate (per-
 * endpoint/per-pattern loops stop appending once out of room, exactly
 * the existing documented behavior below) rather than repeat 3a's whole-
 * response-emptied bug. MAGNUS_METRICS_BUFFER stays comfortably below
 * this with headroom for HTTP headers. */
#define MAGNUS_OUTPUT_LIMIT 17408
/* Sized to stay well clear of MAGNUS_OUTPUT_LIMIT once wrapped in
 * response headers; magnus_build_metrics()'s per-endpoint/per-bucket
 * loops stop appending once they run out of room rather than risk
 * overflowing the response envelope, so the fixed aggregate lines are
 * always present even when there is not room for full detail. */
#define MAGNUS_METRICS_BUFFER 16384
#define MAGNUS_IDLE_SECONDS 30
#define MAGNUS_HEADER_TIMEOUT_SECONDS 10
#define MAGNUS_PROXY_BUFFER 16384
#define MAGNUS_INITIAL_INPUT 2048
#define MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS 5
#define MAGNUS_PROXY_READ_TIMEOUT_SECONDS 10
#define MAGNUS_PROXY_HEADER_LIMIT MAGNUS_PROXY_BUFFER
#define MAGNUS_PROXY_SANITIZED_LIMIT 4096
#define MAGNUS_PROXY_MAX_ATTEMPTS 2
/* TLS passthrough / SNI routing (roadmap 3b): how long a stream
 * connection may sit in MAGNUS_STREAM_PEEKING before giving up and
 * falling back to the default stream_upstream cluster -- the same
 * fallback a parsed-but-unmatched or genuinely malformed ClientHello
 * already gets, just triggered by a stalled/slow client instead. */
#define MAGNUS_STREAM_PEEK_TIMEOUT_SECONDS 5
/* gRPC deadline propagation (roadmap 2c-3): an explicit upper bound on
 * how far a client-supplied grpc-timeout may extend a stream's
 * connect/read budget past the default MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS/
 * MAGNUS_PROXY_READ_TIMEOUT_SECONDS -- every new resource this codebase
 * introduces gets one (see e.g. MAGNUS_MAX_BODY), and an unbounded
 * client-claimed deadline would otherwise let one request hold an
 * upstream connection (and this stream's memory) open indefinitely. Five
 * minutes is generous for a real streaming RPC while still being a world
 * away from "unbounded." */
#define MAGNUS_GRPC_MAX_TIMEOUT_MS (5 * 60 * 1000)
#define MAGNUS_HEALTH_CHECK_INTERVAL_SECONDS 5
#define MAGNUS_HEALTH_PROBE_TIMEOUT_SECONDS 2
#define MAGNUS_CLUSTER_FAILURE_THRESHOLD 3
#define MAGNUS_CLUSTER_COOLDOWN_MS 5000
#define MAGNUS_RATE_TABLE_SIZE 512
#define MAGNUS_POOL_MAX_IDLE_PER_ENDPOINT 8
#define MAGNUS_POOL_IDLE_TIMEOUT_SECONDS 60
#define MAGNUS_POOL_MAX_REQUESTS_PER_CONNECTION 100
/* gRPC upstream connection pool + multiplexing (roadmap 2c-5): unlike the
 * h1 pool above (one fd, checked out exclusively for one request at a
 * time, idle otherwise), a pooled gRPC connection is a *shared*, always-
 * live nghttp2 CLIENT session that many concurrent client-side gRPC
 * streams multiplex onto at once -- so "pool size" here means how many
 * physical TCP+h2 connections magnus keeps open per endpoint, not how
 * many are idle. Deliberately small: h2 multiplexing already lets one
 * connection carry a very large number of concurrent RPCs (see
 * magnus_grpc_conn_pick()'s own comment on why more than one is still
 * worth having). MAX_REQUESTS_PER_CONNECTION recycles a connection after
 * it has served a lot of RPCs -- both to bound how close its nghttp2
 * stream-ID counter (31-bit, odd-only, never reused within one session)
 * can ever realistically get to exhaustion, and as a mundane hygiene
 * measure (picking up DNS/config changes, not letting one connection's
 * memory live forever) -- set far higher than the h1 pool's own 100,
 * since one h2 stream is far cheaper than one full HTTP/1.1 connection. */
#define MAGNUS_GRPC_POOL_MAX_CONNS_PER_ENDPOINT 4
#define MAGNUS_GRPC_POOL_IDLE_TIMEOUT_SECONDS 60
#define MAGNUS_GRPC_POOL_MAX_REQUESTS_PER_CONNECTION 100000
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
    unsigned char *compressed_body;
    size_t compressed_body_length;
    size_t compressed_body_sent;
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
    /* Advanced load balancing (roadmap 2e-1): true from the moment
     * magnus_proxy_attach_upstream() successfully attaches this
     * connection's proxy attempt to proxy_endpoint_index, until whichever
     * of magnus_proxy_teardown_upstream()/the pool-checkin branch of
     * magnus_proxy_flush() releases it -- see magnus_cluster_endpoint_begin()/
     * _end()'s own comment. Guards against a double-release (the two
     * release sites are mutually exclusive in practice, but this makes
     * that a guarantee rather than an assumption). */
    bool proxy_endpoint_counted;
    unsigned proxy_attempt;
    char proxy_affinity_key[64];
    bool proxy_issue_affinity_cookie;
    /* client-side method/target of the request currently being proxied,
     * captured at proxy start so the completion access-log line (written
     * later, asynchronously, once the upstream response arrives) can
     * still report what the client actually asked for. */
    char proxy_log_method[8];
    char proxy_log_target[256];
    /* Reverse-proxy cache (roadmap 2d-1) -- see magnus_cache.h's own top
     * comment. `cache_enabled` is this dispatch's own route opt-in
     * (magnus_route_t's cache_enabled), captured once at dispatch time so
     * the rest of this async, multi-step flow (connect -> request ->
     * headers -> body -> complete) never needs the route table again.
     * `cache_host`/`cache_target` are the lookup/store key, likewise
     * copied at dispatch time since the client's own magnus_http_request_t
     * is stack-local and does not survive the asynchronous upstream
     * fetch. `cache_revalidating` is true exactly while the in-flight
     * upstream attempt is a conditional GET against an existing stale
     * entry (magnus_proxy_pick_and_start() set cache_validator_etag/
     * _last_modified from that entry to send); a plain miss/refetch
     * leaves it false. `cache_this_response_cacheable`/`cache_freshness`
     * are decided once response headers are known
     * (magnus_proxy_receive_headers()) and acted on once the body is
     * fully relayed (magnus_proxy_flush()'s own "response complete"
     * branch). `cache_capture`/_length/_capacity/_overflowed mirror the
     * gRPC pool's own io_buffer growth pattern (roadmap 2c-1/2c-2) to
     * accumulate the response body being relayed, bounded by
     * MAGNUS_CACHE_MAX_ENTRY_BYTES, purely as a side observation -- the
     * normal client-facing relay through proxy_buffer is entirely
     * unaffected by capture succeeding, failing, or never being
     * attempted at all. */
    bool cache_enabled;
    bool cache_revalidating;
    char cache_host[256];
    char cache_target[256];
    char cache_validator_etag[128];
    char cache_validator_last_modified[64];
    bool cache_this_response_cacheable;
    magnus_cache_freshness_t cache_freshness;
    /* Copied out of `sanitized` verbatim at header time (the cache-
     * storable prefix -- status line + pass-through headers, before
     * Connection/X-Magnus-Via/the affinity Set-Cookie; see
     * magnus_proxy_sanitize_response_headers()'s own
     * out_cacheable_prefix_length parameter) rather than remembered by
     * offset into proxy_header_out: that buffer is freed the moment its
     * own bytes finish reaching the client (magnus_proxy_flush()'s own
     * header-flush phase), typically well before the body -- and
     * therefore this cache store, at true response completion -- is
     * ever reached. Same shape as the h2 path's own
     * cache_pending_headers, for the identical reason (there, nothing
     * ever persists the raw text at all). */
    char cache_pending_headers[MAGNUS_PROXY_SANITIZED_LIMIT];
    size_t cache_pending_headers_length;
    /* This response's own ETag/Last-Modified (if any), captured at header
     * time for magnus_cache_store() to use once the body completes --
     * distinct from cache_validator_etag/_last_modified above, which
     * instead hold the *stale entry's* validators sent *out* on a
     * revalidation request; these are what comes *back*. */
    char cache_response_etag[128];
    char cache_response_last_modified[64];
    char *cache_capture;
    size_t cache_capture_length;
    size_t cache_capture_capacity;
    bool cache_capture_overflowed;
    /* Serving a cache HIT (or a successful revalidation) directly to the
     * client, entirely bypassing the upstream -- the cache-hit analogue
     * of compressed_body above (same "malloc'd buffer, sent via
     * magnus_handle_write(), freed once fully sent" shape, kept as its
     * own separate field rather than reusing compressed_body itself so
     * neither purpose's own lifecycle comments have to account for the
     * other). cache_serve_headers holds the freshly-assembled status
     * line + headers block (Content-Length/Connection/X-Cache recomputed
     * for *this* client/response, never replayed verbatim from what a
     * different client's own request happened to produce); cache_serve_body
     * is a copy of the entry's own stored body, copied rather than
     * referenced directly so this client's own slow-consumer pace can
     * never be blocked on (or, worse, outlive) the cache entry itself
     * being evicted/replaced mid-flight. */
    char *cache_serve_headers;
    size_t cache_serve_headers_length;
    size_t cache_serve_headers_sent;
    char *cache_serve_body;
    size_t cache_serve_body_length;
    size_t cache_serve_body_sent;
    struct in_addr client_address;
    struct in_addr raw_peer_address;
    bool proxy_proto_done;
    bool realip_from_proxy_proto;
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
/* Not `static` -- see src/magnus_static.h's own comment on why
 * magnus_quic.c (HTTP/3, roadmap Phase 4b) needs this and the two
 * functions below it directly. */
int magnus_root_fd = -1;
static SSL_CTX *magnus_tls_context;
static magnus_cluster_t magnus_cluster;
static bool magnus_upstream_enabled;
/* gRPC upstream cluster (roadmap 2c-1): a separate pool from magnus_cluster
 * above, targeted only by a route with action=grpc -- reuses
 * magnus_cluster_t's own weighted-RR/health/circuit-breaker logic
 * unmodified (no new load-balancer code needed), just a second instance,
 * since a real gRPC backend fleet and an ordinary HTTP/1.x one are rarely
 * the same servers. */
static magnus_cluster_t magnus_grpc_cluster;
static bool magnus_grpc_upstream_enabled;

/* L4 TCP passthrough (roadmap 3a): a third, independent cluster/listener,
 * architecturally distinct from the two above -- a stream connection never
 * goes through magnus_http_parse() at all, just two raw byte pipes shovelled
 * between the client fd and whichever endpoint magnus_stream_cluster.policy
 * picks (round_robin/least_conn/ip_hash reused unmodified; no cookie-based
 * affinity, since there is no HTTP-level cookie to key on at L4). One
 * listener/cluster for this first increment -- see magnus_stream_conn_t's
 * own comment for the rest of the design. */
static magnus_cluster_t magnus_stream_cluster;
static bool magnus_stream_enabled;
static unsigned magnus_stream_port;
static int magnus_stream_listener = -1;
/* PROXY protocol emission: applies uniformly to every stream connection
 * regardless of which cluster it ends up at -- see
 * magnus_config_t.stream_proxy_protocol's own comment on why this is not
 * per-cluster in this increment. Not tied to any one magnus_cluster_t,
 * hence its own global rather than living on magnus_stream_cluster
 * itself. */
static magnus_proxy_protocol_mode_t magnus_stream_proxy_protocol_mode =
    MAGNUS_PROXY_PROTOCOL_OFF;

/* TLS passthrough / SNI routing (roadmap 3b): layered on top of
 * magnus_stream_cluster above, never a replacement for it. Each entry is
 * its own independent magnus_cluster_t (own endpoints, own round_robin
 * selection, own passive circuit-breaker state) matched by pattern,
 * first-match-wins in config-file order -- see
 * magnus_sni_select_cluster()'s own comment on why active health
 * checking is deliberately out of scope for these. */
typedef struct {
    char pattern[MAGNUS_CONFIG_SNI_PATTERN_MAX];
    magnus_cluster_t cluster;
} magnus_sni_cluster_t;

static magnus_sni_cluster_t magnus_sni_clusters[MAGNUS_CONFIG_MAX_SNI_ROUTES];
static size_t magnus_sni_cluster_count;

/* UDP passthrough (roadmap 3d): a fourth, independent listener -- plain
 * SOCK_DGRAM, no `accept()`/handshake of any kind, since UDP has neither.
 * One magnus_udp_session_t per distinct (source IP, source port) tuple
 * the listener has ever seen recently, each owning its own dedicated
 * connect()ed UDP socket to whichever backend magnus_udp_cluster.policy
 * picked for that tuple -- the same "one socket per active flow,
 * connect() fixes the peer so replies route back unambiguously" pattern
 * every other cluster in this file already uses for TCP, just with
 * SOCK_DGRAM sockets that never actually handshake. Capped at
 * magnus_udp_max_sessions (<= MAGNUS_UDP_MAX_SESSIONS_CEILING, the fixed
 * array size actually allocated) -- the "Section 12" memory bound the
 * roadmap itself flagged needing a real answer before implementation,
 * not discovered mid-implementation: once full, a new (source IP,
 * source port) tuple's packet is simply dropped, never evicting an
 * existing session to make room (an already-active session's own client
 * would silently lose its return traffic for a stranger's benefit,
 * which -- combined with how trivially spoofable a UDP source address
 * is -- would turn eviction itself into a denial-of-service primitive
 * rather than a safety valve). No health tracking of any kind, active
 * or passive: a connect()ed UDP socket's own connect() call succeeds
 * locally almost unconditionally regardless of whether the backend
 * actually exists (there is no handshake to fail the way TCP's SYN/ACK
 * would), so it carries none of the passive signal
 * magnus_cluster_result() relies on elsewhere in this file; a genuine
 * UDP-level health probe is a distinct, not-yet-built future increment,
 * matching the same scope-cut precedent stream_sni_route's own clusters
 * (roadmap 3b) already set. least_conn is still meaningful without a
 * health signal -- it reads live session counts via the same
 * magnus_cluster_endpoint_begin()/_end() every other cluster's own
 * `active_requests` field already tracks, reused here unmodified for
 * "sessions currently pinned to this endpoint" instead of "requests". */
#define MAGNUS_UDP_MAX_SESSIONS_CEILING 4096
#define MAGNUS_UDP_DATAGRAM_MAX MAGNUS_PROXY_BUFFER

static magnus_cluster_t magnus_udp_cluster;
static bool magnus_udp_enabled;
static unsigned magnus_udp_port;
static int magnus_udp_listener = -1;
static unsigned magnus_udp_session_idle_seconds = 30;
static unsigned magnus_udp_max_sessions = 1024;

/* QUIC transport (roadmap Phase 4a) -- see src/magnus_quic.h for the
 * full scope note. Unlike magnus_udp_listener above, this is not a
 * passthrough listener; magnus_quic.c owns the actual per-connection
 * state (ngtcp2_conn table), magnus.c only owns the listener fd and
 * the epoll/periodic-sweep wiring, same division of responsibility
 * magnus_h2.c/magnus_ws.c already have for their own protocols. */
static bool magnus_quic_enabled;
static unsigned magnus_quic_port;
static int magnus_quic_listener = -1;

typedef struct {
    bool in_use;
    struct in_addr client_addr;
    in_port_t client_port;
    int upstream_fd;
    size_t endpoint_index;
    bool endpoint_counted;
    time_t last_active;
} magnus_udp_session_t;

static magnus_udp_session_t magnus_udp_sessions[MAGNUS_UDP_MAX_SESSIONS_CEILING];
static size_t magnus_udp_session_count;
/* fd -> session, for O(1) reply routing once a session's own backend
 * socket becomes readable -- the forward direction (an arriving client
 * datagram on the single shared listener) has no fd of its own to index
 * by and instead linear-scans magnus_udp_sessions[], bounded by
 * magnus_udp_max_sessions; a hash index there would be the natural next
 * optimization if real deployments ever need more than this increment's
 * own modest default ceiling, the same honest, explicitly-scoped
 * trade-off magnus_rate_table's own linear scan already makes. */
static magnus_udp_session_t *magnus_udp_upstream_owner[MAGNUS_MAX_FDS];
static uint64_t magnus_udp_sessions_total;
static uint64_t magnus_udp_bytes_c2u_total;
static uint64_t magnus_udp_bytes_u2c_total;

/* One direction of a stream connection's byte relay: `buffer[sent..length)`
 * is buffered-but-not-yet-written to the destination fd. `source_eof` is
 * set once read() on the source fd returns 0; once that pipe's own buffer
 * is also fully drained (length == sent), the destination fd is shutdown()
 * for writing (dest_shutdown) -- a standard half-close, so the *other*
 * direction can keep flowing after one side finishes sending (e.g. a
 * client that sends a request-like preamble then only reads a long-lived
 * response stream). magnus_stream_pipe_done() below is true once both of
 * those have happened, at which point this direction contributes nothing
 * more to the connection's lifetime.
 *
 * Doubles as the SNI peek buffer (roadmap 3b): during MAGNUS_STREAM_PEEKING
 * the client's initial bytes are read directly into c2u.buffer (with
 * upstream_fd still -1, sent staying 0) while magnus_sni_extract() is
 * attempted against what has accumulated so far. Once a cluster is picked
 * and connected, those same buffered bytes are exactly what
 * magnus_stream_pump() needs to flush to the upstream first -- they are
 * genuinely part of the ClientHello the backend must see unmodified for
 * passthrough to mean anything, so reusing this buffer rather than
 * copying into a separate one is not just an optimization, it is what
 * makes forwarding them automatic instead of one more thing to remember. */
typedef struct {
    char buffer[MAGNUS_PROXY_BUFFER];
    size_t length;
    size_t sent;
    bool source_eof;
    bool dest_shutdown;
} magnus_stream_pipe_t;

typedef enum {
    /* Buffering the client's initial bytes into c2u, looking for a TLS
     * SNI hostname to route on -- only ever entered when at least one
     * stream_sni_route is configured; a deployment with none goes
     * straight to CONNECTING; see magnus_stream_accept()'s own comment. */
    MAGNUS_STREAM_PEEKING,
    /* upstream_fd is open; connect() not yet confirmed. */
    MAGNUS_STREAM_CONNECTING,
    /* Fully connected; ordinary bidirectional pumping. */
    MAGNUS_STREAM_RELAYING
} magnus_stream_conn_stage_t;

/* One L4 passthrough connection: a client fd, the upstream fd it was
 * matched to (once picked -- -1 while still MAGNUS_STREAM_PEEKING), and
 * one magnus_stream_pipe_t per direction. `cluster` is which cluster
 * `endpoint_index` is an index into -- magnus_stream_cluster itself if
 * SNI routing is disabled, never matched, or gave up (peek buffer full/
 * timed out) without a decision, or one of magnus_sni_clusters[] if a
 * pattern matched. Unlike the L7 proxy, there is no retry budget here --
 * by the time any bytes have been read there is no "request" to safely
 * retry, only an already-in-progress byte stream. `endpoint_counted`
 * mirrors the same idempotent-release guard
 * magnus_cluster_endpoint_begin()/_end() already needed for the L7 proxy
 * paths (roadmap 2e-1) -- here there is only ever one completion path
 * (magnus_stream_close()), so it is a simpler true-once flag rather than
 * needing to survive multiple possible teardown routes. */
typedef struct {
    int fd;
    int upstream_fd;
    magnus_stream_conn_stage_t stage;
    magnus_cluster_t *cluster;
    size_t endpoint_index;
    bool endpoint_counted;
    /* Captured once at accept4() time -- magnus_cluster_select()'s own
     * ip_hash policy, and a peek-timeout/full-buffer fallback decision,
     * both need it well after the original accept() call has returned.
     * peer_port is only ever used to build a PROXY protocol preamble
     * (magnus_stream_connect()) -- nothing else in this file needs the
     * client's own source port. */
    struct in_addr peer_address;
    in_port_t peer_port;
    time_t last_active;
    time_t connect_started;
    time_t peek_started;
    /* PROXY protocol emission: built once by magnus_stream_connect(),
     * right when the upstream connect() is confirmed (synchronously or
     * async), and flushed to the backend before a single byte of actual
     * client<->backend relay traffic -- see
     * magnus_stream_flush_proxy_protocol()'s own comment.
     * proxy_protocol_header_length stays 0 (this whole mechanism a
     * no-op) whenever magnus_stream_proxy_protocol_mode is OFF, the
     * default. */
    char proxy_protocol_header[MAGNUS_PROXY_PROTO_BUILD_MAX];
    size_t proxy_protocol_header_length;
    size_t proxy_protocol_header_sent;
    magnus_stream_pipe_t c2u;
    magnus_stream_pipe_t u2c;
} magnus_stream_conn_t;

/* Keyed by the client fd (magnus_stream_owner) and, separately, by the
 * upstream fd (magnus_stream_upstream_owner, unused while still
 * MAGNUS_STREAM_PEEKING) -- both point at the same magnus_stream_conn_t,
 * exactly the two-owner-map shape the L7 proxy already uses for
 * magnus_connections{,_upstream_owner}. Active-health probe state for
 * magnus_stream_cluster (TCP-connect only, same reasoning as the gRPC
 * cluster -- see magnus_health_tick()'s own comment) lives in its own
 * third probe array, dispatched from the same magnus_health_tick_cluster()
 * roadmap 2f already generalized for exactly this; magnus_sni_clusters[]
 * gets passive health only -- see its own comment on why. */
static magnus_stream_conn_t *magnus_stream_owner[MAGNUS_MAX_FDS];
static magnus_stream_conn_t *magnus_stream_upstream_owner[MAGNUS_MAX_FDS];
/* magnus_stream_health_probes/_last_probe/_probe_owner (same shape as the
 * gRPC cluster's own probe arrays) are declared alongside
 * magnus_health_probe_t itself, further down -- that type does not exist
 * yet at this point in the file. */
static uint64_t magnus_stream_connections_total;
static uint64_t magnus_stream_connections_active;
static uint64_t magnus_stream_bytes_c2u_total;
static uint64_t magnus_stream_bytes_u2c_total;
/* Evaluated in order, first match wins, ahead of the built-in
 * healthz/metrics/proxy-prefix/static dispatch -- see
 * magnus_dispatch_request(). Empty (route_count == 0, the default) means
 * every request falls straight through to that built-in dispatch exactly
 * as it did before routes existed. */
static magnus_route_t magnus_routes[MAGNUS_CONFIG_MAX_ROUTES];
static size_t magnus_route_count;
static magnus_cidr_t magnus_trusted_proxies[MAGNUS_CONFIG_MAX_TRUSTED_PROXIES];
static size_t magnus_trusted_proxy_count;
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

/* gRPC upstream connection pool + multiplexing (roadmap 2c-5): a pooled,
 * shared upstream h2 connection, kept alive across many RPCs rather than
 * the earlier one-fresh-connection-per-unary-RPC design (2c-1 through
 * 2c-4's own top-of-section comment explicitly flagged this as the
 * deliberately-scoped-out follow-up). `session` is a magnus-owned CLIENT-
 * role nghttp2 session exactly like before, except now many concurrent
 * client-side gRPC streams (`streams`, an intrusive list threaded through
 * each magnus_h2_stream's own grpc_conn_next/grpc_conn_prev) submit
 * requests onto the *same* session at once -- nghttp2 was built for
 * exactly this (nghttp2_submit_request2()'s own stream_user_data
 * parameter, retrieved per-frame via nghttp2_session_get_stream_user_data())
 * so no home-grown stream-id-to-magnus_h2_stream map is needed. `fd`/
 * `session` belong to the pool, never to any one stream -- see
 * magnus_h2_stream_teardown_upstream()'s own comment on what that changes
 * about a single RPC's teardown. */
typedef struct magnus_grpc_conn {
    bool in_use;
    int fd;
    nghttp2_session *session;
    size_t endpoint_index;
    bool connected;
    /* Set from the on_frame_recv GOAWAY case (magnus_h2_grpc_client_on_frame_recv())
     * -- once true, this connection is never picked for a *new* stream
     * again (magnus_grpc_conn_pick()), but every stream already attached
     * is left to finish normally; the connection is only actually closed
     * once active_streams reaches 0 (magnus_grpc_conn_maybe_close_idle()). */
    bool goaway_received;
    /* Set the moment any I/O on this connection fails (recv()==0/error,
     * send() error, a corrupt h2 frame) -- magnus_grpc_conn_fail() fans a
     * clean UNAVAILABLE out to every stream still attached (there is no
     * transparent per-stream retry-to-a-different-endpoint here, unlike
     * pre-pooling 2c-1..2c-4's own connect-failure retry; see
     * magnus_h2_grpc_start()'s own comment on why that trade-off is
     * accepted deliberately rather than silently). */
    bool broken;
    unsigned active_streams;
    unsigned requests_served;
    time_t connect_started;
    time_t last_activity;
    /* Serialized nghttp2 output this connection could not write in one
     * go -- the shared-connection analogue of stream->grpc_output before
     * pooling (now conn-scoped, since the fd/session themselves are). */
    unsigned char *output;
    size_t output_length;
    size_t output_sent;
    struct magnus_h2_stream *streams;
} magnus_grpc_conn_t;

/* Fixed grid rather than a free list: MAGNUS_CONFIG_MAX_GRPC_UPSTREAMS (8)
 * endpoints x MAGNUS_GRPC_POOL_MAX_CONNS_PER_ENDPOINT (4) is 32 slots at
 * most, trivial to scan linearly every time (magnus_grpc_conn_pick(),
 * magnus_grpc_pool_expire(), magnus_grpc_pool_close_all()) without any
 * allocation or bookkeeping beyond each slot's own `in_use`. */
static magnus_grpc_conn_t
    magnus_grpc_pool[MAGNUS_CONFIG_MAX_GRPC_UPSTREAMS][MAGNUS_GRPC_POOL_MAX_CONNS_PER_ENDPOINT];
/* Parallel to magnus_h2_upstream_owner[] above, but keyed to a pooled
 * gRPC connection instead of a single stream -- one fd here can be
 * driving many concurrent client-side streams' upstream leg at once. */
static magnus_grpc_conn_t *magnus_grpc_conn_owner[MAGNUS_MAX_FDS];

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
 * instead of treating it as client or proxied-upstream traffic. Two
 * independent owner maps (roadmap 2f) since the `upstream` cluster's
 * probes and the `grpc_upstream` cluster's probes are separate state
 * machines running against separate magnus_cluster_t instances -- see
 * magnus_health_tick()'s own comment on why they are not unified into
 * one array. */
static int magnus_health_probe_owner[MAGNUS_MAX_FDS];
static int magnus_grpc_health_probe_owner[MAGNUS_MAX_FDS];
/* Third owner map (roadmap 3a) for magnus_stream_cluster's own active
 * probe -- same reasoning as the two above. */
static int magnus_stream_health_probe_owner[MAGNUS_MAX_FDS];

/* Active health checking (roadmap 2f): interval/timeout apply to both
 * clusters' probes; path/expected_status are consulted only by the
 * `upstream` cluster's HTTP-mode probe (see magnus_health_advance()).
 * Defaults reproduce this codebase's pre-2f hardcoded behavior; overridden
 * by magnus_config's own health_check_* keys / the matching --health-
 * check-* CLI flags. */
#define MAGNUS_HEALTH_CHECK_PATH_MAX 256
static unsigned magnus_health_check_interval_seconds =
    MAGNUS_HEALTH_CHECK_INTERVAL_SECONDS;
static unsigned magnus_health_check_timeout_seconds =
    MAGNUS_HEALTH_PROBE_TIMEOUT_SECONDS;
static char magnus_health_check_path[MAGNUS_HEALTH_CHECK_PATH_MAX] = "/";
static unsigned magnus_health_check_expected_status = 200;

/* Per-endpoint active-probe state. A probe walks CONNECTING -> (HTTP mode
 * only) SENDING -> READING; a TCP-only probe (the gRPC cluster's own,
 * see below) resolves the instant CONNECTING succeeds, never entering the
 * other two stages. `response` accumulates just enough of the reply to
 * read its status line -- this is a liveness probe, not a real HTTP
 * client, so the body is never read. */
typedef enum {
    MAGNUS_HEALTH_PROBE_CONNECTING,
    MAGNUS_HEALTH_PROBE_SENDING,
    MAGNUS_HEALTH_PROBE_READING
} magnus_health_probe_stage_t;

typedef struct {
    int fd;
    time_t started;
    magnus_health_probe_stage_t stage;
    char request[MAGNUS_HEALTH_CHECK_PATH_MAX + 64];
    size_t request_length;
    size_t request_sent;
    char response[256];
    size_t response_length;
} magnus_health_probe_t;

static magnus_health_probe_t magnus_health_probes[MAGNUS_MAX_UPSTREAMS];
static time_t magnus_health_last_probe[MAGNUS_MAX_UPSTREAMS];
static magnus_health_probe_t magnus_grpc_health_probes[MAGNUS_MAX_UPSTREAMS];
static time_t magnus_grpc_health_last_probe[MAGNUS_MAX_UPSTREAMS];
static magnus_health_probe_t magnus_stream_health_probes[MAGNUS_MAX_UPSTREAMS];
static time_t magnus_stream_health_last_probe[MAGNUS_MAX_UPSTREAMS];
static uint64_t magnus_connections_total;
static uint64_t magnus_connections_active;
static uint64_t magnus_requests_total;
static uint64_t magnus_responses_4xx;
static uint64_t magnus_responses_5xx;
static uint64_t magnus_bytes_sent;
static uint64_t magnus_rate_limited_total;
/* gRPC-status-aware observability (roadmap 2c-4): indices 0-16, the 17
 * canonical gRPC status codes (0=OK ... 16=UNAUTHENTICATED). Deliberately
 * separate from magnus_responses_4xx/5xx above -- a gRPC response's own
 * wire :status is always 200 regardless of outcome (see
 * magnus_h2_grpc_fail()'s own comment), so those two counters stay
 * exactly what they always were, an HTTP-status-code breakdown, and this
 * is what actually answers "how many gRPC calls failed, and how." Only
 * incremented for the two dispatch outcomes that already call
 * magnus_access_log() with a real grpc_status (magnus_h2_grpc_fail(), and
 * magnus_grpc_conn_finalize_closed_streams()'s own stream-closed
 * finalization) --
 * a mid-stream abort (magnus_h2_grpc_abort()) does not log or count here
 * either, matching how the h1-proxy path's own magnus_h2_proxy_abort()
 * has never counted toward magnus_responses_4xx/5xx. */
static uint64_t magnus_grpc_status_counts[17];

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

/* Kept only so magnus_quic_init() (called once, at startup, after
 * magnus_parse_options() returns -- see main()) has the actual
 * certificate/key file paths to build its own separate QUIC-specific
 * SSL_CTX from; magnus_tls_context itself is an already-built SSL_CTX*,
 * not paths. Populated from both entry points that can establish TLS
 * (the CLI --tls-cert/--tls-key branch and magnus_apply_config(), the
 * latter covering both --config startup and SIGHUP reload). A reload
 * that rotates the certificate does NOT currently propagate to the
 * QUIC listener's own SSL_CTX -- a known Phase 4a gap, see
 * src/magnus_quic.h; only the HTTPS listener's cert hot-reloads today. */
static char magnus_tls_cert_path[MAGNUS_CONFIG_PATH_MAX];
static char magnus_tls_key_path[MAGNUS_CONFIG_PATH_MAX];

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
static int magnus_handle_write(int epoll_fd, magnus_connection_t *connection);
static int magnus_ws_update_interest(int epoll_fd, magnus_connection_t *connection);
static int magnus_ws_service(int epoll_fd, magnus_connection_t *connection);
static int magnus_h2_session_create(magnus_connection_t *connection);
static int magnus_h2_service(int epoll_fd, magnus_connection_t *connection);
static void magnus_h2_close(magnus_connection_t *connection);
static void magnus_h2_proxy_start(magnus_connection_t *connection,
                                  struct magnus_h2_stream *stream,
                                  const char *forward_path,
                                  bool cache_route_enabled);
static void magnus_h2_submit_cached_response(magnus_connection_t *connection,
                                             struct magnus_h2_stream *stream,
                                             magnus_cache_entry_t *entry,
                                             const char *x_cache_value);
static void magnus_h2_grpc_start(magnus_connection_t *connection,
                                 struct magnus_h2_stream *stream);
static int magnus_h2_handle_upstream(struct magnus_h2_stream *stream,
                                     uint32_t flags);
static int magnus_grpc_conn_push(magnus_grpc_conn_t *conn);
static void magnus_grpc_conn_maybe_close_idle(magnus_grpc_conn_t *conn);
static int magnus_h2_grpc_relay_request_chunk(struct magnus_h2_stream *stream,
                                              const uint8_t *data, size_t len);
static void magnus_h2_grpc_fail_or_abort(magnus_connection_t *connection,
                                         struct magnus_h2_stream *stream,
                                         const char *grpc_status_code,
                                         const char *message);
static void magnus_h2_submit_text(magnus_connection_t *connection,
                                  struct magnus_h2_stream *stream,
                                  const char *status, const char *content_type,
                                  const char *body, bool head_only);
static nghttp2_ssize magnus_h2_read_io_buffer(nghttp2_session *session,
                                              int32_t stream_id, uint8_t *buf,
                                              size_t length,
                                              uint32_t *data_flags,
                                              nghttp2_data_source *source,
                                              void *user_data);
static void magnus_build_metrics(char *out, size_t out_capacity);
static uint64_t magnus_now_ms(void);
static int magnus_proxy_pick_and_start(int epoll_fd,
                                       magnus_connection_t *connection,
                                       magnus_request_t *request,
                                       const magnus_http_request_t *parsed,
                                       const char *forward_path,
                                       const char *client_affinity_key,
                                       bool client_wants_close,
                                       bool cache_route_enabled);

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
    free(connection->compressed_body);
    free(connection->proxy_buffer);
    free(connection->proxy_header_out);
    free(connection->cache_capture);
    free(connection->cache_serve_headers);
    free(connection->cache_serve_body);
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

/* `grpc_status` is one of the 17 canonical gRPC status codes (0-16) for a
 * gRPC-dispatched request (roadmap 2c-4), or -1 for every other request --
 * the wire :status a gRPC response carries is always 200 regardless of
 * outcome (see magnus_h2_grpc_fail()'s own comment), so without this the
 * access log's own status= field cannot tell a successful RPC from a
 * failed one at all. Appended as its own grpc_status= field rather than
 * folded into status= itself, so every other request's log line (the
 * overwhelming majority, even on a deployment that does use gRPC) stays
 * exactly as it always has -- no reader has to special-case a field that
 * is only ever present for one kind of request. */
static void
magnus_access_log(const char *request_id, struct in_addr client_address,
                  const char *method, const char *target, unsigned status,
                  double latency_ms, int grpc_status)
{
    int written;
    char client_ip[INET_ADDRSTRLEN];
    char grpc_field[32] = "";
    if (!magnus_access_log_enabled) return;
    magnus_access_log_seen++;
    if (magnus_access_log_sample > 1
        && (magnus_access_log_seen % magnus_access_log_sample) != 0) return;
    inet_ntop(AF_INET, &client_address, client_ip, sizeof(client_ip));
    if (grpc_status >= 0)
        snprintf(grpc_field, sizeof(grpc_field), "grpc_status=%d ", grpc_status);
    written = snprintf(magnus_access_log_buffer + magnus_access_log_length,
        sizeof(magnus_access_log_buffer) - magnus_access_log_length,
        "access request_id=%s method=%s target=%s status=%u "
        "latency_ms=%.2f %sclient_ip=%s\n", request_id, method, target, status,
        latency_ms, grpc_field, client_ip);
    if (written < 0) return;
    if ((size_t) written >= sizeof(magnus_access_log_buffer)
                            - magnus_access_log_length) {
        magnus_access_log_flush();
        written = snprintf(magnus_access_log_buffer,
            sizeof(magnus_access_log_buffer),
            "access request_id=%s method=%s target=%s status=%u "
            "latency_ms=%.2f %sclient_ip=%s\n", request_id, method, target,
            status, latency_ms, grpc_field, client_ip);
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
    /* Advanced load balancing (roadmap 2e-1): the one point every h1
     * proxy attempt -- fresh or retried, websocket or not -- always
     * passes through on a successful attach, so this is the one place
     * magnus_cluster_endpoint_begin() needs calling at all. */
    magnus_cluster_endpoint_begin(&magnus_cluster, endpoint_index);
    connection->proxy_endpoint_counted = true;
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

/* Appends `data`/`len` to connection->cache_capture (growable, doubling,
 * same shape as the gRPC pool's own io_buffer growth -- see
 * magnus_h2_grpc_client_on_data_chunk_recv()'s own comment on that
 * precedent), bounded by MAGNUS_CACHE_MAX_ENTRY_BYTES. A no-op once
 * cache_capture_overflowed is already true (or on this call's own
 * allocation failure, which sets it) -- capture is always a pure,
 * silently-declinable side observation of a response magnus is relaying
 * to the client regardless, so its failure must never affect (or even be
 * visible to) the normal relay path at all. */
static void
magnus_proxy_cache_capture(magnus_connection_t *connection, const char *data,
                           size_t len)
{
    if (!connection->cache_enabled || connection->cache_capture_overflowed
        || len == 0)
        return;
    if (connection->cache_capture_length + len > MAGNUS_CACHE_MAX_ENTRY_BYTES) {
        connection->cache_capture_overflowed = true;
        return;
    }
    if (connection->cache_capture_length + len
        > connection->cache_capture_capacity) {
        size_t new_capacity = connection->cache_capture_capacity == 0
            ? MAGNUS_PROXY_BUFFER : connection->cache_capture_capacity * 2;
        char *grown;
        while (new_capacity < connection->cache_capture_length + len)
            new_capacity *= 2;
        grown = realloc(connection->cache_capture, new_capacity);
        if (grown == NULL) {
            connection->cache_capture_overflowed = true;
            return;
        }
        connection->cache_capture = grown;
        connection->cache_capture_capacity = new_capacity;
    }
    memcpy(connection->cache_capture + connection->cache_capture_length, data,
          len);
    connection->cache_capture_length += len;
}

/* Serves a stored magnus_cache_entry_t directly to the client -- a cold
 * HIT, or a successful revalidation (a 304 from the upstream) -- entirely
 * bypassing the upstream for this one request. `x_cache_value` names
 * which of those this was ("HIT" or "REVALIDATED"), reported back to the
 * client via a new X-Cache response header, the same observability
 * marker nginx/Varnish both already use.
 *
 * Synthesizes a *fresh* status-line-plus-headers block for cache_serve_headers
 * -- the entry's own stored pass-through headers, followed by a newly
 * computed Content-Length/Connection/X-Cache/X-Magnus-Via -- never the
 * verbatim framing whichever earlier response happened to produce this
 * entry used, since Content-Length must match *this* cached body's own
 * length regardless of what the origin originally sent (already true by
 * construction, but recomputing it fresh here does not depend on that),
 * and Connection depends on *this* client's own request, not whichever
 * client's request first populated the entry. cache_serve_body is a
 * private copy of the entry's own stored body -- copied, not referenced,
 * so this client's own slow-consumer pace can never be coupled to (or,
 * worse, outlive) the cache entry itself being evicted/replaced by an
 * unrelated request mid-flight; see cache_serve_body's own struct
 * comment. Mirrors magnus_prepare_response()'s own counters/phase-hook
 * side effects so a cache-served response is indistinguishable from any
 * other synchronous dispatch to everything downstream of it (metrics,
 * the PHASE_RESPONSE hook, the common access-log tail in
 * magnus_dispatch_request()).
 *
 * Returns 0 on success (the response is now queued; magnus_handle_write()'s
 * existing cache_serve_* drain, mirroring compressed_body's own, picks it
 * up from here). Returns -1 on allocation failure, in which case nothing
 * was queued and the caller must fall back to an ordinary upstream fetch
 * instead -- a cache-serve failure is never a client-visible error on its
 * own, only ever a missed optimization. */
static int
magnus_serve_cached_response(magnus_connection_t *connection,
                             magnus_cache_entry_t *entry,
                             bool client_wants_close,
                             const char *x_cache_value,
                             magnus_request_t *request)
{
    const char *headers, *body, *etag, *last_modified;
    size_t headers_length, body_length;
    char *header_block;
    int written;
    bool keep_alive = !client_wants_close;
    (void) etag;
    (void) last_modified;

    magnus_cache_entry_data(entry, &headers, &headers_length, &body,
                            &body_length, &etag, &last_modified);

    /* +192 is generous headroom for the trailer this call appends below
     * (Content-Length/Connection/X-Cache/X-Magnus-Via/blank line) --
     * comparable in spirit to MAGNUS_PROXY_SANITIZED_LIMIT's own margin
     * over MAGNUS_PROXY_HEADER_LIMIT for the same kind of appended
     * trailer. */
    header_block = malloc(headers_length + 192);
    if (header_block == NULL) return -1;
    memcpy(header_block, headers, headers_length);
    written = snprintf(header_block + headers_length, 192,
        "Content-Length: %zu\r\nConnection: %s\r\nX-Cache: %s\r\n"
        "X-Magnus-Via: magnus-proxy/0.1\r\n\r\n",
        body_length, keep_alive ? "keep-alive" : "close", x_cache_value);
    if (written < 0 || (size_t) written >= 192) {
        free(header_block);
        return -1;
    }

    if (body_length > 0) {
        connection->cache_serve_body = malloc(body_length);
        if (connection->cache_serve_body == NULL) {
            free(header_block);
            return -1;
        }
        memcpy(connection->cache_serve_body, body, body_length);
    }
    connection->cache_serve_headers = header_block;
    connection->cache_serve_headers_length = headers_length + (size_t) written;
    connection->cache_serve_headers_sent = 0;
    connection->cache_serve_body_length = body_length;
    connection->cache_serve_body_sent = 0;
    connection->close_after_write = !keep_alive;

    request->status = (unsigned) magnus_cache_entry_status(entry);
    magnus_requests_total++;
    (void) magnus_phase_run(&magnus_phases, MAGNUS_PHASE_RESPONSE, request);
    return 0;
}

/* Builds the outbound proxy request once, then selects a healthy cluster
 * endpoint and connects to it, retrying against a different endpoint -- up
 * to MAGNUS_PROXY_MAX_ATTEMPTS total attempts -- if the connect itself
 * fails immediately. Returns 0 if an attempt is now in flight (client
 * interest already updated to watch for abort), 2 if the request was
 * answered synchronously and completely from the reverse-proxy cache
 * (roadmap 2d-1, `cache_route_enabled` -- a GET with a fresh stored entry;
 * see magnus_serve_cached_response()) with no upstream ever touched, or -1
 * if no healthy endpoint was available or the retry budget was exhausted.
 * A stale-but-still-revalidatable entry (has an ETag/Last-Modified but its
 * freshness window has passed) is neither of those: it still returns 0
 * like an ordinary fetch, just with conditional If-None-Match/
 * If-Modified-Since headers added to the outbound request -- see
 * `cache_revalidating`'s own struct comment for how the eventual 304-or-
 * not outcome is handled once headers come back.
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
                            magnus_request_t *request,
                            const magnus_http_request_t *parsed,
                            const char *forward_path,
                            const char *client_affinity_cookie,
                            bool client_wants_close, bool cache_route_enabled)
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
                                                 NULL, connection->client_address);
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

    /* Reverse-proxy cache (roadmap 2d-1): only ever consulted for a GET
     * on a route that opted in (cache_route_enabled -- action=proxy;
     * cache=on). A fresh hit answers the request right here, with no
     * upstream ever touched; a stale hit that still carries a validator
     * switches this attempt into a conditional GET instead (below), so a
     * confirming 304 can refresh the entry without re-transferring its
     * body; anything else (no entry, or stale with no validator) is an
     * ordinary miss and falls straight through to the plain fetch this
     * function has always done. */
    connection->cache_enabled = cache_route_enabled;
    connection->cache_revalidating = false;
    connection->cache_this_response_cacheable = false;
    connection->cache_capture_overflowed = false;
    if (cache_route_enabled && strcmp(request->method, "GET") == 0) {
        strncpy(connection->cache_host, parsed->host,
               sizeof(connection->cache_host) - 1);
        connection->cache_host[sizeof(connection->cache_host) - 1] = '\0';
        strncpy(connection->cache_target, forward_path,
               sizeof(connection->cache_target) - 1);
        connection->cache_target[sizeof(connection->cache_target) - 1] = '\0';

        magnus_cache_entry_t *entry
            = magnus_cache_lookup(connection->cache_host, connection->cache_target);
        if (entry != NULL
            && magnus_cache_entry_is_fresh(entry, magnus_cache_now_ms())) {
            if (magnus_serve_cached_response(connection, entry, client_wants_close,
                                             "HIT", request) == 0)
                return 2;
            /* Allocation failure serving from cache: never a client-visible
             * error on its own (see magnus_serve_cached_response()'s own
             * comment) -- falls through to an ordinary upstream fetch
             * instead, exactly as if this had been a miss. */
        } else if (entry != NULL && magnus_cache_entry_has_validator(entry)) {
            const char *h, *b, *etag, *last_modified;
            size_t hl, bl;
            magnus_cache_entry_data(entry, &h, &hl, &b, &bl, &etag,
                                    &last_modified);
            connection->cache_revalidating = true;
            strncpy(connection->cache_validator_etag, etag,
                   sizeof(connection->cache_validator_etag) - 1);
            connection->cache_validator_etag[
                sizeof(connection->cache_validator_etag) - 1] = '\0';
            strncpy(connection->cache_validator_last_modified, last_modified,
                   sizeof(connection->cache_validator_last_modified) - 1);
            connection->cache_validator_last_modified[
                sizeof(connection->cache_validator_last_modified) - 1] = '\0';
        }
        /* else: no entry at all, or a stale one with no validator to
         * revalidate against -- an ordinary miss, indistinguishable from
         * here on out from a route that just enabled caching for the
         * first time. */
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
     * closed connection can stay unresolved.
     *
     * cache_revalidating (roadmap 2d-1) adds If-None-Match/If-Modified-
     * Since, built once into a small fragment first rather than juggling
     * conditional format strings -- only ever reachable for a bodyless
     * GET (see the cache lookup above, which only ever sets it for a GET,
     * and a cacheable request is never one this codebase attaches a body
     * to), so only the body_length==0 branch below needs it. */
    char conditional_headers[300] = "";
    if (connection->cache_revalidating) {
        size_t off = 0;
        int w;
        if (connection->cache_validator_etag[0] != '\0') {
            w = snprintf(conditional_headers + off, sizeof(conditional_headers) - off,
                        "If-None-Match: %s\r\n", connection->cache_validator_etag);
            if (w > 0 && (size_t) w < sizeof(conditional_headers) - off) off += (size_t) w;
        }
        if (connection->cache_validator_last_modified[0] != '\0') {
            w = snprintf(conditional_headers + off, sizeof(conditional_headers) - off,
                        "If-Modified-Since: %s\r\n",
                        connection->cache_validator_last_modified);
            if (w > 0 && (size_t) w < sizeof(conditional_headers) - off) off += (size_t) w;
        }
    }
    written = connection->body_length > 0
        ? snprintf(connection->proxy_request, sizeof(connection->proxy_request),
                   "%s %s HTTP/1.0\r\nHost: magnus-upstream\r\n"
                   "Connection: keep-alive\r\nContent-Length: %zu\r\n"
                   "X-Magnus-Request-Id: %s\r\n\r\n",
                   request->method, forward_path,
                   connection->body_length, request->request_id)
        : snprintf(connection->proxy_request, sizeof(connection->proxy_request),
                   "%s %s HTTP/1.0\r\nHost: magnus-upstream\r\n"
                   "Connection: keep-alive\r\n%sX-Magnus-Request-Id: %s\r\n\r\n",
                   request->method, forward_path, conditional_headers,
                   request->request_id);
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
                                           preferred_index,
                                           connection->client_address)
            : magnus_cluster_select(&magnus_cluster, magnus_now_ms(), NULL,
                                    connection->client_address);
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
    /* Advanced load balancing (roadmap 2e-1): released here for every
     * abnormal/non-poolable ending this attempt can have (fail/abort, a
     * connect that never completed, a non-poolable clean completion) --
     * the poolable clean-completion case releases inline at
     * magnus_proxy_flush()'s own pool-checkin instead, since that path
     * never reaches here at all; either way this is guarded so it is
     * always exactly one release per magnus_proxy_attach_upstream()'s own
     * begin, regardless of which path actually fires. */
    if (connection->proxy_endpoint_counted) {
        magnus_cluster_endpoint_end(&magnus_cluster, connection->proxy_endpoint_index);
        connection->proxy_endpoint_counted = false;
    }
    free(connection->proxy_buffer);
    connection->proxy_buffer = NULL;
    free(connection->proxy_header_out);
    connection->proxy_header_out = NULL;
    /* Whatever this one attempt had captured toward a possible cache
     * store (roadmap 2d-1) never outlives the attempt: a retry's fresh
     * response must not be prefixed by a failed attempt's partial bytes,
     * and a successful, cacheable completion has already handed this
     * buffer's contents to magnus_cache_store() before ever reaching here
     * -- see magnus_proxy_flush()'s own "response complete" branch, which
     * always stores (if applicable) first and tears down after. */
    free(connection->cache_capture);
    connection->cache_capture = NULL;
    connection->cache_capture_length = 0;
    connection->cache_capture_capacity = 0;
    connection->cache_capture_overflowed = false;
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
        magnus_access_log(request.request_id, connection->client_address,
                          connection->proxy_log_method,
                          connection->proxy_log_target, status, latency_ms,
                          -1);
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
                                             NULL, connection->client_address);
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

        /* Reverse-proxy cache (roadmap 2d-1): commits the captured body
         * (if capturing was ever attempted and never overflowed) now that
         * the whole response is known complete -- before either upstream-
         * leg outcome below, both of which can free cache_capture (the
         * pool-checkin branch does not touch it, but
         * magnus_proxy_teardown_upstream() does, and this must not race
         * that). */
        if (connection->cache_this_response_cacheable
            && !connection->cache_capture_overflowed) {
            magnus_cache_store(connection->cache_host, connection->cache_target,
                200, connection->cache_pending_headers,
                connection->cache_pending_headers_length, connection->cache_capture,
                connection->cache_capture_length, connection->cache_response_etag,
                connection->cache_response_last_modified,
                &connection->cache_freshness);
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
            /* Advanced load balancing (roadmap 2e-1): the one release
             * site magnus_proxy_teardown_upstream()'s own does not cover
             * -- see that function's own comment. */
            if (connection->proxy_endpoint_counted) {
                magnus_cluster_endpoint_end(&magnus_cluster,
                                            connection->proxy_endpoint_index);
                connection->proxy_endpoint_counted = false;
            }
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
    size_t cacheable_prefix_length = 0;

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
        connection->proxy_client_wants_close, &info, &cacheable_prefix_length);
    if (sanitized_length < 0)
        return magnus_proxy_connect_failed(epoll_fd, connection, 502,
                                           "Bad Gateway");

    /* Reverse-proxy cache (roadmap 2d-1): a successful revalidation -- the
     * one outcome this attempt was actually sent as a conditional GET for
     * (see magnus_proxy_pick_and_start()'s own cache_revalidating branch).
     * A 304 carries no body by definition (RFC 9110 15.4.5), so this
     * upstream leg is already fully "received" the moment its headers
     * are -- finished off directly here (pool-checkin or teardown, same
     * decision magnus_proxy_flush()'s own completion branch makes) rather
     * than through the normal buffered body-relay path below, which has
     * nothing of this response's own to relay: the *cached* body is what
     * actually goes to the client, via the exact same
     * magnus_serve_cached_response() a cold HIT uses, just with a
     * different X-Cache value. */
    if (connection->cache_revalidating && info.status == 304) {
        magnus_cache_entry_t *entry;
        if (info.upstream_poolable && connection->upstream_fd >= 0) {
            int fd = connection->upstream_fd;
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
            magnus_upstream_owner[fd] = NULL;
            connection->upstream_fd = -1;
            magnus_pool_checkin(connection->proxy_endpoint_index, fd,
                connection->proxy_upstream_requests_served + 1);
            /* Advanced load balancing (roadmap 2e-1): same release-site
             * gap as magnus_proxy_flush()'s own pool-checkin branch --
             * see that one's own comment. */
            if (connection->proxy_endpoint_counted) {
                magnus_cluster_endpoint_end(&magnus_cluster,
                                            connection->proxy_endpoint_index);
                connection->proxy_endpoint_counted = false;
            }
            connection->proxy_active = false;
            free(connection->proxy_buffer);
            connection->proxy_buffer = NULL;
            free(connection->proxy_header_out);
            connection->proxy_header_out = NULL;
        } else {
            magnus_proxy_teardown_upstream(epoll_fd, connection);
        }

        entry = magnus_cache_lookup(connection->cache_host, connection->cache_target);
        if (entry != NULL) {
            magnus_cache_freshness_t freshness;
            magnus_cache_compute_freshness(
                info.cache_control[0] != '\0' ? info.cache_control : NULL,
                info.expires[0] != '\0' ? info.expires : NULL, NULL, false,
                magnus_cache_now_ms(), &freshness);
            magnus_cache_revalidated(entry, &freshness);
            {
                magnus_request_t log_request = {0};
                memcpy(log_request.request_id, connection->proxy_request_id,
                      sizeof(log_request.request_id));
                if (magnus_serve_cached_response(connection, entry,
                        connection->proxy_client_wants_close, "REVALIDATED",
                        &log_request) == 0) {
                    double latency_ms = (double) (magnus_now_ms()
                                                  - connection->request_started_ms);
                    magnus_record_latency(latency_ms);
                    magnus_access_log(connection->proxy_request_id,
                                      connection->client_address,
                                      connection->proxy_log_method,
                                      connection->proxy_log_target,
                                      log_request.status, latency_ms, -1);
                    (void) magnus_update_interest(epoll_fd, connection,
                                                  EPOLLOUT | EPOLLRDHUP);
                    return magnus_handle_write(epoll_fd, connection);
                }
            }
        }
        /* The entry vanished between this attempt starting and the 304
         * arriving (evicted by unrelated cache pressure elsewhere -- a
         * narrow, honest-to-admit race, not a bug: this module never
         * promised an entry survives an async round trip -- see
         * magnus_cache_entry_data()'s own comment), or serving it failed
         * outright. Either way there is nothing left to honestly answer
         * with (a 304 carries no body of its own to fall back to), so
         * this is treated like any other upstream response this codebase
         * cannot make sense of. */
        return magnus_proxy_fail(epoll_fd, connection, 502, "Bad Gateway");
    }

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
                              connection->client_address,
                              connection->proxy_log_method,
                              connection->proxy_log_target, 101, latency_ms,
                              -1);
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

    /* Reverse-proxy cache (roadmap 2d-1): decided once, right here, the
     * moment headers (and therefore Cache-Control/Expires/Vary/Set-Cookie/
     * status) are known -- only ever true for a route that opted in
     * (cache_enabled) and a 200 response (the only status this increment
     * ever caches; see magnus_cache.h's own top comment). A response that
     * arrived as a revalidation attempt but turned out *not* to be a 304
     * (the origin decided to send fresh content instead -- handled
     * entirely above, before this point, when it *is* a 304) is judged by
     * exactly the same rule as any ordinary fetch: this simply overwrites
     * whatever stale entry prompted the revalidation once the body
     * completes, same as magnus_cache_store()'s own replace-in-place
     * behavior already does for any repeat store. Body bytes are captured
     * from here on (this leftover chunk now, every subsequent
     * magnus_handle_upstream() recv() later) purely as a side observation
     * -- see magnus_proxy_cache_capture()'s own comment on why its
     * failure can never affect the normal relay below. */
    connection->cache_this_response_cacheable = false;
    if (connection->cache_enabled && info.status == 200) {
        magnus_cache_compute_freshness(
            info.cache_control[0] != '\0' ? info.cache_control : NULL,
            info.expires[0] != '\0' ? info.expires : NULL,
            info.vary[0] != '\0' ? info.vary : NULL, info.has_set_cookie,
            magnus_cache_now_ms(), &connection->cache_freshness);
        connection->cache_this_response_cacheable
            = connection->cache_freshness.cacheable;
    }
    if (connection->cache_this_response_cacheable) {
        memcpy(connection->cache_pending_headers, sanitized,
              cacheable_prefix_length);
        connection->cache_pending_headers_length = cacheable_prefix_length;
        strcpy(connection->cache_response_etag, info.etag);
        strcpy(connection->cache_response_last_modified, info.last_modified);
        magnus_proxy_cache_capture(connection, body_start, leftover);
    }

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
                          connection->client_address,
                          connection->proxy_log_method,
                          connection->proxy_log_target, info.status,
                          latency_ms, -1);
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
            if (connection->cache_this_response_cacheable)
                magnus_proxy_cache_capture(connection, connection->proxy_buffer,
                    (size_t) received);
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

const char *
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

/* The first compression increment buffers bounded static files completely so
 * both protocols can send an exact compressed Content-Length. Files outside
 * the 256-byte..8-MiB window retain their existing streaming path. */
static int
magnus_compress_static(int fd, const struct stat *metadata,
                       const magnus_http_request_t *request,
                       const char *content_type, unsigned char **output,
                       size_t *output_length)
{
    unsigned char *input;
    size_t length;
    size_t offset = 0;
    if (metadata->st_size < MAGNUS_COMPRESSION_MIN_SIZE
        || metadata->st_size > MAGNUS_COMPRESSION_MAX_SIZE
        || !magnus_content_type_compressible(content_type)
        || !magnus_accepts_gzip(
            magnus_http_header_find(request, "accept-encoding"))) return 0;
    length = (size_t) metadata->st_size;
    input = malloc(length);
    if (input == NULL) return 0;
    while (offset < length) {
        ssize_t got = pread(fd, input + offset, length - offset, (off_t) offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) {
            free(input);
            return 0;
        }
        offset += (size_t) got;
    }
    if (magnus_gzip_compress(input, length, output, output_length) != 0) {
        free(input);
        return 0;
    }
    free(input);
    return 1;
}

int
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
                             bool close_connection, magnus_request_t *request,
                             const magnus_http_request_t *parsed)
{
    int written;
    const char *content_type = magnus_content_type(request->path);
    unsigned char *compressed = NULL;
    size_t compressed_length = 0;
    bool use_gzip = magnus_compress_static(file_fd, metadata, parsed,
                                           content_type, &compressed,
                                           &compressed_length) == 1;
    long long response_length = use_gzip
        ? (long long) compressed_length : (long long) metadata->st_size;
    request->status = 200;
    magnus_requests_total++;
    (void) magnus_phase_run(&magnus_phases, MAGNUS_PHASE_RESPONSE, request);
    written = snprintf(connection->output, sizeof(connection->output),
        "HTTP/1.1 200 OK\r\nServer: Magnus/%s\r\nContent-Type: %s\r\n"
        "Content-Length: %lld\r\n%s%sConnection: %s\r\nAccept-Ranges: bytes\r\n"
        "X-Magnus-Engine: native-c17/0.1\r\nX-Magnus-Request-Id: %s\r\n\r\n",
        MAGNUS_VERSION, content_type, response_length,
        use_gzip ? "Content-Encoding: gzip\r\n" : "",
        use_gzip ? "Vary: Accept-Encoding\r\n" : "",
        close_connection ? "close" : "keep-alive",
        request->request_id);
    if (written < 0 || (size_t) written >= sizeof(connection->output)) {
        close(file_fd);
        free(compressed);
        connection->output_length = 0;
        connection->close_after_write = true;
        return;
    }
    connection->output_length = (size_t) written;
    connection->output_sent = 0;
    connection->close_after_write = close_connection;
    connection->file_fd = (head_only || use_gzip) ? -1 : file_fd;
    connection->file_offset = 0;
    connection->file_length = head_only ? 0 : metadata->st_size;
    if (use_gzip) {
        close(file_fd);
        if (head_only) {
            free(compressed);
        } else {
            connection->compressed_body = compressed;
            connection->compressed_body_length = compressed_length;
            connection->compressed_body_sent = 0;
        }
    } else if (head_only) {
        close(file_fd);
    }
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
    /* Real IP (roadmap 2b): this stream's own resolved client address,
     * used for route source-CIDR matching, rate limiting, and access
     * logging in place of connection->client_address. h2 multiplexes many
     * concurrent streams over one connection, so a Forwarded/
     * X-Forwarded-For value is never safe to resolve into the
     * connection-level client_address the way HTTP/1.1 does at the top of
     * magnus_dispatch_request() -- two streams racing that mutation could
     * see (or log) each other's resolved address. Set once, at the top of
     * magnus_h2_dispatch(), from connection->client_address by default
     * (see magnus_h2_stream_new()) and overwritten only if this stream's
     * own headers resolve a trusted, more specific value. */
    struct in_addr effective_client_address;
    /* Set the moment magnus_h2_dispatch() runs its committing pass (see
     * that function's own comment on why it can now run twice per stream
     * -- an early, headers-only call for a gRPC route, deferred calls for
     * everything else -- but must only ever *commit* once), so a second
     * END_STREAM-bearing frame on the same stream (defensively -- HTTP/2
     * framing should never actually produce one) cannot dispatch it
     * twice. */
    bool dispatched;
    /* True from the moment ANY frame (HEADERS or DATA) carrying
     * NGHTTP2_FLAG_END_STREAM has been observed for this stream's
     * *request* -- i.e. "the whole request body, if any, is now fully
     * known" -- independent of whether dispatch() has actually committed
     * yet. Sets apart "headers are complete" (magnus_h2_dispatch() is
     * always callable once that's true) from "the whole request is
     * complete" (which is what every non-streaming dispatch still needs
     * before it may safely act -- see magnus_h2_dispatch()'s own
     * comment). */
    bool request_end_stream_seen;

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
    /* Advanced load balancing (roadmap 2e-1) -- the h2 analogue of
     * magnus_connection_t's own identically-named field; see that one's
     * comment. Only ever set for an is_proxy stream (gRPC streams never
     * touch magnus_cluster at all -- they have their own separate
     * magnus_grpc_cluster, out of scope for this increment). */
    bool cluster_endpoint_counted;
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
    /* Reverse-proxy cache (roadmap 2d-1) -- the h2 analogue of
     * magnus_connection_t's own identically-named fields; see those for
     * the full rationale. No cache_serve_* here at all: an h2 cache-hit
     * response reuses stream->io_buffer/magnus_h2_read_io_buffer()
     * directly (see magnus_h2_submit_cached_response()), the same
     * whole-body-known-upfront plumbing magnus_h2_submit_text() already
     * established for /healthz//metrics -- h2 never needed a second,
     * dedicated buffer the way HTTP/1.1's own separate proxy-flush vs.
     * synchronous-write code paths did. */
    bool cache_enabled;
    bool cache_revalidating;
    char cache_host[256];
    char cache_target[256];
    char cache_validator_etag[128];
    char cache_validator_last_modified[64];
    bool cache_this_response_cacheable;
    magnus_cache_freshness_t cache_freshness;
    /* h2 has no persisted raw sanitized-text buffer to defer to the way
     * HTTP/1.1's own connection->proxy_header_out stays around until
     * teardown (magnus_h2_proxy_submit_response() tokenizes the sanitized
     * block into nghttp2 name/value pairs and its own text is stack-
     * local) -- so the cacheable prefix is copied out here, verbatim, at
     * header time instead of remembered by reference/offset. */
    char cache_pending_headers[MAGNUS_PROXY_SANITIZED_LIMIT];
    size_t cache_pending_headers_length;
    char cache_response_etag[128];
    char cache_response_last_modified[64];
    char *cache_capture;
    size_t cache_capture_length;
    size_t cache_capture_capacity;
    bool cache_capture_overflowed;
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
    /* gRPC path only (2c-1): io_buffer's current malloc()'d size, grown
     * (realloc, doubling) as the upstream's response DATA accumulates --
     * unlike the h1-proxy path above, which streams a fixed
     * MAGNUS_PROXY_BUFFER window and never needs to grow it, gRPC's
     * "buffer the whole unary response before ever telling the client
     * anything" design (see magnus_h2_grpc_client_on_stream_close()) needs
     * genuine growth. Stays 0 for an h1-proxy stream. */
    size_t io_capacity;
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

    /* -- gRPC dispatch (roadmap 2c-1, streaming since 2c-2): client h2
     * stream -> upstream h2 (gRPC) server -- see the block comment above
     * magnus_h2_grpc_start() for the full design. Reuses body/
     * body_length/body_sent above as a *sliding* request-body relay
     * queue (bytes the client has sent but magnus has not yet forwarded
     * to the upstream -- compacted as they drain, not "the whole request,
     * known upfront" the way the h1-proxy path's own body_* fields are),
     * and io_buffer/io_length/io_sent above the same way for the
     * upstream's response body in the other direction; only what
     * genuinely differs (a second, magnus-owned nghttp2 CLIENT session
     * driving the upstream leg, since a real gRPC server requires actual
     * h2 trailers HTTP/1.1 cannot carry) gets new fields below. */
    bool is_grpc;
    /* Pooled/shared upstream connection (roadmap 2c-5) this RPC is
     * currently attached to, or NULL if none. `grpc_session` is kept as a
     * plain cached copy of `grpc_conn->session` (always in sync -- set
     * together at attach, cleared together at detach) purely so the many
     * existing call sites that already reference stream->grpc_session
     * directly (nghttp2_session_resume_data(stream->grpc_session, ...),
     * mainly) did not all need touching when the session itself moved
     * from being stream-owned to conn-owned. `grpc_conn_next`/
     * `grpc_conn_prev` thread this stream into its conn's own intrusive
     * `streams` list -- see magnus_grpc_conn_t's own comment. */
    magnus_grpc_conn_t *grpc_conn;
    struct magnus_h2_stream *grpc_conn_next;
    struct magnus_h2_stream *grpc_conn_prev;
    nghttp2_session *grpc_session;
    int32_t grpc_stream_id;
    /* Deadline propagation (roadmap 2c-3): an absolute magnus_now_ms()
     * deadline parsed from the client's own "grpc-timeout" request
     * header (magnus_grpc_parse_timeout()), clamped to
     * MAGNUS_GRPC_MAX_TIMEOUT_MS -- 0 means the client sent no
     * grpc-timeout at all (or a malformed one), in which case this
     * stream falls back to the same default MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS/
     * MAGNUS_PROXY_READ_TIMEOUT_SECONDS budget every other proxy/gRPC
     * stream already gets (see magnus_expire_proxies()). Set exactly
     * once, in magnus_h2_grpc_start(), and never recomputed across a
     * connect retry to a different endpoint -- it is the deadline for
     * the *whole* RPC as the client defined it, not a per-attempt one. */
    uint64_t grpc_deadline_ms;
    /* True if magnus_h2_grpc_read_request_body() last returned
     * NGHTTP2_ERR_DEFERRED because it caught up with everything the
     * client has sent so far and request_end_stream_seen was not yet
     * true -- the request-body-direction analogue of the existing
     * `deferred` field above, which is the response direction's own.
     * Whoever next adds bytes (magnus_h2_on_data_chunk_recv(), for a
     * dispatched gRPC stream) or observes request_end_stream_seen
     * becoming true must call nghttp2_session_resume_data() on
     * grpc_session to make it eligible again. */
    bool grpc_request_deferred;
    /* Set (only) by magnus_h2_grpc_client_on_stream_close() -- the
     * upstream nghttp2 session's callback context, where it is unsafe to
     * do anything more than record the fact (see this section's own
     * comment on why nghttp2_session_del() must never be called from
     * inside one of that same session's own callbacks). The real
     * finalization (marking response_complete so the client-facing data
     * provider knows it is safe to emit the trailer once io_buffer
     * drains, or -- if the upstream never even got as far as sending
     * response headers -- a synthesized UNAVAILABLE failure) happens back
     * in magnus_grpc_conn_finalize_closed_streams(), checked right after
     * each nghttp2_session_mem_recv2() round (and, since 2c-5, also from
     * magnus_grpc_conn_push() -- see that function's own comment). */
    bool grpc_stream_closed;
    /* Captured from the upstream response's leading HEADERS frame
     * (NGHTTP2_HCAT_RESPONSE) -- :status, plus every ordinary header
     * (content-type, grpc-encoding, ...) -- to forward to the real client
     * once the whole exchange is known complete (see
     * magnus_h2_grpc_client_on_stream_close()). grpc-status/grpc-message
     * are captured separately below, not into this array, since they
     * belong in the *trailer* this stream submits to the client, not its
     * initial response headers. */
    char grpc_response_status[8];
    magnus_http_header_t grpc_response_headers[16];
    size_t grpc_response_header_count;
    /* Captured from whichever HEADERS frame actually carries them --
     * either the trailer proper, or the single HEADERS frame of a
     * "Trailers-Only" error response that never sent a body at all; both
     * shapes are treated identically here, deliberately (see
     * magnus_h2_grpc_client_on_header()). Left empty until one arrives;
     * still empty at stream-close means the upstream never produced a
     * gRPC-shaped response at all (a raw transport failure, not an RPC
     * error), answered as grpc-status=14 (UNAVAILABLE) instead. */
    char grpc_status[16];
    char grpc_message[256];
    /* Any other trailer field (custom trailing metadata, e.g.
     * server-timing/cache-tag-style values a real gRPC service sets via
     * its own context.set_trailing_metadata()) -- forwarded to the real
     * client's trailer alongside grpc-status/grpc-message, not dropped,
     * since trailing metadata is a first-class part of gRPC's own
     * request/response model, not an edge case. */
    magnus_http_header_t grpc_response_trailers[8];
    size_t grpc_response_trailer_count;
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
    /* Defaults to the connection's own client_address (itself possibly
     * already PROXY-protocol-resolved at accept time) until/unless
     * magnus_h2_dispatch() resolves a per-request Forwarded/X-Forwarded-For
     * value for this specific stream -- see effective_client_address's own
     * comment on the struct field for why this cannot just be
     * connection->client_address mutated in place the way HTTP/1.1 does. */
    stream->effective_client_address = connection->client_address;
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
    if (stream->upstream_fd >= 0) {
        if (magnus_global_epoll_fd >= 0)
            epoll_ctl(magnus_global_epoll_fd, EPOLL_CTL_DEL,
                     stream->upstream_fd, NULL);
        magnus_h2_upstream_owner[stream->upstream_fd] = NULL;
        close(stream->upstream_fd);
        stream->upstream_fd = -1;
    }
    /* Advanced load balancing (roadmap 2e-1): released here for every
     * abnormal/non-poolable ending an is_proxy stream's own attempt can
     * have -- see magnus_proxy_teardown_upstream()'s own identical
     * comment. Naturally a no-op for a gRPC stream (cluster_endpoint_counted
     * is never set true for one in the first place). */
    if (stream->cluster_endpoint_counted) {
        magnus_cluster_endpoint_end(&magnus_cluster, stream->endpoint_index);
        stream->cluster_endpoint_counted = false;
    }
    /* Reverse-proxy cache (roadmap 2d-1): whatever this one attempt had
     * captured toward a possible cache store never outlives the attempt
     * -- see magnus_proxy_teardown_upstream()'s own identical comment for
     * the HTTP/1.1 path. */
    free(stream->cache_capture);
    stream->cache_capture = NULL;
    stream->cache_capture_length = 0;
    stream->cache_capture_capacity = 0;
    stream->cache_capture_overflowed = false;
    /* gRPC (2c-1, pooled/multiplexed since 2c-5): the fd/session this
     * stream's RPC was relayed through belong to the *pool*, not this
     * stream, and must never be closed/deleted just because this one RPC
     * is ending -- unlike before 2c-5, when a fresh session+connection
     * really was created and torn down per RPC. Detaching only ever
     * means: cancel the one upstream nghttp2 stream this RPC owns
     * (RST_STREAM, skipped if the upstream already closed it itself, or
     * if the connection is already known broken -- see
     * magnus_grpc_conn_fail()'s own comment on why bothering would be
     * pointless there), clear this stream's own stream_user_data
     * association so a stray late callback for this stream_id cannot
     * dereference a magnus_h2_stream about to be freed, then unlink from
     * the connection's stream list and let magnus_grpc_conn_maybe_close_idle()
     * decide whether the connection itself is now idle-and-retiring
     * enough to close. Checked unconditionally (not folded into the
     * upstream_fd guard above), since a stream can reach here via many
     * paths -- a clean RPC completion, the real client resetting its own
     * stream early, this whole client connection dying -- not only ones
     * that ever had upstream_fd set at all (gRPC streams never do; see
     * that field's own h1-proxy-only contract now). */
    if (stream->grpc_conn != NULL) {
        magnus_grpc_conn_t *conn = stream->grpc_conn;
        if (!stream->grpc_stream_closed && !conn->broken && conn->session != NULL) {
            (void) nghttp2_submit_rst_stream(conn->session, NGHTTP2_FLAG_NONE,
                                             stream->grpc_stream_id,
                                             NGHTTP2_CANCEL);
            (void) nghttp2_session_set_stream_user_data(conn->session,
                stream->grpc_stream_id, NULL);
            (void) magnus_grpc_conn_push(conn);
        }
        if (stream->grpc_conn_prev != NULL)
            stream->grpc_conn_prev->grpc_conn_next = stream->grpc_conn_next;
        else conn->streams = stream->grpc_conn_next;
        if (stream->grpc_conn_next != NULL)
            stream->grpc_conn_next->grpc_conn_prev = stream->grpc_conn_prev;
        stream->grpc_conn_next = NULL;
        stream->grpc_conn_prev = NULL;
        if (conn->active_streams > 0) conn->active_streams--;
        magnus_grpc_conn_maybe_close_idle(conn);
        stream->grpc_conn = NULL;
        stream->grpc_session = NULL;
    }
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
    free(stream->cache_capture);
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
    nghttp2_nv headers[6];
    size_t header_count = 4;
    const char *content_type;
    unsigned char *compressed = NULL;
    size_t compressed_length = 0;
    bool use_gzip;

    fd = magnus_open_static(stream->parsed.target, &metadata);
    if (fd < 0) {
        magnus_h2_submit_status(session, stream->stream_id, "404");
        return;
    }
    stream->head_only = strcmp(stream->parsed.method, "HEAD") == 0;
    content_type = magnus_content_type(stream->parsed.target);
    use_gzip = magnus_compress_static(fd, &metadata, &stream->parsed,
                                      content_type, &compressed,
                                      &compressed_length) == 1;
    stream->file_offset = 0;
    stream->file_length = use_gzip ? (off_t) compressed_length : metadata.st_size;
    snprintf(content_length, sizeof(content_length), "%lld",
            (long long) stream->file_length);
    headers[0] = magnus_h2_nv(":status", "200");
    headers[1] = magnus_h2_nv("server", "Magnus/" MAGNUS_VERSION);
    headers[2] = magnus_h2_nv("content-type", content_type);
    headers[3] = magnus_h2_nv("content-length", content_length);
    if (use_gzip) {
        headers[4] = magnus_h2_nv("content-encoding", "gzip");
        headers[5] = magnus_h2_nv("vary", "Accept-Encoding");
        header_count = 6;
    }
    if (stream->head_only) {
        close(fd);
        free(compressed);
        (void) nghttp2_submit_response2(session, stream->stream_id, headers,
                                        header_count, NULL);
        return;
    }
    if (use_gzip) {
        /* The whole compressed body is already sitting in memory --
         * exactly the same shape magnus_h2_submit_text() (1e-4,
         * /healthz//metrics) already reuses magnus_h2_read_io_buffer()
         * for, right down to needing response_complete set up front so
         * the callback knows it is safe to report EOF once the buffer
         * drains rather than ever deferring. Reused here rather than
         * given a near-identical sibling callback, for the same reason
         * every other h2 dispatch path in this file reuses an existing
         * helper instead of reimplementing it. */
        close(fd);
        stream->io_buffer = (char *) compressed;
        stream->io_length = compressed_length;
        stream->io_sent = 0;
        stream->response_complete = true;
    } else {
        stream->file_fd = fd;
    }
    {
        nghttp2_data_provider2 data_provider = {
            .source = { .ptr = stream },
            .read_callback = use_gzip ? magnus_h2_read_io_buffer
                                      : magnus_h2_read_file,
        };
        (void) nghttp2_submit_response2(session, stream->stream_id, headers,
                                        header_count, &data_provider);
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
    bool is_grpc_route = false;
    bool route_denied = false;
    bool cache_route_enabled = false;
    bool is_healthz_path;
    bool is_metrics_path;
    bool head_only;
    const char *forward_path;

    if (stream->method_overflow) {
        stream->dispatched = true;
        magnus_h2_submit_status(session, stream->stream_id, "405");
        return;
    }
    if (stream->path_overflow) {
        stream->dispatched = true;
        magnus_h2_submit_status(session, stream->stream_id, "414");
        return;
    }

    /* Real IP (roadmap 2b): resolved once, here, into this stream's own
     * effective_client_address -- never connection->client_address, which
     * a concurrently dispatching sibling stream on the same connection
     * could be reading at the same instant. Trust is always decided
     * against connection->raw_peer_address (the true, direct TCP peer),
     * never against client_address itself, so a resolved value from one
     * hop can never be replayed to forge trust for the next. */
    if (magnus_trusted_proxy_count > 0
        && magnus_realip_is_trusted(magnus_trusted_proxies,
                                    magnus_trusted_proxy_count,
                                    connection->raw_peer_address)) {
        struct in_addr resolved;
        if (magnus_realip_resolve_headers(&stream->parsed, magnus_trusted_proxies,
                                          magnus_trusted_proxy_count, &resolved)) {
            stream->effective_client_address = resolved;
        }
    }

    literal_proxy_prefix = magnus_upstream_enabled
        && strncmp(stream->parsed.target, "/proxy", 6) == 0
        && (stream->parsed.target[6] == '/' || stream->parsed.target[6] == '\0');
    is_proxy_route = literal_proxy_prefix;
    forward_path = literal_proxy_prefix ? stream->parsed.target + 6
                                        : stream->parsed.target;

    for (size_t r = 0; r < magnus_route_count; r++) {
        if (!magnus_route_matches(&magnus_routes[r], &stream->parsed,
                                  stream->effective_client_address))
            continue;
        if (magnus_routes[r].action == MAGNUS_ROUTE_ACTION_PROXY) {
            is_proxy_route = true;
            forward_path = stream->parsed.target;
            cache_route_enabled = magnus_routes[r].cache_enabled;
        } else if (magnus_routes[r].action == MAGNUS_ROUTE_ACTION_DENY) {
            route_denied = true;
        } else if (magnus_routes[r].action == MAGNUS_ROUTE_ACTION_GRPC) {
            is_grpc_route = true;
        }
        break;
    }

    /* Streaming (roadmap 2c-2): magnus_h2_on_frame_recv() now calls this
     * function as soon as the request HEADERS frame completes, not only
     * once the whole request body (if any) has arrived -- a gRPC route
     * needs that head start to begin relaying to the upstream before the
     * body is fully known (client-streaming/bidi). Every other route
     * still needs the whole body buffered first (rate limiting in
     * particular must only ever be consumed once per request), so if
     * this call is the early, headers-only one and the route is not
     * gRPC, defer: return without touching stream->dispatched, so
     * whichever later call actually observes end-of-body (routed back
     * here by that same function once the DATA-frame-carrying
     * END_STREAM arrives) is the one that commits. Re-running route
     * matching/Real IP resolution on that later call is harmless,
     * side-effect-free duplicate work -- rate limiting below is what
     * must not run twice, and it never does, since only the committing
     * call ever reaches it. */
    if (!is_grpc_route && !stream->request_end_stream_seen) return;
    stream->dispatched = true;

    /* /healthz and /metrics stay exempt from rate limiting for the same
     * reason as HTTP/1.1: they are exactly what an operator or
     * monitoring system needs to reach to see *why* real traffic is
     * being throttled, so gating them behind the same limiter would be
     * self-defeating. */
    is_healthz_path = strcmp(stream->parsed.target, "/healthz") == 0;
    is_metrics_path = strcmp(stream->parsed.target, "/metrics") == 0;
    if (!is_healthz_path && !is_metrics_path
        && !magnus_rate_check(stream->effective_client_address, time(NULL))) {
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
        && !is_proxy_route && !is_grpc_route) {
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
    if (is_grpc_route) {
        if (stream->body_overflow) {
            magnus_h2_submit_status(session, stream->stream_id, "413");
            return;
        }
        magnus_h2_grpc_start(connection, stream);
        return;
    }
    if (is_proxy_route) {
        if (stream->body_overflow) {
            magnus_h2_submit_status(session, stream->stream_id, "413");
            return;
        }
        magnus_h2_proxy_start(connection, stream, forward_path, cache_route_enabled);
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
 * failing the stream mid-flight.
 *
 * A gRPC stream that has already been dispatched (2c-2: happens as soon
 * as its request HEADERS complete, well before END_STREAM for a
 * streaming RPC) takes a completely different path instead --
 * magnus_h2_grpc_relay_request_chunk() -- relaying each chunk to the
 * upstream as it arrives rather than accumulating a "whole request"
 * MAGNUS_MAX_BODY never actually has to hold at once for a long-lived
 * streaming call. */
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

    if (stream->is_grpc && stream->dispatched) {
        if (magnus_h2_grpc_relay_request_chunk(stream, data, len) != 0) {
            stream->body_overflow = true;
            magnus_h2_grpc_fail_or_abort(stream->connection, stream, "8",
                                         "request body exceeded buffering "
                                         "limit");
        }
        return 0;
    }

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
 * further reaction from magnus itself at this stage of the roadmap.
 *
 * Streaming (2c-2): unlike before, a request HEADERS frame is inspected
 * here regardless of whether it also carries END_STREAM -- magnus_h2_
 * dispatch() is called the moment headers complete, not only once the
 * whole request is known, so a gRPC route can start relaying to the
 * upstream immediately (client-streaming/bidi) rather than waiting for a
 * body that might not finish for a long time, if ever, on its own. Every
 * other route still only *commits* inside dispatch() once
 * request_end_stream_seen is true (see that function's own comment) --
 * this callback's job is only to track that flag and re-invoke dispatch()
 * once it flips, not to decide what any given route does with it. */
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

    if (frame->hd.type != NGHTTP2_HEADERS && frame->hd.type != NGHTTP2_DATA)
        return 0;
    if (frame->hd.type == NGHTTP2_HEADERS
        && frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    stream = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (stream == NULL) return 0;

    if ((frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
        stream->request_end_stream_seen = true;
        if (stream->is_grpc && stream->grpc_session != NULL
            && stream->grpc_request_deferred) {
            stream->grpc_request_deferred = false;
            (void) nghttp2_session_resume_data(stream->grpc_session,
                                               stream->grpc_stream_id);
            if (stream->grpc_conn != NULL && stream->grpc_conn->connected)
                (void) magnus_grpc_conn_push(stream->grpc_conn);
        }
    }

    if (!stream->dispatched
        && (frame->hd.type == NGHTTP2_HEADERS
            || stream->request_end_stream_seen)) {
        magnus_h2_dispatch(connection, stream);
    }
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
    {
        magnus_record_latency(latency_ms);
        magnus_access_log(stream->request_id, stream->effective_client_address,
                          stream->log_method,
                          stream->log_target, status_code, latency_ms, -1);
    }
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
        stream->io_capacity = MAGNUS_PROXY_BUFFER;
    }
    stream->upstream_fd = fd;
    stream->upstream_connected = connected;
    stream->upstream_requests_served = requests_served;
    stream->endpoint_index = endpoint_index;
    /* Advanced load balancing (roadmap 2e-1) -- see
     * magnus_proxy_attach_upstream()'s own identical comment on why this
     * one function is the single right place for it. */
    magnus_cluster_endpoint_begin(&magnus_cluster, endpoint_index);
    stream->cluster_endpoint_counted = true;
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
                                             NULL, stream->effective_client_address);
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

/* The h2 analogue of magnus_proxy_cache_capture() -- see that function's
 * own comment for the full rationale, identical here except operating on
 * stream->cache_capture* instead of connection->cache_capture*. */
static void
magnus_h2_proxy_cache_capture(struct magnus_h2_stream *stream,
                              const char *data, size_t len)
{
    if (!stream->cache_enabled || stream->cache_capture_overflowed
        || len == 0)
        return;
    if (stream->cache_capture_length + len > MAGNUS_CACHE_MAX_ENTRY_BYTES) {
        stream->cache_capture_overflowed = true;
        return;
    }
    if (stream->cache_capture_length + len > stream->cache_capture_capacity) {
        size_t new_capacity = stream->cache_capture_capacity == 0
            ? MAGNUS_PROXY_BUFFER : stream->cache_capture_capacity * 2;
        char *grown;
        while (new_capacity < stream->cache_capture_length + len)
            new_capacity *= 2;
        grown = realloc(stream->cache_capture, new_capacity);
        if (grown == NULL) {
            stream->cache_capture_overflowed = true;
            return;
        }
        stream->cache_capture = grown;
        stream->cache_capture_capacity = new_capacity;
    }
    memcpy(stream->cache_capture + stream->cache_capture_length, data, len);
    stream->cache_capture_length += len;
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
                      struct magnus_h2_stream *stream, const char *forward_path,
                      bool cache_route_enabled)
{
    const char *cookie_header = magnus_http_header_find(&stream->parsed, "cookie");
    char client_affinity[64] = "";
    char conditional_headers[300] = "";
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

    /* Reverse-proxy cache (roadmap 2d-1) -- see magnus_proxy_pick_and_start()'s
     * own identical logic for the full rationale; a fresh HIT here submits
     * the response directly and returns, never touching the upstream at
     * all. */
    stream->cache_enabled = cache_route_enabled;
    stream->cache_revalidating = false;
    stream->cache_this_response_cacheable = false;
    stream->cache_capture_overflowed = false;
    if (cache_route_enabled && strcmp(stream->parsed.method, "GET") == 0) {
        strncpy(stream->cache_host, stream->parsed.host,
               sizeof(stream->cache_host) - 1);
        stream->cache_host[sizeof(stream->cache_host) - 1] = '\0';
        strncpy(stream->cache_target, forward_path,
               sizeof(stream->cache_target) - 1);
        stream->cache_target[sizeof(stream->cache_target) - 1] = '\0';

        magnus_cache_entry_t *entry
            = magnus_cache_lookup(stream->cache_host, stream->cache_target);
        if (entry != NULL
            && magnus_cache_entry_is_fresh(entry, magnus_cache_now_ms())) {
            /* Deliberately no magnus_h2_push() here (unlike, say,
             * magnus_h2_grpc_client_on_frame_recv()'s own immediate push
             * after a mid-stream submit): magnus_h2_proxy_start() is
             * always reached from inside nghttp2_session_mem_recv2()'s own
             * callback stack (magnus_h2_on_frame_recv() -> magnus_h2_dispatch(),
             * or the synthetic h2c-upgrade dispatch in
             * magnus_h2c_activate()) -- pushing here can drive
             * nghttp2_session_mem_send2() far enough to close this stream
             * and free it out from under the caller, which still needs
             * `stream` after this function returns (found the hard way:
             * a real heap-use-after-free under ASan). The existing outer
             * driving loop already pushes exactly once, safely, after
             * everything here has finished with `stream` -- see
             * magnus_h2_service()'s own post-recv magnus_h2_drain_send()
             * call, and magnus_h2c_activate()'s own tail. */
            magnus_h2_submit_cached_response(connection, stream, entry, "HIT");
            return;
        } else if (entry != NULL && magnus_cache_entry_has_validator(entry)) {
            const char *h, *b, *etag, *last_modified;
            size_t hl, bl;
            magnus_cache_entry_data(entry, &h, &hl, &b, &bl, &etag,
                                    &last_modified);
            stream->cache_revalidating = true;
            strncpy(stream->cache_validator_etag, etag,
                   sizeof(stream->cache_validator_etag) - 1);
            stream->cache_validator_etag[
                sizeof(stream->cache_validator_etag) - 1] = '\0';
            strncpy(stream->cache_validator_last_modified, last_modified,
                   sizeof(stream->cache_validator_last_modified) - 1);
            stream->cache_validator_last_modified[
                sizeof(stream->cache_validator_last_modified) - 1] = '\0';
        }
    }
    if (stream->cache_revalidating) {
        size_t off = 0;
        int w;
        if (stream->cache_validator_etag[0] != '\0') {
            w = snprintf(conditional_headers + off, sizeof(conditional_headers) - off,
                        "If-None-Match: %s\r\n", stream->cache_validator_etag);
            if (w > 0 && (size_t) w < sizeof(conditional_headers) - off) off += (size_t) w;
        }
        if (stream->cache_validator_last_modified[0] != '\0') {
            w = snprintf(conditional_headers + off, sizeof(conditional_headers) - off,
                        "If-Modified-Since: %s\r\n",
                        stream->cache_validator_last_modified);
            if (w > 0 && (size_t) w < sizeof(conditional_headers) - off) off += (size_t) w;
        }
    }

    written = stream->body_length > 0
        ? snprintf(stream->proxy_request, sizeof(stream->proxy_request),
                   "%s %s HTTP/1.0\r\nHost: magnus-upstream\r\n"
                   "Connection: keep-alive\r\nContent-Length: %zu\r\n"
                   "X-Magnus-Request-Id: %s\r\n\r\n",
                   stream->parsed.method, forward_path, stream->body_length,
                   stream->request_id)
        : snprintf(stream->proxy_request, sizeof(stream->proxy_request),
                   "%s %s HTTP/1.0\r\nHost: magnus-upstream\r\n"
                   "Connection: keep-alive\r\n%sX-Magnus-Request-Id: %s\r\n\r\n",
                   stream->parsed.method, forward_path, conditional_headers,
                   stream->request_id);
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
                                           preferred_index,
                                           stream->effective_client_address)
            : magnus_cluster_select(&magnus_cluster, magnus_now_ms(), NULL,
                                    stream->effective_client_address);
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

/* Serves a stored magnus_cache_entry_t directly to an h2 stream -- the h2
 * analogue of magnus_serve_cached_response() -- a cold HIT, or a
 * successful revalidation (a 304 from the upstream), entirely bypassing
 * the upstream for this one stream. Reuses stream->io_buffer/
 * magnus_h2_read_io_buffer() exactly like magnus_h2_submit_text() already
 * does for /healthz//metrics: the whole body is copied in and
 * response_complete set to true from the very start, since (like those)
 * there is no upstream, or anything else asynchronous, left to wait on.
 * The entry's own stored headers (status line + pass-through fields,
 * Content-Length already excluded by magnus_cache_store() -- see that
 * function's own comment) are lowercased/tokenized exactly like
 * magnus_h2_proxy_submit_response()'s own pass-through loop (h2 field
 * names must be lowercase; the entry's own stored casing is not
 * guaranteed to already be, since it came from an HTTP/1.x upstream
 * response), then a fresh content-length/x-cache are added -- `Connection`
 * is dropped entirely, same as magnus_h2_proxy_submit_response() already
 * does, since it is forbidden in h2 (RFC 9113 8.2.2) and meaningless
 * there regardless. `x_cache_value` names which of those this was ("HIT"
 * or "REVALIDATED"). */
static void
magnus_h2_submit_cached_response(magnus_connection_t *connection,
                                 struct magnus_h2_stream *stream,
                                 magnus_cache_entry_t *entry,
                                 const char *x_cache_value)
{
    const char *entry_headers, *entry_body, *etag, *last_modified;
    size_t entry_headers_length, entry_body_length;
    nghttp2_nv headers[24];
    char name_storage[24][64];
    size_t count = 0;
    char status_text[8];
    char content_length_text[32];
    char *copy;
    char *saveptr = NULL;
    char *line;

    magnus_cache_entry_data(entry, &entry_headers, &entry_headers_length,
                            &entry_body, &entry_body_length, &etag,
                            &last_modified);
    (void) etag;
    (void) last_modified;

    copy = malloc(entry_headers_length + 1);
    if (copy == NULL) {
        magnus_h2_submit_status(connection->h2_session, stream->stream_id, "500");
        return;
    }
    memcpy(copy, entry_headers, entry_headers_length);
    copy[entry_headers_length] = '\0';

    snprintf(status_text, sizeof(status_text), "%u",
            magnus_cache_entry_status(entry));
    headers[count] = magnus_h2_nv(":status", status_text);
    count++;

    strtok_r(copy, "\r\n", &saveptr); /* status line, already captured above */
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
    /* NOT freed here: each header's *value* (unlike its name, already
     * copied into name_storage) is still a pointer straight into `copy`
     * (magnus_h2_nv() copies neither -- see its own comment on
     * NGHTTP2_NV_FLAG_NONE), so `copy` must outlive
     * nghttp2_submit_response2() itself, which is what actually copies
     * every name/value pair into its own storage. Freed once that call
     * has returned, below. */

    if (count < sizeof(headers) / sizeof(headers[0])) {
        snprintf(content_length_text, sizeof(content_length_text), "%zu",
                entry_body_length);
        headers[count] = magnus_h2_nv("content-length", content_length_text);
        count++;
    }
    if (count < sizeof(headers) / sizeof(headers[0])) {
        headers[count] = magnus_h2_nv("x-cache", x_cache_value);
        count++;
    }

    if (entry_body_length > 0) {
        stream->io_buffer = malloc(entry_body_length);
        if (stream->io_buffer == NULL) {
            free(copy);
            magnus_h2_submit_status(connection->h2_session, stream->stream_id,
                                    "500");
            return;
        }
        memcpy(stream->io_buffer, entry_body, entry_body_length);
    }
    stream->io_length = entry_body_length;
    stream->io_sent = 0;
    stream->response_complete = true;
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
    free(copy);

    magnus_requests_total++;
    {
        double latency_ms = (double) (magnus_now_ms() - stream->started_ms);
        magnus_record_latency(latency_ms);
        magnus_access_log(stream->request_id, stream->effective_client_address,
                          stream->log_method, stream->log_target,
                          magnus_cache_entry_status(entry), latency_ms, -1);
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
    /* Reverse-proxy cache (roadmap 2d-1): commits the captured body now
     * that the whole response is known complete -- before either upstream
     * -leg outcome below, both of which can free stream->cache_capture
     * (the pool-checkin branch does not touch it, but
     * magnus_h2_stream_teardown_upstream() does) -- see
     * magnus_proxy_flush()'s own identical HTTP/1.1 comment. Unlike
     * HTTP/1.1 (which still has connection->proxy_header_out, the raw
     * sanitized text block, sitting around until its own teardown), h2
     * never keeps one -- magnus_h2_proxy_submit_response() tokenizes it
     * into nghttp2 name/value pairs and the text itself was stack-local --
     * so the cacheable prefix had to be copied out into
     * stream->cache_pending_headers at header time instead of remembered
     * by reference; see magnus_h2_proxy_receive_headers()'s own comment. */
    if (stream->cache_this_response_cacheable
        && !stream->cache_capture_overflowed) {
        magnus_cache_store(stream->cache_host, stream->cache_target, 200,
            stream->cache_pending_headers, stream->cache_pending_headers_length,
            stream->cache_capture, stream->cache_capture_length,
            stream->cache_response_etag, stream->cache_response_last_modified,
            &stream->cache_freshness);
    }
    if (complete_by_length && stream->upstream_poolable
        && stream->upstream_fd >= 0) {
        int fd = stream->upstream_fd;
        epoll_ctl(magnus_global_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        magnus_h2_upstream_owner[fd] = NULL;
        stream->upstream_fd = -1;
        magnus_pool_checkin(stream->endpoint_index, fd,
                            stream->upstream_requests_served + 1);
        /* Advanced load balancing (roadmap 2e-1): the one release site
         * magnus_h2_stream_teardown_upstream()'s own does not cover --
         * see magnus_proxy_flush()'s own identical HTTP/1.1 comment. */
        if (stream->cluster_endpoint_counted) {
            magnus_cluster_endpoint_end(&magnus_cluster, stream->endpoint_index);
            stream->cluster_endpoint_counted = false;
        }
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
    size_t cacheable_prefix_length = 0;

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
              * dropped rather than forwarded either way */, &info,
        &cacheable_prefix_length);
    if (sanitized_length < 0) {
        magnus_h2_proxy_connect_failed(connection, stream, "502");
        return true;
    }

    /* Reverse-proxy cache (roadmap 2d-1): a successful revalidation -- see
     * magnus_proxy_receive_headers()'s own identical HTTP/1.1 handling for
     * the full rationale (a 304 carries no body by definition, so this
     * upstream leg is already fully "received" the moment its headers
     * are; the *cached* body is what actually goes to the client, via
     * magnus_h2_submit_cached_response(), never the raw 304 this stream
     * itself would otherwise have submitted). */
    if (stream->cache_revalidating && info.status == 304) {
        magnus_cache_entry_t *entry;
        if (info.upstream_poolable && stream->upstream_fd >= 0) {
            int fd = stream->upstream_fd;
            epoll_ctl(magnus_global_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
            magnus_h2_upstream_owner[fd] = NULL;
            stream->upstream_fd = -1;
            magnus_pool_checkin(stream->endpoint_index, fd,
                stream->upstream_requests_served + 1);
            /* Advanced load balancing (roadmap 2e-1): same release-site
             * gap as magnus_h2_proxy_maybe_complete()'s own pool-checkin
             * branch -- see that one's own comment. */
            if (stream->cluster_endpoint_counted) {
                magnus_cluster_endpoint_end(&magnus_cluster,
                                            stream->endpoint_index);
                stream->cluster_endpoint_counted = false;
            }
        } else {
            magnus_h2_stream_teardown_upstream(stream);
        }

        entry = magnus_cache_lookup(stream->cache_host, stream->cache_target);
        if (entry != NULL) {
            magnus_cache_freshness_t freshness;
            magnus_cache_compute_freshness(
                info.cache_control[0] != '\0' ? info.cache_control : NULL,
                info.expires[0] != '\0' ? info.expires : NULL, NULL, false,
                magnus_cache_now_ms(), &freshness);
            magnus_cache_revalidated(entry, &freshness);
            /* Deliberately no magnus_h2_push() here -- see
             * magnus_h2_proxy_start()'s own identical comment on why
             * (found via the exact same heap-use-after-free under ASan):
             * this function's own caller, magnus_h2_handle_upstream(),
             * still reads `stream` after this call returns and only then
             * pushes, once, at its own tail. */
            magnus_h2_submit_cached_response(connection, stream, entry,
                                             "REVALIDATED");
            return true;
        }
        /* The entry vanished between this attempt starting and the 304
         * arriving, or serving it failed outright -- see the HTTP/1.1
         * path's own identical comment. Nothing left to honestly answer
         * with. */
        magnus_h2_proxy_fail(connection, stream, "502");
        return true;
    }

    /* Decided once, right here, the moment headers (and therefore
     * Cache-Control/Expires/Vary/Set-Cookie/status) are known -- see
     * magnus_proxy_receive_headers()'s own identical comment. */
    stream->cache_this_response_cacheable = false;
    if (stream->cache_enabled && info.status == 200) {
        magnus_cache_compute_freshness(
            info.cache_control[0] != '\0' ? info.cache_control : NULL,
            info.expires[0] != '\0' ? info.expires : NULL,
            info.vary[0] != '\0' ? info.vary : NULL, info.has_set_cookie,
            magnus_cache_now_ms(), &stream->cache_freshness);
        stream->cache_this_response_cacheable = stream->cache_freshness.cacheable;
    }
    if (stream->cache_this_response_cacheable) {
        memcpy(stream->cache_pending_headers, sanitized, cacheable_prefix_length);
        stream->cache_pending_headers_length = cacheable_prefix_length;
        strcpy(stream->cache_response_etag, info.etag);
        strcpy(stream->cache_response_last_modified, info.last_modified);
    }

    if (info.has_content_length && leftover > info.content_length)
        leftover = info.content_length;
    if (stream->cache_this_response_cacheable)
        magnus_h2_proxy_cache_capture(stream, body_start, leftover);
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
        magnus_access_log(stream->request_id, stream->effective_client_address,
                          stream->log_method,
                          stream->log_target, info.status, latency_ms, -1);
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
        if (stream->cache_this_response_cacheable)
            magnus_h2_proxy_cache_capture(stream, stream->io_buffer,
                                          (size_t) received);
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

    /* gRPC (2c-1, pooled since 2c-5) streams never reach here at all any
     * more: their upstream fd belongs to a shared magnus_grpc_conn_t, not
     * this stream, and is dispatched straight to
     * magnus_grpc_conn_handle_event() via magnus_grpc_conn_owner[] in the
     * main epoll loop instead of magnus_h2_upstream_owner[] -- see that
     * table's own comment. */

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

/* ---- gRPC dispatch (roadmap 2c-1, pooled/multiplexed since 2c-5):
 * client h2 stream -> upstream h2 (real gRPC) server -- an h2-to-h2
 * sibling of the h2-to-HTTP/1.x proxy dispatch above (1e-2), needed
 * because a real gRPC server is HTTP/2-native end to end and requires
 * actual trailers (grpc-status/grpc-message) to report an RPC's outcome,
 * which HTTP/1.1 cannot carry at all -- translating through the existing
 * h1-upstream proxy path the way every other action=proxy route does
 * would simply not work for gRPC.
 *
 * Through 2c-4, a fresh magnus-owned CLIENT-role nghttp2 session was
 * created and torn down for every single RPC (a fresh TCP + h2 handshake
 * per unary call). 2c-5 replaces that with a small pool of shared,
 * long-lived upstream connections per endpoint (magnus_grpc_pool[][],
 * magnus_grpc_conn_t) -- many concurrent client-side gRPC streams
 * multiplex onto the same physical connection exactly the way a real h2
 * client library would, using nghttp2's own stream_user_data mechanism
 * (nghttp2_submit_request2()'s last parameter,
 * nghttp2_session_get_stream_user_data() to retrieve it) rather than a
 * hand-rolled stream-id-to-magnus_h2_stream map. See magnus_grpc_conn_t's
 * own comment (near magnus_h2_upstream_owner[]) for the pool's shape, and
 * magnus_h2_grpc_start()'s own comment for what changed (and what
 * deliberately did not) about connection-failure handling now that a
 * failure can affect more than one RPC at once.
 *
 * What did not change from 2c-1..2c-4: both directions still stream
 * through incrementally (request DATA relayed to the upstream as it
 * arrives, response HEADERS/DATA forwarded to the real client as they
 * arrive -- magnus_h2_grpc_read_response()/magnus_h2_grpc_read_request_body()'s
 * own comments), grpc-timeout deadline propagation (2c-3), and
 * header_prefix routing/grpc-status metrics/session affinity (2c-4) all
 * work exactly as before -- this increment only changes *how many*
 * physical connections carry all of that traffic, not any of the
 * gRPC-over-HTTP/2 semantics layered on top of it.
 *
 * Per the gRPC-over-HTTP/2 wire spec, every response this dispatch ever
 * sends the real client uses :status 200 regardless of RPC outcome -- a
 * gRPC client treats any other :status as a *transport*-level failure,
 * not the RPC-level one grpc-status conveys, so a gateway-level failure
 * (no healthy upstream, connect failure, a malformed/absent upstream
 * response) is always answered as a "Trailers-Only" 200 response with
 * grpc-status=14 (UNAVAILABLE) rather than an ordinary 502/504 the way
 * action=proxy would. */

/* Increments magnus_grpc_status_counts[] for a completed gRPC dispatch
 * (roadmap 2c-4) -- bounds-checked against a string that, in practice,
 * only ever holds "0" through "16" (every caller passes a literal from
 * that set), but this stays defensive against anything else (an
 * out-of-range or non-numeric string) by simply not counting it rather
 * than indexing out of bounds. */
static void
magnus_grpc_record_status(const char *grpc_status_code)
{
    char *end;
    long code = strtol(grpc_status_code, &end, 10);
    if (*end != '\0' || end == grpc_status_code || code < 0 || code > 16) return;
    magnus_grpc_status_counts[code]++;
}

static bool
magnus_grpc_endpoint_sockaddr(size_t index, struct sockaddr_in *out)
{
    if (index >= magnus_grpc_cluster.count) return false;
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t) magnus_grpc_cluster.endpoints[index].port);
    return inet_pton(AF_INET, magnus_grpc_cluster.endpoints[index].address,
                     &out->sin_addr) == 1;
}

/* Third sockaddr resolver (roadmap 3a), same shape as the two above, for
 * magnus_stream_cluster -- used by both this cluster's active-health probe
 * (magnus_health_tick()) and magnus_stream_accept()'s own connect(). */
static bool
magnus_stream_endpoint_sockaddr(size_t index, struct sockaddr_in *out)
{
    if (index >= magnus_stream_cluster.count) return false;
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t) magnus_stream_cluster.endpoints[index].port);
    return inet_pton(AF_INET, magnus_stream_cluster.endpoints[index].address,
                     &out->sin_addr) == 1;
}

/* Parses a gRPC "grpc-timeout" request header value -- 1 to 8 ASCII
 * decimal digits followed by exactly one unit character (H/M/S hours/
 * minutes/seconds, m/u/n milli-/micro-/nanoseconds -- the full set the
 * gRPC-over-HTTP/2 wire spec defines) -- into a millisecond duration.
 * Returns false (leaving *out_ms untouched) for anything that does not
 * match that shape exactly, including empty, digit-only, unit-only, too
 * many digits, or an unrecognized unit -- a malformed grpc-timeout is
 * simply treated as though the header had been absent (see
 * magnus_h2_grpc_start()'s own comment), not itself an error worth
 * rejecting the request over. A sub-millisecond result (a client asking
 * for e.g. "1n") is rounded up to 1ms rather than 0, since 0 is reserved
 * on the struct field to mean "no deadline at all." */
static bool
magnus_grpc_parse_timeout(const char *value, uint64_t *out_ms)
{
    char *end;
    unsigned long digits;
    double ms;
    size_t value_length = strlen(value);
    if (value_length < 2 || value_length > 9) return false;
    errno = 0;
    digits = strtoul(value, &end, 10);
    if (errno != 0 || end == value || (size_t) (end - value) > 8) return false;
    if ((size_t) (end - value) != value_length - 1) return false;
    switch (*end) {
        case 'H': ms = (double) digits * 3600000.0; break;
        case 'M': ms = (double) digits * 60000.0; break;
        case 'S': ms = (double) digits * 1000.0; break;
        case 'm': ms = (double) digits; break;
        case 'u': ms = (double) digits / 1000.0; break;
        case 'n': ms = (double) digits / 1000000.0; break;
        default: return false;
    }
    if (ms < 1.0) ms = 1.0;
    *out_ms = (uint64_t) ms;
    return true;
}

/* Submits a "Trailers-Only" gRPC error response directly to the real
 * client -- :status 200 (see this block's own top comment on why),
 * content-type: application/grpc, grpc-status/grpc-message, and no body
 * at all. The gRPC analogue of magnus_h2_proxy_fail() for the h1 proxy
 * path -- but unlike that function, never itself detaches this stream
 * from its pooled upstream connection (magnus_h2_stream_teardown_upstream()
 * does that, and is only ever safe to call *outside* one of that
 * connection's own nghttp2 callbacks -- see grpc_stream_closed's own
 * comment); every caller is responsible for that teardown itself, at
 * whichever point is safe for it. Must only be called before any
 * client-facing response has been submitted for this stream. gRPC
 * failures deliberately do not increment magnus_responses_4xx/5xx (both
 * are HTTP-status-code buckets, and the wire status here is always 200) --
 * grpc-status-aware metrics (magnus_grpc_record_status() below) cover
 * this instead. */
static void
magnus_h2_grpc_fail(magnus_connection_t *connection,
                    struct magnus_h2_stream *stream,
                    const char *grpc_status_code, const char *message)
{
    nghttp2_nv headers[4];
    size_t count = 0;
    double latency_ms = (double) (magnus_now_ms() - stream->started_ms);
    headers[count++] = magnus_h2_nv(":status", "200");
    headers[count++] = magnus_h2_nv("content-type", "application/grpc");
    headers[count++] = magnus_h2_nv("grpc-status", grpc_status_code);
    if (message != NULL && message[0] != '\0')
        headers[count++] = magnus_h2_nv("grpc-message", message);
    stream->response_headers_submitted = true;
    (void) nghttp2_submit_response2(connection->h2_session, stream->stream_id,
                                    headers, count, NULL);
    magnus_requests_total++;
    magnus_record_latency(latency_ms);
    magnus_grpc_record_status(grpc_status_code);
    magnus_access_log(stream->request_id, stream->effective_client_address,
                      stream->log_method, stream->log_target, 200, latency_ms,
                      (int) strtol(grpc_status_code, NULL, 10));
}

/* The gRPC analogue of magnus_h2_proxy_abort(): ends a stream whose
 * response headers were already submitted to the real client -- a fresh
 * status/trailer is no longer possible (h2 does not allow a second
 * HEADERS frame after the response has started any more than it allows a
 * second status line), so the stream itself is reset instead. Only ever
 * reachable once streaming (2c-2) is genuinely mid-flight; 2c-1's own
 * whole-response-buffered-first shape could never reach this state
 * (nothing was ever submitted to the client before the outcome was fully
 * known). */
static void
magnus_h2_grpc_abort(struct magnus_h2_stream *stream)
{
    magnus_connection_t *connection = stream->connection;
    magnus_h2_stream_teardown_upstream(stream);
    (void) nghttp2_submit_rst_stream(connection->h2_session, NGHTTP2_FLAG_NONE,
                                     stream->stream_id, NGHTTP2_INTERNAL_ERROR);
}

/* Picks the one correct reaction to a gRPC stream failure depending on
 * whether the real client has already started receiving a response for
 * it: magnus_h2_grpc_fail() (a clean "Trailers-Only" gRPC error) if not,
 * since the client has not committed to anything yet; magnus_h2_grpc_abort()
 * if so, since retrying to a different endpoint transparently no longer
 * makes sense once the client is mid-conversation with *this* specific
 * attempt. Used by every gRPC failure path (connect/connection failure at
 * any stage, a client body that overflows mid-stream, an upstream that
 * never produced a valid response) so this branch is decided in exactly
 * one place. */
static void
magnus_h2_grpc_fail_or_abort(magnus_connection_t *connection,
                             struct magnus_h2_stream *stream,
                             const char *grpc_status_code,
                             const char *message)
{
    if (stream->response_headers_submitted) {
        magnus_h2_grpc_abort(stream);
        return;
    }
    magnus_h2_grpc_fail(connection, stream, grpc_status_code, message);
    magnus_h2_stream_teardown_upstream(stream);
}

/* nghttp2 data-provider read callback for a gRPC-dispatched stream's
 * response to the real client -- pulls from stream->io_buffer/io_length/
 * io_sent exactly like magnus_h2_read_io_buffer() does for every other h2
 * response, but cannot simply reuse that callback: at true EOF it must
 * also submit this stream's trailer (grpc-status/grpc-message), which no
 * other caller of magnus_h2_read_io_buffer() ever needs to do. Streaming
 * (2c-2): unlike the buffer-it-all-first shape 2c-1 shipped,
 * response_complete is NOT implicitly true just because io_buffer is
 * empty right now -- magnus_h2_grpc_client_on_data_chunk_recv() can still
 * be about to append more (server-streaming/bidi), so "no bytes
 * available" defers (NGHTTP2_ERR_DEFERRED, exactly like
 * magnus_h2_read_io_buffer() already does for the h1-proxy path) unless
 * response_complete is *also* true (set only once
 * stream->grpc_stream_closed is observed -- see that field's own
 * comment), which is the one condition that actually means "no more DATA
 * is ever coming." Compacts io_buffer back to empty once fully drained,
 * so a long-lived streaming response's buffer never grows by more than
 * however far behind the client connection currently is. */
static nghttp2_ssize
magnus_h2_grpc_read_response(nghttp2_session *session, int32_t stream_id,
                             uint8_t *buf, size_t length, uint32_t *data_flags,
                             nghttp2_data_source *source, void *user_data)
{
    struct magnus_h2_stream *stream = source->ptr;
    size_t available = stream->io_length - stream->io_sent;
    (void) stream_id;
    (void) user_data;
    if (available == 0) {
        nghttp2_nv trailer[2 + 8];
        size_t trailer_count = 0;
        if (!stream->response_complete) {
            stream->deferred = true;
            return NGHTTP2_ERR_DEFERRED;
        }
        *data_flags |= NGHTTP2_DATA_FLAG_EOF | NGHTTP2_DATA_FLAG_NO_END_STREAM;
        trailer[trailer_count++] = magnus_h2_nv("grpc-status",
            stream->grpc_status[0] != '\0' ? stream->grpc_status : "0");
        if (stream->grpc_message[0] != '\0')
            trailer[trailer_count++] = magnus_h2_nv("grpc-message",
                                                     stream->grpc_message);
        for (size_t i = 0; i < stream->grpc_response_trailer_count
                           && trailer_count < sizeof(trailer) / sizeof(trailer[0]);
             i++) {
            trailer[trailer_count++] = magnus_h2_nv(
                stream->grpc_response_trailers[i].name,
                stream->grpc_response_trailers[i].value);
        }
        (void) nghttp2_submit_trailer(session, stream->stream_id, trailer,
                                      trailer_count);
        return 0;
    }
    if (length > available) length = available;
    memcpy(buf, stream->io_buffer + stream->io_sent, length);
    stream->io_sent += length;
    if (stream->io_sent == stream->io_length) {
        stream->io_length = 0;
        stream->io_sent = 0;
    }
    return (nghttp2_ssize) length;
}

/* Submits this stream's response HEADERS (and attaches
 * magnus_h2_grpc_read_response() as its DATA source) to the real client
 * as soon as the upstream's own response HEADERS frame is fully known --
 * called from magnus_h2_grpc_client_on_frame_recv() the moment that
 * happens, streaming (2c-2): unlike 2c-1, this no longer waits for the
 * whole response body (or even the trailer) to be known first. Must only
 * be called once, while stream->response_headers_submitted is still
 * false. Logging/counters are deliberately NOT done here -- latency and
 * final status are only meaningful once the whole exchange is known
 * complete, which for a streaming response can be long after headers go
 * out; see the finalization in magnus_grpc_conn_finalize_closed_streams()
 * instead. */
static void
magnus_h2_grpc_submit_headers(magnus_connection_t *connection,
                              struct magnus_h2_stream *stream)
{
    nghttp2_nv headers[3 + 16];
    size_t count = 0;
    char cookie_value[128];
    const char *status_text = stream->grpc_response_status[0] != '\0'
        ? stream->grpc_response_status : "200";

    headers[count++] = magnus_h2_nv(":status", status_text);
    headers[count++] = magnus_h2_nv("server", "Magnus/" MAGNUS_VERSION);
    if (stream->issue_affinity_cookie) {
        /* Session affinity (roadmap 2c-4) -- same MAGNUS_AFFINITY cookie
         * attributes the h1/h2-proxy paths already issue (see
         * magnus_proxy_sanitize_response_headers()'s own Set-Cookie
         * line). Harmless if the client never round-trips it (most real
         * gRPC clients have no automatic cookie jar) -- see
         * magnus_h2_grpc_start()'s own comment. */
        snprintf(cookie_value, sizeof(cookie_value),
                "%s=%s; Path=/; HttpOnly; SameSite=Lax",
                MAGNUS_AFFINITY_COOKIE_NAME, stream->affinity_key);
        headers[count++] = magnus_h2_nv("set-cookie", cookie_value);
    }
    for (size_t i = 0; i < stream->grpc_response_header_count
                       && count < sizeof(headers) / sizeof(headers[0]); i++) {
        headers[count++] = magnus_h2_nv(stream->grpc_response_headers[i].name,
                                        stream->grpc_response_headers[i].value);
    }

    stream->response_headers_submitted = true;
    {
        nghttp2_data_provider2 data_provider = {
            .source = { .ptr = stream },
            .read_callback = magnus_h2_grpc_read_response,
        };
        (void) nghttp2_submit_response2(connection->h2_session,
                                        stream->stream_id, headers, count,
                                        &data_provider);
    }
}

/* nghttp2 data-provider read callback for this stream's outbound gRPC
 * request body, sent to the upstream -- pulls from stream->body/
 * body_length/body_sent, the same buffer the h1-proxy path's own raw
 * send() loop drains (reused, not duplicated, since the two dispatch
 * modes are mutually exclusive per stream). Streaming (2c-2): unlike
 * 2c-1, the whole body is not necessarily known up front any more --
 * magnus_h2_grpc_relay_request_chunk() can still be about to append more
 * as the client keeps sending (client-streaming/bidi) -- so catching up
 * with everything sent *so far* only means EOF if request_end_stream_seen
 * is also true; otherwise this defers (NGHTTP2_ERR_DEFERRED), exactly
 * mirroring magnus_h2_grpc_read_response()'s own response-direction
 * shape via grpc_request_deferred, its request-direction counterpart.
 * `session`/`stream_id` here are the pooled upstream connection's own
 * shared session/this RPC's own stream id within it -- unused directly
 * (the source->ptr stream pointer is all this needs), exactly as before
 * pooling. */
static nghttp2_ssize
magnus_h2_grpc_read_request_body(nghttp2_session *session, int32_t stream_id,
                                 uint8_t *buf, size_t length,
                                 uint32_t *data_flags,
                                 nghttp2_data_source *source, void *user_data)
{
    struct magnus_h2_stream *stream = source->ptr;
    size_t available = stream->body_length - stream->body_sent;
    (void) session;
    (void) stream_id;
    (void) user_data;
    if (available == 0) {
        if (!stream->request_end_stream_seen) {
            stream->grpc_request_deferred = true;
            return NGHTTP2_ERR_DEFERRED;
        }
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }
    if (length > available) length = available;
    memcpy(buf, stream->body + stream->body_sent, length);
    stream->body_sent += length;
    return (nghttp2_ssize) length;
}

/* on_header callback for a pooled connection's shared upstream session --
 * captures the upstream's response :status and ordinary headers
 * (content-type, grpc-encoding, custom metadata, ...) from its leading
 * HEADERS frame (NGHTTP2_HCAT_RESPONSE) into grpc_response_status/
 * grpc_response_headers, and grpc-status/grpc-message from *whichever*
 * HEADERS frame actually carries them -- either a real trailer, or the
 * single HEADERS frame of a "Trailers-Only" error response that never
 * sent a body at all. Both shapes are deliberately treated identically:
 * grpc-status is checked for on every HEADERS frame regardless of
 * category, so this dispatch never needs to special-case Trailers-Only
 * separately. Every other trailer field (custom trailing metadata) is
 * captured into grpc_response_trailers, bounded the same way
 * grpc_response_headers is -- see that field's own comment.
 *
 * Pooling (2c-5): many concurrent RPCs share this one session now, so the
 * owning magnus_h2_stream is resolved per frame via
 * nghttp2_session_get_stream_user_data() (the id this stream was attached
 * under -- see magnus_grpc_stream_attach()) rather than being the whole
 * callback context the way it was pre-pooling. */
static int
magnus_h2_grpc_client_on_header(nghttp2_session *session,
                                const nghttp2_frame *frame,
                                const uint8_t *name, size_t namelen,
                                const uint8_t *value, size_t valuelen,
                                uint8_t flags, void *user_data)
{
    struct magnus_h2_stream *stream;
    (void) flags;
    (void) user_data;
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;
    stream = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (stream == NULL) return 0;
    stream->last_activity = time(NULL);

    if (namelen == 11 && memcmp(name, "grpc-status", 11) == 0) {
        if (valuelen < sizeof(stream->grpc_status)) {
            memcpy(stream->grpc_status, value, valuelen);
            stream->grpc_status[valuelen] = '\0';
        }
        return 0;
    }
    if (namelen == 12 && memcmp(name, "grpc-message", 12) == 0) {
        if (valuelen < sizeof(stream->grpc_message)) {
            memcpy(stream->grpc_message, value, valuelen);
            stream->grpc_message[valuelen] = '\0';
        }
        return 0;
    }
    if (frame->headers.cat != NGHTTP2_HCAT_RESPONSE) {
        /* Any other trailer field (custom trailing metadata) -- captured
         * for magnus_h2_grpc_read_response() to forward, same truncation/
         * bound-count precedent as grpc_response_headers below. */
        if (stream->grpc_response_trailer_count
            < sizeof(stream->grpc_response_trailers)
                  / sizeof(stream->grpc_response_trailers[0])) {
            magnus_http_header_t *stored = &stream->grpc_response_trailers[
                stream->grpc_response_trailer_count];
            size_t stored_name_length = namelen < sizeof(stored->name) - 1
                ? namelen : sizeof(stored->name) - 1;
            size_t stored_value_length = valuelen < sizeof(stored->value) - 1
                ? valuelen : sizeof(stored->value) - 1;
            memcpy(stored->name, name, stored_name_length);
            stored->name[stored_name_length] = '\0';
            memcpy(stored->value, value, stored_value_length);
            stored->value[stored_value_length] = '\0';
            stream->grpc_response_trailer_count++;
        }
        return 0;
    }
    if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
        if (valuelen < sizeof(stream->grpc_response_status)) {
            memcpy(stream->grpc_response_status, value, valuelen);
            stream->grpc_response_status[valuelen] = '\0';
        }
        return 0;
    }
    if (namelen > 0 && name[0] == ':') return 0; /* any other pseudo-header */
    if (stream->grpc_response_header_count
        < sizeof(stream->grpc_response_headers)
              / sizeof(stream->grpc_response_headers[0])) {
        magnus_http_header_t *stored = &stream->grpc_response_headers[
            stream->grpc_response_header_count];
        size_t stored_name_length = namelen < sizeof(stored->name) - 1
            ? namelen : sizeof(stored->name) - 1;
        size_t stored_value_length = valuelen < sizeof(stored->value) - 1
            ? valuelen : sizeof(stored->value) - 1;
        memcpy(stored->name, name, stored_name_length);
        stored->name[stored_name_length] = '\0';
        memcpy(stored->value, value, stored_value_length);
        stored->value[stored_value_length] = '\0';
        stream->grpc_response_header_count++;
    }
    return 0;
}

/* on_data_chunk_recv callback for a pooled connection's shared upstream
 * session -- appends the upstream response body into the owning stream's
 * io_buffer (resolved via nghttp2_session_get_stream_user_data(), same as
 * on_header() above), growing it (realloc, doubling) as needed up to
 * MAGNUS_MAX_BODY, the same cap the client request-body side already
 * enforces (magnus_h2_on_data_chunk_recv()). Unlike the h1-proxy path's
 * fixed MAGNUS_PROXY_BUFFER window, io_buffer genuinely grows here -- see
 * io_capacity's own comment on the struct. Streaming (2c-2): compacts
 * away whatever magnus_h2_grpc_read_response() has already drained
 * (io_sent) before appending, so the cap bounds how far behind the
 * *client* connection has fallen, not the response's total size -- and,
 * if that data provider was stalled waiting for exactly this
 * (stream->deferred), wakes it and pushes onto the client fd immediately,
 * since nothing else guarantees that fd has a pending epoll event right
 * now to otherwise trigger it (mirrors the h1-proxy path's own
 * magnus_h2_handle_upstream() tail for the identical reason). */
static int
magnus_h2_grpc_client_on_data_chunk_recv(nghttp2_session *session,
                                         uint8_t flags, int32_t stream_id,
                                         const uint8_t *data, size_t len,
                                         void *user_data)
{
    struct magnus_h2_stream *stream
        = nghttp2_session_get_stream_user_data(session, stream_id);
    (void) flags;
    (void) user_data;
    if (stream == NULL || len == 0) return 0;
    stream->last_activity = time(NULL);
    if (stream->io_sent > 0) {
        memmove(stream->io_buffer, stream->io_buffer + stream->io_sent,
               stream->io_length - stream->io_sent);
        stream->io_length -= stream->io_sent;
        stream->io_sent = 0;
    }
    if (stream->io_length + len > MAGNUS_MAX_BODY) return NGHTTP2_ERR_CALLBACK_FAILURE;
    if (stream->io_length + len > stream->io_capacity) {
        size_t new_capacity = stream->io_capacity == 0
            ? MAGNUS_PROXY_BUFFER : stream->io_capacity * 2;
        char *grown;
        while (new_capacity < stream->io_length + len) new_capacity *= 2;
        grown = realloc(stream->io_buffer, new_capacity);
        if (grown == NULL) return NGHTTP2_ERR_CALLBACK_FAILURE;
        stream->io_buffer = grown;
        stream->io_capacity = new_capacity;
    }
    memcpy(stream->io_buffer + stream->io_length, data, len);
    stream->io_length += len;

    if (stream->deferred) {
        stream->deferred = false;
        (void) nghttp2_session_resume_data(stream->connection->h2_session,
                                           stream->stream_id);
        (void) magnus_h2_push(magnus_global_epoll_fd, stream->connection);
    }
    return 0;
}

/* on_frame_recv callback for a pooled connection's shared upstream
 * session -- session-level (user_data is the magnus_grpc_conn_t itself,
 * not any one stream), since it also has to react to GOAWAY, which is a
 * whole-connection event, not a per-stream one: once received, this
 * connection is retired from magnus_grpc_conn_pick() (no *new* stream
 * will ever be attached to it again), while every stream already
 * attached is left running normally to completion -- see
 * goaway_received's own comment on the struct.
 *
 * The other job here, unchanged since 2c-2: the moment the upstream's
 * response HEADERS frame (the very first one, NGHTTP2_HCAT_RESPONSE) is
 * fully known for a given stream, submit it to the real client
 * immediately via magnus_h2_grpc_submit_headers() rather than waiting for
 * the whole exchange to finish -- that immediate hand-off is what lets a
 * server-streaming or bidi response's DATA start reaching the real client
 * as it arrives, instead of only once grpc_stream_closed. Fires at most
 * once per stream (guarded by response_headers_submitted); the later
 * trailer HEADERS frame, if any, has already had grpc-status/grpc-message
 * captured by on_header() and needs no reaction here. */
static int
magnus_h2_grpc_client_on_frame_recv(nghttp2_session *session,
                                    const nghttp2_frame *frame,
                                    void *user_data)
{
    magnus_grpc_conn_t *conn = user_data;
    struct magnus_h2_stream *stream;
    if (frame->hd.type == NGHTTP2_GOAWAY) {
        conn->goaway_received = true;
        return 0;
    }
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;
    stream = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (stream == NULL) return 0;
    stream->last_activity = time(NULL);
    if (frame->headers.cat != NGHTTP2_HCAT_RESPONSE
        || stream->response_headers_submitted)
        return 0;
    magnus_h2_grpc_submit_headers(stream->connection, stream);
    (void) magnus_h2_push(magnus_global_epoll_fd, stream->connection);
    return 0;
}

/* on_stream_close callback for a pooled connection's shared upstream
 * session -- deliberately does nothing but record the fact against the
 * one stream it closed (resolved via nghttp2_session_get_stream_user_data(),
 * same as the other per-stream callbacks above; see grpc_stream_closed's
 * own comment on why: nghttp2_session_del() must never be called from
 * inside one of that same session's own callbacks, and finalizing a
 * stream's response -- or, worse, closing the whole shared connection --
 * from here would be reachable from exactly such a context, and would
 * still be wrong even if it were safe: one stream closing says nothing
 * about whether *other* streams sharing this connection are done). The
 * actual finalization/teardown work happens back in
 * magnus_grpc_conn_finalize_closed_streams(), once nghttp2_session_mem_recv2()
 * (which is what invokes this) has returned. */
static int
magnus_h2_grpc_client_on_stream_close(nghttp2_session *session,
                                      int32_t stream_id, uint32_t error_code,
                                      void *user_data)
{
    struct magnus_h2_stream *stream
        = nghttp2_session_get_stream_user_data(session, stream_id);
    (void) user_data;
    (void) error_code;
    if (stream != NULL) stream->grpc_stream_closed = true;
    return 0;
}

/* on_frame_not_send callback for a pooled connection's shared upstream
 * session -- fires when a non-DATA frame this connection had already
 * queued (almost always this one RPC's own request HEADERS) turns out to
 * be impossible to actually send after all, e.g. a GOAWAY arrived on this
 * same connection in the narrow window between magnus_grpc_conn_pick()
 * choosing it and nghttp2 actually flushing that HEADERS frame (see
 * nghttp2_session_mem_send2()'s own documented step 3: "the control frame
 * cannot be sent because some preconditions are not met ... invoked. Abort
 * the following steps."). Same deferred-teardown discipline as
 * on_stream_close() above (this fires from inside the same session's own
 * mem_send2() call stack) -- simply reusing grpc_stream_closed with no
 * grpc-status ever having been set is enough: magnus_grpc_conn_finalize_closed_streams()
 * already treats exactly that shape as a clean UNAVAILABLE/gateway failure,
 * with no separate flag needed. */
static int
magnus_h2_grpc_client_on_frame_not_send(nghttp2_session *session,
                                        const nghttp2_frame *frame,
                                        int lib_error_code, void *user_data)
{
    struct magnus_h2_stream *stream;
    (void) user_data;
    (void) lib_error_code;
    if (frame->hd.type != NGHTTP2_HEADERS) return 0;
    stream = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (stream != NULL) stream->grpc_stream_closed = true;
    return 0;
}

/* Closes a pooled connection outright: deregisters/closes its fd (if any
 * -- a connection that failed before ever getting an fd, or whose fd is
 * already gone, is fine to call this on too, same idempotent-guard shape
 * as magnus_h2_stream_teardown_upstream()), deletes its nghttp2 session,
 * frees its pending-output buffer, and marks the slot free again. Must
 * only ever be called once active_streams is already 0 -- see
 * magnus_grpc_conn_maybe_close_idle()'s own comment, the only place this
 * is normally reached from; calling it earlier would orphan every
 * magnus_h2_stream still pointing at this connection via its own
 * grpc_conn field, a use-after-free waiting to happen the next time any
 * of them is touched. */
static void
magnus_grpc_conn_close(magnus_grpc_conn_t *conn)
{
    if (conn->fd >= 0) {
        if (magnus_global_epoll_fd >= 0)
            epoll_ctl(magnus_global_epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
        magnus_grpc_conn_owner[conn->fd] = NULL;
        close(conn->fd);
        conn->fd = -1;
    }
    if (conn->session != NULL) {
        nghttp2_session_del(conn->session);
        conn->session = NULL;
    }
    free(conn->output);
    conn->output = NULL;
    conn->output_length = 0;
    conn->output_sent = 0;
    conn->in_use = false;
}

/* True once a connection should never be handed a *new* stream again by
 * magnus_grpc_conn_pick() -- either because the peer told us it is
 * shutting down (GOAWAY), a fatal I/O error already happened on it, or it
 * has simply carried enough traffic in its lifetime to be recycled (see
 * MAGNUS_GRPC_POOL_MAX_REQUESTS_PER_CONNECTION's own comment). Streams
 * already attached are unaffected by this on its own -- they keep running
 * to completion; only new attachment is refused. */
static bool
magnus_grpc_conn_retiring(const magnus_grpc_conn_t *conn)
{
    return conn->goaway_received || conn->broken
        || conn->requests_served >= MAGNUS_GRPC_POOL_MAX_REQUESTS_PER_CONNECTION;
}

/* Closes `conn` if it is both idle (no stream currently attached) and
 * retiring (magnus_grpc_conn_retiring()) -- called after every detach
 * (magnus_h2_stream_teardown_upstream()) and from the periodic sweep
 * (magnus_grpc_pool_expire()), so a connection that only just became both
 * (its last stream finished right as/after GOAWAY arrived, say) is closed
 * promptly rather than lingering. A merely-idle-but-healthy connection is
 * deliberately left open here -- that is the whole point of pooling it. */
static void
magnus_grpc_conn_maybe_close_idle(magnus_grpc_conn_t *conn)
{
    if (conn->active_streams == 0 && magnus_grpc_conn_retiring(conn))
        magnus_grpc_conn_close(conn);
}

/* Walks every stream currently attached to `conn` and fails it cleanly
 * (magnus_h2_grpc_fail_or_abort(), the same clean-UNAVAILABLE-or-abort
 * choice every other gRPC failure path already uses) -- used when the
 * connection itself is the problem (a fatal I/O error, a connect that
 * never completed in time, or the whole pool being flushed on config
 * reload/shutdown), not any one RPC. Captures `next` before reacting to
 * the current stream, since magnus_h2_grpc_fail_or_abort() ->
 * magnus_h2_stream_teardown_upstream() unlinks the stream from
 * conn->streams as a side effect -- iterating the list while it is being
 * mutated out from under this loop would otherwise be undefined
 * behavior. */
static void
magnus_grpc_conn_fail_all_streams(magnus_grpc_conn_t *conn,
                                  const char *grpc_status_code,
                                  const char *message)
{
    struct magnus_h2_stream *stream = conn->streams;
    while (stream != NULL) {
        struct magnus_h2_stream *next = stream->grpc_conn_next;
        magnus_h2_grpc_fail_or_abort(stream->connection, stream,
                                     grpc_status_code, message);
        (void) magnus_h2_push(magnus_global_epoll_fd, stream->connection);
        stream = next;
    }
}

/* Reacts to `conn` itself having failed -- a connect that never
 * succeeded, or any later I/O/protocol error. Records the failure against
 * the endpoint's own circuit breaker (magnus_cluster_result(), exactly
 * like a connect failure always has), fails every stream still attached
 * with a clean UNAVAILABLE (no transparent retry-to-a-different-endpoint
 * here -- see magnus_h2_grpc_start()'s own comment on why that is an
 * accepted, deliberate trade-off of pooling rather than an oversight),
 * then closes the connection once (as a side effect of the last stream's
 * own detach, or directly below if none were attached at all -- an idle
 * pooled connection's peer closing it, most commonly). */
static void
magnus_grpc_conn_fail(magnus_grpc_conn_t *conn)
{
    conn->broken = true;
    magnus_cluster_result(&magnus_grpc_cluster, conn->endpoint_index, false,
                          magnus_now_ms());
    magnus_grpc_conn_fail_all_streams(conn, "14",
                                      "gRPC upstream connection lost");
    magnus_grpc_conn_maybe_close_idle(conn);
}

/* Finalizes every stream attached to `conn` whose upstream side has
 * closed (grpc_stream_closed, set by on_stream_close()/on_frame_not_send()
 * above from inside a callback, where nothing more than recording the
 * fact is safe) -- the one piece of work that must happen back in the
 * driving loop's own stack instead. A stream that never got as far as
 * response headers is answered a clean UNAVAILABLE
 * (magnus_h2_grpc_fail()); one that did is marked response_complete (and
 * woken if its own data-provider was deferred waiting for exactly this)
 * so magnus_h2_grpc_read_response() can emit its trailer -- with a
 * synthesized UNKNOWN(2) grpc-status if the upstream's h2 stream simply
 * ended without ever naming a real one, exactly as before pooling.
 * Logging/counters happen here, not at magnus_h2_grpc_submit_headers()
 * time, for the same reason as before: latency and the final outcome are
 * only meaningful once the whole exchange is known complete. Called
 * before reacting to any I/O outcome of the connection itself
 * (magnus_grpc_conn_push()'s own ordering) so a stream that legitimately
 * finished in the same round a later write happens to fail on is never
 * clobbered by that unrelated failure. */
static void
magnus_grpc_conn_finalize_closed_streams(magnus_grpc_conn_t *conn)
{
    struct magnus_h2_stream *stream = conn->streams;
    while (stream != NULL) {
        struct magnus_h2_stream *next = stream->grpc_conn_next;
        if (stream->grpc_stream_closed) {
            magnus_connection_t *connection = stream->connection;
            if (!stream->response_headers_submitted) {
                magnus_h2_grpc_fail(connection, stream, "14",
                                    "upstream did not return a valid gRPC "
                                    "response");
            } else {
                if (stream->grpc_status[0] == '\0') {
                    stream->grpc_status[0] = '2';
                    stream->grpc_status[1] = '\0';
                }
                stream->response_complete = true;
                if (stream->deferred) {
                    stream->deferred = false;
                    (void) nghttp2_session_resume_data(connection->h2_session,
                                                       stream->stream_id);
                }
                {
                    unsigned status_for_log = (unsigned) strtoul(
                        stream->grpc_response_status[0] != '\0'
                            ? stream->grpc_response_status : "200",
                        NULL, 10);
                    double latency_ms = (double) (magnus_now_ms()
                                                  - stream->started_ms);
                    magnus_requests_total++;
                    magnus_record_latency(latency_ms);
                    magnus_grpc_record_status(stream->grpc_status);
                    magnus_access_log(stream->request_id,
                                      stream->effective_client_address,
                                      stream->log_method, stream->log_target,
                                      status_for_log, latency_ms,
                                      (int) strtol(stream->grpc_status, NULL, 10));
                }
            }
            magnus_h2_stream_teardown_upstream(stream);
            (void) magnus_h2_push(magnus_global_epoll_fd, connection);
        }
        stream = next;
    }
}

/* Flushes whatever was left over from a previous magnus_grpc_conn_drain_send()
 * call that could not be written in one go -- the pooled-connection
 * analogue of the old per-stream magnus_h2_grpc_flush_output(), against
 * conn->fd/conn->output instead. */
static int
magnus_grpc_conn_flush_output(magnus_grpc_conn_t *conn)
{
    while (conn->output != NULL && conn->output_sent < conn->output_length) {
        ssize_t sent = send(conn->fd, conn->output + conn->output_sent,
                            conn->output_length - conn->output_sent,
                            MSG_NOSIGNAL);
        if (sent > 0) {
            conn->output_sent += (size_t) sent;
            conn->last_activity = time(NULL);
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        return -1;
    }
    if (conn->output != NULL) {
        free(conn->output);
        conn->output = NULL;
        conn->output_length = 0;
        conn->output_sent = 0;
    }
    return 0;
}

/* Pulls as much serialized output as conn->session currently has queued
 * and writes it to conn->fd -- the pooled-connection analogue of
 * magnus_h2_drain_send(), plaintext-only (plain send(), not
 * magnus_socket_write(): grpc_upstream has no TLS support yet, same as
 * before pooling). Same "copy the unwritten remainder into our own buffer
 * rather than retrying against nghttp2's pointer later" shape, for the
 * identical reason magnus_h2_drain_send() already documents. */
static int
magnus_grpc_conn_drain_send(magnus_grpc_conn_t *conn)
{
    nghttp2_session *session = conn->session;
    for (;;) {
        const uint8_t *data = NULL;
        nghttp2_ssize length = nghttp2_session_mem_send2(session, &data);
        ssize_t sent;
        if (length < 0) return -1;
        if (length == 0) return 0;
        sent = send(conn->fd, data, (size_t) length, MSG_NOSIGNAL);
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) sent = 0;
        else if (sent < 0 && errno == EINTR) sent = 0;
        else if (sent < 0) return -1;
        if ((size_t) sent == (size_t) length) {
            conn->last_activity = time(NULL);
            continue;
        }
        conn->output = malloc((size_t) length - (size_t) sent);
        if (conn->output == NULL) return -1;
        memcpy(conn->output, data + sent, (size_t) length - (size_t) sent);
        conn->output_length = (size_t) length - (size_t) sent;
        conn->output_sent = 0;
        return 0;
    }
}

/* The pooled-connection analogue of magnus_h2_update_interest(), against
 * conn->fd/conn->session instead of connection->fd/h2_session. Unlike the
 * old per-stream magnus_h2_grpc_update_interest(), "nothing to read or
 * write right now" is never treated as an error worth tearing the
 * connection down over here: EPOLLIN is requested unconditionally
 * whenever this is called at all, even for a connection sitting fully
 * idle (active_streams == 0) between RPCs -- unlike the h1 pool's own
 * idle connections (deliberately *not* epoll-registered while idle, see
 * that pool's own comment), a pooled gRPC connection is a live nghttp2
 * session that can receive an unsolicited GOAWAY or PING at any moment,
 * and a genuinely idle connection sitting registered costs nothing
 * meaningful given how small this pool is (at most
 * MAGNUS_CONFIG_MAX_GRPC_UPSTREAMS * MAGNUS_GRPC_POOL_MAX_CONNS_PER_ENDPOINT
 * fds total). */
static int
magnus_grpc_conn_update_interest(int epoll_fd, magnus_grpc_conn_t *conn)
{
    uint32_t events = EPOLLRDHUP | EPOLLIN;
    struct epoll_event event;
    if (nghttp2_session_want_write(conn->session) || conn->output != NULL)
        events |= EPOLLOUT;
    event = (struct epoll_event) { .events = events, .data.fd = conn->fd };
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &event);
}

/* Flushes+drains whatever conn->session currently has queued toward
 * conn->fd, reconciles any streams that just finished or failed as a
 * result (magnus_grpc_conn_finalize_closed_streams() -- run *before*
 * reacting to a write failure below, so a stream that legitimately
 * completed in this same round is never clobbered by an unrelated later
 * write error), and re-arms epoll interest -- the pooled-connection
 * analogue of magnus_h2_push(), callable from outside
 * magnus_grpc_conn_handle_event()'s own driving loop (magnus_grpc_stream_attach(),
 * magnus_h2_grpc_relay_request_chunk(), the END_STREAM wake in
 * magnus_h2_on_frame_recv()) whenever new work needs pushing toward the
 * upstream immediately rather than waiting for whatever epoll event
 * happens to fire next. A no-op, safely, if the connection has not
 * finished connecting yet, or is already gone -- magnus_grpc_conn_handle_event()
 * itself picks up anything already queued once it has connected, and
 * nothing is left to push once the connection has already been closed. */
static int
magnus_grpc_conn_push(magnus_grpc_conn_t *conn)
{
    if (conn->fd < 0 || conn->session == NULL || !conn->connected) return 0;
    magnus_grpc_conn_finalize_closed_streams(conn);
    if (conn->fd < 0 || conn->session == NULL) return 0; /* finalize may have closed an idle, retiring conn */
    if (magnus_grpc_conn_flush_output(conn) < 0
        || (conn->output == NULL && magnus_grpc_conn_drain_send(conn) < 0)) {
        magnus_grpc_conn_fail(conn);
        return 0;
    }
    if (conn->fd >= 0 && conn->session != NULL
        && magnus_grpc_conn_update_interest(magnus_global_epoll_fd, conn) < 0) {
        magnus_grpc_conn_fail(conn);
    }
    return 0;
}

/* Relays one chunk of the client's request body to the upstream as it
 * arrives -- magnus_h2_on_data_chunk_recv()'s gRPC-streaming branch
 * (2c-2). Compacts away whatever magnus_h2_grpc_read_request_body() has
 * already drained (body_sent) before appending, so MAGNUS_MAX_BODY bounds
 * how far behind the *upstream* has fallen, not the request's total size
 * -- the request-direction mirror of magnus_h2_grpc_client_on_data_chunk_recv()'s
 * own compaction on the response side. If the data provider was stalled
 * waiting for exactly this (grpc_request_deferred), wakes it and pushes
 * toward the upstream immediately, once it is actually connected (before
 * that, magnus_grpc_conn_handle_event() will pick up everything queued so
 * far the moment it is). Returns 0 on success, -1 on overflow/OOM -- the
 * caller decides how to react to that (see magnus_h2_grpc_fail_or_abort()). */
static int
magnus_h2_grpc_relay_request_chunk(struct magnus_h2_stream *stream,
                                   const uint8_t *data, size_t len)
{
    if (stream->body_sent > 0) {
        memmove(stream->body, stream->body + stream->body_sent,
               stream->body_length - stream->body_sent);
        stream->body_length -= stream->body_sent;
        stream->body_sent = 0;
    }
    if (stream->body_length + len > MAGNUS_MAX_BODY) return -1;
    if (stream->body_length + len > stream->body_capacity) {
        size_t new_capacity = stream->body_capacity == 0
            ? MAGNUS_PROXY_BUFFER : stream->body_capacity * 2;
        char *grown;
        while (new_capacity < stream->body_length + len) new_capacity *= 2;
        grown = realloc(stream->body, new_capacity);
        if (grown == NULL) return -1;
        stream->body = grown;
        stream->body_capacity = new_capacity;
    }
    memcpy(stream->body + stream->body_length, data, len);
    stream->body_length += len;

    if (stream->grpc_session != NULL && stream->grpc_request_deferred) {
        stream->grpc_request_deferred = false;
        (void) nghttp2_session_resume_data(stream->grpc_session,
                                           stream->grpc_stream_id);
        if (stream->grpc_conn != NULL && stream->grpc_conn->connected)
            (void) magnus_grpc_conn_push(stream->grpc_conn);
    }
    return 0;
}

/* Entry point for any epoll event on a pooled gRPC connection's fd --
 * dispatched via magnus_grpc_conn_owner[] in the main epoll loop, the
 * pooled-connection analogue of magnus_h2_handle_upstream(). Unlike that
 * function (and unlike the pre-pooling magnus_h2_grpc_handle_upstream()
 * it replaces), a failure here is never stream-local: this fd can be
 * driving many concurrent RPCs' upstream leg at once, across possibly
 * several different real client connections, so a fatal error fails every
 * one of them via magnus_grpc_conn_fail() rather than just one. Always
 * returns 0 -- unlike magnus_h2_handle_upstream()'s own contract, no
 * outcome here can ever mean any *particular* client connection must
 * close (magnus_h2_push() is still called per affected connection inside
 * the finalize/fail paths as needed), so the main loop needs no return
 * value to react to. */
static int
magnus_grpc_conn_handle_event(magnus_grpc_conn_t *conn, uint32_t flags)
{
    unsigned char recv_buffer[MAGNUS_PROXY_BUFFER];

    if ((flags & (EPOLLERR | EPOLLHUP)) != 0) {
        magnus_grpc_conn_fail(conn);
        return 0;
    }
    if (!conn->connected) {
        int error = 0;
        socklen_t length = sizeof(error);
        if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &error, &length) < 0
            || error != 0) {
            magnus_grpc_conn_fail(conn);
            return 0;
        }
        conn->connected = true;
        conn->last_activity = time(NULL);
    }

    if (magnus_grpc_conn_flush_output(conn) < 0
        || (conn->output == NULL && magnus_grpc_conn_drain_send(conn) < 0)) {
        magnus_grpc_conn_fail(conn);
        return 0;
    }

    if (conn->output == NULL && (flags & (EPOLLIN | EPOLLRDHUP)) != 0) {
        for (;;) {
            ssize_t received = recv(conn->fd, recv_buffer, sizeof(recv_buffer), 0);
            if (received > 0) {
                nghttp2_ssize consumed = nghttp2_session_mem_recv2(
                    conn->session, recv_buffer, (size_t) received);
                conn->last_activity = time(NULL);
                if (consumed < 0 || magnus_grpc_conn_drain_send(conn) < 0) {
                    magnus_grpc_conn_fail(conn);
                    return 0;
                }
                if (conn->output != NULL) break;
                continue;
            }
            if (received == 0) {
                /* Unlike before pooling, a live connection's peer closing
                 * it is always unexpected here, whether or not any stream
                 * is currently mid-flight on it -- a pooled connection is
                 * meant to stay open indefinitely for reuse, not close
                 * itself the moment its current work is done. */
                magnus_grpc_conn_fail(conn);
                return 0;
            }
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            magnus_grpc_conn_fail(conn);
            return 0;
        }
    }

    magnus_grpc_conn_finalize_closed_streams(conn);
    if (conn->fd >= 0 && conn->session != NULL
        && magnus_grpc_conn_update_interest(magnus_global_epoll_fd, conn) < 0) {
        magnus_grpc_conn_fail(conn);
    }
    return 0;
}

/* Opens a brand-new pooled connection for `endpoint_index`: claims a free
 * slot in magnus_grpc_pool[endpoint_index][] (NULL if the pool is already
 * full for this endpoint -- magnus_grpc_conn_pick() falls back to reusing
 * an existing connection in that case), creates its CLIENT-role nghttp2
 * session (session-level user_data is the magnus_grpc_conn_t itself, not
 * any one stream -- see the per-stream callbacks' own comments on why
 * each resolves its owning stream individually via
 * nghttp2_session_get_stream_user_data() instead), and starts a
 * non-blocking connect(). Nothing here submits any stream's actual
 * request -- that is magnus_grpc_stream_attach()'s job, called
 * separately once a connection (new or existing) has been chosen; a
 * fresh connection can have its first request(s) attached to it well
 * before the connect() itself has completed, exactly as before pooling
 * (nghttp2_submit_request2() only queues frames in the session's own
 * internal state; magnus_grpc_conn_handle_event() flushes them once the
 * fd is actually writable). Returns NULL on any failure (pool full,
 * out of memory, socket()/connect() failing synchronously, epoll_ctl
 * failing) -- every failure mode here cleans up fully after itself,
 * leaving no half-initialized slot behind. */
static magnus_grpc_conn_t *
magnus_grpc_conn_open(size_t endpoint_index)
{
    magnus_grpc_conn_t *conn = NULL;
    nghttp2_session_callbacks *callbacks;
    struct sockaddr_in address;
    int fd, result;

    if (endpoint_index >= MAGNUS_CONFIG_MAX_GRPC_UPSTREAMS) return NULL;
    for (size_t i = 0; i < MAGNUS_GRPC_POOL_MAX_CONNS_PER_ENDPOINT; i++) {
        if (!magnus_grpc_pool[endpoint_index][i].in_use) {
            conn = &magnus_grpc_pool[endpoint_index][i];
            break;
        }
    }
    if (conn == NULL) return NULL;
    if (!magnus_grpc_endpoint_sockaddr(endpoint_index, &address)) return NULL;

    memset(conn, 0, sizeof(*conn));
    conn->fd = -1;

    if (nghttp2_session_callbacks_new(&callbacks) != 0) return NULL;
    nghttp2_session_callbacks_set_on_header_callback(callbacks,
        magnus_h2_grpc_client_on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks,
        magnus_h2_grpc_client_on_data_chunk_recv);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
        magnus_h2_grpc_client_on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
        magnus_h2_grpc_client_on_stream_close);
    nghttp2_session_callbacks_set_on_frame_not_send_callback(callbacks,
        magnus_h2_grpc_client_on_frame_not_send);
    result = nghttp2_session_client_new(&conn->session, callbacks, conn);
    nghttp2_session_callbacks_del(callbacks);
    if (result != 0) return NULL;
    /* Every session -- client or server -- must submit its own initial
     * SETTINGS before nghttp2 will fully process frames the peer sends
     * back: without this, mem_recv2() still reports the peer's bytes as
     * successfully consumed, but never invokes on_frame_recv()/on_header()
     * for anything past the peer's own SETTINGS frame, silently stranding
     * every RPC on this connection forever (found the hard way -- see
     * this increment's own CHANGELOG entry). An empty entry list is
     * enough; there is nothing this session needs to advertise beyond
     * nghttp2's own defaults (no server push to accept, no reason to cap
     * NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS below what nghttp2 already
     * assumes -- see magnus_grpc_conn_pick()'s own comment on why magnus
     * does not need to track that limit itself). */
    if (nghttp2_submit_settings(conn->session, NGHTTP2_FLAG_NONE, NULL, 0) != 0) {
        nghttp2_session_del(conn->session);
        conn->session = NULL;
        return NULL;
    }

    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0 || fd >= MAGNUS_MAX_FDS) {
        if (fd >= 0) close(fd);
        nghttp2_session_del(conn->session);
        conn->session = NULL;
        return NULL;
    }
    result = connect(fd, (struct sockaddr *) &address, sizeof(address));
    if (result < 0 && errno != EINPROGRESS) {
        close(fd);
        nghttp2_session_del(conn->session);
        conn->session = NULL;
        return NULL;
    }

    conn->fd = fd;
    conn->endpoint_index = endpoint_index;
    conn->connected = (result == 0);
    conn->connect_started = time(NULL);
    conn->last_activity = conn->connect_started;
    conn->in_use = true;
    magnus_grpc_conn_owner[fd] = conn;
    {
        struct epoll_event event = { .events = EPOLLOUT | EPOLLRDHUP,
                                     .data.fd = fd };
        if (epoll_ctl(magnus_global_epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
            magnus_grpc_conn_owner[fd] = NULL;
            close(fd);
            nghttp2_session_del(conn->session);
            conn->session = NULL;
            conn->fd = -1;
            conn->in_use = false;
            return NULL;
        }
    }
    return conn;
}

/* Chooses which pooled connection a new gRPC stream should attach to for
 * `endpoint_index` -- the heart of the pool+multiplex design. Scans every
 * connection already open for this endpoint that is neither retiring
 * (magnus_grpc_conn_retiring()) nor already gone, and remembers the one
 * with the fewest streams currently attached (`best`).
 *
 * Deliberately prefers opening a brand-new connection over piling onto an
 * existing one whenever the pool still has room *and* the least-loaded
 * existing connection already has any real load on it at all: with
 * MAGNUS_GRPC_POOL_MAX_CONNS_PER_ENDPOINT connections available, the
 * first few concurrent RPCs to a given endpoint each get their own
 * dedicated connection (maximum parallelism, no head-of-line blocking
 * between unrelated RPCs sharing one connection's own flow-control
 * window), and only once that many are already busy does a new RPC start
 * genuinely multiplexing onto whichever existing connection has room.
 * This is "pool for parallelism, multiplex for overflow" -- not a manual
 * cap on how many streams a connection may carry: nghttp2 already applies
 * the peer's own advertised SETTINGS_MAX_CONCURRENT_STREAMS internally
 * (queuing a request's HEADERS frame rather than sending it immediately
 * if the limit is currently reached, and sending it automatically once
 * room frees up -- see nghttp2_session_mem_send2()'s own documented
 * behavior), so magnus does not need to track or enforce that limit
 * itself for correctness, only for this load-spreading heuristic.
 *
 * Returns NULL only if no usable connection exists for this endpoint and
 * opening a fresh one also failed outright (pool already full and every
 * existing connection is retiring, or a synchronous socket()/connect()
 * failure) -- the caller (magnus_h2_grpc_start()) treats that exactly
 * like the pre-pooling code's own synchronous connect failure: try a
 * different endpoint, bounded by MAGNUS_PROXY_MAX_ATTEMPTS. */
static magnus_grpc_conn_t *
magnus_grpc_conn_pick(size_t endpoint_index)
{
    magnus_grpc_conn_t *best = NULL;
    if (endpoint_index >= MAGNUS_CONFIG_MAX_GRPC_UPSTREAMS) return NULL;
    for (size_t i = 0; i < MAGNUS_GRPC_POOL_MAX_CONNS_PER_ENDPOINT; i++) {
        magnus_grpc_conn_t *conn = &magnus_grpc_pool[endpoint_index][i];
        if (!conn->in_use || magnus_grpc_conn_retiring(conn)) continue;
        if (best == NULL || conn->active_streams < best->active_streams)
            best = conn;
    }
    if (best == NULL || best->active_streams > 0) {
        magnus_grpc_conn_t *fresh = magnus_grpc_conn_open(endpoint_index);
        if (fresh != NULL) return fresh;
    }
    return best;
}

/* Builds and submits this stream's outbound gRPC request onto `conn`'s
 * shared session -- the pooled-connection analogue of the pre-pooling
 * magnus_h2_grpc_build_session()'s own request-submission half (session
 * creation itself moved to magnus_grpc_conn_open(), called at most once
 * per connection rather than once per RPC). Resets every per-attempt
 * gRPC capture field first, so this is also what a retry (a different
 * endpoint, a different connection) calls again cleanly. Requires
 * conn->endpoint_index to name the same cluster entry stream->endpoint_index
 * was just set to (magnus_h2_grpc_start() guarantees this -- the
 * outbound request's :authority depends on which endpoint was chosen).
 *
 * Links `stream` into conn->streams (its intrusive attached-stream list)
 * and increments active_streams/requests_served *before* the final
 * magnus_grpc_conn_push(), so a push that immediately discovers the
 * connection is broken (magnus_grpc_conn_fail()) already sees this stream
 * as one it needs to fail, rather than leaking it un-tracked. Returns 0
 * on success, -1 on failure (out of memory, or nghttp2_submit_request2()
 * itself refusing, e.g. stream-id space exhausted on an extremely
 * long-lived connection -- see MAGNUS_GRPC_POOL_MAX_REQUESTS_PER_CONNECTION's
 * own comment on why that is not a realistic concern in practice) --
 * nothing is linked/counted in that case, so the caller can simply try a
 * different connection or endpoint. */
static int
magnus_grpc_stream_attach(struct magnus_h2_stream *stream,
                          magnus_grpc_conn_t *conn)
{
    nghttp2_nv headers[4 + MAGNUS_HTTP_MAX_HEADERS];
    size_t count = 0;
    char authority[80];
    int32_t submitted_stream_id;

    stream->grpc_stream_closed = false;
    stream->grpc_request_deferred = false;
    stream->grpc_status[0] = '\0';
    stream->grpc_message[0] = '\0';
    stream->grpc_response_status[0] = '\0';
    stream->grpc_response_header_count = 0;
    stream->grpc_response_trailer_count = 0;
    stream->io_length = 0;
    stream->io_sent = 0;
    stream->body_sent = 0;

    snprintf(authority, sizeof(authority), "%s:%u",
            magnus_grpc_cluster.endpoints[conn->endpoint_index].address,
            magnus_grpc_cluster.endpoints[conn->endpoint_index].port);

    headers[count++] = magnus_h2_nv(":method", stream->parsed.method);
    headers[count++] = magnus_h2_nv(":scheme", "http");
    headers[count++] = magnus_h2_nv(":authority", authority);
    headers[count++] = magnus_h2_nv(":path", stream->parsed.target);
    for (size_t i = 0; i < stream->parsed.header_count
                       && count < sizeof(headers) / sizeof(headers[0]); i++) {
        const char *name = stream->parsed.headers[i].name;
        const char *value = stream->parsed.headers[i].value;
        /* Hop-by-hop (never meaningful in h2 anyway, RFC 9113 8.2.2) plus
         * "host" -- already carried as :authority above. "te" is hop-by-hop
         * too, EXCEPT for the one value RFC 9113 8.2.2 explicitly still
         * allows: "trailers" -- which is exactly what every real gRPC
         * client sends on every request (RFC-mandated, to signal trailer
         * support), so stripping it unconditionally here breaks gRPC
         * outright: grpc-core rejects a request missing it with an
         * immediate RST_STREAM before ever reaching the application
         * handler, which is indistinguishable from any other transport
         * failure without capturing wire traffic to notice. */
        if (strcmp(name, "connection") == 0 || strcmp(name, "keep-alive") == 0
            || strcmp(name, "proxy-connection") == 0
            || strcmp(name, "transfer-encoding") == 0
            || strcmp(name, "upgrade") == 0
            || (strcmp(name, "te") == 0 && strcmp(value, "trailers") != 0)
            || strcmp(name, "host") == 0)
            continue;
        headers[count++] = magnus_h2_nv(name, value);
    }

    {
        nghttp2_data_provider2 data_provider = {
            .source = { .ptr = stream },
            .read_callback = magnus_h2_grpc_read_request_body,
        };
        /* Dispatch happens as soon as request HEADERS complete, well
         * before END_STREAM for anything but a bodyless call -- so
         * body_length being 0 *right now* does not mean there is no
         * body, only that none of it has arrived yet. The data provider
         * must be attached whenever more could still be coming
         * (!request_end_stream_seen), not just when something has
         * already arrived; omitting it here for a soon-to-stream call
         * would wrongly submit HEADERS with END_STREAM set (data_prd ==
         * NULL means "no body, ever" -- see nghttp2_submit_request2()'s
         * own contract), foreclosing the request body track entirely. */
        bool has_body_or_more_coming = stream->body_length > 0
            || !stream->request_end_stream_seen;
        submitted_stream_id = nghttp2_submit_request2(conn->session, NULL,
            headers, count, has_body_or_more_coming ? &data_provider : NULL,
            NULL);
    }
    if (submitted_stream_id < 0) return -1;
    (void) nghttp2_session_set_stream_user_data(conn->session,
        submitted_stream_id, stream);

    stream->grpc_conn = conn;
    stream->grpc_session = conn->session;
    stream->grpc_stream_id = submitted_stream_id;
    stream->last_activity = time(NULL);
    stream->grpc_conn_next = conn->streams;
    stream->grpc_conn_prev = NULL;
    if (conn->streams != NULL) conn->streams->grpc_conn_prev = stream;
    conn->streams = stream;
    conn->active_streams++;
    conn->requests_served++;

    (void) magnus_grpc_conn_push(conn);
    return 0;
}

/* Entry point from magnus_h2_dispatch(): picks a healthy
 * magnus_grpc_cluster endpoint, then picks or opens a pooled connection
 * for it (magnus_grpc_conn_pick()) and attaches this stream's request
 * onto it (magnus_grpc_stream_attach()) -- retrying once against a
 * different endpoint on an immediate failure, exactly like the h1-proxy
 * path (MAGNUS_PROXY_MAX_ATTEMPTS).
 *
 * Pooling (2c-5) narrows one thing from before: a *synchronous* failure
 * right here (no healthy endpoint at all, or the very first connection
 * to a never-yet-proven endpoint failing to even start) still retries a
 * different endpoint before ever telling the client anything, same as
 * always. But an *asynchronous* connect failure discovered later, via
 * epoll (magnus_grpc_conn_fail(), called from magnus_grpc_conn_handle_event()),
 * no longer transparently retries the affected stream(s) onto a
 * different endpoint the way the pre-pooling design did -- it answers a
 * clean UNAVAILABLE (grpc-status=14) instead. This is an accepted,
 * deliberate trade-off, not an oversight: unlike before pooling, where
 * every single RPC opened its own fresh connection (so any connect
 * failure was necessarily this one RPC's own, and the natural place to
 * retry it), a pooled connection is reused across many RPCs once proven
 * -- an async connect failure now only ever affects the (typically very
 * few, often exactly one) RPC(s) that happened to be the first ever sent
 * to a not-yet-proven endpoint, or every endpoint being down at once
 * (already the existing, unavoidable "no healthy upstream" case).
 * UNAVAILABLE is also specifically the one gRPC status code real client
 * libraries already retry on their own under most default retry
 * policies, unlike most other codes -- so the client-visible behavior
 * for this narrow case is "the client's own retry fires instead of
 * magnus's," not "the request simply fails where it used to succeed."
 * Reproducing the old per-RPC retry-to-a-different-endpoint behavior
 * for this async case would mean re-running endpoint selection + pool
 * pick + attach for every still-not-yet-submitted stream individually
 * from inside magnus_grpc_conn_fail_all_streams()'s own fan-out, each of
 * which could itself pick yet another still-connecting, possibly-also-
 * failing connection -- real complexity for a failure mode this rare
 * once any endpoint has ever proven reachable at all.
 *
 * Session affinity (roadmap 2c-4) is unaffected by any of this: works
 * the same way as the h1/h2-proxy paths, and independently of which
 * *connection* within the chosen endpoint's own little pool this stream's
 * RPC ends up multiplexed onto (affinity is endpoint-level, not
 * connection-level -- a sticky client's repeat calls all land on the same
 * backend process, but may still ride different physical connections to
 * it, exactly as intended: it is the backend's own state the client
 * needs to stay pinned to, never a single TCP connection). */
static void
magnus_h2_grpc_start(magnus_connection_t *connection,
                     struct magnus_h2_stream *stream)
{
    const char *timeout_header;
    const char *cookie_header = magnus_http_header_find(&stream->parsed, "cookie");
    char client_affinity[64] = "";
    bool sticky;
    size_t preferred_index;

    magnus_generate_token(stream->request_id);
    strncpy(stream->log_method, stream->parsed.method,
           sizeof(stream->log_method) - 1);
    stream->log_method[sizeof(stream->log_method) - 1] = '\0';
    strncpy(stream->log_target, stream->parsed.target,
           sizeof(stream->log_target) - 1);
    stream->log_target[sizeof(stream->log_target) - 1] = '\0';
    stream->is_grpc = true;
    stream->attempt = 0;

    /* Deadline propagation (roadmap 2c-3): parsed and clamped exactly
     * once here, never recomputed on a connect retry (see
     * grpc_deadline_ms's own comment on the struct). Left at 0 (no
     * deadline -- falls back to the default connect/read timeout budget
     * in magnus_expire_proxies()) when the header is absent or
     * malformed. */
    timeout_header = magnus_http_header_find(&stream->parsed, "grpc-timeout");
    if (timeout_header != NULL) {
        uint64_t timeout_ms;
        if (magnus_grpc_parse_timeout(timeout_header, &timeout_ms)) {
            if (timeout_ms > MAGNUS_GRPC_MAX_TIMEOUT_MS)
                timeout_ms = MAGNUS_GRPC_MAX_TIMEOUT_MS;
            stream->grpc_deadline_ms = magnus_now_ms() + timeout_ms;
        }
    }

    if (cookie_header != NULL)
        (void) magnus_http_extract_cookie(cookie_header, strlen(cookie_header),
                                          MAGNUS_AFFINITY_COOKIE_NAME,
                                          client_affinity,
                                          sizeof(client_affinity));
    sticky = magnus_decode_affinity_cookie(
        client_affinity[0] != '\0' ? client_affinity : NULL, &preferred_index);
    stream->issue_affinity_cookie = !sticky;

    for (;;) {
        int endpoint = sticky
            ? magnus_cluster_select_sticky(&magnus_grpc_cluster,
                                           magnus_now_ms(), preferred_index,
                                           stream->effective_client_address)
            : magnus_cluster_select(&magnus_grpc_cluster, magnus_now_ms(),
                                    NULL, stream->effective_client_address);
        magnus_grpc_conn_t *conn;
        if (endpoint < 0) {
            magnus_h2_grpc_fail(connection, stream, "14",
                                "no healthy gRPC upstream available");
            return;
        }
        if (sticky) {
            sticky = false;
        } else if (stream->attempt > 0) {
            stream->issue_affinity_cookie = true;
        }
        stream->attempt++;
        stream->endpoint_index = (size_t) endpoint;

        conn = magnus_grpc_conn_pick((size_t) endpoint);
        if (conn != NULL && magnus_grpc_stream_attach(stream, conn) == 0) {
            if (stream->issue_affinity_cookie) {
                magnus_encode_affinity_cookie(stream->affinity_key,
                                              sizeof(stream->affinity_key),
                                              (size_t) endpoint);
            }
            return;
        }
        magnus_cluster_result(&magnus_grpc_cluster, (size_t) endpoint, false,
                              magnus_now_ms());
        if (stream->attempt >= MAGNUS_PROXY_MAX_ATTEMPTS) {
            magnus_h2_grpc_fail(connection, stream, "14",
                                "gRPC upstream connect failed");
            return;
        }
    }
}

/* Closes every pooled gRPC connection outright, failing any stream still
 * attached to one with a clean UNAVAILABLE first -- the gRPC pool's
 * analogue of magnus_pool_close_all(), called from the same two places:
 * magnus_apply_config() (a reload may have changed the gRPC cluster's own
 * endpoint set entirely, so nothing here can safely be kept around to be
 * reused against a config that may no longer even describe the same
 * backends) and final process shutdown. */
static void
magnus_grpc_pool_close_all(void)
{
    for (size_t endpoint = 0; endpoint < MAGNUS_CONFIG_MAX_GRPC_UPSTREAMS;
         endpoint++) {
        for (size_t i = 0; i < MAGNUS_GRPC_POOL_MAX_CONNS_PER_ENDPOINT; i++) {
            magnus_grpc_conn_t *conn = &magnus_grpc_pool[endpoint][i];
            if (!conn->in_use) continue;
            if (conn->active_streams > 0)
                magnus_grpc_conn_fail_all_streams(conn, "14",
                    "gRPC upstream pool reset");
            magnus_grpc_conn_close(conn);
        }
    }
}

/* Periodic (1Hz) sweep for the gRPC pool, called alongside
 * magnus_pool_expire_idle()/magnus_expire_proxies(): fails any connection
 * that has been trying to connect for too long
 * (MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS, the same budget a fresh h1/h2-
 * proxy connect attempt gets) without ever completing, and closes any
 * connection that has sat fully idle (no stream attached) for too long
 * (MAGNUS_GRPC_POOL_IDLE_TIMEOUT_SECONDS). Deliberately a connection-level
 * sweep, not folded into magnus_expire_proxies()'s own per-stream loop:
 * a connect timeout is a whole-connection event that can affect several
 * concurrently-attached streams at once (every stream that raced to
 * attach to the same still-connecting new connection), and reacting to
 * it once per *stream* there would mean the first stream's own reaction
 * (magnus_grpc_conn_fail() closing the connection) leaves every later
 * stream in that same per-stream loop iteration pointing at an
 * already-freed connection -- a use-after-free. Per-stream concerns
 * (grpc-timeout deadlines, and the default per-stream read/inactivity
 * timeout once a connection *is* connected) stay in
 * magnus_expire_proxies() itself, where reacting to them individually is
 * safe -- see that function's own comment. */
static void
magnus_grpc_pool_expire(time_t now)
{
    for (size_t endpoint = 0; endpoint < MAGNUS_CONFIG_MAX_GRPC_UPSTREAMS;
         endpoint++) {
        for (size_t i = 0; i < MAGNUS_GRPC_POOL_MAX_CONNS_PER_ENDPOINT; i++) {
            magnus_grpc_conn_t *conn = &magnus_grpc_pool[endpoint][i];
            if (!conn->in_use) continue;
            if (!conn->connected) {
                if (now - conn->connect_started
                    >= MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS)
                    magnus_grpc_conn_fail(conn);
                continue;
            }
            if (conn->active_streams == 0
                && now - conn->last_activity
                       >= MAGNUS_GRPC_POOL_IDLE_TIMEOUT_SECONDS) {
                magnus_grpc_conn_close(conn);
            }
        }
    }
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
    /* Advanced load balancing (roadmap 2e-1): live per-endpoint in-flight
     * count -- what MAGNUS_LB_LEAST_CONN itself reads to decide, and
     * useful observability regardless of which policy is configured
     * (always maintained by the h1/h2 proxy dispatch paths; see
     * magnus_cluster_endpoint_begin()'s own comment). */
    if (written < out_capacity) {
        int line = snprintf(out + written, out_capacity - written,
            "# TYPE magnus_upstream_active_requests gauge\n");
        if (line > 0 && (size_t) line < out_capacity - written)
            written += (size_t) line;
    }
    for (size_t index = 0; index < magnus_cluster.count
         && written < out_capacity; index++) {
        int line = snprintf(out + written, out_capacity - written,
            "magnus_upstream_active_requests{endpoint=\"%s:%u\"} %u\n",
            magnus_cluster.endpoints[index].address,
            magnus_cluster.endpoints[index].port,
            magnus_cluster.endpoints[index].active_requests);
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

    /* gRPC-status breakdown (roadmap 2c-4) -- gated on
     * magnus_grpc_upstream_enabled (unlike magnus_upstream_healthy above,
     * which always iterates every configured HTTP/1.x endpoint even at
     * zero) so a deployment that never configured a grpc_upstream at all
     * gets no new lines here whatsoever; among gRPC status codes
     * themselves, only ones that have actually occurred at least once are
     * emitted, keeping this lean rather than always printing all 17. */
    if (magnus_grpc_upstream_enabled && written < out_capacity) {
        int line = snprintf(out + written, out_capacity - written,
            "# TYPE magnus_grpc_status_total counter\n");
        if (line > 0 && (size_t) line < out_capacity - written)
            written += (size_t) line;
        for (int code = 0; code < 17 && written < out_capacity; code++) {
            if (magnus_grpc_status_counts[code] == 0) continue;
            int line2 = snprintf(out + written, out_capacity - written,
                "magnus_grpc_status_total{code=\"%d\"} %llu\n", code,
                (unsigned long long) magnus_grpc_status_counts[code]);
            if (line2 < 0 || (size_t) line2 >= out_capacity - written) return;
            written += (size_t) line2;
        }
        /* Active health checking now covers the gRPC cluster too (roadmap
         * 2f, TCP-connect probe only -- see magnus_health_tick()'s own
         * comment on why not a real HTTP GET here); before this it had no
         * per-endpoint health observability of its own at all, only
         * whatever live gRPC traffic happened to reveal. Mirrors
         * magnus_upstream_healthy above, one line per configured gRPC
         * endpoint. */
        if (written < out_capacity) {
            int line = snprintf(out + written, out_capacity - written,
                "# TYPE magnus_grpc_upstream_healthy gauge\n");
            if (line > 0 && (size_t) line < out_capacity - written)
                written += (size_t) line;
        }
        for (size_t index = 0; index < magnus_grpc_cluster.count
             && written < out_capacity; index++) {
            int line = snprintf(out + written, out_capacity - written,
                "magnus_grpc_upstream_healthy{endpoint=\"%s:%u\"} %d\n",
                magnus_grpc_cluster.endpoints[index].address,
                magnus_grpc_cluster.endpoints[index].port,
                magnus_grpc_cluster.endpoints[index].healthy ? 1 : 0);
            if (line < 0 || (size_t) line >= out_capacity - written) return;
            written += (size_t) line;
        }
    }

    /* L4 TCP passthrough (roadmap 3a) -- gated on magnus_stream_enabled,
     * same reasoning as the gRPC block above: a deployment that never
     * configured stream_listen at all gets no new lines here whatsoever. */
    if (magnus_stream_enabled && written < out_capacity) {
        int line = snprintf(out + written, out_capacity - written,
            "# TYPE magnus_stream_connections_total counter\n"
            "magnus_stream_connections_total %llu\n"
            "# TYPE magnus_stream_connections_active gauge\n"
            "magnus_stream_connections_active %llu\n"
            "# TYPE magnus_stream_bytes_total counter\n"
            "magnus_stream_bytes_total{direction=\"client_to_upstream\"} %llu\n"
            "magnus_stream_bytes_total{direction=\"upstream_to_client\"} %llu\n"
            "# TYPE magnus_stream_upstream_healthy gauge\n",
            (unsigned long long) magnus_stream_connections_total,
            (unsigned long long) magnus_stream_connections_active,
            (unsigned long long) magnus_stream_bytes_c2u_total,
            (unsigned long long) magnus_stream_bytes_u2c_total);
        if (line > 0 && (size_t) line < out_capacity - written)
            written += (size_t) line;
        for (size_t index = 0; index < magnus_stream_cluster.count
             && written < out_capacity; index++) {
            int line2 = snprintf(out + written, out_capacity - written,
                "magnus_stream_upstream_healthy{endpoint=\"%s:%u\"} %d\n",
                magnus_stream_cluster.endpoints[index].address,
                magnus_stream_cluster.endpoints[index].port,
                magnus_stream_cluster.endpoints[index].healthy ? 1 : 0);
            if (line2 < 0 || (size_t) line2 >= out_capacity - written) return;
            written += (size_t) line2;
        }
        /* TLS passthrough / SNI routing (roadmap 3b) -- one gauge line
         * per (pattern, endpoint) pair across every configured
         * stream_sni_route cluster; empty (no extra lines at all) when
         * none are configured, same as the base block above already is
         * when stream_listen itself is unused. */
        if (magnus_sni_cluster_count > 0 && written < out_capacity) {
            int line3 = snprintf(out + written, out_capacity - written,
                "# TYPE magnus_stream_sni_upstream_healthy gauge\n");
            if (line3 > 0 && (size_t) line3 < out_capacity - written)
                written += (size_t) line3;
        }
        for (size_t route_index = 0; route_index < magnus_sni_cluster_count
             && written < out_capacity; route_index++) {
            magnus_sni_cluster_t *route = &magnus_sni_clusters[route_index];
            for (size_t index = 0; index < route->cluster.count
                 && written < out_capacity; index++) {
                int line4 = snprintf(out + written, out_capacity - written,
                    "magnus_stream_sni_upstream_healthy{pattern=\"%s\","
                    "endpoint=\"%s:%u\"} %d\n",
                    route->pattern, route->cluster.endpoints[index].address,
                    route->cluster.endpoints[index].port,
                    route->cluster.endpoints[index].healthy ? 1 : 0);
                if (line4 < 0 || (size_t) line4 >= out_capacity - written)
                    return;
                written += (size_t) line4;
            }
        }
    }

    /* UDP passthrough (roadmap 3d) -- gated on magnus_udp_enabled, same
     * reasoning as the stream block above. No healthy/unhealthy gauge:
     * this cluster tracks no health signal at all (see
     * magnus_udp_session_t's own comment on why) -- exposing one that
     * could only ever read "always healthy" would be actively
     * misleading rather than merely unused. active_sessions is the real
     * per-endpoint load signal this cluster does have, reusing
     * magnus_endpoint_t's own active_requests field (see
     * magnus_udp_create_session()'s own comment on the reuse). */
    if (magnus_udp_enabled && written < out_capacity) {
        int line = snprintf(out + written, out_capacity - written,
            "# TYPE magnus_udp_sessions_total counter\n"
            "magnus_udp_sessions_total %llu\n"
            "# TYPE magnus_udp_sessions_active gauge\n"
            "magnus_udp_sessions_active %zu\n"
            "# TYPE magnus_udp_bytes_total counter\n"
            "magnus_udp_bytes_total{direction=\"client_to_upstream\"} %llu\n"
            "magnus_udp_bytes_total{direction=\"upstream_to_client\"} %llu\n"
            "# TYPE magnus_udp_upstream_active_sessions gauge\n",
            (unsigned long long) magnus_udp_sessions_total,
            magnus_udp_session_count,
            (unsigned long long) magnus_udp_bytes_c2u_total,
            (unsigned long long) magnus_udp_bytes_u2c_total);
        if (line > 0 && (size_t) line < out_capacity - written)
            written += (size_t) line;
        for (size_t index = 0; index < magnus_udp_cluster.count
             && written < out_capacity; index++) {
            int line2 = snprintf(out + written, out_capacity - written,
                "magnus_udp_upstream_active_sessions{endpoint=\"%s:%u\"} %u\n",
                magnus_udp_cluster.endpoints[index].address,
                magnus_udp_cluster.endpoints[index].port,
                magnus_udp_cluster.endpoints[index].active_requests);
            if (line2 < 0 || (size_t) line2 >= out_capacity - written) return;
            written += (size_t) line2;
        }
    }

    /* Reverse-proxy cache (roadmap 2d-1) -- always emitted (like the
     * connections/requests counters above), not gated on any route
     * actually having cache=on: the values are simply all zero when
     * nothing ever does, same as every other counter here starts at
     * zero. */
    if (written < out_capacity) {
        int line = snprintf(out + written, out_capacity - written,
            "# TYPE magnus_cache_hits_total counter\n"
            "magnus_cache_hits_total %llu\n"
            "# TYPE magnus_cache_misses_total counter\n"
            "magnus_cache_misses_total %llu\n"
            "# TYPE magnus_cache_revalidated_total counter\n"
            "magnus_cache_revalidated_total %llu\n"
            "# TYPE magnus_cache_entries gauge\n"
            "magnus_cache_entries %zu\n"
            "# TYPE magnus_cache_bytes gauge\n"
            "magnus_cache_bytes %zu\n",
            (unsigned long long) magnus_cache_hits_total(),
            (unsigned long long) magnus_cache_misses_total(),
            (unsigned long long) magnus_cache_revalidated_total(),
            magnus_cache_entries_count(), magnus_cache_bytes_used());
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
    bool is_grpc_route = false;
    bool literal_proxy_prefix;
    bool route_denied = false;
    bool cache_route_enabled = false;
    const char *proxy_forward_path;

    memcpy(request.method, parsed->method, sizeof(request.method));
    memcpy(request.path, parsed->target, sizeof(request.path));

    /* Real IP (roadmap 2b): resolved once per request, here, into
     * connection->client_address itself -- safe for HTTP/1.1 (unlike h2)
     * because a connection only ever has one request in flight at a time,
     * so nothing else can observe a half-updated value. Trust is always
     * decided against connection->raw_peer_address (the true, direct TCP
     * peer), never against client_address, so a resolved value from one
     * hop can never be replayed to forge trust for the next. */
    if (!connection->admin_only && magnus_trusted_proxy_count > 0
        && magnus_realip_is_trusted(magnus_trusted_proxies,
                                    magnus_trusted_proxy_count,
                                    connection->raw_peer_address)) {
        struct in_addr resolved;
        if (magnus_realip_resolve_headers(parsed, magnus_trusted_proxies,
                                          magnus_trusted_proxy_count, &resolved)) {
            connection->client_address = resolved;
        }
    }

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
                cache_route_enabled = magnus_routes[r].cache_enabled;
            } else if (magnus_routes[r].action == MAGNUS_ROUTE_ACTION_DENY) {
                route_denied = true;
            } else if (magnus_routes[r].action == MAGNUS_ROUTE_ACTION_GRPC) {
                is_grpc_route = true;
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
    } else if (strcmp(request.method, "GET") != 0 && !head_only && !is_proxy_route
               && !is_grpc_route) {
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
    } else if (is_grpc_route) {
        /* A real gRPC server requires HTTP/2 end to end (trailers alone
         * make it impossible over HTTP/1.1) -- explicit and immediate
         * here, per this codebase's standing convention of never silently
         * mis-serving a request that reached an incompatible dispatch
         * path, rather than letting it fall through to ordinary static
         * dispatch as if action=grpc were not there at all. Checked after
         * the /healthz//metrics literal-path exemptions above, same
         * precedent as is_proxy_route below: a literal /healthz or
         * /metrics request still gets its ordinary built-in answer even
         * if it happens to also match an action=grpc route's conditions.
         * See magnus_h2_dispatch()'s own action=grpc branch for the real,
         * HTTP/2-only path this exists for. */
        magnus_prepare_response(connection, 505, "HTTP Version Not Supported",
                                "text/plain",
                                "gRPC requires HTTP/2 (TLS ALPN \"h2\" or "
                                "h2c)\n", head_only, close_connection,
                                &request);
    } else if (is_proxy_route) {
        int start_result = magnus_proxy_pick_and_start(epoll_fd, connection,
                                                        &request, parsed,
                                                        proxy_forward_path,
                                                        parsed->affinity_key,
                                                        close_connection,
                                                        cache_route_enabled);
        if (start_result == 0) {
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
        } else if (start_result != 2) {
            magnus_prepare_response(connection, 502, "Bad Gateway", "text/plain",
                                    "bad gateway\n", head_only, true, &request);
        }
        /* start_result == 2: answered synchronously and completely from
         * the reverse-proxy cache (roadmap 2d-1) -- request.status was
         * already set by magnus_serve_cached_response(), so this falls
         * through to the same common access-log tail below every other
         * synchronous dispatch in this function already uses. */
    } else if (strcmp(request.path, "/") == 0) {
        magnus_prepare_response(connection, 200, "OK", "application/json",
                                "{\"name\":\"Magnus\",\"engine\":\"native-c17\",\"status\":\"ready\"}\n",
                                head_only, close_connection, &request);
    } else {
        struct stat metadata;
        int file_fd = magnus_open_static(request.path, &metadata);
        if (file_fd >= 0)
            magnus_prepare_file_response(connection, file_fd, &metadata,
                                         head_only, close_connection, &request,
                                         parsed);
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
        magnus_access_log(request.request_id, connection->client_address,
                          request.method, request.path,
                          request.status, latency_ms, -1);
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
    /* This synthetic stream never goes through magnus_h2_on_frame_recv()'s
     * real HEADERS-frame handling at all (see this function's own
     * comment: it is dispatched immediately, exactly as if END_STREAM
     * had just been observed) -- so magnus_h2_dispatch()'s own streaming
     * (2c-2) defer-until-request_end_stream_seen check needs telling
     * directly that this request's body (an Upgrade: h2c request is
     * scoped to carry none at all -- see h2c_pending's own comment) is
     * already fully known, or a non-gRPC route here would wait forever
     * for a END_STREAM event that can never arrive on this stream. */
    stream->request_end_stream_seen = true;
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

/* Largest possible PROXY protocol preamble: v1's text line is capped at
 * 107 bytes by spec; v2's binary header is a fixed 16-byte prefix plus up
 * to 1024 bytes of address block (the cap magnus_proxy_proto_parse()
 * itself enforces, returning MAGNUS_PROXY_PROTO_ERROR past it) -- so 1040
 * bytes is always enough to see one complete preamble of either kind in a
 * single MSG_PEEK. */
#define MAGNUS_PROXY_PROTO_PEEK_MAX 1040

/* Real IP (roadmap 2b): checked at most once per connection, before either
 * TLS handshake or h2c prior-knowledge preface detection -- a proxy
 * speaking the PROXY protocol prepends its preamble in plaintext ahead of
 * the actual payload (a TLS ClientHello just as much as plain HTTP), so
 * this has to run first regardless of connection->tls, and it talks to
 * connection->fd directly with plain recv() rather than through
 * magnus_socket_read()/SSL for exactly that reason -- OpenSSL has not
 * touched this fd yet at this point (SSL_accept() is only ever called once
 * tls_ready is checked, further down the dispatch loop), so a raw peek
 * here cannot desynchronize a TLS handshake that comes after it.
 *
 * Only ever reached for a connection whose raw_peer_address matched
 * magnus_trusted_proxies at accept time (see magnus_accept_connections):
 * every other connection already has proxy_proto_done set to true from
 * the moment it was accepted and never calls this at all, making the
 * feature a zero-cost no-op for every untrusted peer or when no
 * trusted_proxies are configured at all.
 *
 * Uses MSG_PEEK until a full preamble is confirmed one way or another, so
 * an incomplete preamble costs nothing but being asked again against the
 * same (plus whatever newly arrived) bytes on the next EPOLLIN, with no
 * extra accumulation buffer of its own. Returns 0 to let the caller
 * continue handling this event -- either more bytes are still needed, or
 * the preamble is now fully resolved (consumed if it was one; left
 * untouched on the wire if it was not) and the caller should proceed
 * exactly as if this check did not exist -- or -1 on a fatal, malformed
 * preamble from a supposedly trusted peer. */
static int
magnus_proxy_proto_check(magnus_connection_t *connection)
{
    char peek_buffer[MAGNUS_PROXY_PROTO_PEEK_MAX];
    ssize_t peeked;
    size_t consumed = 0;
    struct in_addr src_ip = {0};
    magnus_proxy_proto_result_t proto_result;

    peeked = recv(connection->fd, peek_buffer, sizeof(peek_buffer), MSG_PEEK);
    if (peeked < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;
        return -1;
    }
    if (peeked == 0) {
        /* Peer closed before sending anything at all -- let the ordinary
         * TLS handshake or magnus_handle_read() path observe the same EOF
         * and close the connection exactly as it always has. */
        connection->proxy_proto_done = true;
        return 0;
    }

    proto_result = magnus_proxy_proto_parse(peek_buffer, (size_t) peeked,
                                            &consumed, &src_ip);
    if (proto_result == MAGNUS_PROXY_PROTO_INCOMPLETE) {
        /* A hostile trusted peer trickling bytes forever is still bounded
         * by the same header_deadline/idle-timeout sweep as any other slow
         * client -- nothing extra needed here. */
        return 0;
    }
    if (proto_result == MAGNUS_PROXY_PROTO_ERROR) {
        return -1;
    }
    connection->proxy_proto_done = true;
    if (proto_result == MAGNUS_PROXY_PROTO_NOT_PROXY) {
        /* Not a PROXY preamble -- nothing was consumed (MSG_PEEK never
         * touches the socket's read position), so the caller falls
         * through to ordinary TLS/HTTP processing of these exact same
         * bytes as if this check had never run. */
        return 0;
    }
    /* MAGNUS_PROXY_PROTO_OK: drain exactly the preamble's bytes now that
     * their count is known -- MSG_PEEK left them sitting on the socket. */
    {
        char discard[256];
        size_t remaining = consumed;
        while (remaining > 0) {
            size_t chunk = remaining < sizeof(discard) ? remaining : sizeof(discard);
            ssize_t drained = recv(connection->fd, discard, chunk, 0);
            if (drained <= 0) return -1;
            remaining -= (size_t) drained;
        }
    }
    /* TCP4 (v1) / AF_INET PROXY (v2) resolve a real source address; v1
     * UNKNOWN/TCP6 and v2 LOCAL/UNSPEC/AF_INET6/AF_UNIX are all valid
     * preambles that intentionally carry none (see magnus_proxy_proto_parse's
     * own contract) -- raw_peer_address remains the correct, already-set
     * client_address in every one of those cases, so only overwrite it when
     * an address actually came back. */
    if (src_ip.s_addr != 0) {
        connection->client_address = src_ip;
        connection->realip_from_proxy_proto = true;
    }
    return 0;
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
    while (connection->compressed_body_sent
           < connection->compressed_body_length) {
        sent = magnus_socket_write(connection,
            connection->compressed_body + connection->compressed_body_sent,
            connection->compressed_body_length
                - connection->compressed_body_sent);
        if (sent > 0) {
            connection->compressed_body_sent += (size_t) sent;
            magnus_bytes_sent += (uint64_t) sent;
            connection->last_active = time(NULL);
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        return -1;
    }
    /* Reverse-proxy cache (roadmap 2d-1): a cache-served response's own
     * headers, then body -- see magnus_serve_cached_response()'s own
     * comment on why these are two dedicated fields rather than reusing
     * output/compressed_body above (same shape, kept separate so neither
     * purpose's lifecycle has to account for the other). Mutually
     * exclusive with the file_fd-driven blocks below by construction: a
     * cache-serve response never sets file_fd. */
    while (connection->cache_serve_headers != NULL
           && connection->cache_serve_headers_sent
              < connection->cache_serve_headers_length) {
        sent = magnus_socket_write(connection,
            connection->cache_serve_headers + connection->cache_serve_headers_sent,
            connection->cache_serve_headers_length
                - connection->cache_serve_headers_sent);
        if (sent > 0) {
            connection->cache_serve_headers_sent += (size_t) sent;
            magnus_bytes_sent += (uint64_t) sent;
            connection->last_active = time(NULL);
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        return -1;
    }
    while (connection->cache_serve_body_sent
           < connection->cache_serve_body_length) {
        sent = magnus_socket_write(connection,
            connection->cache_serve_body + connection->cache_serve_body_sent,
            connection->cache_serve_body_length
                - connection->cache_serve_body_sent);
        if (sent > 0) {
            connection->cache_serve_body_sent += (size_t) sent;
            magnus_bytes_sent += (uint64_t) sent;
            connection->last_active = time(NULL);
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
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
    free(connection->compressed_body);
    connection->compressed_body = NULL;
    connection->compressed_body_length = 0;
    connection->compressed_body_sent = 0;
    free(connection->cache_serve_headers);
    connection->cache_serve_headers = NULL;
    connection->cache_serve_headers_length = 0;
    connection->cache_serve_headers_sent = 0;
    free(connection->cache_serve_body);
    connection->cache_serve_body = NULL;
    connection->cache_serve_body_length = 0;
    connection->cache_serve_body_sent = 0;
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
        connection->raw_peer_address = peer_address.sin_addr;
        connection->admin_only = admin;
        /* Real IP (roadmap 2b): the PROXY-protocol peek in
         * magnus_proxy_proto_check() only ever runs for a connection from
         * a configured, trusted proxy -- trust is always decided against
         * this connection's true, direct TCP peer (raw_peer_address),
         * never against client_address, since client_address is exactly
         * what a later header/preamble resolution overwrites and trusting
         * it here would let one hop's spoofed value forge trust for the
         * next. Deciding it once, right here at accept time, makes every
         * other connection (untrusted peer, or the feature simply unused)
         * a zero-cost no-op: proxy_proto_done is already true before the
         * dispatch loop ever sees this connection. Never applies to the
         * admin listener, which has no IPv4 peer address at all. */
        connection->proxy_proto_done = admin
            || !magnus_realip_is_trusted(magnus_trusted_proxies,
                                         magnus_trusted_proxy_count,
                                         connection->raw_peer_address);
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

    /* HTTP/2 proxy dispatch (1e-2) and gRPC dispatch (2c-1..2c-4, pooled
     * since 2c-5): the same connect/read timeout budgets as the HTTP/1.1
     * sweep above, but there is no equivalent of magnus_connections[]'s
     * single set of proxy_* fields to check here -- one h2 connection can
     * have many streams each proxying (or relaying gRPC) concurrently, so
     * every open stream on every h2-active connection needs its own
     * check. A gRPC stream carrying a client-supplied grpc-timeout
     * (roadmap 2c-3, grpc_deadline_ms != 0) is bounded by that absolute
     * deadline instead -- entirely replacing the default connect/read
     * budget for that one stream, not added on top of it, since the
     * client has already told us exactly how long the *whole* RPC may
     * take.
     *
     * Pooling (2c-5): a gRPC stream's own connect-timeout is no longer
     * checked here at all -- once attached, a stream is either riding an
     * already-connected pooled connection (nothing to time out) or a
     * still-connecting *new* one, and a connect timeout on that new
     * connection can affect several streams that raced to attach to it
     * at once, which is unsafe to react to per-stream in this loop (the
     * first reaction would close the connection, leaving every later
     * stream in this same loop iteration pointing at a freed one) -- see
     * magnus_grpc_pool_expire()'s own comment, called once per second
     * alongside this function instead. Only the per-stream read/
     * inactivity timeout (once connected) and the deadline check above
     * remain here, both of which only ever affect the *one* stream being
     * checked. */
    for (fd = 0; fd < MAGNUS_MAX_FDS; fd++) {
        magnus_connection_t *connection = magnus_connections[fd];
        struct magnus_h2_stream *stream;
        bool push_needed = false;
        uint64_t now_ms = 0;
        if (connection == NULL || !connection->h2_active) continue;
        for (stream = connection->h2_streams; stream != NULL;
             stream = stream->next) {
            if (stream->is_grpc && stream->grpc_conn != NULL
                && stream->grpc_deadline_ms != 0) {
                if (now_ms == 0) now_ms = magnus_now_ms();
                if (now_ms < stream->grpc_deadline_ms) continue;
                magnus_h2_grpc_fail_or_abort(connection, stream, "4",
                                             "deadline exceeded");
                push_needed = true;
                continue;
            }
            if (stream->is_grpc && stream->grpc_conn != NULL) {
                if (!stream->grpc_conn->connected
                    || now - stream->last_activity
                           < MAGNUS_PROXY_READ_TIMEOUT_SECONDS) {
                    continue;
                }
                magnus_h2_grpc_fail_or_abort(connection, stream, "4",
                                             "gRPC upstream timed out");
                push_needed = true;
                continue;
            }
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

/* Active health checking (roadmap 2f): independent of live traffic,
 * periodically probes each cluster endpoint and feeds the outcome into
 * the same magnus_cluster_result() passive-health state that real proxy
 * traffic feeds, so an endpoint can be found (and recover) even while it
 * is receiving no requests at all. Two modes: the `upstream` cluster gets
 * a real HTTP/1.1 GET against magnus_health_check_path, success iff the
 * response status equals magnus_health_check_expected_status -- a
 * backend that accepts connections but returns 500s on everything is
 * caught, which a bare connect() never could. The `grpc_upstream`
 * cluster stays TCP-connect-only: a real gRPC server is typically
 * HTTP/2-only, and speaking a raw HTTP/1.1 request line into that socket
 * would just get every probe rejected by a perfectly healthy backend --
 * a false-negative regression, not real coverage. Still real coverage
 * over the pre-2f state, which ran no active probe against this cluster
 * at all. Both modes share one parameterized state machine below,
 * dispatched twice (once per cluster) from magnus_health_tick(). */

static void
magnus_health_close_probe(int epoll_fd, magnus_health_probe_t *probes,
                          int *owner, size_t index)
{
    int fd = probes[index].fd;
    if (fd < 0) return;
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    owner[fd] = 0;
    close(fd);
    probes[index].fd = -1;
}

static void
magnus_health_fail(int epoll_fd, magnus_cluster_t *cluster,
                   magnus_health_probe_t *probes, int *owner, size_t index)
{
    magnus_cluster_result(cluster, index, false, magnus_now_ms());
    magnus_health_close_probe(epoll_fd, probes, owner, index);
}

static void
magnus_health_succeed(int epoll_fd, magnus_cluster_t *cluster,
                      magnus_health_probe_t *probes, int *owner, size_t index)
{
    magnus_cluster_result(cluster, index, true, magnus_now_ms());
    magnus_health_close_probe(epoll_fd, probes, owner, index);
}

static void
magnus_health_rearm(int epoll_fd, int fd, uint32_t events)
{
    struct epoll_event event = { .events = events, .data.fd = fd };
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &event);
}

/* Extracts the status code from as much of an HTTP/1.x response as has
 * been buffered so far. Returns false (need more bytes, or truly
 * malformed once the caller's buffer is full) until at least one byte
 * past a well-formed 3-digit status code has arrived -- deliberately not
 * requiring the full status line, since that byte alone is enough to
 * know the 3 digits were not cut short by the buffer's own edge. Not a
 * general HTTP parser: this is a liveness probe reading its own
 * configured backend, not untrusted input, so "reasonably correct" is
 * the bar, not exploit-proof. */
static bool
magnus_health_parse_status(const char *response, size_t length,
                           unsigned *out_status)
{
    const char *limit = response + length;
    const char *space;
    const char *digits;
    const char *cursor;
    unsigned long status;
    char *end;

    if (length < 12 || strncmp(response, "HTTP/1.", 7) != 0) return false;
    space = memchr(response, ' ', length);
    if (space == NULL) return false;
    digits = space + 1;
    cursor = digits;
    while (cursor < limit && isdigit((unsigned char) *cursor)) cursor++;
    if ((size_t) (cursor - digits) != 3 || cursor >= limit) return false;
    status = strtoul(digits, &end, 10);
    if (end != cursor) return false;
    *out_status = (unsigned) status;
    return true;
}

/* Drives one probe forward as far as it can go without blocking, from
 * whatever stage it is currently in. Called both right after a
 * synchronous connect() (typical for loopback/LAN targets) and from
 * every subsequent epoll event for that fd -- a probe that completes a
 * whole stage without ever returning EAGAIN (the common case for a tiny
 * request/response against a healthy local backend) falls straight
 * through every remaining stage in one call, exactly like the pre-2f
 * TCP-only probe already resolved synchronously in the common case. */
static void
magnus_health_advance(int epoll_fd, magnus_cluster_t *cluster,
                      magnus_health_probe_t *probes, int *owner,
                      size_t index, bool http_mode)
{
    magnus_health_probe_t *probe = &probes[index];
    int fd = probe->fd;

    if (probe->stage == MAGNUS_HEALTH_PROBE_CONNECTING) {
        if (!http_mode) {
            magnus_health_succeed(epoll_fd, cluster, probes, owner, index);
            return;
        }
        probe->stage = MAGNUS_HEALTH_PROBE_SENDING;
        magnus_health_rearm(epoll_fd, fd, EPOLLOUT | EPOLLRDHUP);
    }
    if (probe->stage == MAGNUS_HEALTH_PROBE_SENDING) {
        while (probe->request_sent < probe->request_length) {
            ssize_t written = write(fd, probe->request + probe->request_sent,
                                    probe->request_length
                                    - probe->request_sent);
            if (written < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return;
                magnus_health_fail(epoll_fd, cluster, probes, owner, index);
                return;
            }
            probe->request_sent += (size_t) written;
        }
        probe->stage = MAGNUS_HEALTH_PROBE_READING;
        magnus_health_rearm(epoll_fd, fd, EPOLLIN | EPOLLRDHUP);
    }
    if (probe->stage == MAGNUS_HEALTH_PROBE_READING) {
        for (;;) {
            ssize_t received;
            unsigned status;
            if (probe->response_length >= sizeof(probe->response)) {
                magnus_health_fail(epoll_fd, cluster, probes, owner, index);
                return;
            }
            received = read(fd, probe->response + probe->response_length,
                            sizeof(probe->response) - probe->response_length);
            if (received < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return;
                magnus_health_fail(epoll_fd, cluster, probes, owner, index);
                return;
            }
            if (received == 0) {
                magnus_health_fail(epoll_fd, cluster, probes, owner, index);
                return;
            }
            probe->response_length += (size_t) received;
            if (magnus_health_parse_status(probe->response,
                                           probe->response_length, &status)) {
                if (status == magnus_health_check_expected_status) {
                    magnus_health_succeed(epoll_fd, cluster, probes, owner,
                                          index);
                } else {
                    magnus_health_fail(epoll_fd, cluster, probes, owner,
                                       index);
                }
                return;
            }
        }
    }
}

static void
magnus_health_start_probe(int epoll_fd, magnus_cluster_t *cluster,
                          magnus_health_probe_t *probes, int *owner,
                          bool (*sockaddr_fn)(size_t, struct sockaddr_in *),
                          size_t index, time_t now, bool http_mode)
{
    struct sockaddr_in address;
    struct epoll_event event;
    magnus_health_probe_t *probe = &probes[index];
    int fd;
    int result;

    if (!sockaddr_fn(index, &address)) return;
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0 || fd >= MAGNUS_MAX_FDS) {
        if (fd >= 0) close(fd);
        return;
    }
    result = connect(fd, (struct sockaddr *) &address, sizeof(address));
    if (result < 0 && errno != EINPROGRESS) {
        close(fd);
        magnus_cluster_result(cluster, index, false, magnus_now_ms());
        return;
    }
    event = (struct epoll_event) { .events = EPOLLOUT | EPOLLRDHUP,
                                   .data.fd = fd };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        close(fd);
        return;
    }
    probe->fd = fd;
    probe->started = now;
    probe->stage = MAGNUS_HEALTH_PROBE_CONNECTING;
    probe->request_sent = 0;
    probe->response_length = 0;
    probe->request_length = 0;
    if (http_mode) {
        /* Host: the endpoint's own literal IPv4 address -- a cluster
         * endpoint carries no separate virtual-host name to probe with,
         * same as the plain TCP-connect probe never had one either. */
        int length = snprintf(probe->request, sizeof(probe->request),
            "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: magnus-health-check/1\r\n"
            "Connection: close\r\n\r\n",
            magnus_health_check_path, cluster->endpoints[index].address);
        if (length > 0 && (size_t) length < sizeof(probe->request)) {
            probe->request_length = (size_t) length;
        }
    }
    owner[fd] = (int) (index + 1);
    if (result == 0) {
        /* connected synchronously: resolve as far as possible immediately
         * instead of waiting on an epoll event that a level-triggered,
         * already-satisfied condition may not re-deliver. */
        magnus_health_advance(epoll_fd, cluster, probes, owner, index,
                              http_mode);
    }
}

static void
magnus_health_handle_probe(int epoll_fd, magnus_cluster_t *cluster,
                           magnus_health_probe_t *probes, int *owner,
                           size_t index, uint32_t flags, bool http_mode)
{
    magnus_health_probe_t *probe = &probes[index];
    if (probe->fd < 0) return;
    if (probe->stage == MAGNUS_HEALTH_PROBE_CONNECTING) {
        bool success = false;
        if ((flags & (EPOLLERR | EPOLLHUP)) == 0) {
            int error = 0;
            socklen_t length = sizeof(error);
            success = getsockopt(probe->fd, SOL_SOCKET, SO_ERROR, &error,
                                 &length) == 0 && error == 0;
        }
        if (!success) {
            magnus_health_fail(epoll_fd, cluster, probes, owner, index);
            return;
        }
    }
    magnus_health_advance(epoll_fd, cluster, probes, owner, index, http_mode);
}

static void
magnus_health_tick_cluster(int epoll_fd, magnus_cluster_t *cluster,
                           magnus_health_probe_t *probes, time_t *last_probe,
                           int *owner,
                           bool (*sockaddr_fn)(size_t, struct sockaddr_in *),
                           time_t now, bool http_mode)
{
    size_t index;
    for (index = 0; index < cluster->count; index++) {
        if (probes[index].fd >= 0) {
            if ((unsigned) (now - probes[index].started)
                >= magnus_health_check_timeout_seconds) {
                magnus_health_fail(epoll_fd, cluster, probes, owner, index);
            }
            continue;
        }
        if ((unsigned) (now - last_probe[index])
            >= magnus_health_check_interval_seconds) {
            last_probe[index] = now;
            magnus_health_start_probe(epoll_fd, cluster, probes, owner,
                                      sockaddr_fn, index, now, http_mode);
        }
    }
}

/* Dispatched once per cluster rather than unified into one loop over "all
 * endpoints everywhere": the two clusters have independent endpoint
 * counts/indices, independent owner maps (a raw fd number means a
 * different endpoint depending which cluster it belongs to), and -- the
 * actual reason a shared loop would not simplify anything -- different
 * probe modes (see the block comment above magnus_health_close_probe()). */
static void
magnus_health_tick(int epoll_fd, time_t now)
{
    magnus_health_tick_cluster(epoll_fd, &magnus_cluster, magnus_health_probes,
                               magnus_health_last_probe,
                               magnus_health_probe_owner,
                               magnus_endpoint_sockaddr, now, true);
    magnus_health_tick_cluster(epoll_fd, &magnus_grpc_cluster,
                               magnus_grpc_health_probes,
                               magnus_grpc_health_last_probe,
                               magnus_grpc_health_probe_owner,
                               magnus_grpc_endpoint_sockaddr, now, false);
    /* roadmap 3a: TCP-connect only, same reasoning as the gRPC cluster --
     * what is actually flowing over a stream connection is unknown at
     * this layer by design, so an HTTP-level probe would be meaningless
     * (and could easily misfire against a non-HTTP protocol). */
    magnus_health_tick_cluster(epoll_fd, &magnus_stream_cluster,
                               magnus_stream_health_probes,
                               magnus_stream_health_last_probe,
                               magnus_stream_health_probe_owner,
                               magnus_stream_endpoint_sockaddr, now, false);
}

/* L4 TCP passthrough (roadmap 3a), extended with TLS passthrough / SNI
 * routing (3b): a raw bidirectional byte relay between a client fd and
 * the upstream fd it was matched to -- no HTTP parsing, no framing
 * awareness of any kind, and (3b) no TLS termination either, just enough
 * of a peek at the ClientHello to decide which cluster's endpoint to
 * relay to. Everything below mirrors established patterns elsewhere in
 * this file (the L7 proxy's own buffered-write backpressure, the
 * active-health probe's own epoll-interest rearming) rather than
 * inventing new ones. */

/* First pattern match wins, config-file order, same evaluation order
 * `route` already uses for L7. Returns NULL (caller falls back to
 * magnus_stream_cluster) when SNI routing is disabled entirely
 * (magnus_sni_cluster_count == 0, the common case for a deployment that
 * never configured stream_sni_route) or when `hostname` matches none of
 * the configured patterns. */
static magnus_cluster_t *
magnus_sni_select_cluster(const char *hostname)
{
    for (size_t index = 0; index < magnus_sni_cluster_count; index++) {
        if (magnus_sni_pattern_matches(magnus_sni_clusters[index].pattern,
                                       hostname))
            return &magnus_sni_clusters[index].cluster;
    }
    return NULL;
}

/* Generic sockaddr resolver taking an explicit cluster, unlike
 * magnus_endpoint_sockaddr()/magnus_grpc_endpoint_sockaddr()/
 * magnus_stream_endpoint_sockaddr() (each implicitly bound to one fixed
 * global cluster, for magnus_health_tick()'s own fixed-signature probe
 * callback) -- needed here because a stream connection's eventual
 * cluster is only known at connect time, picked fresh per connection
 * from either magnus_stream_cluster or one of magnus_sni_clusters[]. */
static bool
magnus_cluster_endpoint_sockaddr(magnus_cluster_t *cluster, size_t index,
                                 struct sockaddr_in *out)
{
    if (index >= cluster->count) return false;
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t) cluster->endpoints[index].port);
    return inet_pton(AF_INET, cluster->endpoints[index].address,
                     &out->sin_addr) == 1;
}

static bool
magnus_stream_pipe_done(const magnus_stream_pipe_t *pipe)
{
    return pipe->source_eof && pipe->length == pipe->sent;
}

/* Drains whatever is already buffered in `pipe` to `dest_fd`, then (once
 * the buffer is empty and the source has not already EOF'd) reads more
 * from `source_fd` and writes it straight out, looping as long as both
 * succeed fully -- bounded naturally by one of the two eventually
 * returning EAGAIN. Never grows `pipe->buffer` past its fixed
 * MAGNUS_PROXY_BUFFER capacity: a destination that cannot keep up simply
 * leaves bytes buffered-but-unsent, and magnus_stream_rearm() (called by
 * the caller after this returns) stops re-reading the source side until
 * that drains -- the same backpressure discipline magnus_proxy_flush()
 * already applies to the L7 proxy path, just without any HTTP framing to
 * track alongside it. Returns false only on a real I/O error (never on a
 * clean EOF or a destination simply being unwritable right now), which
 * the caller treats as fatal for the whole connection -- a broken pipe on
 * either leg of an L4 tunnel cannot be partially recovered from the way a
 * completed HTTP response can. */
static bool
magnus_stream_pump(magnus_stream_pipe_t *pipe, int source_fd, int dest_fd,
                   uint64_t *byte_counter)
{
    while (pipe->sent < pipe->length) {
        ssize_t written = write(dest_fd, pipe->buffer + pipe->sent,
                                pipe->length - pipe->sent);
        if (written < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
            return false;
        }
        *byte_counter += (uint64_t) written;
        pipe->sent += (size_t) written;
    }
    pipe->length = 0;
    pipe->sent = 0;
    if (pipe->source_eof) {
        if (!pipe->dest_shutdown) {
            shutdown(dest_fd, SHUT_WR);
            pipe->dest_shutdown = true;
        }
        return true;
    }
    for (;;) {
        ssize_t received = read(source_fd, pipe->buffer, sizeof(pipe->buffer));
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
            return false;
        }
        if (received == 0) {
            pipe->source_eof = true;
            shutdown(dest_fd, SHUT_WR);
            pipe->dest_shutdown = true;
            return true;
        }
        pipe->length = (size_t) received;
        pipe->sent = 0;
        while (pipe->sent < pipe->length) {
            ssize_t written = write(dest_fd, pipe->buffer + pipe->sent,
                                    pipe->length - pipe->sent);
            if (written < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
                return false;
            }
            *byte_counter += (uint64_t) written;
            pipe->sent += (size_t) written;
        }
        pipe->length = 0;
        pipe->sent = 0;
    }
}

/* Recomputes and applies both fds' epoll interest from current pipe state,
 * unconditionally (an extra epoll_ctl MOD when nothing actually changed
 * is cheap and simple to reason about -- the same trade-off
 * magnus_health_rearm() already makes). While still MAGNUS_STREAM_PEEKING
 * there is no upstream_fd yet, so only the client fd (plain EPOLLIN,
 * looking for more ClientHello bytes) is touched at all. Once connected,
 * EPOLLIN on a side is only asked for while the pipe it feeds has room
 * (i.e. is fully flushed) and its source has not EOF'd; EPOLLOUT is only
 * asked for while there is something buffered to flush toward it, the
 * connect() itself is still outstanding, or (PROXY protocol emission) a
 * built preamble has not finished flushing to the upstream yet. */
static void
magnus_stream_rearm(int epoll_fd, magnus_stream_conn_t *conn)
{
    struct epoll_event event;
    uint32_t client_events = EPOLLRDHUP;
    uint32_t upstream_events = EPOLLRDHUP;

    if (conn->stage == MAGNUS_STREAM_PEEKING) {
        event = (struct epoll_event) { .events = EPOLLIN | EPOLLRDHUP,
                                       .data.fd = conn->fd };
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &event);
        return;
    }

    if (!conn->c2u.source_eof && conn->c2u.length == conn->c2u.sent)
        client_events |= EPOLLIN;
    if (conn->u2c.length > conn->u2c.sent)
        client_events |= EPOLLOUT;
    if (!conn->u2c.source_eof && conn->u2c.length == conn->u2c.sent)
        upstream_events |= EPOLLIN;
    if (conn->c2u.length > conn->c2u.sent
        || conn->stage == MAGNUS_STREAM_CONNECTING
        || conn->proxy_protocol_header_sent < conn->proxy_protocol_header_length)
        upstream_events |= EPOLLOUT;

    event = (struct epoll_event) { .events = client_events, .data.fd = conn->fd };
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &event);
    event = (struct epoll_event) { .events = upstream_events,
                                   .data.fd = conn->upstream_fd };
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->upstream_fd, &event);
}

static void
magnus_stream_close(int epoll_fd, magnus_stream_conn_t *conn)
{
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL);
    magnus_stream_owner[conn->fd] = NULL;
    close(conn->fd);
    /* upstream_fd is still -1 for a connection that never made it past
     * MAGNUS_STREAM_PEEKING (client closed, or the peek buffer filled/
     * timed out and even the default-cluster fallback connect() itself
     * failed) -- guarded the same way magnus_close_connection() already
     * guards its own upstream_fd, for the same reason (calloc() zero-
     * initializes this field to 0, a live fd, not -1). */
    if (conn->upstream_fd >= 0) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn->upstream_fd, NULL);
        magnus_stream_upstream_owner[conn->upstream_fd] = NULL;
        close(conn->upstream_fd);
    }
    if (conn->endpoint_counted) {
        magnus_cluster_endpoint_end(conn->cluster, conn->endpoint_index);
        conn->endpoint_counted = false;
    }
    if (magnus_stream_connections_active > 0) magnus_stream_connections_active--;
    free(conn);
}

/* Opens a non-blocking connect() to endpoint `selected` of `cluster` for
 * a connection that has already been accepted (conn->fd already
 * registered with epoll) -- shared by magnus_stream_accept()'s own
 * immediate-connect path (SNI routing disabled) and
 * magnus_stream_peek_decide() below (SNI routing enabled, decision just
 * made). Registers the new upstream fd with epoll and transitions
 * conn->stage to MAGNUS_STREAM_CONNECTING or (synchronous connect,
 * typical for loopback/LAN targets) straight to MAGNUS_STREAM_RELAYING,
 * resolving the circuit-breaker result immediately in that case, same as
 * every other synchronous-completion path in this file. Only ever
 * cleans up what it itself opened on failure -- the caller is
 * responsible for tearing down the rest of `conn`. */
static bool
magnus_stream_connect(int epoll_fd, magnus_stream_conn_t *conn,
                      magnus_cluster_t *cluster, size_t selected)
{
    struct sockaddr_in upstream_address;
    int upstream_fd;
    int connect_result;
    int one = 1;
    struct epoll_event event;

    if (!magnus_cluster_endpoint_sockaddr(cluster, selected, &upstream_address))
        return false;
    upstream_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (upstream_fd < 0 || upstream_fd >= MAGNUS_MAX_FDS) {
        if (upstream_fd >= 0) close(upstream_fd);
        return false;
    }
    connect_result = connect(upstream_fd, (struct sockaddr *) &upstream_address,
                             sizeof(upstream_address));
    if (connect_result < 0 && errno != EINPROGRESS) {
        magnus_cluster_result(cluster, selected, false, magnus_now_ms());
        close(upstream_fd);
        return false;
    }
    (void) setsockopt(upstream_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    event = (struct epoll_event) {
        .events = (uint32_t) (connect_result != 0 ? EPOLLOUT : EPOLLIN)
                  | EPOLLRDHUP,
        .data.fd = upstream_fd
    };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, upstream_fd, &event) < 0) {
        close(upstream_fd);
        return false;
    }
    conn->upstream_fd = upstream_fd;
    conn->cluster = cluster;
    conn->endpoint_index = selected;
    conn->connect_started = time(NULL);
    magnus_cluster_endpoint_begin(cluster, selected);
    conn->endpoint_counted = true;
    magnus_stream_upstream_owner[upstream_fd] = conn;
    conn->stage = connect_result != 0 ? MAGNUS_STREAM_CONNECTING
                                       : MAGNUS_STREAM_RELAYING;
    /* Built unconditionally here (pure computation, no I/O) regardless of
     * whether the connect() itself resolved synchronously or not -- `dst`
     * is this endpoint, exactly what was just connect()ed to, so it is
     * already fully known now. Actually flushing it to upstream_fd is
     * left to magnus_stream_after_connect()/magnus_stream_service(),
     * since it must never precede a still-outstanding connect(). A no-op
     * (proxy_protocol_header_length stays 0) whenever
     * magnus_stream_proxy_protocol_mode is MAGNUS_PROXY_PROTOCOL_OFF. */
    conn->proxy_protocol_header_length = magnus_proxy_proto_build(
        magnus_stream_proxy_protocol_mode, conn->peer_address,
        ntohs(conn->peer_port), upstream_address.sin_addr,
        ntohs(upstream_address.sin_port),
        (unsigned char *) conn->proxy_protocol_header,
        sizeof(conn->proxy_protocol_header));
    conn->proxy_protocol_header_sent = 0;
    if (connect_result == 0) {
        magnus_cluster_result(cluster, selected, true, magnus_now_ms());
    }
    return true;
}

/* Flushes conn->proxy_protocol_header[proxy_protocol_header_sent..length)
 * to conn->upstream_fd, looping while each write() succeeds fully -- the
 * same EAGAIN-vs-fatal distinction magnus_stream_pump() itself makes. A
 * no-op returning true immediately whenever proxy_protocol_header_length
 * is 0 (magnus_stream_proxy_protocol_mode is MAGNUS_PROXY_PROTOCOL_OFF,
 * the default), so every caller can call this unconditionally without
 * first checking whether PROXY protocol emission is even enabled.
 * Deliberately writes from a small fixed buffer built once by
 * magnus_stream_connect(), not conn->c2u.buffer -- see
 * magnus_stream_conn_t's own comment on why this stays a separate buffer
 * rather than being prepended into the ordinary relay buffer. */
static bool
magnus_stream_flush_proxy_protocol(magnus_stream_conn_t *conn)
{
    while (conn->proxy_protocol_header_sent < conn->proxy_protocol_header_length) {
        ssize_t written = write(conn->upstream_fd,
            conn->proxy_protocol_header + conn->proxy_protocol_header_sent,
            conn->proxy_protocol_header_length - conn->proxy_protocol_header_sent);
        if (written < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
            return false;
        }
        conn->proxy_protocol_header_sent += (size_t) written;
    }
    return true;
}

/* Shared follow-up for every caller of magnus_stream_connect() once it
 * returns true, folding together the two things that need to happen as
 * early as possible when a stream connection resolves synchronously (the
 * common case for loopback/LAN backends) -- flushing any PROXY protocol
 * preamble ahead of relay traffic, and pumping whatever ClientHello
 * prefix magnus_stream_advance_peek() already buffered into conn->c2u --
 * rather than each call site re-deriving the same ordering by hand. Still
 * MAGNUS_STREAM_CONNECTING (async connect) is a correct, harmless no-op
 * here: there is nothing to flush or pump yet, and
 * magnus_stream_service()'s own MAGNUS_STREAM_CONNECTING-confirmation
 * branch does the equivalent work once the connect() itself resolves.
 * Always finishes with magnus_stream_rearm() so epoll interest reflects
 * whatever state was actually reached. */
static void
magnus_stream_after_connect(int epoll_fd, magnus_stream_conn_t *conn)
{
    if (conn->stage == MAGNUS_STREAM_RELAYING) {
        if (!magnus_stream_flush_proxy_protocol(conn)) {
            magnus_stream_close(epoll_fd, conn);
            return;
        }
        if (conn->proxy_protocol_header_sent == conn->proxy_protocol_header_length
            && conn->c2u.length > 0) {
            if (!magnus_stream_pump(&conn->c2u, conn->fd, conn->upstream_fd,
                                    &magnus_stream_bytes_c2u_total)) {
                magnus_stream_close(epoll_fd, conn);
                return;
            }
        }
    }
    magnus_stream_rearm(epoll_fd, conn);
}

/* Finalizes a MAGNUS_STREAM_PEEKING decision: `cluster` is the SNI
 * cluster a matched ClientHello picked, or NULL for every other outcome
 * (no stream_sni_route configured at all, a parsed-but-unmatched
 * hostname, a definitively-not-TLS or malformed ClientHello, the peek
 * buffer filling up without ever resolving, the client closing before
 * sending enough bytes to decide, or a peek timeout) -- all of which
 * fall back to the plain, always-present magnus_stream_cluster, exactly
 * the fallback behavior this roadmap increment was scoped to have.
 * Whatever bytes already sit in conn->c2u.buffer (the real ClientHello
 * prefix, peeked but never consumed) are left in place;
 * magnus_stream_connect()'s own synchronous-connect case flushes them
 * immediately below when possible, same as any other synchronous-
 * completion path in this file -- otherwise the ordinary pump on the
 * first upstream-writable event picks them up. */
static void
magnus_stream_peek_decide(int epoll_fd, magnus_stream_conn_t *conn,
                          magnus_cluster_t *cluster)
{
    int selected;

    if (cluster == NULL) cluster = &magnus_stream_cluster;
    selected = magnus_cluster_select(cluster, magnus_now_ms(), NULL,
                                     conn->peer_address);
    if (selected < 0
        || !magnus_stream_connect(epoll_fd, conn, cluster, (size_t) selected)) {
        magnus_stream_close(epoll_fd, conn);
        return;
    }
    magnus_stream_after_connect(epoll_fd, conn);
}

/* Reads more of the client's initial bytes directly into conn->c2u.buffer
 * (see magnus_stream_pipe_t's own comment on why that buffer specifically,
 * not a separate one) and attempts magnus_sni_extract() against what has
 * accumulated -- called both right after accept() (in case the
 * ClientHello arrived as part of the client's very first flight of
 * bytes, resolving synchronously) and from every subsequent EPOLLIN event
 * on the client fd while still MAGNUS_STREAM_PEEKING. Every exit funnels
 * through magnus_stream_peek_decide() above once an outcome is known;
 * MAGNUS_SNI_INCOMPLETE alone loops back to read further immediately
 * rather than waiting for another epoll event, matching this file's own
 * "resolve as far as possible synchronously" convention. */
static void
magnus_stream_advance_peek(int epoll_fd, magnus_stream_conn_t *conn)
{
    for (;;) {
        ssize_t received;
        char hostname[MAGNUS_SNI_HOSTNAME_MAX];
        magnus_sni_result_t result;

        if (conn->c2u.length >= sizeof(conn->c2u.buffer)) {
            magnus_stream_peek_decide(epoll_fd, conn, NULL);
            return;
        }
        received = read(conn->fd, conn->c2u.buffer + conn->c2u.length,
                        sizeof(conn->c2u.buffer) - conn->c2u.length);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                magnus_stream_rearm(epoll_fd, conn);
                return;
            }
            magnus_stream_close(epoll_fd, conn);
            return;
        }
        if (received == 0) {
            /* Client closed before ever sending a resolvable ClientHello.
             * Falls back like any other unresolved peek rather than being
             * special-cased -- the default cluster's own connect (or the
             * pump once connected, finding the client side already at
             * EOF) unwinds this the normal way. */
            magnus_stream_peek_decide(epoll_fd, conn, NULL);
            return;
        }
        conn->c2u.length += (size_t) received;

        result = magnus_sni_extract((const unsigned char *) conn->c2u.buffer,
                                    conn->c2u.length, hostname, sizeof(hostname));
        if (result == MAGNUS_SNI_INCOMPLETE) continue;
        magnus_stream_peek_decide(epoll_fd, conn,
            result == MAGNUS_SNI_OK ? magnus_sni_select_cluster(hostname) : NULL);
        return;
    }
}

/* Called for every epoll event on either of `conn`'s two fds -- `fd`/
 * `flags` identify which one actually fired and with what, so a
 * connect() failure or an EPOLLERR is attributed to the right side. Once
 * connecting resolves (or immediately, if this is any event on the
 * already-connected client fd), both pipes are pumped unconditionally
 * regardless of which fd triggered the call: cheap when there is nothing
 * to do (magnus_stream_pump() returns almost immediately on EAGAIN), and
 * avoids having to reason precisely about which flag combination implies
 * which direction needs servicing. Writing to (or reading from)
 * conn->upstream_fd while still MAGNUS_STREAM_CONNECTING is safe on
 * Linux -- both simply return EAGAIN/EWOULDBLOCK until the connection
 * actually completes, which magnus_stream_pump() already treats as
 * "nothing to do yet". */
static void
magnus_stream_service(int epoll_fd, magnus_stream_conn_t *conn, int fd,
                      uint32_t flags)
{
    conn->last_active = time(NULL);
    if (conn->stage == MAGNUS_STREAM_PEEKING) {
        if ((flags & EPOLLERR) != 0) {
            magnus_stream_close(epoll_fd, conn);
            return;
        }
        magnus_stream_advance_peek(epoll_fd, conn);
        return;
    }
    if (conn->stage == MAGNUS_STREAM_CONNECTING && fd == conn->upstream_fd) {
        bool success = false;
        if ((flags & (EPOLLERR | EPOLLHUP)) == 0) {
            int error = 0;
            socklen_t length = sizeof(error);
            success = getsockopt(conn->upstream_fd, SOL_SOCKET, SO_ERROR,
                                 &error, &length) == 0 && error == 0;
        }
        magnus_cluster_result(conn->cluster, conn->endpoint_index, success,
                              magnus_now_ms());
        if (!success) {
            magnus_stream_close(epoll_fd, conn);
            return;
        }
        conn->stage = MAGNUS_STREAM_RELAYING;
    }
    if ((flags & EPOLLERR) != 0 || !magnus_stream_flush_proxy_protocol(conn)) {
        magnus_stream_close(epoll_fd, conn);
        return;
    }
    /* A PROXY protocol header that could not fully flush synchronously
     * (magnus_stream_after_connect(), or right above) must finish before
     * a single byte of ordinary relay traffic goes out -- wait for the
     * next upstream-writable event (magnus_stream_rearm() already asks
     * for EPOLLOUT while this is true) rather than falling through to the
     * pumps below. */
    if (conn->proxy_protocol_header_sent < conn->proxy_protocol_header_length) {
        magnus_stream_rearm(epoll_fd, conn);
        return;
    }
    if (!magnus_stream_pump(&conn->c2u, conn->fd, conn->upstream_fd,
                            &magnus_stream_bytes_c2u_total)
        || !magnus_stream_pump(&conn->u2c, conn->upstream_fd, conn->fd,
                               &magnus_stream_bytes_u2c_total)) {
        magnus_stream_close(epoll_fd, conn);
        return;
    }
    if (magnus_stream_pipe_done(&conn->c2u) && magnus_stream_pipe_done(&conn->u2c)) {
        magnus_stream_close(epoll_fd, conn);
        return;
    }
    magnus_stream_rearm(epoll_fd, conn);
}

/* Accepts every currently-pending connection on magnus_stream_listener.
 * With no stream_sni_route configured at all (the common case), an
 * endpoint of magnus_stream_cluster is picked and connected immediately,
 * exactly as roadmap 3a always did -- zero peeking overhead for a
 * deployment that never asked for SNI routing. Otherwise the connection
 * starts MAGNUS_STREAM_PEEKING and magnus_stream_advance_peek() takes it
 * from there. Unlike the L7 proxy path there is no retry budget: an L4
 * tunnel has no "request" to safely retry once any bytes have moved, and
 * a connect()-stage failure is reported the same way a real client would
 * see any other closed door -- an immediately-reset connection. */
static void
magnus_stream_accept(int epoll_fd)
{
    for (;;) {
        struct sockaddr_in peer_address = {0};
        socklen_t peer_length = sizeof(peer_address);
        int client = accept4(magnus_stream_listener,
                             (struct sockaddr *) &peer_address, &peer_length,
                             SOCK_NONBLOCK | SOCK_CLOEXEC);
        magnus_stream_conn_t *conn;
        int one = 1;
        struct epoll_event event;

        if (client < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            return;
        }
        if (client >= MAGNUS_MAX_FDS) {
            close(client);
            continue;
        }
        conn = calloc(1, sizeof(*conn));
        if (conn == NULL) {
            close(client);
            continue;
        }
        conn->fd = client;
        conn->upstream_fd = -1;
        conn->peer_address = peer_address.sin_addr;
        conn->peer_port = peer_address.sin_port;
        conn->last_active = time(NULL);
        conn->peek_started = conn->last_active;
        (void) setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        event = (struct epoll_event) { .events = EPOLLIN | EPOLLRDHUP,
                                       .data.fd = client };
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client, &event) < 0) {
            close(client);
            free(conn);
            continue;
        }
        magnus_stream_owner[client] = conn;
        magnus_stream_connections_total++;
        magnus_stream_connections_active++;

        if (magnus_sni_cluster_count == 0) {
            int selected = magnus_cluster_select(&magnus_stream_cluster,
                magnus_now_ms(), NULL, conn->peer_address);
            if (selected < 0
                || !magnus_stream_connect(epoll_fd, conn, &magnus_stream_cluster,
                                          (size_t) selected)) {
                magnus_stream_close(epoll_fd, conn);
                continue;
            }
            magnus_stream_after_connect(epoll_fd, conn);
        } else {
            conn->stage = MAGNUS_STREAM_PEEKING;
            magnus_stream_advance_peek(epoll_fd, conn);
        }
    }
}

/* 1Hz sweep companion to magnus_expire_idle(): a stream connection with no
 * bytes flowing in either direction for MAGNUS_IDLE_SECONDS is closed
 * (the same idle budget every other connection type in this file already
 * uses); one still MAGNUS_STREAM_PEEKING past
 * MAGNUS_STREAM_PEEK_TIMEOUT_SECONDS gives up and falls back to the
 * default cluster via magnus_stream_peek_decide() (the same outcome a
 * parsed-but-unmatched or malformed ClientHello already gets, just
 * triggered by a stalled/slow client instead of a parse result); one
 * still MAGNUS_STREAM_CONNECTING past MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS
 * is treated as a connect failure. Walks magnus_stream_owner (keyed by
 * client fd) only, never magnus_stream_upstream_owner -- both point at
 * the same connections, so walking both would visit (and double-close)
 * each one twice. */
static void
magnus_stream_expire_idle(int epoll_fd, time_t now)
{
    for (int fd = 0; fd < MAGNUS_MAX_FDS; fd++) {
        magnus_stream_conn_t *conn = magnus_stream_owner[fd];
        if (conn == NULL) continue;
        if (conn->stage == MAGNUS_STREAM_PEEKING
            && now - conn->peek_started >= MAGNUS_STREAM_PEEK_TIMEOUT_SECONDS) {
            magnus_stream_peek_decide(epoll_fd, conn, NULL);
            continue;
        }
        if (conn->stage == MAGNUS_STREAM_CONNECTING
            && now - conn->connect_started >= MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS) {
            magnus_cluster_result(conn->cluster, conn->endpoint_index, false,
                                  magnus_now_ms());
            magnus_stream_close(epoll_fd, conn);
            continue;
        }
        if (now - conn->last_active > MAGNUS_IDLE_SECONDS) {
            magnus_stream_close(epoll_fd, conn);
        }
    }
}

/* UDP passthrough (roadmap 3d): see magnus_udp_session_t's own comment
 * for the full session-lifecycle design. Linear scan, bounded by
 * magnus_udp_max_sessions -- see magnus_udp_upstream_owner's own comment
 * on why. */
static magnus_udp_session_t *
magnus_udp_find_session(struct in_addr client_addr, in_port_t client_port)
{
    for (size_t index = 0; index < magnus_udp_max_sessions; index++) {
        magnus_udp_session_t *session = &magnus_udp_sessions[index];
        if (session->in_use
            && session->client_addr.s_addr == client_addr.s_addr
            && session->client_port == client_port)
            return session;
    }
    return NULL;
}

static void
magnus_udp_close_session(int epoll_fd, magnus_udp_session_t *session)
{
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, session->upstream_fd, NULL);
    magnus_udp_upstream_owner[session->upstream_fd] = NULL;
    close(session->upstream_fd);
    if (session->endpoint_counted) {
        magnus_cluster_endpoint_end(&magnus_udp_cluster, session->endpoint_index);
        session->endpoint_counted = false;
    }
    session->in_use = false;
    session->upstream_fd = -1;
    if (magnus_udp_session_count > 0) magnus_udp_session_count--;
}

/* Picks an endpoint (magnus_udp_cluster.policy; no cookie-based affinity,
 * same reasoning as the TCP stream cluster -- there is no HTTP-level
 * cookie at this layer either) and opens a fresh connect()ed UDP socket
 * to it for a (source IP, source port) tuple never seen before. Returns
 * NULL (caller drops the triggering packet) if the session cap has
 * already been reached, no endpoint is configured, or the socket/
 * epoll_ctl setup itself fails -- deliberately never blocks waiting for
 * anything, since UDP has no connection handshake to wait on in the
 * first place; the very next packet from the same client tries again
 * from scratch. */
static magnus_udp_session_t *
magnus_udp_create_session(int epoll_fd, struct in_addr client_addr,
                          in_port_t client_port)
{
    struct sockaddr_in upstream_address;
    int upstream_fd;
    int selected;
    magnus_udp_session_t *session = NULL;
    struct epoll_event event;

    if (magnus_udp_session_count >= magnus_udp_max_sessions) return NULL;
    selected = magnus_cluster_select(&magnus_udp_cluster, magnus_now_ms(), NULL,
                                     client_addr);
    if (selected < 0
        || !magnus_cluster_endpoint_sockaddr(&magnus_udp_cluster,
                                             (size_t) selected, &upstream_address))
        return NULL;
    upstream_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (upstream_fd < 0 || upstream_fd >= MAGNUS_MAX_FDS) {
        if (upstream_fd >= 0) close(upstream_fd);
        return NULL;
    }
    /* connect() on a UDP socket never handshakes -- it only fixes the
     * default peer address locally, letting send()/recv() stand in for
     * sendto()/recvfrom() and (the real reason it matters here) giving
     * this session's own reply traffic a distinct fd to arrive on. Its
     * success here says nothing about whether the backend actually
     * exists -- see magnus_udp_session_t's own comment on why this
     * cluster tracks no health signal at all. */
    if (connect(upstream_fd, (struct sockaddr *) &upstream_address,
               sizeof(upstream_address)) < 0) {
        close(upstream_fd);
        return NULL;
    }
    for (size_t index = 0; index < magnus_udp_max_sessions; index++) {
        if (!magnus_udp_sessions[index].in_use) {
            session = &magnus_udp_sessions[index];
            break;
        }
    }
    if (session == NULL) {
        /* Should not happen given the count check above; defensive only. */
        close(upstream_fd);
        return NULL;
    }
    event = (struct epoll_event) { .events = EPOLLIN, .data.fd = upstream_fd };
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, upstream_fd, &event) < 0) {
        close(upstream_fd);
        return NULL;
    }
    session->in_use = true;
    session->client_addr = client_addr;
    session->client_port = client_port;
    session->upstream_fd = upstream_fd;
    session->endpoint_index = (size_t) selected;
    session->last_active = time(NULL);
    magnus_cluster_endpoint_begin(&magnus_udp_cluster, session->endpoint_index);
    session->endpoint_counted = true;
    magnus_udp_upstream_owner[upstream_fd] = session;
    magnus_udp_session_count++;
    magnus_udp_sessions_total++;
    return session;
}

/* The single shared UDP listener becoming readable: one arriving
 * datagram is one client packet, read via recvfrom() (never accept() --
 * UDP has no such concept) so the source (IP, port) tuple is known
 * before anything else happens. An existing session for that tuple gets
 * the packet relayed on its own dedicated backend socket; a new tuple
 * gets a fresh magnus_udp_create_session() attempt, and (cap reached, no
 * endpoint available, or the connect() itself failing) the packet is
 * simply dropped -- UDP itself already offers no delivery guarantee, so
 * a dropped packet here is well within the protocol's own contract, not
 * a magnus-specific failure mode needing a client-visible signal. */
static void
magnus_udp_listener_service(int epoll_fd)
{
    for (;;) {
        char buffer[MAGNUS_UDP_DATAGRAM_MAX];
        struct sockaddr_in client_address;
        socklen_t address_length = sizeof(client_address);
        ssize_t received;
        magnus_udp_session_t *session;

        received = recvfrom(magnus_udp_listener, buffer, sizeof(buffer), 0,
                            (struct sockaddr *) &client_address, &address_length);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            return;
        }
        session = magnus_udp_find_session(client_address.sin_addr,
                                          client_address.sin_port);
        if (session == NULL) {
            session = magnus_udp_create_session(epoll_fd, client_address.sin_addr,
                                                client_address.sin_port);
            if (session == NULL) continue;
        }
        session->last_active = time(NULL);
        if (send(session->upstream_fd, buffer, (size_t) received, 0) >= 0) {
            magnus_udp_bytes_c2u_total += (uint64_t) received;
        }
    }
}

/* A session's own dedicated backend socket becoming readable: relay the
 * reply datagram back to exactly the client that session belongs to
 * (sendto(), since the shared listener socket itself is never
 * connect()ed and has no fixed peer of its own). A hard read error
 * (most notably ECONNREFUSED, which Linux can surface on a connect()ed
 * UDP socket from a matching ICMP port-unreachable -- the one real
 * liveness signal UDP offers at all) tears the session down immediately
 * rather than waiting out the idle timeout, freeing its fd right away;
 * the client's own next packet starts a fresh session (and a fresh
 * endpoint pick) from scratch. */
static void
magnus_udp_session_service(int epoll_fd, magnus_udp_session_t *session)
{
    for (;;) {
        char buffer[MAGNUS_UDP_DATAGRAM_MAX];
        struct sockaddr_in client_address;
        ssize_t received = recv(session->upstream_fd, buffer, sizeof(buffer), 0);

        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            magnus_udp_close_session(epoll_fd, session);
            return;
        }
        session->last_active = time(NULL);
        client_address = (struct sockaddr_in) {
            .sin_family = AF_INET,
            .sin_addr = session->client_addr,
            .sin_port = session->client_port
        };
        if (sendto(magnus_udp_listener, buffer, (size_t) received, 0,
                  (struct sockaddr *) &client_address,
                  sizeof(client_address)) >= 0) {
            magnus_udp_bytes_u2c_total += (uint64_t) received;
        }
    }
}

/* 1Hz sweep companion to magnus_stream_expire_idle(): a UDP session with
 * no datagram in either direction for magnus_udp_session_idle_seconds is
 * closed -- the only way a session's fd/slot is ever reclaimed short of
 * a hard read error, since UDP itself carries no equivalent of a TCP
 * FIN/RST to signal "this flow is over". */
static void
magnus_udp_expire_idle(int epoll_fd, time_t now)
{
    for (size_t index = 0; index < magnus_udp_max_sessions; index++) {
        magnus_udp_session_t *session = &magnus_udp_sessions[index];
        if (!session->in_use) continue;
        if ((unsigned) (now - session->last_active)
            > magnus_udp_session_idle_seconds) {
            magnus_udp_close_session(epoll_fd, session);
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

/* UDP passthrough (roadmap 3d): same shape as magnus_create_listener()
 * above, but SOCK_DGRAM and no listen() -- UDP has no connection
 * backlog to configure, since it has no connections to accept in the
 * first place; every arriving datagram is read directly off this one
 * socket via recvfrom() in magnus_udp_listener_service(). */
static int
magnus_create_udp_listener(unsigned port)
{
    int listener;
    int enabled = 1;
    struct sockaddr_in address = {0};

    listener = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
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
    if (bind(listener, (struct sockaddr *) &address, sizeof(address)) < 0) {
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
    magnus_cluster_t new_grpc_cluster;
    magnus_cluster_t new_stream_cluster;
    magnus_sni_cluster_t new_sni_clusters[MAGNUS_CONFIG_MAX_SNI_ROUTES];
    magnus_cluster_t new_udp_cluster;
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
    magnus_cluster_init(&new_cluster, config->health_check_failure_threshold,
                        (uint64_t) config->health_check_cooldown_seconds
                        * 1000, config->lb_policy);
    for (index = 0; index < config->upstream_count; index++) {
        if (magnus_cluster_add(&new_cluster, config->upstreams[index].address,
                               config->upstreams[index].port,
                               config->upstreams[index].weight) != 0) {
            if (new_tls_context != NULL) SSL_CTX_free(new_tls_context);
            if (new_root_fd >= 0) close(new_root_fd);
            return -1;
        }
    }
    /* The gRPC cluster's own load-balancing policy is never exposed to
     * config/CLI (roadmap 2e-1 is scoped to the h1/h2 proxy dispatch
     * paths' own shared `magnus_cluster` only -- see
     * magnus_cluster_endpoint_begin()'s own comment on why the gRPC
     * cluster does not participate in MAGNUS_LB_LEAST_CONN's live
     * counting at all, which MAGNUS_LB_IP_HASH does not strictly need but
     * is left equally out of scope here for the same reason: a distinct
     * future increment, not silently half-done). The circuit-breaker
     * failure_threshold/cooldown are a different, orthogonal axis --
     * shared by both clusters' passive health state since well before
     * roadmap 2f, and now driven by the same health_check_* config keys
     * as the `upstream` cluster's own active probe (roadmap 2f). */
    magnus_cluster_init(&new_grpc_cluster,
                        config->health_check_failure_threshold,
                        (uint64_t) config->health_check_cooldown_seconds
                        * 1000, MAGNUS_LB_ROUND_ROBIN);
    for (index = 0; index < config->grpc_upstream_count; index++) {
        if (magnus_cluster_add(&new_grpc_cluster,
                               config->grpc_upstreams[index].address,
                               config->grpc_upstreams[index].port,
                               config->grpc_upstreams[index].weight) != 0) {
            if (new_tls_context != NULL) SSL_CTX_free(new_tls_context);
            if (new_root_fd >= 0) close(new_root_fd);
            return -1;
        }
    }
    /* L4 stream cluster (roadmap 3a): same shared circuit-breaker state as
     * the two clusters above, its own configurable stream_lb_policy (this
     * one *is* exposed, unlike the gRPC cluster's -- a raw TCP passthrough
     * cluster has the exact same "which endpoint" question the h1/h2 proxy
     * cluster does, with no protocol-specific reason to leave it out). */
    magnus_cluster_init(&new_stream_cluster,
                        config->health_check_failure_threshold,
                        (uint64_t) config->health_check_cooldown_seconds
                        * 1000, config->stream_lb_policy);
    for (index = 0; index < config->stream_upstream_count; index++) {
        if (magnus_cluster_add(&new_stream_cluster,
                               config->stream_upstreams[index].address,
                               config->stream_upstreams[index].port,
                               config->stream_upstreams[index].weight) != 0) {
            if (new_tls_context != NULL) SSL_CTX_free(new_tls_context);
            if (new_root_fd >= 0) close(new_root_fd);
            return -1;
        }
    }
    /* TLS passthrough / SNI routing (roadmap 3b): one independent cluster
     * per configured pattern, round_robin only (no active health probe,
     * no configurable policy -- see magnus_config_sni_route_t's own
     * comment on why this is a deliberate, documented scope cut for this
     * increment) but still sharing the same passive circuit-breaker
     * failure_threshold/cooldown every other cluster in this file uses.
     * Hot-reloadable, unlike stream_listen itself: adding, removing, or
     * changing a pattern's endpoints touches no listening socket. */
    for (index = 0; index < config->sni_route_count; index++) {
        magnus_cluster_init(&new_sni_clusters[index].cluster,
                            config->health_check_failure_threshold,
                            (uint64_t) config->health_check_cooldown_seconds
                            * 1000, MAGNUS_LB_ROUND_ROBIN);
        strcpy(new_sni_clusters[index].pattern, config->sni_routes[index].pattern);
        for (size_t j = 0; j < config->sni_routes[index].upstream_count; j++) {
            if (magnus_cluster_add(&new_sni_clusters[index].cluster,
                                   config->sni_routes[index].upstreams[j].address,
                                   config->sni_routes[index].upstreams[j].port,
                                   config->sni_routes[index].upstreams[j].weight)
                != 0) {
                if (new_tls_context != NULL) SSL_CTX_free(new_tls_context);
                if (new_root_fd >= 0) close(new_root_fd);
                return -1;
            }
        }
    }
    /* UDP passthrough (roadmap 3d): its own configurable udp_lb_policy,
     * same reasoning as the stream cluster's own stream_lb_policy above.
     * failure_threshold/cooldown are passed through for consistency with
     * every other magnus_cluster_init() call in this function but are
     * inert here -- magnus_cluster_result() is never called for this
     * cluster at all (see magnus_udp_session_t's own comment on why). */
    magnus_cluster_init(&new_udp_cluster, config->health_check_failure_threshold,
                        (uint64_t) config->health_check_cooldown_seconds
                        * 1000, config->udp_lb_policy);
    for (index = 0; index < config->udp_upstream_count; index++) {
        if (magnus_cluster_add(&new_udp_cluster, config->udp_upstreams[index].address,
                               config->udp_upstreams[index].port,
                               config->udp_upstreams[index].weight) != 0) {
            if (new_tls_context != NULL) SSL_CTX_free(new_tls_context);
            if (new_root_fd >= 0) close(new_root_fd);
            return -1;
        }
    }

    if (magnus_root_fd >= 0) close(magnus_root_fd);
    magnus_root_fd = new_root_fd;
    if (magnus_tls_context != NULL) SSL_CTX_free(magnus_tls_context);
    magnus_tls_context = new_tls_context;
    if (config->has_tls) {
        strcpy(magnus_tls_cert_path, config->tls_cert);
        strcpy(magnus_tls_key_path, config->tls_key);
    }
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
    /* Same stale-by-position hazard as magnus_pool_close_all() above,
     * for the gRPC connection pool (roadmap 2c-5) -- flush it before
     * swapping in the new cluster, not after. */
    magnus_grpc_pool_close_all();
    magnus_grpc_cluster = new_grpc_cluster;
    magnus_grpc_upstream_enabled = new_grpc_cluster.count > 0;
    /* No connection pool to flush for the stream cluster -- unlike the L7
     * proxy's upstream connections, a stream connection's upstream_fd is
     * captured once at accept time and never reused across connections,
     * so there is no stale-by-position pooled-fd hazard to guard against
     * here; only the active-health probe array (reset in the loop below,
     * alongside the other two clusters) needs it. */
    magnus_stream_cluster = new_stream_cluster;
    /* PROXY protocol emission: applies uniformly across the whole
     * stream_listen surface (see magnus_config_t.stream_proxy_protocol's
     * own comment) -- a straight overwrite, like stream_lb_policy, since
     * it involves no listening socket and no in-flight per-connection
     * state that could go stale-by-position the way the two pools above
     * can. In-flight connections are unaffected either way: the header
     * (if any) was already built once by magnus_stream_connect() at
     * accept time, well before any reload could change this. */
    magnus_stream_proxy_protocol_mode = config->stream_proxy_protocol;
    /* No active-health probe array or connection pool exists for these
     * (see the comment where new_sni_clusters[] was built above), so a
     * straight overwrite is the whole swap -- no flush/reset step
     * equivalent to the ones around it needed. */
    for (size_t i = 0; i < config->sni_route_count; i++)
        magnus_sni_clusters[i] = new_sni_clusters[i];
    magnus_sni_cluster_count = config->sni_route_count;
    /* UDP passthrough (roadmap 3d): no connection pool, no active-health
     * probe array (see magnus_udp_session_t's own comment on why) -- a
     * straight overwrite is the whole swap here too. Existing sessions
     * are left alone (same "in-flight work drains against whatever
     * generation it started under" precedent as the stream cluster
     * above); only a *new* client packet after this point sees the new
     * cluster's endpoints/policy. */
    magnus_udp_cluster = new_udp_cluster;
    magnus_udp_session_idle_seconds = config->udp_session_idle_seconds;
    magnus_udp_max_sessions = config->udp_max_sessions;
    /* Same stale-by-position hazard once more (roadmap 2f): an in-flight
     * active-health probe for old position N belongs to whatever backend
     * used to be there, not necessarily the new cluster's position N.
     * Closing every in-flight probe and resetting last_probe (so a fresh
     * one starts promptly under the new generation, rather than waiting
     * out whatever fraction of the old interval happened to remain) is
     * the same fix magnus_pool_close_all()/magnus_grpc_pool_close_all()
     * already apply to the two connection pools above. */
    for (size_t probe_index = 0; probe_index < MAGNUS_MAX_UPSTREAMS;
         probe_index++) {
        magnus_health_close_probe(magnus_global_epoll_fd, magnus_health_probes,
                                  magnus_health_probe_owner, probe_index);
        magnus_health_close_probe(magnus_global_epoll_fd,
                                  magnus_grpc_health_probes,
                                  magnus_grpc_health_probe_owner, probe_index);
        magnus_health_close_probe(magnus_global_epoll_fd,
                                  magnus_stream_health_probes,
                                  magnus_stream_health_probe_owner, probe_index);
        magnus_health_last_probe[probe_index] = 0;
        magnus_grpc_health_last_probe[probe_index] = 0;
        magnus_stream_health_last_probe[probe_index] = 0;
    }
    magnus_health_check_interval_seconds = config->health_check_interval_seconds;
    magnus_health_check_timeout_seconds = config->health_check_timeout_seconds;
    strcpy(magnus_health_check_path, config->health_check_path);
    magnus_health_check_expected_status = config->health_check_expected_status;
    /* Reverse-proxy cache (roadmap 2d-1): a reload can change which
     * routes have cache=on at all, or the cluster a cached response's
     * host+target combination would now hit -- flushed unconditionally,
     * same conservative "never let a config generation see stale-by-
     * meaning state" precedent as the two pools above, rather than trying
     * to reason about which entries are still safe to keep. */
    magnus_cache_purge_all();
    memcpy(magnus_routes, config->routes, sizeof(magnus_routes));
    magnus_route_count = config->route_count;
    memcpy(magnus_trusted_proxies, config->trusted_proxies,
          sizeof(magnus_trusted_proxies));
    magnus_trusted_proxy_count = config->trusted_proxy_count;
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
    if (config.has_stream_listen != magnus_stream_enabled
        || (config.has_stream_listen
            && config.stream_listen_port != magnus_stream_port)) {
        fprintf(stderr, "magnus: reload rejected: changing stream_listen "
                        "requires a restart\n");
        return;
    }
    if (config.has_udp_listen != magnus_udp_enabled
        || (config.has_udp_listen
            && config.udp_listen_port != magnus_udp_port)) {
        fprintf(stderr, "magnus: reload rejected: changing udp_listen "
                        "requires a restart\n");
        return;
    }
    if (config.has_quic_listen != magnus_quic_enabled
        || (config.has_quic_listen
            && config.quic_listen_port != magnus_quic_port)) {
        fprintf(stderr, "magnus: reload rejected: changing quic_listen "
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
        /* L4 stream listener (roadmap 3a): same restart-only shape as
         * admin_socket above -- the listening port itself is fixed for
         * the process lifetime, only the cluster it dispatches to
         * (magnus_apply_config() above) is hot-reloadable. */
        if (config.has_stream_listen) {
            magnus_stream_port = config.stream_listen_port;
            magnus_stream_enabled = true;
        }
        /* UDP listener (roadmap 3d): same restart-only shape once more. */
        if (config.has_udp_listen) {
            magnus_udp_port = config.udp_listen_port;
            magnus_udp_enabled = true;
        }
        /* QUIC listener (roadmap Phase 4a): same restart-only shape;
         * magnus_config_load() already rejected quic_listen without
         * tls_cert/tls_key, so `config.has_tls` is guaranteed true
         * here whenever this is. */
        if (config.has_quic_listen) {
            magnus_quic_port = config.quic_listen_port;
            magnus_quic_enabled = true;
        }
        return config.port;
    }
    const char *certificate = NULL;
    const char *private_key = NULL;
    magnus_cluster_init(&magnus_cluster, MAGNUS_CLUSTER_FAILURE_THRESHOLD,
                        MAGNUS_CLUSTER_COOLDOWN_MS, MAGNUS_LB_ROUND_ROBIN);
    /* The gRPC cluster's own policy is never exposed to config/CLI in
     * this increment -- see magnus_apply_config()'s own comment on why. */
    magnus_cluster_init(&magnus_grpc_cluster, MAGNUS_CLUSTER_FAILURE_THRESHOLD,
                        MAGNUS_CLUSTER_COOLDOWN_MS, MAGNUS_LB_ROUND_ROBIN);
    magnus_cluster_init(&magnus_stream_cluster, MAGNUS_CLUSTER_FAILURE_THRESHOLD,
                        MAGNUS_CLUSTER_COOLDOWN_MS, MAGNUS_LB_ROUND_ROBIN);
    magnus_cluster_init(&magnus_udp_cluster, MAGNUS_CLUSTER_FAILURE_THRESHOLD,
                        MAGNUS_CLUSTER_COOLDOWN_MS, MAGNUS_LB_ROUND_ROBIN);
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
        } else if (strcmp(argv[index], "--grpc-upstream") == 0) {
            /* ipv4:port or ipv4:port:weight; repeatable to build a gRPC
             * cluster. Literal IPv4 only for now -- unlike --upstream, no
             * hostname/DNS resolution yet (roadmap 2c-1's own explicit
             * scope cut; see MAGNUS_CONFIG_MAX_GRPC_UPSTREAMS's comment). */
            char spec[80];
            char *saveptr = NULL;
            char *address;
            char *port_text;
            char *weight_text;
            char *end;
            unsigned long upstream_port;
            unsigned long weight = 1;
            struct in_addr probe;
            if (strlen(argv[index + 1]) >= sizeof(spec)) break;
            strcpy(spec, argv[index + 1]);
            address = strtok_r(spec, ":", &saveptr);
            port_text = strtok_r(NULL, ":", &saveptr);
            weight_text = strtok_r(NULL, ":", &saveptr);
            if (address == NULL || port_text == NULL) break;
            if (inet_pton(AF_INET, address, &probe) != 1) break;
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
            if (magnus_cluster_add(&magnus_grpc_cluster, address,
                                   (unsigned) upstream_port,
                                   (unsigned) weight) != 0) break;
            magnus_grpc_upstream_enabled = true;
        } else if (strcmp(argv[index], "--stream-listen") == 0) {
            char *end;
            unsigned long stream_port;
            errno = 0;
            stream_port = strtoul(argv[index + 1], &end, 10);
            if (errno != 0 || *end != '\0' || stream_port == 0
                || stream_port > 65535) break;
            magnus_stream_port = (unsigned) stream_port;
            magnus_stream_enabled = true;
        } else if (strcmp(argv[index], "--stream-upstream") == 0) {
            /* ipv4:port or ipv4:port:weight; repeatable to build the L4
             * passthrough cluster. Literal IPv4 only, same restriction and
             * reason as --grpc-upstream above. */
            char spec[80];
            char *saveptr = NULL;
            char *address;
            char *port_text;
            char *weight_text;
            char *end;
            unsigned long upstream_port;
            unsigned long weight = 1;
            struct in_addr probe;
            if (strlen(argv[index + 1]) >= sizeof(spec)) break;
            strcpy(spec, argv[index + 1]);
            address = strtok_r(spec, ":", &saveptr);
            port_text = strtok_r(NULL, ":", &saveptr);
            weight_text = strtok_r(NULL, ":", &saveptr);
            if (address == NULL || port_text == NULL) break;
            if (inet_pton(AF_INET, address, &probe) != 1) break;
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
            if (magnus_cluster_add(&magnus_stream_cluster, address,
                                   (unsigned) upstream_port,
                                   (unsigned) weight) != 0) break;
        } else if (strcmp(argv[index], "--stream-lb-policy") == 0) {
            if (strcmp(argv[index + 1], "round_robin") == 0) {
                magnus_stream_cluster.policy = MAGNUS_LB_ROUND_ROBIN;
            } else if (strcmp(argv[index + 1], "least_conn") == 0) {
                magnus_stream_cluster.policy = MAGNUS_LB_LEAST_CONN;
            } else if (strcmp(argv[index + 1], "ip_hash") == 0) {
                magnus_stream_cluster.policy = MAGNUS_LB_IP_HASH;
            } else {
                break;
            }
        } else if (strcmp(argv[index], "--stream-proxy-protocol") == 0) {
            if (strcmp(argv[index + 1], "off") == 0) {
                magnus_stream_proxy_protocol_mode = MAGNUS_PROXY_PROTOCOL_OFF;
            } else if (strcmp(argv[index + 1], "v1") == 0) {
                magnus_stream_proxy_protocol_mode = MAGNUS_PROXY_PROTOCOL_V1;
            } else if (strcmp(argv[index + 1], "v2") == 0) {
                magnus_stream_proxy_protocol_mode = MAGNUS_PROXY_PROTOCOL_V2;
            } else {
                break;
            }
        } else if (strcmp(argv[index], "--stream-sni-route") == 0) {
            /* "<pattern> <ipv4:port[:weight]>", same shape as the
             * config-file stream_sni_route key; repeatable, and multiple
             * invocations sharing the same pattern accumulate into that
             * pattern's own cluster, same as --stream-upstream does for
             * the plain one. */
            char outer_spec[256];
            char *outer_saveptr = NULL;
            char *pattern;
            char *upstream_text;
            const char *pattern_shape;
            char inner_spec[80];
            char *inner_saveptr = NULL;
            char *address;
            char *port_text;
            char *weight_text;
            char *end;
            unsigned long upstream_port;
            unsigned long weight = 1;
            struct in_addr probe;
            magnus_sni_cluster_t *route = NULL;
            size_t i;

            if (strlen(argv[index + 1]) >= sizeof(outer_spec)) break;
            strcpy(outer_spec, argv[index + 1]);
            pattern = strtok_r(outer_spec, " \t", &outer_saveptr);
            upstream_text = strtok_r(NULL, " \t", &outer_saveptr);
            if (pattern == NULL || upstream_text == NULL
                || strtok_r(NULL, " \t", &outer_saveptr) != NULL) break;
            pattern_shape = (pattern[0] == '*' && pattern[1] == '.')
                ? pattern + 2 : pattern;
            if (strlen(pattern) >= sizeof(route->pattern)
                || !magnus_config_looks_like_hostname(pattern_shape)) break;

            if (strlen(upstream_text) >= sizeof(inner_spec)) break;
            strcpy(inner_spec, upstream_text);
            address = strtok_r(inner_spec, ":", &inner_saveptr);
            port_text = strtok_r(NULL, ":", &inner_saveptr);
            weight_text = strtok_r(NULL, ":", &inner_saveptr);
            if (address == NULL || port_text == NULL) break;
            if (inet_pton(AF_INET, address, &probe) != 1) break;
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

            for (i = 0; i < magnus_sni_cluster_count; i++) {
                if (strcmp(magnus_sni_clusters[i].pattern, pattern) == 0) {
                    route = &magnus_sni_clusters[i];
                    break;
                }
            }
            if (route == NULL) {
                if (magnus_sni_cluster_count == MAGNUS_CONFIG_MAX_SNI_ROUTES)
                    break;
                route = &magnus_sni_clusters[magnus_sni_cluster_count++];
                magnus_cluster_init(&route->cluster, MAGNUS_CLUSTER_FAILURE_THRESHOLD,
                                    MAGNUS_CLUSTER_COOLDOWN_MS, MAGNUS_LB_ROUND_ROBIN);
                strcpy(route->pattern, pattern);
            }
            if (magnus_cluster_add(&route->cluster, address,
                                   (unsigned) upstream_port,
                                   (unsigned) weight) != 0) break;
        } else if (strcmp(argv[index], "--udp-listen") == 0) {
            char *end;
            unsigned long udp_port;
            errno = 0;
            udp_port = strtoul(argv[index + 1], &end, 10);
            if (errno != 0 || *end != '\0' || udp_port == 0
                || udp_port > 65535) break;
            magnus_udp_port = (unsigned) udp_port;
            magnus_udp_enabled = true;
        } else if (strcmp(argv[index], "--quic-port") == 0) {
            char *end;
            unsigned long quic_port;
            errno = 0;
            quic_port = strtoul(argv[index + 1], &end, 10);
            if (errno != 0 || *end != '\0' || quic_port == 0
                || quic_port > 65535) break;
            magnus_quic_port = (unsigned) quic_port;
            magnus_quic_enabled = true;
        } else if (strcmp(argv[index], "--udp-upstream") == 0) {
            /* ipv4:port or ipv4:port:weight; repeatable to build the UDP
             * cluster. Literal IPv4 only, same restriction and reason as
             * --grpc-upstream/--stream-upstream above. */
            char spec[80];
            char *saveptr = NULL;
            char *address;
            char *port_text;
            char *weight_text;
            char *end;
            unsigned long upstream_port;
            unsigned long weight = 1;
            struct in_addr probe;
            if (strlen(argv[index + 1]) >= sizeof(spec)) break;
            strcpy(spec, argv[index + 1]);
            address = strtok_r(spec, ":", &saveptr);
            port_text = strtok_r(NULL, ":", &saveptr);
            weight_text = strtok_r(NULL, ":", &saveptr);
            if (address == NULL || port_text == NULL) break;
            if (inet_pton(AF_INET, address, &probe) != 1) break;
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
            if (magnus_cluster_add(&magnus_udp_cluster, address,
                                   (unsigned) upstream_port,
                                   (unsigned) weight) != 0) break;
        } else if (strcmp(argv[index], "--udp-lb-policy") == 0) {
            if (strcmp(argv[index + 1], "round_robin") == 0) {
                magnus_udp_cluster.policy = MAGNUS_LB_ROUND_ROBIN;
            } else if (strcmp(argv[index + 1], "least_conn") == 0) {
                magnus_udp_cluster.policy = MAGNUS_LB_LEAST_CONN;
            } else if (strcmp(argv[index + 1], "ip_hash") == 0) {
                magnus_udp_cluster.policy = MAGNUS_LB_IP_HASH;
            } else {
                break;
            }
        } else if (strcmp(argv[index], "--udp-session-idle") == 0) {
            char *end;
            unsigned long seconds;
            errno = 0;
            seconds = strtoul(argv[index + 1], &end, 10);
            if (errno != 0 || *end != '\0' || seconds == 0 || seconds > 3600)
                break;
            magnus_udp_session_idle_seconds = (unsigned) seconds;
        } else if (strcmp(argv[index], "--udp-max-sessions") == 0) {
            char *end;
            unsigned long sessions;
            errno = 0;
            sessions = strtoul(argv[index + 1], &end, 10);
            if (errno != 0 || *end != '\0' || sessions == 0
                || sessions > MAGNUS_UDP_MAX_SESSIONS_CEILING) break;
            magnus_udp_max_sessions = (unsigned) sessions;
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
        } else if (strcmp(argv[index], "--lb-policy") == 0) {
            if (strcmp(argv[index + 1], "round_robin") == 0) {
                magnus_cluster.policy = MAGNUS_LB_ROUND_ROBIN;
            } else if (strcmp(argv[index + 1], "least_conn") == 0) {
                magnus_cluster.policy = MAGNUS_LB_LEAST_CONN;
            } else if (strcmp(argv[index + 1], "ip_hash") == 0) {
                magnus_cluster.policy = MAGNUS_LB_IP_HASH;
            } else {
                break;
            }
        } else if (strcmp(argv[index], "--health-check-path") == 0) {
            const char *path = argv[index + 1];
            if (*path != '/' || strlen(path) >= sizeof(magnus_health_check_path)
                || strpbrk(path, " \t\r\n") != NULL) break;
            strcpy(magnus_health_check_path, path);
        } else if (strcmp(argv[index], "--health-check-expected-status") == 0) {
            char *end;
            unsigned long status;
            errno = 0;
            status = strtoul(argv[index + 1], &end, 10);
            if (errno != 0 || *end != '\0' || status < 100 || status > 599)
                break;
            magnus_health_check_expected_status = (unsigned) status;
        } else if (strcmp(argv[index], "--health-check-interval") == 0) {
            char *end;
            unsigned long seconds;
            errno = 0;
            seconds = strtoul(argv[index + 1], &end, 10);
            if (errno != 0 || *end != '\0' || seconds == 0 || seconds > 3600)
                break;
            magnus_health_check_interval_seconds = (unsigned) seconds;
        } else if (strcmp(argv[index], "--health-check-timeout") == 0) {
            char *end;
            unsigned long seconds;
            errno = 0;
            seconds = strtoul(argv[index + 1], &end, 10);
            if (errno != 0 || *end != '\0' || seconds == 0 || seconds > 3600)
                break;
            magnus_health_check_timeout_seconds = (unsigned) seconds;
        } else if (strcmp(argv[index], "--health-check-failure-threshold") == 0) {
            char *end;
            unsigned long count;
            errno = 0;
            count = strtoul(argv[index + 1], &end, 10);
            if (errno != 0 || *end != '\0' || count == 0 || count > 1000)
                break;
            magnus_cluster.failure_threshold = (unsigned) count;
            magnus_grpc_cluster.failure_threshold = (unsigned) count;
        } else if (strcmp(argv[index], "--health-check-cooldown") == 0) {
            char *end;
            unsigned long seconds;
            errno = 0;
            seconds = strtoul(argv[index + 1], &end, 10);
            if (errno != 0 || *end != '\0' || seconds == 0 || seconds > 86400)
                break;
            magnus_cluster.cooldown_ms = (uint64_t) seconds * 1000;
            magnus_grpc_cluster.cooldown_ms = (uint64_t) seconds * 1000;
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
        } else if (strcmp(argv[index], "--trusted-proxies") == 0) {
            /* Comma-separated CIDR list; mirrors the config-file
             * 'trusted_proxies' key (magnus_config.c) so plain-flag mode
             * and --config mode behave identically. */
            char spec[512];
            char *saveptr = NULL;
            char *token;
            if (strlen(argv[index + 1]) >= sizeof(spec)) {
                fprintf(stderr, "magnus: --trusted-proxies: list too long\n");
                exit(2);
            }
            strcpy(spec, argv[index + 1]);
            for (token = strtok_r(spec, ",", &saveptr); token != NULL;
                 token = strtok_r(NULL, ",", &saveptr)) {
                char *cidr_text = token;
                struct in_addr network;
                unsigned prefix_length;
                if (*cidr_text == '\0') continue;
                if (magnus_trusted_proxy_count == MAGNUS_CONFIG_MAX_TRUSTED_PROXIES) {
                    fprintf(stderr, "magnus: --trusted-proxies: too many "
                                    "entries (max %d)\n",
                                    MAGNUS_CONFIG_MAX_TRUSTED_PROXIES);
                    exit(2);
                }
                if (!magnus_route_parse_cidr(cidr_text, &network, &prefix_length)) {
                    fprintf(stderr, "magnus: --trusted-proxies: invalid "
                                    "CIDR '%s'\n", cidr_text);
                    exit(2);
                }
                magnus_trusted_proxies[magnus_trusted_proxy_count].network = network;
                magnus_trusted_proxies[magnus_trusted_proxy_count].prefix_length = prefix_length;
                magnus_trusted_proxy_count++;
            }
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
        if (magnus_routes[r].action == MAGNUS_ROUTE_ACTION_GRPC
            && !magnus_grpc_upstream_enabled) {
            fprintf(stderr, "magnus: --route: a route with action=grpc "
                            "needs at least one --grpc-upstream\n");
            exit(2);
        }
    }
    if (magnus_stream_enabled && magnus_stream_cluster.count == 0) {
        fprintf(stderr, "magnus: --stream-listen needs at least one "
                        "--stream-upstream\n");
        exit(2);
    }
    if (!magnus_stream_enabled && magnus_stream_cluster.count > 0) {
        fprintf(stderr, "magnus: --stream-upstream needs "
                        "--stream-listen\n");
        exit(2);
    }
    if (magnus_stream_enabled && port != 0 && magnus_stream_port == port) {
        fprintf(stderr, "magnus: --stream-listen must differ from "
                        "--port\n");
        exit(2);
    }
    if (!magnus_stream_enabled && magnus_sni_cluster_count > 0) {
        fprintf(stderr, "magnus: --stream-sni-route needs "
                        "--stream-listen\n");
        exit(2);
    }
    if (magnus_udp_enabled && magnus_udp_cluster.count == 0) {
        fprintf(stderr, "magnus: --udp-listen needs at least one "
                        "--udp-upstream\n");
        exit(2);
    }
    if (!magnus_udp_enabled && magnus_udp_cluster.count > 0) {
        fprintf(stderr, "magnus: --udp-upstream needs --udp-listen\n");
        exit(2);
    }
    if (magnus_quic_enabled && (certificate == NULL || private_key == NULL)) {
        fprintf(stderr, "magnus: --quic-port needs --tls-cert/--tls-key "
                        "(QUIC terminates its own TLS 1.3, using the same "
                        "certificate the HTTPS listener does)\n");
        exit(2);
    }
    /* Deliberately no "--udp-listen must differ from --port/--stream-
     * listen" check -- see magnus_config_t's own comment on why. */
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
            if (strlen(certificate) >= sizeof(magnus_tls_cert_path)
                || strlen(private_key) >= sizeof(magnus_tls_key_path)) {
                fprintf(stderr, "magnus: --tls-cert/--tls-key path too long\n");
                exit(2);
            }
            strcpy(magnus_tls_cert_path, certificate);
            strcpy(magnus_tls_key_path, private_key);
        }
        return port;
    }
    fprintf(stderr, "usage: %s --port <1-65535> [--root <directory>] "
                    "[--tls-cert <pem> --tls-key <pem>] "
                    "[--upstream <ipv4:port[:weight]> ...] "
                    "[--lb-policy round_robin|least_conn|ip_hash] "
                    "[--rate-limit <rps[:burst]>] "
                    "[--admin-socket <path>] "
                    "[--access-log on|off] [--access-log-sample <n>] "
                    "[--health-check-path </path>] "
                    "[--health-check-expected-status <100-599>] "
                    "[--health-check-interval <seconds>] "
                    "[--health-check-timeout <seconds>] "
                    "[--health-check-failure-threshold <n>] "
                    "[--health-check-cooldown <seconds>] "
                    "[--stream-listen <1-65535> --stream-upstream "
                    "<ipv4:port[:weight]> ...] "
                    "[--stream-lb-policy round_robin|least_conn|ip_hash] "
                    "[--stream-proxy-protocol off|v1|v2] "
                    "[--stream-sni-route "
                    "'<pattern> <ipv4:port[:weight]>' ...] "
                    "[--udp-listen <1-65535> --udp-upstream "
                    "<ipv4:port[:weight]> ...] "
                    "[--udp-lb-policy round_robin|least_conn|ip_hash] "
                    "[--udp-session-idle <seconds>] "
                    "[--udp-max-sessions <n>] "
                    "[--quic-port <1-65535>] "
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
    /* Must happen before magnus_parse_options(): --config mode calls
     * magnus_apply_config() from inside option parsing, which closes any
     * in-flight active-health probe for every position on every config
     * load (not just a later reload -- see its own comment on the stale-
     * by-position hazard). Static storage zero-initializes these arrays,
     * and 0 is a live fd (stdin) -- without this, that very first
     * magnus_apply_config() call would call close() on whatever
     * uninitialized/zero fd value each slot happened to hold. */
    for (size_t probe_index = 0; probe_index < MAGNUS_MAX_UPSTREAMS;
         probe_index++) {
        magnus_health_probes[probe_index].fd = -1;
        magnus_grpc_health_probes[probe_index].fd = -1;
        magnus_stream_health_probes[probe_index].fd = -1;
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
    if (magnus_stream_enabled) {
        struct epoll_event stream_event;
        magnus_stream_listener = magnus_create_listener(magnus_stream_port);
        if (magnus_stream_listener < 0) {
            perror("magnus: stream-listen");
            if (magnus_admin_listener >= 0) close(magnus_admin_listener);
            close(epoll_fd);
            close(listener);
            return 1;
        }
        stream_event = (struct epoll_event) { .events = EPOLLIN,
                                              .data.fd = magnus_stream_listener };
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, magnus_stream_listener,
                      &stream_event) < 0) {
            perror("magnus: stream-listen epoll_ctl");
            close(magnus_stream_listener);
            if (magnus_admin_listener >= 0) close(magnus_admin_listener);
            close(epoll_fd);
            close(listener);
            return 1;
        }
    }
    if (magnus_udp_enabled) {
        struct epoll_event udp_event;
        magnus_udp_listener = magnus_create_udp_listener(magnus_udp_port);
        if (magnus_udp_listener < 0) {
            perror("magnus: udp-listen");
            if (magnus_stream_listener >= 0) close(magnus_stream_listener);
            if (magnus_admin_listener >= 0) close(magnus_admin_listener);
            close(epoll_fd);
            close(listener);
            return 1;
        }
        udp_event = (struct epoll_event) { .events = EPOLLIN,
                                           .data.fd = magnus_udp_listener };
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, magnus_udp_listener,
                      &udp_event) < 0) {
            perror("magnus: udp-listen epoll_ctl");
            close(magnus_udp_listener);
            if (magnus_stream_listener >= 0) close(magnus_stream_listener);
            if (magnus_admin_listener >= 0) close(magnus_admin_listener);
            close(epoll_fd);
            close(listener);
            return 1;
        }
    }
    if (magnus_quic_enabled) {
        struct epoll_event quic_event;
        if (magnus_quic_init(magnus_tls_cert_path, magnus_tls_key_path) != 0) {
            if (magnus_udp_listener >= 0) close(magnus_udp_listener);
            if (magnus_stream_listener >= 0) close(magnus_stream_listener);
            if (magnus_admin_listener >= 0) close(magnus_admin_listener);
            close(epoll_fd);
            close(listener);
            return 1;
        }
        magnus_quic_listener = magnus_quic_create_listener(magnus_quic_port);
        if (magnus_quic_listener < 0) {
            perror("magnus: quic-port");
            if (magnus_udp_listener >= 0) close(magnus_udp_listener);
            if (magnus_stream_listener >= 0) close(magnus_stream_listener);
            if (magnus_admin_listener >= 0) close(magnus_admin_listener);
            close(epoll_fd);
            close(listener);
            return 1;
        }
        quic_event = (struct epoll_event) { .events = EPOLLIN,
                                            .data.fd = magnus_quic_listener };
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, magnus_quic_listener,
                      &quic_event) < 0) {
            perror("magnus: quic-port epoll_ctl");
            close(magnus_quic_listener);
            if (magnus_udp_listener >= 0) close(magnus_udp_listener);
            if (magnus_stream_listener >= 0) close(magnus_stream_listener);
            if (magnus_admin_listener >= 0) close(magnus_admin_listener);
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
    /* Active-health probe fd slots were already reset to -1 before
     * magnus_parse_options() -- see that call site's own comment. */
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
                && magnus_grpc_conn_owner[fd] != NULL) {
                /* A pooled gRPC connection's fd (roadmap 2c-5) can be
                 * driving many concurrent RPCs' upstream leg at once,
                 * across possibly several different real client
                 * connections -- unlike either branch above, no single
                 * magnus_connection_t is "the" owner of this event, so
                 * there is no close-on-failure decision to make here at
                 * all; magnus_grpc_conn_handle_event() already pushes
                 * onto every affected client connection internally (and
                 * closes any of them individually only via the normal
                 * magnus_h2_push() failure path each of those calls
                 * already goes through). */
                (void) magnus_grpc_conn_handle_event(
                    magnus_grpc_conn_owner[fd], flags);
                continue;
            }
            if (fd >= 0 && fd < MAGNUS_MAX_FDS
                && magnus_health_probe_owner[fd] != 0) {
                magnus_health_handle_probe(epoll_fd, &magnus_cluster,
                    magnus_health_probes, magnus_health_probe_owner,
                    (size_t) (magnus_health_probe_owner[fd] - 1), flags, true);
                continue;
            }
            if (fd >= 0 && fd < MAGNUS_MAX_FDS
                && magnus_grpc_health_probe_owner[fd] != 0) {
                magnus_health_handle_probe(epoll_fd, &magnus_grpc_cluster,
                    magnus_grpc_health_probes, magnus_grpc_health_probe_owner,
                    (size_t) (magnus_grpc_health_probe_owner[fd] - 1), flags,
                    false);
                continue;
            }
            if (fd >= 0 && fd < MAGNUS_MAX_FDS
                && magnus_stream_health_probe_owner[fd] != 0) {
                magnus_health_handle_probe(epoll_fd, &magnus_stream_cluster,
                    magnus_stream_health_probes, magnus_stream_health_probe_owner,
                    (size_t) (magnus_stream_health_probe_owner[fd] - 1), flags,
                    false);
                continue;
            }
            if (fd == magnus_stream_listener && magnus_stream_listener >= 0) {
                magnus_stream_accept(epoll_fd);
                continue;
            }
            if (fd >= 0 && fd < MAGNUS_MAX_FDS
                && magnus_stream_owner[fd] != NULL) {
                magnus_stream_service(epoll_fd, magnus_stream_owner[fd], fd, flags);
                continue;
            }
            if (fd >= 0 && fd < MAGNUS_MAX_FDS
                && magnus_stream_upstream_owner[fd] != NULL) {
                magnus_stream_service(epoll_fd, magnus_stream_upstream_owner[fd],
                                      fd, flags);
                continue;
            }
            if (fd == magnus_udp_listener && magnus_udp_listener >= 0) {
                magnus_udp_listener_service(epoll_fd);
                continue;
            }
            if (fd >= 0 && fd < MAGNUS_MAX_FDS
                && magnus_udp_upstream_owner[fd] != NULL) {
                magnus_udp_session_service(epoll_fd, magnus_udp_upstream_owner[fd]);
                continue;
            }
            if (fd == magnus_quic_listener && magnus_quic_listener >= 0) {
                /* Unlike every listener dispatched above, QUIC has no
                 * per-connection fd of its own to also match here --
                 * every active QUIC connection is demultiplexed inside
                 * magnus_quic_listener_service() itself, by connection
                 * ID, off this one shared UDP socket. See
                 * src/magnus_quic.h. */
                magnus_quic_listener_service(magnus_quic_listener);
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
            } else if (!connection->proxy_proto_done) {
                result = ((flags & EPOLLIN) != 0)
                    ? magnus_proxy_proto_check(connection) : 0;
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
            magnus_stream_expire_idle(epoll_fd, now);
            magnus_udp_expire_idle(epoll_fd, now);
            if (magnus_quic_enabled)
                magnus_quic_tick(magnus_quic_listener, now);
            magnus_pool_expire_idle(now);
            magnus_grpc_pool_expire(now);
            magnus_cache_expire_sweep(magnus_cache_now_ms());
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
    for (int fd = 0; fd < MAGNUS_MAX_FDS; fd++) {
        if (magnus_stream_owner[fd] != NULL) {
            magnus_stream_close(epoll_fd, magnus_stream_owner[fd]);
        }
    }
    for (size_t index = 0; index < magnus_udp_max_sessions; index++) {
        if (magnus_udp_sessions[index].in_use) {
            magnus_udp_close_session(epoll_fd, &magnus_udp_sessions[index]);
        }
    }
    magnus_pool_close_all();
    magnus_grpc_pool_close_all();
    magnus_cache_purge_all();
    magnus_dns_stop();
    close(epoll_fd);
    close(listener);
    if (magnus_admin_listener >= 0) {
        close(magnus_admin_listener);
        unlink(magnus_admin_socket_path);
    }
    if (magnus_stream_listener >= 0) close(magnus_stream_listener);
    if (magnus_udp_listener >= 0) close(magnus_udp_listener);
    if (magnus_quic_listener >= 0) {
        close(magnus_quic_listener);
        magnus_quic_shutdown();
    }
    if (magnus_root_fd >= 0) close(magnus_root_fd);
    if (magnus_tls_context != NULL) SSL_CTX_free(magnus_tls_context);
    magnus_access_log_flush();
    fprintf(stderr, "magnus: stopped\n");
    return 0;
}
