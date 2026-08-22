#include "magnus_quic.h"
#include "magnus_static.h"
#include "magnus_cache.h"
#include "magnus_compression.h"
#include "magnus_proxy.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Bounded, linear-scan tables -- the same style every other fixed-size
 * state table in this codebase already uses (magnus_health_probes[],
 * magnus_config_t's route/upstream arrays, ...); Section 8's own policy
 * is "no optimization without a measured need", and QUIC connection
 * counts here are not yet anything close to where a linear scan would
 * show up in a profile. A CID can outlive its connection's normal
 * bookkeeping only briefly (removed the same tick a connection is
 * freed), so MAGNUS_QUIC_MAX_CIDS only needs enough headroom for a
 * handshake's own initial handful of issued CIDs per connection, not
 * an unbounded accumulation. */
#define MAGNUS_QUIC_MAX_CONNECTIONS 256
#define MAGNUS_QUIC_MAX_CIDS (MAGNUS_QUIC_MAX_CONNECTIONS * 8)
#define MAGNUS_QUIC_RECV_BUFFER 65536
#define MAGNUS_QUIC_SEND_BUFFER 65536
/* One second on Magnus's own coarse per-tick clock (magnus_quic_tick()
 * is only ever called once per magnus.c's existing 1 Hz sweep) beyond
 * ngtcp2's own last-activity signal, before a connection this module's
 * own idle bookkeeping considers worth double-checking is expired is
 * not needed for correctness -- ngtcp2_conn_get_expiry()/
 * ngtcp2_conn_handle_expiry() are what actually enforce the QUIC idle
 * timeout (see MAGNUS_QUIC_MAX_IDLE_TIMEOUT_NS below); this is only a
 * backstop against a connection somehow surviving past its own expiry
 * (a bug, not a normal path) camping on a table slot forever. */
#define MAGNUS_QUIC_STALE_SECONDS 120
#define MAGNUS_QUIC_MAX_IDLE_TIMEOUT_NS (30ULL * NGTCP2_SECONDS)
/* Concurrent client-initiated bidirectional (HTTP/3 request) streams
 * per QUIC connection -- advertised to the peer via
 * initial_max_streams_bidi (magnus_quic_accept_new()) and, separately,
 * the bound magnus_quic_slot_free()'s own error-path stream-struct
 * sweep walks against (see that function's comment). 100 matches this
 * codebase's existing h2 concurrent-stream expectations (no explicit
 * cap is set on the nghttp2 side either -- both protocols size their
 * concurrency the same informal way for now). */
#define MAGNUS_QUIC_MAX_BIDI_STREAMS 100

/* Proxy dispatch (roadmap 4d) -- deliberately independent of magnus.c's
 * own MAGNUS_PROXY_BUFFER/MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS/
 * MAGNUS_PROXY_READ_TIMEOUT_SECONDS, same reasoning as
 * MAGNUS_METRICS_BUFFER's own local redefinition: these need to be
 * *reasonable*, not byte-for-byte identical to the h1/h2 path's own
 * constants, to stay correct. Values matched anyway, since there is no
 * reason for this increment's defaults to differ from the rest of the
 * codebase's. */
#define MAGNUS_QUIC_PROXY_BUFFER 16384
#define MAGNUS_QUIC_PROXY_HEADER_LIMIT MAGNUS_QUIC_PROXY_BUFFER
#define MAGNUS_QUIC_PROXY_SANITIZED_LIMIT 4096
#define MAGNUS_QUIC_PROXY_CONNECT_TIMEOUT_SECONDS 5
#define MAGNUS_QUIC_PROXY_READ_TIMEOUT_SECONDS 10
/* Same value as magnus.c's own (`#define`-local, not shared) MAGNUS_
 * PROXY_MAX_ATTEMPTS -- roadmap 4g's own retry-on-connect-failure,
 * mirroring magnus_h2_proxy_connect_failed()'s identical semantics: at
 * most this many total connect attempts (the original plus retries
 * against a freshly-selected endpoint) before giving up with a clean
 * status-coded error, exactly the same "just don't share the literal
 * define, keep the value in sync by convention" reasoning
 * magnus_now_ms_local()'s own comment gives for not threading every
 * such small constant across src/magnus_static.h. */
#define MAGNUS_QUIC_PROXY_MAX_ATTEMPTS 2
/* Bounded, linear-scan table (see this file's own top comment on why
 * that style, same as everywhere else here) mapping an upstream
 * connection's own fd to the magnus_quic_stream_t that owns it --
 * needed because, unlike every *client*-facing QUIC stream (which lives
 * entirely inside ngtcp2/nghttp3's own per-connection state), a proxy
 * dispatch's upstream leg is an ordinary TCP fd that must be registered
 * on magnus.c's shared epoll instance (magnus_global_epoll_fd, src/
 * magnus_static.h) to ever be serviced at all -- a QUIC connection has
 * no fd of its own for that epoll registration to piggyback on (see
 * magnus_quic.h's own top comment). Sized to match magnus.c's own
 * MAGNUS_MAX_FDS so every fd this process could ever open has a slot. */
#define MAGNUS_QUIC_MAX_FDS 65536

typedef struct {
    bool in_use;
    ngtcp2_conn *conn;
    ngtcp2_crypto_conn_ref conn_ref;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage remote_addr;
    socklen_t remote_addrlen;
    bool handshake_logged;
    time_t last_activity;
    /* HTTP/3 (roadmap Phase 4b, see magnus_quic.h) -- NULL until the
     * server's own 1-RTT TX key is available (magnus_quic_recv_tx_key(),
     * the earliest point 1-RTT application data, i.e. the HTTP/3
     * control/QPACK streams, can go out at all), and for the entire
     * lifetime of a connection this module's own scope note excludes it
     * from needing one (a plain L4-only future stream_listen-style
     * connection has no reason to ever get one). */
    nghttp3_conn *http3_conn;
} magnus_quic_connection_t;

/* One HTTP/3 request stream. Deliberately not pooled/bounded the way
 * magnus_quic_connections[]/magnus_quic_cids[] are: nghttp3 itself
 * already bounds concurrent streams per connection via
 * initial_max_streams_bidi (see magnus_quic_accept_new()), so a second,
 * independent bound here would only duplicate that enforcement --
 * malloc/free per stream matches struct magnus_h2_stream's own approach
 * in magnus.c for the exact same reason. */
typedef struct {
    int64_t stream_id;
    /* :method/:path/:authority captured into .method/.target/.host,
     * every ordinary header into .headers[] -- exactly the shape
     * magnus_h2_on_header() already builds for HTTP/2's own
     * stream->parsed (magnus.c), reused verbatim here (not a QUIC-local
     * near-copy) specifically so magnus_route_matches() (roadmap 4f:
     * host/path-prefix/method/header/header_prefix/cookie/query/
     * source-CIDR route matching) and magnus_accepts_gzip() (roadmap
     * 4e, via magnus_http_header_find(&stream->parsed,
     * "accept-encoding") -- no longer a separate ad hoc field) both
     * work identically regardless of which protocol a request arrived
     * over. See magnus_quic_http_recv_header()'s own comment for the
     * capture side. */
    magnus_http_request_t parsed;
    bool head_only;
    /* The whole file, mmap()ed once at dispatch and handed to nghttp3
     * as a single vec (magnus_quic_http_read_file()) rather than
     * pread() in chunks -- found the hard way, not by review: a
     * chunked-pread version that advanced its own read offset inside
     * the read_data callback silently skipped/reordered bytes, because
     * nghttp3_conn_writev_stream() can call read_data again for the
     * same stream before a previous chunk has actually finished being
     * written onto the wire (observed directly: a second call arrived
     * having only flushed 645 of a first 16384-byte chunk), and that
     * callback has no way to know how much of what it last returned
     * was actually consumed -- only nghttp3_conn_add_write_offset()
     * (which magnus_quic_flush() already calls) knows that. One mmap
     * spanning the whole file sidesteps the question entirely: the
     * same immutable memory stays valid and correct regardless of how
     * many times or in what order nghttp3 asks for it, matching the
     * static-file path of the reference implementation this stack was
     * verified against (docs/phase4-spike-results.md) exactly. */
    void *mmap_base;
    size_t mmap_length;
    /* /healthz and /metrics (roadmap 4c) reuse mmap_base/mmap_length as
     * a generic "response body pointer + length" rather than adding a
     * second pair of fields -- their body is a small malloc()ed copy
     * (magnus_build_metrics() writes into a stack buffer that does not
     * outlive the dispatch call, so it must be copied somewhere that
     * does), not a file mapping, so this flag is what
     * magnus_quic_http_stream_free() checks to call free() instead of
     * munmap() on cleanup. */
    bool body_is_malloc;
    /* Proxy dispatch (roadmap 4d, retry-on-connect-failure added 4g) --
     * see magnus_quic.h's own scope note for what is deliberately still
     * not here: upstream connection pooling/reuse, session affinity,
     * response caching. */
    bool is_proxy;
    int upstream_fd;
    bool upstream_connected;
    size_t endpoint_index;
    bool cluster_endpoint_counted;
    /* How many total connect attempts this stream has made so far
     * (the original plus any retries) -- roadmap 4g, the h3 analogue of
     * magnus_h2_stream's own `attempt` field, bounded by
     * MAGNUS_QUIC_PROXY_MAX_ATTEMPTS the same way. */
    int attempt;
    /* Session affinity (roadmap 4h) -- the h3 analogue of
     * struct magnus_h2_stream's own identically-named pair. `affinity_key`
     * is filled in by magnus_encode_affinity_cookie() the moment a fresh
     * (non-sticky, or deviated-from-sticky) endpoint is actually
     * selected -- not up front -- since a retry (roadmap 4g) can still
     * change which endpoint the client should be pinned to after the
     * first attempt. `issue_affinity_cookie` is what
     * magnus_quic_proxy_receive_headers() checks to decide whether to
     * pass a non-NULL affinity_key through to
     * magnus_proxy_sanitize_response_headers() (its own existing
     * parameter, unused by roadmap 4d/4f/4g -- always passed NULL until
     * now), the same shared Set-Cookie-emission code path HTTP/1.1's
     * own proxy dispatch and magnus_h2_proxy_receive_headers() already
     * use. */
    bool issue_affinity_cookie;
    char affinity_key[64];
    /* Reverse-proxy cache (roadmap 4i for HTTP/3) -- the h3 analogue of
     * struct magnus_h2_stream's own identically-named fields, see
     * magnus_h2_proxy_start()'s and magnus_h2_proxy_receive_headers()'s
     * own comments for the full rationale behind each one. `cache_enabled`
     * is this stream's own copy of the matched route's `cache_enabled`
     * (roadmap 4f) -- action=proxy without cache=on never touches any of
     * the rest of this. `cache_host`/`cache_target` key the lookup
     * (stream->parsed.host / the forward path, exact case-sensitive
     * match on both). `cache_revalidating` plus the two validator fields
     * are set only when a stale-but-still-useful entry was found, driving
     * the conditional GET (If-None-Match/If-Modified-Since) built into
     * the outbound proxy_request. `cache_this_response_cacheable` is
     * decided once headers are known (roadmap 2d-1's own precedent);
     * `cache_pending_headers`/`cache_response_etag`/
     * `cache_response_last_modified` are what magnus_cache_store()
     * eventually gets, `cache_capture`/`cache_capture_length`/
     * `cache_capture_capacity`/`cache_capture_overflowed` the growable
     * body buffer magnus_quic_proxy_cache_capture() fills as the
     * response streams in. */
    bool cache_enabled;
    bool cache_revalidating;
    char cache_host[256];
    char cache_target[256];
    char cache_validator_etag[128];
    char cache_validator_last_modified[64];
    bool cache_this_response_cacheable;
    magnus_cache_freshness_t cache_freshness;
    char cache_pending_headers[MAGNUS_QUIC_PROXY_SANITIZED_LIMIT];
    size_t cache_pending_headers_length;
    char cache_response_etag[128];
    char cache_response_last_modified[64];
    char *cache_capture;
    size_t cache_capture_length;
    size_t cache_capture_capacity;
    bool cache_capture_overflowed;
    time_t connect_started;
    time_t last_activity;
    char *proxy_request;
    size_t proxy_request_length;
    size_t proxy_request_sent;
    bool upstream_headers_sent;
    /* Accumulates the upstream's raw status-line+header block (may
     * arrive split across several recv() calls) until the terminating
     * blank line is found -- separate from the body-streaming buffer
     * below because the two have different growth/backpressure needs
     * (this one only ever needs to hold up to MAGNUS_QUIC_PROXY_HEADER_LIMIT
     * once, the body buffer refills indefinitely). */
    char *header_buffer;
    size_t header_accum;
    bool headers_received;
    bool response_headers_submitted;
    bool has_response_length;
    size_t response_length;
    size_t response_received;
    bool upstream_poolable; /* computed, but never acted on in this
                             * increment -- no pool to check into (see
                             * this struct's own top comment) -- kept so
                             * a later increment adding pooling has
                             * nothing to change here. */
    bool upstream_eof;
    bool response_complete;
    /* One chunk in flight at a time -- NOT the same shape as
     * magnus_h2_read_io_buffer()'s single reused buffer, and
     * deliberately so: found the hard way, not by review, that
     * reusing one buffer here corrupts a real proxied response under
     * real QUIC flow-control backpressure. nghttp3's own documented
     * contract for nghttp3_read_data_callback is stricter than
     * nghttp2's: the memory a read_data call hands off "must [stay
     * retained] until they are safe to free... notified by
     * nghttp3_acked_stream_data" -- i.e. until the *peer has
     * acknowledged* that stream data, not merely until
     * ngtcp2_conn_writev_stream() has copied it into a packet (nghttp2's
     * own read_callback model guarantees that synchronously within one
     * call; nghttp3's does not, since ngtcp2 itself may hold onto the
     * exact vec pointer for retransmission until acked). Marking a
     * chunk "safe to reuse" the moment read_data merely *handed it to
     * nghttp3* (this file's own first version) let
     * magnus_quic_proxy_stream_response() overwrite it with fresh
     * recv() bytes while ngtcp2 could still be holding it unacked under
     * flow control -- reproduced directly with a 220 KB streamed
     * response through a small stream flow-control window: two lines
     * spliced together mid-word, total length still correct. Each
     * recv() now gets its own fresh allocation instead of reusing one
     * buffer, freed only once magnus_quic_proxy_acked() below confirms
     * the peer has actually acknowledged it -- the same "just don't
     * reuse memory before its real lifetime ends" fix roadmap 4b's own
     * mmap change made for the static-file path, adapted here for
     * memory that (unlike an mmap'd file) genuinely does need to be
     * freed once, not held for the whole stream's life. */
    uint8_t *body_chunk;
    size_t body_chunk_length;
    bool body_chunk_offered;
    uint64_t body_chunk_end_offset;
    uint64_t body_offered_total;
    uint64_t body_acked_total;
    /* True after magnus_quic_proxy_read_body() last returned
     * NGHTTP3_ERR_WOULDBLOCK (nothing buffered, response not complete
     * yet) -- magnus_quic_proxy_stream_response() calls
     * nghttp3_conn_resume_stream() the next time it actually offers a
     * new chunk, exactly once per such wait, per nghttp3's own
     * documented contract for that error code. */
    bool nghttp3_wants_resume;
} magnus_quic_stream_t;

typedef struct {
    bool in_use;
    uint8_t data[NGTCP2_MAX_CIDLEN];
    size_t datalen;
    int slot;
} magnus_quic_cid_entry_t;

static magnus_quic_connection_t magnus_quic_connections[MAGNUS_QUIC_MAX_CONNECTIONS];
static magnus_quic_cid_entry_t magnus_quic_cids[MAGNUS_QUIC_MAX_CIDS];
static SSL_CTX *magnus_quic_ssl_ctx;
static uint8_t magnus_quic_static_secret[32];
static bool magnus_quic_initialized;
/* Indexed by fd -- see MAGNUS_QUIC_MAX_FDS's own comment. Each entry's
 * magnus_quic_connection_t* lets an upstream fd event find its way back
 * to the QUIC connection whose flush()/writev_stream() calls actually
 * push the response onward, without needing a reverse map from stream
 * back to connection (magnus_quic_stream_t itself carries none). */
static magnus_quic_stream_t *magnus_quic_upstream_owner[MAGNUS_QUIC_MAX_FDS];
static magnus_quic_connection_t *magnus_quic_upstream_connection[MAGNUS_QUIC_MAX_FDS];
/* See magnus_quic_create_listener()'s own comment on why this is
 * cached rather than threaded through as a parameter everywhere. */
static int magnus_quic_listener_fd = -1;

/* --- small helpers ------------------------------------------------- */

static ngtcp2_tstamp
magnus_quic_timestamp(void)
{
    struct timespec ts;
    /* ngtcp2 only needs a monotonically increasing nanosecond counter
     * for its own internal RTT/timer math -- it never has to correlate
     * with wall-clock time, so CLOCK_MONOTONIC (not CLOCK_REALTIME) is
     * the right source, same reasoning as magnusd_wait_healthy()'s own
     * clock_gettime(CLOCK_MONOTONIC) fix (see feedback_* on that bug in
     * this project's history: fake/coarse pacing loops around real
     * timers are exactly the class of bug this avoids). */
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp) ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp) ts.tv_nsec;
}

/* A millisecond-resolution monotonic clock reading, same source and
 * shape as magnus.c's own (`static`) magnus_now_ms() -- kept as a
 * separate, un-exported local helper rather than one more symbol
 * threaded across src/magnus_static.h, since magnus_cluster_select()/
 * magnus_cluster_result() (roadmap 4d) only need *a* reasonable
 * monotonic ms clock, not the identical one magnus.c's own proxy path
 * happens to use -- same reasoning as MAGNUS_METRICS_BUFFER's own
 * local redefinition. */
static uint64_t
magnus_now_ms_local(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

/* `connection->remote_addr`'s own IPv4 address, or 0.0.0.0 for anything
 * else (this codebase's QUIC listener only ever binds IPv4 -- see
 * magnus_quic_create_listener() -- so the else branch is defensive, not
 * an expected-to-bite case) -- fed to magnus_cluster_select() (endpoint
 * selection) and MAGNUS_ROUTE_MATCH_SOURCE_CIDR route conditions
 * (roadmap 4f) alike, the one place this cast lives rather than
 * repeated at each of its own several call sites. */
static struct in_addr
magnus_quic_client_ip(const magnus_quic_connection_t *connection)
{
    struct in_addr client_ip;
    if (connection->remote_addr.ss_family == AF_INET)
        return ((const struct sockaddr_in *) &connection->remote_addr)->sin_addr;
    client_ip.s_addr = 0;
    return client_ip;
}

static int
magnus_quic_cid_find(const uint8_t *data, size_t datalen)
{
    size_t index;
    for (index = 0; index < MAGNUS_QUIC_MAX_CIDS; index++) {
        if (!magnus_quic_cids[index].in_use) continue;
        if (magnus_quic_cids[index].datalen == datalen
            && memcmp(magnus_quic_cids[index].data, data, datalen) == 0)
            return magnus_quic_cids[index].slot;
    }
    return -1;
}

static bool
magnus_quic_cid_register(const uint8_t *data, size_t datalen, int slot)
{
    size_t index;
    for (index = 0; index < MAGNUS_QUIC_MAX_CIDS; index++) {
        if (magnus_quic_cids[index].in_use) continue;
        magnus_quic_cids[index].in_use = true;
        memcpy(magnus_quic_cids[index].data, data, datalen);
        magnus_quic_cids[index].datalen = datalen;
        magnus_quic_cids[index].slot = slot;
        return true;
    }
    return false;
}

static void
magnus_quic_cid_remove(const uint8_t *data, size_t datalen)
{
    size_t index;
    for (index = 0; index < MAGNUS_QUIC_MAX_CIDS; index++) {
        if (!magnus_quic_cids[index].in_use) continue;
        if (magnus_quic_cids[index].datalen == datalen
            && memcmp(magnus_quic_cids[index].data, data, datalen) == 0) {
            magnus_quic_cids[index].in_use = false;
            return;
        }
    }
}

static void
magnus_quic_cid_remove_slot(int slot)
{
    size_t index;
    for (index = 0; index < MAGNUS_QUIC_MAX_CIDS; index++) {
        if (magnus_quic_cids[index].in_use
            && magnus_quic_cids[index].slot == slot)
            magnus_quic_cids[index].in_use = false;
    }
}

static int
magnus_quic_slot_alloc(void)
{
    int index;
    for (index = 0; index < MAGNUS_QUIC_MAX_CONNECTIONS; index++) {
        if (!magnus_quic_connections[index].in_use) return index;
    }
    return -1;
}

/* Forward declarations -- all defined with the rest of proxy dispatch
 * (roadmap 4d) further down; magnus_quic_http_stream_free(),
 * magnus_quic_tick(), magnus_quic_proxy_fail() (roadmap 4g's own
 * retry-on-connect-failure), and magnus_quic_proxy_receive_headers()
 * (roadmap 4i's own cache-revalidation branch) below all need one ahead
 * of that point in file order. */
static void magnus_quic_proxy_teardown_upstream(magnus_quic_stream_t *stream);
static void magnus_quic_proxy_tick(time_t now);
static void magnus_quic_flush(int listener_fd, int slot);
static int magnus_quic_proxy_connect_endpoint(
    magnus_quic_connection_t *connection, magnus_quic_stream_t *stream,
    size_t endpoint_index);
static void magnus_quic_submit_cached_response(
    magnus_quic_connection_t *connection, magnus_quic_stream_t *stream,
    magnus_cache_entry_t *entry, const char *x_cache_value);

/* Unmaps whatever magnus_quic_http_dispatch_static() mapped (if
 * anything -- a HEAD request or a zero-length file never map one) and
 * frees `stream` itself. The one place both the normal-completion path
 * (magnus_quic_stream_close(), the ngtcp2-level stream_close callback)
 * and the abnormal-teardown path (magnus_quic_slot_free()'s own sweep,
 * for a connection torn down mid-flight) reach to release a stream's
 * memory, so the two paths cannot drift out of sync with each other. */
static void
magnus_quic_http_stream_free(magnus_quic_stream_t *stream)
{
    if (stream->mmap_base) {
        if (stream->body_is_malloc) free(stream->mmap_base);
        else munmap(stream->mmap_base, stream->mmap_length);
    }
    /* Proxy dispatch (roadmap 4d): declared further down (defined after
     * this function in file order -- forward-declared here rather than
     * reordering every proxy function ahead of every static-file/
     * healthz/metrics one just to satisfy single-pass compilation).
     * A stream freed here mid-flight (client aborted, or the whole
     * connection is tearing down -- see magnus_quic_stream_close()'s
     * and magnus_quic_slot_free()'s own comments on the two paths that
     * reach this function) still needs its upstream leg, if any, torn
     * down the same as a clean completion would have. */
    if (stream->is_proxy) magnus_quic_proxy_teardown_upstream(stream);
    free(stream->header_buffer);
    free(stream->body_chunk);
    free(stream->proxy_request);
    free(stream->cache_capture); /* roadmap 4i */
    free(stream);
}

static void
magnus_quic_slot_free(int slot)
{
    magnus_quic_connection_t *connection = &magnus_quic_connections[slot];
    magnus_quic_cid_remove_slot(slot);
    /* nghttp3_conn_del() does not free the per-stream magnus_quic_stream_t
     * structs it holds as stream_user_data (nghttp3 has no idea that's
     * what they are) -- magnus_quic_stream_close() below normally frees
     * each one as its own stream closes, but a connection torn down
     * here mid-flight (an error path, not the ordinary one) can still
     * be holding some; ngtcp2_conn_get_stream_user_data() (queried, not
     * nghttp3's own equivalent -- see magnus_quic_http_begin_headers()'s
     * own comment on why the *ngtcp2*-level association is the portable
     * one here) has no "for each stream" form either, so this walks
     * every plausible client-initiated bidi stream id nghttp3's own
     * initial_max_streams_bidi (magnus_quic_accept_new()) could ever
     * have opened, freeing whichever ones are still non-NULL.
     * Client-initiated bidi stream ids are always of the form 4*n (RFC
     * 9000 2.1). */
    if (connection->http3_conn) {
        int64_t candidate;
        for (candidate = 0; candidate < MAGNUS_QUIC_MAX_BIDI_STREAMS * 4;
             candidate += 4) {
            void *stream_user_data =
                ngtcp2_conn_get_stream_user_data(connection->conn, candidate);
            if (stream_user_data)
                magnus_quic_http_stream_free(stream_user_data);
        }
        nghttp3_conn_del(connection->http3_conn);
    }
    if (connection->conn) ngtcp2_conn_del(connection->conn);
    if (connection->ossl_ctx) {
        SSL *ssl = ngtcp2_crypto_ossl_ctx_get_ssl(connection->ossl_ctx);
        if (ssl) {
            SSL_set_app_data(ssl, NULL);
            SSL_free(ssl);
        }
        ngtcp2_crypto_ossl_ctx_del(connection->ossl_ctx);
    }
    memset(connection, 0, sizeof(*connection));
}

/* --- ngtcp2 callbacks ------------------------------------------------ */

static ngtcp2_conn *
magnus_quic_get_conn(ngtcp2_crypto_conn_ref *ref)
{
    magnus_quic_connection_t *connection = ref->user_data;
    return connection->conn;
}

static void
magnus_quic_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
    (void) rand_ctx;
    /* Best-effort: RAND_bytes failing here (OpenSSL's own DRBG
     * exhausted/misconfigured) is not a case ngtcp2's rand callback
     * signature gives us any way to report -- it returns void. Falling
     * back to zeroed bytes on that (practically never hit) failure is
     * safer than leaving `dest` uninitialized; it is not a security
     * property (rand feeds jitter/randomization, not the handshake's
     * own key material -- that path is entirely inside crypto_ossl/
     * OpenSSL and unaffected by this callback). */
    if (RAND_bytes(dest, (int) destlen) != 1) memset(dest, 0, destlen);
}

static int
magnus_quic_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                  uint8_t *token, size_t cidlen,
                                  void *user_data)
{
    /* `user_data` is the same magnus_quic_connection_t* passed to
     * ngtcp2_conn_server_new() below, recovered here as a stable
     * pointer into the static table rather than a separately-threaded
     * slot index -- see the ngtcp2_conn_server_new() call site's own
     * comment on why that's the one consistent user_data type across
     * every per-connection callback in this file. */
    magnus_quic_connection_t *connection = user_data;
    int slot = (int) (connection - magnus_quic_connections);
    (void) conn;
    if (RAND_bytes(cid->data, (int) cidlen) != 1)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    cid->datalen = cidlen;
    if (ngtcp2_crypto_generate_stateless_reset_token(
            token, magnus_quic_static_secret,
            sizeof(magnus_quic_static_secret), cid) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    if (!magnus_quic_cid_register(cid->data, cid->datalen, slot))
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

static int
magnus_quic_remove_connection_id(ngtcp2_conn *conn, const ngtcp2_cid *cid,
                                 void *user_data)
{
    (void) conn;
    (void) user_data;
    magnus_quic_cid_remove(cid->data, cid->datalen);
    return 0;
}

static int
magnus_quic_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                             int64_t stream_id, uint64_t offset,
                             const uint8_t *data, size_t datalen,
                             void *user_data, void *stream_user_data)
{
    magnus_quic_connection_t *connection = user_data;
    (void) offset;
    (void) stream_user_data;
    if (connection->http3_conn) {
        nghttp3_ssize consumed = nghttp3_conn_read_stream(
            connection->http3_conn, stream_id, data, datalen,
            (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0);
        if (consumed < 0) {
            fprintf(stderr, "magnus: quic nghttp3_conn_read_stream: %s\n",
                   nghttp3_strerror((int) consumed));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        /* Flow-control credit for exactly `consumed`, not `datalen` --
         * matching the reference implementation exactly (see
         * Handler::recv_stream_data in the ngtcp2 examples this stack
         * was verified against, docs/phase4-spike-results.md). Any
         * portion nghttp3 did not consume this call (buffered pending
         * some other stream's own QPACK decoder dependency) must NOT
         * be credited yet -- it is still occupying nghttp3's own
         * receive buffer, so crediting it now would let the peer send
         * more than that buffer actually has room for. It gets
         * credited later, once actually consumed, via the recv_data/
         * deferred_consume nghttp3 callbacks below. */
        ngtcp2_conn_extend_max_stream_offset(conn, stream_id,
                                             (uint64_t) consumed);
        ngtcp2_conn_extend_max_offset(conn, (uint64_t) consumed);
        return 0;
    }
    /* No http3_conn yet (e.g. a 0-RTT-adjacent race before
     * magnus_quic_recv_tx_key() has run -- 4a never reaches this branch
     * at all since it never had one to begin with): drain flow control
     * only, same as 4a's own original behavior, rather than stalling
     * the peer. */
    ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(conn, datalen);
    return 0;
}

static int
magnus_quic_acked_stream_data_offset(ngtcp2_conn *conn, int64_t stream_id,
                                     uint64_t offset, uint64_t datalen,
                                     void *user_data, void *stream_user_data)
{
    magnus_quic_connection_t *connection = user_data;
    (void) conn;
    (void) offset;
    (void) stream_user_data;
    if (connection->http3_conn) {
        int rv = nghttp3_conn_add_ack_offset(connection->http3_conn, stream_id,
                                             datalen);
        if (rv != 0) {
            fprintf(stderr, "magnus: quic nghttp3_conn_add_ack_offset: %s\n",
                   nghttp3_strerror(rv));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }
    return 0;
}

static int
magnus_quic_extend_max_stream_data(ngtcp2_conn *conn, int64_t stream_id,
                                   uint64_t max_data, void *user_data,
                                   void *stream_user_data)
{
    magnus_quic_connection_t *connection = user_data;
    (void) conn;
    (void) max_data;
    (void) stream_user_data;
    if (connection->http3_conn) {
        int rv = nghttp3_conn_unblock_stream(connection->http3_conn, stream_id);
        if (rv != 0) {
            fprintf(stderr, "magnus: quic nghttp3_conn_unblock_stream: %s\n",
                   nghttp3_strerror(rv));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }
    return 0;
}

static int
magnus_quic_stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                         uint64_t app_error_code, void *user_data,
                         void *stream_user_data)
{
    magnus_quic_connection_t *connection = user_data;
    (void) conn;
    if (connection->http3_conn) {
        int rv;
        if ((flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) == 0)
            app_error_code = NGHTTP3_H3_NO_ERROR;
        rv = nghttp3_conn_close_stream(connection->http3_conn, stream_id,
                                       app_error_code);
        /* NGHTTP3_ERR_STREAM_NOT_FOUND is not an error worth reporting --
         * an idle/control stream ngtcp2 knows about that nghttp3 never
         * had reason to open its own state for. Anything else is
         * logged, not treated as fatal to the whole connection: one
         * misbehaving stream should not take the rest of it down. */
        if (rv != 0 && rv != NGHTTP3_ERR_STREAM_NOT_FOUND)
            fprintf(stderr, "magnus: quic nghttp3_conn_close_stream: %s\n",
                   nghttp3_strerror(rv));
        /* `stream_user_data` here is the *ngtcp2*-level association
         * (see magnus_quic_http_begin_headers()'s own comment on why
         * that, not nghttp3's own per-stream user data, is what this
         * callback receives) -- populated the moment a request stream's
         * headers begin, so this is non-NULL for exactly the streams
         * magnus_quic_http_dispatch_static() (or an early 400/404/500)
         * ever allocated a magnus_quic_stream_t for. Control/QPACK
         * streams (unidirectional, never registered this way) and a
         * request stream nghttp3 never got far enough into to call
         * begin_headers for both correctly leave this NULL. */
        if (stream_user_data)
            magnus_quic_http_stream_free(stream_user_data);
    }
    return 0;
}

static int
magnus_quic_handshake_completed(ngtcp2_conn *conn, void *user_data)
{
    magnus_quic_connection_t *connection = user_data;
    (void) conn;
    if (!connection->handshake_logged) {
        connection->handshake_logged = true;
        fprintf(stderr, "magnus: quic handshake confirmed\n");
    }
    return 0;
}

/* --- HTTP/3 (roadmap Phase 4b/4c, see magnus_quic.h) -------------------
 *
 * 4b scoped this the same way HTTP/2's own first increment (roadmap
 * 1e-1) was: static-file GET/HEAD only. 4c adds /healthz and /metrics
 * (roadmap 1e-4's own next increment on the h2 side) -- still no proxy
 * dispatch or compression over h3, which is what 1e-2 added on the h2
 * side and h3 can follow the same path for in a later increment rather
 * than trying to reach parity in one step. Reuses magnus.c's own
 * magnus_open_static()/magnus_content_type()/magnus_build_metrics()
 * (magnus_static.h) so every protocol agrees on path resolution/
 * traversal safety, MIME typing, and metrics content by construction,
 * the same reasoning magnus_h2_dispatch_static()'s own comment gives
 * for doing the same on the h2 side. */

static nghttp3_nv
magnus_quic_nv(const char *name, const char *value)
{
    return (nghttp3_nv) {
        .name = (const uint8_t *) name, .value = (const uint8_t *) value,
        .namelen = strlen(name), .valuelen = strlen(value),
        .flags = NGHTTP3_NV_FLAG_NONE,
    };
}

static void
magnus_quic_http_submit_status(magnus_quic_connection_t *connection,
                               magnus_quic_stream_t *stream, const char *status)
{
    nghttp3_nv headers[2] = {
        magnus_quic_nv(":status", status),
        magnus_quic_nv("server", "Magnus/" MAGNUS_VERSION),
    };
    (void) nghttp3_conn_submit_response(connection->http3_conn,
                                        stream->stream_id, headers, 2, NULL);
}

static nghttp3_ssize
magnus_quic_http_read_file(nghttp3_conn *conn, int64_t stream_id,
                           nghttp3_vec *vec, size_t veccnt, uint32_t *pflags,
                           void *conn_user_data, void *stream_user_data)
{
    magnus_quic_stream_t *stream = stream_user_data;
    (void) conn;
    (void) stream_id;
    (void) veccnt;
    (void) conn_user_data;
    /* The whole body in one vec, EOF immediately -- whatever
     * stream->mmap_base/mmap_length currently point at (a static
     * file's mmap, roadmap 4b, or a /healthz//metrics malloc()ed copy,
     * roadmap 4c -- magnus_quic_stream_t's own comment on
     * body_is_malloc has the full story on why one pair of fields
     * covers both). A zero-length body is valid input (vec.len 0, base
     * non-NULL or NULL) and nghttp3 handles it correctly as "no body". */
    vec[0].base = stream->mmap_base;
    vec[0].len = stream->mmap_length;
    *pflags |= NGHTTP3_DATA_FLAG_EOF;
    return 1;
}

/* /healthz and /metrics (roadmap 4c): `body` is copied into a malloc()ed
 * buffer that outlives this call (unlike the caller's own stack buffer
 * for /metrics -- magnus_build_metrics() writes into one that does not),
 * reusing magnus_quic_http_read_file() as the data-reader exactly like
 * the static-file path does, just over a copy instead of an mmap. */
static void
magnus_quic_http_submit_text(magnus_quic_connection_t *connection,
                             magnus_quic_stream_t *stream, const char *status,
                             const char *content_type, const char *body)
{
    size_t length = strlen(body);
    char content_length[32];
    nghttp3_nv headers[4];

    snprintf(content_length, sizeof(content_length), "%zu", length);
    headers[0] = magnus_quic_nv(":status", status);
    headers[1] = magnus_quic_nv("server", "Magnus/" MAGNUS_VERSION);
    headers[2] = magnus_quic_nv("content-type", content_type);
    headers[3] = magnus_quic_nv("content-length", content_length);
    if (stream->head_only) {
        (void) nghttp3_conn_submit_response(connection->http3_conn,
                                            stream->stream_id, headers, 4,
                                            NULL);
        return;
    }
    if (length > 0) {
        stream->mmap_base = malloc(length);
        if (stream->mmap_base == NULL) {
            magnus_quic_http_submit_status(connection, stream, "500");
            return;
        }
        memcpy(stream->mmap_base, body, length);
        stream->mmap_length = length;
        stream->body_is_malloc = true;
    }
    {
        nghttp3_data_reader reader = { .read_data = magnus_quic_http_read_file };
        (void) nghttp3_conn_submit_response(connection->http3_conn,
                                            stream->stream_id, headers, 4,
                                            &reader);
    }
}

/* --- HTTP/3 proxy dispatch (roadmap Phase 4d) --------------------------
 *
 * A literal "/proxy" path prefix relayed to the same plain
 * magnus_cluster every HTTP/1.1 and HTTP/2 "/proxy" request already
 * uses (src/magnus_static.h), translated into an HTTP/1.1 request and
 * back via magnus_proxy_sanitize_response_headers() -- the exact same
 * hop-by-hop-stripping/framing logic every other protocol's own proxy
 * path already shares, so no protocol can drift into forwarding a
 * response differently from the others.
 *
 * Deliberately its own narrower first increment, the same "narrow the
 * first cut, extend later" call every other new protocol surface in
 * this codebase has made (Phase 1e's own HTTP/2 work, Phase 3's L4
 * work, and 4a/4b/4c immediately before this): a single attempt against
 * one selected endpoint (no retry budget), a fresh connection every
 * time (no magnus_upstream_pool reuse), no session affinity cookie, no
 * response caching. GET/HEAD only -- magnus_quic_http_dispatch()'s own
 * method validation already guarantees that by the time this runs, so
 * no request body relay is needed either. Each of those is a real,
 * separately-scoped later increment, not silently missing. */

static char *
magnus_quic_proxy_find_header_end(char *buffer, size_t length)
{
    size_t index;
    for (index = 3; index < length; index++) {
        if (buffer[index - 3] == '\r' && buffer[index - 2] == '\n'
            && buffer[index - 1] == '\r' && buffer[index] == '\n')
            return &buffer[index + 1];
    }
    return NULL;
}

/* Appends `data`/`len` to stream->cache_capture (growable, doubling,
 * bounded by MAGNUS_CACHE_MAX_ENTRY_BYTES) -- the h3 analogue of
 * magnus_h2_proxy_cache_capture(), same shape exactly. A no-op once
 * cache_capture_overflowed is already true (or on this call's own
 * allocation failure, which sets it) -- capture is always a pure,
 * silently-declinable side observation of a response this stream is
 * relaying to the client regardless, so its failure must never affect
 * (or even be visible to) the normal relay path at all. */
static void
magnus_quic_proxy_cache_capture(magnus_quic_stream_t *stream,
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
            ? MAGNUS_QUIC_PROXY_BUFFER : stream->cache_capture_capacity * 2;
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

static void
magnus_quic_proxy_teardown_upstream(magnus_quic_stream_t *stream)
{
    if (stream->upstream_fd < 0) return;
    epoll_ctl(magnus_global_epoll_fd, EPOLL_CTL_DEL, stream->upstream_fd, NULL);
    magnus_quic_upstream_owner[stream->upstream_fd] = NULL;
    magnus_quic_upstream_connection[stream->upstream_fd] = NULL;
    close(stream->upstream_fd);
    stream->upstream_fd = -1;
    if (stream->cluster_endpoint_counted) {
        magnus_cluster_endpoint_end(&magnus_cluster, stream->endpoint_index);
        stream->cluster_endpoint_counted = false;
    }
}

/* Ends a proxy-dispatched stream before any response headers have gone
 * out -- the h3 analogue of magnus_h2_proxy_fail()/magnus_proxy_fail().
 * Every call site here is, by this function's own contract, a pre-header
 * failure (connect refused/timed out, a mid-request send() error, a
 * malformed/oversized/unparseable upstream response, an upstream read
 * timeout) -- exactly the class magnus_proxy_connect_failed()'s own
 * centralized magnus_cluster_result(false) call covers for h1, and
 * magnus_h2_proxy_fail()/magnus_h2_proxy_connect_failed() covers for
 * h2. Recording the failure here, once, keeps every one of this
 * function's callers from having to remember to do it themselves --
 * the gap this comment used to describe before roadmap 4g (found live:
 * a killed upstream correctly produced its 502 but never actually
 * degraded /metrics' own magnus_upstream_healthy, since only the
 * *synchronous* connect()-failed branch recorded a failure -- the far
 * more common asynchronous EINPROGRESS-then-EPOLLOUT failure path here
 * never did). A stream that already reached
 * magnus_quic_proxy_receive_headers() successfully has already recorded
 * its own success (see that function's own magnus_cluster_result(true)
 * call) before any of *this* function's callers can run, so there is no
 * double-counting risk from always recording a failure here.
 *
 * Roadmap 4g: also retries against a freshly-selected endpoint, bounded
 * by MAGNUS_QUIC_PROXY_MAX_ATTEMPTS total attempts, exactly the same
 * shape magnus_h2_proxy_connect_failed()'s own retry has -- this is the
 * *asynchronous*-failure counterpart to magnus_quic_proxy_start()'s own
 * synchronous-failure retry loop, so between the two, every pre-header
 * failure this stream can hit gets the same retry budget regardless of
 * which stage detected it. Every accumulated per-attempt field
 * (header_accum/headers_received/proxy_request_sent/
 * upstream_headers_sent) is reset before the retry connect -- stale
 * from the failed attempt, and magnus_quic_proxy_teardown_upstream()
 * itself does not touch them (it only ever closes the fd and stops
 * counting this stream against the endpoint's own active_requests). */
static void
magnus_quic_proxy_fail(magnus_quic_connection_t *connection,
                       magnus_quic_stream_t *stream, const char *status)
{
    magnus_cluster_result(&magnus_cluster, stream->endpoint_index, false,
                          magnus_now_ms_local());
    magnus_quic_proxy_teardown_upstream(stream);
    if (stream->attempt < MAGNUS_QUIC_PROXY_MAX_ATTEMPTS) {
        int endpoint = magnus_cluster_select(&magnus_cluster,
                                             magnus_now_ms_local(), NULL,
                                             magnus_quic_client_ip(connection));
        if (endpoint >= 0) {
            stream->attempt++;
            stream->header_accum = 0;
            stream->headers_received = false;
            stream->proxy_request_sent = 0;
            stream->upstream_headers_sent = false;
            if (magnus_quic_proxy_connect_endpoint(connection, stream,
                                                   (size_t) endpoint) == 0) {
                /* Deviated from whatever selection produced the failed
                 * attempt (roadmap 4h, matching
                 * magnus_h2_proxy_connect_failed()'s identical
                 * unconditional refresh here): the cookie must reflect
                 * the endpoint actually used now, not the one that just
                 * failed. */
                stream->issue_affinity_cookie = true;
                magnus_encode_affinity_cookie(stream->affinity_key,
                                              sizeof(stream->affinity_key),
                                              (size_t) endpoint);
                return;
            }
            magnus_cluster_result(&magnus_cluster, (size_t) endpoint, false,
                                  magnus_now_ms_local());
        }
    }
    magnus_quic_http_submit_status(connection, stream, status);
}

/* Ends a proxy-dispatched stream after response headers were already
 * submitted -- no fresh status is possible any more (same reasoning as
 * magnus_h2_proxy_abort()), so the stream's write side is shut down
 * abruptly instead; the client sees this as a truncated response, the
 * same as an abruptly closed HTTP/1.1 connection mid-body. */
static void
magnus_quic_proxy_abort(magnus_quic_connection_t *connection,
                        magnus_quic_stream_t *stream)
{
    magnus_quic_proxy_teardown_upstream(stream);
    (void) ngtcp2_conn_shutdown_stream_write(connection->conn, 0,
                                             stream->stream_id,
                                             NGHTTP3_H3_INTERNAL_ERROR);
}

static int
magnus_quic_proxy_attach_upstream(magnus_quic_connection_t *connection,
                                  magnus_quic_stream_t *stream,
                                  size_t endpoint_index, int fd)
{
    struct epoll_event event;
    if (fd < 0 || fd >= MAGNUS_QUIC_MAX_FDS) {
        if (fd >= 0) close(fd);
        return -1;
    }
    stream->upstream_fd = fd;
    stream->upstream_connected = false;
    stream->endpoint_index = endpoint_index;
    magnus_cluster_endpoint_begin(&magnus_cluster, endpoint_index);
    stream->cluster_endpoint_counted = true;
    stream->connect_started = time(NULL);
    stream->last_activity = stream->connect_started;
    magnus_quic_upstream_owner[fd] = stream;
    magnus_quic_upstream_connection[fd] = connection;
    event = (struct epoll_event) { .events = EPOLLOUT | EPOLLRDHUP,
                                   .data.fd = fd };
    if (epoll_ctl(magnus_global_epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        magnus_quic_upstream_owner[fd] = NULL;
        magnus_quic_upstream_connection[fd] = NULL;
        close(fd);
        stream->upstream_fd = -1;
        return -1;
    }
    return 0;
}

static int
magnus_quic_proxy_connect_endpoint(magnus_quic_connection_t *connection,
                                   magnus_quic_stream_t *stream,
                                   size_t endpoint_index)
{
    struct sockaddr_in address;
    int fd;
    int result;

    if (!magnus_endpoint_sockaddr(endpoint_index, &address)) return -1;
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0 || fd >= MAGNUS_QUIC_MAX_FDS) {
        if (fd >= 0) close(fd);
        return -1;
    }
    result = connect(fd, (struct sockaddr *) &address, sizeof(address));
    if (result < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    if (magnus_quic_proxy_attach_upstream(connection, stream, endpoint_index,
                                          fd) != 0)
        return -1;
    if (result == 0) stream->upstream_connected = true;
    return 0;
}

/* nghttp3 read_data callback for a proxy-dispatched stream's response
 * body -- hands off stream->body_chunk *once* (see magnus_quic_stream_t's
 * own comment on why one chunk at a time, freed only once acked, rather
 * than a reused buffer). Returns NGHTTP3_ERR_WOULDBLOCK, per nghttp3's
 * own documented contract for this callback, whenever there is no
 * not-yet-offered chunk but the response is not known complete yet --
 * magnus_quic_proxy_stream_response() calls nghttp3_conn_resume_stream()
 * the next time it actually offers a new one. */
static nghttp3_ssize
magnus_quic_proxy_read_body(nghttp3_conn *conn, int64_t stream_id,
                            nghttp3_vec *vec, size_t veccnt, uint32_t *pflags,
                            void *conn_user_data, void *stream_user_data)
{
    magnus_quic_stream_t *stream = stream_user_data;
    (void) conn;
    (void) stream_id;
    (void) veccnt;
    (void) conn_user_data;
    if (stream->body_chunk != NULL && !stream->body_chunk_offered) {
        vec[0].base = stream->body_chunk;
        vec[0].len = stream->body_chunk_length;
        stream->body_chunk_offered = true;
        stream->body_offered_total += stream->body_chunk_length;
        stream->body_chunk_end_offset = stream->body_offered_total;
        if (stream->response_complete) *pflags |= NGHTTP3_DATA_FLAG_EOF;
        return 1;
    }
    if (stream->body_chunk == NULL && stream->response_complete) {
        *pflags |= NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    stream->nghttp3_wants_resume = true;
    return NGHTTP3_ERR_WOULDBLOCK;
}

/* Converts a magnus_proxy_sanitize_response_headers() text block into
 * HTTP/3 response headers and submits them -- the h3 analogue of
 * magnus_h2_proxy_submit_response(), same reasoning for dropping the
 * `Connection` header sanitize always appends (forbidden by RFC 9114
 * 4.2 the same way RFC 9113 8.2.2 forbids it for h2; an h3 stream's
 * lifetime is governed by its own FIN/reset, not a client-facing
 * keep-alive/close choice per response) and lowercasing every other
 * field name (an HTTP/1.x upstream's casing is not guaranteed to
 * already be, and both h2 and h3 field names must be). */
static void
magnus_quic_proxy_submit_response(magnus_quic_connection_t *connection,
                                  magnus_quic_stream_t *stream,
                                  unsigned status, char *sanitized)
{
    nghttp3_nv headers[24];
    char name_storage[24][64];
    size_t count = 0;
    char status_text[8];
    char *saveptr = NULL;
    char *line;
    nghttp3_data_reader reader = { .read_data = magnus_quic_proxy_read_body };

    snprintf(status_text, sizeof(status_text), "%u", status);
    headers[count] = magnus_quic_nv(":status", status_text);
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
        headers[count] = magnus_quic_nv(name_storage[count], value);
        count++;
    }

    stream->response_headers_submitted = true;
    (void) nghttp3_conn_submit_response(connection->http3_conn,
                                        stream->stream_id, headers, count,
                                        &reader);
}

/* Once the response is known fully received (Content-Length reached, or
 * the upstream closed), tears the upstream leg down -- no pool to check
 * into in this increment, see this section's own top comment -- and
 * marks response_complete so magnus_quic_proxy_read_body() knows it is
 * safe to report EOF once stream->body_chunk finishes draining. */
static void
magnus_quic_proxy_maybe_complete(magnus_quic_connection_t *connection,
                                 magnus_quic_stream_t *stream)
{
    bool complete_by_length = stream->has_response_length
        && stream->response_received >= stream->response_length;
    if (!stream->upstream_eof && !complete_by_length) return;
    stream->response_complete = true;
    /* Reverse-proxy cache (roadmap 4i): commits the captured body now
     * that the whole response is known complete -- before
     * magnus_quic_proxy_teardown_upstream() below, which does not touch
     * stream->cache_capture itself but this is still the natural,
     * single place every completion path (Content-Length reached or
     * upstream EOF) passes through, matching
     * magnus_h2_proxy_maybe_complete()'s own identical placement. */
    if (stream->cache_this_response_cacheable
        && !stream->cache_capture_overflowed) {
        magnus_cache_store(stream->cache_host, stream->cache_target, 200,
            stream->cache_pending_headers, stream->cache_pending_headers_length,
            stream->cache_capture, stream->cache_capture_length,
            stream->cache_response_etag, stream->cache_response_last_modified,
            &stream->cache_freshness);
    }
    magnus_quic_proxy_teardown_upstream(stream);
    if (stream->nghttp3_wants_resume) {
        stream->nghttp3_wants_resume = false;
        (void) nghttp3_conn_resume_stream(connection->http3_conn,
                                          stream->stream_id);
    }
}

/* The h3 analogue of magnus_h2_proxy_receive_headers(): accumulates the
 * upstream response's status line + header block into stream->header_buffer
 * (may arrive split across several recv() calls), then rewrites it via
 * magnus_proxy_sanitize_response_headers() once the terminating blank
 * line is found and submits it as this stream's h3 response. Leftover
 * bytes already read past the header block become the first chunk of
 * body. Returns true once headers were fully received (whether the
 * outcome was a clean submit or a failure this stream is now done
 * for), false while still waiting for more. */
static bool
magnus_quic_proxy_receive_headers(magnus_quic_connection_t *connection,
                                  magnus_quic_stream_t *stream)
{
    char *body_start;
    size_t header_length;
    size_t leftover;
    char header_copy[MAGNUS_QUIC_PROXY_HEADER_LIMIT + 1];
    char sanitized[MAGNUS_QUIC_PROXY_SANITIZED_LIMIT];
    magnus_proxy_response_info_t info;
    int sanitized_length;

    while (stream->header_accum < MAGNUS_QUIC_PROXY_HEADER_LIMIT) {
        ssize_t received = recv(stream->upstream_fd,
            stream->header_buffer + stream->header_accum,
            MAGNUS_QUIC_PROXY_HEADER_LIMIT - stream->header_accum, 0);
        if (received > 0) {
            stream->header_accum += (size_t) received;
            stream->last_activity = time(NULL);
            if (magnus_quic_proxy_find_header_end(stream->header_buffer,
                                                  stream->header_accum)
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
        magnus_quic_proxy_fail(connection, stream, "502");
        return true;
    }

    body_start = magnus_quic_proxy_find_header_end(stream->header_buffer,
                                                    stream->header_accum);
    if (body_start == NULL) {
        if (stream->upstream_eof
            || stream->header_accum == MAGNUS_QUIC_PROXY_HEADER_LIMIT) {
            magnus_quic_proxy_fail(connection, stream, "502");
            return true;
        }
        return false;
    }

    header_length = (size_t) (body_start - stream->header_buffer);
    leftover = stream->header_accum - header_length;
    memcpy(header_copy, stream->header_buffer, header_length);
    header_copy[header_length] = '\0';
    {
        size_t cacheable_prefix_length;
        sanitized_length = magnus_proxy_sanitize_response_headers(header_copy,
            header_length, sanitized, sizeof(sanitized),
            stream->issue_affinity_cookie ? stream->affinity_key : NULL
            /* roadmap 4h: emits the MAGNUS_AFFINITY Set-Cookie line
             * itself when non-NULL, the same shared code path h1/h2
             * proxy dispatch already use -- see magnus_quic_stream_t's
             * own comment on issue_affinity_cookie/affinity_key. */,
            true /* client_wants_close: N/A for h3, same reasoning as h2
                  * -- see magnus_quic_proxy_submit_response()'s own
                  * comment on why the Connection header this produces
                  * is dropped either way */, &info,
            &cacheable_prefix_length /* roadmap 4i: bytes of `sanitized`
                                       * that are safe for
                                       * magnus_cache_store() -- see
                                       * this parameter's own doc
                                       * comment in magnus_proxy.h for
                                       * exactly what it excludes and
                                       * why. */);
        if (sanitized_length < 0) {
            magnus_quic_proxy_fail(connection, stream, "502");
            return true;
        }

        magnus_cluster_result(&magnus_cluster, stream->endpoint_index, true,
                              magnus_now_ms_local());

        /* Reverse-proxy cache revalidation (roadmap 4i): a 304 from the
         * upstream in response to the conditional GET
         * magnus_quic_proxy_start() built -- refresh the stored entry's
         * freshness window and serve it, exactly like
         * magnus_h2_proxy_receive_headers()'s own identical branch (see
         * its own comment on why nothing left to honestly answer with
         * if the entry vanished between this attempt starting and the
         * 304 arriving). */
        if (stream->cache_revalidating && info.status == 304) {
            magnus_cache_entry_t *entry;
            magnus_quic_proxy_teardown_upstream(stream);
            entry = magnus_cache_lookup(stream->cache_host,
                                        stream->cache_target);
            if (entry != NULL) {
                magnus_cache_freshness_t freshness;
                magnus_cache_compute_freshness(
                    info.cache_control[0] != '\0' ? info.cache_control : NULL,
                    info.expires[0] != '\0' ? info.expires : NULL, NULL,
                    false, magnus_cache_now_ms(), &freshness);
                magnus_cache_revalidated(entry, &freshness);
                magnus_quic_submit_cached_response(connection, stream, entry,
                                                   "REVALIDATED");
                return true;
            }
            magnus_quic_http_submit_status(connection, stream, "502");
            return true;
        }

        /* Decided once, right here, the moment headers (and therefore
         * Cache-Control/Expires/Vary/Set-Cookie/status) are known --
         * see magnus_h2_proxy_receive_headers()'s own identical
         * comment. */
        if (stream->cache_enabled && info.status == 200) {
            magnus_cache_compute_freshness(
                info.cache_control[0] != '\0' ? info.cache_control : NULL,
                info.expires[0] != '\0' ? info.expires : NULL,
                info.vary[0] != '\0' ? info.vary : NULL, info.has_set_cookie,
                magnus_cache_now_ms(), &stream->cache_freshness);
            stream->cache_this_response_cacheable
                = stream->cache_freshness.cacheable;
        }
        if (stream->cache_this_response_cacheable) {
            memcpy(stream->cache_pending_headers, sanitized,
                  cacheable_prefix_length);
            stream->cache_pending_headers_length = cacheable_prefix_length;
            strcpy(stream->cache_response_etag, info.etag);
            strcpy(stream->cache_response_last_modified,
                  info.last_modified);
        }
    }

    if (info.has_content_length && leftover > info.content_length)
        leftover = info.content_length;
    if (stream->cache_this_response_cacheable)
        magnus_quic_proxy_cache_capture(stream, body_start, leftover);
    if (leftover > 0) {
        /* stream->body_chunk is necessarily NULL here (this is the
         * very first body data this stream has ever seen) -- see
         * magnus_quic_stream_t's own comment on why a fresh allocation
         * per chunk, not a reused buffer. */
        stream->body_chunk = malloc(leftover);
        if (stream->body_chunk == NULL) {
            magnus_quic_proxy_fail(connection, stream, "502");
            return true;
        }
        memcpy(stream->body_chunk, body_start, leftover);
        stream->body_chunk_length = leftover;
    }
    stream->headers_received = true;
    stream->upstream_poolable = info.upstream_poolable;
    stream->has_response_length = info.has_content_length;
    stream->response_length = info.content_length;
    stream->response_received = leftover;

    magnus_quic_proxy_submit_response(connection, stream, info.status,
                                      sanitized);
    magnus_quic_proxy_maybe_complete(connection, stream);
    return true;
}

/* Keeps stream->body_chunk filled from the upstream socket for
 * magnus_quic_proxy_read_body() to pull from, once headers are already
 * submitted -- respecting backpressure (never reads more while a chunk
 * is still outstanding -- offered-but-unacked or not yet even offered,
 * either way magnus_quic_stream_t's own body_chunk field is non-NULL,
 * see its own comment for why *this* backpressure gate, not "nghttp3
 * has not pulled it out yet", is the correct one here) and never
 * reading past a declared Content-Length, exactly the same shape as
 * magnus_h2_proxy_stream_response() minus the reused-buffer part. */
static void
magnus_quic_proxy_stream_response(magnus_quic_connection_t *connection,
                                  magnus_quic_stream_t *stream)
{
    size_t want;
    ssize_t received;
    uint8_t buffer[MAGNUS_QUIC_PROXY_BUFFER];

    if (stream->body_chunk != NULL) return; /* backpressure */
    want = sizeof(buffer);
    if (stream->has_response_length) {
        size_t remaining = stream->response_length - stream->response_received;
        if (remaining < want) want = remaining;
    }
    if (want == 0) {
        magnus_quic_proxy_maybe_complete(connection, stream);
        return;
    }
    received = recv(stream->upstream_fd, buffer, want, 0);
    if (received > 0) {
        stream->body_chunk = malloc((size_t) received);
        if (stream->body_chunk == NULL) {
            magnus_quic_proxy_abort(connection, stream);
            return;
        }
        memcpy(stream->body_chunk, buffer, (size_t) received);
        stream->body_chunk_length = (size_t) received;
        stream->response_received += (size_t) received;
        stream->last_activity = time(NULL);
        if (stream->cache_this_response_cacheable)
            magnus_quic_proxy_cache_capture(stream, (const char *) buffer,
                                            (size_t) received);
        if (stream->nghttp3_wants_resume) {
            stream->nghttp3_wants_resume = false;
            (void) nghttp3_conn_resume_stream(connection->http3_conn,
                                              stream->stream_id);
        }
        magnus_quic_proxy_maybe_complete(connection, stream);
        return;
    }
    if (received == 0) {
        stream->upstream_eof = true;
        magnus_quic_proxy_maybe_complete(connection, stream);
        return;
    }
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return;
    magnus_quic_proxy_abort(connection, stream);
}

/* Called once per magnus_quic_tick()'s own per-second sweep (this
 * codebase's existing cadence for every other periodic timeout check):
 * connect and read timeouts for every proxy-dispatched stream currently
 * holding an upstream fd open, the same two bounds
 * MAGNUS_PROXY_CONNECT_TIMEOUT_SECONDS/MAGNUS_PROXY_READ_TIMEOUT_SECONDS
 * already enforce for HTTP/1.1 and HTTP/2 -- without this, a stuck
 * upstream would hold *this one stream* open indefinitely (not the
 * whole process -- every other connection/stream stays fine, this is
 * single-threaded epoll -- but still a real, user-visible hang this
 * increment should not ship without). Walks
 * magnus_quic_upstream_owner[] directly (bounded, only ever as many
 * live entries as there are concurrent proxy attempts) rather than
 * every QUIC connection's own stream set, which magnus_quic.c has no
 * enumerable list of at all (nghttp3 owns that). */
static void
magnus_quic_proxy_tick(time_t now)
{
    int fd;
    for (fd = 0; fd < MAGNUS_QUIC_MAX_FDS; fd++) {
        magnus_quic_stream_t *stream = magnus_quic_upstream_owner[fd];
        magnus_quic_connection_t *connection;
        if (stream == NULL) continue;
        connection = magnus_quic_upstream_connection[fd];
        if (!stream->upstream_connected
            && now - stream->connect_started
                   >= MAGNUS_QUIC_PROXY_CONNECT_TIMEOUT_SECONDS) {
            magnus_quic_proxy_fail(connection, stream, "504");
        } else if (stream->upstream_connected
                  && now - stream->last_activity
                         >= MAGNUS_QUIC_PROXY_READ_TIMEOUT_SECONDS) {
            if (stream->response_headers_submitted)
                magnus_quic_proxy_abort(connection, stream);
            else
                magnus_quic_proxy_fail(connection, stream, "504");
        } else {
            continue;
        }
        magnus_quic_flush(magnus_quic_listener_fd,
                          (int) (connection - magnus_quic_connections));
    }
}

/* Entry point for any epoll event on a proxy-dispatched stream's
 * upstream fd -- the h3 analogue of magnus_h2_handle_upstream(). */
static void
magnus_quic_proxy_handle_upstream(magnus_quic_connection_t *connection,
                                  magnus_quic_stream_t *stream, uint32_t flags)
{
    int slot = (int) (connection - magnus_quic_connections);

    if ((flags & (EPOLLERR | EPOLLHUP)) != 0) {
        if (stream->response_headers_submitted)
            magnus_quic_proxy_abort(connection, stream);
        else
            magnus_quic_proxy_fail(connection, stream, "502");
        magnus_quic_flush(magnus_quic_listener_fd, slot);
        return;
    }
    if (!stream->upstream_connected) {
        int error = 0;
        socklen_t length = sizeof(error);
        if (getsockopt(stream->upstream_fd, SOL_SOCKET, SO_ERROR, &error,
                       &length) < 0 || error != 0) {
            magnus_quic_proxy_fail(connection, stream, "502");
            magnus_quic_flush(magnus_quic_listener_fd, slot);
            return;
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
            return;
        } else {
            magnus_quic_proxy_fail(connection, stream, "502");
            magnus_quic_flush(magnus_quic_listener_fd, slot);
            return;
        }
        if (stream->proxy_request_sent == stream->proxy_request_length)
            stream->upstream_headers_sent = true;
    }
    if (!stream->headers_received) {
        if ((flags & (EPOLLIN | EPOLLRDHUP)) != 0) {
            if (!magnus_quic_proxy_receive_headers(connection, stream)) {
                struct epoll_event event = { .events = EPOLLIN | EPOLLRDHUP,
                                             .data.fd = stream->upstream_fd };
                epoll_ctl(magnus_global_epoll_fd, EPOLL_CTL_MOD,
                         stream->upstream_fd, &event);
                return;
            }
        } else {
            struct epoll_event event = { .events = EPOLLIN | EPOLLRDHUP,
                                         .data.fd = stream->upstream_fd };
            epoll_ctl(magnus_global_epoll_fd, EPOLL_CTL_MOD, stream->upstream_fd,
                     &event);
            magnus_quic_flush(magnus_quic_listener_fd, slot);
            return;
        }
    } else if ((flags & (EPOLLIN | EPOLLRDHUP)) != 0) {
        magnus_quic_proxy_stream_response(connection, stream);
    }
    magnus_quic_flush(magnus_quic_listener_fd, slot);
}

/* Entry point from magnus.c's main epoll loop for any event on a fd
 * magnus_quic_upstream_owner[] recognizes -- returns false (nothing
 * handled) for any other fd, so the caller falls through to its own
 * next check exactly like every other *_owner[]-dispatched handler
 * there already does. */
bool
magnus_quic_handle_upstream_event(int fd, uint32_t flags)
{
    magnus_quic_stream_t *stream;
    magnus_quic_connection_t *connection;
    if (fd < 0 || fd >= MAGNUS_QUIC_MAX_FDS) return false;
    stream = magnus_quic_upstream_owner[fd];
    if (stream == NULL) return false;
    connection = magnus_quic_upstream_connection[fd];
    magnus_quic_proxy_handle_upstream(connection, stream, flags);
    return true;
}

/* Serves a stored cache entry directly, never touching the upstream at
 * all -- the h3 analogue of magnus_h2_submit_cached_response(), same
 * shape exactly (its own header-line tokenizer duplicated here rather
 * than shared, matching magnus_quic_proxy_submit_response()'s own
 * pre-existing near-identical copy for the same reason: nghttp3_nv and
 * nghttp2_nv are different types, so nothing about the loop itself is
 * actually shareable). `x_cache_value` is "HIT" (a fresh entry found
 * at dispatch time) or "REVALIDATED" (a stale entry the upstream just
 * confirmed via 304) -- magnus_quic_http_dispatch()'s and
 * magnus_quic_proxy_receive_headers()'s own two call sites. The body
 * is copied into a fresh malloc()ed buffer and handed to nghttp3 via
 * magnus_quic_http_read_file() exactly like /healthz//metrics (4c) and
 * compressed static files (4e) already reuse it for -- see
 * body_is_malloc's own comment on why one pair of fields covers every
 * non-mmap body shape. */
static void
magnus_quic_submit_cached_response(magnus_quic_connection_t *connection,
                                   magnus_quic_stream_t *stream,
                                   magnus_cache_entry_t *entry,
                                   const char *x_cache_value)
{
    const char *entry_headers, *entry_body, *etag, *last_modified;
    size_t entry_headers_length, entry_body_length;
    nghttp3_nv headers[24];
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
        magnus_quic_http_submit_status(connection, stream, "500");
        return;
    }
    memcpy(copy, entry_headers, entry_headers_length);
    copy[entry_headers_length] = '\0';

    snprintf(status_text, sizeof(status_text), "%u",
            magnus_cache_entry_status(entry));
    headers[count] = magnus_quic_nv(":status", status_text);
    count++;
    headers[count] = magnus_quic_nv("server", "Magnus/" MAGNUS_VERSION);
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
        headers[count] = magnus_quic_nv(name_storage[count], value);
        count++;
    }
    /* NOT freed until after nghttp3_conn_submit_response() below --
     * each header's *value* (unlike its name, already copied into
     * name_storage) is still a pointer straight into `copy`.
     * nghttp3_conn_submit_response() copies every name/value out
     * synchronously within the call (magnus_quic_proxy_submit_response()'s
     * own identical pattern, passing a *stack*-local buffer with no
     * explicit lifetime management at all, is the proof this is safe --
     * were that not true, that pre-existing, already-ASan-verified code
     * would itself be a dangling-pointer bug). */

    if (count < sizeof(headers) / sizeof(headers[0])) {
        snprintf(content_length_text, sizeof(content_length_text), "%zu",
                entry_body_length);
        headers[count] = magnus_quic_nv("content-length", content_length_text);
        count++;
    }
    if (count < sizeof(headers) / sizeof(headers[0])) {
        headers[count] = magnus_quic_nv("x-cache", x_cache_value);
        count++;
    }

    if (stream->head_only) {
        free(copy);
        (void) nghttp3_conn_submit_response(connection->http3_conn,
                                            stream->stream_id, headers,
                                            count, NULL);
        return;
    }
    if (entry_body_length > 0) {
        stream->mmap_base = malloc(entry_body_length);
        if (stream->mmap_base == NULL) {
            free(copy);
            magnus_quic_http_submit_status(connection, stream, "500");
            return;
        }
        memcpy(stream->mmap_base, entry_body, entry_body_length);
        stream->mmap_length = entry_body_length;
        stream->body_is_malloc = true;
    }
    {
        nghttp3_data_reader reader = { .read_data = magnus_quic_http_read_file };
        (void) nghttp3_conn_submit_response(connection->http3_conn,
                                            stream->stream_id, headers,
                                            count, &reader);
    }
    free(copy);
}

/* Entry point from magnus_quic_http_dispatch() below: reverse-proxy
 * cache lookup (roadmap 4i, only for `cache_route_enabled` routes and
 * GET requests -- see magnus_h2_proxy_start()'s own identical logic
 * for the full rationale) first, since a fresh HIT never touches the
 * upstream at all; a stale-but-still-validator-bearing entry drives a
 * conditional GET instead. Then builds the outbound HTTP/1.1 proxy
 * request (an h3 analogue of magnus_proxy_pick_and_start()'s own
 * request-building, GET/HEAD only -- see this section's own top
 * comment for why no body), then selects a healthy cluster endpoint (a
 * returning client's own MAGNUS_AFFINITY cookie, if present and still
 * valid, always wins over whichever load-balancing policy is
 * configured -- roadmap 4h, magnus_cluster_select_sticky()'s own
 * documented precedence, matching every other protocol's identical
 * proxy dispatch) and connects -- retrying against a freshly selected
 * endpoint on a *synchronous* connect failure (roadmap 4g; the far
 * more common asynchronous failure, detected later via epoll, is
 * magnus_quic_proxy_fail()'s own retry to handle, not this function's),
 * bounded by MAGNUS_QUIC_PROXY_MAX_ATTEMPTS total attempts -- the same
 * shape magnus_h2_proxy_start()'s own `for (;;)` connect loop already
 * has. `Connection: close` to the upstream unconditionally -- this
 * increment never pools a connection for reuse, so there is nothing to
 * keep it open for, and it lets EOF unambiguously frame a response
 * with no Content-Length the same way HTTP/1.1 itself would.
 * `forward_path` is the caller's to decide (roadmap 4d's own literal
 * "/proxy"-prefix-stripped path, or roadmap 4f's own route-matched
 * unstripped stream->parsed.target -- see magnus_quic_http_dispatch()'s
 * own comment on why a route match always wins when both apply,
 * matching magnus_proxy_pick_and_start()'s identical h1/h2 precedent);
 * also this stream's own cache_target once a route with cache=on
 * matched, matching magnus_h2_proxy_start()'s identical choice to key
 * the cache on the *forwarded*, not the client-facing, path. */
static void
magnus_quic_proxy_start(magnus_quic_connection_t *connection,
                        magnus_quic_stream_t *stream,
                        const char *forward_path, bool cache_route_enabled)
{
    struct in_addr client_ip;
    int written;
    const char *cookie_header;
    char client_affinity[64];
    size_t preferred_index = 0;
    bool sticky;
    char conditional_headers[300] = "";

    stream->cache_enabled = cache_route_enabled;
    stream->cache_revalidating = false;
    stream->cache_this_response_cacheable = false;
    stream->cache_capture_overflowed = false;
    if (cache_route_enabled && strcmp(stream->parsed.method, "GET") == 0) {
        magnus_cache_entry_t *entry;
        strncpy(stream->cache_host, stream->parsed.host,
               sizeof(stream->cache_host) - 1);
        stream->cache_host[sizeof(stream->cache_host) - 1] = '\0';
        strncpy(stream->cache_target, forward_path,
               sizeof(stream->cache_target) - 1);
        stream->cache_target[sizeof(stream->cache_target) - 1] = '\0';

        entry = magnus_cache_lookup(stream->cache_host, stream->cache_target);
        if (entry != NULL
            && magnus_cache_entry_is_fresh(entry, magnus_cache_now_ms())) {
            magnus_quic_submit_cached_response(connection, stream, entry,
                                               "HIT");
            return;
        }
        if (entry != NULL && magnus_cache_entry_has_validator(entry)) {
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
            w = snprintf(conditional_headers + off,
                        sizeof(conditional_headers) - off,
                        "If-None-Match: %s\r\n", stream->cache_validator_etag);
            if (w > 0 && (size_t) w < sizeof(conditional_headers) - off)
                off += (size_t) w;
        }
        if (stream->cache_validator_last_modified[0] != '\0') {
            w = snprintf(conditional_headers + off,
                        sizeof(conditional_headers) - off,
                        "If-Modified-Since: %s\r\n",
                        stream->cache_validator_last_modified);
            if (w > 0 && (size_t) w < sizeof(conditional_headers) - off)
                off += (size_t) w;
        }
    }

    /* No stream->body_chunk allocation here -- unlike the old
     * stream->body_buffer, a chunk is allocated fresh per read by
     * magnus_quic_proxy_stream_response() and freed once acked (see
     * magnus_quic_stream_t's own comment), never pre-allocated. */
    stream->header_buffer = malloc(MAGNUS_QUIC_PROXY_HEADER_LIMIT);
    stream->proxy_request = malloc(512 + strlen(forward_path)
                                   + strlen(conditional_headers));
    if (stream->header_buffer == NULL
        || stream->proxy_request == NULL) {
        magnus_quic_http_submit_status(connection, stream, "500");
        return;
    }
    written = snprintf(stream->proxy_request,
        512 + strlen(forward_path) + strlen(conditional_headers),
        "%s %s HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n\r\n",
        stream->parsed.method, forward_path,
        stream->parsed.host[0] != '\0' ? stream->parsed.host : "localhost",
        conditional_headers);
    if (written < 0) {
        magnus_quic_http_submit_status(connection, stream, "500");
        return;
    }
    stream->proxy_request_length = (size_t) written;

    client_affinity[0] = '\0';
    cookie_header = magnus_http_header_find(&stream->parsed, "cookie");
    if (cookie_header != NULL)
        (void) magnus_http_extract_cookie(cookie_header, strlen(cookie_header),
                                          MAGNUS_AFFINITY_COOKIE_NAME,
                                          client_affinity,
                                          sizeof(client_affinity));
    sticky = magnus_decode_affinity_cookie(
        client_affinity[0] != '\0' ? client_affinity : NULL, &preferred_index);
    stream->issue_affinity_cookie = !sticky;

    client_ip = magnus_quic_client_ip(connection);
    stream->attempt = 0;
    for (;;) {
        int endpoint = sticky
            ? magnus_cluster_select_sticky(&magnus_cluster,
                                           magnus_now_ms_local(),
                                           preferred_index, client_ip)
            : magnus_cluster_select(&magnus_cluster, magnus_now_ms_local(),
                                    NULL, client_ip);
        if (endpoint < 0) {
            magnus_quic_http_submit_status(connection, stream, "502");
            return;
        }
        if (sticky) {
            sticky = false;
        } else if (stream->attempt > 0) {
            /* Deviating from the client's original sticky target (or
             * from plain round-robin) because a previous attempt
             * failed -- the cookie must be refreshed to reflect the
             * endpoint actually used, not what a retried/failed
             * attempt implied. */
            stream->issue_affinity_cookie = true;
        }
        stream->attempt++;
        if (magnus_quic_proxy_connect_endpoint(connection, stream,
                                               (size_t) endpoint) == 0) {
            if (stream->issue_affinity_cookie)
                magnus_encode_affinity_cookie(stream->affinity_key,
                                              sizeof(stream->affinity_key),
                                              (size_t) endpoint);
            return;
        }
        magnus_cluster_result(&magnus_cluster, (size_t) endpoint, false,
                              magnus_now_ms_local());
        if (stream->attempt >= MAGNUS_QUIC_PROXY_MAX_ATTEMPTS) {
            magnus_quic_http_submit_status(connection, stream, "502");
            return;
        }
    }
}

/* gzip-compresses fd's whole contents into a fresh malloc()ed buffer,
 * the h3 analogue of magnus_compress_static() -- duplicated rather
 * than reused directly because that function takes a
 * `magnus_http_request_t *` purely to reach
 * magnus_http_header_find(request, "accept-encoding"), and pulling in
 * magnus_http.h just for that would coupled this module to a request
 * shape it does not otherwise use anywhere (magnus_quic_stream_t
 * already carries its own flat accept_encoding field, captured
 * straight off the QPACK static-table token -- see that field's own
 * comment). Same eligibility rule (256 bytes..8 MiB, compressible MIME
 * type, client advertises gzip) and the same "buffer the whole file,
 * compress once, exact Content-Length" shape 2a already established
 * for HTTP/1.1 and HTTP/2. Returns true and fills `*output`/
 * `*output_length` on success (caller owns the buffer); false leaves
 * both untouched and the caller falls back to the uncompressed path,
 * exactly like magnus_compress_static()'s own every-failure-mode
 * contract. */
static bool
magnus_quic_compress_static(int fd, const struct stat *metadata,
                            const char *content_type,
                            const char *accept_encoding,
                            unsigned char **output, size_t *output_length)
{
    unsigned char *input;
    size_t length;
    size_t offset = 0;
    if (metadata->st_size < MAGNUS_COMPRESSION_MIN_SIZE
        || metadata->st_size > MAGNUS_COMPRESSION_MAX_SIZE
        || !magnus_content_type_compressible(content_type)
        || !magnus_accepts_gzip(accept_encoding)) return false;
    length = (size_t) metadata->st_size;
    input = malloc(length);
    if (input == NULL) return false;
    while (offset < length) {
        ssize_t got = pread(fd, input + offset, length - offset,
                            (off_t) offset);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) {
            free(input);
            return false;
        }
        offset += (size_t) got;
    }
    if (magnus_gzip_compress(input, length, output, output_length) != 0) {
        free(input);
        return false;
    }
    free(input);
    return true;
}

/* Serves stream->parsed.target as a static file -- the fallback once
 * magnus_quic_http_dispatch() below has ruled out /healthz, /metrics,
 * and every route (roadmap 4f). Method/head_only validation already
 * happened there, same as magnus_h2_dispatch()'s own single validation
 * pass ahead of its own healthz/metrics/static branches. */
static void
magnus_quic_http_dispatch_static(magnus_quic_connection_t *connection,
                                 magnus_quic_stream_t *stream)
{
    struct stat metadata;
    const char *content_type;
    char content_length[32];
    nghttp3_nv headers[6];
    size_t header_count = 4;
    int fd;
    unsigned char *compressed = NULL;
    size_t compressed_length = 0;
    bool use_gzip;

    fd = magnus_open_static(stream->parsed.target, &metadata);
    if (fd < 0) {
        magnus_quic_http_submit_status(connection, stream, "404");
        return;
    }
    content_type = magnus_content_type(stream->parsed.target);
    /* Computed unconditionally, ahead of the head_only check below --
     * a HEAD response still needs the *compressed* Content-Length to
     * be accurate (what a subsequent GET would actually transfer),
     * exactly like magnus_h2_dispatch_static()'s own ordering. */
    use_gzip = magnus_quic_compress_static(fd, &metadata, content_type,
                                           magnus_http_header_find(
                                               &stream->parsed,
                                               "accept-encoding"),
                                           &compressed, &compressed_length);
    snprintf(content_length, sizeof(content_length), "%lld",
            use_gzip ? (long long) compressed_length
                     : (long long) metadata.st_size);
    headers[0] = magnus_quic_nv(":status", "200");
    headers[1] = magnus_quic_nv("server", "Magnus/" MAGNUS_VERSION);
    headers[2] = magnus_quic_nv("content-type", content_type);
    headers[3] = magnus_quic_nv("content-length", content_length);
    if (use_gzip) {
        headers[4] = magnus_quic_nv("content-encoding", "gzip");
        headers[5] = magnus_quic_nv("vary", "Accept-Encoding");
        header_count = 6;
    }
    if (stream->head_only) {
        close(fd);
        free(compressed);
        (void) nghttp3_conn_submit_response(connection->http3_conn,
                                            stream->stream_id, headers,
                                            header_count, NULL);
        return;
    }
    if (use_gzip) {
        /* The whole compressed body is already sitting in memory --
         * exactly the same shape /healthz//metrics (roadmap 4c) already
         * reuse mmap_base/mmap_length/body_is_malloc for (see that
         * flag's own comment); reused here rather than given a
         * near-identical sibling field pair. */
        close(fd);
        stream->mmap_base = compressed;
        stream->mmap_length = compressed_length;
        stream->body_is_malloc = true;
        nghttp3_data_reader reader = { .read_data = magnus_quic_http_read_file };
        (void) nghttp3_conn_submit_response(connection->http3_conn,
                                            stream->stream_id, headers,
                                            header_count, &reader);
        return;
    }
    if (metadata.st_size > 0) {
        /* PROT_READ/MAP_PRIVATE: this process never writes through the
         * mapping, and no other process needs to see this fd's writes
         * (there are none) -- the same safety properties a `sendfile`-
         * style zero-copy path would have, see magnus_quic_stream_t's
         * own comment on why mmap over pread-in-chunks at all. */
        stream->mmap_base = mmap(NULL, (size_t) metadata.st_size, PROT_READ,
                                 MAP_PRIVATE, fd, 0);
        if (stream->mmap_base == MAP_FAILED) {
            stream->mmap_base = NULL;
            close(fd);
            magnus_quic_http_submit_status(connection, stream, "500");
            return;
        }
        stream->mmap_length = (size_t) metadata.st_size;
    }
    /* The mapping stays valid after the fd closes (POSIX mmap(2)) --
     * nothing past this point needs the fd itself, only the mapping,
     * which magnus_quic_http_stream_free() unmaps once this stream is
     * done (normal completion or the connection tearing down mid-
     * flight both go through it -- see that function's own comment). */
    close(fd);
    {
        nghttp3_data_reader reader = { .read_data = magnus_quic_http_read_file };
        (void) nghttp3_conn_submit_response(connection->http3_conn,
                                            stream->stream_id, headers,
                                            header_count, &reader);
    }
}

/* Entry point from the end_stream nghttp3 callback below, once a
 * request's headers and (if any) body have both been fully received --
 * exactly the same trigger point magnus_h2_dispatch()'s own non-early-
 * response path uses. Method/path validation, then /healthz, then
 * /metrics, then the `route` table (roadmap 4f), then static -- literal
 * "/healthz"/"/metrics" wins over a same-named file *and* over any
 * route's own conditions, exactly like magnus_h2_dispatch()'s own
 * comment documents for the h2 side (a route matching action=grpc, say,
 * still leaves /healthz alone). No request body is ever read for GET/
 * HEAD, so in practice this fires as soon as headers finish for the
 * only two methods this increment accepts. */
static void
magnus_quic_http_dispatch(magnus_quic_connection_t *connection,
                          magnus_quic_stream_t *stream)
{
    bool literal_proxy_prefix;
    bool is_proxy_route;
    bool route_denied = false;
    bool is_grpc_route = false;
    bool cache_route_enabled = false;
    const char *forward_path;
    struct in_addr client_ip;

    stream->head_only = strcmp(stream->parsed.method, "HEAD") == 0;
    if (stream->parsed.target[0] == '\0'
        || (strcmp(stream->parsed.method, "GET") != 0 && !stream->head_only)) {
        magnus_quic_http_submit_status(connection, stream, "400");
        return;
    }
    if (strcmp(stream->parsed.target, "/healthz") == 0) {
        magnus_quic_http_submit_text(connection, stream, "200", "text/plain",
                                     "magnus: ok\n");
        return;
    }
    /* Withdrawn once --admin-socket/admin_socket is configured -- same
     * access-control boundary the main TCP listener already applies
     * (roadmap 1e-4), extended to the QUIC listener too. Falls through
     * to the static-file path below when withdrawn, same as a request
     * for any other path that happens not to exist. */
    if (strcmp(stream->parsed.target, "/metrics") == 0
        && !magnus_admin_enabled) {
        /* Matches magnus.c's own MAGNUS_METRICS_BUFFER -- not shared
         * via magnus_static.h because that constant's own sizing is
         * coupled to magnus.c's unrelated MAGNUS_OUTPUT_LIMIT (see its
         * own comment there); magnus_build_metrics() itself documents
         * that any buffer at least this large truncates safely rather
         * than overflows, so the two do not need to be the exact same
         * named constant to stay correct. */
        char metrics[16384];
        magnus_build_metrics(metrics, sizeof(metrics));
        magnus_quic_http_submit_text(connection, stream, "200",
                                     "text/plain; version=0.0.4", metrics);
        return;
    }

    /* Roadmap 4d: the literal "/proxy" prefix, stripped before
     * relaying (falls back to "/" for a bare "/proxy" request rather
     * than forwarding an empty request-target, which HTTP/1.1 does not
     * allow -- a deliberate small improvement over the exact h1/h2
     * edge case, not a behavior this path needs to import unchanged). */
    literal_proxy_prefix = magnus_upstream_enabled
        && strncmp(stream->parsed.target, "/proxy", 6) == 0
        && (stream->parsed.target[6] == '/' || stream->parsed.target[6] == '\0');
    is_proxy_route = literal_proxy_prefix;
    forward_path = literal_proxy_prefix ? stream->parsed.target + 6
                                        : stream->parsed.target;
    if (forward_path[0] == '\0') forward_path = "/";

    client_ip = magnus_quic_client_ip(connection);

    /* Roadmap 4f: host/path-prefix/method/header/header_prefix/cookie/
     * query/source-CIDR route matching, reusing magnus_route_matches()
     * (src/magnus_route.h) and the same magnus_routes[]/magnus_route_count
     * table (src/magnus_static.h) HTTP/1.1 and HTTP/2 already share --
     * evaluated in file order, first match wins, exactly like
     * magnus_h2_dispatch()'s own identical loop. A matched action=proxy
     * route always wins over the literal "/proxy" prefix above (its own
     * forward_path is the *whole*, unstripped target, matching
     * magnus_proxy_pick_and_start()'s documented h1/h2 precedent), even
     * when both apply to the same request -- and, once matched, its own
     * `cache_enabled` (roadmap 4i) travels along with it into
     * magnus_quic_proxy_start(). Deliberately NOT consulted here: Real
     * IP resolution (source_cidr below matches against the raw QUIC
     * peer address, not a trusted-proxy-resolved one -- QUIC has no
     * established PROXY-protocol-over-UDP precedent in this codebase to
     * resolve from in the first place). */
    for (size_t r = 0; r < magnus_route_count; r++) {
        if (!magnus_route_matches(&magnus_routes[r], &stream->parsed,
                                  client_ip))
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
        /* action=static needs no branch of its own here: matching and
         * being neither deny/proxy/grpc already falls through to the
         * same static-file dispatch a request with no matching route
         * at all gets, exactly like magnus_h2_dispatch()'s own comment
         * documents. */
        break;
    }

    if (route_denied) {
        magnus_quic_http_submit_status(connection, stream, "403");
        return;
    }
    if (is_grpc_route) {
        /* A real gRPC server requires HTTP/2 end to end (trailers alone
         * make it impossible over HTTP/1.1 -- and this codebase's own
         * gRPC dispatch is HTTP/2-native-only in the first place, see
         * magnus_h2_dispatch()'s own action=grpc branch), so HTTP/3 is
         * no more able to reach it than HTTP/1.1 is -- same explicit,
         * immediate 505 magnus_dispatch_request()'s own action=grpc
         * branch already answers with, rather than silently falling
         * through to ordinary static dispatch as if action=grpc were
         * not there at all. */
        magnus_quic_http_submit_text(connection, stream, "505", "text/plain",
            "gRPC requires HTTP/2 (TLS ALPN \"h2\" or h2c)\n");
        return;
    }
    if (is_proxy_route) {
        stream->is_proxy = true;
        magnus_quic_proxy_start(connection, stream, forward_path,
                                cache_route_enabled);
        return;
    }
    magnus_quic_http_dispatch_static(connection, stream);
}

/* nghttp3's own documented contract for a read_data callback's returned
 * memory (see magnus_quic_stream_t's own comment, and
 * magnus_quic_proxy_read_body()'s): it must stay valid until *this*
 * callback confirms the peer has acknowledged it, not merely until
 * ngtcp2 has copied it into an outgoing packet. For a proxy stream,
 * once the currently in-flight chunk (stream->body_chunk, ending at
 * stream->body_chunk_end_offset) is fully acked, it is freed and
 * magnus_quic_proxy_stream_response() is retried immediately -- epoll
 * will not necessarily refire on its own if the upstream socket's
 * already-available bytes were fully drained while backpressure
 * (stream->body_chunk != NULL) was blocking a further read. */
static int
magnus_quic_http_acked_stream_data(nghttp3_conn *conn, int64_t stream_id,
                                   uint64_t datalen, void *conn_user_data,
                                   void *stream_user_data)
{
    magnus_quic_connection_t *connection = conn_user_data;
    magnus_quic_stream_t *stream = stream_user_data;
    (void) conn;
    (void) stream_id;
    if (stream == NULL || !stream->is_proxy) return 0;
    stream->body_acked_total += datalen;
    if (stream->body_chunk != NULL
        && stream->body_acked_total >= stream->body_chunk_end_offset) {
        free(stream->body_chunk);
        stream->body_chunk = NULL;
        stream->body_chunk_length = 0;
        stream->body_chunk_offered = false;
        if (stream->upstream_fd >= 0)
            magnus_quic_proxy_stream_response(connection, stream);
    }
    return 0;
}

static int
magnus_quic_http_recv_data(nghttp3_conn *conn, int64_t stream_id,
                           const uint8_t *data, size_t datalen,
                           void *conn_user_data, void *stream_user_data)
{
    magnus_quic_connection_t *connection = conn_user_data;
    (void) conn;
    (void) data;
    (void) stream_user_data;
    ngtcp2_conn_extend_max_stream_offset(connection->conn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(connection->conn, datalen);
    return 0;
}

static int
magnus_quic_http_deferred_consume(nghttp3_conn *conn, int64_t stream_id,
                                  size_t nconsumed, void *conn_user_data,
                                  void *stream_user_data)
{
    magnus_quic_connection_t *connection = conn_user_data;
    (void) conn;
    (void) stream_user_data;
    ngtcp2_conn_extend_max_stream_offset(connection->conn, stream_id,
                                         nconsumed);
    ngtcp2_conn_extend_max_offset(connection->conn, nconsumed);
    return 0;
}

static int
magnus_quic_http_begin_headers(nghttp3_conn *conn, int64_t stream_id,
                               void *conn_user_data, void *stream_user_data)
{
    magnus_quic_connection_t *connection = conn_user_data;
    magnus_quic_stream_t *stream;
    (void) stream_user_data;
    stream = calloc(1, sizeof(*stream));
    if (stream == NULL) return NGHTTP3_ERR_CALLBACK_FAILURE;
    stream->stream_id = stream_id;
    /* Explicit, not left at calloc's 0 default -- 0 is a valid fd (this
     * exact class of bug, magnus.c's own connection->upstream_fd
     * silently defaulting to 0 instead of -1, was found and fixed once
     * already during this project's Phase 4/M5 work; not repeating it
     * here). */
    stream->upstream_fd = -1;
    (void) nghttp3_conn_set_stream_user_data(conn, stream_id, stream);
    /* Also registered at the *ngtcp2* level (magnus_quic_stream_close()'s
     * own `stream_user_data` parameter, not a separate lookup) --
     * portable across nghttp3 versions this project supports building
     * against (the EPEL package on the development host vs. the
     * Dockerfile builder's own older pinned release both have
     * nghttp3_conn_set_stream_user_data, but only the newer one also
     * has nghttp3_conn_get_stream_user_data; ngtcp2_conn_get_stream_user_data
     * has been stable since ngtcp2 v1.17.0, well below both this
     * project's EPEL and Dockerfile-pinned ngtcp2 versions). Found via
     * the Dockerfile image build actually failing to compile against
     * its own older-pinned nghttp3, not by reading changelogs first. */
    (void) ngtcp2_conn_set_stream_user_data(connection->conn, stream_id,
                                            stream);
    return 0;
}

/* Captures :method/:path/:authority into stream->parsed's own fixed
 * fields, and (roadmap 4f) every ordinary header into
 * stream->parsed.headers[] up to MAGNUS_HTTP_MAX_HEADERS -- truncated
 * (not rejected) past its fixed-size slot, simply not retained past
 * the count limit, exactly mirroring magnus_h2_on_header()'s own
 * handling (and, further back, magnus_http_parse()'s), so route
 * matching and Accept-Encoding negotiation behave identically
 * regardless of which protocol a request arrived over. Any other
 * pseudo-header (:scheme, :protocol, ...) is silently ignored, same as
 * magnus_h2_on_header()'s own `name[0] == ':'` check. */
static int
magnus_quic_http_recv_header(nghttp3_conn *conn, int64_t stream_id,
                             int32_t token, nghttp3_rcbuf *name,
                             nghttp3_rcbuf *value, uint8_t flags,
                             void *conn_user_data, void *stream_user_data)
{
    magnus_quic_stream_t *stream = stream_user_data;
    nghttp3_vec v;
    nghttp3_vec n;
    (void) conn;
    (void) stream_id;
    (void) flags;
    (void) conn_user_data;
    if (stream == NULL) return 0;
    v = nghttp3_rcbuf_get_buf(value);
    if (token == NGHTTP3_QPACK_TOKEN__METHOD) {
        size_t length = v.len < sizeof(stream->parsed.method) - 1
            ? v.len : sizeof(stream->parsed.method) - 1;
        memcpy(stream->parsed.method, v.base, length);
        stream->parsed.method[length] = '\0';
        return 0;
    }
    if (token == NGHTTP3_QPACK_TOKEN__PATH) {
        size_t length = v.len < sizeof(stream->parsed.target) - 1
            ? v.len : sizeof(stream->parsed.target) - 1;
        memcpy(stream->parsed.target, v.base, length);
        stream->parsed.target[length] = '\0';
        return 0;
    }
    if (token == NGHTTP3_QPACK_TOKEN__AUTHORITY) {
        /* :authority -- becomes the outbound Host header for a
         * proxy-dispatched request (roadmap 4d) and the value a
         * MAGNUS_ROUTE_MATCH_HOST condition compares against (roadmap
         * 4f), matching HTTP/2's own :authority-as-Host precedent
         * exactly (see magnus_h2_on_header()'s own comment). */
        size_t length = v.len < sizeof(stream->parsed.host) - 1
            ? v.len : sizeof(stream->parsed.host) - 1;
        memcpy(stream->parsed.host, v.base, length);
        stream->parsed.host[length] = '\0';
        return 0;
    }
    n = nghttp3_rcbuf_get_buf(name);
    if (n.len > 0 && n.base[0] == ':') return 0; /* any other pseudo-header */
    if (stream->parsed.header_count < MAGNUS_HTTP_MAX_HEADERS) {
        magnus_http_header_t *stored
            = &stream->parsed.headers[stream->parsed.header_count];
        size_t stored_name_length = n.len < sizeof(stored->name) - 1
            ? n.len : sizeof(stored->name) - 1;
        size_t stored_value_length = v.len < sizeof(stored->value) - 1
            ? v.len : sizeof(stored->value) - 1;
        memcpy(stored->name, n.base, stored_name_length);
        stored->name[stored_name_length] = '\0';
        memcpy(stored->value, v.base, stored_value_length);
        stored->value[stored_value_length] = '\0';
        stream->parsed.header_count++;
    }
    return 0;
}

static int
magnus_quic_http_end_headers(nghttp3_conn *conn, int64_t stream_id, int fin,
                             void *conn_user_data, void *stream_user_data)
{
    (void) conn;
    (void) stream_id;
    (void) fin;
    (void) conn_user_data;
    (void) stream_user_data;
    return 0;
}

static int
magnus_quic_http_end_stream(nghttp3_conn *conn, int64_t stream_id,
                            void *conn_user_data, void *stream_user_data)
{
    magnus_quic_connection_t *connection = conn_user_data;
    magnus_quic_stream_t *stream = stream_user_data;
    (void) conn;
    (void) stream_id;
    if (stream == NULL) return 0;
    magnus_quic_http_dispatch(connection, stream);
    return 0;
}

static int
magnus_quic_http_stop_sending(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *conn_user_data,
                              void *stream_user_data)
{
    magnus_quic_connection_t *connection = conn_user_data;
    (void) conn;
    (void) stream_user_data;
    (void) ngtcp2_conn_shutdown_stream_read(connection->conn, 0, stream_id,
                                            app_error_code);
    return 0;
}

static int
magnus_quic_http_reset_stream(nghttp3_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *conn_user_data,
                              void *stream_user_data)
{
    magnus_quic_connection_t *connection = conn_user_data;
    (void) conn;
    (void) stream_user_data;
    (void) ngtcp2_conn_shutdown_stream_write(connection->conn, 0, stream_id,
                                             app_error_code);
    return 0;
}

/* Called once, from magnus_quic_recv_tx_key() below, the moment the
 * server's own 1-RTT TX key is installed -- the earliest point 1-RTT
 * application data (the HTTP/3 control/QPACK streams opened here) can
 * go out at all, same trigger point the reference server this stack
 * was verified against (docs/phase4-spike-results.md) uses. */
static int
magnus_quic_setup_http3(magnus_quic_connection_t *connection)
{
    nghttp3_callbacks callbacks;
    nghttp3_settings settings;
    const ngtcp2_transport_params *params;
    int64_t control_stream_id;
    int64_t qpack_encoder_stream_id;
    int64_t qpack_decoder_stream_id;
    int rv;

    if (connection->http3_conn) return 0;

    if (ngtcp2_conn_get_streams_uni_left(connection->conn) < 3) {
        fprintf(stderr,
               "magnus: quic peer does not allow >= 3 unidirectional "
               "streams, cannot start http3\n");
        return -1;
    }

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.acked_stream_data = magnus_quic_http_acked_stream_data;
    callbacks.recv_data = magnus_quic_http_recv_data;
    callbacks.deferred_consume = magnus_quic_http_deferred_consume;
    callbacks.begin_headers = magnus_quic_http_begin_headers;
    callbacks.recv_header = magnus_quic_http_recv_header;
    callbacks.end_headers = magnus_quic_http_end_headers;
    callbacks.stop_sending = magnus_quic_http_stop_sending;
    callbacks.end_stream = magnus_quic_http_end_stream;
    callbacks.reset_stream = magnus_quic_http_reset_stream;
    /* No .rand: an nghttp3_callbacks field added after the Dockerfile
     * builder's own pinned nghttp3 release (see
     * magnus_quic_http_begin_headers()'s own comment on that version
     * gap) -- "optional due to backward compatibility" per nghttp3's
     * own docs, so simply not setting it is correct on every version
     * this project builds against, not a workaround. */

    nghttp3_settings_default(&settings);
    settings.qpack_max_dtable_capacity = 4096;
    settings.qpack_blocked_streams = 100;

    rv = nghttp3_conn_server_new(&connection->http3_conn, &callbacks,
                                 &settings, NULL, connection);
    if (rv != 0) {
        fprintf(stderr, "magnus: nghttp3_conn_server_new: %s\n",
               nghttp3_strerror(rv));
        return -1;
    }

    params = ngtcp2_conn_get_local_transport_params(connection->conn);
    nghttp3_conn_set_max_client_streams_bidi(connection->http3_conn,
        params->initial_max_streams_bidi);

    if (ngtcp2_conn_open_uni_stream(connection->conn, &control_stream_id,
                                    NULL) != 0
        || nghttp3_conn_bind_control_stream(connection->http3_conn,
                                            control_stream_id) != 0
        || ngtcp2_conn_open_uni_stream(connection->conn,
                                       &qpack_encoder_stream_id, NULL) != 0
        || ngtcp2_conn_open_uni_stream(connection->conn,
                                       &qpack_decoder_stream_id, NULL) != 0
        || nghttp3_conn_bind_qpack_streams(connection->http3_conn,
                                           qpack_encoder_stream_id,
                                           qpack_decoder_stream_id) != 0) {
        fprintf(stderr, "magnus: quic http3 control/qpack stream setup "
                        "failed\n");
        nghttp3_conn_del(connection->http3_conn);
        connection->http3_conn = NULL;
        return -1;
    }

    return 0;
}

static int
magnus_quic_recv_tx_key(ngtcp2_conn *conn, ngtcp2_encryption_level level,
                        void *user_data)
{
    magnus_quic_connection_t *connection = user_data;
    (void) conn;
    if (level != NGTCP2_ENCRYPTION_LEVEL_1RTT) return 0;
    if (magnus_quic_setup_http3(connection) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

/* --- TLS / SSL_CTX setup -------------------------------------------- */

/* Wire format (RFC 7301): each entry is a length byte followed by that
 * many bytes, no terminator. Just "h3" -- 4a doesn't yet speak HTTP/3
 * itself (see magnus_quic.h), but negotiating the protocol a real
 * client actually offers is what lets that client's own handshake
 * complete normally rather than falling back/erroring on ALPN
 * mismatch, which is what this increment is here to validate. */
static const unsigned char MAGNUS_QUIC_ALPN_H3[] = { 2, 'h', '3' };

static int
magnus_quic_alpn_select_cb(SSL *ssl, const unsigned char **out,
                           unsigned char *outlen, const unsigned char *in,
                           unsigned int inlen, void *arg)
{
    unsigned int offset;
    (void) ssl;
    (void) arg;
    /* Manual scan of the client's offered list rather than
     * SSL_select_next_proto(): with only one protocol this server ever
     * selects, matching it directly against each client-offered entry
     * needs no extra const-cast gymnastics around that function's
     * non-const `unsigned char **out` -- same approach the ngtcp2
     * reference server's own alpn_select_proto_h3_cb takes. */
    for (offset = 0; offset + 1 <= inlen && offset + 1 + in[offset] <= inlen;
         offset += (unsigned int) (1 + in[offset])) {
        if (in[offset] == MAGNUS_QUIC_ALPN_H3[0]
            && memcmp(&in[offset + 1], &MAGNUS_QUIC_ALPN_H3[1],
                     MAGNUS_QUIC_ALPN_H3[0]) == 0) {
            *out = &in[offset + 1];
            *outlen = in[offset];
            return SSL_TLSEXT_ERR_OK;
        }
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

int
magnus_quic_init(const char *tls_cert, const char *tls_key)
{
    if (magnus_quic_initialized) return 0;

    if (RAND_bytes(magnus_quic_static_secret,
                   (int) sizeof(magnus_quic_static_secret)) != 1) {
        fprintf(stderr, "magnus: quic RAND_bytes (static secret) failed\n");
        return -1;
    }

    if (ngtcp2_crypto_ossl_init() != 0) {
        fprintf(stderr, "magnus: ngtcp2_crypto_ossl_init failed\n");
        return -1;
    }

    magnus_quic_ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!magnus_quic_ssl_ctx) {
        fprintf(stderr, "magnus: quic SSL_CTX_new: %s\n",
               ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    /* QUIC carries TLS 1.3 exclusively (RFC 9001 4); early-data replay
     * protection is QUIC's own job (ngtcp2 tracks 0-RTT acceptance),
     * not TLS's -- SSL_OP_NO_ANTI_REPLAY matches every ngtcp2 example's
     * own server context, and 4a leaves 0-RTT itself disabled below
     * regardless (SSL_set_quic_tls_early_data_enabled is not called in
     * magnus_quic_listener_service()). */
    SSL_CTX_set_min_proto_version(magnus_quic_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(magnus_quic_ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_options(magnus_quic_ssl_ctx,
                        SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
    SSL_CTX_set_mode(magnus_quic_ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    SSL_CTX_set_alpn_select_cb(magnus_quic_ssl_ctx, magnus_quic_alpn_select_cb,
                              NULL);

    if (SSL_CTX_use_PrivateKey_file(magnus_quic_ssl_ctx, tls_key,
                                    SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "magnus: quic SSL_CTX_use_PrivateKey_file(%s): %s\n",
               tls_key, ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(magnus_quic_ssl_ctx);
        magnus_quic_ssl_ctx = NULL;
        return -1;
    }
    if (SSL_CTX_use_certificate_chain_file(magnus_quic_ssl_ctx, tls_cert) != 1) {
        fprintf(stderr,
               "magnus: quic SSL_CTX_use_certificate_chain_file(%s): %s\n",
               tls_cert, ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(magnus_quic_ssl_ctx);
        magnus_quic_ssl_ctx = NULL;
        return -1;
    }
    if (SSL_CTX_check_private_key(magnus_quic_ssl_ctx) != 1) {
        fprintf(stderr, "magnus: quic SSL_CTX_check_private_key: %s\n",
               ERR_error_string(ERR_get_error(), NULL));
        SSL_CTX_free(magnus_quic_ssl_ctx);
        magnus_quic_ssl_ctx = NULL;
        return -1;
    }

    magnus_quic_initialized = true;
    return 0;
}

/* --- listener / socket ------------------------------------------------ */

int
magnus_quic_create_listener(unsigned port)
{
    int fd;
    int flags;
    struct sockaddr_in address;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("magnus: quic socket");
        return -1;
    }

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("magnus: quic fcntl O_NONBLOCK");
        close(fd);
        return -1;
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons((uint16_t) port);
    if (bind(fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
        perror("magnus: quic bind");
        close(fd);
        return -1;
    }

    /* Cached for magnus_quic_handle_upstream_event() below (roadmap
     * 4d): unlike magnus_quic_listener_service()/magnus_quic_tick(),
     * which the caller already passes this fd into on every call,
     * that entry point's own public signature (magnus_quic.h) takes
     * only the upstream fd and its epoll flags -- matching every other
     * *_owner[fd]-dispatched handler's own shape in magnus.c's main
     * loop -- so this is the one place that fd has to come from
     * instead. There is only ever one QUIC listener per process. */
    magnus_quic_listener_fd = fd;
    return fd;
}

/* --- per-connection setup for an unmatched Initial packet -------------- */

static void
magnus_quic_flush(int listener_fd, int slot)
{
    magnus_quic_connection_t *connection = &magnus_quic_connections[slot];
    uint8_t buffer[MAGNUS_QUIC_SEND_BUFFER];

    for (;;) {
        ngtcp2_path path;
        ngtcp2_pkt_info pi;
        ngtcp2_ssize written;
        ngtcp2_ssize ndatalen = -1;
        int64_t stream_id = -1;
        int fin = 0;
        /* One slot: magnus_quic_http_read_file() only ever fills one
         * (the whole response body, mmap'd -- see magnus_quic_stream_t's
         * own comment for why a chunked-read version of that callback
         * does not work correctly here), so a larger array would only
         * ever have its extra slots go unused. */
        nghttp3_vec vec[1];
        nghttp3_ssize veccnt = 0;
        uint32_t write_flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

        memset(&pi, 0, sizeof(pi));
        path.local.addr = (ngtcp2_sockaddr *) &connection->local_addr;
        path.local.addrlen = connection->local_addrlen;
        path.remote.addr = (ngtcp2_sockaddr *) &connection->remote_addr;
        path.remote.addrlen = connection->remote_addrlen;
        path.user_data = NULL;

        /* Pull whatever HTTP/3 response data is ready to go out on
         * whichever stream nghttp3 picks next -- mirrors the reference
         * write_pkt() loop this stack was verified against
         * (docs/phase4-spike-results.md), including the three
         * ngtcp2_conn_writev_stream() error cases below that only ever
         * arise when a stream (not the connection) is involved. Guarded
         * on ngtcp2_conn_get_max_data_left() the same way the reference
         * is: asking nghttp3 for data when the connection-level flow
         * control window is already exhausted would only get told
         * STREAM_DATA_BLOCKED right back. */
        if (connection->http3_conn
            && ngtcp2_conn_get_max_data_left(connection->conn) > 0) {
            veccnt = nghttp3_conn_writev_stream(connection->http3_conn,
                &stream_id, &fin, vec, sizeof(vec) / sizeof(vec[0]));
            if (veccnt < 0) {
                fprintf(stderr, "magnus: quic nghttp3_conn_writev_stream: %s\n",
                       nghttp3_strerror((int) veccnt));
                magnus_quic_slot_free(slot);
                return;
            }
        }
        if (fin) write_flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

        written = ngtcp2_conn_writev_stream(connection->conn, &path, &pi,
            buffer, sizeof(buffer), &ndatalen, write_flags, stream_id,
            (const ngtcp2_vec *) vec, (size_t) veccnt,
            magnus_quic_timestamp());
        if (written < 0) {
            int rv = (int) written;
            if (rv == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                (void) nghttp3_conn_block_stream(connection->http3_conn,
                                                 stream_id);
                continue;
            }
            if (rv == NGTCP2_ERR_STREAM_SHUT_WR) {
                (void) nghttp3_conn_shutdown_stream_write(
                    connection->http3_conn, stream_id);
                continue;
            }
            if (rv == NGTCP2_ERR_WRITE_MORE) {
                if (nghttp3_conn_add_write_offset(connection->http3_conn,
                                                  stream_id,
                                                  (size_t) ndatalen) != 0) {
                    magnus_quic_slot_free(slot);
                    return;
                }
                continue;
            }
            fprintf(stderr, "magnus: quic writev_stream: %s\n",
                   ngtcp2_strerror(rv));
            magnus_quic_slot_free(slot);
            return;
        }

        if (ndatalen >= 0 && connection->http3_conn
            && nghttp3_conn_add_write_offset(connection->http3_conn,
                                             stream_id,
                                             (size_t) ndatalen) != 0) {
            magnus_quic_slot_free(slot);
            return;
        }

        if (written == 0) return;

        if (sendto(listener_fd, buffer, (size_t) written, 0,
                  (struct sockaddr *) &connection->remote_addr,
                  connection->remote_addrlen) < 0
            && errno != EAGAIN && errno != EWOULDBLOCK) {
            /* A send failure here is not fatal to the connection the
             * same way a read/write error inside ngtcp2 itself is --
             * ngtcp2's own PTO retransmission will simply try again on
             * the next magnus_quic_tick(). Logged, not treated as a
             * reason to free the slot. */
            perror("magnus: quic sendto");
        }
    }
}

static int
magnus_quic_accept_new(int listener_fd, const struct sockaddr *local_addr,
                       socklen_t local_addrlen,
                       const struct sockaddr *remote_addr,
                       socklen_t remote_addrlen, const uint8_t *data,
                       size_t datalen)
{
    ngtcp2_pkt_hd header;
    ngtcp2_cid scid;
    ngtcp2_path path;
    ngtcp2_callbacks callbacks;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    magnus_quic_connection_t *connection;
    SSL *ssl;
    int slot;
    int rv;

    if (ngtcp2_accept(&header, data, datalen) != 0) {
        /* Not a well-formed Initial packet for a version we speak --
         * silently dropped. Phase 4a scope note (magnus_quic.h): no
         * stateless reset / version-negotiation reply on this path
         * yet, same "narrow the first increment" call Phase 3's own
         * PROXY-protocol-emission entry made about UDP's v2 variant. */
        return 0;
    }

    slot = magnus_quic_slot_alloc();
    if (slot < 0) return 0; /* table full -- drop, same as any other
                              * bounded-resource-exhaustion path in this
                              * codebase (e.g. magnus_health_probes[]). */

    connection = &magnus_quic_connections[slot];
    memset(connection, 0, sizeof(*connection));
    connection->in_use = true;
    memcpy(&connection->local_addr, local_addr, (size_t) local_addrlen);
    connection->local_addrlen = local_addrlen;
    memcpy(&connection->remote_addr, remote_addr, (size_t) remote_addrlen);
    connection->remote_addrlen = remote_addrlen;
    connection->last_activity = time(NULL);

    if (RAND_bytes(scid.data, NGTCP2_MAX_CIDLEN) != 1) {
        memset(connection, 0, sizeof(*connection));
        return 0;
    }
    scid.datalen = NGTCP2_MAX_CIDLEN;

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_stream_data = magnus_quic_recv_stream_data;
    callbacks.acked_stream_data_offset = magnus_quic_acked_stream_data_offset;
    callbacks.stream_close = magnus_quic_stream_close;
    callbacks.extend_max_stream_data = magnus_quic_extend_max_stream_data;
    callbacks.recv_tx_key = magnus_quic_recv_tx_key;
    callbacks.rand = magnus_quic_rand;
    callbacks.get_new_connection_id = magnus_quic_get_new_connection_id;
    callbacks.remove_connection_id = magnus_quic_remove_connection_id;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx =
        ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.get_path_challenge_data =
        ngtcp2_crypto_get_path_challenge_data_cb;
    callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    callbacks.handshake_completed = magnus_quic_handshake_completed;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = magnus_quic_timestamp();

    ngtcp2_transport_params_default(&params);
    params.initial_max_data = 1u << 20;
    /* Bidi streams are HTTP/3 request/response streams (roadmap Phase
     * 4b, see magnus_quic.h) -- MAGNUS_QUIC_MAX_BIDI_STREAMS concurrent
     * per connection, matching this codebase's existing (informal) h2
     * concurrency sizing. Uni covers the three control/QPACK streams
     * (RFC 9114 6.2) every real HTTP/3 client opens regardless of bidi
     * count. */
    params.initial_max_stream_data_bidi_local = 1u << 16;
    params.initial_max_stream_data_bidi_remote = 1u << 16;
    params.initial_max_streams_bidi = MAGNUS_QUIC_MAX_BIDI_STREAMS;
    params.initial_max_streams_uni = 8;
    params.initial_max_stream_data_uni = 1u << 16;
    params.max_idle_timeout = MAGNUS_QUIC_MAX_IDLE_TIMEOUT_NS;
    /* Mandatory for a server connection (RFC 9000 18.2): the client's
     * own Initial-packet DCID -- ngtcp2_conn_server_new() itself
     * assert()s on this when original_dcid_present is left unset (this
     * was found the hard way: a real handshake attempt against a
     * running magnus crashed the whole process on this exact assert,
     * not a review-time catch), since it lets the client detect a
     * spoofed/off-path server response by confirming the server saw
     * the same DCID the client originally sent. */
    params.original_dcid = header.dcid;
    params.original_dcid_present = 1;

    path.local.addr = (ngtcp2_sockaddr *) local_addr;
    path.local.addrlen = local_addrlen;
    path.remote.addr = (ngtcp2_sockaddr *) remote_addr;
    path.remote.addrlen = remote_addrlen;
    path.user_data = NULL;

    connection->conn_ref.get_conn = magnus_quic_get_conn;
    connection->conn_ref.user_data = connection;

    /* `connection` (a stable pointer into the static
     * magnus_quic_connections[] table, not a slot index) is the one
     * user_data value passed to every per-connection ngtcp2 callback
     * below -- get_new_connection_id()'s first call happens
     * synchronously inside ngtcp2_conn_server_new() itself, before
     * connection->conn is even assigned, so that callback (and
     * remove_connection_id(), handshake_completed(), ...) must be able
     * to recover the table slot from user_data alone, never from
     * conn_->conn. */
    rv = ngtcp2_conn_server_new(&connection->conn, &header.scid, &scid, &path,
        header.version, &callbacks, &settings, &params, NULL, connection);
    if (rv != 0) {
        fprintf(stderr, "magnus: ngtcp2_conn_server_new: %s\n",
               ngtcp2_strerror(rv));
        memset(connection, 0, sizeof(*connection));
        return 0;
    }
    /* get_new_connection_id() above already ran once as part of
     * ngtcp2_conn_server_new() and registered its own CID against
     * `slot` (cast through user_data the same way); this initial scid
     * additionally needs registering directly, since it was generated
     * here, not through that callback. */
    if (!magnus_quic_cid_register(scid.data, scid.datalen, slot)) {
        ngtcp2_conn_del(connection->conn);
        memset(connection, 0, sizeof(*connection));
        return 0;
    }
    /* Also register the CLIENT's own original dcid (header.dcid, the
     * value it will keep sending as every Initial-space packet's dcid
     * until it learns our scid from our first response) -- found the
     * hard way, not by review: a first flight large enough to span
     * more than one Initial packet (routine with a post-quantum hybrid
     * key share bulking up the ClientHello well past ~1200 bytes) or a
     * retransmitted Initial arriving before our first response does
     * both still carry the client's original dcid, not our scid; not
     * registering it here made magnus_quic_listener_service()'s own
     * demux miss the match and spawn a second, bogus accept for what
     * is really a continuation of this same handshake. Harmless to
     * leave in the table after the handshake settles -- the client
     * stops using it on its own once it switches to our scid, and it
     * is reclaimed the same way every other cid this connection owns
     * is, via magnus_quic_cid_remove_slot() in magnus_quic_slot_free(). */
    if (!magnus_quic_cid_register(header.dcid.data, header.dcid.datalen,
                                  slot)) {
        ngtcp2_conn_del(connection->conn);
        memset(connection, 0, sizeof(*connection));
        return 0;
    }

    if (ngtcp2_crypto_ossl_ctx_new(&connection->ossl_ctx, NULL) != 0) {
        magnus_quic_slot_free(slot);
        return 0;
    }
    ssl = SSL_new(magnus_quic_ssl_ctx);
    if (!ssl) {
        fprintf(stderr, "magnus: quic SSL_new: %s\n",
               ERR_error_string(ERR_get_error(), NULL));
        magnus_quic_slot_free(slot);
        return 0;
    }
    ngtcp2_crypto_ossl_ctx_set_ssl(connection->ossl_ctx, ssl);
    if (ngtcp2_crypto_ossl_configure_server_session(ssl) != 0) {
        fprintf(stderr,
               "magnus: ngtcp2_crypto_ossl_configure_server_session failed\n");
        magnus_quic_slot_free(slot);
        return 0;
    }
    SSL_set_app_data(ssl, &connection->conn_ref);
    SSL_set_accept_state(ssl);
    ngtcp2_conn_set_tls_native_handle(connection->conn, connection->ossl_ctx);

    rv = ngtcp2_conn_read_pkt(connection->conn, &path, NULL, data, datalen,
                             magnus_quic_timestamp());
    if (rv != 0) {
        fprintf(stderr, "magnus: quic accept read_pkt: %s\n",
               ngtcp2_strerror(rv));
        magnus_quic_slot_free(slot);
        return 0;
    }

    magnus_quic_flush(listener_fd, slot);
    return 0;
}

void
magnus_quic_listener_service(int listener_fd)
{
    /* Bounded per call for the same reason magnus_udp_listener_service()
     * and every other shared-listener drain loop in this codebase is:
     * one very chatty source must not starve every other fd this
     * epoll_wait() tick is also responsible for. */
    static const int MAGNUS_QUIC_MAX_PACKETS_PER_CALL = 64;
    int processed;
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;

    local_addrlen = sizeof(local_addr);
    if (getsockname(listener_fd, (struct sockaddr *) &local_addr,
                    &local_addrlen) < 0) {
        /* Falls back to an empty (all-zero) local address -- this only
         * affects ngtcp2_path equality checks used for migration
         * detection, which 4a's own scope note already excludes; the
         * handshake and data path both still function. */
        memset(&local_addr, 0, sizeof(local_addr));
        local_addrlen = sizeof(struct sockaddr_in);
    }

    for (processed = 0; processed < MAGNUS_QUIC_MAX_PACKETS_PER_CALL;
         processed++) {
        uint8_t buffer[MAGNUS_QUIC_RECV_BUFFER];
        struct sockaddr_storage remote_addr;
        socklen_t remote_addrlen = sizeof(remote_addr);
        ssize_t received;
        ngtcp2_version_cid vc;
        int slot;

        received = recvfrom(listener_fd, buffer, sizeof(buffer), 0,
                            (struct sockaddr *) &remote_addr,
                            &remote_addrlen);
        if (received < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                perror("magnus: quic recvfrom");
            return;
        }
        if (received < 21) continue; /* too short for any QUIC packet */

        if (ngtcp2_pkt_decode_version_cid(&vc, buffer, (size_t) received,
                                          NGTCP2_MAX_CIDLEN) != 0)
            continue;

        slot = magnus_quic_cid_find(vc.dcid, vc.dcidlen);
        if (slot < 0) {
            magnus_quic_accept_new(listener_fd,
                (struct sockaddr *) &local_addr, local_addrlen,
                (struct sockaddr *) &remote_addr, remote_addrlen, buffer,
                (size_t) received);
            continue;
        }

        {
            magnus_quic_connection_t *connection =
                &magnus_quic_connections[slot];
            ngtcp2_path path;
            int rv;

            path.local.addr = (ngtcp2_sockaddr *) &connection->local_addr;
            path.local.addrlen = connection->local_addrlen;
            path.remote.addr = (ngtcp2_sockaddr *) &connection->remote_addr;
            path.remote.addrlen = connection->remote_addrlen;
            path.user_data = NULL;

            rv = ngtcp2_conn_read_pkt(connection->conn, &path, NULL, buffer,
                                     (size_t) received,
                                     magnus_quic_timestamp());
            connection->last_activity = time(NULL);
            if (rv != 0) {
                if (rv != NGTCP2_ERR_DRAINING)
                    fprintf(stderr, "magnus: quic read_pkt: %s\n",
                           ngtcp2_strerror(rv));
                magnus_quic_slot_free(slot);
                continue;
            }
            magnus_quic_flush(listener_fd, slot);
        }
    }
}

void
magnus_quic_tick(int listener_fd, time_t now)
{
    int slot;
    for (slot = 0; slot < MAGNUS_QUIC_MAX_CONNECTIONS; slot++) {
        magnus_quic_connection_t *connection = &magnus_quic_connections[slot];
        ngtcp2_tstamp expiry;
        ngtcp2_tstamp ts;

        if (!connection->in_use) continue;

        if (now - connection->last_activity > MAGNUS_QUIC_STALE_SECONDS) {
            /* Backstop only -- see MAGNUS_QUIC_STALE_SECONDS' own
             * comment; ngtcp2's own expiry handling below is what
             * normally closes an idle connection out first. */
            magnus_quic_slot_free(slot);
            continue;
        }

        expiry = ngtcp2_conn_get_expiry(connection->conn);
        ts = magnus_quic_timestamp();
        if (expiry == UINT64_MAX || expiry > ts) continue;

        if (ngtcp2_conn_handle_expiry(connection->conn, ts) != 0) {
            magnus_quic_slot_free(slot);
            continue;
        }
        magnus_quic_flush(listener_fd, slot);
    }
    magnus_quic_proxy_tick(now);
}

void
magnus_quic_shutdown(void)
{
    int slot;
    for (slot = 0; slot < MAGNUS_QUIC_MAX_CONNECTIONS; slot++) {
        if (magnus_quic_connections[slot].in_use)
            magnus_quic_slot_free(slot);
    }
    if (magnus_quic_ssl_ctx) {
        SSL_CTX_free(magnus_quic_ssl_ctx);
        magnus_quic_ssl_ctx = NULL;
    }
    magnus_quic_initialized = false;
}
