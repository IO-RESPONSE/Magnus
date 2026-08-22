#include "magnus_quic.h"
#include "magnus_static.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    char method[8];
    char path[256];
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
    if (stream->mmap_base) munmap(stream->mmap_base, stream->mmap_length);
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

/* --- HTTP/3 (roadmap Phase 4b, see magnus_quic.h) ---------------------
 *
 * Scoped the same way HTTP/2's own first increment (roadmap 1e-1) was:
 * static-file GET/HEAD only. No proxy dispatch, no /healthz//metrics
 * over h3, no compression -- those are what nghttp2's own later
 * increments (1e-2, 1e-4) added on top of an identical starting point,
 * and h3 can follow the same path in its own later increments rather
 * than trying to reach parity in one step. Reuses magnus.c's own
 * magnus_open_static()/magnus_content_type() (magnus_static.h) so both
 * protocols agree on path resolution/traversal safety and MIME typing
 * by construction, the same reasoning magnus_h2_dispatch_static()'s own
 * comment gives for doing the same on the h2 side. */

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
    /* The whole file in one vec, EOF immediately -- see
     * magnus_quic_stream_t's own comment on why this is mmap'd rather
     * than read in chunks. A zero-length file is valid input (vec.len
     * 0, base non-NULL) and nghttp3 handles it correctly as "no body". */
    vec[0].base = stream->mmap_base;
    vec[0].len = stream->mmap_length;
    *pflags |= NGHTTP3_DATA_FLAG_EOF;
    return 1;
}

/* Serves stream->path as a static file -- called once a request's
 * headers and (if any) body have both been fully received (the
 * end_stream nghttp3 callback below), exactly the same trigger point
 * magnus_h2_dispatch()'s own non-early-response path uses. No request
 * body is ever read for GET/HEAD, so in practice this fires as soon as
 * headers finish for the only two methods this increment accepts. */
static void
magnus_quic_http_dispatch_static(magnus_quic_connection_t *connection,
                                 magnus_quic_stream_t *stream)
{
    struct stat metadata;
    const char *content_type;
    char content_length[32];
    nghttp3_nv headers[4];
    int fd;

    stream->head_only = strcmp(stream->method, "HEAD") == 0;
    if (stream->path[0] == '\0'
        || (strcmp(stream->method, "GET") != 0 && !stream->head_only)) {
        magnus_quic_http_submit_status(connection, stream, "400");
        return;
    }
    fd = magnus_open_static(stream->path, &metadata);
    if (fd < 0) {
        magnus_quic_http_submit_status(connection, stream, "404");
        return;
    }
    content_type = magnus_content_type(stream->path);
    snprintf(content_length, sizeof(content_length), "%lld",
            (long long) metadata.st_size);
    headers[0] = magnus_quic_nv(":status", "200");
    headers[1] = magnus_quic_nv("server", "Magnus/" MAGNUS_VERSION);
    headers[2] = magnus_quic_nv("content-type", content_type);
    headers[3] = magnus_quic_nv("content-length", content_length);
    if (stream->head_only) {
        close(fd);
        (void) nghttp3_conn_submit_response(connection->http3_conn,
                                            stream->stream_id, headers, 4,
                                            NULL);
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
                                            stream->stream_id, headers, 4,
                                            &reader);
    }
}

static int
magnus_quic_http_acked_stream_data(nghttp3_conn *conn, int64_t stream_id,
                                   uint64_t datalen, void *conn_user_data,
                                   void *stream_user_data)
{
    (void) conn;
    (void) stream_id;
    (void) datalen;
    (void) conn_user_data;
    (void) stream_user_data;
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

static int
magnus_quic_http_recv_header(nghttp3_conn *conn, int64_t stream_id,
                             int32_t token, nghttp3_rcbuf *name,
                             nghttp3_rcbuf *value, uint8_t flags,
                             void *conn_user_data, void *stream_user_data)
{
    magnus_quic_stream_t *stream = stream_user_data;
    nghttp3_vec v;
    (void) conn;
    (void) stream_id;
    (void) name;
    (void) flags;
    (void) conn_user_data;
    if (stream == NULL) return 0;
    v = nghttp3_rcbuf_get_buf(value);
    if (token == NGHTTP3_QPACK_TOKEN__METHOD) {
        size_t length = v.len < sizeof(stream->method) - 1
            ? v.len : sizeof(stream->method) - 1;
        memcpy(stream->method, v.base, length);
        stream->method[length] = '\0';
    } else if (token == NGHTTP3_QPACK_TOKEN__PATH) {
        size_t length = v.len < sizeof(stream->path) - 1
            ? v.len : sizeof(stream->path) - 1;
        memcpy(stream->path, v.base, length);
        stream->path[length] = '\0';
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
    magnus_quic_http_dispatch_static(connection, stream);
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
