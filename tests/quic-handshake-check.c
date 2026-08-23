/* Minimal QUIC/HTTP-3 client used only for Phase 4 regression coverage
 * (see src/magnus_quic.h, docs/phase4-spike-results.md): connects to
 * 127.0.0.1:<port>, completes a real ngtcp2 handshake against magnus's
 * own QUIC listener, and -- when a third argument is given -- issues
 * one real HTTP/3 GET for that path and prints its response status and
 * body to stdout, exactly the shape tests/test-core.sh's own Phase 4
 * block checks against a running magnus. Prints "quic-handshake-check:
 * ok" (handshake-only mode) or the response (GET mode) and exits 0 on
 * success; any failure or a deadline exceeded without completion exits
 * 1 with a diagnostic on stderr. Not a general-purpose client -- no
 * request body, no more than one request stream per run, only enough
 * of RFC 9000/9114 to prove magnus's own listener and HTTP/3 static-
 * file dispatch (src/magnus_quic.c) work under real network I/O, the
 * same thing an external reference client (ngtcp2's own
 * `examples/osslclient`) was hand-verified against in
 * docs/phase4-spike-results.md before this automated, in-repo version
 * existed -- including the exact bug (a chunked read_data callback
 * that let bytes get skipped/reordered under real network I/O; see
 * magnus_quic.c's own magnus_quic_stream_t comment) this GET mode was
 * built specifically to catch a regression of.
 *
 * Deliberately skips server certificate verification
 * (SSL_VERIFY_NONE): this tool tests magnus's own QUIC transport/
 * handshake/HTTP-3 code, not certificate trust chains, and
 * test-core.sh's fixture certificate is self-signed. */

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define QUIC_HANDSHAKE_CHECK_DEADLINE_SECONDS 5
/* Roadmap 2a-9: bumped from 1 MiB to comfortably exceed MAGNUS_
 * COMPRESSION_MAX_SIZE (8 MiB, src/magnus_compression.h) -- this tool
 * is the only way to exercise HTTP/3 at all (no HTTP/3 support in this
 * project's own curl), so verifying streaming compression's own
 * well-past-8-MiB fixtures needs a body cap that can actually hold one
 * whole response, not just proving the first 1 MiB decodes correctly. */
#define QUIC_HANDSHAKE_CHECK_MAX_BODY (16u << 20)

static ngtcp2_conn *g_conn;
static nghttp3_conn *g_httpconn;
static bool g_handshake_confirmed;
static const char *g_request_path; /* NULL: handshake-only mode */
/* roadmap 4e (gzip)/2a-5 (zstd)/2a-6 (br): send Accept-Encoding: <this>
 * when non-NULL -- the literal token itself, not just a bool, so this
 * tool can exercise any of the three negotiated encodings. */
static const char *g_request_accept_encoding;
static const char *g_request_cookie; /* roadmap 4h: send Cookie: <this> */
static bool g_request_submitted;
/* roadmap 4l: after the first request completes, rebind to a fresh
 * local UDP port and issue a second request over the SAME ngtcp2
 * connection from there -- simulates the simplest, most common real
 * migration scenario (NAT rebinding: the client's own 4-tuple changes
 * mid-connection, with no explicit ngtcp2_conn_initiate_migration()
 * call needed on either side, since the server is the one that must
 * notice and validate the new path; see magnus_quic_path_validation()'s
 * own comment in src/magnus_quic.c). */
static bool g_migrate;
/* Real IP (roadmap 2b, extended to HTTP/3): send X-Forwarded-For: <this>
 * -- the same "final positional arg, '-' sentinel means absent" shape
 * every other optional request header this tool sends already uses. */
static const char *g_request_xff;
static char g_response_status[8];
static char g_response_content_encoding[32]; /* roadmap 4e */
static char g_response_vary[32]; /* roadmap 4e */
static char g_response_set_cookie[128]; /* roadmap 4h */
static char g_response_x_cache[32]; /* roadmap 4i */
static uint8_t *g_response_body;
static size_t g_response_body_len;
static bool g_response_done;

static ngtcp2_tstamp
now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp) ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp) ts.tv_nsec;
}

static ngtcp2_conn *
get_conn_cb(ngtcp2_crypto_conn_ref *ref)
{
    (void) ref;
    return g_conn;
}

static void
rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *ctx)
{
    (void) ctx;
    if (RAND_bytes(dest, (int) destlen) != 1) memset(dest, 0, destlen);
}

static int
get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
                         size_t cidlen, void *user_data)
{
    (void) conn;
    (void) user_data;
    if (RAND_bytes(cid->data, (int) cidlen) != 1)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    cid->datalen = cidlen;
    /* This test client never needs its own issued CIDs to carry a
     * usable stateless reset token -- it only ever runs one short,
     * single-path connection and never receives a stateless reset
     * addressed to one of these. */
    memset(token, 0, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

static int
recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                    uint64_t offset, const uint8_t *data, size_t datalen,
                    void *user_data, void *stream_user_data)
{
    (void) offset;
    (void) user_data;
    (void) stream_user_data;
    if (g_httpconn) {
        nghttp3_ssize consumed = nghttp3_conn_read_stream(g_httpconn, stream_id,
            data, datalen, (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0);
        if (consumed < 0) {
            fprintf(stderr, "quic-handshake-check: nghttp3_conn_read_stream: %s\n",
                   nghttp3_strerror((int) consumed));
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        ngtcp2_conn_extend_max_stream_offset(conn, stream_id, (uint64_t) consumed);
        ngtcp2_conn_extend_max_offset(conn, (uint64_t) consumed);
        return 0;
    }
    ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(conn, datalen);
    return 0;
}

static int
acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
                            uint64_t offset, uint64_t datalen,
                            void *user_data, void *stream_user_data)
{
    (void) conn;
    (void) offset;
    (void) user_data;
    (void) stream_user_data;
    if (g_httpconn
        && nghttp3_conn_add_ack_offset(g_httpconn, stream_id, datalen) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

static int
extend_max_stream_data_cb(ngtcp2_conn *conn, int64_t stream_id,
                          uint64_t max_data, void *user_data,
                          void *stream_user_data)
{
    (void) conn;
    (void) max_data;
    (void) user_data;
    (void) stream_user_data;
    if (g_httpconn && nghttp3_conn_unblock_stream(g_httpconn, stream_id) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

static int
ngtcp2_stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                       uint64_t app_error_code, void *user_data,
                       void *stream_user_data)
{
    (void) conn;
    (void) user_data;
    (void) stream_user_data;
    if (g_httpconn) {
        if ((flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) == 0)
            app_error_code = NGHTTP3_H3_NO_ERROR;
        (void) nghttp3_conn_close_stream(g_httpconn, stream_id, app_error_code);
    }
    return 0;
}

static int
handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
    (void) conn;
    (void) user_data;
    g_handshake_confirmed = true;
    return 0;
}

/* --- HTTP/3 (client side) -------------------------------------------- */

static int
http_recv_data_cb(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
                  size_t datalen, void *conn_user_data, void *stream_user_data)
{
    size_t copy_len = datalen;
    (void) conn;
    (void) stream_id;
    (void) conn_user_data;
    (void) stream_user_data;
    if (g_response_body_len + copy_len > QUIC_HANDSHAKE_CHECK_MAX_BODY)
        copy_len = QUIC_HANDSHAKE_CHECK_MAX_BODY - g_response_body_len;
    if (copy_len > 0) {
        memcpy(g_response_body + g_response_body_len, data, copy_len);
        g_response_body_len += copy_len;
    }
    ngtcp2_conn_extend_max_stream_offset(g_conn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(g_conn, datalen);
    return 0;
}

static int
http_deferred_consume_cb(nghttp3_conn *conn, int64_t stream_id,
                         size_t nconsumed, void *conn_user_data,
                         void *stream_user_data)
{
    (void) conn;
    (void) conn_user_data;
    (void) stream_user_data;
    ngtcp2_conn_extend_max_stream_offset(g_conn, stream_id, nconsumed);
    ngtcp2_conn_extend_max_offset(g_conn, nconsumed);
    return 0;
}

static int
http_begin_headers_cb(nghttp3_conn *conn, int64_t stream_id,
                      void *conn_user_data, void *stream_user_data)
{
    (void) conn;
    (void) stream_id;
    (void) conn_user_data;
    (void) stream_user_data;
    return 0;
}

static int
http_recv_header_cb(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                    nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                    void *conn_user_data, void *stream_user_data)
{
    (void) conn;
    (void) stream_id;
    (void) flags;
    (void) conn_user_data;
    (void) stream_user_data;
    if (token == NGHTTP3_QPACK_TOKEN__STATUS) {
        nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
        size_t length = v.len < sizeof(g_response_status) - 1
            ? v.len : sizeof(g_response_status) - 1;
        memcpy(g_response_status, v.base, length);
        g_response_status[length] = '\0';
    } else if (token == NGHTTP3_QPACK_TOKEN_CONTENT_ENCODING) {
        nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
        size_t length = v.len < sizeof(g_response_content_encoding) - 1
            ? v.len : sizeof(g_response_content_encoding) - 1;
        memcpy(g_response_content_encoding, v.base, length);
        g_response_content_encoding[length] = '\0';
    } else if (token == NGHTTP3_QPACK_TOKEN_VARY) {
        nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
        size_t length = v.len < sizeof(g_response_vary) - 1
            ? v.len : sizeof(g_response_vary) - 1;
        memcpy(g_response_vary, v.base, length);
        g_response_vary[length] = '\0';
    } else if (token == NGHTTP3_QPACK_TOKEN_SET_COOKIE) {
        nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
        size_t length = v.len < sizeof(g_response_set_cookie) - 1
            ? v.len : sizeof(g_response_set_cookie) - 1;
        memcpy(g_response_set_cookie, v.base, length);
        g_response_set_cookie[length] = '\0';
    } else {
        /* No QPACK static-table token for "x-cache" (roadmap 4i) --
         * it is not a standard HTTP header, so unlike every other
         * response header captured above this one is matched by name
         * instead of by its own token. */
        nghttp3_vec n = nghttp3_rcbuf_get_buf(name);
        if (n.len == 7 && strncasecmp((const char *) n.base, "x-cache", 7)
            == 0) {
            nghttp3_vec v = nghttp3_rcbuf_get_buf(value);
            size_t length = v.len < sizeof(g_response_x_cache) - 1
                ? v.len : sizeof(g_response_x_cache) - 1;
            memcpy(g_response_x_cache, v.base, length);
            g_response_x_cache[length] = '\0';
        }
    }
    return 0;
}

static int
http_end_headers_cb(nghttp3_conn *conn, int64_t stream_id, int fin,
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
http_end_stream_cb(nghttp3_conn *conn, int64_t stream_id, void *conn_user_data,
                   void *stream_user_data)
{
    (void) conn;
    (void) stream_id;
    (void) conn_user_data;
    (void) stream_user_data;
    g_response_done = true;
    return 0;
}

static int
http_acked_stream_data_cb(nghttp3_conn *conn, int64_t stream_id,
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

/* roadmap 4l: split out of setup_httpconn() below so a second,
 * post-migration request can open a fresh bidi stream and submit
 * again without re-creating the http3 connection or its control/QPACK
 * streams (nghttp3_conn already supports many requests per
 * connection -- that is the entire premise roadmap 4j's own
 * connection pooling relies on for h1/h2). */
static int
submit_request(void)
{
    int64_t request_stream_id;
    nghttp3_nv headers[7];
    size_t header_count = 4;

    if (ngtcp2_conn_open_bidi_stream(g_conn, &request_stream_id, NULL) != 0) {
        fprintf(stderr, "quic-handshake-check: open_bidi_stream failed\n");
        return -1;
    }
    headers[0] = (nghttp3_nv) { .name = (const uint8_t *) ":method",
        .value = (const uint8_t *) "GET", .namelen = 7, .valuelen = 3 };
    headers[1] = (nghttp3_nv) { .name = (const uint8_t *) ":scheme",
        .value = (const uint8_t *) "https", .namelen = 7, .valuelen = 5 };
    headers[2] = (nghttp3_nv) { .name = (const uint8_t *) ":authority",
        .value = (const uint8_t *) "localhost", .namelen = 10, .valuelen = 9 };
    headers[3] = (nghttp3_nv) { .name = (const uint8_t *) ":path",
        .value = (const uint8_t *) g_request_path, .namelen = 5,
        .valuelen = strlen(g_request_path) };
    if (g_request_accept_encoding != NULL) {
        headers[header_count] = (nghttp3_nv) {
            .name = (const uint8_t *) "accept-encoding",
            .value = (const uint8_t *) g_request_accept_encoding, .namelen = 15,
            .valuelen = strlen(g_request_accept_encoding) };
        header_count++;
    }
    if (g_request_cookie != NULL) {
        headers[header_count] = (nghttp3_nv) { .name = (const uint8_t *) "cookie",
            .value = (const uint8_t *) g_request_cookie, .namelen = 6,
            .valuelen = strlen(g_request_cookie) };
        header_count++;
    }
    if (g_request_xff != NULL) {
        headers[header_count] = (nghttp3_nv) {
            .name = (const uint8_t *) "x-forwarded-for",
            .value = (const uint8_t *) g_request_xff, .namelen = 15,
            .valuelen = strlen(g_request_xff) };
        header_count++;
    }
    if (nghttp3_conn_submit_request(g_httpconn, request_stream_id, headers,
                                    header_count, NULL, NULL) != 0) {
        fprintf(stderr, "quic-handshake-check: nghttp3_conn_submit_request "
                        "failed\n");
        return -1;
    }
    g_request_submitted = true;
    return 0;
}

static int
setup_httpconn(void)
{
    nghttp3_callbacks callbacks;
    nghttp3_settings settings;
    int64_t control_stream_id, qpack_encoder_stream_id, qpack_decoder_stream_id;

    if (g_httpconn || !g_request_path) return 0;

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.recv_data = http_recv_data_cb;
    callbacks.deferred_consume = http_deferred_consume_cb;
    callbacks.begin_headers = http_begin_headers_cb;
    callbacks.recv_header = http_recv_header_cb;
    callbacks.end_headers = http_end_headers_cb;
    callbacks.end_stream = http_end_stream_cb;
    callbacks.acked_stream_data = http_acked_stream_data_cb;
    /* No .rand: see src/magnus_quic.c's own comment (its
     * magnus_quic_setup_http3()) on why -- not present in every
     * nghttp3_callbacks version this project builds against, and
     * "optional due to backward compatibility" per nghttp3's own docs. */

    nghttp3_settings_default(&settings);

    if (nghttp3_conn_client_new(&g_httpconn, &callbacks, &settings, NULL,
                                NULL) != 0) {
        fprintf(stderr, "quic-handshake-check: nghttp3_conn_client_new failed\n");
        return -1;
    }

    if (ngtcp2_conn_open_uni_stream(g_conn, &control_stream_id, NULL) != 0
        || nghttp3_conn_bind_control_stream(g_httpconn, control_stream_id) != 0
        || ngtcp2_conn_open_uni_stream(g_conn, &qpack_encoder_stream_id,
                                       NULL) != 0
        || ngtcp2_conn_open_uni_stream(g_conn, &qpack_decoder_stream_id,
                                       NULL) != 0
        || nghttp3_conn_bind_qpack_streams(g_httpconn, qpack_encoder_stream_id,
                                           qpack_decoder_stream_id) != 0) {
        fprintf(stderr, "quic-handshake-check: http3 control/qpack setup "
                        "failed\n");
        return -1;
    }

    return submit_request();
}

static int
recv_rx_key_cb(ngtcp2_conn *conn, ngtcp2_encryption_level level,
               void *user_data)
{
    (void) conn;
    (void) user_data;
    if (level != NGTCP2_ENCRYPTION_LEVEL_1RTT) return 0;
    if (setup_httpconn() != 0) return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

static void
flush(int fd)
{
    uint8_t buffer[1500];
    for (;;) {
        ngtcp2_path path;
        ngtcp2_ssize written;
        ngtcp2_ssize ndatalen = -1;
        int64_t stream_id = -1;
        int fin = 0;
        nghttp3_vec vec[1];
        nghttp3_ssize veccnt = 0;
        uint32_t write_flags = NGTCP2_WRITE_STREAM_FLAG_MORE;

        memset(&path, 0, sizeof(path));

        if (g_httpconn && ngtcp2_conn_get_max_data_left(g_conn) > 0) {
            veccnt = nghttp3_conn_writev_stream(g_httpconn, &stream_id, &fin,
                vec, sizeof(vec) / sizeof(vec[0]));
            if (veccnt < 0) {
                fprintf(stderr, "quic-handshake-check: "
                                "nghttp3_conn_writev_stream: %s\n",
                       nghttp3_strerror((int) veccnt));
                return;
            }
        }
        if (fin) write_flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

        written = ngtcp2_conn_writev_stream(g_conn, NULL, NULL, buffer,
            sizeof(buffer), &ndatalen, write_flags, stream_id,
            (const ngtcp2_vec *) vec, (size_t) veccnt, now_ns());
        if (written < 0) {
            int rv = (int) written;
            if (rv == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                (void) nghttp3_conn_block_stream(g_httpconn, stream_id);
                continue;
            }
            if (rv == NGTCP2_ERR_STREAM_SHUT_WR) {
                (void) nghttp3_conn_shutdown_stream_write(g_httpconn,
                                                          stream_id);
                continue;
            }
            if (rv == NGTCP2_ERR_WRITE_MORE) {
                (void) nghttp3_conn_add_write_offset(g_httpconn, stream_id,
                                                     (size_t) ndatalen);
                continue;
            }
            fprintf(stderr, "quic-handshake-check: writev_stream: %s\n",
                   ngtcp2_strerror(rv));
            return;
        }
        if (ndatalen >= 0 && g_httpconn)
            (void) nghttp3_conn_add_write_offset(g_httpconn, stream_id,
                                                 (size_t) ndatalen);
        if (written == 0) return;
        if (send(fd, buffer, (size_t) written, 0) < 0
            && errno != EAGAIN && errno != EWOULDBLOCK)
            perror("quic-handshake-check: send");
    }
}

static bool
phase1_done(void)
{
    return g_handshake_confirmed && (!g_request_path || g_response_done);
}

static bool
phase2_done(void)
{
    return g_response_done;
}

/* Drives the connection (retransmission/idle-timeout expiry, reading
 * whatever arrives on `fd`, flushing whatever that produces) until
 * `is_done()` reports true or `deadline` passes -- the exact loop
 * `main()` always ran inline for the single-path case; factored out
 * here (roadmap 4l) so a post-migration second wait can reuse it
 * unchanged against a *different* fd and path once the first request
 * has already completed. `path` is passed through to
 * ngtcp2_conn_read_pkt() unchanged from what the caller set up --
 * this client, unlike magnus_quic.c's own server-side fix this tool
 * exists to exercise, never needs to update it mid-loop: it only ever
 * has one path active at a time, and migrates by tearing down and
 * rebuilding path/fd together between calls, not by tracking a
 * changing path within one. */
static int
run_event_loop(int fd, ngtcp2_path *path, ngtcp2_tstamp deadline,
               bool (*is_done)(void))
{
    while (now_ns() < deadline) {
        ngtcp2_tstamp expiry;
        ngtcp2_tstamp ts;
        int timeout_ms = 200;
        struct pollfd pfd;

        if (is_done()) return 0;

        expiry = ngtcp2_conn_get_expiry(g_conn);
        ts = now_ns();
        if (expiry != UINT64_MAX && expiry <= ts) {
            if (ngtcp2_conn_handle_expiry(g_conn, ts) != 0) {
                fprintf(stderr, "quic-handshake-check: handle_expiry failed\n");
                return -1;
            }
            flush(fd);
            continue;
        }
        if (expiry != UINT64_MAX) {
            ngtcp2_tstamp remaining_ns = expiry - ts;
            int64_t remaining_ms = (int64_t) (remaining_ns / NGTCP2_MILLISECONDS);
            if (remaining_ms >= 0 && remaining_ms < timeout_ms)
                timeout_ms = (int) remaining_ms;
        }

        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        if (poll(&pfd, 1, timeout_ms) > 0 && (pfd.revents & POLLIN)) {
            uint8_t buffer[65536];
            ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
            if (received > 0) {
                int rv = ngtcp2_conn_read_pkt(g_conn, path, NULL, buffer,
                                             (size_t) received, now_ns());
                if (rv != 0 && rv != NGTCP2_ERR_DRAINING) {
                    fprintf(stderr, "quic-handshake-check: read_pkt: %s\n",
                           ngtcp2_strerror(rv));
                    return -1;
                }
                flush(fd);
            }
        }
    }
    return 0; /* deadline reached -- caller checks is_done()/response state
                * itself, same as before this was factored out */
}

int
main(int argc, char **argv)
{
    const char *host;
    unsigned long port;
    int fd;
    struct sockaddr_in address;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    ngtcp2_crypto_ossl_ctx *ossl_ctx;
    ngtcp2_crypto_conn_ref conn_ref;
    ngtcp2_cid dcid, scid;
    ngtcp2_path path;
    ngtcp2_callbacks callbacks;
    ngtcp2_settings settings;
    ngtcp2_transport_params params;
    struct sockaddr_storage local_addr;
    struct sockaddr_storage remote_addr;
    socklen_t local_addrlen = sizeof(local_addr);
    socklen_t remote_addrlen = sizeof(remote_addr);
    ngtcp2_tstamp deadline;
    static const unsigned char alpn_h3[] = { 2, 'h', '3' };

    if (argc < 3 || argc > 8) {
        fprintf(stderr,
            "usage: %s <host> <port> [request-path] [gzip|zstd|br|-] "
            "[cookie|-] [migrate|-] [xff]\n", argv[0]);
        return 2;
    }
    host = argv[1];
    port = strtoul(argv[2], NULL, 10);
    if (argc >= 4) g_request_path = argv[3];
    if (argc >= 5 && (strcmp(argv[4], "gzip") == 0
                       || strcmp(argv[4], "zstd") == 0
                       || strcmp(argv[4], "br") == 0))
        g_request_accept_encoding = argv[4];
    /* "-" is a no-op sentinel here too (matching argv[4]'s own "gzip|-"
     * convention) -- needed so a caller that wants the trailing
     * "migrate"/xff args (roadmap 4l/2b) but no cookie does not have to
     * send a literal, meaningless "Cookie: -" header just to keep the
     * cookie slot's position. */
    if (argc >= 6 && strcmp(argv[5], "-") != 0) g_request_cookie = argv[5];
    if (argc >= 7) g_migrate = strcmp(argv[6], "migrate") == 0;
    if (argc == 8 && strcmp(argv[7], "-") != 0) g_request_xff = argv[7];

    g_response_body = malloc(QUIC_HANDSHAKE_CHECK_MAX_BODY);
    if (!g_response_body) {
        fprintf(stderr, "quic-handshake-check: malloc failed\n");
        return 1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("quic-handshake-check: socket"); return 1; }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t) port);
    if (inet_pton(AF_INET, host, &address.sin_addr) != 1) {
        fprintf(stderr, "quic-handshake-check: bad host '%s'\n", host);
        return 2;
    }
    if (connect(fd, (struct sockaddr *) &address, sizeof(address)) < 0) {
        perror("quic-handshake-check: connect");
        return 1;
    }
    if (getsockname(fd, (struct sockaddr *) &local_addr, &local_addrlen) < 0) {
        perror("quic-handshake-check: getsockname");
        return 1;
    }
    memcpy(&remote_addr, &address, sizeof(address));
    remote_addrlen = sizeof(address);

    if (ngtcp2_crypto_ossl_init() != 0) {
        fprintf(stderr, "quic-handshake-check: ngtcp2_crypto_ossl_init failed\n");
        return 1;
    }

    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL); /* see file header */

    if (ngtcp2_crypto_ossl_ctx_new(&ossl_ctx, NULL) != 0) {
        fprintf(stderr, "quic-handshake-check: ngtcp2_crypto_ossl_ctx_new failed\n");
        return 1;
    }
    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    ngtcp2_crypto_ossl_ctx_set_ssl(ossl_ctx, ssl);
    if (ngtcp2_crypto_ossl_configure_client_session(ssl) != 0) {
        fprintf(stderr,
               "quic-handshake-check: ngtcp2_crypto_ossl_configure_client_session "
               "failed\n");
        return 1;
    }
    SSL_set_alpn_protos(ssl, alpn_h3, sizeof(alpn_h3));
    SSL_set_tlsext_host_name(ssl, "localhost");
    SSL_set_connect_state(ssl);

    conn_ref.get_conn = get_conn_cb;
    conn_ref.user_data = NULL;
    SSL_set_app_data(ssl, &conn_ref);

    if (RAND_bytes(dcid.data, NGTCP2_MIN_INITIAL_DCIDLEN) != 1
        || RAND_bytes(scid.data, NGTCP2_MIN_INITIAL_DCIDLEN) != 1) {
        fprintf(stderr, "quic-handshake-check: RAND_bytes failed\n");
        return 1;
    }
    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    scid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;

    path.local.addr = (ngtcp2_sockaddr *) &local_addr;
    path.local.addrlen = local_addrlen;
    path.remote.addr = (ngtcp2_sockaddr *) &remote_addr;
    path.remote.addrlen = remote_addrlen;
    path.user_data = NULL;

    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_stream_data = recv_stream_data_cb;
    callbacks.acked_stream_data_offset = acked_stream_data_offset_cb;
    callbacks.stream_close = ngtcp2_stream_close_cb;
    callbacks.extend_max_stream_data = extend_max_stream_data_cb;
    callbacks.recv_rx_key = recv_rx_key_cb;
    callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
    callbacks.rand = rand_cb;
    callbacks.get_new_connection_id = get_new_connection_id_cb;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
    callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    callbacks.handshake_completed = handshake_completed_cb;

    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ns();

    ngtcp2_transport_params_default(&params);
    params.initial_max_data = 1u << 20;
    /* Local (bidi streams this client itself opens, i.e. the one HTTP/3
     * request stream in GET mode): needs real flow-control room, unlike
     * handshake-only mode's original 0. Remote (bidi streams the SERVER
     * would open toward the client) stays 0 -- HTTP/3 servers never
     * initiate requests. */
    params.initial_max_stream_data_bidi_local = 1u << 16;
    params.initial_max_stream_data_bidi_remote = 0;
    params.initial_max_streams_bidi = 0;
    params.initial_max_streams_uni = 3;
    params.initial_max_stream_data_uni = 1u << 16;

    if (ngtcp2_conn_client_new(&g_conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                               &callbacks, &settings, &params, NULL, NULL) != 0) {
        fprintf(stderr, "quic-handshake-check: ngtcp2_conn_client_new failed\n");
        return 1;
    }
    ngtcp2_conn_set_tls_native_handle(g_conn, ossl_ctx);

    flush(fd);

    deadline = now_ns() + (ngtcp2_tstamp) QUIC_HANDSHAKE_CHECK_DEADLINE_SECONDS
        * NGTCP2_SECONDS;
    if (run_event_loop(fd, &path, deadline, phase1_done) != 0) return 1;

    if (!g_handshake_confirmed) {
        fprintf(stderr, "quic-handshake-check: handshake not confirmed within "
                        "%d seconds\n", QUIC_HANDSHAKE_CHECK_DEADLINE_SECONDS);
        return 1;
    }

    if (!g_request_path) {
        printf("quic-handshake-check: ok\n");
        return 0;
    }

    if (!g_response_done) {
        fprintf(stderr, "quic-handshake-check: request to '%s' did not "
                        "complete within %d seconds\n", g_request_path,
               QUIC_HANDSHAKE_CHECK_DEADLINE_SECONDS);
        return 1;
    }

    if (g_migrate) {
        /* roadmap 4l: rebind to a fresh local UDP port -- the simplest,
         * most common real migration scenario (NAT rebinding). No
         * ngtcp2_conn_initiate_migration() call is needed on this side:
         * the SAME connection ID keeps being used, from a new source
         * port, and it is the SERVER's job to notice and validate the
         * new path (see src/magnus_quic.c's own
         * magnus_quic_path_validation() comment) -- which is exactly
         * the behavior this mode exists to prove actually happens, not
         * merely compiles. A second, independent HTTP/3 request is
         * then submitted on the same g_conn/g_httpconn and must
         * complete entirely over the new path for this to pass. */
        int new_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (new_fd < 0) {
            perror("quic-handshake-check: migrate socket");
            return 1;
        }
        if (connect(new_fd, (struct sockaddr *) &address, sizeof(address))
            < 0) {
            perror("quic-handshake-check: migrate connect");
            return 1;
        }
        local_addrlen = sizeof(local_addr);
        if (getsockname(new_fd, (struct sockaddr *) &local_addr,
                        &local_addrlen) < 0) {
            perror("quic-handshake-check: migrate getsockname");
            return 1;
        }
        path.local.addrlen = local_addrlen; /* path.local.addr already
                                              * points at &local_addr,
                                              * just refreshed in place */
        close(fd);
        fd = new_fd;

        /* ngtcp2_conn_initiate_migration()'s own doc comment is explicit:
         * "Only client can initiate migration" -- simply reading packets
         * whose `path` differs from what this connection was created
         * with (as this file did before this fix) is not enough for a
         * CLIENT connection; unlike the SERVER side (which reacts to
         * whatever path a packet's own recvfrom() reports, no explicit
         * app call needed -- see this mode's own top comment and
         * src/magnus_quic.c's read-path fix), the client side is
         * required to register its own path change explicitly before
         * ngtcp2 will treat data arriving there as real (rather than
         * silently decoding-but-discarding it, which is exactly what
         * was observed before this call was added: read_pkt succeeded
         * with no error, yet recv_stream_data_cb never fired for the
         * new stream). This starts ngtcp2's own path validation on the
         * new path from the client's side too -- the client and server
         * each independently validate the SAME new path, meeting in the
         * middle via PATH_CHALLENGE/PATH_RESPONSE either one of them
         * could have initiated first. */
        if (ngtcp2_conn_initiate_migration(g_conn, &path, now_ns()) != 0) {
            fprintf(stderr,
                   "quic-handshake-check: initiate_migration failed\n");
            return 1;
        }

        g_response_done = false;
        g_response_body_len = 0;
        g_response_status[0] = '\0';
        g_response_content_encoding[0] = '\0';
        g_response_vary[0] = '\0';
        g_response_set_cookie[0] = '\0';
        g_response_x_cache[0] = '\0';

        if (submit_request() != 0) return 1;
        flush(fd);

        deadline = now_ns()
            + (ngtcp2_tstamp) QUIC_HANDSHAKE_CHECK_DEADLINE_SECONDS
            * NGTCP2_SECONDS;
        if (run_event_loop(fd, &path, deadline, phase2_done) != 0) return 1;

        if (!g_response_done) {
            fprintf(stderr, "quic-handshake-check: post-migration request "
                            "to '%s' did not complete within %d seconds\n",
                   g_request_path, QUIC_HANDSHAKE_CHECK_DEADLINE_SECONDS);
            return 1;
        }
    }

    printf("status: %s\n", g_response_status);
    printf("content-length: %zu\n", g_response_body_len);
    /* Printed only when actually present (roadmap 4e) -- every existing
     * caller's own `tail -n +3` (skip exactly status + content-length)
     * stays correct for a non-gzip response; magnus_quic.c only ever
     * sends these two together (never one without the other), so a
     * caller expecting a compressed response uses `tail -n +5` instead. */
    if (g_response_content_encoding[0] != '\0')
        printf("content-encoding: %s\n", g_response_content_encoding);
    if (g_response_vary[0] != '\0')
        printf("vary: %s\n", g_response_vary);
    /* roadmap 4h -- same "printed only when present" convention. */
    if (g_response_set_cookie[0] != '\0')
        printf("set-cookie: %s\n", g_response_set_cookie);
    /* roadmap 4i -- same convention again. */
    if (g_response_x_cache[0] != '\0')
        printf("x-cache: %s\n", g_response_x_cache);
    fwrite(g_response_body, 1, g_response_body_len, stdout);
    /* Skipped for a compressed body (roadmap 4e): gzip's own trailing
     * bytes are effectively random, so this readability nicety would
     * silently corrupt the stream for a caller that pipes the body
     * straight into gunzip. */
    if (g_response_content_encoding[0] == '\0'
        && (g_response_body_len == 0
            || g_response_body[g_response_body_len - 1] != '\n'))
        printf("\n");
    return 0;
}
