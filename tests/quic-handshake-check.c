/* Minimal QUIC client used only for Phase 4a regression coverage (see
 * src/magnus_quic.h and docs/phase4-spike-results.md): connects to
 * 127.0.0.1:<port>, completes a real ngtcp2 handshake against magnus's
 * own QUIC listener, prints "quic-handshake-check: ok" and exits 0 on
 * success. Any failure or a 5-second deadline exceeded without
 * confirmation exits 1 with a diagnostic on stderr. Not a general-
 * purpose QUIC client -- it never opens a stream or sends application
 * data, only enough of RFC 9000's handshake to prove magnus's own
 * listener (src/magnus_quic.c) completes one under real network I/O,
 * the same thing an external reference client (ngtcp2's own
 * `examples/osslclient`) was hand-verified against in
 * docs/phase4-spike-results.md before this automated, in-repo version
 * existed.
 *
 * Deliberately skips server certificate verification
 * (SSL_VERIFY_NONE): this tool tests magnus's own QUIC transport/
 * handshake code, not certificate trust chains, and test-core.sh's
 * fixture certificate is self-signed. */

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

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
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define QUIC_HANDSHAKE_CHECK_DEADLINE_SECONDS 5

static ngtcp2_conn *g_conn;
static bool g_handshake_confirmed;

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
    (void) flags;
    (void) offset;
    (void) data;
    (void) user_data;
    (void) stream_user_data;
    ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(conn, datalen);
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

static void
flush(int fd)
{
    uint8_t buffer[1500];
    for (;;) {
        ngtcp2_ssize written = ngtcp2_conn_writev_stream(g_conn, NULL, NULL,
            buffer, sizeof(buffer), NULL, NGTCP2_WRITE_STREAM_FLAG_NONE, -1,
            NULL, 0, now_ns());
        if (written <= 0) return;
        if (send(fd, buffer, (size_t) written, 0) < 0
            && errno != EAGAIN && errno != EWOULDBLOCK)
            perror("quic-handshake-check: send");
    }
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

    if (argc != 3) {
        fprintf(stderr, "usage: %s <host> <port>\n", argv[0]);
        return 2;
    }
    host = argv[1];
    port = strtoul(argv[2], NULL, 10);

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
    params.initial_max_stream_data_bidi_local = 0;
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
    while (!g_handshake_confirmed && now_ns() < deadline) {
        ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(g_conn);
        ngtcp2_tstamp ts = now_ns();
        int timeout_ms = 200;
        struct pollfd pfd;

        if (expiry != UINT64_MAX && expiry <= ts) {
            if (ngtcp2_conn_handle_expiry(g_conn, ts) != 0) {
                fprintf(stderr, "quic-handshake-check: handle_expiry failed\n");
                return 1;
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
                int rv = ngtcp2_conn_read_pkt(g_conn, &path, NULL, buffer,
                                             (size_t) received, now_ns());
                if (rv != 0 && rv != NGTCP2_ERR_DRAINING) {
                    fprintf(stderr, "quic-handshake-check: read_pkt: %s\n",
                           ngtcp2_strerror(rv));
                    return 1;
                }
                flush(fd);
            }
        }
    }

    if (!g_handshake_confirmed) {
        fprintf(stderr, "quic-handshake-check: handshake not confirmed within "
                        "%d seconds\n", QUIC_HANDSHAKE_CHECK_DEADLINE_SECONDS);
        return 1;
    }

    printf("quic-handshake-check: ok\n");
    return 0;
}
