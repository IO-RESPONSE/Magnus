#include "magnus_quic.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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
} magnus_quic_connection_t;

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

static void
magnus_quic_slot_free(int slot)
{
    magnus_quic_connection_t *connection = &magnus_quic_connections[slot];
    magnus_quic_cid_remove_slot(slot);
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
    /* Phase 4a scope (see magnus_quic.h): drain flow control only, no
     * HTTP/3 framing yet -- nghttp3 wiring is 4b's job. Deliberately
     * discards `data`; only its length matters here. */
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

        memset(&pi, 0, sizeof(pi));
        path.local.addr = (ngtcp2_sockaddr *) &connection->local_addr;
        path.local.addrlen = connection->local_addrlen;
        path.remote.addr = (ngtcp2_sockaddr *) &connection->remote_addr;
        path.remote.addrlen = connection->remote_addrlen;
        path.user_data = NULL;

        written = ngtcp2_conn_writev_stream(connection->conn, &path, &pi,
            buffer, sizeof(buffer), NULL, NGTCP2_WRITE_STREAM_FLAG_NONE, -1,
            NULL, 0, magnus_quic_timestamp());
        if (written < 0) {
            fprintf(stderr, "magnus: quic writev_stream: %s\n",
                   ngtcp2_strerror((int) written));
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
    params.initial_max_stream_data_bidi_local = 0;
    params.initial_max_stream_data_bidi_remote = 0;
    /* Bidi streams (HTTP/3 request/response) stay closed in 4a -- see
     * magnus_quic.h's own scope note; nonzero uni lets a real HTTP/3
     * client still open its three control/QPACK streams (RFC 9114 6.2)
     * without erroring the connection out from under the handshake
     * this increment is actually here to validate. */
    params.initial_max_streams_bidi = 0;
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
