#ifndef MAGNUS_H2_H
#define MAGNUS_H2_H

#include <openssl/ssl.h>

/* HTTP/2 (roadmap Phase 1e-1) ALPN negotiation. Kept as its own small,
 * self-contained module -- unlike the rest of the HTTP/2 integration
 * (nghttp2 session wiring, request dispatch), which lives directly in
 * magnus.c because nghttp2's callback model needs deep access to
 * magnus.c's own static-file-serving and socket-I/O internals -- this
 * callback needs nothing beyond the raw ALPN protocol list TLS itself
 * hands it, so it has no such dependency and is easy to reason about
 * and test in isolation. */

/* Registers the ALPN callback that offers "h2" on `ctx`. Every TLS
 * context magnus creates (initial load and every config reload) must
 * call this for HTTP/2 to be reachable at all; a client that does not
 * offer "h2" negotiates nothing, and its connection proceeds exactly as
 * any ordinary HTTP/1.1-over-TLS connection always has -- ALPN is
 * additive, not a mode switch on the listener itself. */
void magnus_h2_configure_alpn(SSL_CTX *ctx);

/* The callback itself, exposed only so tests/test-h2.c can exercise its
 * client-list scanning directly (bounds, malformed-length handling, no
 * match, exact match) without needing a real TLS handshake to reach it --
 * not meant to be called directly by application code, which only ever
 * needs magnus_h2_configure_alpn() above. */
int magnus_h2_alpn_select_callback(SSL *ssl, const unsigned char **out,
                                   unsigned char *outlen,
                                   const unsigned char *in, unsigned int inlen,
                                   void *arg);

#endif
