#include "magnus_h2.h"

/* Deliberately not `SSL_select_next_proto()`: that function's contract
 * for a client list nghttp2/OpenSSL considers malformed or empty has
 * shifted across versions and was itself the subject of a real CVE
 * (CVE-2024-5535) in the not-too-distant past. With exactly one
 * candidate protocol to look for, a direct, bounded scan of the
 * (length-prefixed, RFC 7301 wire format) client list avoids depending
 * on that function's edge-case behavior at all. Malformed input (a
 * length byte that would run past the end of the buffer) is handled by
 * simply stopping the scan and reporting no match -- never reading past
 * `inlen`. */
int
magnus_h2_alpn_select_callback(SSL *ssl, const unsigned char **out,
                               unsigned char *outlen, const unsigned char *in,
                               unsigned int inlen, void *arg)
{
    unsigned int offset = 0;
    (void) ssl;
    (void) arg;
    while (offset < inlen) {
        unsigned char entry_length = in[offset];
        if (offset + 1 + (unsigned int) entry_length > inlen) break;
        if (entry_length == 2 && in[offset + 1] == 'h' && in[offset + 2] == '2') {
            *out = in + offset + 1;
            *outlen = entry_length;
            return SSL_TLSEXT_ERR_OK;
        }
        offset += 1 + entry_length;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

void
magnus_h2_configure_alpn(SSL_CTX *ctx)
{
    SSL_CTX_set_alpn_select_cb(ctx, magnus_h2_alpn_select_callback, NULL);
}
