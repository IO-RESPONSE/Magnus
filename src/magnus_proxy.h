#ifndef MAGNUS_PROXY_H
#define MAGNUS_PROXY_H

#include <stdbool.h>
#include <stddef.h>

/* True if `name` (an HTTP header field name, case-insensitive) is a
 * hop-by-hop header per RFC 7230 6.1 and must not be relayed across a
 * proxy boundary unchanged. */
bool magnus_proxy_is_hop_by_hop(const char *name);

typedef struct {
    unsigned status;
    /* Whether the client-facing Connection header this call wrote was
     * "keep-alive" (true) or "close" (false) -- i.e. whether the client
     * connection may stay open after this response. Requires both that
     * the client's own request wanted keep-alive (client_wants_close was
     * false) and that the response body's length is unambiguous
     * (has_content_length below): a response framed by the upstream
     * closing its connection can only ever be relayed to the client the
     * same way. */
    bool keep_client_alive;
    /* Whether the *upstream* connection this response came in on may be
     * pooled for reuse: has_content_length, and the upstream did not
     * itself send Connection: close. Independent of keep_client_alive --
     * the upstream leg and the client leg are pooled/kept-alive on their
     * own separate merits. */
    bool upstream_poolable;
    /* True if exactly one well-formed Content-Length was present and no
     * Transfer-Encoding was (chunked upstream responses are not decoded
     * yet, so they are always treated as length-unknown, same as no
     * Content-Length at all). content_length is only meaningful when
     * this is true; magnus.c uses it to know exactly how many body bytes
     * to relay before the response is complete, independent of whether
     * the upstream ever closes its end. */
    bool has_content_length;
    unsigned long content_length;
} magnus_proxy_response_info_t;

/* Parses a raw upstream HTTP response header block (a status line followed
 * by header fields, ending with the blank line that terminates the header
 * section) and rewrites it into `out`:
 *   - the status line is normalized to HTTP/1.1
 *   - hop-by-hop headers are dropped
 *   - an `X-Magnus-Via` marker header is appended
 *   - the client-facing `Connection` header is set to "keep-alive" or
 *     "close" per `info->keep_client_alive` (see magnus_proxy_response_info_t)
 *
 * `raw` must be NUL-terminated and is mutated in place (tokenized).
 * `header_length` is the length of `raw` up to and including the trailing
 * blank line's CRLFCRLF. `client_wants_close` is the client's own original
 * request preference (already resolved by magnus_http_parse against its
 * HTTP version and any Connection header it sent). If
 * `affinity_cookie_value` is non-NULL, a `Set-Cookie: MAGNUS_AFFINITY=<value>`
 * line is appended so the client sticks to this cluster endpoint on future
 * requests; pass NULL when the client already carries a valid affinity
 * cookie. `info` is filled in on success (unspecified on failure).
 *
 * Returns the number of bytes written to `out` (excluding the NUL
 * terminator) on success, or -1 if the status line is malformed, a
 * Content-Length was malformed or duplicated, or `out` is too small to
 * hold the sanitized block. */
int magnus_proxy_sanitize_response_headers(char *raw, size_t header_length,
                                           char *out, size_t out_capacity,
                                           const char *affinity_cookie_value,
                                           bool client_wants_close,
                                           magnus_proxy_response_info_t *info);

#endif
