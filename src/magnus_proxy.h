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
    /* Reverse-proxy cache support (roadmap 2d-1) -- captured while the
     * same header pass already walks every upstream response header for
     * framing purposes, so magnus_cache_compute_freshness()'s caller
     * never needs a second pass over the raw response. Each string is ""
     * (never NULL) when that header was absent; `has_set_cookie` is a
     * plain bool since only presence, not the cookie's own value, matters
     * for cacheability (a shared cache must never serve one client's
     * session state to another -- see magnus_cache.h's own top
     * comment). */
    bool has_set_cookie;
    char cache_control[256];
    char expires[64];
    char etag[128];
    char last_modified[64];
    char vary[128];
    /* Proxy dispatch response compression (roadmap 2a-2) -- captured the
     * same "already walking every header anyway" way as the fields just
     * above. `content_type` feeds magnus_content_type_compressible()'s
     * own eligibility check; `has_content_encoding` excludes a response
     * the upstream *already* encoded (gzip or otherwise) from being
     * compressed a second time. */
    char content_type[128];
    bool has_content_encoding;
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
 * `out_cacheable_prefix_length` (roadmap 2d-1), if non-NULL, receives how
 * many bytes at the start of `out` are the status line plus every
 * pass-through header field this call forwarded -- i.e. everything
 * *before* the affinity Set-Cookie/Connection/X-Magnus-Via lines this
 * function itself appends, which a cache entry must never store verbatim
 * (Connection depends on each future client's own preference; Content-
 * Length gets recomputed from the cached body's own length; the affinity
 * Set-Cookie is specific to the client that produced this one response,
 * not safe to hand to every other client a shared cache entry serves).
 * magnus_cache_store()'s own `headers_block` is exactly `out[0..*out_cacheable_prefix_length)`.
 *
 * `compressed_content_length` (roadmap 2a-2) is `(size_t) -1` for every
 * caller that just wants the upstream's own response relayed as-is (the
 * only mode that existed before this parameter) -- any other value asks
 * this call to instead emit `Content-Length: <that value>\r\nContent-
 * Encoding: <compressed_content_encoding>\r\nVary: Accept-Encoding\r\n`
 * in place of the upstream's own (verbatim, unmodified) Content-Length
 * line, for a caller that has already compressed the body itself and
 * knows its real length. `compressed_content_encoding` (roadmap 2a-5;
 * e.g. `"gzip"` or `"zstd"`, `magnus_encoding_name()` in
 * src/magnus_compression.h) is unused/ignored when
 * `compressed_content_length` is `(size_t) -1`, and must be non-NULL
 * otherwise. Intended for exactly one calling pattern: sanitize once,
 * normally, to learn the *uncompressed* length/content-type/etc. and
 * decide whether to even attempt compression (and which encoding to
 * use); buffer and compress the body separately; then call this
 * function a *second* time, on a fresh copy of the same raw header
 * block, with the compressed length and encoding now known. Never
 * valid to pass together with a non-NULL `out_cacheable_prefix_length`
 * -- a compressed response is never stored in the cache this way (see
 * CHANGELOG.md's own 2a-2 entry for why); callers doing so pass NULL.
 *
 * `(size_t) -2` (roadmap 2a-10) is a second sentinel, for a caller
 * that knows it will compress the body but, unlike the pattern above,
 * can never know the real compressed length ahead of time because it
 * is streaming the response as upstream bytes arrive rather than
 * buffering the whole thing first (past MAGNUS_COMPRESSION_MAX_SIZE).
 * Emits `Content-Encoding`/`Vary` exactly like a known compressed
 * length would, but no `Content-Length` line at all, and forces the
 * client-facing `Connection` to "close" regardless of
 * `client_wants_close` -- at the time this sentinel was added there
 * was no `Transfer-Encoding: chunked` response writer in this codebase
 * yet, so an unknown-length body could only ever be framed by closing,
 * the same choice 2a-7's own static-file streaming compression already
 * made. Still used by HTTP/2 and HTTP/3 proxy dispatch (2a-11/2a-12),
 * since chunked encoding is an HTTP/1.1-only concept neither protocol
 * has any use for regardless (both already drop the `Connection`
 * header entirely on their own, real chunked writer or not). Intended
 * to be called once, immediately, the moment headers are known --
 * unlike the buffer-then-compress pattern above, nothing about a
 * streamed response is ever deferred to a second call.
 *
 * `(size_t) -3` (roadmap 2a-14) is a third sentinel, HTTP/1.1's own
 * real `Transfer-Encoding: chunked` writer (2a-13) applied to this
 * same streaming-proxy-dispatch case: identical to `(size_t) -2` in
 * every other respect (still no `Content-Length`, still emits
 * `Content-Encoding`/`Vary`, still called once immediately), except it
 * emits `Transfer-Encoding: chunked` instead and leaves the client-
 * facing `Connection` to the ordinary `client_wants_close` decision
 * every non-streaming response already gets, rather than forcing
 * "close" regardless.
 *
 * Returns the number of bytes written to `out` (excluding the NUL
 * terminator) on success, or -1 if the status line is malformed, a
 * Content-Length was malformed or duplicated, or `out` is too small to
 * hold the sanitized block. */
int magnus_proxy_sanitize_response_headers(char *raw, size_t header_length,
                                           char *out, size_t out_capacity,
                                           const char *affinity_cookie_value,
                                           bool client_wants_close,
                                           size_t compressed_content_length,
                                           const char *compressed_content_encoding,
                                           magnus_proxy_response_info_t *info,
                                           size_t *out_cacheable_prefix_length);

#endif
