#ifndef MAGNUS_HTTP_H
#define MAGNUS_HTTP_H

#include <stdbool.h>
#include <stddef.h>

/* Name of the cookie magnus_http_parse() looks for to carry a client's
 * cluster session-affinity key, and that the gateway issues via Set-Cookie
 * the first time a client arrives without one. */
#define MAGNUS_AFFINITY_COOKIE_NAME "MAGNUS_AFFINITY"

/* Bounds how many header fields magnus_http_parse() remembers individually
 * (for magnus_http_header_find(), used by route matching -- see
 * magnus_route.h). A header beyond this count is still fully validated as
 * part of parsing but is not retained; MAGNUS_INPUT_LIMIT's 8KiB request
 * cap already bounds how many headers a request can realistically carry,
 * so this is a defensive limit, not an expected-to-bite one. */
#define MAGNUS_HTTP_MAX_HEADERS 32

typedef struct {
    char name[64];
    char value[192];
} magnus_http_header_t;

typedef struct {
    char method[8];
    char target[256];
    bool http_11;
    bool close_connection;
    bool head_only;
    char affinity_key[64];
    /* Content-Length, if the request carried exactly one well-formed one.
     * Transfer-Encoding is rejected outright (MAGNUS_HTTP_BAD_REQUEST) --
     * chunked request bodies are not yet supported, and accepting the
     * header without honoring it would be a framing hazard. */
    bool has_content_length;
    unsigned long content_length;
    /* Host header's value verbatim (already required/validated non-empty
     * for HTTP/1.1 -- see host_seen in magnus_http_parse()). */
    char host[256];
    /* Every header field, name and value verbatim, up to
     * MAGNUS_HTTP_MAX_HEADERS -- see magnus_http_header_find(). */
    magnus_http_header_t headers[MAGNUS_HTTP_MAX_HEADERS];
    size_t header_count;
} magnus_http_request_t;

/* Case-insensitive lookup of a header's value among the (up to
 * MAGNUS_HTTP_MAX_HEADERS) ones magnus_http_parse() retained. Returns NULL
 * if not present (including if the request had more headers than were
 * retained and this one happened to be past the cutoff). */
const char *magnus_http_header_find(const magnus_http_request_t *request,
                                    const char *name);

/* Finds `name=value` within a `Cookie:` header's value (";"-separated
 * pairs, optional leading space after each ";") and copies `value` into
 * `out`. Returns false if the cookie is absent or its value does not fit
 * in `out_capacity` (including the NUL terminator). Exposed (not just
 * magnus_http_parse()'s own internal use for the MAGNUS_AFFINITY cookie)
 * so an HTTP/2 request -- which never goes through magnus_http_parse()'s
 * wire-format parsing at all, since it arrives as nghttp2-decoded
 * pseudo-/regular headers instead -- can extract the same cookie the same
 * way, rather than a second, potentially-divergent implementation. */
bool magnus_http_extract_cookie(const char *value, size_t value_length,
                                const char *name, char *out,
                                size_t out_capacity);

typedef enum {
    MAGNUS_HTTP_OK = 0,
    MAGNUS_HTTP_BAD_REQUEST,
    MAGNUS_HTTP_URI_TOO_LONG,
    MAGNUS_HTTP_VERSION_UNSUPPORTED
} magnus_http_result_t;

magnus_http_result_t magnus_http_parse(const char *data, size_t length,
                                       magnus_http_request_t *request);

#endif
