#include "magnus_proxy.h"
#include "magnus_http.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *const magnus_proxy_hop_by_hop_headers[] = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade", NULL
};

bool
magnus_proxy_is_hop_by_hop(const char *name)
{
    size_t index;
    for (index = 0; magnus_proxy_hop_by_hop_headers[index] != NULL; index++) {
        if (strcasecmp(name, magnus_proxy_hop_by_hop_headers[index]) == 0) {
            return true;
        }
    }
    return false;
}

static bool
magnus_proxy_parse_status_line(char *line, unsigned *status, char *reason,
                               size_t reason_capacity)
{
    char *space = strchr(line, ' ');
    char *end;
    unsigned long code;

    if (space == NULL) return false;
    space++;
    code = strtoul(space, &end, 10);
    if (end == space || code < 100 || code > 599) return false;
    while (*end == ' ') end++;
    if (reason_capacity > 0) {
        strncpy(reason, end, reason_capacity - 1);
        reason[reason_capacity - 1] = '\0';
    }
    *status = (unsigned) code;
    return true;
}

int
magnus_proxy_sanitize_response_headers(char *raw, size_t header_length,
                                       char *out, size_t out_capacity,
                                       const char *affinity_cookie_value,
                                       bool client_wants_close,
                                       size_t compressed_content_length,
                                       const char *compressed_content_encoding,
                                       magnus_proxy_response_info_t *info,
                                       size_t *out_cacheable_prefix_length)
{
    char *saveptr = NULL;
    char *line;
    char reason[64] = "Upstream Response";
    unsigned status;
    int written;
    size_t total;
    bool content_length_seen = false;
    bool content_length_valid = true;
    bool transfer_encoding_seen = false;
    bool upstream_wants_close = false;
    unsigned long content_length = 0;
    bool has_set_cookie = false;
    bool has_content_encoding = false;
    bool compressing = compressed_content_length != (size_t) -1;
    /* Roadmap 2a-10: the streaming-proxy-dispatch-compression, close-
     * delimited sentinel -- see this function's own doc comment. Still
     * `compressing` (so the upstream's own Content-Length line is
     * dropped, same as the whole-buffered compressed case), but the
     * real length can never be known ahead of time, so no Content-
     * Length is ever written, and (at the time this sentinel was
     * added) the client-facing Connection was forced to "close"
     * regardless of client_wants_close/has_content_length, since no
     * chunked response writer existed in this codebase yet. Superseded
     * by streaming_chunked below (roadmap 2a-14) for HTTP/1.1's own
     * proxy dispatch once that writer existed -- kept here, unused by
     * any current caller, only because h2/h3's own proxy-dispatch
     * streaming compression (2a-11/2a-12) still route through this
     * same close-delimited shape (chunked encoding is an HTTP/1.1-only
     * concept; h2/h3 never needed either sentinel's own Connection
     * handling in the first place, since both protocols already drop
     * the Connection header sanitize would otherwise append). */
    bool streaming_compressed = compressed_content_length == (size_t) -2;
    /* Roadmap 2a-14: the streaming-proxy-dispatch-compression, chunked-
     * encoded sentinel -- HTTP/1.1's own real Transfer-Encoding:
     * chunked writer (2a-13) applied to proxy dispatch. Also
     * `compressing` (drops the upstream's own Content-Length the same
     * way), but unlike streaming_compressed above, this emits
     * Transfer-Encoding: chunked instead of forcing Connection: close,
     * and keep_client_alive below is left to the ordinary
     * has_content_length-independent client_wants_close check just
     * like every non-streaming response already gets -- the whole
     * point of having a chunked writer at all. */
    bool streaming_chunked = compressed_content_length == (size_t) -3;
    char cache_control[sizeof(info->cache_control)] = "";
    char expires[sizeof(info->expires)] = "";
    char etag[sizeof(info->etag)] = "";
    char last_modified[sizeof(info->last_modified)] = "";
    char vary[sizeof(info->vary)] = "";
    char content_type[sizeof(info->content_type)] = "";

    (void) header_length;
    line = strtok_r(raw, "\r\n", &saveptr);
    if (line == NULL || !magnus_proxy_parse_status_line(line, &status, reason,
                                                         sizeof(reason))) {
        return -1;
    }

    written = snprintf(out, out_capacity, "HTTP/1.1 %u %s\r\n", status, reason);
    if (written < 0 || (size_t) written >= out_capacity) return -1;
    total = (size_t) written;

    for (line = strtok_r(NULL, "\r\n", &saveptr); line != NULL;
         line = strtok_r(NULL, "\r\n", &saveptr)) {
        char *colon = strchr(line, ':');
        char name[64];
        size_t name_length;
        char *value;

        if (colon == NULL) continue;
        name_length = (size_t) (colon - line);
        if (name_length == 0 || name_length >= sizeof(name)) continue;
        memcpy(name, line, name_length);
        name[name_length] = '\0';

        value = colon + 1;
        while (*value == ' ' || *value == '\t') value++;

        /* Inspect Connection/Content-Length/Transfer-Encoding for framing
         * purposes even though (being hop-by-hop) none of them get
         * forwarded verbatim below -- what the client and the connection
         * pool actually see is decided from these facts, not by passing
         * the upstream's own header through. */
        if (strcasecmp(name, "connection") == 0) {
            if (strcasestr(value, "close") != NULL) upstream_wants_close = true;
        } else if (strcasecmp(name, "transfer-encoding") == 0) {
            transfer_encoding_seen = true;
        } else if (strcasecmp(name, "content-length") == 0) {
            char *end;
            unsigned long parsed;
            if (content_length_seen) {
                content_length_valid = false;
            } else {
                content_length_seen = true;
                for (const char *scan = value; *scan != '\0'; scan++)
                    if (!isdigit((unsigned char) *scan))
                        content_length_valid = false;
                if (content_length_valid) {
                    errno = 0;
                    parsed = strtoul(value, &end, 10);
                    if (errno != 0 || end == value || *end != '\0')
                        content_length_valid = false;
                    else
                        content_length = parsed;
                }
            }
        } else if (strcasecmp(name, "set-cookie") == 0) {
            /* Presence alone matters for cacheability (see
             * magnus_proxy_response_info_t's own comment) -- the value
             * itself is still relayed to *this* client normally below,
             * just never stored in a shared cache entry other clients
             * would also receive it from. */
            has_set_cookie = true;
        } else if (strcasecmp(name, "cache-control") == 0) {
            strncpy(cache_control, value, sizeof(cache_control) - 1);
        } else if (strcasecmp(name, "expires") == 0) {
            strncpy(expires, value, sizeof(expires) - 1);
        } else if (strcasecmp(name, "etag") == 0) {
            strncpy(etag, value, sizeof(etag) - 1);
        } else if (strcasecmp(name, "last-modified") == 0) {
            strncpy(last_modified, value, sizeof(last_modified) - 1);
        } else if (strcasecmp(name, "vary") == 0) {
            strncpy(vary, value, sizeof(vary) - 1);
        } else if (strcasecmp(name, "content-type") == 0) {
            strncpy(content_type, value, sizeof(content_type) - 1);
        } else if (strcasecmp(name, "content-encoding") == 0) {
            /* Presence alone matters (roadmap 2a-2) -- a response the
             * upstream already encoded itself is never eligible for a
             * second, magnus-applied encoding on top; the value itself
             * still passes through to the client below like any other
             * ordinary header, same reasoning as set-cookie above. */
            has_content_encoding = true;
        }

        if (magnus_proxy_is_hop_by_hop(name)) continue;
        /* Roadmap 2a-2: the upstream's own Content-Length line is
         * dropped here, not forwarded, when this call is building the
         * *compressed* response's own header block (compressing ==
         * true) -- the real, compressed length is written once, after
         * this loop, alongside Content-Encoding/Vary below, instead.
         * Forwarding both would be a duplicate Content-Length header,
         * which magnus_http_parse() (and every other well-behaved HTTP
         * parser) must reject. */
        if (compressing && strcasecmp(name, "content-length") == 0) continue;

        written = snprintf(out + total, out_capacity - total, "%s\r\n", line);
        if (written < 0 || (size_t) written >= out_capacity - total) return -1;
        total += (size_t) written;
    }

    if (content_length_seen && !content_length_valid) return -1;

    /* Everything above this point -- status line plus every pass-through
     * header field -- is what a cache entry may store; everything below
     * (the affinity Set-Cookie, then Connection/X-Magnus-Via) is specific
     * to *this* relay and must never be replayed to a different client
     * from a stored entry -- see this function's own doc comment on
     * out_cacheable_prefix_length. */
    if (out_cacheable_prefix_length != NULL) *out_cacheable_prefix_length = total;

    /* Roadmap 2a-2: the real, compressed Content-Length -- the upstream's
     * own line was dropped, not forwarded, above. A second, separate
     * `Vary: Accept-Encoding` line is emitted unconditionally rather than
     * merged into an upstream-supplied Vary value that may have already
     * passed through above -- two Vary header fields are semantically
     * equivalent to one comma-joined line (RFC 9110 5.3), just not as
     * tidy; narrowed for a later increment, not a correctness gap. */
    if (compressing && streaming_chunked) {
        written = snprintf(out + total, out_capacity - total,
                           "Content-Encoding: %s\r\nVary: Accept-Encoding\r\n"
                           "Transfer-Encoding: chunked\r\n",
                           compressed_content_encoding);
        if (written < 0 || (size_t) written >= out_capacity - total) return -1;
        total += (size_t) written;
    } else if (compressing && streaming_compressed) {
        written = snprintf(out + total, out_capacity - total,
                           "Content-Encoding: %s\r\nVary: Accept-Encoding\r\n",
                           compressed_content_encoding);
        if (written < 0 || (size_t) written >= out_capacity - total) return -1;
        total += (size_t) written;
    } else if (compressing) {
        written = snprintf(out + total, out_capacity - total,
                           "Content-Length: %zu\r\nContent-Encoding: %s\r\n"
                           "Vary: Accept-Encoding\r\n", compressed_content_length,
                           compressed_content_encoding);
        if (written < 0 || (size_t) written >= out_capacity - total) return -1;
        total += (size_t) written;
    }

    if (affinity_cookie_value != NULL) {
        written = snprintf(out + total, out_capacity - total,
                           "Set-Cookie: " MAGNUS_AFFINITY_COOKIE_NAME
                           "=%s; Path=/; HttpOnly; SameSite=Lax\r\n",
                           affinity_cookie_value);
        if (written < 0 || (size_t) written >= out_capacity - total) return -1;
        total += (size_t) written;
    }

    info->status = status;
    info->has_content_length = content_length_seen && !transfer_encoding_seen;
    info->content_length = info->has_content_length ? content_length : 0;
    info->upstream_poolable = info->has_content_length && !upstream_wants_close;
    /* Roadmap 2a-14: streaming_chunked never needs has_content_length
     * (chunked framing has no use for the upstream's own declared
     * length at all) and is never forced false the way streaming_
     * compressed's own close-delimited framing still is -- respecting
     * client_wants_close alone is the whole point of having a chunked
     * writer to fall back on instead of always closing. */
    info->keep_client_alive = streaming_chunked
        ? !client_wants_close
        : !client_wants_close && info->has_content_length
              && !streaming_compressed;
    info->has_set_cookie = has_set_cookie;
    strcpy(info->cache_control, cache_control);
    strcpy(info->expires, expires);
    strcpy(info->etag, etag);
    strcpy(info->last_modified, last_modified);
    strcpy(info->vary, vary);
    strcpy(info->content_type, content_type);
    info->has_content_encoding = has_content_encoding;

    written = snprintf(out + total, out_capacity - total,
                       "Connection: %s\r\nX-Magnus-Via: magnus-proxy/0.1\r\n\r\n",
                       info->keep_client_alive ? "keep-alive" : "close");
    if (written < 0 || (size_t) written >= out_capacity - total) return -1;
    total += (size_t) written;

    return (int) total;
}
