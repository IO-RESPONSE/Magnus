#include "magnus_proxy.h"

#include <assert.h>
#include <string.h>

int
main(void)
{
    char raw[512];
    char out[512];
    magnus_proxy_response_info_t info;
    int written;

    assert(magnus_proxy_is_hop_by_hop("Connection"));
    assert(magnus_proxy_is_hop_by_hop("keep-alive"));
    assert(magnus_proxy_is_hop_by_hop("Transfer-Encoding"));
    assert(magnus_proxy_is_hop_by_hop("Upgrade"));
    assert(!magnus_proxy_is_hop_by_hop("Content-Type"));
    assert(!magnus_proxy_is_hop_by_hop("Content-Length"));
    assert(!magnus_proxy_is_hop_by_hop("X-Debug"));

    /* Transfer-Encoding present (even alongside a Content-Length) means
     * length-unknown -- not poolable, not keep-alive to the client -- and
     * the chunked-encoded framing is never decoded so it must not be
     * mistaken for something we understood. */
    strcpy(raw,
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 5\r\n"
        "Connection: keep-alive\r\n"
        "Transfer-Encoding: chunked\r\n"
        "X-Debug: value\r\n"
        "\r\n");
    written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, (size_t) -1, NULL, &info, NULL);
    assert(written > 0);
    assert(info.status == 200);
    assert(!info.has_content_length);
    assert(!info.upstream_poolable);
    assert(!info.keep_client_alive);
    assert(strncmp(out, "HTTP/1.1 200 OK\r\n", 17) == 0);
    assert(strstr(out, "Content-Type: text/plain\r\n") != NULL);
    assert(strstr(out, "Content-Length: 5\r\n") != NULL);
    assert(strstr(out, "X-Debug: value\r\n") != NULL);
    assert(strstr(out, "Transfer-Encoding") == NULL);
    assert(strstr(out, "Keep-Alive") == NULL);
    {
        const char *first = strstr(out, "Connection:");
        assert(first != NULL);
        assert(strstr(first + 1, "Connection:") == NULL);
        assert(strncmp(first, "Connection: close\r\n", 19) == 0);
    }
    assert(strstr(out, "X-Magnus-Via: magnus-proxy/0.1\r\n") != NULL);
    assert(strcmp(out + written - 2, "\r\n") == 0);

    strcpy(raw, "not-a-status-line\r\n\r\n");
    assert(magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, (size_t) -1, NULL, &info, NULL) == -1);

    strcpy(raw, "HTTP/1.1 abc OK\r\n\r\n");
    assert(magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, (size_t) -1, NULL, &info, NULL) == -1);

    strcpy(raw, "HTTP/1.1 200 OK\r\nX-Long: value\r\n\r\n");
    assert(magnus_proxy_sanitize_response_headers(raw, strlen(raw), out, 8,
        NULL, false, (size_t) -1, NULL, &info, NULL) == -1);

    strcpy(raw, "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
    written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), "sess-token-abc", false, (size_t) -1, NULL, &info, NULL);
    assert(written > 0);
    assert(strstr(out, "Set-Cookie: MAGNUS_AFFINITY=sess-token-abc; "
                       "Path=/; HttpOnly; SameSite=Lax\r\n") != NULL);

    /* A clean, single, well-formed Content-Length with no upstream
     * Connection: close and a client that wants keep-alive: both legs get
     * to stay open. */
    strcpy(raw, "HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n");
    written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, (size_t) -1, NULL, &info, NULL);
    assert(written > 0);
    assert(info.has_content_length);
    assert(info.content_length == 42);
    assert(info.upstream_poolable);
    assert(info.keep_client_alive);
    assert(strstr(out, "Connection: keep-alive\r\n") != NULL);

    /* Same response, but the client's own request wanted the connection
     * closed: the upstream leg is still poolable on its own merits, but
     * the client leg must not claim keep-alive. */
    strcpy(raw, "HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n");
    written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, true, (size_t) -1, NULL, &info, NULL);
    assert(written > 0);
    assert(info.has_content_length);
    assert(info.upstream_poolable);
    assert(!info.keep_client_alive);
    assert(strstr(out, "Connection: close\r\n") != NULL);

    /* Upstream explicitly asked to close despite a valid Content-Length:
     * not poolable, even though the client leg can still be kept alive
     * (magnus is not obligated to mirror the upstream's own preference to
     * the client -- it fully controls and correctly frames what it sends
     * the client regardless of what happens to the now-doomed upstream
     * connection). */
    strcpy(raw,
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\n");
    written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, (size_t) -1, NULL, &info, NULL);
    assert(written > 0);
    assert(info.has_content_length);
    assert(!info.upstream_poolable);
    assert(info.keep_client_alive);

    /* A duplicate Content-Length is a request-smuggling-relevant ambiguity
     * and must be rejected outright, exactly like the client-request-side
     * parser already does. */
    strcpy(raw,
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n");
    assert(magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, (size_t) -1, NULL, &info, NULL) == -1);

    /* A malformed Content-Length is likewise rejected, not silently
     * ignored or misparsed. */
    strcpy(raw, "HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n");
    assert(magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, (size_t) -1, NULL, &info, NULL) == -1);

    /* Reverse-proxy cache support (roadmap 2d-1): Cache-Control/Expires/
     * ETag/Last-Modified/Vary are captured (still forwarded to the client
     * normally, same as any other non-hop-by-hop header) and Set-Cookie's
     * mere presence is flagged. out_cacheable_prefix_length marks the end
     * of the pass-through headers, strictly before the affinity
     * Set-Cookie/Connection/X-Magnus-Via lines this function itself
     * appends -- none of the cache-relevant captures above appear after
     * it, so a cache entry storing only that prefix still has everything
     * it needs. */
    {
        size_t prefix_length = 0;
        strcpy(raw,
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 5\r\n"
            "Cache-Control: max-age=60\r\n"
            "Expires: Sun, 06 Nov 1994 08:49:37 GMT\r\n"
            "ETag: \"abc123\"\r\n"
            "Last-Modified: Mon, 01 Jan 2024 00:00:00 GMT\r\n"
            "Vary: Accept-Encoding\r\n"
            "Set-Cookie: session=xyz\r\n"
            "\r\n");
        written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
            sizeof(out), "sess-token-abc", false, (size_t) -1, NULL, &info, &prefix_length);
        assert(written > 0);
        assert(info.has_set_cookie);
        assert(strcmp(info.cache_control, "max-age=60") == 0);
        assert(strcmp(info.expires, "Sun, 06 Nov 1994 08:49:37 GMT") == 0);
        assert(strcmp(info.etag, "\"abc123\"") == 0);
        assert(strcmp(info.last_modified,
                      "Mon, 01 Jan 2024 00:00:00 GMT") == 0);
        assert(strcmp(info.vary, "Accept-Encoding") == 0);
        assert(prefix_length > 0 && prefix_length < (size_t) written);
        assert(strstr(out, "Set-Cookie: session=xyz\r\n") != NULL);
        /* The prefix itself carries every pass-through header this
         * response had, verbatim, and nothing added afterward. */
        assert(memmem(out, prefix_length, "Cache-Control: max-age=60",
                     strlen("Cache-Control: max-age=60")) != NULL);
        assert(memmem(out, prefix_length, "Set-Cookie: session=xyz",
                     strlen("Set-Cookie: session=xyz")) != NULL);
        assert(memmem(out, prefix_length, "MAGNUS_AFFINITY",
                     strlen("MAGNUS_AFFINITY")) == NULL);
        assert(memmem(out, prefix_length, "X-Magnus-Via",
                     strlen("X-Magnus-Via")) == NULL);
    }

    /* Headers this response never carried leave the corresponding info
     * field empty, not garbage/uninitialized. */
    strcpy(raw, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, (size_t) -1, NULL, &info, NULL);
    assert(written > 0);
    assert(!info.has_set_cookie);
    assert(strcmp(info.cache_control, "") == 0);
    assert(strcmp(info.expires, "") == 0);
    assert(strcmp(info.etag, "") == 0);
    assert(strcmp(info.last_modified, "") == 0);
    assert(strcmp(info.vary, "") == 0);

    /* Roadmap 2a-2: content-type/content-encoding are captured the same
     * "still forwarded normally" way every other cache-relevant header
     * already is above. */
    strcpy(raw,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
        "Content-Length: 100\r\n\r\n");
    written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, (size_t) -1, NULL, &info, NULL);
    assert(written > 0);
    assert(strcmp(info.content_type, "text/plain") == 0);
    assert(!info.has_content_encoding);

    strcpy(raw, "HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n"
                "Content-Length: 100\r\n\r\n");
    written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, (size_t) -1, NULL, &info, NULL);
    assert(written > 0);
    assert(info.has_content_encoding);

    /* Roadmap 2a-2: compressed_content_length != (size_t) -1 replaces
     * the upstream's own Content-Length line (never forwarded verbatim
     * alongside it -- exactly one Content-Length line must ever appear)
     * with the compressed one, and adds Content-Encoding: gzip plus a
     * second Vary: Accept-Encoding line -- the same response the
     * ordinary (size_t) -1 call above already proved forwards a plain
     * Content-Length: 100 unmodified when compression is not in play. */
    strcpy(raw,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
        "Content-Length: 100\r\n\r\n");
    written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, 42, "gzip", &info, NULL);
    assert(written > 0);
    assert(strstr(out, "Content-Length: 42\r\n") != NULL);
    assert(strstr(out, "Content-Length: 100\r\n") == NULL);
    assert(strstr(out, "Content-Encoding: gzip\r\n") != NULL);
    assert(strstr(out, "Vary: Accept-Encoding\r\n") != NULL);
    {
        /* Exactly one Content-Length line, not two. */
        const char *first = strstr(out, "Content-Length:");
        assert(first != NULL);
        assert(strstr(first + 1, "Content-Length:") == NULL);
    }

    /* An upstream Vary the client already needs (e.g. Accept-Language)
     * passes through untouched, in addition to (not merged with -- see
     * this function's own doc comment) the Accept-Encoding one this
     * call adds. */
    strcpy(raw,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
        "Vary: Accept-Language\r\nContent-Length: 100\r\n\r\n");
    written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, 42, "gzip", &info, NULL);
    assert(written > 0);
    assert(strstr(out, "Vary: Accept-Language\r\n") != NULL);
    assert(strstr(out, "Vary: Accept-Encoding\r\n") != NULL);

    /* Roadmap 2a-5: the same compressed_content_length path, but with
     * "zstd" as compressed_content_encoding -- proves the %s substitution
     * is not hardcoded to "gzip" any more. */
    strcpy(raw,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
        "Content-Length: 100\r\n\r\n");
    written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, 42, "zstd", &info, NULL);
    assert(written > 0);
    assert(strstr(out, "Content-Length: 42\r\n") != NULL);
    assert(strstr(out, "Content-Encoding: zstd\r\n") != NULL);
    assert(strstr(out, "Vary: Accept-Encoding\r\n") != NULL);

    /* Roadmap 2a-6: same again with "br" (Brotli's own Content-Encoding
     * token, not "brotli"). */
    strcpy(raw,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
        "Content-Length: 100\r\n\r\n");
    written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, 42, "br", &info, NULL);
    assert(written > 0);
    assert(strstr(out, "Content-Length: 42\r\n") != NULL);
    assert(strstr(out, "Content-Encoding: br\r\n") != NULL);
    assert(strstr(out, "Vary: Accept-Encoding\r\n") != NULL);

    return 0;
}
