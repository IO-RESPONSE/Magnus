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
        sizeof(out), NULL, false, &info);
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
        sizeof(out), NULL, false, &info) == -1);

    strcpy(raw, "HTTP/1.1 abc OK\r\n\r\n");
    assert(magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, &info) == -1);

    strcpy(raw, "HTTP/1.1 200 OK\r\nX-Long: value\r\n\r\n");
    assert(magnus_proxy_sanitize_response_headers(raw, strlen(raw), out, 8,
        NULL, false, &info) == -1);

    strcpy(raw, "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
    written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), "sess-token-abc", false, &info);
    assert(written > 0);
    assert(strstr(out, "Set-Cookie: MAGNUS_AFFINITY=sess-token-abc; "
                       "Path=/; HttpOnly; SameSite=Lax\r\n") != NULL);

    /* A clean, single, well-formed Content-Length with no upstream
     * Connection: close and a client that wants keep-alive: both legs get
     * to stay open. */
    strcpy(raw, "HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n");
    written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, &info);
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
        sizeof(out), NULL, true, &info);
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
        sizeof(out), NULL, false, &info);
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
        sizeof(out), NULL, false, &info) == -1);

    /* A malformed Content-Length is likewise rejected, not silently
     * ignored or misparsed. */
    strcpy(raw, "HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n");
    assert(magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
        sizeof(out), NULL, false, &info) == -1);

    return 0;
}
