#include "magnus_proxy.h"

#include <assert.h>
#include <string.h>

int
main(void)
{
    char raw[512];
    char out[512];
    unsigned status;
    int written;

    assert(magnus_proxy_is_hop_by_hop("Connection"));
    assert(magnus_proxy_is_hop_by_hop("keep-alive"));
    assert(magnus_proxy_is_hop_by_hop("Transfer-Encoding"));
    assert(magnus_proxy_is_hop_by_hop("Upgrade"));
    assert(!magnus_proxy_is_hop_by_hop("Content-Type"));
    assert(!magnus_proxy_is_hop_by_hop("Content-Length"));
    assert(!magnus_proxy_is_hop_by_hop("X-Debug"));

    strcpy(raw,
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 5\r\n"
        "Connection: keep-alive\r\n"
        "Transfer-Encoding: chunked\r\n"
        "X-Debug: value\r\n"
        "\r\n");
    written = magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
                                                      sizeof(out), &status);
    assert(written > 0);
    assert(status == 200);
    assert(strncmp(out, "HTTP/1.1 200 OK\r\n", 17) == 0);
    assert(strstr(out, "Content-Type: text/plain\r\n") != NULL);
    assert(strstr(out, "Content-Length: 5\r\n") != NULL);
    assert(strstr(out, "X-Debug: value\r\n") != NULL);
    assert(strstr(out, "Transfer-Encoding") == NULL);
    assert(strstr(out, "Keep-Alive") == NULL);
    /* exactly one Connection header: our own forced "close" */
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
                                                   sizeof(out), &status) == -1);

    strcpy(raw, "HTTP/1.1 abc OK\r\n\r\n");
    assert(magnus_proxy_sanitize_response_headers(raw, strlen(raw), out,
                                                   sizeof(out), &status) == -1);

    strcpy(raw, "HTTP/1.1 200 OK\r\nX-Long: value\r\n\r\n");
    assert(magnus_proxy_sanitize_response_headers(raw, strlen(raw), out, 8,
                                                   &status) == -1);

    return 0;
}
