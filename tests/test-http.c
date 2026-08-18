#include "magnus_http.h"

#include <assert.h>
#include <string.h>

static magnus_http_result_t
parse(const char *text, magnus_http_request_t *request)
{
    return magnus_http_parse(text, strlen(text), request);
}

int
main(void)
{
    magnus_http_request_t request;
    assert(parse("GET /x HTTP/1.1\r\nHost: example\r\n\r\n", &request)
           == MAGNUS_HTTP_OK);
    assert(strcmp(request.method, "GET") == 0);
    assert(strcmp(request.target, "/x") == 0);
    assert(!request.close_connection);
    assert(parse("GET / HTTP/1.1\r\n\r\n", &request)
           == MAGNUS_HTTP_BAD_REQUEST);
    assert(parse("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", &request)
           == MAGNUS_HTTP_BAD_REQUEST);
    assert(parse("GET / HTTP/2.0\r\nHost: a\r\n\r\n", &request)
           == MAGNUS_HTTP_VERSION_UNSUPPORTED);
    assert(parse("GET relative HTTP/1.1\r\nHost: a\r\n\r\n", &request)
           == MAGNUS_HTTP_BAD_REQUEST);
    assert(parse("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", &request)
           == MAGNUS_HTTP_OK);
    assert(!request.close_connection);

    assert(parse("GET /x HTTP/1.1\r\nHost: a\r\n"
                 "Cookie: foo=1; MAGNUS_AFFINITY=abc123; bar=2\r\n\r\n",
                 &request) == MAGNUS_HTTP_OK);
    assert(strcmp(request.affinity_key, "abc123") == 0);
    assert(parse("GET /x HTTP/1.1\r\nHost: a\r\nCookie: MAGNUS_AFFINITY=xyz\r\n\r\n",
                 &request) == MAGNUS_HTTP_OK);
    assert(strcmp(request.affinity_key, "xyz") == 0);
    assert(parse("GET /x HTTP/1.1\r\nHost: a\r\nCookie: other=1\r\n\r\n", &request)
           == MAGNUS_HTTP_OK);
    assert(request.affinity_key[0] == '\0');
    assert(parse("GET /x HTTP/1.1\r\nHost: a\r\n\r\n", &request) == MAGNUS_HTTP_OK);
    assert(request.affinity_key[0] == '\0');
    return 0;
}
