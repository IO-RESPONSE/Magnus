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
    return 0;
}
