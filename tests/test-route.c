#include "magnus_route.h"
#include "magnus_http.h"

#include <arpa/inet.h>
#include <assert.h>
#include <string.h>

static void
set_header(magnus_http_request_t *request, const char *name, const char *value)
{
    magnus_http_header_t *h = &request->headers[request->header_count++];
    strcpy(h->name, name);
    strcpy(h->value, value);
}

int
main(void)
{
    magnus_route_t route;
    char error[128];
    magnus_http_request_t request;
    struct in_addr ip;

    /* --- parsing --- */

    assert(magnus_route_parse("action=proxy", &route, error, sizeof(error)));
    assert(route.condition_count == 0);
    assert(route.action == MAGNUS_ROUTE_ACTION_PROXY);

    assert(magnus_route_parse(
        "host=api.example.com; path_prefix=/v1; method=POST; action=proxy",
        &route, error, sizeof(error)));
    assert(route.condition_count == 3);
    assert(route.conditions[0].kind == MAGNUS_ROUTE_MATCH_HOST);
    assert(strcmp(route.conditions[0].value, "api.example.com") == 0);
    assert(route.conditions[1].kind == MAGNUS_ROUTE_MATCH_PATH_PREFIX);
    assert(route.conditions[2].kind == MAGNUS_ROUTE_MATCH_METHOD);

    assert(magnus_route_parse("header:X-Debug=1; action=deny", &route, error,
                              sizeof(error)));
    assert(route.conditions[0].kind == MAGNUS_ROUTE_MATCH_HEADER);
    assert(strcmp(route.conditions[0].key, "X-Debug") == 0);
    assert(strcmp(route.conditions[0].value, "1") == 0);

    assert(magnus_route_parse("cookie:session=abc; action=static", &route,
                              error, sizeof(error)));
    assert(route.conditions[0].kind == MAGNUS_ROUTE_MATCH_COOKIE);
    assert(route.action == MAGNUS_ROUTE_ACTION_STATIC);

    assert(magnus_route_parse("query:debug=1; action=proxy", &route, error,
                              sizeof(error)));
    assert(route.conditions[0].kind == MAGNUS_ROUTE_MATCH_QUERY);

    assert(magnus_route_parse("source_cidr=10.0.0.0/8; action=deny", &route,
                              error, sizeof(error)));
    assert(route.conditions[0].kind == MAGNUS_ROUTE_MATCH_SOURCE_CIDR);
    assert(route.conditions[0].cidr_prefix_length == 8);

    /* missing action */
    assert(!magnus_route_parse("host=a.com", &route, error, sizeof(error)));
    /* unrecognized action */
    assert(!magnus_route_parse("action=bogus", &route, error, sizeof(error)));
    /* duplicate action */
    assert(!magnus_route_parse("action=proxy; action=deny", &route, error,
                               sizeof(error)));
    /* unrecognized condition key */
    assert(!magnus_route_parse("bogus=1; action=proxy", &route, error,
                               sizeof(error)));
    /* path_prefix must start with / */
    assert(!magnus_route_parse("path_prefix=v1; action=proxy", &route, error,
                               sizeof(error)));
    /* malformed CIDR */
    assert(!magnus_route_parse("source_cidr=10.0.0.0; action=proxy", &route,
                               error, sizeof(error)));
    assert(!magnus_route_parse("source_cidr=10.0.0.0/33; action=proxy", &route,
                               error, sizeof(error)));
    /* not key=value at all */
    assert(!magnus_route_parse("nonsense; action=proxy", &route, error,
                               sizeof(error)));
    /* too many conditions */
    assert(!magnus_route_parse(
        "host=a;host=a;host=a;host=a;host=a;host=a;host=a;host=a;host=a;"
        "action=proxy", &route, error, sizeof(error)));

    /* --- matching --- */

    memset(&request, 0, sizeof(request));
    strcpy(request.method, "POST");
    strcpy(request.target, "/v1/widgets?debug=1");
    strcpy(request.host, "api.example.com");
    set_header(&request, "Cookie", "session=abc; other=x");
    set_header(&request, "X-Debug", "1");
    ip.s_addr = 0;
    inet_pton(AF_INET, "10.1.2.3", &ip);

    assert(magnus_route_parse(
        "host=api.example.com; path_prefix=/v1; method=POST; action=proxy",
        &route, error, sizeof(error)));
    assert(magnus_route_matches(&route, &request, ip));

    assert(magnus_route_parse("host=other.example.com; action=proxy", &route,
                              error, sizeof(error)));
    assert(!magnus_route_matches(&route, &request, ip));

    assert(magnus_route_parse("path_prefix=/v2; action=proxy", &route, error,
                              sizeof(error)));
    assert(!magnus_route_matches(&route, &request, ip));

    assert(magnus_route_parse("method=GET; action=proxy", &route, error,
                              sizeof(error)));
    assert(!magnus_route_matches(&route, &request, ip));

    assert(magnus_route_parse("header:X-Debug=1; action=deny", &route, error,
                              sizeof(error)));
    assert(magnus_route_matches(&route, &request, ip));
    assert(magnus_route_parse("header:X-Debug=0; action=deny", &route, error,
                              sizeof(error)));
    assert(!magnus_route_matches(&route, &request, ip));
    assert(magnus_route_parse("header:X-Missing=1; action=deny", &route,
                              error, sizeof(error)));
    assert(!magnus_route_matches(&route, &request, ip));

    assert(magnus_route_parse("cookie:session=abc; action=static", &route,
                              error, sizeof(error)));
    assert(magnus_route_matches(&route, &request, ip));
    assert(magnus_route_parse("cookie:session=wrong; action=static", &route,
                              error, sizeof(error)));
    assert(!magnus_route_matches(&route, &request, ip));
    assert(magnus_route_parse("cookie:missing=x; action=static", &route,
                              error, sizeof(error)));
    assert(!magnus_route_matches(&route, &request, ip));

    assert(magnus_route_parse("query:debug=1; action=proxy", &route, error,
                              sizeof(error)));
    assert(magnus_route_matches(&route, &request, ip));
    assert(magnus_route_parse("query:debug=0; action=proxy", &route, error,
                              sizeof(error)));
    assert(!magnus_route_matches(&route, &request, ip));

    assert(magnus_route_parse("source_cidr=10.0.0.0/8; action=deny", &route,
                              error, sizeof(error)));
    assert(magnus_route_matches(&route, &request, ip));
    assert(magnus_route_parse("source_cidr=192.168.0.0/16; action=deny",
                              &route, error, sizeof(error)));
    assert(!magnus_route_matches(&route, &request, ip));

    /* /prefix must not match a request path that merely contains it later
     * -- it is a *prefix* match, anchored at the start. */
    assert(magnus_route_parse("path_prefix=/v1/widgets; action=proxy", &route,
                              error, sizeof(error)));
    assert(magnus_route_matches(&route, &request, ip));
    strcpy(request.target, "/other/v1/widgets");
    assert(!magnus_route_matches(&route, &request, ip));

    /* Case-insensitivity: host/method/header match case-insensitively
     * (HTTP convention); query does not (query values are opaque data,
     * not a protocol token). */
    strcpy(request.target, "/v1/widgets?debug=1");
    strcpy(request.host, "API.EXAMPLE.COM");
    assert(magnus_route_parse("host=api.example.com; action=proxy", &route,
                              error, sizeof(error)));
    assert(magnus_route_matches(&route, &request, ip));
    strcpy(request.method, "post");
    assert(magnus_route_parse("method=POST; action=proxy", &route, error,
                              sizeof(error)));
    assert(magnus_route_matches(&route, &request, ip));

    /* A route with zero conditions is a catch-all. */
    assert(magnus_route_parse("action=deny", &route, error, sizeof(error)));
    assert(magnus_route_matches(&route, &request, ip));

    /* cache=on (roadmap 2d-1): defaults off, opts in only alongside
     * action=proxy, order-independent with action=, rejected everywhere
     * else. */
    assert(magnus_route_parse("path_prefix=/; action=proxy", &route, error,
                              sizeof(error)));
    assert(!route.cache_enabled);
    assert(magnus_route_parse("path_prefix=/; action=proxy; cache=on",
                              &route, error, sizeof(error)));
    assert(route.cache_enabled);
    /* order-independent: cache= before action= too. */
    assert(magnus_route_parse("cache=on; path_prefix=/; action=proxy",
                              &route, error, sizeof(error)));
    assert(route.cache_enabled);
    assert(magnus_route_parse("path_prefix=/; action=proxy; cache=off",
                              &route, error, sizeof(error)));
    assert(!route.cache_enabled);
    assert(!magnus_route_parse("path_prefix=/; action=proxy; cache=maybe",
                               &route, error, sizeof(error)));
    assert(!magnus_route_parse(
        "path_prefix=/; action=proxy; cache=on; cache=on", &route, error,
        sizeof(error)));
    assert(!magnus_route_parse("path_prefix=/; action=static; cache=on",
                               &route, error, sizeof(error)));
    assert(!magnus_route_parse("path_prefix=/; action=deny; cache=on",
                               &route, error, sizeof(error)));
    assert(!magnus_route_parse("path_prefix=/; action=grpc; cache=on",
                               &route, error, sizeof(error)));

    return 0;
}
