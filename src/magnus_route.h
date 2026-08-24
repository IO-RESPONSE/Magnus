#ifndef MAGNUS_ROUTE_H
#define MAGNUS_ROUTE_H

#include "magnus_http.h"

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>

/* How many conditions a single route may combine (all ANDed together).
 * Generous for the compact single-line DSL magnus_route_parse() reads;
 * nothing about the matcher itself needs a higher bound. */
#define MAGNUS_ROUTE_MAX_CONDITIONS 8

typedef enum {
    MAGNUS_ROUTE_MATCH_HOST,
    MAGNUS_ROUTE_MATCH_PATH_PREFIX,
    MAGNUS_ROUTE_MATCH_METHOD,
    MAGNUS_ROUTE_MATCH_HEADER,
    MAGNUS_ROUTE_MATCH_COOKIE,
    MAGNUS_ROUTE_MATCH_QUERY,
    MAGNUS_ROUTE_MATCH_SOURCE_CIDR,
    /* Like HEADER, but a case-insensitive *prefix* match on the header's
     * value rather than an exact one (roadmap 2c-4) -- added specifically
     * because HEADER's exact match cannot usefully express "route gRPC
     * traffic": a real gRPC request's content-type is "application/grpc"
     * with an optional codec suffix the client itself chooses
     * ("+proto"/"+json"/...), so a fixed exact value can never cover
     * every real request. `header_prefix:content-type=application/grpc`
     * matches all of them; not gRPC-specific in the matcher itself
     * (general prefix matching on any header), the way this codebase's
     * other conditions are never narrower than the mechanism actually
     * needs to be. */
    MAGNUS_ROUTE_MATCH_HEADER_PREFIX
} magnus_route_match_kind_t;

typedef struct {
    magnus_route_match_kind_t kind;
    /* Field name for HEADER/HEADER_PREFIX/COOKIE/QUERY (the header name,
     * cookie name, or query parameter name being matched); unused
     * otherwise. */
    char key[64];
    /* Expected value for HOST/PATH_PREFIX/METHOD/HEADER/HEADER_PREFIX/
     * COOKIE/QUERY; unused for SOURCE_CIDR. */
    char value[192];
    /* Parsed network address and prefix length for SOURCE_CIDR; unused
     * otherwise. Both already validated by magnus_route_parse(). */
    struct in_addr cidr_network;
    unsigned cidr_prefix_length;
} magnus_route_condition_t;

typedef enum {
    MAGNUS_ROUTE_ACTION_PROXY,
    MAGNUS_ROUTE_ACTION_DENY,
    MAGNUS_ROUTE_ACTION_STATIC,
    /* gRPC (roadmap 2c-1): relays to an HTTP/2-native upstream (a real
     * gRPC server, which HTTP/1.1 cannot speak to at all -- no trailers)
     * rather than the ordinary action=proxy path's HTTP/1.x upstream.
     * Only ever dispatched for an h2 client stream; an HTTP/1.1 request
     * matching this action is answered with an explicit error instead of
     * silently falling through to proxy/static (see
     * magnus_dispatch_request()). */
    MAGNUS_ROUTE_ACTION_GRPC,
    /* FastCGI dispatch (roadmap 5a-1/5a-2): relays to a FastCGI
     * application server (PHP-FPM et al.) over its own binary record
     * protocol -- a categorically different upstream protocol from the
     * ordinary action=proxy path's raw HTTP/1.x relay, the same
     * reasoning action=grpc already established its own dedicated
     * cluster/dispatch machinery for. HTTP/1.1 only; any method, with
     * or without a request body (5a-2 lifted 5a-1's original GET-only,
     * no-body restriction -- see magnus_fastcgi_build_request()'s own
     * doc comment in magnus.c). */
    MAGNUS_ROUTE_ACTION_FASTCGI,
    /* SCGI dispatch (roadmap 5b-1): relays to an SCGI application
     * server over its own netstring-framed header block + raw-body
     * protocol -- a categorically different upstream protocol from
     * both action=proxy's raw HTTP/1.x relay and action=fastcgi's own
     * binary record framing, the same reasoning each of those already
     * established its own dedicated cluster/dispatch machinery for.
     * HTTP/1.1 only; any method, with or without a request body (SCGI
     * requires a CONTENT_LENGTH header on every request regardless, so
     * unlike action=fastcgi's own original 5a-1 GET-only first cut,
     * there is no natural narrower restriction to start from here --
     * see magnus_scgi_build_request()'s own doc comment in magnus.c). */
    MAGNUS_ROUTE_ACTION_SCGI
} magnus_route_action_t;

typedef struct {
    magnus_route_condition_t conditions[MAGNUS_ROUTE_MAX_CONDITIONS];
    size_t condition_count;
    magnus_route_action_t action;
    /* Reverse-proxy response cache (roadmap 2d-1), opt-in per route via a
     * `cache=on` modifier -- parsed and validated (requires action=proxy)
     * by magnus_route_parse(), consumed by magnus_proxy_pick_and_start()/
     * magnus_h2_proxy_start() in magnus.c. Defaults to false (every route
     * that never mentions `cache=` at all): caching is never applied to a
     * proxy route automatically -- caching a route that assumes every
     * response is unique (session-bound APIs, mutating endpoints, etc.)
     * would be a correctness bug, not just a missed optimization, so it
     * requires a deliberate opt-in; see magnus_cache.h's own top comment
     * on why explicit opt-in matters here, not just convenience. */
    bool cache_enabled;
} magnus_route_t;

/* Parses one `route = ...` config value into `out`: semicolon-separated
 * conditions (each `key=value`, or `key:subkey=value` for header/
 * header_prefix/cookie/query, which need a field name as well as an
 * expected value) plus exactly one `action=proxy|deny|static|grpc|fastcgi|scgi`, plus
 * an optional `cache=on|off` modifier (roadmap 2d-1; only valid alongside
 * `action=proxy` -- see magnus_route_t's own `cache_enabled` field), in
 * any order, combinable up to MAGNUS_ROUTE_MAX_CONDITIONS. A route with
 * zero conditions is valid and matches every request -- a deliberate
 * catch-all, e.g. for a route whose only job is to be an explicit
 * default action.
 *
 * Recognized condition keys: host, path_prefix, method, header:<name>,
 * header_prefix:<name> (case-insensitive prefix match on the header's
 * value -- e.g. `header_prefix:content-type=application/grpc` matches
 * both "application/grpc" and "application/grpc+proto"), cookie:<name>,
 * query:<name>, source_cidr (value must be a.b.c.d/prefix-length).
 *
 * Returns true on success with `out` fully populated. Returns false on
 * any malformed token, an unrecognized key, a value that overflows the
 * fixed field it would be stored in, more than MAGNUS_ROUTE_MAX_CONDITIONS
 * conditions, a missing/duplicate/invalid action, a duplicate/invalid
 * `cache=`, or `cache=on` without `action=proxy` -- writing a
 * human-readable reason into `error` (if non-NULL and error_capacity > 0)
 * in every failure case. */
bool magnus_route_parse(const char *value, magnus_route_t *out, char *error,
                        size_t error_capacity);

/* Parses an IPv4 CIDR string (e.g. "192.168.1.0/24") into `network` and
 * `prefix_length`. Returns true on success, false on malformed input (non-IPv4,
 * prefix > 32, missing slash, etc.). Exposed so config loading and trusted-proxy
 * parsing can reuse the same validator. */
bool magnus_route_parse_cidr(const char *text, struct in_addr *network,
                             unsigned *prefix_length);

/* True if every one of `route`'s conditions matches `request` (vacuously
 * true if it has none). `client_ip` is the connection's peer address, used
 * for MAGNUS_ROUTE_MATCH_SOURCE_CIDR. HOST/METHOD/HEADER/HEADER_PREFIX/
 * COOKIE values are compared case-insensitively (HTTP header/method
 * conventions); PATH_PREFIX and QUERY are compared case-sensitively (paths
 * and query values are conventionally case-sensitive). */
bool magnus_route_matches(const magnus_route_t *route,
                          const magnus_http_request_t *request,
                          struct in_addr client_ip);

#endif
