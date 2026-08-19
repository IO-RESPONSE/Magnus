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
    MAGNUS_ROUTE_MATCH_SOURCE_CIDR
} magnus_route_match_kind_t;

typedef struct {
    magnus_route_match_kind_t kind;
    /* Field name for HEADER/COOKIE/QUERY (the header name, cookie name,
     * or query parameter name being matched); unused otherwise. */
    char key[64];
    /* Expected value for HOST/PATH_PREFIX/METHOD/HEADER/COOKIE/QUERY;
     * unused for SOURCE_CIDR. */
    char value[192];
    /* Parsed network address and prefix length for SOURCE_CIDR; unused
     * otherwise. Both already validated by magnus_route_parse(). */
    struct in_addr cidr_network;
    unsigned cidr_prefix_length;
} magnus_route_condition_t;

typedef enum {
    MAGNUS_ROUTE_ACTION_PROXY,
    MAGNUS_ROUTE_ACTION_DENY,
    MAGNUS_ROUTE_ACTION_STATIC
} magnus_route_action_t;

typedef struct {
    magnus_route_condition_t conditions[MAGNUS_ROUTE_MAX_CONDITIONS];
    size_t condition_count;
    magnus_route_action_t action;
} magnus_route_t;

/* Parses one `route = ...` config value into `out`: semicolon-separated
 * conditions (each `key=value`, or `key:subkey=value` for header/cookie/
 * query, which need a field name as well as an expected value) plus
 * exactly one `action=proxy|deny|static`, in any order, combinable up to
 * MAGNUS_ROUTE_MAX_CONDITIONS. A route with zero conditions is valid and
 * matches every request -- a deliberate catch-all, e.g. for a route whose
 * only job is to be an explicit default action.
 *
 * Recognized condition keys: host, path_prefix, method, header:<name>,
 * cookie:<name>, query:<name>, source_cidr (value must be
 * a.b.c.d/prefix-length).
 *
 * Returns true on success with `out` fully populated. Returns false on
 * any malformed token, an unrecognized key, a value that overflows the
 * fixed field it would be stored in, more than MAGNUS_ROUTE_MAX_CONDITIONS
 * conditions, or a missing/duplicate/invalid action -- writing a
 * human-readable reason into `error` (if non-NULL and error_capacity > 0)
 * in every failure case. */
bool magnus_route_parse(const char *value, magnus_route_t *out, char *error,
                        size_t error_capacity);

/* True if every one of `route`'s conditions matches `request` (vacuously
 * true if it has none). `client_ip` is the connection's peer address, used
 * for MAGNUS_ROUTE_MATCH_SOURCE_CIDR. HOST/METHOD/HEADER/COOKIE values are
 * compared case-insensitively (HTTP header/method conventions); PATH_PREFIX
 * and QUERY are compared case-sensitively (paths and query values are
 * conventionally case-sensitive). */
bool magnus_route_matches(const magnus_route_t *route,
                          const magnus_http_request_t *request,
                          struct in_addr client_ip);

#endif
