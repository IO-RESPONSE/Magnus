#ifndef MAGNUS_HTTP_H
#define MAGNUS_HTTP_H

#include <stdbool.h>
#include <stddef.h>

/* Name of the cookie magnus_http_parse() looks for to carry a client's
 * cluster session-affinity key, and that the gateway issues via Set-Cookie
 * the first time a client arrives without one. */
#define MAGNUS_AFFINITY_COOKIE_NAME "MAGNUS_AFFINITY"

typedef struct {
    char method[8];
    char target[256];
    bool http_11;
    bool close_connection;
    bool head_only;
    char affinity_key[64];
} magnus_http_request_t;

typedef enum {
    MAGNUS_HTTP_OK = 0,
    MAGNUS_HTTP_BAD_REQUEST,
    MAGNUS_HTTP_URI_TOO_LONG,
    MAGNUS_HTTP_VERSION_UNSUPPORTED
} magnus_http_result_t;

magnus_http_result_t magnus_http_parse(const char *data, size_t length,
                                       magnus_http_request_t *request);

#endif
