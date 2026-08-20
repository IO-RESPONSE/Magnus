#ifndef MAGNUS_REALIP_H
#define MAGNUS_REALIP_H

#include "magnus_config.h"
#include "magnus_http.h"

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>

/* Checks if `ip` matches any of the `count` trusted CIDRs in `trusted`.
 * Returns false if trusted is NULL or count is 0. */
bool magnus_realip_is_trusted(const magnus_cidr_t *trusted, size_t count,
                              struct in_addr ip);

/* Resolves Real IP from `request`'s Forwarded (RFC 7239) or X-Forwarded-For
 * header, walking the hop chain from right to left and returning the right-most
 * untrusted hop.
 *
 * Precedence: Forwarded is checked first; if absent or contains no parseable
 * IPv4 address, X-Forwarded-For is checked.
 *
 * Returns true if an address was resolved and writes it into `out_real_ip`.
 * Returns false if neither header is present or no valid address was found. */
bool magnus_realip_resolve_headers(const magnus_http_request_t *request,
                                   const magnus_cidr_t *trusted, size_t count,
                                   struct in_addr *out_real_ip);

/* Result codes for PROXY protocol preamble parsing. */
typedef enum {
    MAGNUS_PROXY_PROTO_OK = 0,      /* Complete valid PROXY preamble parsed */
    MAGNUS_PROXY_PROTO_NOT_PROXY,   /* Definitely not PROXY protocol (plain HTTP / TLS) */
    MAGNUS_PROXY_PROTO_INCOMPLETE,  /* Incomplete PROXY preamble, need more bytes */
    MAGNUS_PROXY_PROTO_ERROR        /* Malformed PROXY preamble */
} magnus_proxy_proto_result_t;

/* Parses a PROXY protocol (v1 text or v2 binary) preamble from `buffer` (length `length`).
 *
 * If valid PROXY preamble is found:
 *   Returns MAGNUS_PROXY_PROTO_OK, sets *out_consumed to bytes consumed,
 *   and sets *out_src_ip to the source IPv4 address (or preserves existing if LOCAL/UNKNOWN).
 *
 * If buffer starts with bytes that cannot be PROXY protocol:
 *   Returns MAGNUS_PROXY_PROTO_NOT_PROXY (0 bytes consumed).
 *
 * If buffer starts with a valid prefix of PROXY protocol but is incomplete:
 *   Returns MAGNUS_PROXY_PROTO_INCOMPLETE.
 *
 * If buffer is malformed PROXY protocol:
 *   Returns MAGNUS_PROXY_PROTO_ERROR.
 */
magnus_proxy_proto_result_t
magnus_proxy_proto_parse(const char *buffer, size_t length,
                         size_t *out_consumed, struct in_addr *out_src_ip);

#endif
