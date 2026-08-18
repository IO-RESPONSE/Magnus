#ifndef MAGNUS_PROXY_H
#define MAGNUS_PROXY_H

#include <stdbool.h>
#include <stddef.h>

/* True if `name` (an HTTP header field name, case-insensitive) is a
 * hop-by-hop header per RFC 7230 6.1 and must not be relayed across a
 * proxy boundary unchanged. */
bool magnus_proxy_is_hop_by_hop(const char *name);

/* Parses a raw upstream HTTP response header block (a status line followed
 * by header fields, ending with the blank line that terminates the header
 * section) and rewrites it into `out`:
 *   - the status line is normalized to HTTP/1.1
 *   - hop-by-hop headers are dropped
 *   - framing is forced to `Connection: close` and an `X-Magnus-Via`
 *     marker header is appended
 *
 * `raw` must be NUL-terminated and is mutated in place (tokenized).
 * `header_length` is the length of `raw` up to and including the trailing
 * blank line's CRLFCRLF. `out_status` receives the parsed upstream status
 * code on success.
 *
 * Returns the number of bytes written to `out` (excluding the NUL
 * terminator) on success, or -1 if the status line is malformed or `out`
 * is too small to hold the sanitized block. */
int magnus_proxy_sanitize_response_headers(char *raw, size_t header_length,
                                           char *out, size_t out_capacity,
                                           unsigned *out_status);

#endif
