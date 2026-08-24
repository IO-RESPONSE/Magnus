#ifndef MAGNUS_SCGI_H
#define MAGNUS_SCGI_H

#include <stddef.h>

/* SCGI wire protocol (roadmap 5b-1, Phase 5's second upstream protocol
 * after FastCGI/5a): there is no RFC here either -- this follows the
 * SCGI protocol specification (https://python.ca/scgi/protocol.txt),
 * the de facto reference every real implementation (uwsgi's own SCGI
 * mode, Python's flup, etc.) already follows unchanged. Substantially
 * simpler than FastCGI's own binary record framing: a client opens one
 * TCP connection, sends a single netstring-encoded header block
 * followed immediately by the raw request body (no further framing of
 * any kind -- the body's own length is simply CONTENT_LENGTH, the one
 * header the protocol requires every request to send first), then
 * reads a CGI-shaped response (RFC 3875 6: an optional "Status:" line,
 * ordinary headers, a blank line, then the body) until the connection
 * is closed -- there is no explicit end-of-response marker the way
 * FastCGI's own FCGI_END_REQUEST record is, so completion is always
 * signaled by the upstream itself closing the connection (see this
 * codebase's own magnus_scgi_handle_upstream() in magnus.c). Because
 * the response shape is identical CGI framing either way, this
 * codebase reuses magnus_fastcgi_find_body()/magnus_fastcgi_translate_
 * headers() directly for SCGI's own response translation too, rather
 * than duplicating that already-generic parsing logic under a second
 * name -- the same reasoning MAGNUS_AFFINITY_COOKIE_NAME is already
 * shared, rather than redefined, across every dispatch path that needs
 * it.
 *
 * A header block is a sequence of NUL-terminated name/value pairs
 * (name\0value\0name\0value\0...), unlike FastCGI's own length-
 * prefixed PARAMS encoding -- the NUL terminators are the only framing
 * a pair needs. That whole block is then wrapped in netstring framing
 * (D. J. Bernstein's netstrings: "<decimal-length>:<data>,", where
 * length is the byte length of `data` alone, excluding the colon and
 * comma) before being sent; the request body follows immediately after
 * the closing comma, completely unframed. */

/* Encodes one SCGI header name/value pair (NUL-terminated name, then
 * NUL-terminated value, concatenated) into `out` (capacity
 * `out_capacity`). Returns the number of bytes written
 * (strlen(name) + 1 + strlen(value) + 1), or 0 if it would not fit. */
size_t magnus_scgi_encode_nv(const char *name, const char *value,
                             char *out, size_t out_capacity);

/* Writes the netstring length-prefix ("<decimal-length>:") for a
 * header block whose payload is `payload_length` bytes long into `out`
 * (capacity `out_capacity`) -- the payload bytes themselves, and the
 * trailing ',' netstring terminator, are the caller's own
 * responsibility to write immediately after (this function only ever
 * sees the payload's length, never its bytes, mirroring magnus_
 * fastcgi_write_header()'s own "just the framing" scope). Returns the
 * number of bytes written (excluding a NUL terminator, none is
 * written), or 0 if it would not fit. */
size_t magnus_scgi_write_netstring_prefix(size_t payload_length, char *out,
                                          size_t out_capacity);

#endif
