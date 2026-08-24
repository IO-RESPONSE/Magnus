#ifndef MAGNUS_FASTCGI_H
#define MAGNUS_FASTCGI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* FastCGI wire protocol (roadmap 5a-1, Phase 5's own first slice):
 * pure record/name-value encode and decode helpers, no I/O of any
 * kind -- the same "wire framing only" scope magnus_proxy.h/c already
 * has for HTTP/1.x response sanitizing. magnus.c's own dispatch state
 * machine owns the actual socket I/O and the record-boundary buffering
 * a real, possibly-fragmented TCP stream needs, exactly the way it
 * already owns that for the HTTP/1.x proxy-dispatch and gRPC paths.
 *
 * Spec shape (there is no RFC; this follows the original FastCGI
 * Specification, still the de facto standard every real
 * implementation -- PHP-FPM included -- follows unchanged): every
 * record is an 8-byte header (version, type, a big-endian 16-bit
 * request id, a big-endian 16-bit content length, an 8-bit padding
 * length, one reserved byte) followed by `content_length` content
 * bytes and `padding_length` padding bytes (padding exists purely so
 * a real implementation can align record boundaries; this codebase
 * always uses zero padding, valid per spec, since alignment brings it
 * no benefit). A single record's content is capped at 65535 bytes (the
 * length field's own 16-bit width) -- content needing more is split
 * across multiple records of the same type/request id, same as every
 * real implementation already does. */

#define MAGNUS_FASTCGI_VERSION 1
#define MAGNUS_FASTCGI_HEADER_LEN 8
#define MAGNUS_FASTCGI_MAX_CONTENT_LENGTH 65535

typedef enum {
    MAGNUS_FASTCGI_BEGIN_REQUEST = 1,
    MAGNUS_FASTCGI_ABORT_REQUEST = 2,
    MAGNUS_FASTCGI_END_REQUEST = 3,
    MAGNUS_FASTCGI_PARAMS = 4,
    MAGNUS_FASTCGI_STDIN = 5,
    MAGNUS_FASTCGI_STDOUT = 6,
    MAGNUS_FASTCGI_STDERR = 7,
    MAGNUS_FASTCGI_DATA = 8,
    MAGNUS_FASTCGI_GET_VALUES = 9,
    MAGNUS_FASTCGI_GET_VALUES_RESULT = 10,
    MAGNUS_FASTCGI_UNKNOWN_TYPE = 11
} magnus_fastcgi_record_type_t;

/* The only role this codebase ever requests: "answer one HTTP-shaped
 * request", the role every web-server-facing FastCGI integration
 * (PHP-FPM included) actually implements. FCGI_FILTER/FCGI_AUTHORIZER
 * are real roles in the spec but have no analogue in what a reverse
 * proxy dispatch route does. */
#define MAGNUS_FASTCGI_ROLE_RESPONDER 1

/* BEGIN_REQUEST's own flags byte: keep the connection open after
 * FCGI_END_REQUEST rather than the application server closing it --
 * unused by this first slice (no connection pooling/reuse yet, see
 * magnus.c's own dispatch comment), always sent as 0 for now. */
#define MAGNUS_FASTCGI_KEEP_CONN 1

/* Writes an 8-byte FastCGI record header into `out` (which must have
 * room for MAGNUS_FASTCGI_HEADER_LEN bytes). `content_length` must be
 * <= MAGNUS_FASTCGI_MAX_CONTENT_LENGTH; padding is always written as
 * 0 (see this file's own top comment on why). */
void magnus_fastcgi_write_header(unsigned char *out, unsigned char type,
                                 uint16_t request_id, size_t content_length);

/* Writes the 8-byte BEGIN_REQUEST record body (role + flags + 5
 * reserved bytes, all zeroed) into `out` (which must have room for 8
 * bytes). */
void magnus_fastcgi_write_begin_request_body(unsigned char *out,
                                             uint16_t role,
                                             unsigned char flags);

/* Encodes one FastCGI name-value pair (the PARAMS record's own
 * content shape -- each of name/value length is a 1-byte value when
 * < 128, or a 4-byte big-endian value with the high bit set
 * otherwise, per the spec) into `out` (capacity `out_capacity`).
 * Returns the number of bytes written, or 0 if it would not fit or
 * either length exceeds what this codebase ever needs to send (both
 * name and value are bounded well under the 4-byte-length threshold
 * in every real caller, but the 4-byte form is still implemented
 * faithfully rather than assumed away). */
size_t magnus_fastcgi_encode_nv(const char *name, const char *value,
                                unsigned char *out, size_t out_capacity);

/* Locates the blank line terminating a CGI-shaped response header
 * block (RFC 3875 6: an optional "Status:" line, then ordinary header
 * lines) within `data` (length `length`) -- tolerates either a bare
 * "\n\n" or a proper "\r\n\r\n" (picking whichever occurs first, if
 * both happen to be present), the same leniency real CGI/FastCGI
 * responders are known to need in practice. On success, sets
 * `*header_text_length` to the length of the header text itself
 * (everything before the blank line, NOT including it) and returns a
 * pointer to where the body begins (just past the blank line).
 * Returns NULL if no blank line has appeared in `data` yet -- the
 * caller's own accumulated buffer is still incomplete, not
 * malformed. */
const char *magnus_fastcgi_find_body(const char *data, size_t length,
                                     size_t *header_text_length);

/* Translates one CGI-shaped response header block (`header_text`,
 * `header_text_length` bytes, as located by magnus_fastcgi_find_body()
 * above) into a real HTTP/1.1 response header block written to `out`
 * (capacity `out_capacity`). An application-supplied "Status: NNN
 * [reason]" line (RFC 3875 6.3.3) sets the real status/reason;
 * omitted entirely, the response is 200 OK, matching CGI's own
 * documented default. `Content-Length` is always `body_length` (the
 * real, already-known accumulated body size -- never whatever, if
 * anything, the application itself claimed, which this far upstream
 * of the real client cannot be trusted to match what was actually
 * sent) and `Connection` is `close_connection ? "close" : "keep-alive"`,
 * the same client-preference-driven decision every other response in
 * this codebase makes; any Status:/Content-Length/Connection header
 * line the application sent is consumed, not passed through
 * (superseded by what this function itself decides). Returns the
 * number of bytes written to `out` (excluding the NUL terminator), or
 * -1 if a Status: line's own numeric code is malformed, or `out` is
 * too small. `*out_status` is set to the real status code decided
 * (200 when no Status: line was present) whenever a non-negative
 * value is returned -- the caller's own access-log line needs the
 * real code, not just the bytes written, and re-deriving it a second
 * time from `out` would mean re-parsing what this function already
 * parsed once. */
int magnus_fastcgi_translate_headers(const char *header_text,
                                     size_t header_text_length,
                                     size_t body_length, bool close_connection,
                                     char *out, size_t out_capacity,
                                     unsigned *out_status);

/* Decodes an 8-byte FastCGI record header from `in` (which must have
 * at least MAGNUS_FASTCGI_HEADER_LEN bytes available) into
 * `*type`/`*request_id`/`*content_length`/`*padding_length`. Returns
 * false if the version byte is not MAGNUS_FASTCGI_VERSION (this
 * codebase speaks exactly one protocol version, the only one any real
 * FastCGI application server has ever shipped). */
bool magnus_fastcgi_read_header(const unsigned char *in,
                                unsigned char *type, uint16_t *request_id,
                                size_t *content_length,
                                unsigned char *padding_length);

#endif
