#ifndef MAGNUS_UWSGI_H
#define MAGNUS_UWSGI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The uwsgi wire protocol (roadmap 5c-1, Phase 5's third upstream
 * protocol) -- not to be confused with "uWSGI" the application server
 * itself, which speaks this same protocol as one of several it
 * understands. There is no RFC; this follows the protocol's own
 * reference documentation (uwsgi.readthedocs.io/en/latest/Protocol.html)
 * and was spike-tested directly against a real uWSGI 2.0.31 server
 * before any of this codebase's own dispatch machinery was written
 * against it (see this increment's own CHANGELOG.md entry) -- both to
 * verify the request-encoding side round-trips correctly, and because
 * this codebase's own initial assumption about the *response* side
 * (that it would be CGI "Status:"-line-shaped, the same convention
 * FastCGI/SCGI both use) turned out to be wrong: a real uWSGI server's
 * response to a standard request starts with a genuine HTTP status
 * line ("HTTP/1.1 200 OK\r\n"), never a "Status:" line, which is why
 * this protocol gets its own magnus_uwsgi_translate_headers() below
 * rather than reusing magnus_fastcgi_translate_headers() the way
 * magnus_scgi dispatch (roadmap 5b-1) already does for its own,
 * genuinely CGI-shaped, response.
 *
 * Request framing: a 4-byte header -- 1-byte modifier1 (0 selects the
 * generic/default request type every plain web-server integration
 * uses; other values select plugin-specific modes, e.g. Perl PSGI,
 * none of which this codebase has any reason to ever send), a
 * little-endian 16-bit "vars block" size (the one place this protocol
 * differs from FastCGI's own big-endian convention -- documented as a
 * deliberate x86-native-order choice, not an oversight), and 1-byte
 * modifier2 (0 for the generic request type) -- followed by exactly
 * that many bytes of "vars": a flat sequence of name/value pairs, each
 * a little-endian 16-bit name length, the name bytes, a little-endian
 * 16-bit value length, then the value bytes, with no other separator
 * or terminator (the explicit lengths are the only framing a pair
 * needs, unlike SCGI's NUL-terminated pairs). Any request body follows
 * immediately after the vars block, completely unframed -- the same
 * "body follows the header block directly" shape SCGI already has,
 * unlike FastCGI's own STDIN records. */

#define MAGNUS_UWSGI_HEADER_LEN 4
#define MAGNUS_UWSGI_MODIFIER1_DEFAULT 0
#define MAGNUS_UWSGI_MODIFIER2_DEFAULT 0

/* Writes the 4-byte uwsgi packet header into `out` (which must have
 * room for MAGNUS_UWSGI_HEADER_LEN bytes). `vars_block_size` must fit
 * in 16 bits (the vars block's own length field width) -- it covers
 * only the vars block that follows, never any request body appended
 * after it. */
void magnus_uwsgi_write_header(unsigned char *out, unsigned char modifier1,
                               size_t vars_block_size,
                               unsigned char modifier2);

/* Encodes one uwsgi var (name, then value, each its own little-endian
 * 16-bit length prefix) into `out` (capacity `out_capacity`). Returns
 * the number of bytes written (2 + strlen(name) + 2 + strlen(value)),
 * or 0 if it would not fit or either length exceeds 16 bits. */
size_t magnus_uwsgi_encode_var(const char *name, const char *value,
                               unsigned char *out, size_t out_capacity);

/* Translates one real-HTTP-shaped response header block (`header_text`,
 * `header_text_length` bytes, located the same way magnus_fastcgi_
 * find_body() already does -- reused directly, since finding a blank
 * line is not protocol-specific) into a real HTTP/1.1 response header
 * block written to `out` (capacity `out_capacity`). A first line
 * matching "HTTP/<version> <status> [reason]" sets the real status/
 * reason (this codebase's own tolerant default, mirroring magnus_
 * fastcgi_translate_headers()'s own "absent means 200 OK" behavior, is
 * that a first line NOT matching this shape at all is instead treated
 * as an ordinary header line and the status defaults to 200 -- a real
 * uWSGI server always sends one, so this only ever matters for a
 * malformed/non-conforming application). `Content-Length` is always
 * `body_length` and `Connection` is `close_connection ? "close" :
 * "keep-alive"`, the identical client-preference-driven decision every
 * other response in this codebase makes; any Status-line/Content-
 * Length/Connection the application sent is consumed, not passed
 * through. `affinity_cookie_value`, if non-NULL, appends a `Set-
 * Cookie: MAGNUS_AFFINITY=<value>; Path=/; HttpOnly; SameSite=Lax`
 * line, identical format to every other dispatch path's own. Returns
 * the number of bytes written to `out` (excluding the NUL terminator),
 * or -1 if `out` is too small. `*out_status` is set to the real status
 * code decided whenever a non-negative value is returned. */
int magnus_uwsgi_translate_headers(const char *header_text,
                                   size_t header_text_length,
                                   size_t body_length, bool close_connection,
                                   const char *affinity_cookie_value,
                                   char *out, size_t out_capacity,
                                   unsigned *out_status);

#endif
