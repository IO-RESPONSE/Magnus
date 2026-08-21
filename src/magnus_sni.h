#ifndef MAGNUS_SNI_H
#define MAGNUS_SNI_H

#include <stdbool.h>
#include <stddef.h>

/* Longest hostname magnus_sni_extract() will ever write into `out` --
 * generous for any real DNS name (max 253 bytes) plus the NUL. */
#define MAGNUS_SNI_HOSTNAME_MAX 256

/* Result codes for TLS ClientHello SNI extraction (roadmap 3b), mirroring
 * magnus_proxy_proto_parse()'s own OK/NOT_THIS_PROTOCOL/INCOMPLETE/ERROR
 * shape (magnus_realip.h) -- the same four-way distinction a "peek the
 * preamble, decide, then relay everything including what was already
 * peeked" design always needs, whatever protocol is being peeked at. */
typedef enum {
    /* A complete ClientHello with exactly one host_name server_name entry
     * was found; the hostname itself is in *out. */
    MAGNUS_SNI_OK = 0,
    /* The very first byte(s) already rule out a TLS handshake record --
     * this is definitely not a ClientHello, more bytes will not help. */
    MAGNUS_SNI_NOT_TLS,
    /* Everything examined so far is consistent with a ClientHello, but
     * `length` bytes is not yet enough to know either way -- the caller
     * should buffer more and try again. */
    MAGNUS_SNI_INCOMPLETE,
    /* A complete, well-formed ClientHello was found, but it carries no
     * server_name extension (or none of type host_name) -- not an error,
     * just nothing to route on. */
    MAGNUS_SNI_NO_SNI,
    /* The record/handshake structure itself is malformed (a length field
     * pointing past what it should, an implausible value, etc.) --
     * distinguished from NOT_TLS only for callers that want to log the
     * difference; both are treated identically (fall back) by every
     * caller in this codebase today. */
    MAGNUS_SNI_MALFORMED
} magnus_sni_result_t;

/* Attempts to extract the SNI hostname from a single TLS record's worth
 * of ClientHello bytes at `data[0..length)`. Only ever inspects the
 * record layer, the handshake header, and the ClientHello body up through
 * its extensions -- never anything TLS-version-specific past that (SNI
 * lives in the same place in both a TLS 1.2 and a TLS 1.3 ClientHello).
 * Deliberately does not handle a ClientHello fragmented across more than
 * one TLS record (vanishingly rare for a real client's own SNI-carrying
 * ClientHello, which virtually always fits in one record) -- a
 * multi-record ClientHello is reported as MAGNUS_SNI_INCOMPLETE up to
 * the caller's own peek-buffer limit, then naturally resolves to "give
 * up, use the default" once that limit is reached, same as any other
 * unresolvable case.
 *
 * On MAGNUS_SNI_OK, writes the NUL-terminated hostname (lower-cased) into
 * `out` (at least MAGNUS_SNI_HOSTNAME_MAX bytes) -- callers do not need
 * to case-fold it themselves before matching against a configured
 * pattern. A hostname that would not fit in `out` is reported as
 * MAGNUS_SNI_MALFORMED (a real DNS name is always well under
 * MAGNUS_SNI_HOSTNAME_MAX; anything longer is not one).
 *
 * Not a general TLS parser and not meant to be one: this is a liveness/
 * routing peek at the caller's own configured backend's traffic, not a
 * security boundary parsing untrusted-and-trusted-equally input -- every
 * length field is still bounds-checked against `length` before use (a
 * malformed or hostile ClientHello must never read past the buffer), but
 * no attempt is made to validate the handshake beyond what is needed to
 * locate the server_name extension. */
magnus_sni_result_t magnus_sni_extract(const unsigned char *data, size_t length,
                                       char *out, size_t out_capacity);

/* True if `hostname` (already lower-cased, as magnus_sni_extract() always
 * returns it) matches `pattern`: an exact case-insensitive match, or, if
 * `pattern` begins with the literal two characters `*.`, a case-
 * insensitive match of everything from that `.` onward against the same
 * suffix of `hostname` -- requiring at least one label before it, so
 * `*.example.com` matches `www.example.com` but not `example.com`
 * itself (that needs its own separate, exact-match route). Not a general
 * glob: `*` is only ever recognized in that one leading `*.` position. */
bool magnus_sni_pattern_matches(const char *pattern, const char *hostname);

#endif
