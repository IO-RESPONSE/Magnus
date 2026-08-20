#ifndef MAGNUS_BASE64_H
#define MAGNUS_BASE64_H

#include <stddef.h>

/* base64url (RFC 4648 section 5 -- '-'/'_' instead of '+'/'/') decoding.
 * Kept as its own small, self-contained module -- like magnus_h2.c's ALPN
 * callback -- since its only caller (roadmap 1e-5: decoding an h2c
 * upgrade request's HTTP2-Settings header value) needs nothing beyond
 * this one pure function, and it is exactly the kind of new
 * untrusted-bytes parser this project always gives its own fuzz harness
 * (tests/fuzz-base64.c) rather than inlining directly into the request
 * dispatch path that calls it.
 *
 * Decodes `input` (input_length bytes; a trailing run of 0-2 '='
 * padding characters is tolerated but not required, matching how
 * base64url appears in HTTP headers in practice) into `out`, which must
 * be at least out_capacity bytes. Returns the decoded length on success,
 * or -1 if the input contains a character outside the base64url
 * alphabet (plus '='), has an invalid length (not decodable at all --
 * e.g. a single leftover character with no valid padding), or the
 * decoded output would not fit in out_capacity. Never writes past
 * out_capacity regardless of input. */
int magnus_base64url_decode(const char *input, size_t input_length,
                            unsigned char *out, size_t out_capacity);

#endif
