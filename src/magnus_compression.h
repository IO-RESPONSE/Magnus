#ifndef MAGNUS_COMPRESSION_H
#define MAGNUS_COMPRESSION_H

#include <stdbool.h>
#include <stddef.h>

#define MAGNUS_COMPRESSION_MIN_SIZE 256
#define MAGNUS_COMPRESSION_MAX_SIZE (8 * 1024 * 1024)

/* MAGNUS_ENCODING_NONE is always 0 so `magnus_negotiate_encoding(...)
 * != MAGNUS_ENCODING_NONE` reads as the eligibility check every caller
 * already wants, the same shape magnus_accepts_gzip()'s own bool
 * return used to be (roadmap 2a-5). */
typedef enum {
    MAGNUS_ENCODING_NONE = 0,
    MAGNUS_ENCODING_GZIP,
    MAGNUS_ENCODING_ZSTD
} magnus_encoding_t;

/* Picks the best encoding this Accept-Encoding header value makes
 * available, in this codebase's own narrow preference order (zstd >
 * gzip > none) -- zstd's own default compression level (3) is fast
 * enough for real per-request, on-the-fly compression (unlike, say,
 * Brotli's own default of 11, tuned for precomputed static assets, not
 * this codebase's use case: every eligible response -- static file or
 * proxied -- is compressed fresh on every qualifying request, never
 * cached compressed), so zstd is preferred whenever a client offers
 * it. Deliberately ignores q-values (RFC 9110 12.5.3 permits any
 * server policy that excludes q=0) the same way magnus_accepts_gzip()
 * always did -- a token's own mere presence (or absence) decides this,
 * not its weight; a real q-value-aware negotiation, and Brotli as a
 * third candidate, are both later increments, not silently missing.
 * Returns MAGNUS_ENCODING_NONE for a NULL header or one offering
 * neither. */
magnus_encoding_t magnus_negotiate_encoding(const char *accept_encoding);

/* "gzip" or "zstd" for the Content-Encoding response header -- never
 * called with MAGNUS_ENCODING_NONE. */
const char *magnus_encoding_name(magnus_encoding_t encoding);

bool magnus_content_type_compressible(const char *content_type);

int magnus_gzip_compress(const unsigned char *input, size_t input_length,
                         unsigned char **output, size_t *output_length);

/* Same contract as magnus_gzip_compress() (roadmap 2a-5) -- ZSTD_compress()
 * at its own library default level (ZSTD_CLEVEL_DEFAULT, currently 3),
 * the fast end of zstd's own range, matching magnus_negotiate_encoding()'s
 * own reasoning for preferring zstd here in the first place. */
int magnus_zstd_compress(const unsigned char *input, size_t input_length,
                         unsigned char **output, size_t *output_length);

#endif
