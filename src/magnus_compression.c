#include "magnus_compression.h"

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zlib.h>
#include <zstd.h>
#include <brotli/encode.h>

/* Roadmap 2a-6: benchmarked against a ~230 KB and a ~4.6 MB HTML-shaped
 * fixture (the same repeated-line shape tests/test-core.sh's own
 * compression blocks use), sweeping Brotli's own quality range.
 * Quality 4 held to single-digit-to-low-double-digit milliseconds on
 * both fixtures -- the same ballpark as gzip -9 and zstd's own default
 * level -- while beating gzip's ratio by roughly 2x on both; quality 9
 * and above cost 2-3x the time for a mixed (sometimes worse, on the
 * larger fixture) ratio, and the library's own default quality 11 took
 * over 20x longer than quality 4 on the smaller fixture alone. Not the
 * single best ratio available from Brotli -- the fastest quality that
 * still clearly beats gzip, matching magnus_zstd_compress()'s own
 * already-established "fast end of the range, not the library
 * default" reasoning. */
#define MAGNUS_BROTLI_QUALITY 4

/* Shared token-scan core magnus_negotiate_encoding() below calls once
 * per candidate encoding -- the exact same comma-separated-list walk
 * (trim whitespace, strip a trailing `;q=...` parameter, ignore its
 * value) magnus_accepts_gzip() used to do inline before roadmap 2a-5
 * added a second candidate encoding worth checking for. */
static bool
has_token(const char *accept_encoding, const char *token, size_t token_len)
{
    const char *cursor = accept_encoding;
    if (cursor == NULL) return false;
    while (*cursor != '\0') {
        const char *end = strchr(cursor, ',');
        const char *token_end = end != NULL ? end : cursor + strlen(cursor);
        const char *parameters;
        while (cursor < token_end && isspace((unsigned char) *cursor)) cursor++;
        while (token_end > cursor && isspace((unsigned char) token_end[-1]))
            token_end--;
        parameters = memchr(cursor, ';', (size_t) (token_end - cursor));
        if (parameters != NULL) {
            token_end = parameters;
            while (token_end > cursor && isspace((unsigned char) token_end[-1]))
                token_end--;
        }
        if ((size_t) (token_end - cursor) == token_len
            && strncasecmp(cursor, token, token_len) == 0) return true;
        if (end == NULL) break;
        cursor = end + 1;
    }
    return false;
}

magnus_encoding_t
magnus_negotiate_encoding(const char *accept_encoding)
{
    if (has_token(accept_encoding, "zstd", 4)) return MAGNUS_ENCODING_ZSTD;
    if (has_token(accept_encoding, "br", 2)) return MAGNUS_ENCODING_BROTLI;
    if (has_token(accept_encoding, "gzip", 4)) return MAGNUS_ENCODING_GZIP;
    return MAGNUS_ENCODING_NONE;
}

const char *
magnus_encoding_name(magnus_encoding_t encoding)
{
    switch (encoding) {
    case MAGNUS_ENCODING_ZSTD: return "zstd";
    case MAGNUS_ENCODING_BROTLI: return "br";
    case MAGNUS_ENCODING_GZIP: return "gzip";
    case MAGNUS_ENCODING_NONE: break;
    }
    return "";
}

bool
magnus_content_type_compressible(const char *content_type)
{
    return content_type != NULL
        && (strncasecmp(content_type, "text/", 5) == 0
            || strcasecmp(content_type, "application/json") == 0
            || strcasecmp(content_type, "image/svg+xml") == 0);
}

int
magnus_gzip_compress(const unsigned char *input, size_t input_length,
                     unsigned char **output, size_t *output_length)
{
    z_stream stream = {0};
    unsigned char *compressed;
    uLong bound;
    int result;
    if (output == NULL || output_length == NULL
        || (input == NULL && input_length != 0) || input_length > UINT_MAX)
        return -1;
    *output = NULL;
    *output_length = 0;
    result = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                          15 + 16, 8, Z_DEFAULT_STRATEGY);
    if (result != Z_OK) return -1;
    bound = deflateBound(&stream, (uLong) input_length);
    compressed = malloc((size_t) bound);
    if (compressed == NULL) {
        deflateEnd(&stream);
        return -1;
    }
    stream.next_in = (Bytef *) input;
    stream.avail_in = (uInt) input_length;
    stream.next_out = compressed;
    stream.avail_out = (uInt) bound;
    do {
        result = deflate(&stream, Z_FINISH);
    } while (result == Z_OK);
    if (result != Z_STREAM_END) {
        free(compressed);
        deflateEnd(&stream);
        return -1;
    }
    *output_length = (size_t) stream.total_out;
    *output = compressed;
    deflateEnd(&stream);
    return 0;
}

int
magnus_zstd_compress(const unsigned char *input, size_t input_length,
                     unsigned char **output, size_t *output_length)
{
    unsigned char *compressed;
    size_t bound;
    size_t written;
    if (output == NULL || output_length == NULL
        || (input == NULL && input_length != 0))
        return -1;
    *output = NULL;
    *output_length = 0;
    bound = ZSTD_compressBound(input_length);
    compressed = malloc(bound == 0 ? 1 : bound);
    if (compressed == NULL) return -1;
    written = ZSTD_compress(compressed, bound, input, input_length,
                            ZSTD_CLEVEL_DEFAULT);
    if (ZSTD_isError(written)) {
        free(compressed);
        return -1;
    }
    *output_length = written;
    *output = compressed;
    return 0;
}

int
magnus_brotli_compress(const unsigned char *input, size_t input_length,
                       unsigned char **output, size_t *output_length)
{
    unsigned char *compressed;
    size_t bound;
    size_t encoded_size;
    if (output == NULL || output_length == NULL
        || (input == NULL && input_length != 0))
        return -1;
    *output = NULL;
    *output_length = 0;
    bound = BrotliEncoderMaxCompressedSize(input_length);
    /* Zero means "the library declines to bound this size" (its own
     * documented escape hatch, not a real 0-byte case) -- input_length
     * itself is always a safe fallback capacity: compressed output is
     * never larger than the input for any real compressor without
     * pathological, specifically-crafted input, and this call's own
     * callers (magnus_compress_static(), each protocol's own finish_
     * compression()) only ever pass ordinary file/response bodies. */
    if (bound == 0) bound = input_length == 0 ? 1 : input_length;
    compressed = malloc(bound);
    if (compressed == NULL) return -1;
    encoded_size = bound;
    if (!BrotliEncoderCompress(MAGNUS_BROTLI_QUALITY, BROTLI_DEFAULT_WINDOW,
                               BROTLI_MODE_GENERIC, input_length, input,
                               &encoded_size, compressed)) {
        free(compressed);
        return -1;
    }
    *output_length = encoded_size;
    *output = compressed;
    return 0;
}

int
magnus_compress(magnus_encoding_t encoding, const unsigned char *input,
                size_t input_length, unsigned char **output,
                size_t *output_length)
{
    switch (encoding) {
    case MAGNUS_ENCODING_ZSTD:
        return magnus_zstd_compress(input, input_length, output,
                                    output_length);
    case MAGNUS_ENCODING_BROTLI:
        return magnus_brotli_compress(input, input_length, output,
                                      output_length);
    case MAGNUS_ENCODING_GZIP:
    case MAGNUS_ENCODING_NONE:
        break;
    }
    return magnus_gzip_compress(input, input_length, output, output_length);
}
