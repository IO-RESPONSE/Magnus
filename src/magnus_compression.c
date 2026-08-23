#include "magnus_compression.h"

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zlib.h>
#include <zstd.h>

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
    if (has_token(accept_encoding, "gzip", 4)) return MAGNUS_ENCODING_GZIP;
    return MAGNUS_ENCODING_NONE;
}

const char *
magnus_encoding_name(magnus_encoding_t encoding)
{
    switch (encoding) {
    case MAGNUS_ENCODING_ZSTD: return "zstd";
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
