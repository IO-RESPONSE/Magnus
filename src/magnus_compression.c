#include "magnus_compression.h"

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
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

/* Roadmap 2a-7: named fields, not a union, even though only one is ever
 * valid for a given `encoding` -- z_stream / ZSTD_CStream pointer /
 * BrotliEncoderState pointer inside a union would still be legal C, but named
 * fields read unambiguously at every call site below without needing a
 * comment reminding which union member is live, and the extra two
 * pointers' worth of memory is irrelevant next to the megabytes-scale
 * response this is even being used for. */
struct magnus_stream_compressor {
    magnus_encoding_t encoding;
    z_stream gzip;
    ZSTD_CStream *zstd;
    BrotliEncoderState *brotli;
};

magnus_stream_compressor_t *
magnus_stream_compress_begin(magnus_encoding_t encoding)
{
    magnus_stream_compressor_t *compressor = calloc(1, sizeof(*compressor));
    if (compressor == NULL) return NULL;
    compressor->encoding = encoding;
    switch (encoding) {
    case MAGNUS_ENCODING_ZSTD:
        compressor->zstd = ZSTD_createCStream();
        if (compressor->zstd == NULL
            || ZSTD_isError(ZSTD_initCStream(compressor->zstd,
                                             ZSTD_CLEVEL_DEFAULT))) {
            if (compressor->zstd != NULL) ZSTD_freeCStream(compressor->zstd);
            free(compressor);
            return NULL;
        }
        break;
    case MAGNUS_ENCODING_BROTLI:
        compressor->brotli = BrotliEncoderCreateInstance(NULL, NULL, NULL);
        if (compressor->brotli == NULL) {
            free(compressor);
            return NULL;
        }
        /* Same MAGNUS_BROTLI_QUALITY as the one-shot magnus_brotli_
         * compress() -- this is the streaming analogue of that same
         * function, not an independent choice. */
        (void) BrotliEncoderSetParameter(compressor->brotli,
            BROTLI_PARAM_QUALITY, MAGNUS_BROTLI_QUALITY);
        break;
    case MAGNUS_ENCODING_GZIP:
    case MAGNUS_ENCODING_NONE:
    default:
        if (deflateInit2(&compressor->gzip, Z_DEFAULT_COMPRESSION,
                         Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY)
            != Z_OK) {
            free(compressor);
            return NULL;
        }
        break;
    }
    return compressor;
}

bool
magnus_stream_compress_step(magnus_stream_compressor_t *compressor,
                            const unsigned char *input, size_t input_length,
                            bool finish, size_t *input_consumed,
                            unsigned char *output, size_t output_capacity,
                            size_t *output_length, bool *done)
{
    *input_consumed = 0;
    *output_length = 0;
    *done = false;
    switch (compressor->encoding) {
    case MAGNUS_ENCODING_ZSTD: {
        ZSTD_inBuffer in = { input, input_length, 0 };
        ZSTD_outBuffer out = { output, output_capacity, 0 };
        /* Per ZSTD_compressStream2()'s own doc comment (zstd.h): a
         * return of exactly 0 with endOp == ZSTD_e_end means the frame
         * is fully complete *and* fully flushed into `out` -- nothing
         * else to check, unlike gzip's own Z_STREAM_END-vs-avail_out
         * distinction below. */
        size_t result = ZSTD_compressStream2(compressor->zstd, &out, &in,
            finish ? ZSTD_e_end : ZSTD_e_continue);
        if (ZSTD_isError(result)) return false;
        *input_consumed = in.pos;
        *output_length = out.pos;
        *done = finish && result == 0;
        return true;
    }
    case MAGNUS_ENCODING_BROTLI: {
        size_t available_in = input_length;
        const uint8_t *next_in = input;
        size_t available_out = output_capacity;
        uint8_t *next_out = output;
        if (!BrotliEncoderCompressStream(compressor->brotli,
                finish ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_PROCESS,
                &available_in, &next_in, &available_out, &next_out, NULL))
            return false;
        *input_consumed = input_length - available_in;
        *output_length = output_capacity - available_out;
        *done = finish && BrotliEncoderIsFinished(compressor->brotli);
        return true;
    }
    case MAGNUS_ENCODING_GZIP:
    case MAGNUS_ENCODING_NONE:
    default: {
        int result;
        /* Once deflate() returns Z_STREAM_END no further call is valid
         * (zlib's own contract) -- the caller's own loop (magnus.c's
         * stream-compress write path) stops calling this function the
         * moment *done comes back true, so that never happens here. */
        compressor->gzip.next_in = (Bytef *) input;
        compressor->gzip.avail_in = (uInt) input_length;
        compressor->gzip.next_out = output;
        compressor->gzip.avail_out = (uInt) output_capacity;
        result = deflate(&compressor->gzip, finish ? Z_FINISH : Z_NO_FLUSH);
        if (result != Z_OK && result != Z_STREAM_END && result != Z_BUF_ERROR)
            return false;
        *input_consumed = input_length - compressor->gzip.avail_in;
        *output_length = output_capacity - compressor->gzip.avail_out;
        *done = result == Z_STREAM_END;
        return true;
    }
    }
}

void
magnus_stream_compress_end(magnus_stream_compressor_t *compressor)
{
    if (compressor == NULL) return;
    switch (compressor->encoding) {
    case MAGNUS_ENCODING_ZSTD:
        ZSTD_freeCStream(compressor->zstd);
        break;
    case MAGNUS_ENCODING_BROTLI:
        BrotliEncoderDestroyInstance(compressor->brotli);
        break;
    case MAGNUS_ENCODING_GZIP:
    case MAGNUS_ENCODING_NONE:
    default:
        deflateEnd(&compressor->gzip);
        break;
    }
    free(compressor);
}
