#include "magnus_compression.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static void
round_trip(size_t length)
{
    unsigned char *input = malloc(length == 0 ? 1 : length);
    unsigned char *compressed = NULL;
    unsigned char *decoded = malloc(length == 0 ? 1 : length);
    size_t compressed_length = 0;
    z_stream stream = {0};
    int result;
    assert(input != NULL && decoded != NULL);
    for (size_t index = 0; index < length; index++)
        input[index] = (unsigned char) (index % 251);
    assert(magnus_gzip_compress(input, length, &compressed,
                                &compressed_length) == 0);
    assert(compressed != NULL && compressed_length >= 18);
    assert(inflateInit2(&stream, 15 + 16) == Z_OK);
    stream.next_in = compressed;
    stream.avail_in = (uInt) compressed_length;
    stream.next_out = decoded;
    stream.avail_out = (uInt) (length == 0 ? 1 : length);
    result = inflate(&stream, Z_FINISH);
    assert(result == Z_STREAM_END);
    assert(stream.total_out == length);
    assert(memcmp(input, decoded, length) == 0);
    inflateEnd(&stream);
    free(decoded);
    free(compressed);
    free(input);
}

int
main(void)
{
    assert(magnus_accepts_gzip("gzip"));
    assert(magnus_accepts_gzip("br, gzip ; q=0.5, deflate"));
    assert(magnus_accepts_gzip("GZip;q=0"));
    assert(!magnus_accepts_gzip(NULL));
    assert(!magnus_accepts_gzip("br, xgzip, deflate"));
    assert(magnus_content_type_compressible("text/html; charset=utf-8"));
    assert(magnus_content_type_compressible("application/json"));
    assert(magnus_content_type_compressible("image/svg+xml"));
    assert(!magnus_content_type_compressible("image/png"));
    round_trip(0);
    round_trip(MAGNUS_COMPRESSION_MIN_SIZE);
    round_trip(128 * 1024);
    return 0;
}
