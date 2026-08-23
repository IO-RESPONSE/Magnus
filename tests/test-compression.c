#include "magnus_compression.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <zstd.h>
#include <brotli/decode.h>

static void
gzip_round_trip(size_t length)
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

/* Roadmap 2a-5: the zstd analogue of gzip_round_trip() above, same
 * shape exactly. */
static void
zstd_round_trip(size_t length)
{
    unsigned char *input = malloc(length == 0 ? 1 : length);
    unsigned char *compressed = NULL;
    unsigned char *decoded = malloc(length == 0 ? 1 : length);
    size_t compressed_length = 0;
    size_t decoded_size;
    assert(input != NULL && decoded != NULL);
    for (size_t index = 0; index < length; index++)
        input[index] = (unsigned char) (index % 251);
    assert(magnus_zstd_compress(input, length, &compressed,
                                &compressed_length) == 0);
    assert(compressed != NULL);
    decoded_size = ZSTD_decompress(decoded, length == 0 ? 1 : length,
                                   compressed, compressed_length);
    assert(!ZSTD_isError(decoded_size));
    assert(decoded_size == length);
    assert(memcmp(input, decoded, length) == 0);
    free(decoded);
    free(compressed);
    free(input);
}

/* Roadmap 2a-6: the Brotli analogue again -- same shape once more. */
static void
brotli_round_trip(size_t length)
{
    unsigned char *input = malloc(length == 0 ? 1 : length);
    unsigned char *compressed = NULL;
    unsigned char *decoded = malloc(length == 0 ? 1 : length);
    size_t compressed_length = 0;
    size_t decoded_size = length == 0 ? 1 : length;
    assert(input != NULL && decoded != NULL);
    for (size_t index = 0; index < length; index++)
        input[index] = (unsigned char) (index % 251);
    assert(magnus_brotli_compress(input, length, &compressed,
                                  &compressed_length) == 0);
    assert(compressed != NULL);
    assert(BrotliDecoderDecompress(compressed_length, compressed,
                                   &decoded_size, decoded)
           == BROTLI_DECODER_RESULT_SUCCESS);
    assert(decoded_size == length);
    assert(memcmp(input, decoded, length) == 0);
    free(decoded);
    free(compressed);
    free(input);
}

int
main(void)
{
    assert(magnus_negotiate_encoding("gzip") == MAGNUS_ENCODING_GZIP);
    assert(magnus_negotiate_encoding("gzip ; q=0.5, deflate")
           == MAGNUS_ENCODING_GZIP);
    assert(magnus_negotiate_encoding("GZip;q=0") == MAGNUS_ENCODING_GZIP);
    assert(magnus_negotiate_encoding(NULL) == MAGNUS_ENCODING_NONE);
    assert(magnus_negotiate_encoding("xbr, xgzip, deflate")
           == MAGNUS_ENCODING_NONE);
    /* zstd is preferred over gzip whenever a client offers both, in
     * either order -- the whole point of magnus_negotiate_encoding()
     * existing as a distinct function from the old boolean
     * magnus_accepts_gzip() it replaced. */
    assert(magnus_negotiate_encoding("zstd") == MAGNUS_ENCODING_ZSTD);
    assert(magnus_negotiate_encoding("ZStd") == MAGNUS_ENCODING_ZSTD);
    assert(magnus_negotiate_encoding("gzip, zstd") == MAGNUS_ENCODING_ZSTD);
    assert(magnus_negotiate_encoding("zstd, gzip") == MAGNUS_ENCODING_ZSTD);
    assert(magnus_negotiate_encoding("br, zstd; q=0.1, deflate")
           == MAGNUS_ENCODING_ZSTD);
    assert(magnus_negotiate_encoding("br, xzstd, deflate")
           == MAGNUS_ENCODING_BROTLI);

    /* Roadmap 2a-6: Brotli ("br", the IANA-registered token -- not
     * "brotli") sits between zstd and gzip in preference: loses to
     * zstd, beats gzip, in either offered order either way. */
    assert(magnus_negotiate_encoding("br") == MAGNUS_ENCODING_BROTLI);
    assert(magnus_negotiate_encoding("Br") == MAGNUS_ENCODING_BROTLI);
    assert(magnus_negotiate_encoding("br;q=0") == MAGNUS_ENCODING_BROTLI);
    assert(magnus_negotiate_encoding("gzip, br") == MAGNUS_ENCODING_BROTLI);
    assert(magnus_negotiate_encoding("br, gzip") == MAGNUS_ENCODING_BROTLI);
    assert(magnus_negotiate_encoding("zstd, br") == MAGNUS_ENCODING_ZSTD);
    assert(magnus_negotiate_encoding("br, zstd") == MAGNUS_ENCODING_ZSTD);
    assert(magnus_negotiate_encoding("gzip, br, zstd")
           == MAGNUS_ENCODING_ZSTD);
    /* "brotli" itself is not a valid Accept-Encoding token (RFC 7932
     * registers "br"), so it must not match. */
    assert(magnus_negotiate_encoding("brotli") == MAGNUS_ENCODING_NONE);

    assert(strcmp(magnus_encoding_name(MAGNUS_ENCODING_GZIP), "gzip") == 0);
    assert(strcmp(magnus_encoding_name(MAGNUS_ENCODING_ZSTD), "zstd") == 0);
    assert(strcmp(magnus_encoding_name(MAGNUS_ENCODING_BROTLI), "br") == 0);

    assert(magnus_content_type_compressible("text/html; charset=utf-8"));
    assert(magnus_content_type_compressible("application/json"));
    assert(magnus_content_type_compressible("image/svg+xml"));
    assert(!magnus_content_type_compressible("image/png"));

    gzip_round_trip(0);
    gzip_round_trip(MAGNUS_COMPRESSION_MIN_SIZE);
    gzip_round_trip(128 * 1024);

    zstd_round_trip(0);
    zstd_round_trip(MAGNUS_COMPRESSION_MIN_SIZE);
    zstd_round_trip(128 * 1024);

    brotli_round_trip(0);
    brotli_round_trip(MAGNUS_COMPRESSION_MIN_SIZE);
    brotli_round_trip(128 * 1024);

    return 0;
}
