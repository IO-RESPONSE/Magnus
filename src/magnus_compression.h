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
    MAGNUS_ENCODING_ZSTD,
    MAGNUS_ENCODING_BROTLI
} magnus_encoding_t;

/* Picks the best encoding this Accept-Encoding header value makes
 * available, in this codebase's own narrow preference order (zstd >
 * brotli > gzip > none) -- benchmarked, not assumed (see CHANGELOG.md's
 * own 2a-6 entry): zstd's default level (3) and Brotli at
 * MAGNUS_BROTLI_QUALITY (magnus_compression.c) both stay in the same
 * sub-30ms-per-MiB range real per-request, on-the-fly compression needs
 * (unlike Brotli's own *default* of 11, tuned for precomputed static
 * assets and 20x-plus slower in the same benchmark), and zstd edged out
 * Brotli on ratio on the larger of the two fixtures tested, so it stays
 * first; Brotli still beats plain gzip on ratio at that same speed
 * budget, so it takes second over gzip rather than falling back to
 * gzip's worse compression for a client that already offered something
 * better than zstd. Deliberately ignores q-values (RFC 9110 12.5.3
 * permits any server policy that excludes q=0) the same way
 * magnus_accepts_gzip() always did -- a token's own mere presence (or
 * absence) decides this, not its weight; a real q-value-aware
 * negotiation is a later increment, not silently missing. Returns
 * MAGNUS_ENCODING_NONE for a NULL header or one offering none of the
 * three. */
magnus_encoding_t magnus_negotiate_encoding(const char *accept_encoding);

/* "gzip", "zstd", or "br" (the IANA-registered Content-Encoding token
 * for Brotli -- not "brotli") for the Content-Encoding response header;
 * never called with MAGNUS_ENCODING_NONE. */
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

/* Same contract again (roadmap 2a-6) -- BrotliEncoderCompress() at
 * MAGNUS_BROTLI_QUALITY (magnus_compression.c's own comment has the
 * benchmark behind that specific level) rather than the library's own
 * default quality 11. */
int magnus_brotli_compress(const unsigned char *input, size_t input_length,
                           unsigned char **output, size_t *output_length);

/* Roadmap 2a-6: dispatches to whichever of magnus_gzip_compress()/
 * magnus_zstd_compress()/magnus_brotli_compress() `encoding` names --
 * added once a third candidate made a hand-rolled two-way ternary at
 * every call site (there are five: each protocol's own proxy-dispatch
 * finish_compression(), plus magnus_compress_static() and its h3
 * analogue) turn into a three-way one, at which point one shared
 * dispatcher was clearly better than five near-identical copies of the
 * same branch. Never called with MAGNUS_ENCODING_NONE -- same
 * precondition as magnus_encoding_name(). */
int magnus_compress(magnus_encoding_t encoding, const unsigned char *input,
                    size_t input_length, unsigned char **output,
                    size_t *output_length);

/* Roadmap 2a-7: streaming compression for responses too large for the
 * buffer-then-compress shape every other compress function above uses
 * (magnus_compress()'s own callers cap out at MAGNUS_COMPRESSION_MAX_SIZE
 * for exactly this reason -- holding the whole body, compressed *and*
 * uncompressed, in memory at once stops being reasonable well before 8
 * MiB scales to what a static file server actually needs to handle).
 * Opaque: the concrete encoder state (z_stream / ZSTD_CStream pointer /
 * BrotliEncoderState pointer, one of the three depending on which encoding was
 * negotiated) is magnus_compression.c's own business, not exposed here
 * -- callers only ever see a pointer to feed back into the functions
 * below, the same "opaque handle" shape struct magnus_h2_stream's own
 * callers already use for a persistent object elsewhere in this
 * codebase. */
typedef struct magnus_stream_compressor magnus_stream_compressor_t;

/* Allocates a fresh streaming compressor for `encoding` -- never called
 * with MAGNUS_ENCODING_NONE, same precondition as magnus_compress().
 * Returns NULL on allocation failure (caller falls back to relaying the
 * response uncompressed, the same graceful-degradation every other
 * compress function in this file already provides on its own failure
 * path). */
magnus_stream_compressor_t *magnus_stream_compress_begin(
    magnus_encoding_t encoding);

/* One incremental step: feeds up to `input_length` bytes of `input`
 * into the compressor and writes as many compressed bytes as fit into
 * `output` (capacity `output_capacity`). `*input_consumed` and
 * `*output_length` report how much of each buffer was actually used --
 * `*input_consumed` can be less than `input_length` when `output` fills
 * up first, in which case the caller must call again with the
 * remaining, unconsumed tail of `input` (after draining `output`) to
 * make further progress, exactly like every other partial-write loop
 * already in this codebase (see e.g. magnus_handle_write()'s own
 * sendfile/file_buffer loops in magnus.c). `finish` marks the last
 * input chunk (the source is fully read) -- the compressor may still
 * need several more calls, each with `input_length` 0, to fully flush
 * its own internal buffers; `*done` becomes true only once the whole
 * stream is complete AND `output` from this same call already holds
 * everything left to send (the caller must still drain `*output_length`
 * bytes of `output` before treating the response as finished). Returns
 * false only on an unrecoverable encoder error (never on well-formed
 * input, same as every other compress function here) -- the caller has
 * no good fallback left at that point (unlike a failed one-shot
 * magnus_compress() call, response headers already went out with no
 * Content-Length, framed by the connection closing at the end; see
 * magnus_stream_compress_begin()'s own doc comment for the *earlier*,
 * still-recoverable failure case), and must abort the connection. */
bool magnus_stream_compress_step(magnus_stream_compressor_t *compressor,
                                 const unsigned char *input,
                                 size_t input_length, bool finish,
                                 size_t *input_consumed, unsigned char *output,
                                 size_t output_capacity,
                                 size_t *output_length, bool *done);

/* Releases a streaming compressor -- safe (a no-op) to call whether or
 * not the stream ever reached `*done`, since a client can disconnect
 * mid-stream at any point. */
void magnus_stream_compress_end(magnus_stream_compressor_t *compressor);

#endif
