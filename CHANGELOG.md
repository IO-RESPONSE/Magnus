# Changelog

## 1.47.0

### Fixed

- **A self-inflicted bug found while building this release's own
  streaming-compression feature: an HTTP/2 stream teardown could
  double-free, aborting the whole process with a heap-corruption
  error.** `magnus_h2_stream_free()`'s first draft freed the new
  `proxy_stream_compress_inbuf` staging buffer directly, then
  unconditionally freed it *again* a few lines later inside
  `magnus_h2_stream_teardown_upstream()` (which it always calls, and
  which already owns that field's cleanup -- the same way it already
  owns `compress_capture`/`cache_capture`'s own, both of which are
  correctly freed exactly once because that helper NULLs them
  afterward). Caught immediately: the very first live run of this
  release's own new HTTP/2 streaming-compression test block aborted
  with `corrupted size vs. prev_size while consolidating` -- a real
  glibc malloc heap-corruption check, not a sanitizer finding. Fixed
  by removing the redundant free from `magnus_h2_stream_free()`,
  relying entirely on `magnus_h2_stream_teardown_upstream()` to free
  and NULL the field exactly once. Verified: `make test` clean
  (twice), and direct ASan/UBSan testing of the live server (9+ HTTP/2
  requests across all three encodings, a `--next` connection-reuse
  check, and a plain-large-file regression check, zero findings).

### Added

- **Streaming proxy dispatch response compression, HTTP/2 (roadmap
  2a-11) -- the second protocol slice, following 2a-10's own HTTP/1.1
  one.** Confirms the same prediction 2a-8's own HTTP/2 static-file
  streaming compression already made: no close-delimited-framing
  workaround needed at all, since HTTP/2 never requires a
  Content-Length ahead of a DATA-frame response.

  Structurally different from 2a-8's own *pull*-based
  `nghttp2_data_provider2` `read_callback` (which fetches more input
  itself, on demand, via `pread()`, the moment nghttp2 wants to emit
  the next DATA frame): 2a-11's own input only ever arrives *pushed*,
  asynchronously, off the upstream socket -- exactly like 2a-10's own
  HTTP/1.1 relay, and unlike every other streaming path this codebase
  has so far. Rather than force a pull-based shape onto a push-driven
  data source, this adds a new push-driven fill function instead
  (`magnus_h2_proxy_stream_compress_response()`), called from
  `magnus_h2_handle_upstream()` on every upstream-readable event, in
  place of the plain relay's own `magnus_h2_proxy_stream_response()`.

  `struct magnus_h2_stream`'s own `io_buffer` -- already the pull
  buffer `magnus_h2_read_io_buffer()` drains for every other h2
  response this codebase produces, including the plain, uncompressed
  proxy relay -- is repurposed as the compressed *output* queue here
  too, so no new read callback was needed at all: the existing one
  already knows how to drain it, report `NGHTTP2_ERR_DEFERRED` while
  more is expected, and report EOF once `response_complete` is set.
  Raw, not-yet-compressed bytes `recv()` delivers get a new home
  instead, a dedicated `proxy_stream_compress_inbuf` staging buffer,
  since they can no longer share `io_buffer` with the compressed
  output. Response headers go out immediately (`Content-Encoding`/
  `Vary`, no `Content-Length`) the moment the upstream's own headers
  are known, via the same `(size_t) -2` sentinel 2a-10 added to
  `magnus_proxy_sanitize_response_headers()` -- `magnus_h2_proxy_
  submit_response()` already drops the `Connection` header that call
  would otherwise append regardless (forbidden in h2, RFC 9113 8.2.2),
  so unlike HTTP/1.1 there was no separate "force `Connection: close`"
  step needed here either.

  Verified: a 9 MB (well past the 8 MiB bound) upstream response
  compresses correctly via gzip/zstd/Brotli through a real live HTTP/2
  proxy fetch, byte-exact after decoding, with no `Content-Length`
  header present; a `--next` connection-reuse check confirms the
  connection survives a streamed proxy response and stays multiplexed
  afterward, exactly like 2a-8's own HTTP/2 static-file streaming test
  already proved for that case; `make test` (twice, including the
  pre-existing buffer-then-compress proxy dispatch regression block,
  unaffected) clean; a full Docker image rebuild plus live container
  verification (all three encodings, byte-exact, over real HTTP/2)
  clean.

## 1.46.0

### Added

- **Streaming proxy dispatch response compression, HTTP/1.1 (roadmap
  2a-10) -- the one remaining dimension of "streaming/chunked
  compression above 8 MiB" once 2a-7/2a-8/2a-9 covered every static-
  file case.** A `"/proxy"` response too large for 2a-2's own buffer-
  then-compress shape (past `MAGNUS_COMPRESSION_MAX_SIZE`) previously
  stayed uncompressed no matter what the client's `Accept-Encoding`
  offered; it now compresses incrementally as bytes arrive from the
  upstream fetch instead.

  Structurally different from every static-file streaming path this
  codebase already has: there is no file to `pread()` more of on
  demand the moment the write side wants it. Upstream body bytes only
  ever arrive pushed, asynchronously, by `magnus_handle_upstream()`'s
  own `recv()` off the upstream socket -- the same one the ordinary
  uncompressed relay already uses. Rather than add a dedicated input
  buffer, this reuses `proxy_buffer`/`proxy_buffer_length`/
  `proxy_buffer_sent` directly as the compressor's own pending-input
  queue (`proxy_buffer_sent` now plays "how much of the current chunk
  has been fed to the compressor" instead of "how much has been
  written to the client"), and `magnus_proxy_flush()`'s new streaming-
  compress block -- entered from both the upstream-read path and the
  client-writable path, exactly like its own header/body drain loops
  already are -- simply re-arms the upstream fd for reading and
  returns once it runs out of buffered input, rather than looping to
  fetch more itself the way a `pread()`-backed loop safely could.

  Unlike 2a-2's own buffer-then-compress path (which defers every
  client-visible byte until the whole body is known, so it can emit a
  real compressed `Content-Length`), nothing here is deferred: the
  real compressed length can never be known ahead of time for a
  streamed body any more than a streamed static file's own can, so
  response headers go out the moment the upstream's own headers are
  known, via a new `(size_t) -2` sentinel on
  `magnus_proxy_sanitize_response_headers()` that emits `Content-
  Encoding`/`Vary` but no `Content-Length`, and forces the client-
  facing `Connection` to "close" regardless of what the client asked
  for -- the same close-delimited-framing choice 2a-7's own HTTP/1.1
  static-file streaming compression already made, for the same reason
  (no `Transfer-Encoding: chunked` response writer exists in this
  codebase yet).

  `done` becoming true (the compressor has consumed every remaining
  buffered byte and fully flushed, per `magnus_stream_compress_step()`'s
  own contract, unchanged since 2a-7/8/9) tears the compressor down and
  marks the connection to close after the final chunk drains; a
  defensive zero-out of `proxy_buffer_length`/`_sent` at that point
  guards against ever relaying stale, would-be-raw bytes to the client
  if that contract were ever violated, even though nothing in this
  increment's own testing ever observed it be. HTTP/2 and HTTP/3 proxy
  dispatch streaming compression remain later increments -- see
  `src/magnus_quic.h`'s own "deliberately still not here" list.

  Verified: a 9 MB (well past the 8 MiB bound) upstream response
  compresses correctly via gzip/zstd/Brotli through a real live proxy
  fetch, byte-exact after decoding, with no `Content-Length` header and
  `Connection: close` present, and the server keeps answering normally
  right afterward; `make test` (twice, including the pre-existing
  buffer-then-compress proxy dispatch regression block, unaffected)
  and a full Docker image rebuild plus live container verification both
  clean.

## 1.45.0

### Fixed

- **A second real, previously-latent bug found while building this
  release's own streaming-compression feature: zstd- and Brotli-
  compressed HTTP/3 static files could hang outright.** `ZSTD_
  compressStream2()`'s own documentation states that `ZSTD_e_continue`
  "is guaranteed to make some forward progress... but doesn't
  guarantee maximal forward progress" -- it may legally consume input
  and produce *zero* output on a given call, buffering internally
  instead (`BrotliEncoderCompressStream()`'s `BROTLI_OPERATION_PROCESS`
  behaves the same way; zlib's `deflate()` does not have this property,
  which is exactly why gzip alone never exposed the bug). The h3
  `nghttp3_data_reader` callback this release's own 2a-9 streaming path
  first shipped called the streaming compressor exactly once per
  invocation and treated a zero-output result as "would block, wait to
  be resumed" -- but nghttp3's own resume mechanism has nothing to
  trigger it without a chunk ever having been offered in the first
  place, a genuine deadlock reproduced directly with both zstd and
  Brotli on any static file needing more than a trivial amount of
  compressed output. Fixed by looping inside the callback, feeding more
  input and re-calling the compressor, until a call actually produces
  output or the stream is genuinely done -- the same discipline every
  other streaming-compression write loop in this codebase already
  follows. Applied the identical fix to HTTP/2's own equivalent
  callback too: it never reproduced a hang in testing, but that turned
  out to rest on nghttp2's own eager retry timing rather than on any
  contract this codebase could actually rely on, so it now shares the
  same real guarantee instead of a codepath that merely never got
  caught. Verified: a file that previously timed out at 5+ seconds for
  both encoders now completes in under 250ms, byte-exact, across
  repeated trials; direct ASan/UBSan testing of the live server (9
  runs, all three encodings, zero findings) clean.

### Added

- **Streaming compression for HTTP/3 static files past the 8 MiB bound
  (roadmap 2a-9) -- the third and final static-file slice, following
  2a-7's own HTTP/1.1 one and 2a-8's own HTTP/2 one.** Like HTTP/2, no
  close-delimited-framing workaround was needed: HTTP/3 never requires
  a Content-Length ahead of a DATA-frame response either, so the
  stream simply ends on the frame carrying its own FIN once the
  streaming compressor reports done.

  Unlike HTTP/2 (where nghttp2 hands the read callback a reusable
  buffer to fill directly), HTTP/3's own `nghttp3_data_reader` contract
  is the strictest of the three: each offered chunk must be its own
  independent allocation, kept alive until the *peer has acknowledged*
  it, not merely until it was handed off -- the same ACK-gated
  discipline roadmap 2a-4's own HTTP/3 proxy-dispatch compression
  already established (`struct magnus_quic_stream_t`'s own
  `body_chunk`/`body_chunk_length`/`body_chunk_offered`/
  `body_chunk_end_offset`/`body_offered_total`/`body_acked_total`/
  `nghttp3_wants_resume` fields), reused directly here rather than
  duplicated: exactly one of `is_proxy` or a non-NULL `stream_compress`
  is ever true for a given stream, so both features can safely share
  one field set. `magnus_quic_http_acked_stream_data()` (the shared ack
  callback) was extended to free the in-flight chunk and resume the
  stream for this case too, alongside its existing proxy-dispatch
  logic. Unlike the mmap-based whole-file relay every other h3 static
  response uses, this path needed its own persistent file descriptor
  (`struct magnus_quic_stream_t` gained `file_fd`/`file_offset`) since
  it reads the source file in bounded chunks via `pread()` rather than
  mapping it all at once.

  `tests/quic-handshake-check.c` (the only way to exercise HTTP/3 at
  all in this project, absent HTTP/3 support in its own curl) had its
  fixed response-body buffer bumped from 1 MiB to 16 MiB so it can
  actually hold a whole well-past-8-MiB response for verification,
  rather than only ever proving the first 1 MiB decoded correctly.

  Verified: `make test` (twice) and direct ASan/UBSan testing of the
  live server (9 runs across all three encodings, zero findings) both
  clean; a 12 MB fixture streamed and decoded byte-exact over HTTP/3
  under gzip, zstd, and Brotli. New `tests/test-core.sh` blocks confirm
  byte-exact decode for all three encodings, that a plain request on
  the same oversized file stays on the unmodified relay with a real
  Content-Length, and that the server keeps answering ordinary requests
  normally right after. Docker image rebuilt and a live container
  tested directly.

## 1.44.0

### Fixed

- **A real, previously-latent data-corruption bug: `magnus_h2_drain_send()`
  could silently truncate any HTTP/2-over-TLS response large enough to
  hit a partial write mid-transfer.** Found while building this
  release's own 2a-8 streaming-compression feature (below), which was
  the first thing in this codebase's history to test HTTP/2 static-file
  serving against a fixture well past a few MB -- reproduced reliably
  (roughly 25-40% of attempts) against the *existing*, unmodified
  `magnus_h2_read_file()` plain relay once tested at that size, and
  never against a plain h2c connection with the same fixture.

  Root cause: when a write of nghttp2's own serialized output hit
  `SSL_ERROR_WANT_WRITE` partway through, the old code copied the
  *unsent remainder* into `connection->h2_output` for a later retry --
  but the *first* attempt had been made directly against nghttp2's own
  transient buffer (`nghttp2_session_mem_send2()`'s own pointer, valid
  only until the next `mem_send2`/`mem_recv2` call), never copied at
  all unless that first attempt already came up short. OpenSSL's own
  `SSL_write()` contract requires every retry of an interrupted write
  to use the *exact same buffer address* as the original attempt, not
  merely equal content, whenever `SSL_MODE_ENABLE_PARTIAL_WRITE` isn't
  set (this codebase's default, and OpenSSL's own). The retry via
  `h2_output` handed OpenSSL a *different* address than whatever the
  first attempt saw -- undefined behavior per OpenSSL's own
  documentation, not merely untested territory. Harmless for any
  response small enough to always write fully on the first attempt (no
  retry ever happens, which is why nothing before now ever caught it);
  silently truncated once a large enough transfer actually hit a
  partial write, with the exact cutoff point entirely dependent on how
  fast the peer happened to be draining its own receive buffer at that
  moment -- exactly the shape of bug that stays invisible until
  something exercises a response that large.

  Fixed by copying nghttp2's chunk into `connection->h2_output`
  unconditionally, *before* any write is ever attempted against it --
  every actual write, first attempt or later retry, now goes through
  `magnus_h2_flush_output()`'s own already-correct fixed-address retry
  loop, the same one every other multi-attempt write in this codebase
  already relies on. This is not static-file-specific: `magnus_h2_drain_send()`
  is the shared send path under *every* HTTP/2 response this codebase
  produces (static files, proxy dispatch, gRPC, `/healthz`/`/metrics`,
  all of it), so any of them could have silently truncated a large
  enough response over TLS before this fix, not just static files.

  Verified: 15 consecutive live requests for a 12 MB file over
  HTTP/2+TLS, byte-exact every time (previously ~25-40% truncated);
  `make test` (twice) and direct ASan/UBSan testing of the live server
  (5 runs, zero findings) both clean.

### Added

- **Streaming compression for HTTP/2 static files past the 8 MiB bound
  (roadmap 2a-8) -- the second slice of "streaming/chunked compression
  above 8 MiB", following 2a-7's own HTTP/1.1 slice.** Confirms that
  increment's own prediction: HTTP/2 needed none of HTTP/1.1's close-
  delimited-framing workaround, since no protocol requires a
  Content-Length ahead of a DATA-frame response -- the stream simply
  ends on the frame carrying `END_STREAM`, decided by a new pull-based
  `nghttp2_data_provider2` callback (`magnus_h2_read_stream_compressed()`)
  reporting `NGHTTP2_DATA_FLAG_EOF` once the streaming compressor
  (`src/magnus_compression.h`'s own 2a-7 API) reports done. Unlike
  HTTP/1.1's own write loop, no separate output staging buffer was
  needed either: nghttp2 already hands the callback a buffer to fill
  directly on every pull. A streamed response therefore keeps the
  connection alive and multiplexed afterward exactly like any other --
  verified directly via a second, ordinary request sent right after a
  streamed one on the same connection.

  `struct magnus_h2_stream` gained a dedicated input-staging buffer for
  this path (mirroring `magnus_connection_t`'s own 2a-7 fields), but
  safely reuses the stream's existing `file_fd`/`file_offset`/
  `file_length` fields for the raw source file -- unlike HTTP/1.1's
  connection struct, exactly one `nghttp2_data_provider2` callback is
  ever registered per stream, so there is no risk of two different
  consumers racing over the same fields the way the connection
  struct's own unconditional per-tick sendfile/pread loops made a
  dedicated field set necessary there.

  Verified: `make test` (twice) and direct ASan/UBSan testing of the
  live server (multiple runs, all three encodings, zero findings) both
  clean; a real 12 MB fixture streamed and decoded byte-exact over
  HTTP/2 under gzip, zstd, and Brotli. New `tests/test-core.sh` blocks
  confirm byte-exact decode with no `Content-Length` for all three
  encodings, that plain and `HEAD` requests on the same oversized file
  stay on the unmodified relay, and that the connection survives a
  streamed response to serve a second, ordinary request right after.
  Docker image rebuilt and a live container tested directly.

## 1.43.0

### Added

- **Streaming compression for HTTP/1.1 static files past
  `MAGNUS_COMPRESSION_MAX_SIZE` (roadmap 2a-7) -- the first slice of
  the "streaming/chunked compression above 8 MiB" item every prior
  compression increment (2a through 2a-6) has deferred.** Until now, a
  static file larger than 8 MiB always relayed uncompressed regardless
  of what the client's `Accept-Encoding` offered -- `magnus_compress_
  static()`'s own buffer-then-compress shape (hold the whole body,
  compressed *and* uncompressed, in memory at once) simply refuses
  anything past that bound, by design, to keep memory use predictable.
  A GET for an eligible file above the bound now streams instead:
  compresses the file in 64 KiB chunks as it reads them, using each
  encoder's own incremental/streaming API rather than the one-shot
  functions every other compression path here uses (`deflate()` with
  `Z_NO_FLUSH`/`Z_FINISH` per chunk for gzip, `ZSTD_compressStream2()`
  for zstd, `BrotliEncoderCompressStream()` for Brotli), and writes
  each produced chunk to the client as it becomes available.

  No `Content-Length` can ever be known ahead of time here -- the
  actual reason this needed its own response-framing decision, not
  just a different body-writing loop, unlike every other compression
  path in this codebase. RFC 9112 6.3 permits a response with neither
  `Content-Length` nor `Transfer-Encoding: chunked` as long as the
  connection closes once the body ends; that's the framing this
  increment chose (`Connection: close` plus the existing
  `close_after_write` mechanism), deliberately narrower than building
  this codebase's first `Transfer-Encoding: chunked` response writer --
  the same "narrow the first cut" pattern established throughout
  roadmap 2a, this time trading keep-alive for these specific
  responses away rather than a new framing mechanism. A real chunked
  writer (recovering keep-alive) remains a later increment, along with
  HTTP/2 and HTTP/3 (neither actually needs the close-delimited-framing
  workaround at all -- no protocol requires a Content-Length ahead of
  a DATA-frame response) and proxy dispatch on all three protocols.

  `src/magnus_compression.h/.c` gained a small opaque streaming API
  (`magnus_stream_compressor_t`, `magnus_stream_compress_begin()`/
  `_step()`/`_end()`) sitting alongside the existing one-shot
  `magnus_compress()` -- verified against a standalone sanity harness
  first (18 combinations: all three encodings, input sizes from 0 to 10
  MiB, and deliberately tiny 37-byte output buffers forcing many
  partial-drain iterations, the exact shape the real event-loop caller
  needs to handle) before ever being wired into magnus.c, under
  ASan/UBSan. `struct magnus_connection_t` gained its own dedicated
  fd/buffer set for this path (`stream_compress_fd` et al.) rather than
  reusing `file_fd`/`file_buffer`, so the existing, already-verified
  sendfile/pread relay loops never needed their own guard conditions
  touched.

  One real, previously-latent bug found and fixed along the way, not
  new to this increment: `magnus_close_connection()` never called
  `SSL_shutdown()` before closing a TLS connection's raw fd. Every
  existing `close_after_write`-over-TLS response before this one always
  had a `Content-Length` (or was HTTP/1.0, which stops reading at
  `Content-Length` without ever attempting the read that would expose
  the gap), so a client never needed to detect "body complete" purely
  by watching for the TLS connection to close -- this increment's own
  responses are the first ones that do, and a strict TLS 1.3 client
  (confirmed against this host's own curl/OpenSSL) reported
  `SSL_ERROR_SYSCALL`/"errno 0" on the abrupt close, even though every
  byte it had already read was byte-for-byte correct: an unexpected-EOF
  false alarm, not a real transport error. Fixed with one best-effort,
  non-blocking `SSL_shutdown()` call before `close(fd)` -- OpenSSL's
  own manual documents exactly this "call once, don't wait for the
  peer's own close_notify back" usage as legitimate for a server that
  is simply done with a connection, matching every other
  `close_after_write` path's own now-correct behavior, not just this
  new one's.

  Verified: `make test` (twice) and `make sanitize` (ASan/UBSan) both
  clean; a real 12 MB fixture streamed and decoded byte-exact under
  gzip, zstd, and Brotli, over both plain and TLS HTTP/1.1, manually
  before writing the automated coverage. New `tests/test-core.sh`
  blocks confirm: byte-exact decode for all three encodings with no
  `Content-Length` and `Connection: close`; a plain request (no
  `Accept-Encoding`) and a `HEAD` on the same oversized file both still
  get the unmodified, unaffected uncompressed relay with a real
  `Content-Length` and `keep-alive`, proving this increment changed
  nothing about either of those existing paths. Docker image rebuilt
  and a live container tested directly.

## 1.42.0

### Added

- **Brotli as a third negotiable compression encoding (roadmap 2a-6),
  joining gzip and zstd -- across both static-file and proxy-dispatch
  compression, on all three protocols, closing out the deferral 2a-5
  left open.** `magnus_negotiate_encoding()`'s preference order becomes
  zstd > Brotli > gzip: benchmarked, not assumed. A ~230 KB and a
  ~4.6 MB HTML-shaped fixture (the same repeated-line shape `tests/
  test-core.sh`'s own compression blocks use) were compressed at every
  Brotli quality level from 1 to 11 and compared against gzip -9 and
  zstd's own default level. Quality 4 held to single-digit-to-low-
  double-digit milliseconds on both fixtures -- the same ballpark as
  gzip and zstd -- while beating gzip's ratio by roughly 2x on both;
  quality 9 and above cost 2-3x the time for a mixed (sometimes worse,
  on the larger fixture) ratio, and the library's own default quality
  11 took over 20x longer than quality 4 on the smaller fixture alone.
  `MAGNUS_BROTLI_QUALITY` (`src/magnus_compression.c`) is therefore 4:
  the fastest quality that still clearly beats gzip, not the single
  best ratio Brotli can produce -- the same "fast end of the range, not
  the library default" reasoning `magnus_zstd_compress()` already
  established in 2a-5. zstd still wins first place: it edged out
  Brotli on ratio on the larger of the two fixtures at a comparable
  speed, so a client offering both still gets zstd; a client offering
  only Brotli and gzip gets Brotli, since it still clearly beats gzip
  at that same speed budget.

  Unlike zstd (2a-5), Brotli's runtime libraries were *not* already
  present in the image -- `libbrotlienc.so.1`/`libbrotlicommon.so.1`
  are new `cp -L` lines in the Dockerfile's runtime stage (confirmed via
  `ldd` that `libbrotlienc.so.1` depends only on `libbrotlicommon.so.1`,
  never on the decoder, so `libbrotlidec.so.1` -- Magnus only ever
  compresses, never decompresses, a response body -- is correctly left
  out); the builder stage gained `libbrotli-dev`. `LDLIBS` gained
  `-lbrotlienc -lbrotlicommon`, both explicit per this codebase's own
  established convention (`-lssl -lcrypto` already lists both sides of
  an equivalent transitive dependency rather than relying on implicit
  resolution).

  `magnus_encoding_t` gained `MAGNUS_ENCODING_BROTLI`; `magnus_encoding_
  name()` returns `"br"` for it -- the actual IANA-registered Content-
  Encoding token (RFC 7932), not `"brotli"`. A new `magnus_brotli_
  compress()` (`BrotliEncoderCompress()`/`BrotliEncoderMaxCompressedSize()`,
  the same one-shot shape `magnus_gzip_compress()`/`magnus_zstd_
  compress()` already have) sits alongside them. With three compress
  functions now behind `magnus_negotiate_encoding()`'s result, every
  call site that used to hand-roll a two-way `encoding == MAGNUS_
  ENCODING_ZSTD ? zstd(...) : gzip(...)` ternary (there are five: each
  protocol's own proxy-dispatch `finish_compression()`, plus `magnus_
  compress_static()` and its h3 analogue) was replaced with a single
  shared dispatcher, `magnus_compress(encoding, ...)`, rather than
  growing five near-identical three-way branches.

  One test regression found and fixed, not a code bug: several `tests/
  test-core.sh` blocks used curl's `--compressed` flag to prove gzip
  negotiation worked, relying on libcurl to both send `Accept-Encoding`
  and transparently decompress the response for a byte-exact `cmp`.
  This host's own curl was built with Brotli support (confirmed via
  `curl --version`), so `--compressed` now offers `br` too -- and
  magnus correctly starts preferring it over gzip, which is exactly the
  new behavior this increment intends, but broke the *old* assertion
  that the response would still be gzip. Fixed by switching those
  blocks to an explicit `-H 'Accept-Encoding: gzip'` (decoded manually
  via the `gzip` CLI, the same shape the zstd blocks already used since
  neither zstd nor Brotli get transparent libcurl decompression without
  `--compressed`) for the gzip-specific assertions, and adding new,
  dedicated Brotli blocks that use `--compressed` deliberately -- now
  as live confirmation that a real, unmodified client actually gets
  Brotli back, not despite it.

  Verified: `make test` (twice) and `make sanitize` (ASan/UBSan) both
  clean; `tests/test-compression.c` gained `brotli_round_trip()` (the
  Brotli analogue of the existing `gzip_round_trip()`/`zstd_round_
  trip()`) plus negotiation assertions covering Brotli alone, its
  preference position relative to both other encodings in every
  offered order, and that `"brotli"` itself (not a valid Accept-
  Encoding token) does not match; `tests/fuzz-compression.c`'s seed
  corpus gained Brotli-shaped entries. `tests/test-proxy.c`'s
  `compressed_content_encoding` coverage now includes a `"br"` case.
  New `tests/test-core.sh` blocks (static-file and proxy-dispatch, all
  three protocols) confirm `Accept-Encoding: br` gets back a byte-exact
  `brotli`-decodable body with `Content-Encoding: br`/`Vary: Accept-
  Encoding`, that Brotli beats gzip but loses to zstd in preference
  regardless of offered order, and (via `--compressed`) that this
  host's real curl actually receives and decodes it --
  `tests/quic-handshake-check.c`'s `[gzip|zstd|br|-]` argument (extended
  from 2a-5's own `[gzip|zstd|-]`) drives the HTTP/3 cases. Docker image
  rebuilt and a live container tested directly across all three
  protocols, static and proxied alike.

## 1.41.0

### Added

- **zstd as a second negotiable compression encoding (roadmap 2a-5),
  joining gzip -- across both static-file and proxy-dispatch
  compression, on all three protocols at once.** Unlike 2a-2/2a-3/2a-4
  (each shipped one protocol at a time), this increment is genuinely
  cross-cutting from the start: every place that used to call the old
  gzip-only API now negotiates between gzip and zstd identically,
  whether serving an mmap'd static file or a live upstream proxy
  response, over HTTP/1.1, HTTP/2, or HTTP/3.

  zstd was chosen over Brotli for this increment on two concrete,
  evidence-based grounds, not an arbitrary preference: (a)
  `libzstd.so.1` was *already* being copied into the runtime image
  (`Dockerfile`'s own pre-existing `cp -L .../libzstd.so.1` line), a
  transitive dependency of OpenSSL 3.5+ that no Magnus code had ever
  actually called -- so zstd support adds zero new runtime library
  footprint, whereas Brotli would need two new `.so` files
  (`libbrotlienc`, `libbrotlicommon`) bundled in; (b) zstd's default
  compression level (`ZSTD_CLEVEL_DEFAULT` = 3) is fast, well-suited to
  this codebase's "compress fresh on every qualifying request, never
  cached compressed" design, unlike Brotli's default quality 11 (tuned
  for precomputed static assets, too slow for on-the-fly per-request
  compression of bodies up to 8 MiB). Brotli remains a separate, later,
  well-documented increment -- the same "narrow the first cut, extend
  later" pattern this codebase has used for every prior sub-phase.

  The old boolean `magnus_accepts_gzip()` (`src/magnus_compression.h`)
  became `magnus_negotiate_encoding()`, returning a new
  `magnus_encoding_t` (`MAGNUS_ENCODING_NONE`/`_GZIP`/`_ZSTD`, `NONE`
  always `0` so `!= MAGNUS_ENCODING_NONE` reads as the exact same
  eligibility check every caller already had) -- zstd is preferred
  whenever a client's `Accept-Encoding` offers both, in either order.
  RFC 9110 q-value exclusion (e.g. `gzip;q=0`) stays deliberately
  unhonored, matching the old function's own already-established
  behavior -- confirmed via a pre-existing unit test asserting
  `magnus_accepts_gzip("GZip;q=0")` was true -- rather than a new,
  silent correctness gap; RFC 9110 12.5.3 permits any server policy
  that excludes q=0, and this remains a documented simplification. A
  new `magnus_zstd_compress()` (`ZSTD_compress()`/`ZSTD_compressBound()`,
  the same one-shot shape `magnus_gzip_compress()` already has) sits
  alongside the existing `magnus_gzip_compress()`.

  `magnus_proxy_sanitize_response_headers()` (the shared h1/h2/h3
  response header rewriter) gained a `compressed_content_encoding`
  parameter immediately after its existing `compressed_content_length`
  override -- unused when that length is `(size_t) -1` (no
  compression), required otherwise -- so the one shared `Content-
  Encoding: %s` emission site can name whichever encoding was actually
  negotiated instead of a hardcoded `"gzip"`. Each protocol's own
  proxy-dispatch eligibility/finish-compression pair (h1's
  `connection->proxy_accept_encoding`/`proxy_compress_encoding`, h2's
  and h3's own per-stream `compress_encoding`) was migrated the same
  way; `magnus_compress_static()` (h1/h2 shared) and h3's own
  `magnus_quic_compress_static()` now return the negotiated
  `magnus_encoding_t` instead of a plain bool, for the same reason.

  Verified: `make test` (twice) and `make sanitize` (ASan/UBSan) both
  clean; `tests/test-compression.c` gained `zstd_round_trip()` (the
  zstd analogue of the existing `gzip_round_trip()`) plus negotiation
  assertions covering zstd alone, zstd-preferred-over-gzip in both
  offer orders, and the unchanged q-value/absent-header/no-match cases;
  `tests/fuzz-compression.c`'s seed corpus gained zstd-shaped entries.
  `tests/test-proxy.c`'s `compressed_content_encoding` coverage now
  includes a `"zstd"` case alongside the existing `"gzip"` one. New
  `tests/test-core.sh` blocks (static-file and proxy-dispatch, all
  three protocols) confirm `Accept-Encoding: zstd` gets back a
  byte-exact `zstd`-decodable body with `Content-Encoding: zstd`/
  `Vary: Accept-Encoding`, and that offering `gzip, zstd` together
  always prefers zstd -- `tests/quic-handshake-check.c`'s own
  `[gzip|zstd|-]` argument (previously gzip-only) drives the HTTP/3
  cases. Docker image rebuilt (`libzstd-dev` added to the builder
  stage; the runtime stage needed no change, `libzstd.so.1` was already
  copied) and a live container tested directly across all three
  protocols, static and proxied alike.

## 1.40.0

### Added

- **Real IP for HTTP/3 (roadmap 2b, extended here): `source_cidr` route
  matching and client-IP-based cluster selection (4h's own fallback
  when no sticky affinity cookie applies) now resolve a trusted-proxy-
  forwarded Forwarded/X-Forwarded-For address over QUIC exactly like
  HTTP/1.1 and HTTP/2 already do.** Turned out to need no new QUIC-
  specific mechanism at all: `magnus_realip_resolve_headers()` operates
  purely on already-parsed HTTP header fields, and HTTP/3's own headers
  are just as parseable as HTTP/1.1's -- the only genuinely QUIC-
  incompatible piece is PROXY protocol v1/v2 (no raw preamble concept
  once ngtcp2/nghttp3 have already framed a stream's headers), which
  stays correctly out of scope and is now the *only* remaining item in
  `src/magnus_quic.h`'s own "deliberately still not here" list under
  this heading.

  `magnus_quic_stream_t` gained `effective_client_address`, the h3
  analogue of `struct magnus_h2_stream`'s own identically-named field:
  a *per-stream* value (never `connection->remote_addr` itself, which
  a concurrently dispatching sibling stream on the same QUIC connection
  could be reading at the same instant -- the same multiplexing
  concern h2 already had and HTTP/1.1 never does), resolved once in
  `magnus_quic_http_dispatch()` and read from there by both
  `source_cidr` route matching and `magnus_quic_proxy_start()`'s own
  client-IP-based endpoint selection, rather than each recomputing the
  raw QUIC peer address independently and risking an inconsistent
  answer between the two. Trust is always decided against the
  connection's actual raw peer address, never against an already-
  resolved value, matching `magnus_h2_dispatch()`'s own identical
  anti-forgery reasoning.

  `magnus_trusted_proxies[]`/`magnus_trusted_proxy_count` (magnus.c)
  are no longer `static`, exposed via `src/magnus_static.h` the same
  way `magnus_routes[]`/`magnus_route_count` already are -- config
  state magnus.c owns and populates once at startup, read (never
  written) by magnus_quic.c's dispatch. `magnus_realip_is_trusted()`/
  `magnus_realip_resolve_headers()` themselves needed no changes at
  all: magnus_quic.c now simply `#include`s `magnus_realip.h` directly
  and calls them, the same way h1/h2 already do.

  `tests/quic-handshake-check.c` gained X-Forwarded-For support (a new
  trailing positional argument, matching the tool's own existing
  "`-` sentinel means absent" convention already established for
  cookie/migrate), needed to actually exercise this over QUIC at all
  -- no prior mechanism in the tool could set an arbitrary request
  header.

  Verified: `make test` (twice) and `make sanitize` (ASan/UBSan) both
  clean; a new `tests/test-core.sh` block (config-file mode, matching
  the HTTP/1.1 Real IP block's own precedent of proving the config key
  itself, not just a CLI-flag equivalent) confirms a trusted peer's
  `X-Forwarded-For` making a `source_cidr`-denied address reachable/
  unreachable over QUIC, and that no header at all falls back to
  routing against the raw QUIC peer address correctly. Docker image
  rebuilt and a live container tested directly -- the same deny/allow
  behavior confirmed against the running container, not just the host
  binary.

## 1.39.0

### Added

- **Proxy dispatch response compression, HTTP/3 (roadmap 2a-4): the
  third and final protocol, closing out roadmap 2a's own cross-protocol
  compression story -- every one of h1/h2/h3's own `"/proxy"` dispatch
  now negotiates gzip identically.** Same deferred-submission-until-
  compressed shape as HTTP/1.1 (2a-2) and HTTP/2 (2a-3), adapted to
  nghttp3's own frame-based, pull-driven response model:
  `nghttp3_conn_submit_response()` (previously unconditional, the
  moment upstream headers arrived) is now deferred behind a new
  `stream->compress_pending`, exactly like HTTP/2's `submit_response2()`
  already is.

  Unlike HTTP/2's `stream->io_buffer` (a generically reassignable heap
  pointer reused directly for the compressed body), HTTP/3's own
  `stream->body_chunk` could not be reused the same way: it is a
  single, ACK-gated, one-shot-per-network-chunk allocation by design
  (roadmap 4b's own hard-won lesson -- reusing one buffer there once
  corrupted a real streamed response under genuine QUIC flow-control
  backpressure, reproduced with a 220 KB response through a small
  stream window). A new dedicated `stream->compress_capture` growable
  buffer (mirroring `magnus_h2_proxy_compress_capture()`/
  `magnus_proxy_compress_capture()`) accumulates the body instead; only
  once compression completes does the result become a single fresh
  `body_chunk` allocation, entering that field's own existing
  ACK-gated-free lifecycle completely unchanged.

  Applying the exact bug 1.38.0's own HTTP/2 increment found and fixed
  as a lesson learned rather than repeating it: `magnus_quic_proxy_
  compress_capture()` was wired into *both* call sites from the start
  -- the header-arrival leftover chunk in `magnus_quic_proxy_receive_
  headers()`, and every subsequent chunk `magnus_quic_proxy_stream_
  response()` reads from the upstream socket -- so this increment's own
  manual verification (a response whose headers and body arrived
  separately, the exact scenario that exposed 1.38.0's own gap) passed
  correctly on the first attempt.

  Verified: `make test` (twice) and `make sanitize` (ASan/UBSan) both
  clean; a new `tests/test-core.sh` block (reusing the h1/h2 block's
  own `compress_proxy_root` fixture files rather than recreating them)
  fetches `page.html` through `"/proxy"` over QUIC with and without
  `gzip`, confirming the decompressed body matches the original
  byte-for-byte and the plain body relays unchanged, plus confirms
  `image.png` (non-compressible content-type) and `tiny.html` (under
  the 256-byte floor) both stay uncompressed even when gzip is
  requested. Docker image rebuilt and a live container tested directly
  -- an HTTP/3 proxy request decompresses byte-for-byte identical to
  the original, and a plain HTTP/3 proxy request relays the
  uncompressed body unchanged.

  With this, `src/magnus_quic.h`'s own "deliberately still not here"
  list drops proxied-response compression entirely -- the remaining
  compression-related gaps (Brotli/zstd, streaming/chunked compression
  above the 8 MiB bound) are now genuinely cross-cutting across all
  three protocols, not QUIC-specific.

## 1.38.0

### Added

- **Proxy dispatch response compression, HTTP/2 (roadmap 2a-3):
  extends 1.37.0's own HTTP/1.1 increment to the second protocol,
  reusing the exact same `magnus_proxy_sanitize_response_headers()`
  `compressed_content_length` override -- deferred-submission-until-
  compressed shape as HTTP/1.1, adapted to h2's own frame-based,
  pull-driven response model instead of a push write loop.** h2 never
  submits a `HEADERS` frame the moment upstream headers arrive the way
  it always used to (`magnus_h2_proxy_submit_response()`, previously
  unconditional): a new `stream->compress_pending` flag defers that
  call -- along with the `nghttp2_data_provider2` it registers -- until
  `magnus_h2_proxy_finish_compression()` (the h2 analogue of
  `magnus_proxy_finish_compression()`) has compressed the full body and
  re-sanitized the raw header block a second time.

  No dedicated compressed-body field was needed the way HTTP/1.1's own
  fixed 16 KiB `proxy_buffer` required a new `proxy_compressed_body`:
  `stream->io_buffer` is already a generically reassignable heap
  pointer, reused directly for the compressed output the exact same way
  the *static-file* h2 compression path (`magnus_h2_dispatch_static()`,
  part of 2a's own first increment) already does. No `proxy_accept_gzip`
  field either: `stream->parsed` (h2's own persistent per-stream copy of
  the client's request, unlike HTTP/1.1's stack-local one) is read
  directly at header-arrival time instead. A new `magnus_h2_proxy_
  compress_capture()` (mirroring `magnus_proxy_compress_capture()`) is
  called from *two* sites -- the header-arrival leftover chunk in
  `magnus_h2_proxy_receive_headers()`, and every subsequent chunk
  `magnus_h2_proxy_stream_response()` reads from the upstream socket --
  the second of which was the one real bug this increment found: an
  initial implementation only redirected the header-arrival leftover
  into the capture buffer and forgot the second site, so a response
  whose headers and body arrived as two separate reads (routine, not an
  edge case) silently compressed zero captured bytes into a valid but
  empty gzip stream instead of the real body. Caught by decoding the
  compressed response and diff'ing against the original during manual
  verification, not by code review.

  Verified: `make test` (twice) and `make sanitize` (ASan/UBSan) both
  clean; the existing `tests/test-core.sh` proxy-compression block
  (from 1.37.0) now loops `--http1.1`/`--http2` against one TLS-enabled
  instance, the same `for protocol in ...` shape the static-file
  compression block above it already uses, so both protocols' plain,
  gzip, non-compressible-content-type, and under-the-floor-size cases
  are all exercised identically. Docker image rebuilt and a live
  container tested directly -- an HTTP/2 proxy request decompresses
  byte-for-byte identical to the original, and a plain HTTP/2 proxy
  request (no `Accept-Encoding`) relays the uncompressed body unchanged.

## 1.37.0

### Added

- **Proxy dispatch response compression, HTTP/1.1 (roadmap 2a-2): a
  `"/proxy"` (or route-matched `action=proxy`) response now negotiates
  gzip the same way static-file serving already has since 2a --
  `Accept-Encoding: gzip`, a compressible `Content-Type`, and a body
  within the same 256-byte..8-MiB window `magnus_compress_static()`
  already uses -- except the body has to be fetched from a live
  upstream first, not read from an mmap'd file.** Unlike every earlier
  Phase 2/4 proxy-dispatch feature this session shipped (pooling,
  caching, affinity, retry), this one genuinely changes the relay's own
  timing, not just its side bookkeeping: the *entire* upstream body must
  be captured and compressed before anything about the response reaches
  the client, so a new `proxy_compress_pending` flag gates
  `magnus_handle_upstream()`'s recv loop and `magnus_proxy_flush()`'s
  own write loops directly rather than running alongside them the way
  `cache_capture`'s pure side-observation does.

  `magnus_proxy_sanitize_response_headers()` (the shared, cross-protocol
  header rewriter h1/h2/h3 proxy dispatch all already use) gained a
  `compressed_content_length` parameter: `(size_t) -1` for every
  existing caller (h1's own two other call sites, h2, h3 -- unaffected,
  still just relaying whatever the upstream declared, as before), any
  other value to drop the upstream's own verbatim `Content-Length` line
  and instead emit the real compressed length plus `Content-Encoding:
  gzip` and a `Vary: Accept-Encoding` line. The calling shape is:
  sanitize once, normally, to learn the *uncompressed* framing/content-
  type and decide whether to even attempt compression; buffer the body
  separately (`magnus_proxy_compress_capture()`, the same growable-
  doubling shape `magnus_proxy_cache_capture()` already has); then
  sanitize a *second* time, on a fresh copy of the same raw upstream
  header block (stashed in the new `proxy_compress_raw_headers`, since
  the first sanitize call tokenizes its own scratch copy in place), once
  the real compressed length is known
  (`magnus_proxy_finish_compression()`, called from
  `magnus_proxy_flush()`'s own "response complete" branch the moment the
  full body is captured). `magnus_gzip_compress()` only ever fails on an
  allocation failure (never on well-formed input), so that one case
  falls back to relaying the captured bytes uncompressed rather than
  losing the response outright -- ownership of the capture buffer
  transfers straight into the new `proxy_compressed_body` field (a
  dynamically-sized heap buffer `magnus_proxy_flush()`'s second write
  loop now sends from instead of the fixed 16 KiB `proxy_buffer`
  whenever non-NULL, since a compressed body can be up to 8 MiB) with no
  extra copy.

  A response the upstream *already* sent with its own `Content-Encoding`
  is never compressed a second time (`magnus_proxy_response_info_t`
  gained `content_type`/`has_content_encoding`, captured the same
  "already walking every header anyway" way `cache_control`/`vary`/etc.
  already are). A cached response is still never compressed on serve
  (unchanged from 4i's own explicit "reuses whatever the origin itself
  sent" choice) -- `cache_capture` and `proxy_compress_capture` are
  entirely independent buffers fed from the identical raw bytes, so
  caching and compression coexist for the same response without either
  affecting the other.

  Every other proxy-dispatch feature this session shipped keeps working
  unmodified alongside compression: `complete_by_length`/
  `proxy_upstream_poolable` are computed once, at header time, from the
  *uncompressed* response and never touched by anything compression
  does, so pool-checkin/teardown, cache storage, and session affinity
  all reach exactly the decision they always would have.

  HTTP/2 and HTTP/3 proxy dispatch remain on the ordinary uncompressed
  relay for now -- the same "narrow the first cut, extend later"
  pattern every earlier Phase 2/4 feature in this codebase has already
  used once; see `src/magnus_quic.h`'s own deferred-items list.

  Verified: `make test` (twice) and `make sanitize` (ASan/UBSan) both
  clean; a dedicated `tests/test-core.sh` block fetches a real,
  compressible file through `"/proxy"` with and without
  `Accept-Encoding: gzip` and confirms the decompressed body matches the
  original byte-for-byte, confirms a non-compressible content-type
  (`image/png`) and a body under the 256-byte floor both stay
  uncompressed even when the client offers gzip, and `tests/test-proxy.c`
  gained direct unit coverage of the new `compressed_content_length`
  parameter (exactly one `Content-Length` line, never two; `Content-
  Encoding`/`Vary: Accept-Encoding` added; an upstream's own unrelated
  `Vary` value passes through independently, not merged). Docker image
  rebuilt and a live container tested directly (not just the host
  binary) -- both the compressed and plain proxied responses confirmed
  byte-for-byte correct against the running container.

## 1.36.0

### Added

- **QUIC connection migration / reactive server-side path validation
  (roadmap Phase 4l, RFC 9000 9.3): magnus now correctly notices and
  validates a client's mid-connection address change (NAT rebinding,
  or a genuine client-initiated migration) instead of being unable to
  see it happen at all.** The bug this closes: `magnus_quic_listener_
  service()`'s existing-connection read path was feeding
  `ngtcp2_conn_read_pkt()` the *connection*'s last-known
  `local_addr`/`remote_addr` on every packet, rather than the specific
  packet's own just-received `recvfrom()` address -- meaning ngtcp2
  itself could never observe a path change in the first place,
  regardless of what actually arrived on the wire. Fixed by feeding
  the real, per-packet received addresses instead (a no-op in the
  common, non-migrating case, where the two happen to be identical).
  This alone was not sufficient, though: `magnus_quic_path_validation()`
  (new; wired via `callbacks.path_validation`) initially observed every
  attempted validation *failing*, traced -- via a from-scratch,
  packet-level investigation (`tcpdump` on loopback, plus temporary
  trace instrumentation on both ends, since removed) -- to
  ngtcp2's own documented contract: "only client can initiate
  migration". A client whose local socket changes without an explicit
  `ngtcp2_conn_initiate_migration()` call has its *own* incoming data
  on the new path silently decoded-but-discarded by ngtcp2 (no error,
  no callback, no visible symptom beyond the response simply never
  arriving) until it registers the change itself. `callbacks.
  get_path_challenge_data` (already required and already wired since
  4a) turned out to be all the *server* side ever needed -- no new
  server callback beyond `path_validation` itself was required for the
  reactive/passive server behavior this increment targets.

  A new lifetime counter, `magnus_quic_migration_total` (`/metrics`,
  the same shared `magnus_build_metrics()` every protocol already
  reports through), increments once per successful path validation.
  `tests/quic-handshake-check.c` gained a permanent `migrate` mode
  (its own `submit_request()`/`run_event_loop()` helpers factored out
  of what was previously inline-only-once code, so a second,
  independent HTTP/3 request can be submitted and awaited after
  rebinding to a fresh local UDP port and calling
  `ngtcp2_conn_initiate_migration()` on the same connection) --
  `tests/test-core.sh` gained a dedicated Phase 4l block using it: the
  counter reads 0 against a fresh instance, and increases once a
  migrated request completes, read back over HTTP/1.1 to prove it is
  one shared counter, not a QUIC-only one -- the same proof shape 4k's
  own block already established for its own counter.

  Deliberately out of scope still: 0-RTT, and active/preferred-address
  migration triggers a client might initiate for its own reasons other
  than reacting to a changed local address -- this increment is
  specifically the *server*'s own reactive/passive validation of
  whatever path a client's packets are actually observed arriving
  from, the RFC 9000 9.3 mechanism every server-side QUIC stack needs
  regardless of why a client's address changed.

  Verified: `make test` (twice) and `make sanitize` (ASan/UBSan) both
  clean; the Docker image rebuilt against the pinned ngtcp2 v1.19.0 and
  a live container tested directly (not just the host binary) --
  `quic-handshake-check --migrate` completing a full post-migration
  HTTP/3 request/response against the running container, with
  `magnus_quic_migration_total` incrementing to confirm it. Size
  unchanged in kind from 1.35.0 (no new runtime dependency).

## 1.35.0

### Added

- **QUIC retry-based stateless address validation (roadmap Phase 4k,
  RFC 9000 8.1.2): a client's first `Initial` packet on a fresh
  connection now must prove it can actually receive traffic at its
  claimed source address before magnus allocates any real connection
  state for it.** An `Initial` that arrives with no token gets a
  `Retry` packet back instead (`magnus_quic_send_retry()`, new): a
  fresh server-chosen connection ID plus a short-lived, authenticated
  token binding the client's address and its original destination
  connection ID (`ngtcp2_crypto_generate_retry_token()`, keyed off the
  same process-lifetime `magnus_quic_static_secret` roadmap 4a already
  generates once at startup for stateless-reset tokens -- one secret
  serving both purposes, matching common reference-implementation
  practice; a process restart simply invalidates any in-flight retry
  tokens, forcing an affected client to retry the connection from
  scratch, an acceptable minor inconvenience, not a correctness bug).
  Only once the client resends its `Initial` *with* that exact token
  (`ngtcp2_crypto_verify_retry_token()`, timeout-bounded by the new
  `MAGNUS_QUIC_RETRY_TOKEN_TIMEOUT_NS`) does `magnus_quic_accept_new()`
  go on to allocate a connection slot at all -- an off-path attacker
  spoofing a victim's address can no longer make magnus do a full TLS
  handshake's worth of work toward that victim, and a flood of junk
  no-token `Initial`s can no longer exhaust the fixed
  `MAGNUS_QUIC_MAX_CONNECTIONS` slot table either, since nothing is
  ever allocated until a verified-token retry arrives. The eventual
  real connection's own transport parameters carry `retry_scid`/
  `retry_scid_present` (RFC 9000 18.2) so the client can cryptographically
  confirm a genuine `Retry` actually happened, not an off-path attacker
  telling it to skip validation, and `original_dcid` is taken from the
  *verified token's* own copy rather than the retried `Initial`'s own
  header, per spec. ngtcp2's base (non-`_token2`) retry-token API was
  used deliberately, for the same Docker-pinned-ngtcp2-v1.19.0
  compatibility reason roadmap 4b's own dependency evaluation already
  established -- confirmed to exist there by this release's own image
  rebuild, not merely assumed.

  A new lifetime counter, `magnus_quic_retry_total` (`/metrics`,
  every protocol's own shared `magnus_build_metrics()`), is
  incremented once per `Retry` packet actually sent -- the only
  externally observable proof that address validation is happening at
  all, since a `Retry` produces no connection state of its own to
  otherwise point to. `tests/test-core.sh` gained a dedicated Phase 4k
  block: the counter reads `0` against a fresh instance that has never
  seen a QUIC connection, and strictly increases once
  `quic-handshake-check` completes a single HTTP/3 request against it
  -- read back over an ordinary HTTP/1.1 request, proving it is one
  shared counter, not a QUIC-only one, the same "one shared thing, not
  per-protocol" shape roadmap 4j's own pooling block already
  established for the connection pool. Every pre-existing QUIC test
  block (4a through 4j) now transparently exercises the full two-round-
  trip `Retry` exchange on every one of its own connections too, and
  all still pass unmodified.

  With this, `src/magnus_quic.h`'s own "deliberately still not here"
  list loses its oldest entry: connection migration / path validation
  remains a distinct, still-deferred RFC 9000 mechanism (revalidating
  an address that *changes* mid-connection), not what 4k's own
  narrower scope (confirming a client owns its address once, at the
  very start of a connection) ever claimed to cover.

  Verified: `make test` (twice) and `make sanitize` (ASan/UBSan) both
  clean; manual protocol-level verification (temporary trace
  instrumentation, since removed) against both the host binary and a
  live Docker container confirmed the exact expected sequence -- a
  no-token `Initial`, a `Retry` sent, the client's own harmless
  pre-`Retry` retransmit triggering a second `Retry`, then the
  client's retried `Initial` carrying a valid token, verified, the
  handshake completing, and the HTTP/3 request succeeding -- not
  merely "it still works." Image rebuilt against the pinned ngtcp2
  v1.19.0 and smoke-tested; size unchanged in kind from 1.34.0 (no new
  runtime dependency -- the retry-token helpers are already part of
  `libngtcp2_crypto_ossl`, already linked in since roadmap 4a).

## 1.34.0

### Added

- **HTTP/3 upstream connection pooling for proxy dispatch (roadmap
  Phase 4j): the last remaining gap between HTTP/3 proxy dispatch and
  HTTP/1.1's/HTTP/2's own. A completed response the upstream marked
  poolable is now returned to the exact same shared, endpoint-keyed
  idle pool (`magnus_pool_checkout()`/`magnus_pool_checkin()`,
  `src/magnus_static.h`) HTTP/1.1 and HTTP/2 already use -- one pool,
  not one per protocol, since it is indexed by which *endpoint* a
  connection belongs to, never by which client connection or protocol
  asked for it.** `magnus_quic_proxy_connect_endpoint()` now tries a
  pooled idle connection first, falling back to a fresh `connect()`
  only when the pool has nothing idle for that endpoint -- the exact
  shape `magnus_h2_proxy_connect_endpoint()`'s own identical function
  already has. The outbound proxy request's own `Connection` header
  changed from an unconditional `close` to `keep-alive` (matching
  `magnus_h2_proxy_start()`'s own choice) -- without it the upstream
  would simply close every connection regardless of how eager magnus
  itself was to reuse it. `magnus_quic_stream_t` gained
  `upstream_requests_served`, threaded from checkout through to
  checkin exactly like `struct magnus_h2_stream`'s own field, so
  `MAGNUS_POOL_MAX_REQUESTS_PER_CONNECTION` (magnus.c-internal) still
  retires a connection on schedule regardless of which protocol has
  been driving it. `magnus_quic_proxy_maybe_complete()`'s own
  completion path -- and the reverse-proxy-cache revalidation branch's
  304 handling (roadmap 4i) -- both now check the response's own
  `upstream_poolable` verdict (`magnus_proxy_response_info_t`, already
  computed, previously ignored) before deciding checkin-vs-teardown,
  the same branch `magnus_h2_proxy_maybe_complete()`'s own identical
  logic already has: only a completion by Content-Length (never one by
  upstream EOF, which by definition means the upstream already closed
  its own end) of a poolable response goes back into the idle pool.
  `magnus_pool_expire_idle()`'s own existing once-per-second sweep
  (already running unconditionally from `main()`) needed no QUIC-side
  hook at all -- it already covers the shared pool regardless of which
  protocol checked a connection in.

`tests/test-core.sh` gained a dedicated Phase 4j block mirroring 1a's
own identical connection-pool test's fixture and assertions exactly: a
backend that reports which specific TCP connection (by identity,
assigned once per accept) each request arrived on. Several separate
HTTP/3 requests all landing on the same connection id proves reuse; an
ordinary HTTP/1.1 request against the same running instance landing on
that same id afterward proves it is genuinely the one shared pool, not
a second, QUIC-only one.

With this, HTTP/3 proxy dispatch (roadmap 4d/4f/4g/4h/4i/4j) has
reached functional parity with HTTP/1.1's and HTTP/2's own -- see
`src/magnus_quic.h`'s own top comment for the handful of gaps that
remain genuinely QUIC-specific rather than a missing feature (Real-IP
resolution, since QUIC has no established PROXY-protocol-over-UDP
precedent in this codebase) or cross-cutting rather than HTTP/3-scoped
(proxied-response compression, still absent on every protocol).

Image rebuilt and verified end-to-end (make test, make sanitize both
clean -- including no leaked/dangling pooled fds under ASan across a
proxy request boundary; several live HTTP/3 requests plus a
cross-protocol HTTP/1.1 request all landing on the same pooled
upstream connection identity, against the running container itself,
not just the host binary): image size unchanged in kind from 1.33.0
(no new runtime dependency -- pooling reuses `magnus_pool_checkout()`/
`_checkin()` already linked in for HTTP/1.1 and HTTP/2).

## 1.33.0

### Added

- **HTTP/3 reverse-proxy response caching for proxy dispatch (roadmap
  Phase 4i): a route matched with `action=proxy; cache=on` now shares
  the exact same bounded, in-memory, LRU-evicted cache
  (`src/magnus_cache.h`) HTTP/1.1 and HTTP/2 already use -- one cache,
  not one per protocol.** A fresh `GET` looks the entry up before ever
  touching the upstream; a fresh hit is served entirely from the cache
  (`X-Cache: HIT`); a stale entry that still carries an `ETag`/
  `Last-Modified` validator drives a conditional `GET`
  (`If-None-Match`/`If-Modified-Since`) against the upstream instead of
  a wholesale re-fetch, and a `304` refreshes the stored entry's
  freshness window and serves it (`X-Cache: REVALIDATED`) rather than
  re-transferring a body that has not actually changed.
  `magnus_quic_stream_t` gained the full cache-related field set
  `struct magnus_h2_stream` already carries (`cache_enabled`/
  `cache_host`/`cache_target`/`cache_revalidating`/the two validator
  fields/`cache_this_response_cacheable`/`cache_freshness`/
  `cache_pending_headers`/the two response-validator fields/
  `cache_capture` and its length/capacity/overflow tracking) --
  `magnus_quic_proxy_cache_capture()` (the h3 analogue of
  `magnus_h2_proxy_cache_capture()`) fills the capture buffer as the
  response streams in from two call sites (leftover bytes already read
  past the header block, and each subsequent `recv()`), and
  `magnus_quic_proxy_maybe_complete()` commits it via
  `magnus_cache_store()` once the whole response is known complete.
  Cacheability itself follows the exact same RFC 7234-narrowed rules
  every protocol already shares (`magnus_cache_compute_freshness()`) --
  `no-store`/`private`, a response carrying `Set-Cookie`, or a `Vary`
  other than `Accept-Encoding` are all excluded outright, same as
  before. A new `magnus_quic_submit_cached_response()` (the h3 analogue
  of `magnus_h2_submit_cached_response()`) serves a stored entry
  directly, reusing `magnus_quic_http_read_file()` and the
  `mmap_base`/`mmap_length`/`body_is_malloc` pattern 4c/4e already
  established for non-mmap response bodies.

`tests/quic-handshake-check.c` gained `x-cache` response-header
capture (matched by name -- no QPACK static-table token exists for a
non-standard header). `tests/test-core.sh` gained a dedicated
Phase 4i block mirroring the earlier M-series h1/h2 cache test's own
fixture and assertions exactly: fresh MISS then HIT with zero
additional hits against the fake upstream's own per-request marker,
`no-store`/`Set-Cookie` responses never cached, and a stale
ETag-bearing entry revalidating via `304` (`X-Cache: REVALIDATED`,
identical body) or refetching wholesale when the upstream's own
content genuinely changed -- plus one HTTP/3-specific check the h1/h2
version has no need for: an ordinary HTTP/1.1 request against the same
running instance also sees the entry HTTP/3 just stored, proving one
shared cache rather than a QUIC-local copy.

Image rebuilt and verified end-to-end (make test, make sanitize both
clean; a live HTTP/3 MISS-then-HIT round trip, plus the
cross-protocol HTTP/1.1-sees-the-same-entry check, against the running
container itself, not just the host binary): image size unchanged in
kind from 1.32.0 (no new runtime dependency -- caching reuses
`magnus_cache.c` already linked in for HTTP/1.1 and HTTP/2).

## 1.32.0

### Added

- **HTTP/3 proxy dispatch cookie-based session affinity (roadmap Phase
  4h): a returning client's `MAGNUS_AFFINITY` cookie, when present and
  still valid, wins over whichever load-balancing policy is configured
  -- `magnus_cluster_select_sticky()`'s own documented precedence,
  matching HTTP/1.1's and HTTP/2's identical proxy dispatch exactly.**
  A response that issues a fresh cookie (no cookie presented, or a
  connect-failure retry landed on a different endpoint than whatever
  the cookie implied) does so through
  `magnus_proxy_sanitize_response_headers()`'s own existing
  `affinity_cookie_value` parameter -- always passed `NULL` until now
  -- so the `Set-Cookie` line is the exact same shared code HTTP/1.1
  and HTTP/2 proxy dispatch already emit it through.
  `magnus_decode_affinity_cookie()`/`magnus_encode_affinity_cookie()`
  (`magnus.c`, exposed via `src/magnus_static.h` for this reuse, the
  same pattern every other roadmap-4 cross-module symbol has used) are
  the codec; `magnus_quic_stream_t` gained `issue_affinity_cookie`/
  `affinity_key`, the h3 analogue of `struct magnus_h2_stream`'s own
  identically-named pair. `magnus_quic_proxy_start()`'s own `for (;;)`
  connect loop (4g) now mirrors `magnus_h2_proxy_start()`'s exactly:
  sticky selection on the first iteration if a valid cookie was
  presented, falling back to (and refreshing the cookie for) a fresh
  selection on any deviation -- an invalid/absent cookie, a retried
  connect after failure, or the sticky endpoint itself being
  unavailable. `magnus_quic_proxy_fail()`'s own retry (4g) always
  refreshes the cookie on a successful retry too, for the same reason
  `magnus_h2_proxy_connect_failed()`'s identical retry does: the
  client must be pinned to the endpoint actually used now, not the one
  that just failed. A new `magnus_quic_client_ip()` helper (added in
  4g) is reused as-is; no Real-IP resolution for QUIC yet (see
  `src/magnus_quic.h`'s own scope note).

### Fixed (found during this increment's own verification, not by review)

- The existing 4d/4f `test-core.sh` proxy-dispatch body assertions
  (`tail -n +3 ... | diff/grep`) assumed exactly two response-header
  lines (`:status`, `content-length`) ahead of the body. Once 4h shipped,
  *every* proxy response without a client-presented cookie -- which is
  every one of those pre-existing tests -- now also carries a
  `set-cookie` line, shifting the body one line later and corrupting
  the byte-exact large-payload comparison specifically (a real, visible
  diff: the expected 5000-line fixture short by exactly the leading
  `set-cookie` line). Found by the full `make test` run itself, not
  reviewing the new code in isolation -- fixed by updating those three
  assertions to `tail -n +4`.

`tests/quic-handshake-check.c` gained `set-cookie` response-header
capture and an optional fifth CLI argument to send a `Cookie:` request
header, driving `tests/test-core.sh`'s new Phase 4h block: a fresh
client is issued a cookie and round-robined, presenting that cookie
back keeps every subsequent request on the same endpoint, and killing
the sticky endpoint's own backend still fails over (via 4g's retry)
with a refreshed cookie for the survivor -- mirroring M4's own
identical h1/h2 session-affinity test exactly.

Image rebuilt and verified end-to-end (make test, make sanitize both
clean; a live HTTP/3 proxy round trip against the running container
itself -- first request issues a cookie, presenting it back sticks to
the same endpoint every time): image size unchanged in kind from
1.31.0 (no new runtime dependency -- affinity reuses the cookie codec
and `magnus_proxy_sanitize_response_headers()` already linked in for
HTTP/1.1 and HTTP/2).

## 1.31.0

### Added

- **HTTP/3 proxy dispatch retry-on-connect-failure (roadmap Phase 4g):
  a failed connect attempt (either the literal `"/proxy"` prefix,
  roadmap 4d, or a route-matched `action=proxy`, roadmap 4f) now
  transparently retries against a freshly-selected cluster endpoint
  instead of surfacing 502/504 on the very first failure -- bounded by
  a new `MAGNUS_QUIC_PROXY_MAX_ATTEMPTS` (2, mirroring `magnus.c`'s own
  `MAGNUS_PROXY_MAX_ATTEMPTS`), the exact same total-attempts budget
  `magnus_proxy_connect_failed()`/`magnus_h2_proxy_connect_failed()`
  already give HTTP/1.1 and HTTP/2.** Split across the same two call
  sites those functions cover: `magnus_quic_proxy_start()`'s own
  `for (;;)` loop retries a *synchronous* connect failure (rare --
  `connect()` on a genuinely closed local port almost always returns
  `EINPROGRESS`, not an immediate error); `magnus_quic_proxy_fail()`
  (already the one place every pre-header proxy failure funnels
  through, since 4d's own "killed upstream never degraded
  `magnus_upstream_healthy`" fix) retries the far more common
  *asynchronous* failure, detected later via `SO_ERROR` -- and, per
  that function's own existing contract, every other pre-header
  failure too (a mid-request `send()` error, a malformed/oversized
  upstream response, a read timeout), exactly matching
  `magnus_h2_proxy_connect_failed()`'s identical scope (any failure
  while `response_headers_submitted` is still false, not just a
  connect-stage one). `magnus_quic_stream_t` gained an `attempt` field,
  the h3 analogue of `struct magnus_h2_stream`'s own. Session affinity
  is deliberately not part of this retry (still deferred, see
  `src/magnus_quic.h`'s own scope note) -- a retried request has no
  cookie to issue or honor either way. A new `magnus_quic_client_ip()`
  helper (`connection->remote_addr`'s own IPv4 address, the one place
  this cast now lives) replaces three separate copies of the same
  inline cast this and the 4f route-matching code each had.

`tests/test-core.sh` gained a dedicated retry test mirroring M3's own
identical h1/h2 retry-budget test exactly: the first configured
endpoint refuses every connection, so a request must still complete
successfully against the second (live) one instead of surfacing 502.

Image rebuilt and verified end-to-end (make test, make sanitize both
clean; a live HTTP/3 proxy request against a cluster whose first
endpoint is unreachable, completing successfully via the second,
against the running container itself, not just the host binary): image
size unchanged in kind from 1.30.0 (no new runtime dependency -- the
retry reuses `magnus_cluster_select()`/`magnus_cluster_result()`
already linked in).

## 1.30.0

### Added

- **HTTP/3 `route` table dispatch (roadmap Phase 4f): host/path-prefix/
  method/header/header_prefix/cookie/query/source-CIDR matching, the
  same `--route`/`route =` DSL and `magnus_route_matches()`
  (`src/magnus_route.h`) HTTP/1.1 and HTTP/2 already share.** Evaluated
  in file order, first match wins, ahead of the literal `"/proxy"`
  prefix (4d) and static-file dispatch -- exactly
  `magnus_h2_dispatch()`'s own precedence. A matched `action=proxy`
  route always wins over the literal `"/proxy"` prefix when both apply
  to the same request, forwarding the *whole*, unstripped target
  (matching `magnus_proxy_pick_and_start()`'s documented h1/h2
  precedent); `action=deny` answers 403; `action=grpc` answers an
  explicit 505 (`gRPC requires HTTP/2 ...`) rather than silently
  falling through to static/proxy, since this codebase's gRPC dispatch
  is HTTP/2-native-only and HTTP/3 cannot reach it any more than
  HTTP/1.1 can; `action=static` needs no branch of its own -- matching
  and being neither deny/proxy/grpc already falls through to the same
  static dispatch a request with no matching route at all gets.
  `magnus_quic_stream_t` gained a full `magnus_http_request_t parsed`
  field (`src/magnus_http.h`) -- the same shape HTTP/2's own
  `stream->parsed` already is -- replacing the ad hoc `method`/`path`/
  `authority` fields (and 4e's own `accept_encoding` field, now just
  `magnus_http_header_find(&stream->parsed, "accept-encoding")`):
  `magnus_quic_http_recv_header()` now captures every ordinary header
  into `parsed.headers[]` up to `MAGNUS_HTTP_MAX_HEADERS`, mirroring
  `magnus_h2_on_header()`'s own capture exactly, so route matching
  behaves identically regardless of which protocol a request arrived
  over. `src/magnus_static.h` gained `magnus_routes[]`/
  `magnus_route_count` (declared as an incomplete array type -- valid
  C, magnus_quic.c only ever indexes up to the count, never needs
  `sizeof`) for this reuse.

Deliberately still not here, matching 4d's own scope note exactly (a
matched route decides *whether* and *what path* to forward, never a
different upstream of its own -- there is only ever the one shared
`magnus_cluster`): retry-on-connect-failure, upstream connection
pooling, session affinity, and response caching (a route's own
`cache_enabled` is not consulted yet) for proxy dispatch. Also not
here: Real-IP-aware `source_cidr` matching -- 4f matches against the
raw QUIC peer address only, since QUIC has no established
PROXY-protocol-over-UDP precedent in this codebase to resolve a
trusted client address from in the first place. See
`src/magnus_quic.h`'s own top comment.

`tests/test-core.sh`'s Phase 4 block gained a dedicated route-dispatch
section: a multi-condition (`host` + `path_prefix`) route reaching the
shared upstream cluster with the correct unstripped path, `action=deny`
still denying, `action=grpc` still answering its 505, and an
unmatched path still falling through to ordinary static 404 --
condition-*kind* coverage itself (header/cookie/query/source_cidr) is
not re-proven per protocol, already exercised for h1/h2 in this same
file and unit-tested directly in `tests/test-route.c`; this block
proves the wiring, not the shared matcher.

Image rebuilt and verified end-to-end (make test, make sanitize both
clean; a live HTTP/3 route-matched proxy/deny/grpc-505/404 round trip
against the running container itself, not just the host binary): image
size unchanged in kind from 1.29.0 (no new runtime dependency --
route matching reuses `magnus_route.c`/`magnus_http.c` already linked
in for HTTP/1.1 and HTTP/2).

## 1.29.0

### Added

- **HTTP/3 static-file gzip compression (roadmap Phase 4e): the same
  scope compression 2a shipped for HTTP/1.1 and HTTP/2 in 1.11.0, now
  extended to the third protocol.** A new `magnus_quic_compress_static()`
  in `src/magnus_quic.c` reuses `magnus_accepts_gzip()`/
  `magnus_content_type_compressible()`/`magnus_gzip_compress()`
  (`src/magnus_compression.h`, already linked into the binary for
  HTTP/1.1 and HTTP/2) rather than reusing `magnus_compress_static()`
  directly, since that function's signature takes a
  `magnus_http_request_t *` purely to reach
  `magnus_http_header_find(request, "accept-encoding")` -- pulling in
  `magnus_http.h` just for that would have coupled this module to a
  request shape it does not otherwise use anywhere; `magnus_quic_stream_t`
  already carries its own flat `accept_encoding` field, captured
  straight off `accept-encoding`'s own QPACK static-table token
  (`NGHTTP3_QPACK_TOKEN_ACCEPT_ENCODING`) the same way `:method`/`:path`/
  `:authority` already are via theirs. Same 256-byte..8-MiB eligibility
  window, same compressible-MIME-type gate, same `Vary: Accept-Encoding`
  as 2a; the compressed body reuses `mmap_base`/`mmap_length`/
  `body_is_malloc` (4c's own "one pair of fields covers a file mapping
  or a malloc()ed body" pattern) rather than a third near-identical
  field pair. A HEAD response still reports the *compressed*
  Content-Length, matching `magnus_h2_dispatch_static()`'s own ordering
  (compute compression eligibility before branching on `head_only`, not
  after).
- `tests/quic-handshake-check.c` gained `content-encoding`/`vary`
  response-header capture and an optional fourth CLI argument
  (`gzip`) that sends `Accept-Encoding: gzip` on the request, driving
  `tests/test-core.sh`'s new Phase 4e block: a compressible (`text/html`)
  fixture round-tripped byte-exact through `gunzip`, the same fixture
  requested without `Accept-Encoding` coming back uncompressed, and a
  binary (`image/png`) fixture staying uncompressed even when the
  client does offer gzip.

Deliberately still HTTP/1.1-and-HTTP/2-only, not a QUIC-specific gap:
proxied-response compression (2a's own scope note already excludes it
on every protocol), Brotli/zstd, and streaming/chunked compression for
files above the 8 MiB bound -- see `src/magnus_quic.h`'s own top
comment.

Image rebuilt and verified end-to-end (make test, make sanitize both
clean; a live HTTP/3 gzip-compressed GET -- round-tripped through
`gunzip` back to the exact original bytes -- against the running
container itself, not just the host binary, plus the same
uncompressed/binary-MIME negative checks): image size unchanged in
kind from 1.28.0 (no new runtime dependency -- compression reuses zlib
already linked in for HTTP/1.1 and HTTP/2).

## 1.28.0

### Added

- **HTTP/3 `"/proxy"` dispatch to a real HTTP/1.1 upstream (roadmap
  Phase 4d): the same next increment 2a was on the HTTP/2 side, after
  4a-4c's own transport/static-file/healthz-metrics build-up.** A new
  "HTTP/3 proxy dispatch" section in `src/magnus_quic.c` builds the
  outbound HTTP/1.1 request (the literal `"/proxy"` prefix stripped,
  matching `magnus_proxy_pick_and_start()`'s own documented contract
  for h1/h2 exactly, with one deliberate small improvement: a bare
  `/proxy` request forwards `"/"` rather than importing that precedent's
  own empty-request-target edge case unchanged), selects a cluster
  endpoint via the existing `magnus_cluster_select()`/`magnus_cluster_result()`
  passive-health machinery (`src/magnus_policy.h`, shared with h1/h2),
  connects non-blocking, relays the response headers through the
  existing shared `magnus_proxy_sanitize_response_headers()`
  (`src/magnus_proxy.h`, also shared with h1/h2), and streams the body
  back over HTTP/3 with `nghttp3`'s pull-model `read_data` callback.
  502 on connect failure or a malformed/oversized upstream response,
  504 on a read timeout, an abrupt stream reset if the failure happens
  after headers were already submitted (no fresh status code is
  possible by then) -- the same three-way error shape h1/h2 already
  use. `magnus_static.h` gained `magnus_endpoint_sockaddr()` and
  `magnus_global_epoll_fd` (the epoll instance every fd in this
  process, including a QUIC proxy stream's own upstream fd despite the
  QUIC connection itself having no fd, is registered against) for this
  reuse; `magnus.c`'s main epoll loop gained one new dispatch check
  (`magnus_quic_handle_upstream_event()`) ahead of its existing
  `magnus_connections[fd]` fallback.
- `tests/test-core.sh`'s Phase 4 block gained a dedicated proxy-dispatch
  section: GET through to a real backend (small and a ~130 KB/5000-line
  byte-exact streamed response -- see "Fixed" below for exactly what
  that download is a regression guard for), the backend's own 404
  relayed through unmodified, and a clean 502 (plus the
  `magnus_upstream_healthy` passive-health signal it feeds) once the
  backend is killed outright.

### Fixed (found during this increment's own verification, not by review)

- **Response-body memory corruption under real QUIC flow control** --
  the same *class* of bug 1.26.0's own "Fixed" section already
  describes for the static-file path, but reintroduced here in a new
  form because nghttp3's `read_data` callback has a stricter contract
  than it first appears: per its own documentation, memory handed back
  through a `nghttp3_vec` must stay valid until `nghttp3_acked_stream_data`
  confirms the *peer* has acknowledged it -- not merely until
  `ngtcp2_conn_writev_stream()` has copied it into an outgoing packet.
  The first version of `magnus_quic_proxy_read_body()` reused a single
  `stream->body_buffer` (refilled from the upstream socket only once
  nghttp3 had "consumed" it), the same shape as
  `magnus_h2_read_io_buffer`'s own safe-for-nghttp2 pattern -- safe
  there because nghttp2's `read_callback` copies bytes out of the
  buffer synchronously within the same call, but wrong here: under
  `NGTCP2_ERR_STREAM_DATA_BLOCKED` (QUIC-level per-stream flow
  control), `magnus_quic_flush()`'s own loop can return having only
  partially transmitted -- or not transmitted at all -- a chunk nghttp3
  still holds a reference to for eventual retransmission, while the
  proxy code had already gone on to overwrite that same memory with a
  fresh `recv()`. Reproduced directly (both by hand and by the new
  automated test above): two response lines spliced together
  mid-word, same total byte count as expected but scrambled content --
  the exact same "same length, wrong content" signature 1.26.0's own
  bug had, in a different code path, which is why the new regression
  test above uses the same position-dependent-content trick that one
  did. Fixed by replacing the single reused buffer with one fresh
  `malloc()`ed chunk in flight at a time
  (`stream->body_chunk`/`body_chunk_length`/`body_chunk_offered`),
  freed only once `nghttp3_acked_stream_data` reports the currently
  in-flight chunk's end offset has actually been acknowledged.
- **A killed upstream correctly produced its 502, but never actually
  degraded `/metrics`' own `magnus_upstream_healthy`.** Found by the
  same automated test's own final assertion, immediately after the bug
  above was fixed. Root cause: `magnus_quic_proxy_start()`'s
  synchronous-`connect()`-failed branch was the *only* place in the
  new proxy code calling `magnus_cluster_result(..., false, ...)` --
  but a `connect()` to a genuinely closed local port almost always
  returns `EINPROGRESS`, not an immediate error, so the far more common
  case in practice is the *asynchronous* failure detected later via
  `getsockopt(SO_ERROR)` once epoll reports the fd writable, and that
  path (`magnus_quic_proxy_handle_upstream()`, and every other
  pre-header failure funneled through the shared `magnus_quic_proxy_fail()`
  helper) never recorded a passive-health failure at all -- unlike h1's
  own `magnus_proxy_connect_failed()`, which centralizes exactly this
  so every failure site gets it "for free." Fixed by moving the
  `magnus_cluster_result(..., false, ...)` call into
  `magnus_quic_proxy_fail()` itself, matching that h1 precedent.
- The new proxy-dispatch test block's own backend fixture didn't answer
  `GET /` with 200, so `magnus`'s own periodic active health check
  (`magnus_health_tick()`, default probe path `/`) intermittently
  raced the test's explicit backend-kill/502 sequence: whichever
  active-check tick happened to land while the backend was still up
  but before the deliberate kill could itself spuriously flip the
  endpoint unhealthy for a full cooldown window, depending on exactly
  when it fired relative to the test's own requests -- a ~30% flake
  rate reproduced directly by looping the test block. Fixed by giving
  the fixture a `/` handler too, so only the test's own deliberate
  failure ever counts.

Image rebuilt and verified end-to-end (make test, make sanitize both
clean -- including no leaked `body_chunk` allocations under ASan; a
live HTTP/3 proxy GET/404/502 round trip, byte-exact large-payload
transfer, and passive-health-degradation check against the running
container itself, not just the host binary): image size unchanged in
kind from 1.27.0 (no new runtime dependency -- proxy dispatch reuses
`libngtcp2`/`libnghttp3` already linked in, plus the same
`magnus_proxy.c`/`magnus_policy.c` h1/h2 already use).

Deliberately still not here (each its own future increment): the
`route` table's own host/path-prefix/header/cookie/query/source-CIDR
matching, retry-on-connect-failure, upstream connection pooling,
session affinity, and response caching for HTTP/3 proxy dispatch --
see `src/magnus_quic.h`'s own top comment for the full list.

## 1.27.0

### Added

- **HTTP/3 `/healthz` and `/metrics` (roadmap Phase 4c): the same next
  increment 1e-4 was on the HTTP/2 side, after 1e-1's own static-only
  start -- built on 1.26.0's HTTP/3 static-file GET/HEAD.** Both reuse
  the exact primitives HTTP/1.1 and HTTP/2 already share
  (`magnus_build_metrics()`, now also declared non-`static` in
  `src/magnus_static.h`): no protocol can drift into reporting
  different numbers for the same process. `magnus_quic.c`'s request
  dispatch gained one shared entry point
  (`magnus_quic_http_dispatch()`) ahead of the 4b static-file path:
  literal `/healthz`/`/metrics` win over a same-named file, matching
  `magnus_h2_dispatch()`'s own documented precedence on the h2 side.
- Admin channel isolation (roadmap 1e-4) now applies to the QUIC
  listener too: once `--admin-socket`/`admin_socket` is configured,
  `/metrics` over HTTP/3 is withdrawn (falls through to the static
  path, 404s like any other nonexistent path) while `/healthz` stays
  public -- the same access-control boundary the main TCP listener
  already had, extended rather than left as a QUIC-specific gap.
- `magnus_quic_stream_t`'s `mmap_base`/`mmap_length` fields (1.26.0's
  own file-serving mechanism) are now reused generically as "response
  body pointer + length" for `/healthz`/`/metrics`'s malloc()ed text
  too, distinguished by a new `body_is_malloc` flag so
  `magnus_quic_http_stream_free()` calls the right one of `free()`/
  `munmap()` on cleanup -- one code path serves both kinds of response
  body instead of a second, near-identical one.
- `tests/test-core.sh`'s Phase 4 block gained real-content checks (not
  just status) for `/healthz`/`/metrics` over HTTP/3, plus a dedicated
  admin-isolation check (a second magnus instance with
  `--admin-socket`, confirming `/metrics` 404s there while `/healthz`
  still answers).

Image rebuilt and verified end-to-end (make test, make sanitize both
clean; a live HTTP/3 `/healthz`/`/metrics` request against the running
container itself, not just the host binary): image size unchanged in
kind from 1.26.0 (no new runtime dependency -- `/healthz`/`/metrics`
reuse code already linked in).

## 1.26.0

### Added

- **HTTP/3 static-file GET/HEAD (roadmap Phase 4b): nghttp3 wired
  directly on top of the Phase 4a QUIC transport, scoped the same way
  HTTP/2's own first increment (roadmap 1e-1) was -- static files only,
  no proxy dispatch or compression over h3 yet.** Once a server's own
  1-RTT TX key is available (`ngtcp2_callbacks.recv_tx_key`, the
  earliest point 1-RTT application data can go out), `magnus_quic.c`
  now builds an `nghttp3_conn`, opens the three control/QPACK
  unidirectional streams RFC 9114 6.2 requires, and accepts client
  request (bidirectional) streams up to a new
  `MAGNUS_QUIC_MAX_BIDI_STREAMS` (100, matching this codebase's
  existing informal h2 concurrency sizing). A request's `:method`/
  `:path` drive `magnus_open_static()`/`magnus_content_type()` --
  exposed non-`static` from `magnus.c` via new `src/magnus_static.h`
  for exactly this reuse, so HTTP/1.1, HTTP/2, and now HTTP/3 all agree
  on path-resolution/traversal-safety and MIME typing by construction
  rather than each maintaining their own copy.
- `tests/quic-handshake-check.c` (Phase 4a's handshake-only client)
  gained a client-side HTTP/3 stack of its own: given a third argument,
  it now issues one real GET and prints the response status/body,
  driving `tests/test-core.sh`'s new Phase 4b block (200/404, and a
  ~150 KB byte-exact download -- see "Fixed" below for exactly what
  that download-size test is a regression guard for).

### Fixed (found during this increment's own verification, not by review)

- A first version of the static-file response body used a fixed-size
  buffer refilled via `pread()` inside the `nghttp3_read_data_callback`,
  advancing the file offset on every call. `nghttp3_conn_writev_stream()`
  can legitimately call that callback again for the same stream before
  a previously-returned chunk has actually finished being written onto
  the wire (observed directly: a second call arrived having only
  flushed 645 of a first 16384-byte chunk) -- since the callback had no
  way to know how much of what it last returned was actually consumed,
  this silently skipped/reordered response bytes while the total
  Content-Length stayed correct (same length, wrong content -- a
  same-repeated-byte test fixture could never have caught this, which
  is why the new automated regression test above uses position-dependent
  content instead). Fixed by `mmap()`-ing the whole file once at
  dispatch and handing nghttp3 the same immutable mapping every time,
  regardless of how many times or in what order it's asked for --
  matching the reference implementation's own static-file path
  (docs/phase4-spike-results.md) exactly, and sidestepping the
  "how much did you actually send" question entirely rather than
  tracking it by hand.
- The per-stream `magnus_quic_stream_t` struct was never freed on a
  stream's normal completion (only a whole-connection error-path
  sweep freed any that were still around) -- a real per-request memory
  leak under ordinary, successful traffic. Fixed by freeing it from the
  ngtcp2-level `stream_close` callback too, once nghttp3's own
  `close_stream` call for that stream returns.
- The Docker image build failed against Debian 13's own pinned nghttp3
  release (v1.9.0, the latest actual tag -- nghttp3 versions its own
  releases independently of, and behind, ngtcp2's): two APIs the first
  version of this code used
  (`nghttp3_conn_get_stream_user_data`, `nghttp3_callbacks.rand`) do not
  exist in that release, only in the newer development snapshot the
  EPEL-packaged development-host build happened to resolve. Fixed by
  using the *ngtcp2*-level per-stream user-data association instead
  (`ngtcp2_conn_set_stream_user_data`/`ngtcp2_conn_get_stream_user_data`,
  stable since ngtcp2 v1.17.0, well below this project's own v1.19.0
  pin) and simply not setting `.rand` at all, which nghttp3's own docs
  describe as "optional due to backward compatibility" -- both fixes
  are correct on every nghttp3 version this project builds against, not
  version-specific workarounds. Found by the image build itself
  failing, not by reading changelogs first.

### Known gaps (Phase 4b's own deliberately narrow scope, see
`src/magnus_quic.h`)

- No proxy dispatch, `/healthz`/`/metrics`, or compression over HTTP/3
  -- static GET/HEAD only, the same scope 1e-1 had for HTTP/2 before
  1e-2/1e-4 extended it.
- No request body handling (a GET/HEAD request is never expected to
  carry one; a request that does is not specifically rejected, just
  never read).

## 1.25.0

### Added

- **QUIC transport (roadmap Phase 4a): the first Phase 4 increment,
  scoped the same way Phase 1e (HTTP/2) and Phase 3 both were --
  transport and handshake only, no HTTP/3 request/response layer yet.**
  New `--quic-port`/`quic_listen` config key opens a fifth, independent
  UDP listener (`src/magnus_quic.c`/`.h`) that completes a real RFC
  9000 handshake -- ngtcp2 + `libngtcp2_crypto_ossl` (see
  `docs/phase4-http3-quic-dependency-evaluation.md` for the dependency
  gate this went through first, and `docs/phase4-spike-results.md` for
  the standalone verification against a real OpenSSL 3.5 before this
  landed in `magnus.c`) -- integrated into Magnus's own epoll reactor:
  one shared UDP socket demultiplexes every active connection by QUIC
  connection ID (a bounded, linear-scan table, same style as every
  other fixed-size state table in this codebase), and ngtcp2 timer
  expiry rides the same 1 Hz per-tick sweep `magnus_expire_idle()`/
  `magnus_health_tick()`/etc. already use. Requires `tls_cert`/
  `tls_key` (the same certificate the HTTPS listener uses -- no
  separate QUIC cert); ALPN negotiates `h3` and a modest number of
  unidirectional streams are accepted (drained for flow control only,
  never parsed) so a real HTTP/3 client's own control/QPACK streams
  don't stall its handshake, but bidirectional (request/response)
  streams stay closed -- nghttp3 joins this build in a later increment
  once request handling is actually implemented.
- New `tests/quic-handshake-check.c`: a minimal, self-contained QUIC
  client (same ngtcp2/crypto_ossl stack, no other new dependency) used
  by `tests/test-core.sh`'s own new Phase 4a block to drive a real
  handshake against a running magnus and assert it completes -- not a
  general-purpose client, only enough of the handshake to prove the
  listener works under real network I/O, following up on an external
  reference client (ngtcp2's own `examples/osslclient`) doing the same
  by hand in `docs/phase4-spike-results.md`.
- `Dockerfile`'s builder stage now builds ngtcp2 v1.19.0 from source:
  Debian 13's own package (1.11.0) is below the >= 1.12.0 floor
  `libngtcp2_crypto_ossl` needs for OpenSSL 3.5+, so apt's copy would
  build cleanly but fail the handshake at runtime -- found via the
  dependency evaluation, not by trial and error against the image.

### Fixed (found during this increment's own verification, not by review)

- `ngtcp2_conn_server_new()` asserts on a server connection's transport
  params missing `original_dcid`/`original_dcid_present` (RFC 9000
  18.2) -- `ngtcp2_transport_params_default()` leaves both unset, and
  the very first real handshake attempt against a running magnus
  crashed the whole process on that assert. Fixed by setting both from
  the accepted Initial packet's own header.
- The connection-ID demux table only ever registered CIDs magnus itself
  issued, never the client's own original dcid -- harmless for a
  handshake that fits in one Initial packet, but a first flight large
  enough to span more than one (routine with a post-quantum hybrid key
  share bulking up the ClientHello) or a retransmission arriving before
  magnus's first response reaches the client both still carry the
  client's original dcid, which the table had no entry for, spawning a
  second, bogus connection for what was really a continuation of the
  same handshake. Fixed by also registering the client's original dcid
  at accept time.

### Known gaps (Phase 4a's own deliberately narrow scope, see
`src/magnus_quic.h`)

- No HTTP/3 request/response handling (nghttp3 not yet linked).
- No retry-based stateless address validation (anti-amplification): an
  unmatched Initial is accepted unconditionally.
- No connection migration / path validation beyond a single,
  non-migrating handshake.
- No 0-RTT.
- A certificate rotated via SIGHUP reload does not propagate to the
  QUIC listener's own separate SSL_CTX (only the HTTPS listener's
  cert hot-reloads today) -- a restart is required to rotate the QUIC
  listener's certificate.

## 1.24.0

### Added

- **PROXY protocol emission (roadmap 3e): the last item on Phase 3's own
  headline ("L4 TCP/UDP, TLS passthrough, PROXY protocol"), not covered
  by TCP passthrough (3a), TLS passthrough (3b), or UDP passthrough (3d)
  -- closes out Phase 3.** The reverse direction from Real IP 2b's own
  `magnus_proxy_proto_parse()`: magnus is here the *emitter*, not the
  receiver, prefixing its own outbound connection to a stream backend
  with a preamble identifying the real (source IP, source port) a plain
  relayed TCP connection would otherwise never reveal -- every connection
  would otherwise look, to the backend, like it originates from magnus's
  own address. Scoped to TCP stream passthrough only for this increment
  (UDP passthrough's own distinct "per-datagram header" v2 variant is a
  real complexity/compatibility trade-off, deliberately deferred to a
  future increment).
- New `stream_proxy_protocol=off|v1|v2` config key / `--stream-proxy-
  protocol off|v1|v2` CLI flag. Defaults to `off` -- unconditionally
  turning this on would break any existing deployment whose backend does
  not already expect this preamble as its first bytes. Applies uniformly
  to every stream connection regardless of which cluster it ends up at,
  the plain `stream_upstream` default cluster or a matched
  `stream_sni_route` one (3b) -- a deliberate first-increment
  simplification assuming homogeneous backend expectations across the
  whole `stream_listen` surface; a per-pattern override is a distinct
  possible future increment, not silently half-done. Hot-reloadable,
  like `stream_lb_policy`, since no listening socket is involved.
- New `magnus_proxy_proto_build()` (`magnus_realip.c`/`.h`, alongside the
  parse-side `magnus_proxy_proto_parse()` it mirrors): renders either the
  v1 text format (`PROXY TCP4 <src_ip> <dst_ip> <src_port> <dst_port>
  \r\n`) or the fixed 28-byte v2 binary layout (12-byte signature +
  version/command + family/protocol + address-block length + 4+4-byte
  IPv4 addresses + 2+2-byte big-endian ports), reusing the same
  `MAGNUS_PROXY_V2_SIG` signature constant the parser already defines
  rather than duplicating it. `dst` is simply the backend connection's
  own endpoint -- what magnus itself just `connect()`ed to -- since
  there is no notion of an "original destination" here, unlike a
  transparent proxy.
- The header is built once, synchronously, right when
  `magnus_stream_connect()`'s own `connect()` resolves (whether that
  happens immediately or is confirmed later, asynchronously), and
  flushed to the backend by a new `magnus_stream_flush_proxy_protocol()`
  before a single byte of actual relay traffic goes out -- gated in both
  `magnus_stream_service()`'s per-event dispatch (the ordinary pump calls
  wait for the header to finish flushing first) and
  `magnus_stream_rearm()`'s own epoll-interest computation (asks for
  upstream `EPOLLOUT` while any of the header is still unsent).
- A real, previously-latent gap was found and fixed along the way, not
  by code review but while designing this feature: `magnus_stream_accept
  ()`'s own non-SNI branch had **no follow-up call at all** after a
  successful synchronous `connect()` -- harmless before this increment,
  since there was nothing to proactively send at accept time, but a real
  gap now that a header needs to go out as early as possible. Fixed by a
  new shared `magnus_stream_after_connect()` helper, now called from
  every `magnus_stream_connect()` call site (`magnus_stream_accept()`'s
  non-SNI branch and `magnus_stream_peek_decide()`'s own SNI-resolution
  tail, which previously duplicated the same pump-then-rearm logic
  inline).
- `magnus_stream_conn_t` gained `peer_port` (the client's own source
  port, previously never needed by anything else in this file) and a
  dedicated `proxy_protocol_header[MAGNUS_PROXY_PROTO_BUILD_MAX]` buffer
  -- deliberately separate from the existing `c2u.buffer` (which already
  doubles as the ordinary relay buffer and the SNI-peek buffer from 3b)
  to avoid a `memmove`-based buffer-shifting complication and let the
  header flush as a clean, independent "always goes out first" step.

### Verified

Live, under ASan+UBSan, against real backends parsing both wire formats
directly off the wire (not just trusting magnus's own side): v1 and v2
each independently confirmed as the literal first bytes on the
connection, with the correct real client (source IP, source port); `off`
(the default) confirmed to send no preamble at all, byte-identical to
pre-3e behavior; and the SNI-routing combo (3b) confirmed end-to-end --
both the default cluster and an SNI-matched cluster receive the header
first, followed immediately by the real, unmodified payload (a plain
non-TLS request in one case, a real TLS ClientHello captured from
Python's own `ssl` module in the other), byte-for-byte. New unit
coverage in `tests/test-realip.c`: exact wire-format bytes for both
versions (including a `MAGNUS_PROXY_PROTOCOL_OFF` no-op check and a
buffer-too-small defensive check for each), plus a build/parse
round-trip proving `magnus_proxy_proto_build()` and the pre-existing
`magnus_proxy_proto_parse()` agree on the wire format. New permanent
regression coverage in `tests/test-core.sh`. `make clean && make test`
green (unit, fuzz, `test-core.sh`, `test-control-plane.sh`); two
`test-core.sh` failures during this cycle (one in the pre-existing cache
test, one in the pre-existing SNI test, at different points on different
runs, both entirely unrelated to any stream/PROXY-protocol code path)
were confirmed environmental, not a regression: the exact failing
scenarios reproduced standalone passed cleanly and repeatedly, an
unmodified pre-3e baseline build run under the same conditions passed
cleanly too, and a subsequent clean retry of the full modified suite
(including this feature's own new test block) passed with no failures
at all -- the same established flaky-test class this project has hit
before, sensitive to unrelated system load rather than to this
increment's own code. Image rebuilt, `./scripts/test-image.sh` passes.

## 1.23.0

### Added

- **UDP passthrough (roadmap 3d): a fourth, independent listener, NAT-
  style session tracking, no HTTP/TCP machinery involved at all --
  closes out Phase 3.** New `udp_listen`/`udp_upstream`/`udp_lb_policy`/
  `udp_session_idle_seconds`/`udp_max_sessions` config keys and matching
  `--udp-listen`/`--udp-upstream`/`--udp-lb-policy`/`--udp-session-idle`/
  `--udp-max-sessions` CLI flags.
- Plain `SOCK_DGRAM`, no `accept()`/handshake of any kind (UDP has
  neither) -- one `magnus_udp_session_t` per distinct (source IP, source
  port) tuple the listener has ever seen recently, each owning its own
  dedicated `connect()`ed UDP socket to whichever backend
  `magnus_udp_cluster` picked for that tuple, the same "one socket per
  active flow, `connect()` fixes the peer so replies route back
  unambiguously" pattern every other cluster in this file already uses
  for TCP. Reuses `round_robin`/`least_conn`/`ip_hash` unmodified
  (`ip_hash` keyed on source IP alone, so different source ports from
  the same client still land on the same backend) and the exact same
  `magnus_cluster_endpoint_begin()`/`_end()` live-count mechanism
  roadmap 2e-1 already built, here repurposed as "sessions currently
  pinned to this endpoint" rather than "requests" -- meaningful even
  with no health signal.
- **The "Section 12" memory bound the roadmap itself flagged needing a
  real answer before implementation, not discovered mid-implementation**:
  `udp_max_sessions` (default 1024, hard ceiling
  `MAGNUS_UDP_MAX_SESSIONS_CEILING` = 4096, a fixed array, no dynamic
  allocation) is enforced by simply dropping a new tuple's packet once
  the table is full -- deliberately never evicting an existing session
  to make room. An already-active session's own client would otherwise
  silently lose its return traffic for a stranger's benefit, and
  combined with how trivially spoofable a UDP source address is, that
  would turn eviction itself into a denial-of-service primitive rather
  than a safety valve.
- No health tracking of any kind, active or passive: a `connect()`ed UDP
  socket's own `connect()` call succeeds locally almost unconditionally
  regardless of whether the backend actually exists (there is no
  handshake to fail the way TCP's SYN/ACK would), so it carries none of
  the passive signal `magnus_cluster_result()` relies on elsewhere in
  this file -- the same scope-cut precedent `stream_sni_route`'s own
  clusters (roadmap 3b) already set, for the same underlying reason. A
  hard read error on a session's own backend socket (most notably
  `ECONNREFUSED`, which Linux can surface on a `connect()`ed UDP socket
  from a matching ICMP port-unreachable -- the one real liveness signal
  UDP offers at all) tears that session down immediately instead of
  waiting out the idle timeout, freeing its fd right away.
- `udp_listen` deliberately carries no "must differ from `port`/
  `stream_listen`" restriction, unlike `stream_listen` itself -- UDP and
  TCP occupy independent port namespaces at the OS level, so there is no
  actual conflict to guard against.
- `/metrics` gained `magnus_udp_sessions_total`/`_active`,
  `magnus_udp_bytes_total{direction=...}`, and
  `magnus_udp_upstream_active_sessions{endpoint=...}` -- deliberately no
  healthy/unhealthy gauge, since exposing one that could only ever read
  "always healthy" would be actively misleading rather than merely
  unused.

### Verified

Live, under ASan+UBSan, against real UDP backends: `round_robin`
alternation across distinct clients plus per-session stickiness for
repeated messages from the same client (a session, once picked, never
re-selects); `ip_hash` routing separate sockets that share one source IP
to the same endpoint; the session cap dropping exactly the packets past
the configured ceiling (2 accepted, 2 dropped out of 4 distinct clients
against `--udp-max-sessions 2`) while leaving the two already-active
sessions completely untouched; a session pointed at a genuinely
unreachable backend torn down within roughly 1.5 seconds via the
ICMP-triggered `ECONNREFUSED` path rather than sitting out its full idle
timeout. New permanent regression coverage in `tests/test-core.sh`.
`make clean && make test` and `make sanitize` (ASan+UBSan) both green.
Image rebuilt, `./scripts/test-image.sh` passes.

## 1.22.0

### Added

- **TLS passthrough / SNI routing (roadmap 3b): route a stream
  connection by its TLS ClientHello hostname without ever terminating
  TLS.** New module `magnus_sni.c`/`.h`: a bounded parser that reads only
  as much of a TLS record as needed to locate the `server_name` extension
  in a ClientHello (RFC 6066 3) -- not a general TLS parser, and
  deliberately does not stitch together a ClientHello split across more
  than one TLS record (vanishingly rare for a real client's own
  SNI-carrying ClientHello; falls back the same way any other unresolved
  case does).
- New `stream_sni_route` config key / `--stream-sni-route` CLI flag:
  `"<pattern> <ipv4:port[:weight]>"`. `pattern` is an exact hostname or a
  `*.`-prefixed one, requiring at least one label before the dot (so
  `*.example.com` matches `www.example.com` but never `example.com`
  itself). Repeatable; lines sharing a pattern accumulate into that
  pattern's own independent `magnus_cluster_t` (its own round_robin
  selection, its own passive circuit-breaker state), layered strictly on
  top of the existing `stream_upstream` cluster (roadmap 3a) -- never a
  replacement for it, first-match-wins in config-file order, same
  evaluation order `route` already uses for L7.
- A stream connection gains a third stage ahead of connecting/relaying,
  `MAGNUS_STREAM_PEEKING`, entered only when at least one
  `stream_sni_route` is configured -- zero peeking overhead otherwise,
  byte-identical to 3a's own behavior. The client's initial bytes are
  read directly into the same buffer `magnus_stream_pump()` already uses
  for the client-to-upstream relay, so once a cluster is picked those
  genuine ClientHello bytes are exactly what gets flushed to the backend
  first -- true passthrough, never re-encoded, copied, or held back.
- Every unresolved outcome falls back to the plain `stream_upstream`
  cluster (which `stream_listen` already requires be present): no
  `stream_sni_route` configured at all, a parsed-but-unmatched hostname,
  a definitively-not-TLS or malformed ClientHello, the peek buffer
  filling up without ever resolving, the client closing before sending
  enough bytes, or a new `MAGNUS_STREAM_PEEK_TIMEOUT_SECONDS` (5s) peek
  timeout.
- `/metrics` gained
  `magnus_stream_sni_upstream_healthy{pattern=...,endpoint=...}`,
  mirroring the pre-existing `magnus_stream_upstream_healthy`.
- Deliberately out of scope for this increment: active health checking
  for `stream_sni_route` clusters (passive, connect-result-driven health
  only -- a dynamic, unbounded-in-principle set of small clusters is a
  distinct future increment away from the "one active-probe-array per
  cluster" shape every other cluster in this file already uses); a
  configurable per-pattern load-balancing policy (round_robin only, the
  same scope cut the gRPC cluster's own policy already has).

### Verified

Live, under ASan+UBSan, against real ClientHellos captured from
Python's own `ssl` module (not hand-typed) across three backends:
exact-pattern match, wildcard match, a bare domain correctly *not*
matching its own wildcard pattern, an unmatched hostname, and plain
non-TLS traffic -- the last three all confirmed falling back to the
default cluster, with the matched cases additionally confirmed to relay
the original ClientHello bytes byte-for-byte unmodified (a genuine
passthrough check, not just "which backend answered"). A ClientHello
trickled in dozens of tiny writes (forcing many separate epoll events
through the peek/re-arm loop rather than resolving synchronously in one
read) routed identically to the single-write case. A client that never
sends anything at all was found and fell back to the default cluster
once the peek timeout elapsed, not held open indefinitely. New unit and
fuzz coverage in `tests/test-sni.c`/`tests/fuzz-sni.c` (200k
mutation-based iterations, seeded in part with a real captured TLS 1.3
ClientHello, not only hand-built ones) and new permanent regression
coverage in `tests/test-core.sh`. `make clean && make test` and
`make sanitize` (ASan+UBSan) both green. Image rebuilt,
`./scripts/test-image.sh` passes.

## 1.21.0

### Added

- **TCP passthrough (roadmap 3a): a second, independent listener with
  zero HTTP awareness -- the first Phase 3 (L4) increment.** New
  `stream_listen`/`stream_upstream`/`stream_lb_policy` config keys and
  matching `--stream-listen`/`--stream-upstream`/`--stream-lb-policy`
  CLI flags stand up a raw bidirectional byte relay between a client and
  whichever endpoint a dedicated `magnus_stream_cluster` picks. One
  listener/cluster for this first increment -- multiple simultaneous
  stream listeners is a distinct future increment, not silently
  half-done.
- Reuses the h1/h2 proxy path's existing infrastructure unmodified
  rather than inventing new load-balancing or health-checking code:
  `round_robin`/`least_conn`/`ip_hash` (roadmap 2e-1's rendezvous
  hashing, keyed on client IP since there is no HTTP-level cookie at L4
  -- no cookie-based affinity here), the same circuit-breaker
  trip/cooldown state, and active health checking (roadmap 2f,
  TCP-connect only -- what is actually flowing over a stream connection
  is unknown by design, so an HTTP-level probe would be meaningless, and
  could easily misfire against a non-HTTP protocol).
- New `magnus_stream_conn_t`/`magnus_stream_pipe_t` pair, kept separate
  from the much larger HTTP-oriented `magnus_connection_t` (matching
  this codebase's own precedent of a new protocol surface getting its
  own lightweight state rather than growing the existing one). Drives
  two independent byte pipes with per-direction epoll-interest
  backpressure: a slow destination simply stops its source side being
  read from until the buffered chunk drains, the same discipline the L7
  proxy's own buffered-write path already uses, just with no HTTP
  framing to track alongside it. A standard half-close (one direction
  EOFs and is `shutdown()`-propagated to the other side while the other
  direction keeps flowing) is supported, since an L4 tunnel has no
  request/response boundary to assume one is coming. No retry budget on
  a connect() failure, unlike the L7 proxy path -- there is no "request"
  to safely retry once any bytes have already moved over an
  in-progress byte stream.
- `/metrics` gained `magnus_stream_connections_total`/`_active` (always
  emitted when `stream_listen` is configured), per-direction
  `magnus_stream_bytes_total{direction="client_to_upstream"|
  "upstream_to_client"}`, and `magnus_stream_upstream_healthy{endpoint=...}`
  mirroring the pre-existing `magnus_upstream_healthy`.
- Deliberately out of scope for this increment: TLS passthrough / SNI
  routing (3b) and UDP (3d) remain separate future increments, per the
  roadmap's own Phase 3 scoping.

### Fixed

Found only through this increment's own live testing, not code review:
`/metrics`' fixed response buffer (`MAGNUS_OUTPUT_LIMIT`, 2048 bytes) was
already tight before this increment, and the new stream gauge block
pushed a real multi-cluster deployment's rendered body past it entirely
-- silently emptying the *whole* HTTP response rather than truncating
just the body, since `magnus_prepare_response()`'s own overflow guard
treats "would not fit" as "send nothing", for safety, rather than
partial content. Fixed by growing both `MAGNUS_METRICS_BUFFER`
(1536 -> 8192) and `MAGNUS_OUTPUT_LIMIT` (2048 -> 9216), sized with real
headroom for a fully-populated deployment (the `upstream`,
`grpc_upstream`, and `stream` clusters all near their own max endpoint
count, every gRPC status code, every latency-histogram bucket all
actually present at once), not just enough for this increment's own
test. The HTTP/2 `/metrics` path was never affected -- it allocates its
response buffer dynamically, sized to the actual rendered body, unlike
the HTTP/1.1 path's fixed `connection->output` buffer.

### Verified

Live, under ASan+UBSan, against real backends: `round_robin`
alternation and persistent-connection stickiness (the LB decision is
made once per connection, never per message, since there is no
HTTP-request boundary at L4 to re-decide on); `ip_hash` same-client
determinism; a 300KiB payload relayed byte-for-byte across many
`MAGNUS_PROXY_BUFFER` (16KiB) refills plus a half-close, verified via
SHA-256 against a byte-for-byte echo backend (a labelled echo backend
used elsewhere in this same test run turned out to prefix each
individual `recv()` chunk separately, which would have produced a
false-positive corruption signal on a large payload split across many
chunks -- a test-harness artifact caught and worked around during this
verification, not a product bug); active health check detecting a
killed backend, and its later recovery, with zero stream traffic sent
at all, mirroring the M3/2f-1 discipline. New unit coverage in
`tests/test-config.c` (every `stream_*` key's default, explicit value,
and rejection case). New permanent regression coverage in
`tests/test-core.sh`, including a check that `/metrics`' own last-ever-
emitted line is present and well-formed -- a direct regression guard for
the buffer-size bug above. `make clean && make test` and `make sanitize`
(ASan+UBSan) both green. Image rebuilt, `./scripts/test-image.sh`
passes.

## 1.20.0

### Added

- **Active health check expansion (roadmap 2f-1): HTTP-level probing,
  gRPC cluster coverage, full configurability -- closes out Phase 2's
  own headline scope.** The `upstream` cluster's active probe (M3,
  independent of live traffic) upgrades from a bare non-blocking TCP
  `connect()` to a real HTTP/1.1 `GET` against a configurable
  `health_check_path` (default `/`), success iff the response status
  equals a configurable `health_check_expected_status` (default 200) --
  catching a backend that accepts connections but answers every request
  with a 5xx, which a bare `connect()` could never tell apart from
  actually healthy.
- `health_check_interval_seconds`/`_timeout_seconds`/`_failure_threshold`/
  `_cooldown_seconds` (previously hardcoded constants -- 5s/2s/3/5s) are
  now config keys / matching `--health-check-interval`/`-timeout`/
  `-failure-threshold`/`-cooldown` CLI flags. failure_threshold/cooldown
  feed both clusters' shared circuit-breaker state exactly as they
  already did pre-2f (this was never `upstream`-cluster-specific); only
  the probe *mechanism itself* (path/expected-status) is HTTP-cluster-
  only, for the reason below.
- The `grpc_upstream` cluster -- which had no active probe at all before
  this increment, only whatever live gRPC traffic happened to reveal --
  now gets one too, deliberately kept TCP-connect-only rather than an
  HTTP/1.1 GET: a real gRPC server is typically HTTP/2-only, and a raw
  HTTP/1.1 request line into that socket would get every probe rejected
  by a perfectly healthy backend -- a false-negative regression, not real
  coverage. Still real coverage over the pre-2f state, which ran nothing
  at all. `/metrics` gained `magnus_grpc_upstream_healthy{endpoint=...}`,
  mirroring the `upstream` cluster's pre-existing `magnus_upstream_healthy`.
- Both probe state machines (`CONNECTING` -> HTTP-mode-only `SENDING` ->
  `READING`) share one parameterized implementation
  (`magnus_health_advance()` and friends), dispatched twice per tick --
  once per cluster, each with its own owner map, probe-state array, and
  sockaddr resolver, since the two clusters have independent endpoint
  indices and (the actual reason a unified loop would not simplify
  anything) different probe modes.
- A config reload (`magnus_apply_config()`) now also closes every
  in-flight active probe and resets its next-probe timer, the same
  stale-by-position fix already applied to the two connection pools and
  the reverse-proxy cache on every prior reload-touching increment -- an
  in-flight probe for old position N otherwise belongs to whatever
  backend used to be there, not necessarily the new cluster's position N.
- Deliberately out of scope: a way to disable active checking per cluster
  (it stays unconditionally on, exactly as the pre-2f TCP-only version
  already was); a real gRPC Health Checking Protocol probe
  (`grpc.health.v1.Health/Check`) for the `grpc_upstream` cluster -- a
  much larger increment (full HTTP/2 framing plus a real gRPC service
  call), not a probe-mechanism tweak.

### Fixed

Found only through live testing, not code review: the new HTTP-mode
probe's GET request reaches a real backend's own request handler (unlike
the pre-2f bare `connect()`, which never sent a single byte) -- the
pre-existing reverse-proxy-cache regression test's exact upstream-hit-
counter assertions (`tests/test-core.sh`) broke, because the default
5-second probe interval could now land a background GET on the same fake
upstream those assertions count hits against mid-test. Fixed by pushing
that test's own `--health-check-interval` out past its runtime, not by
changing product behavior -- any real deployment relying on precise
upstream request counts (an unusual thing to depend on, but not unheard
of for billing/quota-style backends) now needs to account for the same
background traffic this feature intentionally introduces.

### Verified

Live, against real backends: an HTTP/1.1 GET against a backend that
accepts every TCP connection but always answers 500 on `/` is found
unhealthy by active checking alone (no proxy traffic sent at all, same
M3 discipline); the same backend configured healthy via a different
`health_check_path` (serving 200 there instead) stays healthy the whole
time, proving the new knobs actually reach the probe rather than the
default silently winning; a `grpc_upstream` endpoint that is simply down
is found (and, once a listener comes up, recovered) purely via the
background TCP-connect probe, with no gRPC traffic sent. New unit
coverage in `tests/test-config.c` (every `health_check_*` key's default,
explicit value, and rejection case). New permanent regression coverage
in `tests/test-core.sh`. `make clean && make test` and `make sanitize`
(ASan+UBSan) both green. Image rebuilt, `./scripts/test-image.sh` passes.

## 1.19.0

### Added

- **Advanced load balancing (roadmap 2e-1): `least_conn` and `ip_hash`
  cluster policies, plus rendezvous-hashed affinity.** New
  `magnus_lb_policy_t` enum (`round_robin` [default, unchanged],
  `least_conn`, `ip_hash`), chosen once per `magnus_cluster_t` -- never
  per request -- via a new `lb_policy=round_robin|least_conn|ip_hash`
  config key / `--lb-policy` CLI flag, validated the same way
  `access_log=on|off` already is (rejects an unrecognized value with a
  line-numbered error). A client's own `MAGNUS_AFFINITY` cookie, when
  present, still always takes priority over whichever policy is
  configured -- the policy only governs a *fresh* (non-sticky) selection.
- `least_conn` picks the healthy endpoint with the fewest requests
  currently in flight against it, ties broken deterministically by lowest
  index. New `magnus_endpoint_t.active_requests` live counter, maintained
  by new `magnus_cluster_endpoint_begin()`/`magnus_cluster_endpoint_end()`
  calls (bounds-guarded against underflow) at every HTTP/1.1 and HTTP/2
  proxy attach/teardown point. Because a proxy attempt can end through
  four different completion paths per protocol (normal teardown; an
  inline connection-pool-checkin branch that bypasses it; and both of
  those again for a `304`-revalidation completion), each begin is guarded
  by a new idempotent `proxy_endpoint_counted` (h1) /
  `cluster_endpoint_counted` (h2) flag so exactly one matching end is ever
  released per begin, regardless of which path an attempt actually exits
  through. `/metrics` gained a per-endpoint
  `magnus_upstream_active_requests` gauge alongside the pre-existing
  `magnus_upstream_healthy`.
- `ip_hash` and the pre-existing cookie-based session affinity now both
  resolve through one shared rendezvous (highest-random-weight) hashing
  primitive, replacing the old naive `hash(key) % count` plus
  linear-probe-forward scheme: an FNV-1a hash of the selection key
  (raw client IP bytes for `ip_hash`, the affinity cookie token for
  sticky sessions) is combined with each candidate endpoint's own
  `"address:port"` identity string, and the highest-scoring healthy
  endpoint wins. This buys a real property modulo hashing does not have:
  adding or removing one endpoint only remaps the traffic that
  endpoint's own score was responsible for, never a wholesale reshuffle
  of every other endpoint's clients -- directly asserted in
  `tests/test-policy.c`.
- Deliberately out of scope for this increment: the separate
  `magnus_grpc_cluster` (its own connection-pooling lifecycle from
  roadmap 2c-5) does not gain a configurable policy or live
  `least_conn` counting here -- it stays hardcoded at `round_robin`,
  since its pooling model would need separate consideration.

### Verified

Against real concurrent/asymmetric-delay backends under ASan+UBSan:
`least_conn` correctly avoided a backend deliberately held busy by an
in-flight request -- busy state confirmed via `/metrics`' own
`magnus_upstream_active_requests` gauge (polled, not a fixed sleep)
before firing two concurrent follow-up requests, both of which landed on
the two idle endpoints instead. `ip_hash` deterministically routed the
same client IP to the same endpoint across both HTTP/1.1 and HTTP/2
requests against one shared cluster. New unit test coverage in
`tests/test-policy.c` (least_conn tie-breaking, underflow-safety of
`_end()`, unhealthy-endpoint skip, affinity-cookie priority over both
policies; ip_hash same-IP determinism, different-IP independence, and
the rendezvous minimal-remapping property) and `tests/test-config.c`
(`lb_policy=` accepted/rejected values). New permanent regression
coverage in `tests/test-core.sh`: three live backends, one held busy on
demand via a `/slow` endpoint, proving `least_conn` avoids it under real
concurrent load, and an `ip_hash` block proving cross-protocol routing
consistency from one client IP. `make clean && make test` and
`make sanitize` (ASan+UBSan) both green. Image rebuilt,
`./scripts/test-image.sh` passes.

## 1.18.0

### Added

- **Reverse-proxy response cache (roadmap 2d-1): a bounded, in-memory,
  LRU-evicted cache shared by both the HTTP/1.1 and HTTP/2 proxy dispatch
  paths, opt-in per route.** New module `magnus_cache.c`/`.h`; new route
  DSL modifier `cache=on|off` (`action=proxy; cache=on`), parsed and
  validated by `magnus_route_parse()` (rejects `cache=on` without
  `action=proxy`).
- Cacheability follows RFC 7234's core rules, narrowed for this
  increment: only `GET` and a `200` response with an explicit freshness
  signal (`Cache-Control: max-age` or `Expires`, `Expires` converted from
  its wall-clock `Date`-relative deadline onto this module's own
  monotonic clock) is ever stored. Excluded outright: `no-store`/
  `private`, a response carrying `Set-Cookie` (a shared cache must never
  serve one client's session state to another), and a `Vary` other than
  (absent or) `Accept-Encoding` (this proxy's own outbound request never
  sends one, so every cached response is always the identity encoding
  regardless of what any given real client asked for -- see
  `magnus_cache_compute_freshness()`'s own comment). `Cache-Control:
  no-cache` still stores the response but marks it immediately stale, so
  every future hit revalidates first rather than serving straight from
  cache.
- A fresh hit is served entirely without touching the upstream, with a
  new `X-Cache: HIT` response header. A stale entry that still carries an
  `ETag`/`Last-Modified` validator triggers a conditional GET
  (`If-None-Match`/`If-Modified-Since` added to the fixed outbound proxy
  request) instead of an unconditional re-fetch; a confirming `304`
  refreshes the entry's freshness window and is answered from the
  *cached* body with no second body transfer at all (`X-Cache:
  REVALIDATED`); an origin that instead sends fresh content on that same
  conditional GET is treated as an ordinary fetch, replacing the stale
  entry (`magnus_cache_store()`'s own replace-in-place behavior).
- Storage: a fixed grid of `MAGNUS_CACHE_MAX_ENTRIES` (512) slots, a
  separate-chaining hash table for lookup, and an intrusive LRU list for
  eviction under either entry-count or byte-budget
  (`MAGNUS_CACHE_MAX_BYTES`, 64MiB) pressure; a single entry over
  `MAGNUS_CACHE_MAX_ENTRY_BYTES` (8MiB) is declined outright, never
  stored truncated. `magnus_cache_store()` always strips any
  `Content-Length` line from the header block it is given -- a stored
  entry's own `Content-Length` is *always* recomputed fresh from the
  actual stored body length at serve time, never replayed from whatever
  the original response claimed, so a caller can never accidentally
  duplicate the header.
- `/metrics` gained `magnus_cache_hits_total`/`_misses_total`/
  `_revalidated_total` (counters) and `magnus_cache_entries`/
  `magnus_cache_bytes` (gauges), always emitted (all zero when no route
  ever enables caching, same as every other counter here starts at zero).
  The whole cache is flushed unconditionally on a config reload (a
  route's own `cache=on`/off, or the cluster a cached host+target would
  now resolve against, may have changed meaning) and at shutdown.
- Deliberately out of scope for this increment: heuristic freshness (no
  fallback when neither `Cache-Control` nor `Expires` is present),
  Vary-keyed multi-variant storage, an explicit purge API, and dogpile/
  request-coalescing protection for a concurrent stampede on a still-
  uncached URL.

### Fixed

Both found only through live testing against a real origin under
ASan+UBSan, not by code review:

- The HTTP/1.1 completion path initially referenced
  `connection->proxy_header_out` (the sanitized response header block) to
  find the cache-storable prefix, on the mistaken assumption that buffer
  stays allocated until the proxy attempt's own teardown. It does not --
  `magnus_proxy_flush()` frees it the moment its own bytes finish
  reaching the client, typically well before the body (and therefore this
  cache store, which only happens at true response completion) does,
  producing a reliably reproducible null-pointer read/crash on the very
  first cacheable response. Fixed by copying the storable header prefix
  out into its own persisted `cache_pending_headers` field at header
  time, mirroring what the HTTP/2 path already had to do (it never had a
  persisted raw-text buffer to defer to in the first place, which is what
  surfaced the HTTP/1.1 analogue as a real gap once compared side by
  side).
- An HTTP/2 cache-hit (and revalidation) response called
  `magnus_h2_push()` immediately after submitting it, mirroring a pattern
  used elsewhere for a mid-stream gRPC submit. Unlike that case,
  `magnus_h2_proxy_start()`/`magnus_h2_proxy_receive_headers()` are always
  reached from *inside* `nghttp2_session_mem_recv2()`'s own callback
  stack, and their own callers still read the stream after they return --
  pushing early can drive `nghttp2_session_mem_send2()` far enough to
  close and free that same stream out from under the caller, a genuine
  heap-use-after-free confirmed under ASan. Fixed by removing the
  premature push entirely: every call path already performs exactly one
  safe push of its own, after the whole callback chain has fully unwound
  (`magnus_h2_service()`'s own post-recv drain, `magnus_h2c_activate()`'s
  own tail, or `magnus_h2_handle_upstream()`'s own tail for the
  upstream-triggered revalidation case).

Verified against a real Python `http.server` origin, across both HTTP/1.1
and HTTP/2 clients, under ASan+UBSan: fresh-miss-then-hit with byte-
identical bodies; cross-protocol sharing in both directions (stored via
one protocol, hit via the other); `no-store` and a `Set-Cookie`-carrying
response each independently confirmed to never cache (every repeated call
still reaching the origin, verified via a request counter the fake origin
itself maintains); revalidation confirmed via `304` (old body preserved,
`X-Cache: REVALIDATED`) and superseded via a fresh `200` (new body
replaces the old, next hit serves the new one); a route with no `cache=`
at all confirmed to never touch the cache regardless of an otherwise
identical upstream/path. New permanent regression coverage in
`tests/test-core.sh` (a `http.server`-based fake origin with a plain
byte-counter file proving zero additional origin round-trips on a hit/
revalidation, matching this project's existing precedent for that style
of upstream fixture). `make clean && make test` and `make sanitize`
(ASan+UBSan) both green. Image rebuilt, `./scripts/test-image.sh` passes.

## 1.17.0

### Added

- **gRPC upstream connection pooling + stream multiplexing (roadmap
  2c-5) -- closes out the gRPC track (2c-1 through 2c-5).** Replaces
  2c-1's design (a fresh TCP + h2 handshake, opened and torn down, per
  single unary RPC) with a small pool of shared, long-lived upstream
  connections per `grpc_upstream` endpoint
  (`MAGNUS_GRPC_POOL_MAX_CONNS_PER_ENDPOINT`, 4) that many concurrent
  client-side gRPC streams multiplex onto, exactly the way a real h2
  client library would.
- New `magnus_grpc_conn_t` type (`magnus_grpc_pool[endpoint][slot]`, a
  fixed 8x4 grid, no allocation): one magnus-owned CLIENT-role nghttp2
  session, one TCP fd, and an intrusive list of every `magnus_h2_stream`
  currently attached to it. Streams attach via
  `nghttp2_submit_request2()`'s own `stream_user_data` parameter
  (immediately followed by `nghttp2_session_set_stream_user_data()`, per
  that function's own documented handling of the "stream not created
  yet" window) rather than a hand-rolled stream-id-to-stream map; every
  nghttp2 callback for the shared session resolves its owning stream via
  `nghttp2_session_get_stream_user_data()` instead of being handed it
  directly as callback context (which is now the connection, needed for
  connection-level events like GOAWAY).
- `magnus_grpc_conn_pick()`: the load-spreading heuristic -- prefers
  opening a brand-new connection over piling onto an existing one
  whenever the pool still has room *and* the least-loaded existing
  connection already has any real load on it at all, so the first few
  concurrent RPCs to an endpoint each get their own dedicated connection
  (no head-of-line blocking between unrelated RPCs), and only once that
  many are already busy does a new RPC genuinely multiplex onto an
  existing one. Not a manual cap on streams-per-connection: nghttp2
  itself queues a request past the peer's own advertised
  `SETTINGS_MAX_CONCURRENT_STREAMS` and sends it automatically once room
  frees up, so magnus never needs to track or enforce that limit for
  correctness, only for this heuristic.
- Connection lifecycle: a connection is recycled (stop accepting *new*
  streams, let attached ones finish, then close) after
  `MAGNUS_GRPC_POOL_MAX_REQUESTS_PER_CONNECTION` (100000) RPCs served or
  `MAGNUS_GRPC_POOL_IDLE_TIMEOUT_SECONDS` (60s) fully idle, and
  unconditionally on a received GOAWAY (tracked via a new session-level
  `on_frame_recv` case) or any fatal I/O error
  (`magnus_grpc_conn_fail()`, which fans a clean `grpc-status: 14`
  UNAVAILABLE out to every RPC still attached via the connection's own
  intrusive stream list, then closes once the last one detaches). Unlike
  the h1 reverse-proxy connection pool (deliberately *not*
  epoll-registered while idle, liveness checked lazily at checkout), an
  idle pooled gRPC connection stays epoll-registered for `EPOLLIN`
  always -- it is a live, shared nghttp2 session that can receive an
  unsolicited GOAWAY or PING at any moment, and this pool is small
  enough (at most `MAGNUS_CONFIG_MAX_GRPC_UPSTREAMS *
  MAGNUS_GRPC_POOL_MAX_CONNS_PER_ENDPOINT` fds) for that to cost
  nothing meaningful.
- New `on_frame_not_send` nghttp2 callback: handles the narrow race where
  a connection's queued HEADERS frame becomes unsendable after all (a
  GOAWAY arriving in the gap between `magnus_grpc_conn_pick()` choosing a
  connection and nghttp2 actually flushing that frame) -- reuses the
  existing `grpc_stream_closed` finalization path (an RPC that closes
  with no `grpc-status` ever named already resolves to a clean
  UNAVAILABLE/UNKNOWN there), no new field needed.
- `magnus_expire_proxies()`'s gRPC branch split in two: per-stream
  concerns (a client's own `grpc-timeout` deadline, and the default
  per-stream read/inactivity timeout once a connection is connected)
  stay in the existing per-stream sweep, since reacting to either
  individually only ever affects the one stream being checked; a
  connect timeout on a still-connecting *new* pooled connection moved to
  a new connection-level sweep, `magnus_grpc_pool_expire()`, since it can
  affect every stream that raced to attach to that same connection at
  once -- reacting to that per-stream in the old shared loop would have
  meant the first stream's own reaction closing the connection while
  later streams in the same loop iteration still pointed at it, a
  use-after-free.
- **Deliberately accepted trade-off, not an oversight:** an *asynchronous*
  connect/I/O failure discovered later via epoll
  (`magnus_grpc_conn_fail()`) no longer transparently retries the
  affected RPC(s) onto a different endpoint the way the pre-pooling
  design did for every RPC (since before 2c-5, "this RPC's own connect
  failed" and "the connection failed" were necessarily the same event).
  A *synchronous* failure picking the very first connection for a
  request still retries a different endpoint before ever answering the
  client, unchanged. See `magnus_h2_grpc_start()`'s own comment for the
  full reasoning -- in short: a pooled connection, once proven, is
  reused across many RPCs, so an async failure now only ever affects the
  (typically one) RPC(s) that happened to be first to a not-yet-proven
  endpoint; UNAVAILABLE (what the client gets instead) is specifically
  the one gRPC status real client libraries already retry on their own
  by default.

### Fixed

- A client-role nghttp2 session that never calls
  `nghttp2_submit_settings()` at least once (with any entry list, even
  empty) silently stops invoking `on_frame_recv`/`on_header` for
  anything the peer sends back past the peer's *own* initial SETTINGS
  frame -- `nghttp2_session_mem_recv2()` keeps reporting the peer's bytes
  as successfully consumed, so this looks exactly like a hung upstream,
  not a protocol violation, without independently instrumenting
  nghttp2's own callback sequence to notice the silence starts right
  after the peer's SETTINGS. Found while building this increment (the
  2c-1..2c-4 code submitted its own settings incidentally, as part of
  capping `MAX_CONCURRENT_STREAMS`, an artifact this rewrite initially
  dropped along with that now-unneeded cap). Fixed by
  `magnus_grpc_conn_open()` always submitting an empty initial SETTINGS
  once per connection, independent of whether magnus has anything of its
  own to advertise.

Verified against a real, independent gRPC implementation (`grpcio`,
Python): 30 concurrent client RPCs against a real `grpcio` server (each
call independently connecting to magnus, a distinct client-side h2
connection per call) measurably multiplexed onto exactly 4 physical
upstream TCP connections (`ss -tn` sampled repeatedly during the burst),
completing in ~0.1s total against a 50ms-per-call server-side delay --
proof of genuine concurrent stream multiplexing within a shared
connection, not merely connection-level parallelism (a purely serialized
4-connections-at-a-time model would have taken roughly 8x that). A
follow-up sequential call after the burst reused one of the same 4
already-open connections rather than opening a new one, confirming
idle-but-healthy connections are kept pooled, not torn down between
bursts. Permanent regression coverage in `tests/test-core.sh` (the
existing 2c-4 multi-endpoint/affinity block) updated so its raw
hand-rolled fake upstreams loop for multiple RPCs per connection instead
of closing after one -- matching both a real gRPC server's own behavior
and what this increment now actually exercises (the block's own repeat
sticky-affinity calls now genuinely reuse a pooled connection rather
than each opening a fresh one). `make clean && make test` and `make
sanitize` (ASan+UBSan) both green. Image rebuilt, `./scripts/test-image.sh`
passes.

## 1.16.0

### Added

- **gRPC routing/observability/affinity polish (roadmap 2c-4) -- closes
  out the gRPC track (2c-1 through 2c-4).**
- New route condition `header_prefix:<name>=<value>` (case-insensitive
  prefix match on a header's value, vs. `header:<name>=<value>`'s exact
  match): specifically because a real gRPC request's `content-type` is
  `application/grpc` with an optional client-chosen codec suffix
  (`+proto`/`+json`/...), which an exact-match condition can never
  reliably cover. `header_prefix:content-type=application/grpc; action=grpc`
  now gates a route on "this looks like gRPC" without needing a
  `path_prefix` catch-all -- not gRPC-specific in the matcher itself
  (general prefix matching on any header), matching how this codebase's
  other route conditions are never narrower than the mechanism actually
  needs to be.
- `magnus_access_log()` gained a `grpc_status` field (only present for a
  gRPC-dispatched request): the wire `:status` a gRPC response carries is
  always 200 regardless of outcome, so `status=` alone could never
  distinguish a successful RPC from a failed one for this traffic. A new
  `/metrics` counter, `magnus_grpc_status_total{code="N"}` (one of the 17
  canonical gRPC status codes), gives the same breakdown for monitoring
  -- gated on at least one `grpc_upstream` being configured at all, and
  only emitting codes that have actually occurred, so a deployment that
  never uses gRPC gets no new `/metrics` output whatsoever.
- Session affinity for `action=grpc` routes, mirroring the h1/h2-proxy
  paths exactly: a valid `MAGNUS_AFFINITY` cookie in the request's
  `cookie` header is preferred for the first connect attempt, and a
  fresh one is issued via `Set-Cookie` on the response headers whenever
  this stream did not arrive with one (or its preferred endpoint could
  not be used). Whether a given real gRPC client actually persists and
  resends it is client-dependent -- most have no automatic cookie jar --
  but reading one is unconditionally safe, and a gateway or client that
  does thread cookies through now gets exactly the same stickiness the
  HTTP/1.x reverse-proxy path already provides.

Deliberately out of scope for this increment: upstream connection
pooling/multiplexing for the gRPC cluster (2c-1's one-shot-per-RPC
connection remains unchanged) -- architecturally comparable in size to
2c-2's own streaming rework, not a "polish" item, and left for a future
increment of its own rather than rushed in here.

Verified against a real, independent gRPC implementation (`grpcio`,
Python): `header_prefix` correctly routes a request carrying
`content-type: application/grpc+proto` (never an exact match for
`application/grpc`) while a request with no grpc-shaped content-type at
all correctly falls through to ordinary dispatch (a plain 404, not a
raw HTTP/2 error); a real client's own `initial_metadata()` shows the
exact `Set-Cookie: MAGNUS_AFFINITY=...` this increment issues; passing
that cookie back as `cookie` metadata on 10 further calls stuck to the
same upstream endpoint every time (both encoded endpoint indices
tested), against a cluster that round-robins between two distinct,
identifiable upstreams when no cookie is presented at all; the access
log and `/metrics` for a successful call, a client-error call, and a
gateway-failure call each showed the correct real gRPC status code
(`0`/`3`/`14`) rather than a uniform `200`. New permanent regression
coverage added to `tests/test-core.sh` (curl plus its own cookie jar
against two distinguishable raw hand-rolled h2 upstreams, no pip
dependency). `make clean && make test` and `make sanitize` (ASan+UBSan)
both green. Image rebuilt, `./scripts/test-image.sh` passes.

## 1.15.0

### Added

- **`grpc-timeout` deadline propagation (roadmap 2c-3).** A client's own
  `grpc-timeout` request header (e.g. `500m`, `5S`, `2M` -- the full unit
  set the gRPC-over-HTTP/2 wire spec defines: hours/minutes/seconds/
  milli-/micro-/nanoseconds) is parsed once at dispatch time into an
  absolute deadline, clamped to a new `MAGNUS_GRPC_MAX_TIMEOUT_MS` (5
  minutes) so no client-claimed deadline can hold an upstream connection
  open indefinitely. When present, that deadline entirely replaces the
  stream's default connect/read timeout budget (the same
  `magnus_expire_proxies()` sweep every proxy/gRPC stream already uses)
  rather than adding to it -- the client has already told magnus exactly
  how long the whole RPC may take. A stream whose deadline is exceeded is
  answered `grpc-status: 4` (DEADLINE_EXCEEDED): a clean "Trailers-Only"
  response if nothing was sent to the client yet, or a stream reset
  (`magnus_h2_grpc_abort()`) if a response was already in flight,
  exactly mirroring 2c-1/2c-2's own connect/mid-stream failure handling.
  A missing or malformed `grpc-timeout` falls back to the pre-existing
  default budget unchanged -- this is purely additive for a request that
  carries none.

Verified against a real, independent gRPC implementation (`grpcio`,
Python): a real client's own `timeout=` call correctly raises
`DEADLINE_EXCEEDED` against a deliberately slow (3-real-second) upstream
when the propagated deadline is shorter than that; an ample deadline
(10s) against the same slow upstream succeeds normally rather than
prematurely cutting it off; a call with no timeout at all still falls
back to the existing default read-timeout behavior unchanged. Separately
verified with a raw, stdlib-only socket client carrying **no client-side
timer of its own** (proving magnus's own server-side sweep enforced the
deadline, not the grpc client library's parallel local one) that a
response arrives around 1 second after a 500ms `grpc-timeout` -- the
sweep's own ~1s granularity -- well before the upstream's unrelated 3s
delay. A dozen malformed `grpc-timeout` values (empty, unit-only,
non-numeric, out-of-range digit counts, negative, embedded NUL, ...)
sent directly over a raw socket all fall back to the default budget
cleanly with no crash, confirmed by continued normal service afterward.
New permanent regression coverage added to `tests/test-core.sh` (a raw
hand-rolled h2 client asserting the same timing bound against a
deliberately slow hand-rolled upstream, no pip dependency). `make clean
&& make test` and `make sanitize` (ASan+UBSan) both green. Image
rebuilt, `./scripts/test-image.sh` passes.

## 1.14.0

### Added

- **True client-streaming, server-streaming, and bidi gRPC support
  (roadmap 2c-2).** Removes 2c-1's "buffer the whole request/response
  before ever touching the upstream or the client" shape on both legs:
  an `action=grpc` stream now dispatches -- and opens its upstream
  connection -- the moment its request HEADERS complete, not once the
  whole request body (if any) has arrived, and the upstream's response
  HEADERS are forwarded to the real client the instant they are known,
  with DATA relayed in each direction as it arrives rather than
  accumulated first. A response chunk sent by a real server-streaming
  RPC now reaches the client within milliseconds of being written,
  independently verified with a timing check against a real `grpcio`
  server (measured ~50ms inter-arrival gaps matching the server's own
  per-chunk delay, not a single post-buffered burst).
- `magnus_h2_dispatch()` is now called as soon as a request's HEADERS
  frame completes, for every route -- not only a gRPC one -- but only a
  gRPC route ever *acts* on that early call; every other route (static,
  `action=proxy`) still only commits once the whole body has arrived
  (tracked by a new `request_end_stream_seen` flag, decoupled from
  "dispatch has run"), exactly matching their existing 1e-1/1e-2
  behavior -- this is a change to *when* the function can be called, not
  to what any non-gRPC route does once it runs.
- Both directions use the same deferred/resume data-provider pattern the
  h1-proxy path (1e-2) already established for its own response leg
  (`stream->deferred` -- now with a `grpc_request_deferred` counterpart
  for the request leg), with the request/response buffers
  (`body`/`io_buffer`) now compacting as they drain instead of growing
  by the exchange's total size, so `MAGNUS_MAX_BODY` bounds how far
  behind either side has fallen, not how long a streaming RPC may run.
- A mid-stream failure after the client has already started receiving a
  response is now a clean stream reset (`magnus_h2_grpc_abort()`, the
  gRPC analogue of the h1-proxy path's own `magnus_h2_proxy_abort()`)
  rather than the impossible-post-headers "Trailers-Only" response 2c-1's
  logic would otherwise have attempted; a connect/transport failure
  before anything was sent to the client still gets 2c-1's own clean
  UNAVAILABLE retry-then-fail behavior. A stream that closes without
  ever naming a real `grpc-status` (a raw mid-exchange transport failure,
  not an RPC-level outcome) is now reported as `grpc-status: 2`
  (UNKNOWN) rather than silently defaulting to success.

Verified against a real, independent gRPC implementation (`grpcio`,
Python) covering every RPC shape: client-streaming (multiple request
messages sent with real inter-message delays, aggregated correctly by
the upstream), server-streaming (5 response chunks with real delays
between them, individually observed as they arrive, with a dedicated
timing assertion confirming genuine incremental delivery rather than a
single post-buffered burst), bidi streaming (interleaved request/response
messages), plain unary calls (still correct through the same
streaming-capable dispatch path -- 2c-1's own coverage re-verified
against this exact build), an RPC-level failure, and a totally
unreachable upstream. New permanent regression coverage added to
`tests/test-core.sh`: a raw, stdlib-only hand-rolled h2 "upstream" (no
h2/hyperframe pip dependency, matching 2c-1's own precedent) sends its
response DATA in two separately-timed chunks, and a raw socket client
asserts a measurable gap between their arrival, proving the wire-level
relay is incremental. Also caught and fixed, during this increment's own
live verification: `magnus_h2_dispatch()`'s new headers-complete calling
convention broke the existing h2c `Upgrade: h2c` path (1e-5), which
synthesizes and dispatches a stream directly rather than going through
the normal HEADERS-frame flow -- fixed by having it mark
`request_end_stream_seen` itself, exactly matching its own existing
"dispatched immediately, as if END_STREAM had just been observed"
contract. `make clean && make test` and `make sanitize` (ASan+UBSan)
both green, including this new incremental-relay traffic. Image
rebuilt, `./scripts/test-image.sh` passes.

## 1.13.0

### Added

- **gRPC reverse-proxy dispatch, unary RPCs (roadmap 2c-1).** A route
  with the new `action=grpc` (mirroring the existing `action=proxy`/
  `deny`/`static` DSL) relays a client h2 stream to a real, HTTP/2-native
  gRPC upstream -- configured via a new, separate `grpc_upstream =
  ipv4:port[:weight]` cluster (config key and `--grpc-upstream` CLI flag,
  repeatable, IPv4-literal only for now). Translating through the
  existing HTTP/1.x reverse-proxy path (`action=proxy`) was never an
  option: a real gRPC server requires actual HTTP/2 trailers
  (`grpc-status`/`grpc-message`) to report an RPC's outcome, which
  HTTP/1.1 cannot carry at all. Magnus now drives the upstream leg with a
  second, magnus-owned CLIENT-role nghttp2 session per stream (a genuine
  h2-to-h2 gateway, not a translation), opened fresh per RPC and torn
  down with it -- no upstream connection pooling/reuse or session
  affinity yet, matching how the very first HTTP/1.1 reverse proxy
  started this same narrow before 1a/1b broadened it.
- Every non-hop-by-hop request header is forwarded to the upstream
  (unlike `action=proxy`'s minimal synthetic request), including `te:
  trailers` -- the one HTTP/2 hop-by-hop exception RFC 9113 8.2.2 still
  allows, and which every real gRPC client sends on every request; a real
  gRPC server (grpc-core) rejects a request missing it outright, which is
  exactly what an early build of this increment hit and fixed before ever
  reaching a live client test.
- The upstream's response headers, body, and trailer (`grpc-status`/
  `grpc-message` plus any custom trailing metadata a service sets) are
  all forwarded to the real client once the whole exchange is known
  complete -- this increment buffers a unary RPC's entire response before
  ever submitting anything to the client, rather than streaming it
  through as it arrives; true client-/server-streaming and bidi support
  is exactly what a later increment (2c-2) is scoped to add.
- Per the gRPC-over-HTTP/2 wire spec, every response -- including a total
  gateway failure (no reachable upstream, a connect failure, or a
  malformed/absent upstream response) -- is answered with `:status 200`;
  a real gRPC client treats any other `:status` as a transport failure
  rather than the RPC-level outcome `grpc-status` conveys, so a gateway
  failure is a "Trailers-Only" 200 response with `grpc-status: 14`
  (UNAVAILABLE), never a raw 502/504 the way `action=proxy` answers one.
  An HTTP/1.1 request against an `action=grpc` route is answered `505`
  explicitly (gRPC requires HTTP/2 end to end) rather than silently
  falling through to static/proxy dispatch.

Verified against a real, independent gRPC implementation (`grpcio`,
Python) on both ends -- not just this project's own code: a successful
unary call through magnus with the correct payload; a service's own
custom trailing metadata (`context.set_trailing_metadata()`) surviving
the round trip; an RPC-level failure (`INVALID_ARGUMENT`) correctly
raising the real client library's own typed error with the right code
and message; and a totally unreachable upstream correctly raising
`UNAVAILABLE` rather than a raw connection error the client library
cannot interpret as gRPC at all. New permanent regression coverage added
to `tests/test-core.sh`, using a raw, stdlib-only hand-rolled h2
"upstream" (no h2/hyperframe pip dependency, matching the 1e-3 Rapid
Reset test's own precedent) that proves the same wire-level plumbing a
curl-only regression can check: status, content-type, and the upstream's
exact response bytes relayed byte-for-byte; the HTTP/1.1 505 rejection;
and the always-200-even-on-total-failure contract. `make clean && make
test` and `make sanitize` (ASan+UBSan) both green, including this new
h2-to-h2 upstream traffic. Image rebuilt, `./scripts/test-image.sh`
passes.

## 1.12.0

### Added

- **Real IP resolution (roadmap 2b): PROXY protocol v1/v2 and RFC 7239
  `Forwarded`/`X-Forwarded-For`, gated entirely on a new `trusted_proxies`
  CIDR allowlist (config-file key and `--trusted-proxies` CLI flag,
  comma-separated).** Disabled by default -- with no `trusted_proxies`
  configured, every connection is completely unaffected, byte-for-byte.
  Trust is always decided against the connection's true, direct TCP peer
  (never against an already-resolved address), so a resolved value from
  one hop can never be replayed to forge trust for the next.
- Accept-time PROXY protocol detection (both the v1 text and v2 binary
  preamble) runs before TLS handshake and before h2c prior-knowledge
  preface detection alike -- a proxy speaking PROXY protocol prepends its
  preamble in plaintext ahead of the actual payload (a TLS ClientHello
  just as much as plain HTTP), so it is read via a raw, MSG_PEEK-based
  `recv()` on the client fd directly, never through OpenSSL, and only for
  a connection whose raw peer address already matched `trusted_proxies` at
  accept time -- making the check a zero-cost no-op for every other
  connection.
- Per-request `Forwarded`/`X-Forwarded-For` resolution (right-most-
  untrusted-hop semantics; `Forwarded` takes precedence when both are
  present) feeds the exact same `client_address` used for `source_cidr`
  route matching, rate limiting, and access logging (`client_ip=` field).
  HTTP/1.1 resolves once per request directly into the connection's own
  address (safe: one request in flight at a time); HTTP/2 resolves into a
  new per-stream `effective_client_address` instead, since one connection
  can multiplex many concurrent streams that must never race each other's
  resolved address.
- `magnus_access_log()`'s signature now takes the client address directly
  (`struct in_addr`, `inet_ntop`'d once inside) rather than each of its
  six call sites separately formatting the same string.
- New `tests/test-realip.c`/`tests/fuzz-realip.c` (200k iterations in
  `make test`, 4M+ verified separately across two seeds) cover CIDR
  matching, XFF/Forwarded resolution (including the spoofing-defense case
  of an untrusted hop's claimed address being ignored), and both PROXY
  protocol versions (valid, incomplete, and malformed preambles).

Verified end to end with hand-crafted raw-socket PROXY v1/v2 preambles
(including one prepended immediately before a real TLS ClientHello, and
another before an h2c prior-knowledge preface, on the very same listener)
plus real `curl` requests carrying `X-Forwarded-For`/`Forwarded` from a
trusted peer, resolving into `source_cidr` route matching (a route
otherwise unreachable becomes deniable once the header resolves into its
CIDR) and the access log alike. Confirmed an untrusted peer's headers are
never honored, a malformed preamble from a trusted peer resets the
connection without affecting any other connection, and a connection that
never speaks PROXY protocol at all falls through to ordinary HTTP
processing unaffected. New permanent regression coverage added to
`tests/test-core.sh`. `make clean && make test` and `make sanitize`
(ASan+UBSan) both green. Image rebuilt, `./scripts/test-image.sh` passes.

## 1.11.0

### Added

- **Negotiated gzip compression for static files over HTTP/1.1 and HTTP/2.**
  Clients offering a comma-delimited `gzip` token in `Accept-Encoding` now
  receive compressible MIME types with `Content-Encoding: gzip`, `Vary:
  Accept-Encoding`, and the exact compressed `Content-Length`. The same zlib
  gzip-wrapper implementation serves both protocols; clients that do not
  offer gzip and binary formats such as PNG/JPEG remain byte-for-byte on the
  previous path.
- Compression is deliberately bounded to files from 256 bytes through 8 MiB.
  This avoids gzip overhead on tiny bodies and caps per-response memory/CPU:
  bounded files are fully compressed before headers are emitted, while larger
  files keep streaming unchanged. A compressed plain-HTTP response uses a
  buffered socket write because transformed bytes cannot use zero-copy
  `sendfile`; every uncompressed plain-HTTP response retains `sendfile`.
  This increment is static-files-only and gzip-only. Proxied-response
  compression, streaming/chunked compression for larger files, Brotli, and
  zstd are explicitly deferred.
- New `tests/fuzz-compression.c`: `magnus_accepts_gzip()` parses the
  client-supplied `Accept-Encoding` header directly, so it gets the same
  mutation-based fuzz harness (200k iterations in `make test`, 4M+ verified
  separately across two seeds) every other new parser of untrusted bytes in
  this project already gets, matching the standing rule
  `magnus_base64.c`'s own fuzz harness (1.10.0) followed.
- The HTTP/2 static-compressed-body data-provider callback reuses the
  existing `magnus_h2_read_io_buffer()` (already serving `/healthz`/
  `/metrics`, 1.9.0) rather than a near-duplicate sibling -- setting
  `stream->response_complete = true` before submitting is all a
  fully-buffered, synchronously-ready body like this ever needed.

Verified with an assert-based zlib round-trip unit test covering empty,
threshold-sized, and multi-call-sized inputs, plus permanent HTTP/1.1 and
HTTP/2 regressions using curl's independent `--compressed` decoder. Coverage
also confirms requests without gzip stay plain, PNG stays uncompressed, and a
raw gzip response decodes byte-exact through `gzip -dc`. Independently
re-verified end to end against the exact 256-byte/8-MiB boundary (255 vs.
256 vs. 257 bytes), a real HTTP/2 request, 30 concurrent compressed
requests, and a HEAD request (compressed `Content-Length`, no body) --
`make sanitize` (ASan+UBSan) clean against all of it with no fd or memory
leaks. `make clean && make test` and `make sanitize` both green. Image
rebuilt, `./scripts/test-image.sh` passes.

## 1.10.0

### Added

- **h2c: cleartext HTTP/2** (roadmap Phase 1e-5), plain (non-TLS) listener
  only -- the existing TLS+ALPN h2 path (1e-1) is completely separate and
  unaffected. Both RFC 9113 entry points:
  - *Prior knowledge* (3.4): a connection's very first bytes are checked
    against the 24-byte h2 client preface before ever attempting
    HTTP/1.1 parsing on them, at most once per connection.
  - *Upgrade: h2c* (3.2): an ordinary HTTP/1.1 request with the right
    `Connection`/`Upgrade`/`HTTP2-Settings` headers gets a
    `101 Switching Protocols`, and the same request becomes h2 stream 1
    via nghttp2's own upgrade support -- scoped to a request with no
    body for this increment (the common real-world case).
  Both entry points reuse every h2 feature already shipped unmodified:
  static files, proxy dispatch, Rapid-Reset hardening,
  `/healthz`/`/metrics`/rate limiting (sharing the same rate-limit state
  HTTP/1.1 and TLS+ALPN h2 already share) -- h2c only changes how a
  connection becomes h2, not anything about how it is dispatched
  afterward.
- New module `magnus_base64.c`/`.h`: a small, standalone base64url
  (RFC 4648 §5) decoder for the HTTP2-Settings header value --
  independently unit-tested and fuzzed (`tests/fuzz-base64.c`, 200k
  iterations in `make test`, 4M+ verified separately across two seeds),
  matching this project's standing rule that any new parser of untrusted
  bytes gets its own fuzz harness.

Verified against real, independent HTTP/2 tooling (curl's own native
`--http2-prior-knowledge` and `--http2`-against-a-plain-`http://`-URL
support): both entry points return real h2 responses for a static file, a
proxy route, `/healthz`, and HEAD/404; the rate limiter's shared state and
the proxy path both work identically to the TLS+ALPN case; an ordinary
HTTP/1.1 client on the very same plain listener is completely unaffected.
`make clean && make test` and `make sanitize` both green, including
~24 connections cycling both entry points against the sanitized build
with no fd or memory leaks. Image rebuilt, `./scripts/test-image.sh`
passes.

## 1.9.0

### Added

- **HTTP/2 operational parity: `/healthz`, `/metrics`, per-client-IP rate
  limiting** (roadmap Phase 1e-4). The h2 dispatch path now answers
  `/healthz` and `/metrics` exactly like HTTP/1.1 does, and applies the
  same per-client-IP rate limiter -- genuinely shared with HTTP/1.1 (the
  limiter is keyed by client IP alone), not a separate h2-only limiter a
  client could evade by splitting traffic across both protocols.
  `/healthz`/`/metrics` stay exempt from the limiter even while it is
  exhausted, matching HTTP/1.1's own exemption exactly.
- `magnus_build_metrics()`: the Prometheus `/metrics` text body is now
  built by one shared function instead of HTTP/1.1-dispatch-inline code,
  so HTTP/1.1 and h2 cannot drift into reporting different numbers for the
  same process (a pure extraction -- no behavior change for HTTP/1.1).
- `magnus_h2_submit_text()`: submits a small in-memory canned-text h2
  response, reusing the same `io_buffer`/data-provider plumbing the 1e-2
  proxy path already streams an upstream response through (the read
  callback was accordingly generalized and renamed,
  `magnus_h2_read_proxy_body` -> `magnus_h2_read_io_buffer`, rather than
  given a near-duplicate sibling).

Verified against real HTTP/2 tooling (`curl --http2`): `/healthz`/
`/metrics` (GET and HEAD) answer correctly and stay exempt from rate
limiting even mid-exhaustion; an ordinary static file hits a configured
burst-of-2 limit and 429s on the third rapid request, recovering after the
refill window, mirroring the pre-existing HTTP/1.1 rate-limit test's own
shape exactly; a same-client HTTP/1.1 request is confirmed rejected too
while the h2-side bucket is still exhausted, proving the shared-state claim
end to end rather than by code inspection alone. `make clean && make test`
and `make sanitize` both green against this exact live traffic. Image
rebuilt, `./scripts/test-image.sh` passes.

## 1.8.0

### Added

- **HTTP/2 Rapid-Reset-class abuse hardening + graceful GOAWAY on
  shutdown** (roadmap Phase 1e-3). A per-connection, one-second sliding
  window now caps how many new request streams a connection may open
  (100/s) and how many `RST_STREAM` frames the client may send on it
  (50/s) -- the latter targeting the Rapid Reset (CVE-2023-44487) shape
  directly: open a stream, immediately reset it, repeat as fast as
  possible. Either cap being exceeded terminates the connection
  immediately, using the same mechanism nghttp2 already uses internally
  for its own PING/SETTINGS-ack-flood and CONTINUATION-flood protections
  (both already covered for free before this release, since any negative
  return from `nghttp2_session_mem_recv2()` was already treated as fatal
  -- only Rapid-Reset-style `RST_STREAM` abuse and raw new-stream floods
  had no cap of their own). Legitimate traffic is completely unaffected;
  the caps are per-connection, not a global circuit-breaker.
- Graceful shutdown now sends every still-open h2 connection a real
  GOAWAY frame before the existing hard-close loop tears everything down
  on `SIGTERM`, instead of an abrupt drop.

Verified against a real, independent HTTP/2 client (Python's `h2`/
`hyperframe` packages, manually; a raw stdlib-only hand-rolled client --
matching 1d WebSocket's own precedent of not adding a pip dependency to
the test suite -- for the permanent `tests/test-core.sh` regression
coverage): a legitimate client's ordinary traffic is unaffected by
either cap; a simulated Rapid Reset attack and a simulated raw
new-stream flood are each cut off within a few hundred attempts of a
thousand attempted; a real GOAWAY frame is confirmed to arrive before
the connection closes on `SIGTERM`; both caps confirmed per-connection.
`make clean && make test` and `make sanitize` both green, including
repeated attack cycles back-to-back against the sanitized build with no
fd or memory leaks. Image rebuilt, `./scripts/test-image.sh` passes.

## 1.7.0

### Added

- **HTTP/2 proxy dispatch + H2↔H1 upstream translation** (roadmap Phase
  1e-2). An h2 stream matched to `action=proxy` (or the literal `/proxy`
  prefix) now resolves through the exact same route matcher HTTP/1.1
  uses and is relayed to an ordinary HTTP/1.x upstream over the same
  connection pool/cluster/health-check state every HTTP/1.1 proxy
  attempt already shares -- the response is translated into h2 response
  headers and DATA frames (streamed via nghttp2's data-provider
  callback, not buffered whole) rather than raw bytes. Request bodies
  (POST/PUT/...) are buffered from DATA frames up to the same 1 MiB cap
  the HTTP/1.1 path enforces and relayed to the upstream; session
  affinity (the `MAGNUS_AFFINITY` cookie) and the connect/read timeout
  budgets both work the same way as HTTP/1.1, now applied per h2 stream
  rather than per connection -- necessary since one h2 connection can
  have many streams each proxying to a (possibly different) upstream
  concurrently, unlike HTTP/1.1's one-attempt-at-a-time model. GET/HEAD
  and now any other method with a body; still no h2c (cleartext
  upgrade); GOAWAY/RST_STREAM handling, Rapid-Reset-class hardening,
  per-client-IP rate limiting, and `/healthz`/`/metrics` for the h2 path
  are not wired in yet -- see docs/development-roadmap.md's 1e entry for
  what remains.
- `magnus_http_extract_cookie()` (`magnus_http.h`/`.c`) is now a public
  helper rather than a `magnus_http_parse()`-internal static function,
  so h2 request handling (which never goes through
  `magnus_http_parse()`'s wire-format parsing at all) can extract the
  `MAGNUS_AFFINITY` cookie value the same way HTTP/1.1 does, rather than
  a second, potentially-divergent implementation.

Verified end-to-end against real, independent HTTP/2 tooling (curl
`--http2`) through a real HTTP/1.1 backend, not just this project's own
code: GET and POST-with-body (small and one spanning multiple
relay-buffer chunks) both proxy correctly with the upstream's own
response headers (Content-Type, a custom header) forwarded; HEAD; a
deny route still denies over h2; an oversized body 413s instead of
hanging; the connection pool is reused across sequential requests
(proven by the backend's own per-accept connection identity coming back
unchanged); 20 genuinely concurrent proxied requests all come back
correct with no cross-stream corruption and leave no leaked fds behind;
ordinary static-file serving (1e-1) keeps working on the same connection
a proxy route also matches on. Along the way, found and fixed a real bug
during this verification: after a proxy-dispatched stream's upstream
connect completed and its request+body were sent (all driven by that
one `EPOLLOUT` event), the upstream fd was left armed for `EPOLLOUT`
only -- nothing ever re-armed it for `EPOLLIN`, so the response could
never be noticed until the periodic timeout sweep gave up on it 10
seconds later (every request "succeeded" but via a 504, not the actual
response). Root-caused by comparing against `magnus_handle_upstream()`'s
own HTTP/1.1 equivalent, which does re-arm in this exact spot; fixed by
doing the same. `make clean && make test` and `make sanitize` both green
(the sanitized build itself served the same live curl traffic above,
including the concurrent and oversized-body cases, without either
sanitizer tripping). Image rebuilt, `./scripts/test-image.sh` passes.

## 1.6.0

### Added

- **HTTP/2, static files only** (roadmap Phase 1e-1). TLS connections now
  negotiate ALPN, offering exactly `"h2"`; a client that agrees gets a
  real nghttp2-driven HTTP/2 session (HPACK, stream multiplexing,
  SETTINGS/PING/WINDOW_UPDATE all handled by nghttp2 itself, not
  hand-rolled parsing) instead of HTTP/1.1 -- a client that never offers
  `"h2"` is unaffected, since ALPN is additive, not a mode switch on the
  listener. Each stream dispatches to the same static-file-serving
  helpers (`magnus_open_static()`/`magnus_content_type()`) the existing
  HTTP/1.1 GET path already uses, so both protocols agree on path
  resolution and traversal safety by construction, and large files
  stream out via a `pread()`-based nghttp2 data provider rather than
  being buffered whole. GET/HEAD only; no request body support (not
  meaningful for a static-file response); no h2c (cleartext upgrade --
  ALPN-negotiated TLS only); no proxy/route dispatch over h2 yet (a
  future 1e increment -- see docs/development-roadmap.md).
- New module `magnus_h2.c`/`.h`: the ALPN protocol-selection callback,
  kept small and standalone (no dependency on the rest of magnus.c) so
  it is independently unit-tested (`tests/test-h2.c`) and fuzzed
  (`tests/fuzz-h2.c`, 200k iterations in `make test`, 4M+ verified
  separately across two seeds) exactly like every other new
  attacker-facing parser this project has added. Deliberately **not**
  using `SSL_select_next_proto()` -- that function's contract for a
  malformed/empty client protocol list was itself the subject of a real
  CVE (CVE-2024-5535); a direct, bounds-checked scan of the RFC 7301
  length-prefixed client list for the one candidate protocol this
  project offers sidesteps that history entirely. The actual nghttp2
  session/stream wiring (request dispatch, the data-source read
  callback, the send/recv pump) lives directly in `magnus.c`, not
  `magnus_h2.c`, since nghttp2's callback model needs the same direct
  access to this file's static-file and socket-I/O internals that the
  1b/1d route-matching and WebSocket-relay wiring already needed.
- An h2-negotiated connection's outbound nghttp2-serialized bytes get
  copied out to a per-connection scratch buffer whenever a socket write
  can't take everything in one non-blocking call, since
  `nghttp2_session_mem_send2()` only guarantees its returned pointer
  stays valid until the *next* nghttp2 call -- unlike this project's
  other relay buffers (WebSocket, proxy body), which own their own
  memory throughout.

Verified end-to-end against real, independent HTTP/2 tooling (curl
`--http2`, `openssl s_client -alpn h2`), not just this project's own
code: ALPN actually lands on `h2` (curl reports HTTP version 2), a small
file and a ~66 KB file (spanning several `pread()`-chunked data-provider
callbacks) both come back byte-exact, HEAD returns no body with the
correct Content-Length, a missing file 404s, a client that never offers
`h2` at all still gets ordinary HTTP/1.1, an unsupported method 405s, an
oversized `:path` 414s, 50 concurrent requests leave no leaked fds behind,
and several requests genuinely multiplexed over one connection all come
back correct. `make clean && make test` and `make sanitize` both green
(the sanitized build itself served the same live curl/openssl traffic
above without either sanitizer tripping). Image rebuilt (now installs
`libnghttp2-dev` at build time and ships `libnghttp2.so.14` alongside the
existing OpenSSL/zlib/zstd runtime libraries), `./scripts/test-image.sh`
passes.

## 1.5.0

### Added

- **WebSocket proxying** (roadmap Phase 1d). `/proxy/*` (or any matched
  `action=proxy` route) now recognizes an RFC 6455 upgrade attempt
  (`Upgrade: websocket`, a `Connection` header containing "upgrade", and
  a non-empty `Sec-WebSocket-Key`) and relays it to the upstream instead
  of rejecting it or handling it as an ordinary request: the handshake's
  `Upgrade`/`Connection`/`Sec-WebSocket-Key`/`-Version`/`-Protocol`/
  `-Extensions` headers are forwarded verbatim (magnus does not
  negotiate or interpret a subprotocol or extension itself -- see
  below), and if the upstream answers `101 Switching Protocols`, that
  response is relayed back byte-exact and the connection pair becomes a
  raw bidirectional pipe for as long as it stays open. Any other status
  for the same attempt is just an ordinary proxied response -- magnus
  never promises the client an upgrade, only relays the attempt.
- The relay itself is bounded-chunk byte shoveling with proper
  backpressure in both directions (mirroring the pattern already used
  for ordinary proxied response bodies), not per-frame reassembly: since
  the proxy never interprets WebSocket frame *content*, correctness and
  memory-safety come from the same bounded streaming already proven for
  HTTP bodies, regardless of what the relayed bytes mean at the framing
  layer. This also means an extension like permessage-deflate "just
  works" through the proxy without magnus needing to understand it --
  the bytes are never decoded here at all.
- New module `magnus_ws.c`/`.h`: an RFC 6455 frame-*header* parser
  (opcode, fin, mask bit, minimal-encoding-checked 7/16/64-bit payload
  length, masking-direction validation, control-frame constraints),
  independently unit-tested and fuzzed (`tests/fuzz-ws.c`, 200k
  iterations in `make test`, 4M+ verified separately across two seeds
  under ASan+UBSan). Deliberately **not** wired into the live relay path
  in this release -- the relay does not need it for correctness or
  safety (see above) -- but built and verified now as real groundwork
  for live per-frame policy (size limits, masking-direction enforcement)
  as a future increment, per "a new binary parser is new attack surface"
  in docs/development-roadmap.md's 1d entry.
- A WebSocket-upgraded connection is never returned to the 1.2.0
  connection pool (it is not a reusable HTTP/1.1 keep-alive connection
  once upgraded) and is exempt from every Content-Length-based framing
  decision that ordinary proxied responses go through, since none of it
  applies to a 101 response.

Verified end-to-end against a real, independent WebSocket client library
(Python's `websockets` package, not this project's own code exercising
itself): 5 sequential text-message round trips, a 1 KiB binary message,
and a 50 KB message that crosses multiple relay-buffer chunks
(`MAGNUS_PROXY_BUFFER`, 16 KiB) all echoed correctly through the proxy,
including with 3 concurrent WebSocket connections and an ordinary
(non-WebSocket) proxied request against the same magnus instance staying
unaffected throughout. New coverage in `tests/test-core.sh` uses a
minimal stdlib-only (no added test dependency) raw-socket handshake and
echo check instead, verifying the relayed `Sec-WebSocket-Accept` is
byte-exact (proof the handshake was not corrupted or recomputed) and
that a >16 KiB payload echoes correctly. Along the way, found and fixed a
real bug during this verification: the *existing* header-sanitizing
function tokenizes its input buffer in place (replacing `\r`/`\n` with
NUL as part of `strtok_r`), and the new WebSocket code was reading from
that now-corrupted buffer to build the verbatim 101 relay -- root-caused
by a raw-socket handshake dump showing literal NUL bytes where `\r`
should have been, fixed by giving the sanitizer its own scratch copy.
`make clean && make test` and `make sanitize` both green. Image
rebuilt, `./scripts/test-image.sh` passes.

## 1.4.0

### Added

- **DNS-resolved upstreams** (roadmap Phase 1c). An `upstream` entry
  (config key or `--upstream` CLI flag) can now be a hostname instead of
  a literal IPv4 address -- resolved asynchronously so the event loop
  never blocks on a lookup, kept up to date on a fixed refresh interval
  (`MAGNUS_DNS_REFRESH_SECONDS`, 30s), and "keep last-known-good" on a
  failed refresh rather than tearing down a perfectly good address over
  one DNS hiccup. A hostname that has never resolved yet fails proxy
  attempts cleanly (502) exactly like any other unreachable endpoint --
  no special-case handling needed for that state, since the endpoint's
  address simply is not a valid IP literal until the first successful
  resolution overwrites it.
- New module `magnus_dns.c`/`.h`: one dedicated background thread runs
  the system's own (blocking) `getaddrinfo()`, with completion delivered
  to the main thread via an eventfd registered in the normal epoll loop
  -- **the first thread this codebase has ever had**. Deliberately built
  on `getaddrinfo()` rather than a hand-rolled DNS wire-format parser:
  it hands correctness (search domains, `/etc/hosts`, NSS modules) to
  the C library instead of adding a new parser of untrusted bytes: the
  trade-off is that the standard API exposes no TTL, so refresh is a
  fixed interval, not the record's actual TTL (a real limitation,
  documented rather than glossed over).
- The DNS worker thread never touches anything outside `magnus_dns.c`'s
  own mutex-protected request/result queues; only the main thread's
  drain callback reaches into the rest of `magnus.c` (overwriting a
  cluster endpoint's address in place), so the only place a data race
  could exist is inside that one module. Verified with a dedicated
  `make tsan` target (ThreadSanitizer) on top of the usual
  `make clean && make test`/`make sanitize`, all green -- this codebase's
  first use of a sanitizer built specifically for concurrency, for its
  first genuinely concurrent code.
- Verified end-to-end, not just via the module's own unit test
  (`tests/test-dns.c`, real worker thread + real eventfd + real
  `getaddrinfo()` against `localhost`, no mocking): a `--config`
  hostname upstream and a CLI `--upstream` hostname both resolve and
  proxy correctly against a real backend, a config reload re-resolves
  and keeps working, and a hostname that cannot resolve at all fails
  proxy attempts cleanly without affecting magnus's own health. New
  coverage in `tests/test-core.sh`.

## 1.3.0

### Added

- **Advanced routing** (roadmap Phase 1b). A repeatable `route = ...`
  config key (and `--route` CLI flag) evaluated in file order -- first
  match wins -- ahead of the existing built-in dispatch, gated out for
  the admin channel exactly like the literal `/proxy/*` prefix already
  is. Each route combines up to 8 conditions with AND: `host`,
  `path_prefix` (must start with `/`), `method`, `header:<name>`,
  `cookie:<name>`, `query:<name>`, and `source_cidr` (`a.b.c.d/prefix`),
  plus exactly one action -- `proxy` (relay to the existing upstream
  cluster; forwards the request's full path, unlike the literal
  `/proxy/*` dispatch, which strips that prefix -- a route isn't anchored
  to any particular prefix, so there's nothing to strip), `deny` (403,
  short-circuits ahead of everything else including the method check),
  or `static` (no config-schema-visible effect yet beyond letting a
  route's conditions gate an otherwise-ordinary static-file request --
  see "Not yet done" below). A route with zero conditions is a valid
  catch-all. `magnus_config_load()` rejects a `proxy`-action route
  outright if no `upstream` is configured, same validate-up-front
  philosophy as every other cross-field constraint.
- `magnus_http_parse()` now retains the Host header's value (not just
  its presence) and every header field (name and value, up to 32) for
  `magnus_http_header_find()` to look up -- what `header:<name>`
  route conditions (and any future consumer) match against.
- New module `magnus_route.c`/`.h`: the compact single-line route DSL
  parser and the request matcher, independently unit-tested
  (`tests/test-route.c`) and fuzzed (`tests/fuzz-route.c`, mutating the
  Host/Cookie/query-string bytes a route condition actually evaluates
  against real request data -- not the DSL parser itself, which only
  ever sees admin-controlled config content, the same reasoning that
  keeps `magnus_config.c` unfuzzed).

### Not yet done (see docs/development-roadmap.md)

- `action=static` does not yet support a per-route root override (routes
  can gate *whether* a request reaches static serving, not redirect it
  to a different directory) -- deferred, not silently unsupported: the
  config schema has no `root=` key on a route spec at all yet.
- `query`/`cookie` condition values are compared case-sensitively (opaque
  data, not a protocol token); `host`/`method`/`header` are
  case-insensitive (HTTP convention). No regex matching -- `path_prefix`
  is a literal, anchored prefix only.

Verified end-to-end against a real backend and real loopback client IPs
(not just the module's own unit tests): host+path_prefix routed to proxy
with the full path forwarded correctly, a non-matching Host falling
straight through to ordinary dispatch, a header-gated deny returning 403
only when the header is present, a source_cidr match against real
127.0.0.1 traffic denying only within its `path_prefix`, and the
pre-existing literal `/proxy/*` dispatch completely unaffected. New
coverage in `tests/test-core.sh`. `make clean && make test` and
`make sanitize` both green; image rebuilt,
`./scripts/test-image.sh` passes.

## 1.2.0

### Added

- **Upstream connection pool** (roadmap Phase 1a). The reverse proxy no
  longer opens a fresh TCP connection to the backend for every request:
  a per-endpoint pool of idle, still-live connections is checked before
  connecting, and a connection is returned to the pool (instead of
  closed) once its response completes cleanly. Bounded at 8 idle
  connections per endpoint, a 60s idle timeout, and 100 requests per
  connection before it is retired -- all enforced without registering
  idle connections with epoll (liveness is checked cheaply, via a
  non-blocking `MSG_PEEK`, at checkout time instead), which keeps the
  pool from needing a second "this event belongs to an idle, currently
  unowned upstream connection" branch in the main dispatch loop. A config
  reload flushes the whole pool (endpoint *position* in a freshly loaded
  cluster is not guaranteed to be the same backend it was before the
  reload).
- **Client-facing keep-alive for proxied responses.** Previously every
  proxied response force-closed the client connection regardless of what
  the client asked for -- found while starting the connection-pool work:
  pooling the *upstream* leg requires knowing a response's exact length
  up front (Content-Length) rather than relying on the upstream closing
  its end to signal completion, and once that's known there is no reason
  not to extend the same length-based framing to the *client* leg too.
  `magnus_proxy_sanitize_response_headers()` now reports whether the
  upstream response has a single well-formed Content-Length (and no
  Transfer-Encoding, which is not decoded), and the client-facing
  `Connection` header is `keep-alive` whenever the client's own request
  wanted it and the response is unambiguously framed -- `close`
  otherwise, exactly as before. The upstream leg's poolability and the
  client leg's keep-alive are decided independently: an upstream that
  sends `Connection: close` doesn't force the client connection closed,
  and a client that wants `close` doesn't prevent the upstream connection
  from being pooled for someone else's next request.
- A duplicate or malformed upstream `Content-Length` is rejected (502),
  matching the request-side parser's existing duplicate-header handling.

Verified: a body-echoing/connection-identifying backend confirmed actual
TCP reuse (many requests over one pooled connection, including from
*different* client connections reusing the same pooled upstream
connection), the 100-requests-per-connection retirement landing exactly
on schedule, a config reload flushing the pool, and a backend dying while
its connection sits idle in the pool recovering cleanly (502, not a hang
or crash) rather than corrupting a later request. `make clean && make
test` and `make sanitize` both green, including this behavior exercised
end-to-end through `tests/test-core.sh` under ASan+UBSan. Image rebuilt
and `./scripts/test-image.sh` passes.

## 1.1.0

### Added

- **The reverse proxy now relays any HTTP method with a request body**
  (POST, PUT, PATCH, DELETE, ...), not just GET/HEAD. Found the gap the
  same way as the 1.0.1 fix: a live check (`curl -X POST .../proxy/...`)
  returned 405, and the cause was structural, not a one-line bug -- the
  method allowlist was global (every route, including `/proxy/*`), and
  the HTTP parser never read a request body at all (no Content-Length
  handling, no buffering, nothing to relay). Both had to change:
  - `magnus_http_parse()` now parses `Content-Length` (rejecting a
    second one, and any value that doesn't parse as a plain decimal --
    both request-smuggling-relevant ambiguities). `Transfer-Encoding`
    (chunked or otherwise) is rejected outright with 400 -- not yet
    supported, and silently mishandling it would be a framing hazard;
    it also forecloses the classic Content-Length/Transfer-Encoding
    smuggling ambiguity for free.
  - A request with a body is now buffered (bounded at 1 MiB, 413 Payload
    Too Large beyond that) before dispatch, across as many non-blocking
    reads as it takes -- mirroring the existing header-accumulation
    state machine -- so a pipelined next request on the same
    connection is never mistaken for body bytes or vice versa.
  - `/proxy/*` is now exempt from the GET/HEAD-only check and forwards
    the buffered body to the upstream with a `Content-Length` header;
    every other route (static files, `/healthz`, `/metrics`, `/`) is
    unchanged and still GET/HEAD-only.
  - Verified end-to-end against a body-echoing backend: POST/PUT/PATCH/
    DELETE with small bodies, a 675 KB body split across many reads
    (byte-for-byte sha256 match), a >1 MiB body correctly 413'd, a
    chunked request correctly 400'd, a POST to a non-proxy path still
    405, and four chained requests (mixed body/no-body) over one reused
    connection each framed correctly. Clean under `make sanitize`
    (ASan+UBSan). New regression coverage in `tests/test-core.sh`.

## 1.0.1

### Fixed

- **Missing `TCP_NODELAY` on accepted client sockets.** Every response
  written on a reused keep-alive connection sat in Nagle's algorithm
  waiting for the peer's ACK, and a peer using standard delayed-ACK
  (the Linux default) could hold that ACK back for up to ~40ms -- the
  two stalls compounded into a fixed ~40ms floor on *every* request
  over a keep-alive connection, independent of load. `Connection: close`
  traffic never showed it (a single write immediately followed by a
  close has nothing left to wait for), which is what let it ship in
  1.0.0 unnoticed. Reproduced directly: with the fix, the same
  static-file/keep-alive/concurrency-16 scenario went from 390 req/s at
  a 41ms average to 17,485 req/s at a 0.9ms average. Fix: set
  `TCP_NODELAY` on every accepted public-listener socket (the admin
  Unix domain socket is unaffected -- TCP_NODELAY does not apply there).
  Regression test added to `tests/test-core.sh`: 20 sequential requests
  over one reused connection must finish in well under the ~800ms a
  40ms-per-request floor would produce.

## 1.0.0

First stable release. Independent C17/epoll HTTP(S) gateway with a
data-plane/control-plane split.

### Data plane (`magnus`)

- Single-threaded, non-blocking epoll event loop; no dependency on an
  external web server runtime.
- Strict HTTP/1.0 and HTTP/1.1 parser, keep-alive, 8KiB request cap.
- Safe document root resolution, MIME typing, HEAD support, zero-copy
  `sendfile` static delivery.
- OpenSSL-based TLS 1.2/1.3 transport (TLS 1.1 and below rejected).
- Non-blocking reverse proxy under `/proxy/*`: connect/read timeouts,
  bounded retry budget, hop-by-hop header stripping, streaming responses
  without blocking the event loop on slow upstreams or large payloads.
- Multi-endpoint cluster routing (weighted round-robin) wired to live
  traffic; active (periodic probe) and passive (live-traffic) health
  checks share one circuit-breaker state per endpoint.
- Cookie-based session affinity (index-encoded, not hash-based) with
  plain round-robin fallback when no valid cookie is present.
- Per-client-IP token-bucket ingress rate limiting with a bounded
  eviction table; `/healthz` and `/metrics` are exempt.
- Structured, request-ID-keyed access log: buffered writer, 1-in-N
  sampling, or fully disabled (`access_log` / `access_log_sample`).
- Prometheus-style `/metrics`: request counters, per-endpoint health
  gauges, and a request-latency histogram.
- Admin channel isolation: `--admin-socket`/`admin_socket` moves
  `/metrics` onto an owner-only Unix domain socket; `/healthz` stays on
  the public port for load-balancer probes; admin connections are exempt
  from the rate limiter; access control is the socket's own filesystem
  permissions.
- Slowloris guard: an absolute header-phase deadline independent of the
  idle timer, so trickling a request one byte at a time can no longer
  hold a connection open indefinitely.
- Per-request 128-bit trace ID, `/healthz`, explicit structured error
  responses, graceful shutdown on SIGTERM/SIGINT.
- Hardened build/runtime: RELRO+NOW, `_FORTIFY_SOURCE=2`, non-root
  container user, read-only rootfs.

### Control plane (`magnusd` / `magnusctl`)

- Strict config-file schema shared by every binary (single source of
  truth); `magnusctl check` validates a file standalone.
- `magnusd` supervises one `magnus` child: validates a config before
  ever applying it, reloads via SIGHUP (existing connections drain under
  the old generation, new connections see the new one), and rolls back
  to the last-known-good config -- respawning the child if it did not
  survive -- on a failed reload or an unexpected crash.
- Audit log of every reload/rollback/shutdown decision.
- `magnusctl reload` / `status` / `shutdown` talk to a running `magnusd`
  over a Unix domain socket.
- Shipped as a separate control-plane binary, not bundled into the
  data-plane container image.

### Verification

- Unit tests for the HTTP parser, policy engine (WRR/circuit-breaker/
  rate-limit), proxy header handling, and config schema.
- `tests/test-core.sh` / `tests/test-control-plane.sh`: end-to-end
  integration coverage across proxy timeouts, cluster routing/failover,
  session affinity, rate limiting, admin-channel isolation, access-log
  modes, slowloris behavior, malformed requests, and FD exhaustion.
- `tests/fuzz-http.c`: seeded, deterministic, in-process mutation fuzzer
  for the HTTP parser (`make test` runs 200k iterations; separately
  verified with 4M+ iterations across multiple seeds).
- `make sanitize`: full test suite clean under AddressSanitizer and
  UndefinedBehaviorSanitizer, zero findings.
- Container image builds and passes its smoke test: 9,207,512 bytes
  (~8.78 MiB), non-root, read-only rootfs.
