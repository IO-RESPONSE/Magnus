#ifndef MAGNUS_QUIC_H
#define MAGNUS_QUIC_H

/* Phase 4 (roadmap): QUIC transport (4a; retry-based stateless address
 * validation added 4k; connection migration / reactive path validation
 * added 4l) + HTTP/3 (4b static files, 4c /healthz//metrics, 4d
 * "/proxy" dispatch, 4e static-file gzip compression, 4f `route` table
 * dispatch, 4g retry-on-connect-failure for proxy dispatch, 4h
 * cookie-based session affinity for proxy dispatch, 4i reverse-proxy
 * response caching for proxy dispatch, 4j upstream connection pooling
 * for proxy dispatch, 2a-4 proxy dispatch response compression -- the
 * last of h1/h2/h3 to get it, closing out roadmap 2a's own cross-
 * protocol compression story; Real IP (roadmap 2b) extended to HTTP/3's
 * own source_cidr route matching and client-IP-based cluster selection;
 * 2a-5 zstd joining gzip as a second negotiable encoding, 2a-6 Brotli
 * joining as a third, both across static-file and proxy-dispatch
 * compression alike, on all three protocols; 2a-7/2a-8/2a-9 streaming
 * compression for static files past 2a's own 8 MiB bound, on HTTP/1.1,
 * HTTP/2, and HTTP/3; 2a-10/2a-11/2a-12 the same for proxy dispatch
 * responses, HTTP/1.1 then HTTP/2 then HTTP/3 -- closing out the whole
 * "streaming/chunked compression above 8 MiB" thread this list has
 * carried since 2a itself. 2a-8 fixed a real, previously-latent bug it
 * found along the way: magnus_h2_drain_send() (magnus.c) retried a
 * failed/partial SSL_write() against a *different* buffer address than
 * the original attempt saw, violating OpenSSL's own same-address retry
 * contract -- silently truncated any h2-over-TLS response large enough
 * to hit a partial write mid-transfer. 2a-9 found a second: zstd's own
 * ZSTD_compressStream2() (and Brotli's BrotliEncoderCompressStream())
 * do not guarantee output on every call, only forward input
 * consumption -- a single-call-per-invocation h3 read_data callback
 * deadlocked outright for both encoders on any file needing more than
 * one packet's worth of compressed output, since nghttp3's own resume
 * mechanism has nothing to trigger it without a chunk ever having been
 * offered; fixed by looping internally until real progress happens
 * (and applied to HTTP/2's own equivalent callback too, which never
 * reproduced a hang in testing but relied on nghttp2's own eager retry
 * timing rather than on any real guarantee to avoid it). 2a-11 found a
 * third, real but self-inflicted this time: its own first draft of
 * struct magnus_h2_stream's teardown freed proxy_stream_compress_inbuf
 * directly, then unconditionally again inside magnus_h2_stream_
 * teardown_upstream() (which already owns that cleanup, same as
 * compress_capture/cache_capture) -- a genuine double-free, caught by
 * a real heap-corruption abort under this increment's own new h2
 * streaming test, not a sanitizer run. 2a-12 found a fourth, the most
 * subtle of the whole thread: its own async producer function called
 * magnus_quic_proxy_maybe_complete() unconditionally whenever a
 * compressed chunk was produced, but that function independently
 * re-derives "is this response complete" from raw upstream byte
 * counts alone -- true the moment every raw byte has been *read*, not
 * once the compressor has actually *flushed* (a still-pending
 * finish=true call can remain outstanding at that exact moment, since
 * the loop's own finish flag is computed once per iteration and so
 * necessarily lags by one). Calling it early marked the response
 * complete while the compressor was still open, letting the very next
 * pull report end-of-stream on a chunk that silently dropped gzip's
 * own trailer and the last still-buffered bytes -- every byte actually
 * offered still reached the client correctly, byte counts even
 * matched, which is exactly why this one was a genuinely subtle catch;
 * fixed by gating the call on the compressor itself being done, not
 * merely on a chunk having been produced. Unlike every static-file
 * streaming path, 2a-10/2a-11/2a-12's own proxy-dispatch input only
 * ever arrives *pushed*, asynchronously, by the ordinary uncompressed
 * relay's own recv() off the upstream socket, not pulled on demand --
 * HTTP/1.1's own magnus_proxy_flush() reuses proxy_buffer/_length/
 * _sent directly as the compressor's pending-input queue; HTTP/2's own
 * magnus_h2_proxy_stream_compress_response() is a push-driven fill
 * function (unlike 2a-8's own *pull*-based read_callback) that reuses
 * stream->io_buffer as the compressed *output* queue magnus_h2_read_
 * io_buffer() already knows how to drain; HTTP/3's own magnus_quic_
 * proxy_stream_compress_response() reuses body_chunk/body_chunk_
 * length/body_chunk_offered/body_chunk_end_offset/body_offered_total/
 * body_acked_total/nghttp3_wants_resume directly instead, the same
 * ACK-gated discipline every other h3 body source already established
 * -- every one of the three adds only a dedicated staging buffer
 * (proxy_stream_compress_inbuf) for the not-yet-compressed raw bytes
 * recv() delivers, and all three simply wait for the next upstream
 * read when they run out of input, rather than fetching more
 * themselves the way a pread()-backed loop safely could. 2a-13 (magnus.c):
 * this codebase's first real HTTP/1.1 `Transfer-Encoding: chunked`
 * response writer (RFC 9112 7.1) -- the follow-up 2a-7's own doc
 * comment always named as a natural next step, once it existed to
 * build on. Every produced chunk is framed *in place*, no extra copy
 * of the data itself: a fixed-width, zero-padded 5-hex-digit chunk-
 * size header is written into a small reserved prefix immediately
 * before wherever the real chunk data already landed, followed by its
 * own trailing CRLF, and the fixed 5-byte last-chunk ("0\r\n\r\n", no
 * trailer section) gets appended directly after the final real chunk's
 * own trailing CRLF the moment the underlying producer reports done --
 * all in the same buffer fill, so the existing "drain output, then
 * finish once done" loop shape every streaming write loop in magnus.c
 * already has needed no other change to support it. Applied to 2a-7's
 * own HTTP/1.1 static-file streaming-compressed responses, which now
 * keep the connection alive afterward (per the client's own stated
 * preference) instead of always closing, same as any other response
 * here. 2a-14 applied the identical writer to 2a-10's own HTTP/1.1
 * proxy-dispatch streaming-compressed responses too, via a third
 * sentinel (`(size_t) -3`) on magnus_proxy_sanitize_response_headers()
 * alongside the existing `(size_t) -1`/`(size_t) -2` ones -- emits
 * Transfer-Encoding: chunked and leaves keep_client_alive to the
 * client's own stated preference, instead of `(size_t) -2`'s own
 * forced Connection: close (still used by h2/h3 proxy dispatch
 * streaming compression, 2a-11/2a-12, since chunked encoding is an
 * HTTP/1.1-only concept neither protocol has any use for).
 * -- a UDP listener wired into Magnus's own epoll reactor that
 * completes a real ngtcp2 handshake using the ngtcp2 +
 * libngtcp2_crypto_ossl + nghttp3 stack chosen in
 * docs/phase4-http3-quic-dependency-evaluation.md and verified working
 * against this host's OpenSSL in docs/phase4-spike-results.md, then
 * serves real HTTP/3 traffic over it -- src/magnus_quic.c's own section
 * comments (search "roadmap 4") have each sub-phase's exact scope.
 *
 * Deliberately still not here, each its own real future increment, not
 * silently missing (same "narrow the first cut, extend later" pattern
 * every sub-phase below has already used once):
 *   - 0-RTT (4a)
 *   - PROXY protocol v1/v2 for QUIC: genuinely has no analogue here
 *     (no raw preamble concept once ngtcp2/nghttp3 have already framed
 *     a stream's headers, unlike a plain TCP byte stream) -- Forwarded/
 *     X-Forwarded-For (roadmap 2b, now wired in above) cover the same
 *     "trusted intermediary forwards the real client address" need
 *     without requiring one, since those are ordinary HTTP header
 *     fields parsed identically regardless of protocol
 * See docs/phase4-spike-results.md for 4a's own standalone
 * verification, and CHANGELOG.md for each shipped sub-phase's detail.
 */

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/* Single source of truth for the version string every protocol's own
 * Server/version-report surface uses -- magnus.c no longer defines its
 * own copy (see the .c file's own history), just includes this header,
 * same as magnus_quic.c's HTTP/3 responses (roadmap Phase 4b) do. Not
 * QUIC-specific in what it represents; kept here rather than a new
 * single-purpose header only because magnus_quic.c already needed one
 * shared string constant and this was the simplest way to give magnus.c
 * and magnus_quic.c one shared definition instead of two that could
 * drift. */
#define MAGNUS_VERSION "1.60.0"

/* One-time global setup: builds the QUIC-specific SSL_CTX (TLS 1.3
 * only, ALPN "h3", the same server certificate/key the HTTPS listener
 * already uses -- no separate QUIC cert) and initializes the
 * libngtcp2_crypto_ossl backend. Must be called at most once, before
 * magnus_quic_create_listener(), only when QUIC is actually enabled.
 * Returns 0 on success, -1 on failure (message already on stderr). */
int magnus_quic_init(const char *tls_cert, const char *tls_key);

/* Creates, binds (0.0.0.0:`port`), and returns a non-blocking UDP
 * listener fd for the caller to register with epoll (EPOLLIN). Returns
 * -1 on failure (message already on stderr). */
int magnus_quic_create_listener(unsigned port);

/* Services one epoll-readable event on the fd magnus_quic_create_listener()
 * returned: drains pending datagrams (bounded per call, so one very
 * busy QUIC listener cannot starve every other fd this process is
 * also servicing), demultiplexes each by QUIC connection ID against
 * the connections this process already knows about, creates a new
 * server-side ngtcp2 connection for an unmatched Initial packet, and
 * drives the handshake state machine forward. */
void magnus_quic_listener_service(int listener_fd);

/* Periodic pass (call once per magnus.c's existing per-second sweep,
 * same cadence as magnus_expire_idle()/magnus_health_tick()/etc.) over
 * every active QUIC connection: applies ngtcp2's own timer expiry
 * (retransmission back-off, idle timeout, end of the post-close
 * draining period) and reaps any connection that expiry closes out.
 * `listener_fd` is where any packet expiry generates (e.g. a PTO
 * retransmission) gets sent from. */
void magnus_quic_tick(int listener_fd, time_t now);

/* Tears down every active QUIC connection and frees the QUIC-specific
 * SSL_CTX. Called once at shutdown, after the listener fd itself has
 * already been removed from epoll and closed. */
void magnus_quic_shutdown(void);

/* Entry point from magnus.c's main epoll loop (roadmap 4d, proxy
 * dispatch): call for any event whose fd is not already recognized by
 * an existing *_owner[fd] table. Returns true (and has already handled
 * the event) if `fd` belongs to a QUIC proxy dispatch's own upstream
 * connection; false otherwise, so the caller's own dispatch chain can
 * move on to its next check exactly like every other such table there
 * already does. */
bool magnus_quic_handle_upstream_event(int fd, uint32_t flags);

/* Roadmap 4k: lifetime count of Retry packets actually sent (address
 * validation, RFC 9000 8.1.2) -- magnus_build_metrics() (magnus.c)
 * publishes this as magnus_quic_retry_total. Always callable, QUIC
 * enabled or not (reads 0 if it was never touched, same as any other
 * counter here before its first increment). */
unsigned long long magnus_quic_retry_total(void);

/* Roadmap 4l: lifetime count of successful path validations (a
 * client's own connection migrating/NAT-rebinding to a new address,
 * proven via PATH_CHALLENGE/PATH_RESPONSE, RFC 9000 9.3) --
 * magnus_build_metrics() (magnus.c) publishes this as
 * magnus_quic_migration_total. Always callable, QUIC enabled or not. */
unsigned long long magnus_quic_migration_total(void);

#endif
