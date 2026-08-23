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
 * compression alike, on all three protocols; 2a-7 streaming compression
 * for HTTP/1.1 static files past 2a's own 8 MiB bound, the first slice
 * of the item this list itself used to carry -- see that item's own
 * narrowed scope below)
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
 *   - streaming compression for HTTP/2 and HTTP/3 static files, and for
 *     proxy-dispatch responses on all three protocols, past 2a's own 8
 *     MiB bound -- 2a-7 narrowed this from "streaming/chunked
 *     compression above 8 MiB, cross-cutting across h1/h2/h3" to just
 *     its first slice (HTTP/1.1 static files); h2/h3 don't need this
 *     increment's own close-delimited-framing workaround at all (no
 *     Content-Length is ever required for a DATA-frame response, unlike
 *     HTTP/1.1 without chunked encoding), so they are plausibly an
 *     *easier* follow-up, not a harder one, once someone picks this
 *     back up
 *   - a real HTTP/1.1 `Transfer-Encoding: chunked` response writer,
 *     which would let 2a-7's own streaming-compressed responses keep
 *     the connection alive afterward instead of always closing -- 2a-7
 *     deliberately chose the narrower of the two ways to frame a
 *     response with no Content-Length known ahead of time (RFC 9112
 *     6.3 permits either), reusing every existing byte-writing
 *     primitive unchanged rather than building this codebase's first
 *     chunked writer just to ship the first slice
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
#define MAGNUS_VERSION "1.43.0"

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
