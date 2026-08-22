#ifndef MAGNUS_QUIC_H
#define MAGNUS_QUIC_H

/* Phase 4a (roadmap): QUIC transport only -- a UDP listener wired into
 * Magnus's own epoll reactor that completes a real ngtcp2 handshake
 * using the ngtcp2 + libngtcp2_crypto_ossl + nghttp3 stack chosen in
 * docs/phase4-http3-quic-dependency-evaluation.md and verified working
 * against this host's OpenSSL in docs/phase4-spike-results.md.
 *
 * Deliberately NOT in this increment (left for 4b and later, same
 * "narrow the first sub-phase" pattern Phase 1e and Phase 3 both used):
 *   - nghttp3 / HTTP/3 request handling over an established QUIC
 *     connection -- streams are accepted (so a real client's handshake
 *     doesn't stall waiting on flow control) but their data is only
 *     drained for flow-control bookkeeping, never parsed
 *   - retry-based stateless address validation (anti-amplification) --
 *     an unmatched Initial is accepted unconditionally
 *   - connection migration / path validation beyond what a single,
 *     non-migrating handshake needs
 *   - 0-RTT
 * See docs/phase4a-quic-transport.md for the full scope note and the
 * concrete plan for each gap above.
 */

#include <stdbool.h>
#include <time.h>

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

#endif
