# Changelog

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
