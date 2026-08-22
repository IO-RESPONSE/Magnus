# Magnus

Magnus is a **lightweight enterprise Web/Application Gateway** developed
independently by IORESPONSE.

## Release: 1.0.0

## Features

- Independent C17/epoll event core with no dependency on an external web
  server runtime
- Strict HTTP/1.0/1.1 parser, keep-alive, 8KiB request cap
- Safe document root, MIME/HEAD, zero-copy `sendfile` static delivery
- Negotiated gzip compression for 256-byte through 8 MiB compressible static
  files over HTTP/1.1 and HTTP/2; other responses retain their streaming path
- Structured access log keyed by request ID
- Native phase API: ingress → route → response → log
- Per-request 128-bit trace ID, health endpoint, explicit error responses
- Graceful shutdown on SIGTERM/SIGINT
- RELRO/NOW, FORTIFY, non-root user, read-only rootfs
- OpenSSL-based TLS 1.2/1.3 transport (TLS 1.1 rejected)
- Non-blocking `/proxy/*` reverse proxy: connect/read timeouts, bounded
  retry budget, hop-by-hop header stripping, streaming without blocking
  the event loop on slow upstreams or large responses; relays any HTTP
  method with a request body (POST/PUT/PATCH/DELETE/...), buffered up to
  1 MiB before dispatch -- every other route stays GET/HEAD-only
- Per-endpoint pool of idle upstream connections (avoids a fresh TCP
  handshake per proxied request); a response with a known length also
  keeps the *client* connection alive, independent of whether the
  upstream leg is pooled
- Advanced routing: repeatable `route` rules (host/path-prefix/method/
  header/header-prefix/cookie/query/source-CIDR, combinable with AND,
  first match wins) ahead of the built-in dispatch, actioned as
  proxy/deny/static/grpc; a `action=proxy` route may also opt into the
  reverse-proxy cache via `cache=on`
- DNS-resolved upstreams: an `upstream` entry may be a hostname,
  resolved asynchronously on a dedicated background thread (this
  codebase's first thread) so the event loop never blocks; fixed-interval
  refresh, keeps the last-known-good address on a failed refresh
- WebSocket proxying: `/proxy/*` (or a matched `action=proxy` route)
  relays an RFC 6455 upgrade handshake and, once the upstream confirms it
  with 101, becomes a raw bidirectional byte pipe for the life of the
  connection
- HTTP/2: TLS ALPN negotiates `"h2"` when the client offers it (HTTP/1.1
  otherwise, unaffected); an nghttp2-driven session multiplexes static
  file responses and, for a request matching `action=proxy` (or `/proxy`),
  a full reverse-proxy round trip to an HTTP/1.x upstream over the same
  connection pool/cluster/health state HTTP/1.1 proxying uses -- request
  bodies included, translated to/from h2 DATA frames; `/healthz`,
  `/metrics`, and per-client-IP rate limiting all work the same way over
  h2 as HTTP/1.1, genuinely sharing the same rate-limit state across both
  protocols. h2c (cleartext HTTP/2, plain listener only -- both prior
  knowledge and `Upgrade: h2c`) reaches every one of the above the same
  way; only how a connection *becomes* h2 differs from TLS+ALPN
- HTTP/2 Rapid-Reset-class abuse hardening: a per-connection, one-second
  window caps both new-stream opens and client-sent `RST_STREAM` frames,
  terminating a connection that exceeds either (the CVE-2023-44487
  shape) while leaving ordinary traffic and every other connection
  unaffected; graceful shutdown sends a real GOAWAY frame to every open
  h2 connection before closing it
- Multi-endpoint cluster routing, wired to live traffic; active and passive
  (live-traffic) health share one circuit-breaker state; cookie-based
  session affinity; per-client-IP ingress rate limiting. Active checking is
  a real HTTP/1.1 `GET` against a configurable `health_check_path`,
  success iff the response status matches a configurable
  `health_check_expected_status` (`--health-check-path`/`--health-check-
  expected-status`, plus `--health-check-interval`/`-timeout`/`-failure-
  threshold`/`-cooldown`) -- catching a backend that accepts connections
  but answers every request with a 5xx. The gRPC cluster gets active
  checking too (TCP-connect only, since a real gRPC server is typically
  HTTP/2-only)
- Real IP resolution behind a trusted reverse proxy: PROXY protocol v1/v2
  (detected before TLS handshake or h2c preface, for either entry point)
  and RFC 7239 `Forwarded`/`X-Forwarded-For` (right-most-untrusted-hop,
  `Forwarded` taking precedence), gated entirely on a `trusted_proxies`
  CIDR allowlist (`trusted_proxies=`/`--trusted-proxies`, default off);
  the resolved address feeds `source_cidr` route matching, rate limiting,
  and access logging alike, always trusted against the connection's real
  direct TCP peer so a spoofed hop can never forge trust for the next
- gRPC reverse-proxy dispatch, including client-streaming, server-
  streaming, and bidi RPCs: a route with `action=grpc` relays a client h2
  stream to a real, HTTP/2-native gRPC upstream (`grpc_upstream=`/
  `--grpc-upstream`, its own separate cluster, IPv4-literal only) over a
  second, magnus-owned CLIENT-role nghttp2 session -- a genuine h2-to-h2
  gateway, not a translation through the HTTP/1.x `action=proxy` path,
  since a real gRPC server requires actual HTTP/2 trailers
  (`grpc-status`/`grpc-message`) HTTP/1.1 cannot carry. Dispatch happens
  as soon as request headers complete, and DATA is relayed incrementally
  in each direction as it arrives rather than buffered first, so a
  streaming RPC's messages reach the other side as the application
  actually sends them, not all at once at the end. Every non-hop-by-hop
  request header (including the RFC 9113 `te: trailers` exception every
  real gRPC client sends) is forwarded, and the upstream's response
  headers/body/trailer -- including custom trailing metadata -- are
  relayed the same way; per the gRPC-over-HTTP/2 wire spec, every
  response (including a total gateway failure) carries `:status 200`,
  with `grpc-status` conveying the real outcome. An HTTP/1.1 request
  against an `action=grpc` route gets an explicit `505`, never a silent
  proxy/static fallback. A client's own `grpc-timeout` request header is
  propagated into an absolute deadline (clamped to 5 minutes) that
  replaces the stream's default connect/read timeout budget; exceeding
  it answers `grpc-status: 4` (DEADLINE_EXCEEDED) rather than waiting on
  a slow or stuck upstream indefinitely. A new `header_prefix:<name>=<value>`
  route condition (case-insensitive prefix match on a header's value)
  can gate `action=grpc` on `content-type` alone
  (`header_prefix:content-type=application/grpc`), covering every codec
  suffix a real client might send; the access log and a new
  `magnus_grpc_status_total{code="N"}` `/metrics` counter report the
  real gRPC outcome, since the wire `:status` alone is always 200; and
  session affinity (the same `MAGNUS_AFFINITY` cookie the h1/h2-proxy
  paths already issue) works identically for gRPC traffic. Upstream
  connections are pooled and multiplexed per endpoint (a small
  per-endpoint pool of long-lived connections, up to
  `MAGNUS_GRPC_POOL_MAX_CONNS_PER_ENDPOINT`, that many concurrent RPCs
  share via nghttp2's own stream multiplexing) rather than a fresh
  TCP+h2 handshake per RPC -- pool for parallelism, multiplex for
  overflow once the pool is warm; a connection recycles gracefully after
  a request-count/idle budget or on GOAWAY/a fatal I/O error
- Reverse-proxy response cache: a bounded, in-memory, LRU-evicted cache
  shared by both the HTTP/1.1 and HTTP/2 proxy dispatch paths (one cache;
  a response stored via one protocol is servable to the other), opt-in
  per route via a new `cache=on` route modifier
  (`action=proxy; cache=on` -- never a global default). Only a GET with an
  explicit freshness signal (`Cache-Control: max-age` or `Expires`) is
  ever stored; `no-store`/`private`, a response carrying `Set-Cookie`, or
  a `Vary` other than (absent or) `Accept-Encoding` are excluded outright.
  A fresh hit is served without touching the upstream at all
  (`X-Cache: HIT`); a stale entry with an `ETag`/`Last-Modified` is
  revalidated via a conditional GET instead of a full re-fetch, and a
  confirming `304` is answered from the cached body with no second
  transfer (`X-Cache: REVALIDATED`)
- Advanced load balancing: `lb_policy=round_robin|least_conn|ip_hash`
  (`--lb-policy`), chosen once per cluster -- `round_robin` (smooth
  weighted, the long-standing default) is unchanged; `least_conn` sends a
  fresh request to whichever healthy endpoint currently has the fewest
  requests in flight (a new per-endpoint live counter, exposed via
  `/metrics` as `magnus_upstream_active_requests`); `ip_hash` and the
  pre-existing `MAGNUS_AFFINITY` cookie affinity both resolve through one
  rendezvous (highest-random-weight) hash, so adding or removing an
  endpoint only remaps the traffic that endpoint's own score was
  responsible for. A client's own affinity cookie, when present, always
  takes priority over whichever policy is configured
- L4 TCP passthrough: a second, independent listener with zero HTTP
  awareness (`stream_listen`/`stream_upstream`/`stream_lb_policy`,
  `--stream-listen`/`--stream-upstream`/`--stream-lb-policy`) -- raw bytes
  relayed bidirectionally to whichever endpoint a dedicated stream cluster
  picks, reusing the same load-balancing policies, circuit-breaker state,
  and TCP-connect-only active health checking the h1/h2 proxy clusters
  already have, unmodified. Per-direction backpressure (a slow
  destination stops its source side being read from until buffered bytes
  drain) and a standard half-close (one direction finishing while the
  other keeps flowing) are both supported; no retry budget on a
  connect() failure, since there is no "request" to safely retry once
  bytes are already in flight. `/metrics` gained
  `magnus_stream_connections_total`/`_active`,
  `magnus_stream_bytes_total{direction=...}`, and
  `magnus_stream_upstream_healthy{endpoint=...}`
- TLS passthrough / SNI routing: routes a stream connection by its TLS
  ClientHello hostname without ever terminating TLS
  (`stream_sni_route`/`--stream-sni-route`, `"<pattern>
  <ipv4:port[:weight]>"`, pattern an exact hostname or a `*.`-prefixed
  one). Layered on top of the plain `stream_upstream` cluster above, never
  a replacement for it -- an unmatched hostname, a non-TLS connection, a
  malformed ClientHello, or a client that never sends enough to decide all
  fall back to it. The client's initial bytes are peeked (never modified)
  just far enough to find the SNI extension, then relayed to the matched
  endpoint exactly as received -- genuine passthrough, not a translation.
  `/metrics` gained `magnus_stream_sni_upstream_healthy{pattern=...,
  endpoint=...}`
- UDP passthrough: a fourth, independent listener, plain `SOCK_DGRAM`
  with no `accept()`/handshake of any kind (`udp_listen`/`udp_upstream`/
  `udp_lb_policy`/`udp_session_idle_seconds`/`udp_max_sessions`,
  `--udp-*`). One NAT-style session per (source IP, source port) tuple,
  each with its own dedicated `connect()`ed backend socket -- the same
  load-balancing policies as every other cluster (`ip_hash` keyed on
  source IP alone), but no health tracking of any kind (a UDP
  `connect()` cannot fail the way TCP's own does). `udp_max_sessions`
  (default 1024) is the explicit answer to UDP's own unbounded-session
  memory risk: once full, a new client's packet is simply dropped, never
  evicting an existing session (which a trivially source-spoofable
  protocol would turn into a denial-of-service primitive). A session
  pointed at a backend that surfaces `ECONNREFUSED` (via a matching ICMP
  port-unreachable) is torn down immediately rather than waiting out the
  idle timeout. `udp_listen` may equal `port`/`stream_listen` without
  conflict -- UDP and TCP occupy independent port namespaces. `/metrics`
  gained `magnus_udp_sessions_total`/`_active`,
  `magnus_udp_bytes_total{direction=...}`, and
  `magnus_udp_upstream_active_sessions{endpoint=...}`
- PROXY protocol emission: prefixes magnus's own outbound connection to a
  TCP stream backend with a PROXY protocol preamble carrying the real
  client (source IP, source port), the reverse direction from the
  Real IP resolution above (`stream_proxy_protocol=off|v1|v2`,
  `--stream-proxy-protocol`) -- without it, every relayed connection looks
  to the backend like it originates from magnus's own address. `off` by
  default; applies uniformly to the whole `stream_listen` surface,
  regardless of which cluster a connection ends up at (the plain
  `stream_upstream` cluster or a matched `stream_sni_route` one). Both
  wire formats supported: v1 text (`PROXY TCP4 <src> <dst> <sport>
  <dport>\r\n`) and the fixed 28-byte v2 binary layout. Built once per
  connection and always flushed ahead of any relay traffic -- including a
  peeked TLS ClientHello prefix (SNI routing above), which still arrives
  byte-for-byte immediately after the header
- `magnusd`/`magnusctl` control plane: a strict config-file schema shared
  by both, SIGHUP hot reload in `magnus` (existing connections drain under
  the old generation, new ones see the new one), automatic health-checked
  rollback on a failed reload or an unexpected crash, and an audit log
- Prometheus `/metrics` (counters, per-endpoint health, and a request
  latency histogram); access log is buffered, 1-in-N sampleable, and can
  be turned off entirely
- Admin channel isolation: `/metrics` moves to an owner-only Unix domain
  socket when `--admin-socket`/`admin_socket` is configured (`/healthz`
  stays on the public port for load-balancer health checks); access
  control is that socket's own filesystem permissions
- Slowloris guard: a connection's first request has a hard header-phase
  deadline independent of the idle timer, so trickling one byte at a time
  no longer holds a connection open indefinitely
- Verified clean under ASan+UBSan across the full test suite (`make
  sanitize`), and against a 4M-iteration mutation fuzz run of the HTTP
  parser (`tests/fuzz-http.c`, `make test` runs 200k of it by default)
- QUIC transport (roadmap Phase 4a): `--quic-port`/`quic_listen` opens a
  UDP listener that completes a real RFC 9000 handshake (ngtcp2 +
  `libngtcp2_crypto_ossl`, terminating TLS 1.3 with the same
  certificate/key the HTTPS listener uses) integrated into Magnus's own
  epoll reactor rather than a bundled event loop; ALPN negotiates `h3`
  so a real client's handshake completes normally
- HTTP/3 static-file serving (roadmap Phase 4b, on top of the QUIC
  transport above): nghttp3 wired directly into the same connection
  table, GET/HEAD only, reusing the identical path-resolution/MIME
  logic the HTTP/1.1 and HTTP/2 static paths already use
  (`src/magnus_static.h`) so all three protocols agree on it by
  construction
- HTTP/3 `/healthz`/`/metrics` (roadmap Phase 4c): same
  `magnus_build_metrics()` every protocol's `/metrics` reports from, so
  none can drift into different numbers for the same process;
  `/metrics` is withdrawn once `--admin-socket`/`admin_socket` is
  configured -- same isolation boundary the main TCP listener already
  applies -- while `/healthz` stays public
- HTTP/3 `"/proxy"` dispatch (roadmap Phase 4d): a real HTTP/1.1
  upstream relay over HTTP/3, reusing the same cluster
  selection/passive-health tracking (`src/magnus_policy.h`) and
  response-header sanitization (`src/magnus_proxy.h`) HTTP/1.1 and
  HTTP/2 already share, so a killed backend produces the same clean
  502 and the same `magnus_upstream_healthy` degradation regardless of
  which protocol the client used
- HTTP/3 static-file gzip compression (roadmap Phase 4e): the same
  scope compression 2a shipped for HTTP/1.1 and HTTP/2, extended to
  the third protocol -- same eligibility window, same
  `Vary: Accept-Encoding`. Proxied-response compression, Brotli/zstd,
  and streaming compression above the 8 MiB bound remain deferred on
  every protocol, not a QUIC-specific gap
- HTTP/3 `route` table dispatch (roadmap Phase 4f): host/path-prefix/
  method/header/header_prefix/cookie/query/source-CIDR matching, the
  same DSL and matcher (`src/magnus_route.h`) HTTP/1.1 and HTTP/2
  already share -- `action=proxy`/`deny`/`static`/`grpc` (the last
  answered with an explicit 505, since this codebase's gRPC dispatch
  is HTTP/2-native-only). Real-IP-aware `source_cidr` matching remains
  a later increment -- see `src/magnus_quic.h`
- HTTP/3 proxy dispatch retry-on-connect-failure (roadmap Phase 4g): a
  failed connect attempt (literal `"/proxy"` or a route-matched
  `action=proxy`) transparently retries against a freshly-selected
  endpoint, the same total-attempts budget HTTP/1.1 and HTTP/2 already
  give proxy dispatch
- HTTP/3 proxy dispatch cookie-based session affinity (roadmap Phase
  4h): a returning client's `MAGNUS_AFFINITY` cookie wins over
  whichever load-balancing policy is configured, the exact same
  `Set-Cookie`-issuing code path (`magnus_proxy_sanitize_response_
  headers()`) HTTP/1.1 and HTTP/2 proxy dispatch already share
- HTTP/3 reverse-proxy response caching for proxy dispatch (roadmap
  Phase 4i): `action=proxy; cache=on` shares the exact same bounded,
  LRU-evicted cache (`src/magnus_cache.h`) HTTP/1.1 and HTTP/2 already
  use -- one cache, not one per protocol -- with the same freshness
  rules, conditional-GET revalidation, and `X-Cache: HIT`/
  `REVALIDATED` observability
- HTTP/3 upstream connection pooling for proxy dispatch (roadmap Phase
  4j): a completed poolable response is returned to the exact same
  shared, endpoint-keyed idle pool HTTP/1.1 and HTTP/2 already use --
  one pool, not one per protocol. This closes the last gap between
  HTTP/3 proxy dispatch and HTTP/1.1's/HTTP/2's own; see
  `src/magnus_quic.h` for the handful of genuinely QUIC-specific or
  cross-cutting items that remain
- QUIC retry-based stateless address validation (roadmap Phase 4k, RFC
  9000 8.1.2): a fresh connection's first `Initial` packet must prove
  its claimed source address is real -- via a server `Retry` packet
  carrying an authenticated, short-lived token -- before magnus
  allocates any connection state for it, closing off both off-path
  amplification attacks and connection-slot-table exhaustion by junk
  no-token `Initial` floods. A new `magnus_quic_retry_total` counter on
  `/metrics` (the same shared `magnus_build_metrics()` every protocol
  already reports through) makes the exchange externally observable
- QUIC connection migration / reactive path validation (roadmap Phase
  4l, RFC 9000 9.3): magnus now correctly notices and validates a
  client's mid-connection address change (NAT rebinding, or a genuine
  client-initiated migration) via ngtcp2's own PATH_CHALLENGE/
  PATH_RESPONSE exchange, fixing a read-path bug that previously kept
  ngtcp2 from ever observing the change at all. A new
  `magnus_quic_migration_total` `/metrics` counter tracks successful
  validations
- Proxy dispatch response compression, HTTP/1.1 (roadmap 2a-2): a
  `"/proxy"` response now negotiates gzip the same way static-file
  serving already has since 2a -- `Accept-Encoding: gzip`, a
  compressible `Content-Type`, and a body within the same 256-byte..8-MiB
  window, except the body is buffered from a live upstream fetch first
  rather than read from an mmap'd file. Pooling, caching, and session
  affinity all keep working unmodified alongside it. HTTP/2 and HTTP/3
  proxy dispatch remain uncompressed for now -- a later increment
- Container image: 10,355,698 bytes (~9.88 MiB), non-root, read-only rootfs

See `CHANGELOG.md` for what shipped in 1.0.0. Longer-range direction and
completion criteria for future work live in `docs/ENTERPRISE_ARCHITECTURE.md`
and `docs/ROADMAP.md`.

## Components

- `magnus`: the standalone HTTP/event data plane. Configured by flags
  (`--port`, `--root`, `--tls-cert`/`--tls-key`, `--upstream`,
  `--grpc-upstream`, `--rate-limit`, `--trusted-proxies`) or by
  `--config <file>`, the only mode SIGHUP reload can target.
- `magnusd`: supervises one `magnus` child -- validates config before ever
  applying it, reloads it via SIGHUP, and rolls back to the last-known-good
  config (respawning the child if it did not survive) on a failed reload
  or a crash. Not bundled into the data-plane image; it is a separate
  control-plane binary per `docs/ENTERPRISE_ARCHITECTURE.md`.
- `magnusctl`: thin CLI for `magnusd` -- `check` validates a config file
  standalone (no daemon needed); `reload`, `status`, `shutdown` talk to a
  running `magnusd` over a Unix domain socket.
- `Magnus Module ABI`: native extension interface per phase (early API)

## Build and verify

```bash
./scripts/check.sh
make test
./scripts/build-image.sh
./scripts/test-image.sh
docker compose config
```

Earlier exploratory code is isolated under `experiments/` and excluded from
this repository.

## License

Magnus was developed with AI assistance. Use is freely permitted, but no
modification of the source code or binaries is permitted by anyone. See
`LICENSE` for the full terms.
