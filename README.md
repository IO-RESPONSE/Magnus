# Magnus

Magnus is a **lightweight enterprise Web/Application Gateway** developed
independently by IORESPONSE.

## Release: 1.0.0

## Features

- Independent C17/epoll event core with no dependency on an external web
  server runtime
- Strict HTTP/1.0/1.1 parser, keep-alive, 8KiB request cap
- Safe document root, MIME/HEAD, zero-copy `sendfile` static delivery
- Negotiated gzip/zstd/Brotli compression for 256-byte through 8 MiB
  compressible static files over HTTP/1.1 and HTTP/2 (preference order
  zstd > Brotli > gzip when a client offers more than one); other
  responses retain their streaming path
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
- FastCGI dispatch: a route with `action=fastcgi` relays to a real
  FastCGI application server (PHP-FPM et al.) over the original
  FastCGI Specification's own binary record protocol
  (`fastcgi_upstream=`/`--fastcgi-upstream`, its own separate cluster,
  IPv4-literal only; `fastcgi_root=`/`--fastcgi-root` for computing
  `SCRIPT_FILENAME`, the FastCGI equivalent of nginx's own
  `fastcgi_param SCRIPT_FILENAME
  $document_root$fastcgi_script_name;`). Idle connections are pooled
  and reused per endpoint (`FCGI_KEEP_CONN` always requested; a
  connection the application server closed anyway is caught by a
  staleness check at reuse time and simply discarded, no different from
  finding none available); session affinity (the same `MAGNUS_AFFINITY`
  cookie the proxy/gRPC paths already issue) works identically here
  too. Both a connect and a stalled read/response are bounded by a
  timeout, answered with a clean `504` rather than hanging the client;
  any upstream-side failure
  -- connect, send, receive, or a malformed response, not just a
  connect-stage one -- retries against a different healthy endpoint
  once before giving up with a clean 502/504, since nothing is ever
  sent to the client until the whole response is known complete. Any
  HTTP
  method is relayed, with whatever request body was already buffered
  ahead of dispatch (the same generic pre-dispatch buffering
  `action=proxy` uses, up to the same 1 MiB cap) sent as one or more
  `STDIN` records; `CONTENT_LENGTH` is always the real buffered size
  and `CONTENT_TYPE` forwards the client's own header when present.
  `Content-Length`/`Connection` on the translated response are always
  real (recomputed from the actual body, decided from the client's own
  preference), never whatever the application itself sent; an
  application `Status: NNN [reason]` line sets the real status/reason,
  defaulting to 200 OK when absent, per CGI convention
- SCGI dispatch: a route with `action=scgi` relays to a real SCGI
  application server over the SCGI protocol specification's own
  netstring-framed header block + raw-body shape
  (`scgi_upstream=`/`--scgi-upstream`, its own separate cluster,
  IPv4-literal only; `scgi_root=`/`--scgi-root`, the same `DOCUMENT_
  ROOT` role `fastcgi_root` plays). Any HTTP method is relayed, with
  whatever request body was already buffered ahead of dispatch (SCGI
  mandates `CONTENT_LENGTH` as its own first header on every request
  regardless, so unlike FastCGI's own original first cut there is no
  narrower request shape to start from). A connect or a stalled read/
  response is bounded by a timeout, answered with a clean `504` rather
  than hanging the client. The response side reuses FastCGI dispatch's
  own CGI-response translation as-is (identical shape: an optional
  `Status:` line, ordinary headers, a blank line, then the body) --
  `Content-Length`/`Connection` are always real, never whatever the
  application sent. Connection pooling, retry, and session affinity are
  not yet implemented for this path (see `docs/development-roadmap.md`)
- uwsgi dispatch: a route with `action=uwsgi` relays to a real uWSGI
  application server over the "uwsgi" wire protocol
  (`uwsgi_upstream=`/`--uwsgi-upstream`, its own separate cluster,
  IPv4-literal only; `uwsgi_root=`/`--uwsgi-root`, the same
  `DOCUMENT_ROOT` role `scgi_root` plays). Any HTTP method is relayed,
  with whatever request body was already buffered ahead of dispatch. A
  connect or a stalled read/response is bounded by a timeout, answered
  with a clean `504` rather than hanging the client. Unlike SCGI
  dispatch's own response translation, this protocol's response side is
  genuinely distinct (a real uWSGI server's response starts with an
  actual HTTP status line, not a CGI `Status:` one -- confirmed by
  direct testing against a real uWSGI 2.0.31 server before this was
  built) and gets its own dedicated translator; `Content-Length`/
  `Connection` are always real, never whatever the application sent.
  Connection pooling, retry, and session affinity are not yet
  implemented for this path either (see `docs/development-roadmap.md`)
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
  rollback on a failed reload or an unexpected crash, an audit log, and
  (roadmap 5d-1) an explicit `drain` command that stops accepting *any*
  new connection at all rather than just moving them to a new config
  generation, and (roadmap 5e-1) a zero-downtime `upgrade` command that
  swaps the whole running binary via a live listener-fd handoff, not
  just its config -- see the Components section below for both mechanisms
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
  `Vary: Accept-Encoding`. Proxied-response compression and streaming
  compression above the 8 MiB bound remain deferred on every protocol,
  not a QUIC-specific gap
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
- Proxy dispatch response compression, HTTP/1.1, HTTP/2, and HTTP/3
  (roadmap 2a-2/2a-3/2a-4): a `"/proxy"` response now negotiates gzip
  identically on all three protocols, the same way static-file serving
  already has since 2a -- `Accept-Encoding: gzip`, a compressible
  `Content-Type`, and a body within the same 256-byte..8-MiB window,
  except the body is buffered from a live upstream fetch first rather
  than read from an mmap'd file. Pooling, caching, and session affinity
  all keep working unmodified alongside it on every protocol
- Real IP for HTTP/3 (roadmap 2b, extended): `source_cidr` route
  matching and client-IP-based cluster selection now resolve a
  trusted-proxy-forwarded Forwarded/X-Forwarded-For address over QUIC,
  identically to HTTP/1.1 and HTTP/2 -- needed no new QUIC-specific
  mechanism, since Forwarded/X-Forwarded-For are ordinary HTTP header
  fields parsed the same way regardless of protocol. PROXY protocol
  v1/v2 has no QUIC analogue and remains out of scope
- zstd as a second negotiable encoding (roadmap 2a-5), alongside gzip,
  for both static-file and proxy dispatch compression, on all three
  protocols: preferred over gzip whenever a client's `Accept-Encoding`
  offers both. `libzstd.so.1` was already present in the runtime image
  as a transitive OpenSSL dependency, so this adds no new runtime
  library footprint; zstd's fast default level also suits this
  codebase's compress-fresh-per-request design better than Brotli's
  asset-tuned default
- Brotli as a third negotiable encoding (roadmap 2a-6), alongside gzip
  and zstd, for both static-file and proxy dispatch compression, on all
  three protocols: preference order zstd > Brotli > gzip, benchmarked
  rather than assumed (see `CHANGELOG.md`'s 1.42.0 entry for the actual
  numbers). Unlike zstd, this *does* add two new runtime libraries to
  the image (`libbrotlienc.so.1`/`libbrotlicommon.so.1` -- the decoder
  is never bundled, since Magnus only ever compresses); Brotli's own
  default quality (11) was too slow for on-the-fly per-request
  compression, so it runs at quality 4, the fastest level that still
  clearly beats gzip's ratio
- Streaming compression for HTTP/1.1 static files past the 8 MiB bound
  (roadmap 2a-7): the first slice of "streaming/chunked compression
  above 8 MiB", the item every prior compression increment has
  deferred. A static file too large for the buffer-then-compress shape
  every other compression path here uses now streams instead --
  compressed in 64 KiB chunks via each encoder's own incremental API as
  the file is read, written to the client as each chunk is produced.
  No `Content-Length` is knowable ahead of time for a streamed body, so
  the response is close-delimited (`Connection: close`, RFC 9112 6.3)
  rather than chunked-encoded -- the narrower of the two real options,
  reusing every existing byte-writing primitive unchanged instead of
  building this codebase's first `Transfer-Encoding: chunked` writer;
  a real chunked writer (recovering keep-alive for these responses),
  HTTP/2 and HTTP/3 static files, and proxy dispatch on every protocol
  all remain later increments. Found and fixed one real, previously-
  latent bug along the way: `magnus_close_connection()` never called
  `SSL_shutdown()` before closing a TLS socket, harmless for every
  existing `Content-Length`-bearing response but visible to a strict
  TLS 1.3 client the moment a response is framed purely by the
  connection closing, exactly what this increment's own responses are
  the first to do
- Streaming compression for HTTP/2 static files past the 8 MiB bound
  (roadmap 2a-8): the second slice, confirming 2a-7's own prediction --
  HTTP/2 needs none of HTTP/1.1's close-delimited-framing workaround,
  since no protocol requires a Content-Length ahead of a DATA-frame
  response, so the connection stays alive and multiplexed after a
  streamed response exactly like any other. HTTP/3 static files
  (below) and proxy dispatch on every protocol remain later increments
  after this one. Found and fixed one real, previously-latent, more
  serious bug along the way:
  `magnus_h2_drain_send()` retried a failed/partial `SSL_write()`
  against a *different* buffer address than the original attempt saw,
  violating OpenSSL's own same-address retry contract -- silently
  truncated *any* HTTP/2-over-TLS response (static files, proxy
  dispatch, gRPC, `/healthz`/`/metrics`, all of it, not just this
  increment's own new code) large enough to hit a partial write
  mid-transfer, invisible until something exercised a response that
  large, which nothing in this codebase's own test suite did before
  this increment's own well-past-8-MiB fixture
- Streaming compression for HTTP/3 static files past the 8 MiB bound
  (roadmap 2a-9): the third and final static-file slice. Like HTTP/2,
  needed no close-delimited-framing workaround either. Unlike HTTP/2,
  each offered chunk must be its own independent allocation kept alive
  until the peer actually acknowledges it -- nghttp3's own strictest-
  of-the-three `read_data` contract -- so this reuses the exact
  ACK-gated `body_chunk` machinery roadmap 2a-4's own HTTP/3 proxy-
  dispatch compression already established, rather than duplicating
  it. Found and fixed a second real, previously-latent bug along the
  way: zstd's and Brotli's own streaming APIs don't guarantee output
  on every call (only forward input consumption), which deadlocked a
  single-call-per-invocation `read_data` callback outright for both
  encoders -- fixed by looping internally until real progress happens,
  and applied to HTTP/2's own equivalent callback too (which never
  reproduced a hang in testing, but only because of nghttp2's own
  retry timing, not any actual guarantee)
- Streaming proxy dispatch response compression, HTTP/1.1 (roadmap
  2a-10): the one remaining dimension of "streaming/chunked compression
  above 8 MiB" once 2a-7/2a-8/2a-9 covered every static-file case --
  a `"/proxy"` response too large to buffer whole before compressing
  once (past `MAGNUS_COMPRESSION_MAX_SIZE`) now compresses incrementally
  as bytes arrive from the upstream fetch instead of simply staying
  uncompressed past that bound. Unlike the static-file streaming paths,
  input is never pulled on demand (there is no file to `pread()` more
  of) -- it only ever arrives pushed, asynchronously, by the same
  upstream `recv()` the ordinary uncompressed relay already uses, so
  the compressor is fed from `proxy_buffer` directly and the drain loop
  simply waits for the next upstream read when it runs out of input
  rather than looping on its own. Response headers (`Content-Encoding`/
  `Vary`, no `Content-Length`, `Connection: close`) go out immediately
  once the upstream's own headers are known, rather than deferred the
  way the buffer-then-compress path's own headers are. HTTP/2 and
  HTTP/3 proxy dispatch streaming compression remain later increments
- Streaming proxy dispatch response compression, HTTP/2 (roadmap 2a-11):
  the second protocol slice, confirming the same prediction 2a-8's own
  HTTP/2 static-file streaming compression already did -- no close-
  delimited-framing workaround needed, since h2 never requires a
  Content-Length ahead of a DATA-frame response. Structurally different
  from 2a-8's own *pull*-based `read_callback` (which fetches more input
  itself, on demand, via `pread()`): here input only ever arrives
  *pushed*, exactly like 2a-10's own HTTP/1.1 relay, so this is a new
  push-driven fill function instead, called on every upstream-readable
  event. `struct magnus_h2_stream`'s own `io_buffer` is repurposed as
  the compressed *output* queue (the existing pull callback already
  knows how to drain it correctly) with a new dedicated staging buffer
  for not-yet-compressed raw bytes. Found and fixed one real,
  self-inflicted bug along the way: the first draft's own stream
  teardown freed the new staging buffer directly, then unconditionally
  again inside the shared upstream-teardown helper that already owned
  that cleanup -- a genuine double-free, caught by a real heap-
  corruption abort under this increment's own new test, not a
  sanitizer run.
- Streaming proxy dispatch response compression, HTTP/3 (roadmap 2a-12)
  -- the third and final protocol slice, closing out the whole
  "streaming/chunked compression above 8 MiB" thread this project has
  carried since 2a itself. Like HTTP/2, no close-delimited-framing
  workaround was needed. `struct magnus_quic_stream_t`'s own
  `body_chunk`/`body_chunk_length`/`body_chunk_offered`/
  `body_chunk_end_offset`/`body_offered_total`/`body_acked_total`/
  `nghttp3_wants_resume` fields are reused directly for the compressed
  output -- the same ACK-gated, one-fresh-allocation-per-chunk
  discipline every other h3 body source already established, with a
  new dedicated staging buffer for not-yet-compressed raw bytes, and a
  new push-driven producer function (unlike 2a-9's own *pull*-based
  `read_data` callback, since h3's proxy-dispatch input arrives pushed
  off the upstream socket, exactly like the HTTP/1.1 and HTTP/2 slices
  before it).

  Found and fixed a fourth real bug along this whole thread's way, the
  most subtle of them: the new producer function finalized the
  response the moment it produced *any* compressed chunk, but the
  shared completion helper it called independently re-derives "is this
  response complete" from raw upstream byte counts alone -- true the
  instant every raw byte has been *read*, not once the compressor has
  actually *flushed*. Calling it early marked the response complete
  while the compressor was still open, so the very next pull reported
  end-of-stream on a chunk that silently dropped gzip's own trailer and
  the last still-buffered bytes -- every byte actually offered still
  reached the client correctly and the byte counts even matched, which
  is exactly why this one needed a live trace (not just review) to
  catch. Fixed by gating that call on the compressor itself being done,
  not merely on a chunk having been produced.
- A real HTTP/1.1 `Transfer-Encoding: chunked` response writer (roadmap
  2a-13) -- this codebase's first, the follow-up 2a-7's own doc comment
  always named as a natural next step. Each produced chunk is framed
  *in place* (RFC 9112 7.1: a fixed-width, zero-padded 5-hex-digit
  chunk-size header written into a small reserved prefix immediately
  before wherever the real chunk data already landed, no extra copy of
  it, plus its own trailing CRLF), and the fixed 5-byte last-chunk
  (`"0\r\n\r\n"`, no trailer section) is appended directly after the
  final real chunk's own trailing CRLF the moment the underlying
  producer reports done -- all in the same buffer fill, so the existing
  "drain output, then finish once done" loop shape every streaming
  write loop in `magnus.c` already had needed no other change to
  support it. Applied to 2a-7's own HTTP/1.1 static-file streaming-
  compressed responses, which now keep the connection alive afterward
  (per the client's own stated preference) instead of always closing,
  the same as any other response here -- verified via curl's own
  `--next`, reusing the same connection for a follow-up request
  (`num_connects: 0`).
- The same chunked writer applied to HTTP/1.1 proxy dispatch streaming
  compression too (roadmap 2a-14): 2a-10's own responses now keep the
  connection alive afterward as well, via a third sentinel
  (`(size_t) -3`) on `magnus_proxy_sanitize_response_headers()`
  alongside the existing `(size_t) -1`/`(size_t) -2` ones -- emits
  `Transfer-Encoding: chunked` and leaves `keep_client_alive` to the
  client's own stated preference, instead of `(size_t) -2`'s own forced
  `Connection: close` (still used by HTTP/2 and HTTP/3 proxy dispatch
  streaming compression, since chunked encoding is an HTTP/1.1-only
  concept neither protocol has any use for). Verified the same way:
  byte-exact gzip/zstd/Brotli through a real live proxy fetch, real
  connection reuse (`--next`, `num_connects: 0`), an explicit
  client-requested close still honored, and the pre-existing buffer-
  then-compress and plain-relay proxy paths unaffected
- Container image: 10,726,527 bytes (~10.23 MiB), non-root, read-only rootfs

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
  standalone (no daemon needed); `reload`, `status`, `drain`,
  `upgrade`, `shutdown` talk to a running `magnusd` over a Unix domain
  socket. `drain` (roadmap 5d-1) stops the supervised `magnus` child
  from accepting any *new* connection while it finishes every one
  already in flight, then exits on its own once idle (delivered as
  `SIGUSR1`, which a container's own entrypoint/PID 1 can also receive
  directly -- `docker kill --signal=USR1 <container>`, the same
  mechanism a Kubernetes `preStop` hook would use, works without
  `magnusd` in the picture at all); `/healthz` on an already-open
  connection flips to `503` and a new `magnus_draining` `/metrics`
  gauge reports the state, so an external load balancer's own
  readiness probe also stops routing new traffic here, not just the
  listener itself refusing new connections at the TCP level.
  `upgrade [<new-binary-path>]` (roadmap 5e-1) replaces the running
  `magnus` child with zero dropped requests: the successor receives the
  live listener fd via `SCM_RIGHTS` (`--upgrade-socket`/`--inherit-fd`
  on `magnus` itself) rather than binding a fresh one, is only ever
  committed to (draining the predecessor via the same `drain` signal)
  once it proves itself ready over a dedicated per-attempt pipe, and a
  broken new binary leaves the old process completely unaffected --
  see `CHANGELOG.md` 1.59.0 for the real health-check-ambiguity bug
  this design was hardened against.
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
