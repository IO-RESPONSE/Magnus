# Changelog

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
