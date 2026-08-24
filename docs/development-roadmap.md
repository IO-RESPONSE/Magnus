# Magnus Development Roadmap: v1.1.0 → NGINX-class Gateway

Baseline for this roadmap is **v1.1.0** (the master prompt that requested this
document named v1.0.1; v1.1.0 shipped the reverse proxy's request-body/any-method
support in the time between that prompt being drafted and this analysis, so the
gap analysis below is against the actual current state, not v1.0.1).

This document is the mandatory first deliverable before any Phase 1 code is
written, per the operating principle for this effort: analyze before building,
one bounded phase at a time, each phase gated on `make && make test &&
make sanitize` plus its own new tests before the next one starts.

## 1. Current state (v1.1.0)

Four C source files outside `magnus.c` are small and single-purpose
(`magnus_http.c` 163 lines, `magnus_policy.c` 126, `magnus_proxy.c` 105,
`magnus_phase.c` 60); the control plane (`magnusd.c` 561, `magnusctl.c` 246,
`magnus_config.c` 317) is already separate from the data plane. `magnus.c`
itself is 2,467 lines and is the one file this roadmap's module-split
(Section 6) is actually about — everything else is already reasonably
decomposed.

### 1.1 Implemented

- **Core**: single-threaded, non-blocking epoll reactor; HTTP/1.0 and
  HTTP/1.1 parsing (strict, 8 KiB header cap); keep-alive; graceful
  shutdown on SIGTERM/SIGINT; per-request 128-bit trace ID.
- **Static content**: safe document-root resolution, MIME typing, HEAD,
  zero-copy `sendfile`. No Range, no conditional requests (ETag/
  If-Modified-Since), no compression.
- **TLS**: OpenSSL, min version pinned to TLS 1.2 (so 1.2 and 1.3 both
  negotiate), no explicit cipher list (platform default), `SSL_OP_NO_COMPRESSION`.
  No SNI-based multi-cert selection, no ALPN, no mTLS, no session
  ticket/OCSP handling beyond OpenSSL's own defaults.
- **Reverse proxy** (`/proxy/*` only, one static config-file route): connect/
  read timeouts, bounded retry budget (`MAGNUS_PROXY_MAX_ATTEMPTS`), hop-by-hop
  header stripping, streaming response relay without blocking the event loop,
  and — as of v1.1.0 — any HTTP method with a Content-Length-delineated
  request body (capped at 1 MiB; chunked request bodies are rejected, not
  yet decoded). One upstream TCP connection per proxied request, opened
  fresh and closed after (`Connection: close` to the upstream) — no
  connection pooling/reuse.
- **Cluster / load balancing**: static `upstream ip:port[:weight]` list
  from config, weighted round-robin only. Active (periodic TCP connect)
  and passive (live-traffic) health checks share one circuit-breaker
  state per endpoint (failure threshold + cooldown). Cookie-based sticky
  session affinity (index-encoded, not hash-based).
- **Traffic policy**: per-client-IP token-bucket rate limiting (single
  global rate/burst, bounded eviction table). No ACL, no connection-count
  limit, no per-route policy.
- **Control plane**: `magnusd` supervises one `magnus` child, validates
  config before applying, SIGHUP hot reload (old generation drains,
  new connections see the new one), health-checked automatic rollback
  on a failed reload or crash, audit log. `magnusctl check/reload/status/
  shutdown` over a Unix domain socket.
- **Observability**: buffered/sampleable/disable-able access log (fixed
  field set: request_id, method, target, status, latency_ms — not the
  full field list in Section 15 of the master prompt, no JSON mode).
  Prometheus-style `/metrics`: request counters, per-endpoint health
  gauges, one latency histogram. No per-route/per-upstream breakdown,
  no TLS/HTTP2/cache/circuit-breaker series.
- **Admin channel isolation**: `--admin-socket` moves `/metrics` to an
  owner-only Unix socket; `/healthz` stays public.
- **Security posture**: slowloris guard (absolute header-phase deadline),
  RELRO+NOW, `_FORTIFY_SOURCE=2`, non-root/read-only container rootfs,
  clean under ASan+UBSan, HTTP parser mutation-fuzzed (200k iterations in
  `make test`, 4M+ verified separately).
- **Config**: flat `key = value` file, strict unknown-key rejection,
  per-field validation. No `include`, no sections (global/upstream/server/
  location/route/tls/cache/stream), no duplicate-key detection beyond
  what already exists for a few fields (Host header, Content-Length).

### 1.2 Not implemented (gap vs. the target list in Section 26)

Everything else in the master prompt's target feature tree: HTTP/2, HTTP/3/
QUIC, WebSocket, gRPC, FastCGI/SCGI/uWSGI, reverse-proxy cache, compression
(gzip/Brotli/zstd), upstream connection pooling, DNS-based upstream
resolution, advanced routing (host/header/cookie/query/regex/canary), least-
connections/hash/consistent-hash load balancing, L4 TCP/UDP proxying, TLS
passthrough, PROXY protocol, mTLS, ACL, Real-IP (X-Forwarded-For/Forwarded)
trust handling, zero-downtime binary upgrade, and the full logging/metrics
field sets in Sections 15–16.

## 2. Phase 1, broken into checkpointed sub-phases

The master prompt bundles HTTP/2, WebSocket, connection pooling, DNS, and
advanced routing into one "Phase 1." Given each of those is independently
substantial — and Section 24's own development method (analyze → design →
implement → unit → integration → security → sanitizer → benchmark → docs →
regression, *per change*) — Phase 1 runs as five gated sub-phases, ordered
by risk and dependency, each ending in the same `make && make test &&
make sanitize` + new-tests-pass + short report cycle already used for every
milestone so far in this project. Nothing here starts without that
checkpoint from the prior sub-phase being green.

1. **1a — Upstream connection pool. Shipped in 1.2.0.** A per-endpoint
   pool of idle connections (checked before opening a fresh one; returned
   to the pool, not closed, once a response completes cleanly), bounded
   at 8 idle/endpoint, a 60s idle timeout, and 100 requests/connection.
   Liveness is checked at checkout time (non-blocking `MSG_PEEK`) rather
   than by keeping idle connections registered with epoll -- simpler, and
   avoids a second "this event belongs to an idle, unowned upstream
   connection" branch in the main dispatch loop, at the cost of not
   detecting a backend-initiated close until the next checkout rather
   than immediately; the idle timeout bounds how long that can matter. A
   config reload flushes the whole pool (endpoint position is not
   guaranteed stable across a reload). Turned out to require -- and this
   ended up being the more consequential half of the sub-phase -- knowing
   a response's exact length up front (Content-Length) rather than
   relying on the upstream closing to signal completion, which is also
   what unlocked a real, independently-shipped fix: proxied responses
   had been force-closing the *client* connection unconditionally since
   M2, regardless of what the client asked for; both legs are now decided
   independently (see CHANGELOG.md 1.2.0). No config schema change yet;
   pool size/timeout/request-budget stay fixed constants for now,
   revisited if real usage shows the defaults wrong. Not yet done:
   TLS-upstream connection reuse (no TLS upstream support exists at all
   yet -- out of this sub-phase's scope) and connection draining as a
   distinct state (a connection mid-response when its budget is hit is
   simply not pooled afterward, not actively drained early).
2. **1b — Advanced routing. Shipped in 1.3.0.** `host`/`path_prefix`/
   `method`/`header:<name>`/`cookie:<name>`/`query:<name>`/`source_cidr`
   match conditions, combinable with AND (up to 8 per route), evaluated
   in file order (first match wins) ahead of the built-in dispatch. New
   `magnus_route.c`/`.h`, independently unit-tested and fuzzed (the
   matcher against real request data, not the DSL parser, which only
   ever sees admin-controlled config — same reasoning `magnus_config.c`
   itself is unfuzzed). New repeatable `route = ...` config key (compact
   single-line DSL, not a multi-line block — kept the flat-file schema
   from needing a section/grouping concept it doesn't have yet) plus a
   mirrored `--route` CLI flag. Three actions: `proxy` (forwards the
   *full* path — a route isn't anchored to the literal `/proxy/*`
   prefix, so nothing gets stripped, unlike that dispatch path), `deny`
   (403, short-circuits ahead of everything else), and `static` (lets a
   route's conditions gate an otherwise-ordinary static request; no
   per-route root override yet — see below). Required extending
   `magnus_http_parse()` to retain the Host value and every header
   field for lookup, which `header:<name>` conditions need.
   Not yet done: `action=static` root override (deferred — no `root=`
   key on a route spec yet, not silently unsupported), regex matching
   (path_prefix is a literal anchored prefix only), OR-combined
   conditions (only AND), and multiple upstream clusters — every
   `action=proxy` route still targets the one cluster this whole
   codebase has always had; per-route upstream selection is a natural
   follow-up, likely worth bundling with the eventual canary/traffic-split
   work in Section 26's routing list rather than doing it twice.
3. **1c — DNS resolver. Shipped in 1.4.0.** An `upstream` entry may be a
   hostname; resolved on a dedicated background thread (this codebase's
   first thread) running the system's own `getaddrinfo()`, completion
   delivered to the main thread over an eventfd registered in the normal
   epoll loop -- chosen over `getaddrinfo_a()` (real-world reliability
   history) and over a hand-rolled DNS wire-format parser (new untrusted-
   byte parsing surface this project has otherwise avoided; also gets
   search domains/`/etc/hosts`/NSS for free). The trade-off that comes
   with `getaddrinfo()`: its standard API exposes no TTL, so this is a
   fixed-interval refresh (`MAGNUS_DNS_REFRESH_SECONDS`, 30s), not a
   TTL-respecting cache as originally scoped here -- true TTL-awareness
   would require the wire-format-parsing approach this deliberately
   avoided, or a library like c-ares; revisit only if the fixed interval
   proves wrong in practice. Resolution failure keeps the last-known-good
   address (decided: an endpoint that has resolved successfully at least
   once should not be torn down over one transient DNS hiccup); an
   endpoint that has never resolved simply fails connect attempts
   cleanly via the existing bad-address handling, no special pending
   state needed. New module `magnus_dns.c`/`.h`, and this codebase's
   first use of ThreadSanitizer (`make tsan`), justified by being its
   first genuinely concurrent code -- the worker thread never touches
   anything outside its own module, so that is also the only place a
   race could exist, and TSan confirms none does.
4. **1d — WebSocket. Shipped in 1.5.0.** Handshake relay (Upgrade/
   Connection/Sec-WebSocket-* headers forwarded verbatim, a 101 response
   relayed byte-exact) plus a raw bidirectional byte-pipe relay once
   upgraded — turned out not to need live per-frame parsing at all for
   correctness or memory-safety, since the relay never interprets frame
   *content*: the same bounded-chunk streaming already proven for
   ordinary proxied bodies is sufficient regardless of what the bytes
   mean at the framing layer. The RFC 6455 frame-*header* parser this
   entry originally asked for was still built and fuzzed
   (`magnus_ws.c`/`.h`, `tests/fuzz-ws.c`) as real groundwork for live
   per-frame policy (size limits, masking-direction enforcement) — just
   deliberately not wired into the relay path yet, since it is not load-
   bearing for what shipped. Verified against a real, independent
   WebSocket client library (Python's `websockets`), not just this
   project's own code — which is how a real bug got caught: the
   pre-existing response-header sanitizer tokenizes its buffer in place,
   and the new code was building the verbatim 101 relay from that
   now-corrupted buffer (see CHANGELOG.md 1.5.0).
5. **1e — HTTP/2.** Expected to be the largest single piece of work in
   Phase 1, and sub-scoped rather than attempted whole (per Section 27's
   own instruction to proceed one bounded phase at a time) into:
   - **1e-1 — ALPN + nghttp2 integration, static files only. Shipped in
     1.6.0.** TLS ALPN negotiation offering exactly `"h2"` (a small,
     standalone, independently fuzzed module — `magnus_h2.c`/`.h`,
     `tests/test-h2.c`, `tests/fuzz-h2.c` — deliberately not using
     `SSL_select_next_proto()`, whose edge-case contract was itself the
     subject of CVE-2024-5535; a direct bounded scan for the one
     candidate protocol sidesteps that history entirely), then a real
     nghttp2-driven session per h2-negotiated connection: HPACK, stream
     multiplexing, and SETTINGS/PING/WINDOW_UPDATE handling all come from
     nghttp2 itself rather than hand-rolled parsing (Section 5's own
     CVE-history warning against that). Each stream dispatches to the
     same `magnus_open_static()`/`magnus_content_type()` helpers the
     HTTP/1.1 GET path already uses, so both protocols agree on path
     resolution/traversal safety by construction — this is the first,
     narrowest slice of the master prompt's "common internal request
     model" (Section 3.1) rather than the full abstraction, which
     proxy/route dispatch over h2 (1e-2+) will still need to generalize.
     GET/HEAD only; no request body support (none is meaningful for a
     static-file response); no h2c (cleartext upgrade — ALPN-negotiated
     TLS only). Verified against real, independent HTTP/2 tooling (curl
     `--http2`, `openssl s_client -alpn h2`) — including ALPN actually
     landing on h2, HTTP/1.1 fallback for a client that never offers h2,
     byte-exact bodies for both a small file and one spanning multiple
     `pread()`-chunked data-provider callbacks, HEAD, 404, and several
     requests genuinely multiplexed over one connection — not just unit
     tests against this project's own code, matching the rigor every
     protocol-level feature this project has shipped has used.
   - **1e-2 — proxy/route dispatch + H2↔H1 upstream translation. Shipped
     in 1.7.0.** An h2 stream matched to `action=proxy` (or the literal
     `/proxy` prefix) resolves through the exact same `magnus_routes[]`/
     `magnus_route_matches()` matcher 1b wrote for HTTP/1.1, now driven
     by a `magnus_http_request_t` filled in directly from nghttp2-decoded
     pseudo-/regular headers instead of HTTP/1.1 wire bytes — the first
     working slice of the master prompt's "common internal request
     model" (Section 3.1) that reaches routing, not just static dispatch
     (1e-1's own narrower slice). The proxied request is relayed to an
     ordinary HTTP/1.x upstream over the *same* `magnus_cluster`/
     `magnus_upstream_pool` and `magnus_proxy_sanitize_response_headers()`
     hop-by-hop-stripping/framing logic every HTTP/1.1 proxy attempt
     already used — reused, not reimplemented, so both protocols agree on
     upstream selection, health/circuit-breaker state, and response
     framing by construction — with the response translated into h2
     response headers (`Connection` dropped: forbidden in h2 by RFC 9113
     8.2.2) and DATA frames pulled through nghttp2's data-provider
     callback (`NGHTTP2_ERR_DEFERRED`/`nghttp2_session_resume_data()`
     while more is still expected from the upstream). Deliberately its
     own parallel set of functions rather than a reuse of
     `magnus_proxy_pick_and_start()`/`magnus_handle_upstream()`/etc.:
     those assume exactly one proxy attempt in flight per client
     *connection*, which h2's concurrent multiplexing genuinely breaks —
     one connection can have many streams each proxying to a (possibly
     different) upstream at once, so this proxy state lives on each
     stream instead (`struct magnus_h2_stream`'s own request/response
     buffers, upstream fd, and a parallel `magnus_h2_upstream_owner[]`
     ownership table alongside the existing per-connection one).
     Request bodies (POST/PUT/...) are buffered from DATA frames up to
     `MAGNUS_MAX_BODY` (1 MiB, same cap the HTTP/1.1 path enforces) and
     relayed to the upstream; session affinity (`MAGNUS_AFFINITY`
     cookie) and the connect/read timeout sweep both work the same way
     as HTTP/1.1, now swept per-stream. Not yet covered: h2c (cleartext
     upgrade); GOAWAY/RST_STREAM handling and Rapid-Reset-class abuse
     hardening (Section 306-308's own note: this class of hardening is
     meaningless before an h2 stack exists at all, so it belongs to 1e's
     own checkpoint, not a deferred blanket "security phase");
     per-client-IP rate limiting and `/healthz`/`/metrics` are not wired
     into the h2 path yet either; WebSocket-over-h2 (RFC 9113 8.5
     extended CONNECT) is out of scope entirely, since h2 has no
     Upgrade-style handshake for 1d's own relay to attach to. Verified
     against real, independent HTTP/2 tooling (curl `--http2`) end to
     end through a real HTTP/1.1 backend: GET and POST-with-body (small
     and one spanning multiple relay-buffer chunks) both proxy correctly
     with the upstream's own response headers (Content-Type, a custom
     header) forwarded; HEAD; a deny route still denies; an oversized
     body 413s instead of hanging; the connection pool is reused across
     sequential requests (proven by the backend's own per-accept
     connection identity coming back unchanged); 20 genuinely concurrent
     proxied requests all come back correct with no cross-stream
     corruption and leave no leaked fds behind; ordinary static-file
     serving keeps working on the same connection a proxy route also
     matches on; verified clean under `make sanitize` (ASan+UBSan)
     against this exact live traffic, including the concurrent and
     oversized-body cases.
   - **1e-3 — GOAWAY/RST_STREAM handling + Rapid-Reset-class abuse
     hardening. Shipped in 1.8.0.** A per-connection, lazily-reset
     one-second window now caps both how many new request streams a
     connection may open (`MAGNUS_H2_MAX_NEW_STREAMS_PER_SECOND`, 100)
     and how many `RST_STREAM` frames the *client* may send on it
     (`MAGNUS_H2_MAX_RESETS_PER_SECOND`, 50) — the latter directly
     targeting the Rapid Reset (CVE-2023-44487) shape: open a stream,
     immediately reset it, repeat as fast as possible, cheap for the
     attacker and potentially expensive for the server if each open
     triggered real dispatch work. Either cap being exceeded terminates
     the connection immediately by returning
     `NGHTTP2_ERR_CALLBACK_FAILURE` from the offending nghttp2 callback —
     the same mechanism nghttp2 already uses internally for its own
     PING/SETTINGS-ack-flood and CONTINUATION-flood protections
     (`NGHTTP2_ERR_FLOODED` / `NGHTTP2_ERR_TOO_MANY_CONTINUATIONS`, both
     already fatal via magnus's existing `consumed < 0` check on every
     `nghttp2_session_mem_recv2()` call — so those two abuse classes were
     already covered for free before this sub-phase existed; only
     Rapid-Reset-style `RST_STREAM` abuse and raw new-stream-open floods
     had no cap of their own, since a rate genuinely legitimate for them
     is application-specific, not something a general-purpose library can
     assume). Separately, graceful shutdown now sends every still-open h2
     connection a real GOAWAY frame (`NGHTTP2_NO_ERROR`, this session's
     own last-processed stream id) before the existing hard-close loop
     tears everything down on `SIGTERM` — a single best-effort frame, not
     RFC 9113 6.8's full two-GOAWAY dance (which is meant to span a full
     RTT to avoid a race with in-flight new streams; magnus's own
     shutdown proceeds immediately afterward regardless, so there is no
     window for that dance to matter in). Verified against a real,
     independent HTTP/2 client (`h2`/`hyperframe`, manually — a raw,
     stdlib-only hand-rolled client for the permanent
     `tests/test-core.sh` regression coverage instead, matching 1d's own
     precedent of not adding a pip dependency to the test suite itself):
     a legitimate client's ordinary traffic is completely unaffected by
     either cap; a simulated Rapid Reset attack (open+immediate-reset in
     a tight loop) and a simulated raw new-stream flood are each cut off
     within a few hundred attempts, well short of the thousand attempted
     — proving both caps actually fire under real, wire-level attack
     traffic, not just unit tests against this project's own code; a
     real GOAWAY frame (type `0x7`) is confirmed to arrive before the
     connection closes on `SIGTERM`; both caps are confirmed
     per-connection, not a global circuit-breaker an attacker could ride
     to deny service to every other client; all of the above re-verified
     clean under `make sanitize` (ASan+UBSan), including repeated attack
     cycles back-to-back with no fd or memory leaks.
   - **1e-4 — h2 path operational parity: `/healthz`, `/metrics`,
     per-client-IP rate limiting. Shipped in 1.9.0.** `magnus_h2_dispatch()`
     now mirrors `magnus_dispatch_request()`'s exact branch order for
     HTTP/1.1 (rate-limit check first — including its own pre-existing
     quirk of consuming a token even for a request that turns out denied,
     matched deliberately rather than "fixed" into a divergence — then
     route-denied, then the method check, then `/healthz`, then
     `/metrics`, then proxy, then static; a literal `/healthz` or
     `/metrics` path wins over a route that happened to match
     `action=proxy` for that same literal path, exactly like HTTP/1.1's
     own if/else-if chain), reusing `magnus_rate_check()` unmodified — the
     token-bucket table is keyed by client IP alone, so it is genuinely
     shared across HTTP/1.1 and h2 traffic from the same client, not two
     independent limiters a client could evade by splitting its traffic
     across both protocols. The Prometheus `/metrics` text body itself is
     now built by a single shared `magnus_build_metrics()` (extracted from
     what was previously HTTP/1.1-dispatch-inline code, a pure
     refactor -- no behavior change for HTTP/1.1) so the two protocols
     cannot drift into reporting different numbers for the same process. A
     new `magnus_h2_submit_text()` submits a small in-memory canned-text
     h2 response (used by both `/healthz` and `/metrics`) by reusing the
     exact same `stream->io_buffer`/data-provider-callback plumbing the
     1e-2 proxy path already streams an upstream response body through —
     the callback itself was accordingly generalized and renamed
     (`magnus_h2_read_proxy_body` → `magnus_h2_read_io_buffer`) rather than
     given a near-duplicate sibling. `connection->admin_only` is always
     false for an h2 connection (h2 requires TLS+ALPN; the admin channel
     is a plain, non-TLS Unix socket), so the HTTP/1.1 path's various
     `admin_only`-conditioned branches collapse to their non-admin case
     here without needing to be repeated. Verified against real HTTP/2
     tooling (`curl --http2`): `/healthz`/`/metrics` (GET and HEAD) answer
     correctly and stay exempt from rate limiting even mid-exhaustion; an
     ordinary static file hits a configured burst-of-2 limit and 429s on
     the third rapid request, recovering after the configured refill
     window, mirroring the pre-existing HTTP/1.1 rate-limit test's own
     shape exactly; a same-client HTTP/1.1 request is confirmed rejected
     too while the h2-side bucket is still exhausted, proving the shared-
     state claim end to end rather than by code inspection alone; `make
     sanitize` (ASan+UBSan) green against this exact live traffic.
   - **1e-5 — h2c (cleartext HTTP/2). Shipped in 1.10.0.** Both RFC 9113
     entry points, plain (non-TLS) listener only -- the TLS+ALPN h2 path
     (1e-1) is completely separate and unaffected. *Prior knowledge*
     (3.4): a connection's very first bytes are compared against the
     24-byte client preface before ever attempting HTTP/1.1 parsing on
     them (`magnus_h2c_check_preface()`, checked at most once per
     connection); nghttp2 itself validates/consumes the preface as part
     of its own ordinary `nghttp2_session_mem_recv2()` processing --
     magnus's own job is only to notice early enough not to hand those
     bytes to the HTTP/1.1 parser first, not to hand-parse the preface
     itself. *Upgrade: h2c* (3.2): an ordinary HTTP/1.1 request carrying
     `Connection: Upgrade, HTTP2-Settings` / `Upgrade: h2c` /
     `HTTP2-Settings: <base64url>` gets a `101 Switching Protocols`
     (queued through the same `connection->output` buffer, and therefore
     the same non-blocking multi-attempt drain, every ordinary response
     already uses -- the 101 is guaranteed to reach the client before any
     h2 byte that follows it), and the *same* request becomes h2 stream 1
     via `nghttp2_session_upgrade2()` -- the already-parsed
     `magnus_http_request_t` is copied directly into the new stream's
     state (both use the identical struct shape) rather than
     re-derived, and dispatched immediately, exactly as if its
     END_STREAM had just been observed. Scoped to a request with no body
     for this increment (a body would need the H1 body-buffering
     machinery to finish *before* the upgrade could proceed, which this
     increment does not wire up -- the overwhelmingly common real-world
     case, priming a connection for h2, has none). New module
     `magnus_base64.c`/`.h`: a small, standalone base64url (RFC 4648 §5)
     decoder for the HTTP2-Settings header value -- independently
     unit-tested and fuzzed (`tests/fuzz-base64.c`, 200k iterations in
     `make test`, 4M+ verified separately across two seeds), matching
     this project's standing rule that any new parser of untrusted bytes
     gets its own fuzz harness rather than being inlined into the
     dispatch path that calls it. Both entry points reuse every h2
     feature already shipped unmodified -- static files (1e-1), proxy
     dispatch (1e-2), Rapid-Reset hardening (1e-3, the same per-connection
     caps apply regardless of how the h2 session was reached),
     `/healthz`/`/metrics`/rate limiting (1e-4, sharing the exact same
     rate-limit state HTTP/1.1 and TLS+ALPN h2 traffic already share) --
     since h2c only changes *how a connection becomes h2*, not anything
     about how an h2-active connection is subsequently dispatched.
     Verified against real, independent HTTP/2 tooling (curl's own native
     `--http2-prior-knowledge` and `--http2`-against-a-plain-`http://`-URL
     support, not this project's own code exercising itself): both entry
     points return real h2 responses (curl reports HTTP version 2) for a
     static file, a proxy route, `/healthz`, and HEAD/404; the rate
     limiter's shared state and the proxy path both work identically to
     the TLS+ALPN case; an ordinary HTTP/1.1 client on the very same
     plain listener is completely unaffected; `make sanitize`
     (ASan+UBSan) green against this exact live traffic across ~24
     connections cycling both entry points with no fd or memory leaks.
   - **1e-6+ — remaining.** Response trailers; WebSocket-over-h2 (extended
     CONNECT); and generalizing 1e-1/1e-2/1e-4/1e-5's still-
     protocol-specific dispatch functions into the master prompt's actual
     unified HTTP/1↔HTTP/2 request-model abstraction (Section 3.1) that
     routing/proxy code can stay fully agnostic against, now that a
     static, a proxy, and a built-in-endpoint path all exist to
     generalize from.

Each sub-phase's own checkpoint report will name its new tests, confirm
`make`/`make test`/`make sanitize` are green, and give the size/behavior
delta — matching the format every milestone in this project has used so
far. Phase 1 as a whole is not reported "done" until all five sub-phases
(1a–1e, with 1e itself covering every 1e-N increment above) are.

## 3. Phases 2–6 (unchanged in intent from the master prompt, summarized)

Detailed sub-phase breakdowns for these will be written the same way Phase
1's was — right before that phase starts, not speculatively now, since the
concrete design depends on what Phase 1 actually settles on (especially the
connection-pool and common-request-model decisions).

- **Phase 2 — gRPC, reverse-proxy cache, compression, advanced LB, health
  check expansion, Real IP.** gRPC rides on the Phase 1e HTTP/2 stack
  (streaming, trailers, deadline propagation) — cannot start before 1e is
  done. Cache and compression are independent of each other and of gRPC,
  so may run as parallel sub-phases.
  - **Compression 2a — static-file gzip. Shipped in 1.11.0.** HTTP/1.1 and
    HTTP/2 negotiate gzip through a bounded `Accept-Encoding` token scan for
    compressible MIME types. Files from 256 bytes through 8 MiB are buffered
    and compressed completely, allowing an exact compressed Content-Length;
    compressed plain-HTTP responses therefore use the buffered write path
    while every uncompressed response retains zero-copy `sendfile`. `Vary:
    Accept-Encoding` prevents a future cache from mixing representations.
    Proxied-response compression, Brotli/zstd, and streaming/chunked
    compression for files above 8 MiB remain separate future increments.
    - **2a-2 — proxy dispatch response compression, HTTP/1.1. Shipped in
      1.37.0.** The same gzip negotiation as 2a's own, now for a
      `"/proxy"` response fetched live from an upstream rather than read
      from an mmap'd file -- genuinely changes the relay's own timing
      (the whole body must be captured and compressed before anything
      reaches the client), unlike every earlier proxy-dispatch feature
      this codebase shipped, which only ever added side bookkeeping
      alongside an unchanged streaming relay. `magnus_proxy_sanitize_
      response_headers()` (the shared h1/h2/h3 header rewriter) gained a
      `compressed_content_length` override parameter for exactly this.
      Pooling/caching/affinity keep working unmodified alongside it.
      HTTP/2 and HTTP/3 proxy dispatch remain uncompressed -- a later
      increment. See `CHANGELOG.md` 1.37.0 for the full detail.
    - **2a-3 — proxy dispatch response compression, HTTP/2. Shipped in
      1.38.0.** The same deferred-submission-until-compressed shape as
      2a-2, adapted to h2's own frame-based, pull-driven response model
      (`nghttp2_data_provider2`) instead of a push write loop --
      `magnus_h2_proxy_submit_response()` is now deferred, not
      unconditional, gated on a new `stream->compress_pending`. No
      dedicated compressed-body field was needed the way HTTP/1.1's own
      fixed-size scratch buffer required one: `stream->io_buffer` is
      already a generically reassignable heap pointer, reused directly
      the exact same way the *static-file* h2 compression path already
      does. One real bug found (not by review): an initial
      implementation only captured the header-arrival leftover chunk
      into the new capture buffer and forgot the *subsequent* upstream
      reads, so a response whose headers and body arrived as two
      separate reads (routine) silently compressed zero bytes into an
      empty-but-valid gzip stream. See `CHANGELOG.md` 1.38.0 for the
      full detail.
    - **2a-4 — proxy dispatch response compression, HTTP/3. Shipped in
      1.39.0.** The third and final protocol, closing out 2a's own
      cross-protocol compression story. Same deferred-submission-until-
      compressed shape, adapted to nghttp3's own frame-based, pull-
      driven model (`nghttp3_conn_submit_response()` now deferred behind
      `stream->compress_pending`). Unlike h2's `io_buffer`, h3's own
      `body_chunk` could not be reused directly -- it is a single,
      ACK-gated, one-shot-per-network-chunk allocation by design (4b's
      own hard-won lesson: reusing one buffer there once corrupted a
      real streamed response under genuine QUIC flow-control
      backpressure). A new dedicated `stream->compress_capture` growable
      buffer accumulates the body instead; only once compression
      completes does the result become a single fresh `body_chunk`
      allocation, entering that field's own existing lifecycle
      unchanged. Applied 2a-3's own lesson from the start this time --
      `magnus_quic_proxy_compress_capture()` was wired into both the
      header-arrival leftover *and* every subsequent upstream read from
      the outset, so the exact scenario that exposed 2a-3's own gap
      passed on the first attempt here. See `CHANGELOG.md` 1.39.0 for
      the full detail.
    - **2a-5 — zstd as a second negotiable encoding. Shipped in 1.41.0.**
      Joins gzip, preferred whenever a client's `Accept-Encoding` offers
      both, across *both* static-file and proxy-dispatch compression, on
      all three protocols at once -- the first compression increment to
      be genuinely cross-cutting from the start rather than shipped
      protocol-by-protocol the way 2a-2/2a-3/2a-4 were. Chosen over
      Brotli for this increment on two concrete grounds: `libzstd.so.1`
      was already being copied into the runtime image as a transitive
      OpenSSL 3.5+ dependency (Brotli would need two new `.so` files),
      and zstd's fast default level (`ZSTD_CLEVEL_DEFAULT`) suits this
      codebase's compress-fresh-on-every-request design, unlike
      Brotli's asset-tuned default quality 11. The old boolean
      `magnus_accepts_gzip()` became `magnus_negotiate_encoding()`,
      returning a `magnus_encoding_t` (`NONE`/`GZIP`/`ZSTD`); q-value
      exclusion stays deliberately unhonored, matching the old
      function's own already-established behavior (an existing unit
      test already asserted `magnus_accepts_gzip("GZip;q=0")` true).
      `magnus_proxy_sanitize_response_headers()` gained a
      `compressed_content_encoding` parameter alongside its existing
      `compressed_content_length` override, so the one shared h1/h2/h3
      header rewriter emits whichever encoding was actually negotiated
      instead of a hardcoded `"gzip"`. See `CHANGELOG.md` 1.41.0 for the
      full detail.
    - **2a-6 — Brotli as a third negotiable encoding. Shipped in
      1.42.0.** Closes the deferral 2a-5 left open. Preference order
      becomes zstd > Brotli > gzip -- benchmarked (a ~230 KB and a
      ~4.6 MB HTML-shaped fixture, swept across Brotli's whole quality
      range against gzip -9 and zstd's default), not assumed: quality 4
      stayed in the same speed ballpark as gzip/zstd while beating
      gzip's ratio by roughly 2x, so `MAGNUS_BROTLI_QUALITY` is 4, not
      the library's own default of 11 (confirmed 20x-plus slower on the
      smaller fixture alone). zstd still wins outright when offered
      alongside Brotli -- it edged out Brotli on ratio on the larger
      fixture at a comparable speed. Unlike zstd, Brotli's runtime
      libraries were genuinely new to the image (`libbrotlienc.so.1`/
      `libbrotlicommon.so.1`; the decoder is never bundled, since Magnus
      only ever compresses). Every one of the five call sites that used
      to hand-roll a two-way `zstd ? ... : gzip` ternary (each
      protocol's own proxy-dispatch `finish_compression()`, plus
      `magnus_compress_static()` and its h3 analogue) was replaced with
      one shared `magnus_compress()` dispatcher rather than growing five
      near-identical three-way branches. One test regression found and
      fixed, not a code bug: several `tests/test-core.sh` blocks used
      curl's `--compressed` flag to prove gzip negotiation, relying on
      libcurl to both request and transparently decompress -- this
      host's curl was built with Brotli support, so `--compressed` now
      offers `br` too, and magnus correctly started preferring it,
      breaking the old gzip-specific assertion. Fixed by switching those
      to an explicit `-H 'Accept-Encoding: gzip'` and adding new,
      dedicated Brotli blocks that use `--compressed` deliberately, as
      live confirmation a real client actually gets Brotli back. See
      `CHANGELOG.md` 1.42.0 for the full detail.
    - **2a-7 — streaming compression, HTTP/1.1 static files past the 8
      MiB bound. Shipped in 1.43.0.** The first slice of "streaming/
      chunked compression above 8 MiB", the item 2a through 2a-6 each
      deferred in turn. `magnus_compress_static()`'s own buffer-then-
      compress shape refuses anything past `MAGNUS_COMPRESSION_MAX_SIZE`
      by design (holding the whole body, compressed and uncompressed,
      in memory at once stops being reasonable well before 8 MiB scales
      to a real static file server's needs) -- an eligible GET above
      that bound now streams instead, compressing 64 KiB chunks via
      each encoder's own incremental API (`deflate()`/`Z_NO_FLUSH`,
      `ZSTD_compressStream2()`, `BrotliEncoderCompressStream()`) as the
      file is read, writing each produced chunk to the client as it
      becomes available. No `Content-Length` is knowable ahead of time
      for a streamed body -- the real reason this needed its own
      response-framing decision, not just a different body-writing
      loop -- so the response is close-delimited (`Connection: close`,
      RFC 9112 6.3 permits this) rather than chunked-encoded: the
      narrower of the two real options, reusing every existing byte-
      writing primitive (`magnus_socket_write()`, the same partial-
      write/EAGAIN handling every other loop in `magnus_handle_write()`
      already has) instead of building this codebase's first
      `Transfer-Encoding: chunked` writer. A real chunked writer
      (recovering keep-alive for these responses), HTTP/3 static files,
      and proxy dispatch on every protocol all remain later increments
      (HTTP/2's own slice followed immediately after, as 2a-8 below).

      `src/magnus_compression.h/.c` gained a small opaque streaming API
      (`magnus_stream_compressor_t`, `_begin()`/`_step()`/`_end()`)
      alongside the existing one-shot `magnus_compress()` -- verified
      against a standalone sanity harness (18 combinations: all three
      encodings, input sizes 0 to 10 MiB, and deliberately tiny 37-byte
      output buffers forcing many partial-drain iterations) before ever
      being wired into `magnus.c`, under ASan/UBSan.
      `struct magnus_connection_t` gained a dedicated fd/buffer set for
      this path rather than reusing `file_fd`/`file_buffer`, so the
      existing sendfile/pread relay loops never needed their own guard
      conditions touched.

      One real, previously-latent bug found and fixed along the way:
      `magnus_close_connection()` never called `SSL_shutdown()` before
      closing a TLS connection. Harmless for every existing
      `close_after_write`-over-TLS response before this one (each
      always had a `Content-Length`, or was HTTP/1.0, so a client never
      needed to detect "body complete" purely by watching the
      connection close) -- this increment's own responses are the first
      that do, and a strict TLS 1.3 client reported `SSL_ERROR_SYSCALL`/
      "errno 0" on the abrupt close despite every byte already read
      being correct. Fixed with one best-effort `SSL_shutdown()` call
      before `close(fd)`, the standard OpenSSL usage for a server not
      waiting on the peer's own close_notify back. See `CHANGELOG.md`
      1.43.0 for the full detail.
    - **2a-8 — streaming compression, HTTP/2 static files past the 8
      MiB bound. Shipped in 1.44.0.** The second slice, confirming
      2a-7's own prediction: no close-delimited-framing workaround
      needed at all, since HTTP/2 never requires a Content-Length ahead
      of a DATA-frame response -- a new pull-based
      `nghttp2_data_provider2` callback (`magnus_h2_read_stream_
      compressed()`) reports `NGHTTP2_DATA_FLAG_EOF` once the streaming
      compressor (2a-7's own API) reports done, and the connection
      stays alive and multiplexed afterward exactly like any other
      (verified directly: a second, ordinary request sent right after a
      streamed one on the same connection). No separate output staging
      buffer was needed the way HTTP/1.1's own write loop requires one
      either -- nghttp2 already hands the callback a buffer to fill
      directly on every pull. `struct magnus_h2_stream` gained a
      dedicated input-staging buffer but safely reuses the stream's
      existing `file_fd`/`file_offset`/`file_length` fields for the raw
      source file, unlike the HTTP/1.1 connection struct: exactly one
      `nghttp2_data_provider2` callback is ever registered per stream,
      so there is no risk of two consumers racing over the same fields.

      Found and fixed a second, more serious previously-latent bug
      along the way, discovered because this was the first thing in
      this codebase's history to test HTTP/2 static-file serving past a
      few MB: `magnus_h2_drain_send()` retried a failed/partial
      `SSL_write()` against a *different* buffer address than the
      original attempt saw (copying nghttp2's own transient output
      buffer into `connection->h2_output` only *after* a short/failed
      first attempt, rather than before every attempt), violating
      OpenSSL's own contract that a retried write must reuse the exact
      same address, not merely equal content, when
      `SSL_MODE_ENABLE_PARTIAL_WRITE` isn't set. Silently truncated any
      HTTP/2-over-TLS response large enough to hit a partial write
      mid-transfer -- not just static files: `magnus_h2_drain_send()` is
      the shared send path under every HTTP/2 response this codebase
      produces (proxy dispatch, gRPC, `/healthz`/`/metrics`, all of it).
      Reproduced reliably (~25-40% of attempts) against the *existing*,
      unmodified plain relay once actually tested at this size; a plain
      h2c connection with the identical fixture never showed it, since
      TLS's own retry contract is the only thing being violated. Fixed
      by copying nghttp2's chunk into `h2_output` unconditionally,
      before any write is attempted, so every write (first attempt or
      retry) goes through `magnus_h2_flush_output()`'s own already-
      correct fixed-address loop. Verified: 15 consecutive live
      requests for a 12 MB file over HTTP/2+TLS, byte-exact every time
      (previously ~25-40% truncated). See `CHANGELOG.md` 1.44.0 for the
      full detail.
    - **2a-9 — streaming compression, HTTP/3 static files past the 8
      MiB bound. Shipped in 1.45.0.** The third and final static-file
      slice. Like HTTP/2, no close-delimited-framing workaround was
      needed -- HTTP/3 never requires a Content-Length ahead of a
      DATA-frame response either. Unlike HTTP/2 (where nghttp2 hands
      the read callback a reusable buffer to fill directly), HTTP/3's
      own `nghttp3_data_reader` contract is the strictest of the three:
      each offered chunk must be its own independent allocation, kept
      alive until the *peer has acknowledged* it. Rather than duplicate
      that machinery, this reuses `struct magnus_quic_stream_t`'s own
      `body_chunk`/`body_chunk_length`/`body_chunk_offered`/
      `body_chunk_end_offset`/`body_offered_total`/`body_acked_total`/
      `nghttp3_wants_resume` fields directly -- the exact same ones
      roadmap 2a-4's own HTTP/3 proxy-dispatch compression already
      established this discipline for, safe because exactly one of
      `is_proxy` or a non-NULL `stream_compress` is ever true for a
      given stream. `magnus_quic_http_acked_stream_data()` (the shared
      ack callback) was extended to free the in-flight chunk and resume
      the stream for this case too. Unlike the mmap-based whole-file
      relay every other h3 static response uses, this path needed its
      own persistent file descriptor (`file_fd`/`file_offset`, new
      fields) since it reads the source file in bounded chunks via
      `pread()` rather than mapping it all at once.
      `tests/quic-handshake-check.c` (the only way to exercise HTTP/3
      at all in this project) had its fixed response-body buffer
      bumped from 1 MiB to 16 MiB so it could actually hold a whole
      well-past-8-MiB response for verification.

      Found and fixed a second real, previously-latent bug along the
      way: zstd's `ZSTD_compressStream2()` (`ZSTD_e_continue`) and
      Brotli's `BrotliEncoderCompressStream()` (`BROTLI_OPERATION_
      PROCESS`) both document that a single call is only guaranteed to
      make forward progress *consuming input*, not producing output --
      unlike zlib's `deflate()`, which is why gzip alone never exposed
      this. A single-call-per-invocation `nghttp3_data_reader` callback
      treated a zero-output result as "would block, wait to be
      resumed" -- but nghttp3's own resume mechanism has nothing to
      trigger it without a chunk ever having been offered, a genuine
      deadlock reproduced directly with both encoders on any file
      needing more than a trivial amount of compressed output. Fixed
      by looping inside the callback until real progress happens, the
      same discipline every other streaming-compression write loop in
      this codebase already follows; applied the identical fix to
      HTTP/2's own equivalent callback too, which never reproduced a
      hang in testing but only because of nghttp2's own eager retry
      timing, not any real guarantee. Verified: a file that previously
      timed out at 5+ seconds for both encoders now completes in under
      250ms, byte-exact, across repeated trials; direct ASan/UBSan
      testing of the live server (9 runs, all three encodings, zero
      findings) clean. See `CHANGELOG.md` 1.45.0 for the full detail.
    - **2a-10 — streaming proxy dispatch response compression, HTTP/1.1.
      Shipped in 1.46.0.** The one remaining dimension of "streaming/
      chunked compression above 8 MiB" once 2a-7/2a-8/2a-9 covered
      every static-file case: a `"/proxy"` response too large for
      2a-2's own buffer-then-compress shape (past
      `MAGNUS_COMPRESSION_MAX_SIZE`) now compresses incrementally
      instead of simply staying excluded, the same way it always was
      through 2a-9. Structurally different from every static-file
      streaming path: there is no file to `pread()` more of on demand
      -- upstream body bytes only ever arrive pushed, asynchronously,
      by the same `recv()` the ordinary uncompressed relay already
      uses (`magnus_handle_upstream()`), so this reuses `proxy_buffer`/
      `_length`/`_sent` directly as the compressor's own pending-input
      queue instead of adding a dedicated one, and the drain loop
      (`magnus_proxy_flush()`) simply re-arms the upstream fd and
      returns when it runs out of buffered input rather than looping
      to fetch more itself. Response headers go out immediately, the
      moment the upstream's own headers are known (`Content-Encoding`/
      `Vary`, no `Content-Length`, `Connection: close` -- the same
      framing choice 2a-7's own static-file streaming already made,
      via a new `(size_t) -2` sentinel on
      `magnus_proxy_sanitize_response_headers()`), rather than
      deferred the way 2a-2's own buffer-then-compress headers still
      are. HTTP/2 and HTTP/3 proxy dispatch streaming compression
      remain later increments. See `CHANGELOG.md` 1.46.0 for the full
      detail.
    - **2a-11 — streaming proxy dispatch response compression, HTTP/2.
      Shipped in 1.47.0.** The second protocol slice, confirming the
      same prediction 2a-8's own HTTP/2 static-file streaming
      compression already did: no close-delimited-framing workaround
      needed, since HTTP/2 never requires a Content-Length ahead of a
      DATA-frame response. Structurally different from 2a-8's own
      *pull*-based `nghttp2_data_provider2` callback (which fetches
      more input itself, on demand, via `pread()`): 2a-11's own input
      only ever arrives *pushed*, asynchronously, exactly like 2a-10's
      own HTTP/1.1 relay -- so this is a new push-driven fill function
      (`magnus_h2_proxy_stream_compress_response()`), called on every
      upstream-readable event, instead of a pull callback. `struct
      magnus_h2_stream`'s own `io_buffer` is repurposed as the
      compressed *output* queue (the pre-existing `magnus_h2_read_io_
      buffer()` pull callback already knows how to drain it correctly
      and report DEFERRED/EOF, so no new read callback was needed at
      all), with a new dedicated `proxy_stream_compress_inbuf` staging
      buffer for the not-yet-compressed raw bytes `recv()` delivers.

      Found and fixed one real bug along the way, this time self-
      inflicted rather than pre-existing: the first draft's own stream
      teardown (`magnus_h2_stream_free()`) freed `proxy_stream_compress_
      inbuf` directly, then unconditionally again inside `magnus_h2_
      stream_teardown_upstream()` (which already owns that cleanup,
      exactly the same way it already owns `compress_capture`/
      `cache_capture`'s own) -- a genuine double-free, caught
      immediately by a real heap-corruption abort (`corrupted size vs.
      prev_size while consolidating`) the moment this increment's own
      new `test-core.sh` block ran, not by a sanitizer pass. Fixed by
      removing the redundant free from `magnus_h2_stream_free()`,
      relying on `magnus_h2_stream_teardown_upstream()` (which it
      always calls) to free-and-NULL both fields exactly once, the
      same pattern `compress_capture`/`cache_capture` already
      established. Verified clean afterward: `make test` (twice) and
      direct ASan/UBSan testing of the live server (9+ h2 requests
      across all three encodings, plus a `--next` connection-reuse
      check and a plain-large-file regression check, zero findings).

      HTTP/3 proxy dispatch streaming compression is now the one
      remaining item on this whole roadmap thread. See `CHANGELOG.md`
      1.47.0 for the full detail.
    - **2a-12 — streaming proxy dispatch response compression, HTTP/3.
      Shipped in 1.48.0.** The third and final protocol slice, closing
      out the whole "streaming/chunked compression above 8 MiB" thread
      this roadmap has carried since 2a itself. Like HTTP/2, no
      close-delimited-framing workaround was needed. `struct magnus_
      quic_stream_t`'s own `body_chunk`/`body_chunk_length`/
      `body_chunk_offered`/`body_chunk_end_offset`/`body_offered_total`/
      `body_acked_total`/`nghttp3_wants_resume` fields are reused
      directly for the compressed output -- the same ACK-gated,
      one-fresh-allocation-per-chunk discipline every other h3 body
      source already established (the plain proxy relay, and 2a-9's
      own static-file streaming) -- with a new dedicated
      `proxy_stream_compress_inbuf` staging buffer for the not-yet-
      compressed raw bytes `recv()` delivers, and a new push-driven
      producer function (`magnus_quic_proxy_stream_compress_response()`)
      instead of 2a-9's own *pull*-based `read_data` callback shape,
      since h3's own proxy-dispatch input arrives pushed off the
      upstream socket rather than pulled on demand from a local file --
      exactly like 2a-10/2a-11's own HTTP/1.1 and HTTP/2 slices.

      Found and fixed a fourth real bug along this whole thread's way,
      the most subtle of the four: the new producer function called
      `magnus_quic_proxy_maybe_complete()` unconditionally whenever it
      produced *any* compressed chunk, but that shared helper
      independently re-derives "is this response complete" from raw
      upstream byte counts alone -- true the instant every raw byte has
      been *read*, not once the compressor has actually *flushed* (the
      still-pending `finish=true` call that would truly finish it can
      remain outstanding at that exact moment, since the producer's own
      finish flag is computed once per loop iteration and so
      necessarily lags by one). Calling the helper early marked the
      response complete while the compressor was still open, so the
      very next pull reported end-of-stream on a chunk that silently
      dropped gzip's own trailer and the last still-buffered bytes --
      every byte actually offered still reached the client correctly,
      and the byte counts even matched exactly, which is exactly why a
      live trace (adding temporary instrumentation and reproducing
      directly), not code review alone, was what actually found it.
      Fixed by gating the completion call on the compressor itself
      being done, not merely on a chunk having been produced. Verified:
      a 9 MB (well past the 8 MiB bound) upstream response now
      decompresses byte-exact via gzip/zstd/Brotli through a real live
      HTTP/3 proxy fetch (previously silently truncated for all three);
      `make test` (twice) and a full `make sanitize` run (ASan/UBSan,
      the whole suite including this increment's own new test) both
      clean.

      With 2a-10/2a-11/2a-12 all shipped, this closes out the entire
      "streaming/chunked compression above 8 MiB" item roadmap 2a
      itself first deferred -- every combination of static-file/proxy-
      dispatch response, across HTTP/1.1/HTTP/2/HTTP/3, and gzip/zstd/
      Brotli, now streams past the 8 MiB buffer-then-compress bound.
      See `CHANGELOG.md` 1.48.0 for the full detail.
    - **2a-13 — a real HTTP/1.1 `Transfer-Encoding: chunked` response
      writer. Shipped in 1.49.0.** This codebase's first -- the
      follow-up 2a-7's own doc comment always named as a natural next
      step, once a real chunked writer existed to build on (2a-7 itself
      deliberately chose the narrower close-delimited option to ship
      its own first slice without building one). Each produced chunk is
      framed *in place*, per RFC 9112 7.1, with no extra copy of the
      data itself: a fixed-width, zero-padded 5-hex-digit chunk-size
      header (`magnus_chunk_header()`, `MAGNUS_CHUNK_HEADER_SIZE` --
      five digits comfortably covers up to 0xFFFFF, well past
      `MAGNUS_STREAM_COMPRESS_CHUNK`'s own 0x10000 maximum, so it can
      never overflow) is written into a small reserved prefix
      immediately before wherever the real chunk data already landed,
      followed by its own trailing CRLF; the fixed 5-byte last-chunk
      (`"0\r\n\r\n"`, no trailer section -- this codebase never has one
      to send) is appended directly after the final real chunk's own
      trailing CRLF the moment the underlying producer reports done,
      all in the same buffer fill (`MAGNUS_CHUNK_FRAME_OVERHEAD` is the
      total extra capacity a chunk-framing buffer must reserve: header
      + data trailer + last-chunk = 7 + 2 + 5 = 14, rounded up to 16).
      This meant the existing "drain output, then finish once done"
      loop shape every streaming write loop in `magnus.c` already has
      needed no other change to support chunked framing -- the write
      loop neither knows nor cares that what it is draining is now
      chunk-framed rather than raw bytes, the same way it never needed
      to know the bytes were compressed at all.

      Applied to 2a-7's own HTTP/1.1 static-file streaming-compressed
      responses: `magnus_prepare_streaming_compressed_file_response()`
      now emits `Transfer-Encoding: chunked` and a real `Connection: %s`
      reflecting the client's own stated preference (`close_connection`,
      previously an unused parameter -- the response always forced
      `Connection: close` before), so these responses keep the
      connection alive afterward exactly like any other response here,
      instead of always closing. 2a-10's own HTTP/1.1 proxy-dispatch
      streaming-compressed responses remain close-delimited for now --
      a natural next application of the same writer, not yet wired in
      (see 2a-14, immediately below, for that follow-up).

      Verified: a 9 MB (well past the 8 MiB bound) static file
      compresses correctly via gzip/zstd/Brotli and decodes byte-exact
      through curl's own transparent chunked-decoding, with
      `Transfer-Encoding: chunked` and `Connection: keep-alive` present
      and no `Content-Length`; a follow-up request over the same
      connection right after (curl's own `--next`, `num_connects: 0`)
      confirms the connection genuinely stays alive; an explicit
      client-requested `Connection: close` is still honored, not
      silently overridden. `make test` (twice) and a full `make
      sanitize` run (ASan/UBSan, the whole suite including this
      increment's own updated test-core.sh assertions) both clean.
      See `CHANGELOG.md` 1.49.0 for the full detail.
    - **2a-14 — the same chunked writer, applied to HTTP/1.1 proxy
      dispatch streaming compression. Shipped in 1.50.0.** 2a-13's own
      "natural next application, not yet wired in" -- 2a-10's own
      responses previously stayed close-delimited unconditionally, the
      one framing choice this whole "streaming/chunked compression
      above 8 MiB" thread had left unresolved once every static-file
      case (2a-13) already had a real chunked writer to fall back on.

      A third sentinel, `(size_t) -3`, joins the existing `(size_t)
      -1`/`(size_t) -2` ones on `magnus_proxy_sanitize_response_
      headers()`: identical to `(size_t) -2` in every other respect
      (still no `Content-Length`, still emits `Content-Encoding`/
      `Vary`, still called once immediately rather than deferred), but
      emits `Transfer-Encoding: chunked` instead and leaves
      `keep_client_alive` to the ordinary `client_wants_close` decision
      every non-streaming response already gets, rather than forcing
      "close" regardless. `magnus_proxy_flush()`'s own streaming-
      compress write loop frames each produced chunk in place using
      the identical `magnus_chunk_header()`/`MAGNUS_CHUNK_HEADER_SIZE`/
      `MAGNUS_CHUNK_FRAME_OVERHEAD` machinery 2a-13 already built,
      reusing it rather than duplicating it -- the loop shape needed no
      other change here either. `close_after_write` is now decided
      once, correctly, from the client's own stated preference the
      moment headers go out (previously forced `true` unconditionally
      both there and again when the compressor finished). HTTP/2 and
      HTTP/3 proxy dispatch streaming compression (2a-11/2a-12) keep
      using `(size_t) -2`'s own close-delimited framing unchanged --
      chunked encoding is an HTTP/1.1-only concept, and neither
      protocol ever needed a workaround to stay alive afterward in the
      first place.

      Verified: a 9 MB (well past the 8 MiB bound) upstream response
      compresses correctly via gzip/zstd/Brotli through a real live
      proxy fetch, byte-exact after decoding, with `Transfer-Encoding:
      chunked` and `Connection: keep-alive` present and no `Content-
      Length`; a follow-up request over the same connection right after
      (curl's own `--next`, `num_connects: 0`) confirms the connection
      genuinely stays alive; an explicit client-requested `Connection:
      close` is still honored; the pre-existing buffer-then-compress
      and plain-relay proxy paths are unaffected. `make test` (twice)
      and direct ASan/UBSan testing of the live server (multiple
      requests across all three encodings plus connection-reuse and
      regression checks, zero findings) both clean -- `make sanitize`'s
      own wrapped run hit the known pre-existing ASan-timing-sensitive
      h2 stream-flood flake before ever reaching this increment's own
      code. A `git stash`/rebuild/reproduce/`git stash pop` A/B check
      also confirmed several other intermittent `test-core.sh` failures
      hit while iterating on this increment were pre-existing
      environmental flakiness, not caused by this change: the identical
      failures reproduced against the unmodified v1.49.0 baseline with
      this increment's own changes fully stashed away. See
      `CHANGELOG.md` 1.50.0 for the full detail.
  - **Real IP 2b — PROXY protocol v1/v2, Forwarded/X-Forwarded-For.
    Shipped in 1.12.0.** Entirely gated on a `trusted_proxies` CIDR
    allowlist (default off); resolution feeds `source_cidr` route
    matching, rate limiting, and access logging alike, always trusting
    only the connection's true direct TCP peer. Was pulled ahead of the
    rest of Phase 2 exactly for the reason flagged above: ACL/rate-limit
    correctness downstream depends on knowing the real client address
    first. **Extended to HTTP/3 in 1.40.0** -- turned out to need no new
    QUIC-specific mechanism, since Forwarded/X-Forwarded-For resolution
    operates purely on already-parsed HTTP headers, identically
    regardless of protocol; only PROXY protocol v1/v2 genuinely has no
    QUIC analogue (no raw preamble concept once ngtcp2/nghttp3 have
    already framed a stream's headers) and stays out of scope. See
    `CHANGELOG.md` 1.40.0 for the full detail.
  - **gRPC 2c — sub-scoped the same way 1e was, given the same "expected
    to be the largest single piece of work" sizing:**
    - **2c-1 — h2-to-h2 upstream dispatch, unary RPCs only. Shipped in
      1.13.0.** New `action=grpc` route + separate `grpc_upstream`
      cluster; a second, magnus-owned CLIENT-role nghttp2 session per
      stream drives the upstream leg (translating through the existing
      HTTP/1.x `action=proxy` path was never viable -- no trailers).
      Whole-response buffering (no true streaming yet), no upstream
      connection pooling/session affinity, IPv4-literal upstreams only.
      Verified against a real `grpcio` client and server. See
      `CHANGELOG.md` 1.13.0 for the full detail.
    - **2c-2 — true client-/server-streaming and bidi support. Shipped
      in 1.14.0.** Removed 2c-1's "buffer the whole request/response
      before dispatch" shape on both legs: dispatch now happens as soon
      as request HEADERS complete (a new `request_end_stream_seen` flag
      decouples that from "the whole request is known," which every
      non-gRPC route still requires before it may act), and DATA flows
      through as it arrives in each direction independently, via the
      same deferred/resume data-provider pattern the h1-proxy path
      (1e-2) already established for its own response leg. Verified
      against a real `grpcio` client and server across every RPC shape,
      including a timing-verified server-streaming case proving genuine
      incremental delivery. See `CHANGELOG.md` 1.14.0 for the full
      detail, including a real h2c (1e-5) regression this increment's
      own dispatch-timing change caused and fixed along the way.
    - **2c-3 — `grpc-timeout` deadline propagation. Shipped in 1.15.0.**
      Parses the request header into an absolute deadline (clamped to a
      new `MAGNUS_GRPC_MAX_TIMEOUT_MS`, 5 minutes) that replaces this
      stream's own connect/read timeout budget in the existing
      `magnus_expire_proxies()` sweep when present, falling back to the
      pre-existing default budget unchanged otherwise. Verified against
      a real `grpcio` client raising `DEADLINE_EXCEEDED` correctly, plus
      a raw socket client with no client-side timer of its own proving
      magnus's own server-side sweep is what enforces it. See
      `CHANGELOG.md` 1.15.0 for the full detail.
    - **2c-4 — gRPC-aware routing/observability polish. Shipped in
      1.16.0.** New `header_prefix:<name>=<value>`
      route condition (a `header:<name>=<value>` exact match can never
      reliably gate on gRPC's own `content-type: application/grpc[+codec]`
      shape); `grpc-status`-aware access logging and a new
      `magnus_grpc_status_total{code="N"}` `/metrics` counter (2c-1
      deliberately never touched `magnus_responses_4xx/5xx` for a gRPC
      outcome, since the wire `:status` is always 200 -- see
      `magnus_h2_grpc_fail()`'s own comment; this is what actually
      answers "how many gRPC calls failed, and how"); session affinity
      for `action=grpc` routes, mirroring the h1/h2-proxy paths exactly
      (`MAGNUS_AFFINITY` cookie, read and issued the same way). Deferred a `grpc_service=<name>` `:path`
      condition as redundant -- `path_prefix=/pkg.Service/` already
      expresses the same scoping with the existing mechanism, so a
      dedicated condition would not have earned its own code. Also
      deliberately out of scope: upstream connection pooling/
      multiplexing for the gRPC cluster (a fresh TCP+h2 handshake per RPC
      remains unchanged from 2c-1) -- architecturally comparable in size
      to 2c-2's own streaming rework, not a "polish" item, left for a
      future increment of its own. Verified against a real `grpcio`
      client and server, including its own `initial_metadata()` showing
      the exact `Set-Cookie` this increment issues, and 10 further calls
      carrying it back sticking to the same upstream endpoint every time
      against a cluster that round-robins without one. See
      `CHANGELOG.md` 1.16.0 for the full detail.
    - **2c-5 — upstream connection pooling + stream multiplexing. Shipped
      in 1.17.0 -- closes out the gRPC track.** Replaces 2c-1's
      one-fresh-TCP+h2-handshake-per-RPC design with a small pool
      (`MAGNUS_GRPC_POOL_MAX_CONNS_PER_ENDPOINT`, 4) of shared, long-lived
      upstream connections per endpoint that many concurrent client-side
      gRPC streams multiplex onto via nghttp2's own `stream_user_data`
      mechanism (`nghttp2_submit_request2()`'s last parameter,
      `nghttp2_session_get_stream_user_data()` to resolve which
      `magnus_h2_stream` a given upstream frame belongs to) -- no
      hand-rolled stream-id map needed. `magnus_grpc_conn_pick()` prefers
      opening a fresh connection while the pool has room and every
      existing one already has real load on it, and only multiplexes onto
      an existing connection once the pool is fully warm ("pool for
      parallelism, multiplex for overflow"); nghttp2 itself queues a
      request past the peer's own advertised
      `SETTINGS_MAX_CONCURRENT_STREAMS` and sends it automatically once
      room frees up, so magnus never needs to track or enforce that limit
      for correctness, only for this load-spreading heuristic. A
      connection is recycled (GOAWAY-style: stop accepting new streams,
      let attached ones finish, then close) after
      `MAGNUS_GRPC_POOL_MAX_REQUESTS_PER_CONNECTION` (100000) RPCs or
      `MAGNUS_GRPC_POOL_IDLE_TIMEOUT_SECONDS` (60) of no attached streams,
      and unconditionally on a received GOAWAY or any fatal I/O error
      (which fans a clean UNAVAILABLE out to every stream still attached,
      via a connection-owned intrusive list of them). Deliberately
      accepted trade-off: an *async* connect/I/O failure discovered via
      epoll no longer transparently retries the affected RPC(s) onto a
      different endpoint the way pre-pooling 2c-1..2c-4 did (a *synchronous*
      failure picking the very first connection to a never-yet-proven
      endpoint still does) -- see `magnus_h2_grpc_start()`'s own comment
      on why this is judged an acceptable narrowing rather than an
      oversight (UNAVAILABLE is specifically the one gRPC status real
      client libraries already retry on their own by default). Verified
      against a real `grpcio` server: 30 concurrent client RPCs measurably
      multiplexed onto exactly 4 physical upstream connections (`ss -tn`
      during the burst), completing in ~0.1s against a 50ms-per-call
      server-side delay -- proof of genuine concurrent multiplexing within
      one connection, not just connection-level parallelism -- plus
      confirmed connection reuse across separate, non-overlapping request
      bursts. See `CHANGELOG.md` 1.17.0 for the full detail, including a
      real bug this increment found and fixed (a client-role nghttp2
      session that never calls `nghttp2_submit_settings()` once silently
      stops invoking frame callbacks for everything the peer sends back
      after its own initial SETTINGS, indistinguishable from a hung
      connection without instrumenting nghttp2's own call sequence to
      notice).
  - **Reverse-proxy cache 2d-1 — bounded in-memory cache with revalidation,
    opt-in per route. Shipped in 1.18.0.** New module `magnus_cache.c`/`.h`:
    a fixed-capacity (`MAGNUS_CACHE_MAX_ENTRIES`, 512), byte-budgeted
    (`MAGNUS_CACHE_MAX_BYTES`, 64MiB; `MAGNUS_CACHE_MAX_ENTRY_BYTES`, 8MiB),
    LRU-evicted store shared by both the HTTP/1.1 and HTTP/2 proxy dispatch
    paths (one cache, keyed on host+target -- a response stored via one
    protocol is servable to the other). Applied only to a route that
    explicitly opts in via a new `cache=on|off` route modifier
    (`action=proxy; cache=on`) -- never a global default, since caching a
    response the origin never intended to be shared would be a
    correctness bug, not just a missed optimization. Cacheability follows
    RFC 7234's core rules, narrowed for this increment: only a GET request
    and a `200` response with an explicit freshness signal (`Cache-Control:
    max-age` or `Expires`) is ever stored; `no-store`/`private`, a response
    carrying `Set-Cookie`, or a `Vary` other than (absent or) `Accept-
    Encoding` are excluded outright. A fresh hit is served entirely
    without touching the upstream (`X-Cache: HIT`); a stale entry that
    still carries an `ETag`/`Last-Modified` validator is revalidated via a
    conditional GET (`If-None-Match`/`If-Modified-Since`) rather than
    re-fetched in full -- a confirming `304` refreshes freshness and is
    answered from the *cached* body with no second body transfer
    (`X-Cache: REVALIDATED`); an origin that instead sends fresh content
    on that same conditional GET is treated as an ordinary fetch,
    replacing the stale entry. `/metrics` gained
    `magnus_cache_hits_total`/`_misses_total`/`_revalidated_total` and
    entry-count/byte-usage gauges. Deliberately out of scope: heuristic
    freshness (no fallback when neither header is present), Vary-keyed
    multi-variant storage, an explicit purge API (the whole cache is
    flushed wholesale on config reload or shutdown instead), and dogpile/
    request-coalescing protection for a concurrent stampede on a still-
    uncached URL. Verified against a real Python `http.server` origin
    across both protocols and every rule above (hit/miss/no-store/Set-
    Cookie/Vary exclusion/revalidation-confirmed/revalidation-superseded/
    cross-protocol sharing/per-route opt-out), under ASan+UBSan -- which
    caught two real bugs found only through that live testing, not code
    review: (1) the HTTP/1.1 completion path referenced
    `connection->proxy_header_out` for the stored header prefix, not
    realizing that buffer is freed the moment its own bytes finish
    reaching the client -- typically well before the body, and therefore
    this cache store, complete -- fixed by copying the storable prefix out
    into its own persisted field at header time instead (the h2 path
    already had to do this, having no persisted raw-text buffer at all,
    which is what surfaced the h1 analogue as a real gap by comparison);
    (2) an HTTP/2 cache-hit/revalidation response called
    `magnus_h2_push()` immediately after submitting, which can drive
    nghttp2 far enough to close and free the very stream the *caller*
    (already inside `nghttp2_session_mem_recv2()`'s own callback stack)
    still needed afterward -- fixed by removing the premature push and
    relying on the existing single, safe push each call path already
    performs once, after the whole callback chain has fully unwound. See
    `CHANGELOG.md` 1.18.0 for the full detail.
  - **Advanced load balancing 2e-1 — least-connections and IP-hash
    policies, rendezvous-hashed affinity. Shipped in 1.19.0.** New
    `magnus_lb_policy_t` (`round_robin` [default, unchanged], `least_conn`,
    `ip_hash`), configured once per `magnus_cluster_t` via a new
    `lb_policy=` config key / `--lb-policy` CLI flag (mirrors
    `access_log=`'s own on/off validation pattern) -- a client's own
    `MAGNUS_AFFINITY` cookie, when present, still always wins over
    whichever policy is configured; the policy only governs a *fresh*
    selection. `least_conn` picks the healthy endpoint with the fewest
    requests currently in flight, tracked live via new
    `magnus_cluster_endpoint_begin()`/`_end()` calls at every h1/h2 proxy
    attach/teardown point (four distinct completion paths per protocol --
    normal teardown, and an inline pool-checkin branch that bypasses it,
    for both a fresh response and a 304-revalidation completion -- each
    guarded by a new idempotent `proxy_endpoint_counted`/
    `cluster_endpoint_counted` flag so a begin is released exactly once no
    matter which path an attempt ends through). `ip_hash` and the
    pre-existing cookie-affinity mechanism both now share one rendezvous
    (highest-random-weight) hashing primitive in place of the old naive
    `hash(key) % count` + linear-probe scheme: score = an FNV-1a hash of
    the selection key (client IP bytes, or the affinity cookie token)
    combined with each endpoint's own `"address:port"` identity, highest
    score wins -- the property this buys over modulo hashing is that
    adding or removing one endpoint only remaps the traffic that
    endpoint's own score was responsible for, never a wholesale reshuffle
    of every other endpoint's clients. `/metrics` gained a per-endpoint
    `magnus_upstream_active_requests` gauge alongside the pre-existing
    `magnus_upstream_healthy`. Deliberately out of scope: the separate
    `magnus_grpc_cluster` (its own connection-pooling lifecycle from
    2c-5) does not get a configurable policy or live least-conn counting
    in this increment -- it stays hardcoded at `round_robin`. Verified
    against real concurrent/asymmetric-delay backends under ASan+UBSan:
    `least_conn` correctly avoided a backend held busy by an in-flight
    request (confirmed busy via `/metrics`' own gauge, not a fixed sleep)
    for two concurrent follow-up requests; `ip_hash` deterministically
    routed the same client IP to the same endpoint across both HTTP/1.1
    and HTTP/2 requests against one shared cluster. See `CHANGELOG.md`
    1.19.0 for the full detail.
  - **Active health check expansion 2f-1 — HTTP-level probing, gRPC
    cluster coverage, full configurability. Shipped in 1.20.0 -- closes
    out Phase 2's own headline scope.** The `upstream` cluster's active
    probe (independent of live traffic, see M3) upgrades from a bare
    non-blocking TCP `connect()` to a real HTTP/1.1 `GET` against a
    configurable `health_check_path`, success iff the response status
    equals a configurable `health_check_expected_status` -- catching a
    backend that accepts connections but answers every request with a
    5xx, which a bare `connect()` could never tell apart from actually
    healthy. `health_check_interval_seconds`/`_timeout_seconds`/
    `_failure_threshold`/`_cooldown_seconds` (previously hardcoded
    constants) are now config keys / matching `--health-check-*` CLI
    flags, the failure/cooldown pair shared by both clusters' circuit-
    breaker state exactly as it already was pre-2f. The `grpc_upstream`
    cluster -- which had no active probe at all before this increment,
    only whatever live gRPC traffic happened to reveal -- now gets one
    too, deliberately kept TCP-connect-only rather than an HTTP/1.1 GET:
    a real gRPC server is typically HTTP/2-only, and a raw HTTP/1.1
    request line into that socket would get every probe rejected by a
    perfectly healthy backend, a false-negative regression rather than
    real coverage. `/metrics` gained `magnus_grpc_upstream_healthy{endpoint=...}`,
    mirroring the `upstream` cluster's pre-existing `magnus_upstream_healthy`.
    Both probe state machines (CONNECTING -> (HTTP mode only) SENDING ->
    READING) share one parameterized implementation, dispatched twice per
    tick -- see `magnus_health_tick()`'s own comment on why a single
    unified loop would not actually simplify anything. A reload
    (`magnus_apply_config()`) now also closes every in-flight probe and
    resets its next-probe timer, the same stale-by-position fix already
    applied to the two connection pools and the cache on every prior
    reload-touching increment -- an in-flight probe for old position N
    otherwise belongs to whatever backend used to be there, not
    necessarily the new cluster's position N. Deliberately out of scope:
    a way to disable active checking per cluster (it stays unconditionally
    on, exactly as the pre-2f TCP-only version already was); a real gRPC
    Health Checking Protocol probe for the `grpc_upstream` cluster (a much
    larger increment: full HTTP/2 framing plus the standard
    `grpc.health.v1.Health/Check` service, not a probe-mechanism tweak).
    Verified live: a real HTTP/1.1 GET against a backend that accepts
    every TCP connection but always answers 500 is found unhealthy by
    active checking alone (no proxy traffic sent, same M3 discipline);
    the same backend configured healthy via a different
    `health_check_path` stays healthy the whole time, proving the new
    knobs actually reach the probe; a `grpc_upstream` endpoint that is
    simply down is found (and, once a listener comes up, recovered)
    purely via the background TCP-connect probe. One real bug caught by
    this live testing, not code review: the new HTTP-mode probe's GET
    request reaches a real backend's own request handler (unlike the
    pre-2f bare `connect()`, which never sent a byte) -- the pre-existing
    cache regression test's exact upstream-hit-counter assertions
    (`tests/test-core.sh`) broke because the default 5-second probe
    interval could now land a background GET on the same fake upstream
    those assertions count against; fixed by pushing that test's own
    `--health-check-interval` out past its runtime, not by changing
    product behavior. See `CHANGELOG.md` 1.20.0 for the full detail.
- **Phase 3 — L4 TCP/UDP, TLS passthrough, PROXY protocol.** Architecturally
  distinct from the L7 phases: a new listener type that doesn't go through
  `magnus_http_parse` at all. UDP session tracking's memory bound (Section
  12) needs its design nailed down before implementation, not discovered
  during it.
  - **TCP passthrough 3a — a second, independent listener with zero HTTP
    awareness. Shipped in 1.21.0.** New `stream_listen`/`stream_upstream`/
    `stream_lb_policy` config keys and matching `--stream-listen`/
    `--stream-upstream`/`--stream-lb-policy` CLI flags stand up a raw
    bidirectional byte relay between a client and whichever endpoint a
    dedicated `magnus_stream_cluster` picks -- one listener/cluster for
    this first increment, deliberately scoped that way (multiple
    simultaneous stream listeners is a distinct future increment). Reuses
    the h1/h2 proxy path's existing infrastructure unmodified rather than
    inventing new load-balancing or health-checking code:
    round_robin/least_conn/ip_hash (roadmap 2e-1's rendezvous hashing,
    keyed on client IP since there is no HTTP-level cookie at L4 -- no
    cookie-based affinity here), the same circuit-breaker
    trip/cooldown state, and active health checking (roadmap 2f,
    TCP-connect only -- what is actually flowing over a stream connection
    is unknown by design, so an HTTP-level probe would be meaningless).
    A small `magnus_stream_conn_t`/`magnus_stream_pipe_t` pair (kept
    separate from the much larger HTTP-oriented `magnus_connection_t`,
    matching this codebase's own precedent of a new protocol surface
    getting its own lightweight state rather than growing the existing
    one) drives two independent byte pipes with per-direction epoll-
    interest backpressure -- a slow destination simply stops its source
    side being read from until the buffered chunk drains, the same
    discipline the L7 proxy's own buffered-write path already uses, just
    without any HTTP framing to track alongside it. A standard half-close
    (one direction EOFs and is `shutdown()`-propagated while the other
    keeps flowing) is supported, since an L4 tunnel has no request/
    response boundary to assume. No retry budget on a connect() failure,
    unlike the L7 proxy path -- there is no "request" to safely retry
    once any bytes have moved over an already-in-progress byte stream.
    `/metrics` gained `magnus_stream_connections_total`/`_active`,
    `magnus_stream_bytes_total{direction=...}`, and
    `magnus_stream_upstream_healthy{endpoint=...}`. Verified live under
    ASan+UBSan against real backends: round_robin alternation and
    persistent-connection stickiness (the LB decision is made once per
    connection, never per message); `ip_hash` same-client determinism;
    a 300KiB payload relayed byte-for-byte across many
    `MAGNUS_PROXY_BUFFER` (16KiB) refills plus a half-close, verified via
    SHA-256 rather than a labelled echo (see the bug below); active
    health check detecting a killed backend, and its recovery, with zero
    stream traffic sent, mirroring the M3/2f-1 discipline. One real bug
    found only through this live testing, not code review: `/metrics`'
    fixed response buffer (`MAGNUS_OUTPUT_LIMIT`, 2048 bytes) was already
    tight before this increment and this increment's own new gauge block
    pushed a real multi-cluster deployment's rendered body past it --
    silently emptying the *entire* HTTP response rather than truncating
    the body, since the buffer-overflow guard in `magnus_prepare_response()`
    treats "would not fit" as "send nothing" for safety. Fixed by growing
    both `MAGNUS_METRICS_BUFFER` (1536 -> 8192) and `MAGNUS_OUTPUT_LIMIT`
    (2048 -> 9216) with real headroom for a fully-populated deployment
    (`upstream` + `grpc_upstream` + `stream` clusters all near their max
    endpoint count, every gRPC status code, every latency bucket) rather
    than just enough for this increment's own test. Deliberately out of
    scope: TLS passthrough / SNI routing (3b) and UDP (3d) remain
    separate future increments, per this section's own scoping. See
    `CHANGELOG.md` 1.21.0 for the full detail.
  - **TLS passthrough / SNI routing 3b — route by ClientHello hostname
    without ever terminating TLS. Shipped in 1.22.0.** New module
    `magnus_sni.c`/`.h`: a bounded parser reading only as much of a TLS
    record as is needed to find the `server_name` extension in a
    ClientHello (RFC 6066 3) -- never a general TLS parser, and
    deliberately does not handle a ClientHello split across more than one
    TLS record (vanishingly rare in practice; falls back the same way any
    other unresolved case does). New `stream_sni_route` config key /
    `--stream-sni-route` CLI flag: `"<pattern> <ipv4:port[:weight]>"`,
    pattern either an exact hostname or a `*.`-prefixed one (requiring at
    least one label before the dot, so `*.example.com` matches
    `www.example.com` but not `example.com` itself), repeatable and
    accumulating into that pattern's own independent `magnus_cluster_t`
    (own round_robin selection, own passive circuit-breaker state) --
    layered strictly on top of 3a's existing `stream_upstream` cluster,
    never a replacement for it. A stream connection now has a third stage
    ahead of connecting/relaying, `MAGNUS_STREAM_PEEKING`, entered only
    when at least one `stream_sni_route` is configured (zero peeking
    overhead otherwise, identical to 3a); the client's initial bytes are
    read directly into the same buffer `magnus_stream_pump()` already uses
    for its client-to-upstream relay, so once a cluster is picked those
    genuine ClientHello bytes are exactly what gets flushed to the
    backend first -- true passthrough, never re-encoded or copied
    elsewhere. Every unresolved outcome (no `stream_sni_route` configured
    at all, a parsed-but-unmatched hostname, a definitively-not-TLS or
    malformed ClientHello, the peek buffer filling up without resolving,
    the client closing early, or a new `MAGNUS_STREAM_PEEK_TIMEOUT_SECONDS`
    (5s) timeout) falls back to the plain `stream_upstream` cluster, which
    `stream_listen` already requires be present. `/metrics` gained
    `magnus_stream_sni_upstream_healthy{pattern=...,endpoint=...}`.
    Deliberately out of scope for this increment: active health checking
    for `stream_sni_route` clusters (passive, connect-result-driven health
    only -- a dynamic, unbounded-in-principle set of small clusters is a
    distinct future increment away from the "one active-probe-array per
    cluster" shape every other cluster in this file already uses) and a
    configurable per-pattern load-balancing policy (round_robin only,
    same scope cut the gRPC cluster's own policy already has). Verified
    live under ASan+UBSan against real ClientHellos captured from
    Python's own `ssl` module (not hand-typed) across three backends:
    exact-pattern match, wildcard match, a bare domain correctly *not*
    matching its own wildcard, an unmatched hostname, and plain non-TLS
    traffic -- the last three all confirmed falling back to the default
    cluster, with the matched cases additionally confirmed to relay the
    original ClientHello bytes byte-for-byte unmodified; a ClientHello
    trickled in dozens of tiny writes (forcing many separate epoll events
    through the peek/re-arm loop rather than resolving synchronously in
    one read) routed identically to the single-write case; a client that
    never sends anything at all was found and fell back to the default
    cluster after the peek timeout, not held open indefinitely. New unit
    and fuzz coverage in `tests/test-sni.c`/`tests/fuzz-sni.c` (200k
    mutation-based iterations, including a real captured TLS 1.3
    ClientHello as a seed, not just hand-built ones) and new permanent
    regression coverage in `tests/test-core.sh`. See `CHANGELOG.md`
    1.22.0 for the full detail.
  - **UDP passthrough 3d — a fourth, independent listener, NAT-style
    session tracking, no HTTP/TCP machinery involved at all. Shipped in
    1.23.0.** New `udp_listen`/`udp_upstream`/
    `udp_lb_policy`/`udp_session_idle_seconds`/`udp_max_sessions` config
    keys and matching `--udp-*` CLI flags. Plain `SOCK_DGRAM`, no
    `accept()`/handshake of any kind (UDP has neither) -- one NAT-style
    `magnus_udp_session_t` per distinct (source IP, source port) tuple the
    listener has ever seen recently, each owning its own dedicated
    `connect()`ed UDP socket to whichever backend `magnus_udp_cluster`
    picked for that tuple, the same "one socket per active flow" pattern
    every other cluster in this file already uses for TCP -- reusing
    `round_robin`/`least_conn`/`ip_hash` (`ip_hash` keyed on source IP
    alone, so unrelated source ports from the same client still land on
    the same backend) and the exact same `magnus_cluster_endpoint_begin()`/
    `_end()` live-count mechanism roadmap 2e-1 already built, here
    repurposed as "sessions currently pinned to this endpoint" rather than
    "requests". **The "Section 12" memory bound the roadmap itself
    flagged needing a real answer before implementation, not discovered
    mid-implementation**: `udp_max_sessions` (default 1024, hard ceiling
    `MAGNUS_UDP_MAX_SESSIONS_CEILING` = 4096, a fixed array, no dynamic
    allocation) is enforced by simply dropping a new tuple's packet once
    full -- deliberately never evicting an existing session to make room,
    since UDP's trivially spoofable source address would otherwise turn
    eviction itself into a denial-of-service primitive against whichever
    legitimate client got evicted. No health tracking of any kind, active
    or passive: a `connect()`ed UDP socket's own `connect()` call succeeds
    locally almost unconditionally regardless of whether the backend
    actually exists (no handshake to fail the way TCP's SYN/ACK would),
    so it carries none of the passive signal `magnus_cluster_result()`
    relies on elsewhere in this file -- the same scope-cut precedent
    `stream_sni_route`'s own clusters (roadmap 3b) already set, for the
    same underlying reason. A hard read error on a session's own backend
    socket (most notably `ECONNREFUSED`, which Linux can surface on a
    `connect()`ed UDP socket from a matching ICMP port-unreachable -- the
    one real liveness signal UDP offers at all) tears that session down
    immediately rather than waiting out the idle timeout. `udp_listen`
    deliberately carries no "must differ from `port`/`stream_listen`"
    restriction, unlike `stream_listen` itself -- UDP and TCP occupy
    independent port namespaces at the OS level, so there is no actual
    conflict to guard against. `/metrics` gained
    `magnus_udp_sessions_total`/`_active`,
    `magnus_udp_bytes_total{direction=...}`, and
    `magnus_udp_upstream_active_sessions{endpoint=...}` -- no
    healthy/unhealthy gauge, since exposing one that could only ever read
    "always healthy" would be actively misleading rather than merely
    unused. Verified live under ASan+UBSan against real UDP backends:
    `round_robin` alternation across distinct clients plus per-session
    stickiness for repeated messages from the same client; `ip_hash`
    routing separate sockets sharing one source IP to the same endpoint;
    the session cap dropping exactly the packets past the configured
    ceiling while leaving already-active sessions untouched; a session
    pointed at a genuinely unreachable backend torn down within
    ~1.5s via the ICMP-triggered `ECONNREFUSED` path rather than sitting
    out its full idle timeout. New permanent regression coverage in
    `tests/test-core.sh`. See `CHANGELOG.md` 1.23.0 for the full detail.
  - **PROXY protocol emission 3e — the last item on this phase's own
    headline, and the reverse direction from Real IP 2b's own
    `magnus_proxy_proto_parse()`: magnus here is the *emitter*, not the
    receiver, prefixing its own outbound connection to a stream backend
    with a preamble identifying the real (source IP, source port) a
    plain relayed TCP connection would otherwise never reveal (every
    connection would otherwise look like it originates from magnus's own
    address). Shipped in 1.24.0 -- closes out Phase 3.** New
    `stream_proxy_protocol=off|v1|v2` config key / `--stream-proxy-
    protocol` CLI flag, defaulting to `off` (unconditionally on would
    break any existing deployment whose backend does not already expect
    this preamble as its first bytes). `magnus_proxy_proto_build()`
    (new, in `magnus_realip.c`/`.h`, alongside the parse-side function it
    mirrors) renders either the v1 text format (`PROXY TCP4 <src> <dst>
    <sport> <dport>\r\n`) or the fixed 28-byte v2 binary layout reusing
    the same `MAGNUS_PROXY_V2_SIG` signature constant the parser already
    defines. Scoped to TCP stream passthrough only for this increment
    (deliberately excluding UDP passthrough's own distinct "per-datagram
    header" v2 variant, a real complexity/compatibility trade-off left
    for a future increment) and applied uniformly across the whole
    `stream_listen` surface regardless of which cluster a connection
    ends up at -- the plain `stream_upstream` default cluster or a
    matched `stream_sni_route` one (3b) -- a first-increment
    simplification assuming homogeneous backend expectations; a
    per-pattern override is a distinct possible future increment, not
    silently half-done. The header is built once, synchronously, right
    when `magnus_stream_connect()`'s own `connect()` resolves (whether
    that happens immediately or later, confirmed asynchronously), and
    flushed to the backend before a single byte of actual relay traffic
    -- a real, previously-latent gap was found and fixed along the way:
    `magnus_stream_accept()`'s own non-SNI branch had no follow-up call
    at all after a successful connect (harmless before this increment,
    since there was nothing to proactively send), fixed by a new shared
    `magnus_stream_after_connect()` helper now called from every
    connect() call site. Hot-reloadable, like `stream_lb_policy`, since
    no listening socket is involved. Verified live under ASan+UBSan
    against real backends parsing both wire formats off the wire: v1 and
    v2 each independently confirmed as the literal first bytes on the
    connection, `off` (the default) confirmed to send no preamble at all
    (unchanged 3a/3b behavior), and the SNI-routing combo (3b) confirmed
    to still deliver the peeked ClientHello prefix byte-for-byte
    immediately after the PROXY header. New unit coverage in
    `tests/test-realip.c` (exact wire-format bytes for both versions,
    including a build/parse round-trip) and new permanent regression
    coverage in `tests/test-core.sh`. See `CHANGELOG.md` 1.24.0 for the
    full detail.
- **Phase 4 — HTTP/3/QUIC.** Per the master prompt's own instruction
  (Section 4), not hand-rolled — evaluated against vetted libraries
  (e.g. an OpenSSL-integrated QUIC stack vs. quiche vs. msquic) in
  Section 5's dependency framework before any code: see
  `docs/phase4-http3-quic-dependency-evaluation.md` (ngtcp2 + nghttp3
  chosen) and `docs/phase4-spike-results.md` (standalone verification
  against a real OpenSSL 3.5 before any of it touched `magnus.c`).
  **4a (transport/handshake only) shipped in 1.25.0, 4b (HTTP/3
  static-file GET/HEAD) in 1.26.0, 4c (HTTP/3 `/healthz`/`/metrics`,
  admin isolation extended to the QUIC listener) in 1.27.0, 4d (HTTP/3
  `"/proxy"` dispatch to a real HTTP/1.1 upstream, reusing the same
  cluster/passive-health and response-sanitization primitives HTTP/1.1
  and HTTP/2 already share) in 1.28.0, 4e (HTTP/3 static-file gzip
  compression, the same scope compression 2a shipped for HTTP/1.1 and
  HTTP/2) in 1.29.0, 4f (HTTP/3 `route` table dispatch --
  host/path-prefix/method/header/header_prefix/cookie/query/source-CIDR
  matching, the same DSL and matcher HTTP/1.1 and HTTP/2 already share)
  in 1.30.0, 4g (HTTP/3 proxy dispatch retry-on-connect-failure, the
  same total-attempts budget HTTP/1.1 and HTTP/2 proxy dispatch already
  have) in 1.31.0, 4h (HTTP/3 proxy dispatch cookie-based session
  affinity, the same `MAGNUS_AFFINITY`-cookie precedence and
  `Set-Cookie`-issuing code HTTP/1.1 and HTTP/2 proxy dispatch already
  share) in 1.32.0, 4i (HTTP/3 reverse-proxy response caching for proxy
  dispatch, one shared bounded/LRU-evicted cache with HTTP/1.1 and
  HTTP/2, not one per protocol) in 1.33.0, 4j (HTTP/3 upstream
  connection pooling for proxy dispatch, one shared endpoint-keyed idle
  pool with HTTP/1.1 and HTTP/2 -- closes out HTTP/3 proxy dispatch's
  parity with theirs) in 1.34.0, 4k (QUIC retry-based stateless address
  validation, RFC 9000 8.1.2 -- a fresh connection's first `Initial`
  must prove its claimed source address is real, via a server `Retry`
  carrying an authenticated token, before any connection state is
  allocated for it, closing off both off-path amplification and
  connection-slot exhaustion by junk `Initial` floods; a new
  `magnus_quic_retry_total` `/metrics` counter makes the exchange
  externally observable) in 1.35.0, 4l (QUIC connection migration /
  reactive server-side path validation, RFC 9000 9.3 -- fixed a
  read-path bug that fed ngtcp2 the connection's last-known address
  instead of each packet's own actual `recvfrom()` address, which had
  been silently preventing it from ever noticing a client's
  mid-connection address change; a new `magnus_quic_migration_total`
  `/metrics` counter tracks successful validations) in 1.36.0** — see
  `CHANGELOG.md`
  1.25.0/1.26.0/1.27.0/1.28.0/1.29.0/1.30.0/1.31.0/1.32.0/1.33.0/1.34.0/1.35.0/1.36.0
  and `src/magnus_quic.h` for the exact scope and what's deliberately
  still missing (proxied-response compression, Brotli/zstd, and
  streaming compression above 2a's own 8 MiB bound, on every protocol,
  not a QUIC-specific gap; Real-IP-aware `source_cidr` route matching
  and client-IP-based cluster selection, since QUIC has no established
  PROXY-protocol-over-UDP precedent in this codebase yet; no 0-RTT at
  the transport level).
- **Phase 5 — FastCGI/SCGI/uWSGI, Runtime API expansion, zero-downtime
  binary upgrade.** The upgrade mechanism (inherited listener FD hand-off,
  old-process drain) touches `magnusd`'s supervision model directly and
  should be designed together with a review of the existing SIGHUP-reload
  atomicity guarantees, not bolted on separately.
  **5a-1 (FastCGI dispatch, HTTP/1.1 GET/HEAD only, no request body, one
  connection per request -- no pooling/retry/affinity/caching/active
  health probing yet, the same deliberately narrow first cut every other
  upstream-protocol dispatch in this codebase began from) shipped in
  1.51.0** — new `src/magnus_fastcgi.h`/`.c` protocol module (record
  encode/decode + CGI-response-to-HTTP/1.1 translation, no I/O of its
  own, mirroring `magnus_proxy.h`/`.c`'s own framing-only scope), a
  dedicated `magnus_fastcgi_cluster` (round-robin only, same
  not-a-shared-namespace precedent gRPC's own cluster already
  established), `--fastcgi-upstream`/`fastcgi_upstream` and
  `--fastcgi-root`/`fastcgi_root` (config's FastCGI equivalent of
  nginx's own `fastcgi_param SCRIPT_FILENAME
  $document_root$fastcgi_script_name;`), and a new `action=fastcgi`
  route action. Verified end-to-end against a real PHP-FPM 8.3.31
  backend (query strings, application-set headers, a `Status:` override,
  PHP-FPM's own 404-for-missing-script, keep-alive/close framing, HEAD,
  a clean 502 on upstream failure, a client-abort mid-request) plus a
  new `tests/test-fastcgi.c` unit test for the protocol module in
  isolation and direct ASan/UBSan testing of the live server — see
  `CHANGELOG.md` 1.51.0 for the one real bug this increment found and
  fixed along the way (the access-log line originally hardcoded
  `status=200` regardless of the application's real response status).
  **5a-2 (FastCGI request-body/POST support) shipped in 1.52.0** --
  lifts 5a-1's GET/HEAD-only restriction: any method with a body
  already buffered by the same generic pre-dispatch buffering
  `action=proxy` uses is now relayed as one or more `STDIN` records
  (split at the 16-bit per-record content-length ceiling), with a real
  `CONTENT_LENGTH` and a new `CONTENT_TYPE` metavariable (the one
  header essential to a relayed body meaning anything to a real
  application, e.g. PHP's own `$_POST`). Verified against real
  PHP-FPM: form-encoded POST, JSON body, a 200000-byte body split
  across 4 records, empty-body POST, and the pre-existing generic 413
  cap unaffected — see `CHANGELOG.md` 1.52.0.

  **5a-3 (FastCGI retry-on-upstream-failure) shipped in 1.53.0** --
  retries against a different healthy endpoint on *any* upstream
  failure (connect/send/receive/malformed response), not just a
  connect-stage one the way `action=proxy`'s own retry is limited to,
  since FastCGI's whole-response-buffering design means nothing ever
  reaches the client before `magnus_fastcgi_finish()` runs. Bounded by
  `MAGNUS_FASTCGI_MAX_ATTEMPTS` (2). Verified against a real two-
  endpoint PHP-FPM cluster with one endpoint always down: 20 sequential
  + 40 concurrent requests all still succeeded — see `CHANGELOG.md`
  1.53.0 for the pre-existing 5a-1 gap (a missing `magnus_cluster_
  result()` call on `EPOLLERR`/`EPOLLHUP`) it fixed along the way.

  **5a-4 (FastCGI connection pooling) shipped in 1.54.0** -- a
  dedicated idle-connection pool (`magnus_fastcgi_pool[]`, mirroring
  `magnus_upstream_pool[]`'s own shape) plus `FCGI_KEEP_CONN` always
  requested in `BEGIN_REQUEST`. Verified against a deliberately
  under-provisioned real PHP-FPM backend (4 static workers) that
  connections genuinely persist and get reused (`ss` showing the same
  TCP 4-tuple idle between requests) and that concurrent bursts succeed
  overwhelmingly. This increment's own heavier concurrent testing found
  and fixed two real gaps along the way, both documented in full in
  `CHANGELOG.md` 1.54.0: a missing `EPOLLOUT`→`EPOLLIN` epoll-interest
  demotion (invisible in every prior FastCGI increment since a fd was
  always short-lived until pooling kept one alive long enough to spin
  the event loop), and a complete absence of connect/read timeout
  enforcement since 5a-1 (a stalled upstream previously hung the
  *client* indefinitely rather than ever answering a clean `504`; fixed
  with a new `magnus_fastcgi_expire()` mirroring `magnus_expire_
  proxies()`).

  **5a-5 (FastCGI session affinity) shipped in 1.55.0** -- the same
  `MAGNUS_AFFINITY` cookie `action=proxy`/`action=grpc` already share
  now works for `action=fastcgi` too (sticky endpoint selection,
  fresh-cookie-on-deviation, `Set-Cookie` in the identical format),
  closing out "FastCGI 고도화" (pooling/retry/affinity as one grouped
  phase of work). Verified against a real two-instance PHP-FPM cluster
  that a cookie sticks to its own endpoint (including across a
  target-endpoint outage, correctly rerouting with a fresh cookie) and
  that pooling/affinity compose correctly together (the same pooled
  connection, not just the same endpoint, gets reused) -- see
  `CHANGELOG.md` 1.55.0.

  **5b-1 (SCGI dispatch) shipped in 1.56.0** -- Phase 5's second
  upstream protocol, a wider first cut than 5a-1's own original scope:
  any method with or without a request body, and connect/read timeout
  enforcement, both included from the start rather than deferred (SCGI
  mandates `CONTENT_LENGTH` as its very first header regardless, so
  GET-only would have been an artificial restriction, not a natural
  one; timeout enforcement's own absence was already a real bug 5a-4
  found and fixed once, not worth knowingly reintroducing into a second
  protocol path). Retry and connection pooling (5a-3/5a-4's own
  equivalents) are still genuinely deferred. New `src/magnus_scgi.h`/
  `.c` covers only what SCGI needs of its own (netstring header-block
  framing) -- its response translation reuses `magnus_fastcgi_find_
  body()`/`magnus_fastcgi_translate_headers()` directly rather than
  duplicating that already-generic CGI-response parsing under a second
  name. Found and fixed a real bug along the way: `magnus_fastcgi_
  translate_headers()` hardcoded `X-Magnus-Via: magnus-fastcgi/0.1`
  regardless of caller, so every SCGI response was misidentifying
  itself as FastCGI's until a `via` parameter was added. Verified
  against a real SCGI backend: `Status:` overrides, 404-equivalents,
  GET/HEAD/POST with bodies up to 200000 bytes, a clean `502` against a
  down endpoint, a clean `504` at exactly the 10-second read timeout
  against a deliberately hanging one (not a hang), 50 concurrent
  requests, zero ASan/UBSan findings -- see `CHANGELOG.md` 1.56.0.

  **5c-1 (uwsgi dispatch) shipped in 1.57.0** -- Phase 5's third
  upstream protocol, same wider-than-FastCGI's-original-5a-1 first cut
  as SCGI dispatch (5b-1). New `src/magnus_uwsgi.h`/`.c`: the uwsgi
  wire protocol's own 4-byte packet header (little-endian, unlike
  FastCGI's big-endian) and length-prefixed var encoding, plus a
  genuinely new `magnus_uwsgi_translate_headers()` -- unlike SCGI
  dispatch, this does NOT reuse `magnus_fastcgi_translate_headers()`,
  because a real uWSGI server's response starts with an actual HTTP
  status line, not a CGI `Status:` one. This was caught by spike-
  testing the protocol directly against a real, pip-installed uWSGI
  2.0.31 server *before* writing magnus.c's own dispatch machinery --
  the initial assumption (reuse the FastCGI/SCGI convention) was wrong,
  and finding that out via a 40-line standalone harness instead of a
  wrong 500-line implementation is exactly what this codebase's own
  Phase-4 spike-testing precedent is for. Verified against the same
  real uWSGI server: status overrides, GET/HEAD/POST with bodies up to
  200000 bytes, a clean 502/504, 50 concurrent requests, zero ASan/
  UBSan findings -- see `CHANGELOG.md` 1.57.0.

  **5d-1 (Runtime API expansion: graceful drain) shipped in 1.58.0** --
  a new `magnusctl drain` control-protocol command (`DRAIN`, delivered
  as a new `SIGUSR1` signal to the running child, mirroring `SIGHUP`'s
  own reload mechanism) that stops the primary listener's own
  `accept()` while every already-open connection keeps being served to
  completion, plus `/healthz` flipping to `503` on any already-open
  connection (e.g. a load balancer's own long-lived health-check
  connection) and a new `magnus_draining` `/metrics` gauge -- so both
  an external readiness probe and direct polling can observe the
  drained state, not just new connection attempts being refused at the
  TCP level. Verified end to end through real `magnusctl drain` against
  a real `magnusd`-supervised child (new `tests/test-control-plane.sh`
  block) and directly inside the real Docker image via `docker kill
  --signal=USR1` (the same mechanism a Kubernetes `preStop` hook would
  use). The admin channel and L4 stream/UDP/QUIC listeners are
  deliberately not gated by this first cut -- see `CHANGELOG.md` 1.58.0.

  Still ahead for Phase 5: the zero-downtime binary upgrade mechanism
  itself (inherited listener FD hand-off, old-process drain -- 5d-1's
  own drain mechanism is a natural building block for the "old process
  stops taking new work" half of that, but the FD hand-off to a new
  binary is still wholly unbuilt).
- **Phase 6 — Production hardening.** Not a feature phase — the security
  attack list in Section 8.1, the fuzz corpus expansion in Section 9, and
  the connection-scale benchmark ladder in Section 10 apply continuously
  to whatever protocol surface exists *at the time*, so in practice this
  work is threaded through every phase above (each new parser gets fuzzed
  as it's written, per Section 1d/1e above) rather than deferred entirely
  to the end. What's left genuinely for a dedicated Phase 6 is the
  cross-cutting audit once all protocol surfaces exist.

## 4. Module structure

`magnus.c` at 2,467 lines is still one file handling the reactor, HTTP/1
request dispatch, static file serving, TLS handshake glue, proxy state
machine, cluster/rate-limit wiring, access logging, and signal handling.
Per Section 20's own caveat ("디렉터리 분리를 목적 자체로 삼지 않는다" —
don't split for its own sake), the split happens incrementally, driven by
what each Phase 1 sub-phase actually needs to not make `magnus.c` worse:

- 1a (connection pool) is the natural point to extract proxy/upstream
  logic that's already partly separate (`magnus_proxy.c`) into a real
  `upstream` module owning connection lifecycle.
- 1b (routing) becomes its own module because it is one (a matcher +
  config schema), not because of a size target.
- 1d/1e (WebSocket, HTTP/2) each get their own module by necessity — a
  frame parser does not belong inlined into the HTTP/1 request loop.
- The reactor/accept/signal-handling core in `magnus.c` stays where it is
  until something concrete (e.g. Phase 3's L4 listeners needing a second
  accept path) forces a `core`/`http1` split, rather than moving it
  preemptively into an empty `src/core/` per Section 20's target tree.

## 5. Dependencies (Section 22 framework applied)

| Need | Candidate | License | Notes |
|---|---|---|---|
| HTTP/2 (1e) | nghttp2 (C, widely deployed, HPACK included) | MIT | Hand-rolling HPACK is explicitly the kind of thing this roadmap avoids (Section 4's own CVE-history warning); evaluate binary size / static-link footprint against the current ~9 MiB image budget before committing |
| HTTP/3 (Phase 4) | ngtcp2+nghttp3, or quiche (Rust, violates Section 2.2's "don't bring in another language's runtime" unless it's a leaf dependency with a C ABI, evaluate accordingly), or defer entirely if the size/complexity trade-off fails Section 2.4's memory-safety bar | varies | Explicitly deferred to Phase 4's own dependency review; not decided here |
| Compression (Phase 2) | zlib (gzip, direct dependency in the review branch), brotli, zstd | zlib/MIT/BSD | Static-file gzip is implemented with 256-byte/8-MiB CPU and memory bounds; proxied streaming and brotli/zstd remain deferred |
| DNS (1c) | `getaddrinfo_a` (glibc, no new dependency) vs. a minimal vendored async resolver | n/a / varies | Prefer no new dependency unless `getaddrinfo_a`'s behavior (thread-pool based, not epoll-native) proves unworkable under load in 1c's own benchmark step |

Every dependency actually adopted gets its license, maintenance status, and
size/runtime-overhead impact recorded in `THIRD_PARTY_NOTICES.md` at the
point it's added — not before, and not skipped.

## 6. API / ABI

The Magnus Module ABI is pre-1.0 (Section 21). Phases 1–3 are the reviewed
window for its design before it needs to hold still: the common HTTP/1↔HTTP/2
request-model decision in 1e in particular has direct ABI implications (a
module hook written against "the request" needs to keep meaning the same
thing across protocol versions). Any breaking change made during this
window is recorded in `CHANGELOG.md` at the version it lands in, per the
versioning policy already adopted (MAJOR = engine change, MINOR = feature,
PATCH = security/bug fix) — an ABI break is an engine-level change and
bumps MAJOR.

## 7. Test plan

Matches Section 17's tree, mapped onto what this repo already has:

- `tests/*.c` unit tests and `tests/fuzz-http.c`-style fuzz harnesses: one
  new fuzz target per new binary parser (routing matcher in 1b, WebSocket
  frames in 1d, HPACK/frame parsing in 1e), each run for 200k iterations
  in `make test` and 4M+ separately before a sub-phase is called done —
  the same bar `tests/fuzz-http.c` already meets.
- `tests/test-core.sh` / `tests/test-control-plane.sh`-style integration
  tests: every sub-phase adds its own block to `tests/test-core.sh`
  (matching the pattern already used for M2–M6 and the 1.1.0 body-proxy
  tests) rather than a separate parallel test tree, until the test file's
  size itself argues for a split.
- Security-specific cases (Section 8.1's attack list) get added
  incrementally as each relevant protocol surface exists — e.g. HTTP/2
  Rapid Reset and stream exhaustion are meaningless before 1e ships, so
  they belong to 1e's own checkpoint, not a deferred blanket "security
  phase."
- Performance: the concurrency ladder in Section 10 and the Magnus/NGINX/
  HAProxy comparison in Section 11 apply once there is a stable feature
  surface worth comparing — a repeat of the external, git-repo-excluded
  benchmark methodology already used for the 1.0.0 NGINX/Apache comparison
  (`/home/nytr/magnus-bench-ext/`, kept outside this repository), extended
  with HAProxy and the new scenarios (HTTP/2, WebSocket, TCP proxy, cache)
  as each becomes available to test.

## 8. Performance and security goals

- No optimization (Section 2.3's Linux API list — `splice`, `SO_REUSEPORT`,
  `TCP_FASTOPEN`, etc.) lands without a before/after benchmark showing it
  actually helped, per Section 23's explicit prohibition on unverified
  performance claims — the TCP_NODELAY fix in v1.0.1 is the template: found
  by reproduction, fixed, measured (390 → 17,485 req/s), not asserted.
- Every new resource (connection pool slots, DNS cache entries, WebSocket
  frame buffers, HTTP/2 stream count, cache size) gets an explicit upper
  bound at the point it's introduced, per Section 12 — not retrofitted
  after an exhaustion bug is found the hard way.
- Every new parser is fuzzed before its sub-phase is called done, not
  after (see Section 7 above).

## 9. What this roadmap deliberately does not do yet

Per Section 27, this document does not commit to a Phase 2–6 line-by-line
plan (Section 3 above stays a summary), does not pre-select the HTTP/3
dependency, and does not begin any Phase 1 implementation. The next step is
1a (upstream connection pool) — starting only once this roadmap itself has
been reviewed.
