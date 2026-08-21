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
  - **Real IP 2b — PROXY protocol v1/v2, Forwarded/X-Forwarded-For.
    Shipped in 1.12.0.** Entirely gated on a `trusted_proxies` CIDR
    allowlist (default off); resolution feeds `source_cidr` route
    matching, rate limiting, and access logging alike, always trusting
    only the connection's true direct TCP peer. Was pulled ahead of the
    rest of Phase 2 exactly for the reason flagged above: ACL/rate-limit
    correctness downstream depends on knowing the real client address
    first.
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
- **Phase 4 — HTTP/3/QUIC.** Per the master prompt's own instruction
  (Section 4), not hand-rolled — evaluated against vetted libraries
  (e.g. an OpenSSL-integrated QUIC stack vs. quiche vs. msquic)
  in Section 5's dependency framework before any code.
- **Phase 5 — FastCGI/SCGI/uWSGI, Runtime API expansion, zero-downtime
  binary upgrade.** The upgrade mechanism (inherited listener FD hand-off,
  old-process drain) touches `magnusd`'s supervision model directly and
  should be designed together with a review of the existing SIGHUP-reload
  atomicity guarantees, not bolted on separately.
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
