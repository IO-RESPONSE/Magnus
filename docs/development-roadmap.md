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
   - **1e-5+ — remaining.** h2c; response trailers; WebSocket-over-h2
     (extended CONNECT); and generalizing 1e-1/1e-2/1e-4's still-
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
  so may run as parallel sub-phases. Real IP (X-Forwarded-For/Forwarded/
  PROXY protocol trust) is small and self-contained; doing it early despite
  being listed in Phase 2 is worth reconsidering since ACL/rate-limit
  correctness downstream depends on it.
- **Phase 3 — L4 TCP/UDP, TLS passthrough, PROXY protocol.** Architecturally
  distinct from the L7 phases: a new listener type that doesn't go through
  `magnus_http_parse` at all. UDP session tracking's memory bound (Section
  12) needs its design nailed down before implementation, not discovered
  during it.
- **Phase 4 — HTTP/3/QUIC.** Per the master prompt's own instruction
  (Section 4), not hand-rolled — evaluated against vetted libraries
  (e.g. an nginx-QUIC-style OpenSSL-integrated stack vs. quiche vs. msquic)
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
| Compression (Phase 2) | zlib (gzip, already a near-universal system dependency), brotli, zstd | zlib/MIT/BSD | Start with gzip only per Section 4.2's "최소" wording; add brotli/zstd only once the gzip path's CPU-exhaustion guard (Section 4.3) is proven |
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
