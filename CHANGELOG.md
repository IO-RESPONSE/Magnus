# Changelog

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
